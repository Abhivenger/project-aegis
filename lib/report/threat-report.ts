// ============================================================================
// PROJECT AEGIS: CRYPTOGRAPHIC COMPLIANCE & THREAT AUDIT EXPORT ENGINE
// Normalizes both SafeLink (URL) and GitShield (code) scan results into a
// single typed report model, then serializes it to Markdown or raw JSON.
// ============================================================================

import type { FindingItem, RemediationData } from '@/components/code-diff-viewer';
import type { UrlAnalysisReport, RedirectHop } from '@/lib/scanners/url-analyzer';
import { classifyIpAddress } from '@/lib/scanners/ip-ranges';
import { generateScanId, sha256Hex } from '@/lib/crypto/fingerprint';

export const REPORT_SCHEMA_VERSION = '1.0';

export type ReportSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ReportVerdict = 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
export type HopDecision = 'ALLOW' | 'BLOCK' | 'N/A';

export interface EntropyArtifactRow {
  artifact: string;
  location: string;
  entropy: number;
  severity: string;
}

export interface IpAuditRow {
  hopNumber: number;
  url: string;
  statusCode: number;
  ipAddress: string | null;
  scope: string;
  decision: HopDecision;
}

export interface GitShieldCommand {
  label: string;
  command: string;
}

export interface BaseThreatReport {
  schemaVersion: string;
  scanId: string;
  generatedAt: string;
  fingerprint: string;
  severity: ReportSeverity;
  riskScore: number;
  verdict: ReportVerdict;
  entropyArtifacts: EntropyArtifactRow[];
  ipAudit: IpAuditRow[];
  remediation: string[];
  gitShieldCommands: GitShieldCommand[];
}

export interface UrlThreatReport extends BaseThreatReport {
  kind: 'url';
  targetUrl: string;
  finalDestination: string;
  reasons: string[];
  detectedKeywords: string[];
  isSsrfBlocked: boolean;
}

export interface CodeThreatReport extends BaseThreatReport {
  kind: 'code';
  filename: string;
  findings: FindingItem[];
}

export type ThreatReport = UrlThreatReport | CodeThreatReport;

export const GITSHIELD_COMMANDS: readonly GitShieldCommand[] = [
  {
    label: 'Install the GitShield pre-commit guard',
    command: 'python3 cli/aegis.py --install',
  },
  {
    label: 'Auto-extract leaked secrets into .env and rewrite source',
    command: 'python3 cli/aegis.py --fix',
  },
  {
    label: 'Export a timestamped machine-readable audit report',
    command: 'python3 cli/aegis.py --export',
  },
];

export interface CodeReportInput {
  filename: string;
  riskScore: number;
  verdict: ReportVerdict;
  findings: FindingItem[];
  remediation?: RemediationData;
  originalContent?: string;
}

export function severityFromRisk(riskScore: number): ReportSeverity {
  if (riskScore >= 85) return 'CRITICAL';
  if (riskScore >= 65) return 'HIGH';
  if (riskScore >= 25) return 'MEDIUM';
  return 'LOW';
}

function classifyHop(hop: RedirectHop): IpAuditRow {
  if (!hop.ipAddress) {
    return {
      hopNumber: hop.hopNumber,
      url: hop.url,
      statusCode: hop.statusCode,
      ipAddress: null,
      scope: 'Unresolved',
      decision: 'N/A',
    };
  }

  const classification = classifyIpAddress(hop.ipAddress);
  return {
    hopNumber: hop.hopNumber,
    url: hop.url,
    statusCode: hop.statusCode,
    ipAddress: hop.ipAddress,
    scope: classification.isPrivate ? classification.scope : 'PUBLIC',
    decision: classification.isPrivate ? 'BLOCK' : 'ALLOW',
  };
}

/** Builds the normalized report for a completed SafeLink URL inspection. */
export function buildUrlThreatReport(report: UrlAnalysisReport): UrlThreatReport {
  const ipAudit = report.redirectChain.map(classifyHop);

  // Fold the pre-flight verdict into the audit trail when no hop captured it.
  if (report.isSsrfBlocked && !ipAudit.some((row) => row.decision === 'BLOCK')) {
    ipAudit.unshift({
      hopNumber: 0,
      url: report.targetUrl,
      statusCode: 0,
      ipAddress: null,
      scope: 'Pre-flight SSRF rejection',
      decision: 'BLOCK',
    });
  }

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    kind: 'url',
    scanId: generateScanId(),
    generatedAt: new Date().toISOString(),
    fingerprint: sha256Hex(`url:${report.targetUrl}`),
    severity: severityFromRisk(report.riskScore),
    riskScore: report.riskScore,
    verdict: report.verdict,
    targetUrl: report.targetUrl,
    finalDestination: report.finalDestination,
    reasons: report.reasons,
    detectedKeywords: report.detectedKeywords,
    isSsrfBlocked: report.isSsrfBlocked,
    entropyArtifacts: [],
    ipAudit,
    remediation: [
      'Rotate any credential the destination may have exposed; treat the endpoint as compromised.',
      'Add the destination host to the SafeLink deny-list and block it at the egress firewall.',
      'Enforce an outbound allow-list so user-supplied URLs can never reach RFC-1918, loopback, or cloud-metadata ranges.',
      'Keep per-hop re-validation enabled to defeat DNS rebinding (TOCTOU) attacks.',
    ],
    gitShieldCommands: [...GITSHIELD_COMMANDS],
  };
}

/** Builds the normalized report for a completed GitShield code audit. */
export function buildCodeThreatReport(input: CodeReportInput): CodeThreatReport {
  const entropyArtifacts: EntropyArtifactRow[] = input.findings
    .filter((finding) => typeof finding.entropy === 'number' && finding.entropy > 0)
    .map((finding) => ({
      artifact: finding.name,
      location: `Line ${finding.lineNumber}`,
      entropy: finding.entropy as number,
      severity: finding.severity,
    }));

  const contentForFingerprint = input.originalContent && input.originalContent.length > 0
    ? input.originalContent
    : `${input.filename}:${input.findings.map((f) => `${f.name}@${f.lineNumber}`).join('|')}`;

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    kind: 'code',
    scanId: generateScanId(),
    generatedAt: new Date().toISOString(),
    fingerprint: sha256Hex(`code:${contentForFingerprint}`),
    severity: severityFromRisk(input.riskScore),
    riskScore: input.riskScore,
    verdict: input.verdict,
    filename: input.filename,
    findings: input.findings,
    entropyArtifacts,
    ipAudit: [],
    remediation: [
      'Rotate every credential listed in the findings table immediately — assume it is compromised.',
      `Move the secrets into environment variables and keep the env file out of source control (${
        input.remediation?.gitignoreRecommendation?.replace(/\n/g, ', ') ?? '.env, .env.local'
      }).`,
      'Purge the secret from Git history (git filter-repo or BFG), since it persists in prior commits.',
      'Install the GitShield pre-commit guard so the leak cannot recur.',
    ],
    gitShieldCommands: [...GITSHIELD_COMMANDS],
  };
}

function markdownTable(headers: string[], rows: string[][]): string[] {
  const lines: string[] = [];
  lines.push(`| ${headers.join(' | ')} |`);
  lines.push(`| ${headers.map(() => '---').join(' | ')} |`);
  for (const row of rows) {
    lines.push(`| ${row.map((cell) => cell.replace(/\|/g, '\\|')).join(' | ')} |`);
  }
  return lines;
}

/** Renders a full human-readable Markdown audit report. */
export function reportToMarkdown(report: ThreatReport): string {
  const lines: string[] = [];

  lines.push('# Project Aegis — Security Audit Report');
  lines.push('');
  lines.push(`> Generated \`${report.generatedAt}\` · Scan ID \`${report.scanId}\``);
  lines.push('');

  // --- Chain of custody ---
  lines.push('## Chain of Custody');
  lines.push('');
  lines.push(`- **Scan class:** ${report.kind === 'url' ? 'SafeLink URL Inspection' : 'GitShield Code Audit'}`);
  lines.push(
    `- **Target:** \`${report.kind === 'url' ? report.targetUrl : report.filename}\``
  );
  lines.push(`- **SHA-256 fingerprint:** \`${report.fingerprint}\``);
  lines.push(`- **Report schema:** v${report.schemaVersion}`);
  lines.push('');

  // --- Executive summary ---
  lines.push('## Executive Summary');
  lines.push('');
  lines.push(`- **Risk score:** ${report.riskScore}/100`);
  lines.push(`- **Severity:** ${report.severity}`);
  lines.push(`- **Verdict:** ${report.verdict}`);
  if (report.kind === 'url') {
    lines.push(`- **SSRF enforcement:** ${report.isSsrfBlocked ? 'BLOCKED' : 'CLEARED'}`);
    lines.push(`- **Final destination:** \`${report.finalDestination}\``);
    lines.push(`- **Flagged keywords:** ${report.detectedKeywords.length}`);
  } else {
    lines.push(`- **Findings:** ${report.findings.length}`);
  }
  lines.push('');

  // --- Shannon entropy metrics ---
  lines.push('## Shannon Entropy Metrics');
  lines.push('');
  if (report.entropyArtifacts.length === 0) {
    lines.push('_No high-entropy artifacts were detected in this scan class._');
  } else {
    lines.push(
      ...markdownTable(
        ['Artifact', 'Location', 'Entropy (bits/char)', 'Severity'],
        report.entropyArtifacts.map((row) => [
          row.artifact,
          row.location,
          row.entropy.toFixed(3),
          row.severity,
        ])
      )
    );
  }
  lines.push('');

  // --- SSRF / IP hop audit trail ---
  lines.push('## SafeLink IP Hop / SSRF Routing Audit');
  lines.push('');
  if (report.kind !== 'url') {
    lines.push('_Not applicable — this is a static code audit (no network egress)._');
  } else if (report.ipAudit.length === 0) {
    lines.push('_No redirect hops were recorded; the target was reached directly or rejected pre-flight._');
  } else {
    lines.push(
      ...markdownTable(
        ['Hop', 'URL', 'HTTP', 'Resolved IP', 'Scope', 'Decision'],
        report.ipAudit.map((row) => [
          String(row.hopNumber),
          row.url,
          row.statusCode > 0 ? String(row.statusCode) : '—',
          row.ipAddress ?? '—',
          row.scope,
          row.decision,
        ])
      )
    );
  }
  lines.push('');

  // --- Findings / reasons detail ---
  if (report.kind === 'code') {
    lines.push('## Detected Findings');
    lines.push('');
    if (report.findings.length === 0) {
      lines.push('_No secrets detected._');
    } else {
      lines.push(
        ...markdownTable(
          ['Signature', 'Type', 'Severity', 'Line', 'Redacted Token', 'Suggested Env Key'],
          report.findings.map((f) => [
            f.name,
            f.type,
            f.severity,
            String(f.lineNumber),
            f.redactedToken,
            `process.env.${f.suggestedEnvKey}`,
          ])
        )
      );
    }
    lines.push('');
  } else {
    lines.push('## Heuristic Evaluation Flags');
    lines.push('');
    for (const reason of report.reasons) {
      lines.push(`- ${reason}`);
    }
    lines.push('');
  }

  // --- Remediation ---
  lines.push('## Prescriptive Remediation');
  lines.push('');
  report.remediation.forEach((step, index) => {
    lines.push(`${index + 1}. ${step}`);
  });
  lines.push('');

  // --- GitShield patch commands ---
  lines.push('## Automated GitShield Patch Commands');
  lines.push('');
  lines.push('```bash');
  for (const command of report.gitShieldCommands) {
    lines.push(`# ${command.label}`);
    lines.push(command.command);
  }
  lines.push('```');
  lines.push('');

  lines.push('---');
  lines.push('');
  lines.push('_Generated by Project Aegis. Confidential — handle according to your security policy._');

  return lines.join('\n');
}

/** Renders the raw telemetry payload as pretty-printed JSON. */
export function reportToJson(report: ThreatReport): string {
  return JSON.stringify(report, null, 2);
}

/** Filesystem-safe timestamp suffix, e.g. `2026-10-04T12-30-00`. */
export function reportFileStamp(report: ThreatReport): string {
  return report.generatedAt.replace(/[:.]/g, '-');
}
