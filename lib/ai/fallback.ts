import { extractHighEntropyTokens } from '@/lib/scanners/entropy';
import {
  redactSecret,
  scanCodeForPatterns,
  type SecretSeverity,
} from '@/lib/scanners/regex-patterns';

export interface LocalAiFinding {
  type: 'KNOWN_SIGNATURE' | 'HIGH_ENTROPY';
  name: string;
  severity: SecretSeverity;
  lineNumber: number;
  redactedToken: string;
  entropy?: number;
}

export interface LocalAiAnalysis {
  mode: 'offline';
  verdict: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
  riskScore: number;
  summary: string;
  findings: LocalAiFinding[];
  entropy: {
    highestEntropy: number;
    candidateCount: number;
  };
  recommendations: string[];
}

/**
 * Deterministic, network-free analysis used whenever the configured AI
 * provider is unavailable. Raw tokens never leave this module's process and
 * are replaced with redacted values before the result is returned.
 */
export function analyzeLocally(content: string): LocalAiAnalysis {
  const patternMatches = scanCodeForPatterns(content);
  const entropyReport = extractHighEntropyTokens(content);
  const registeredTokens = new Set(patternMatches.map((match) => match.matchedString));

  const findings: LocalAiFinding[] = patternMatches.map((match) => ({
    type: 'KNOWN_SIGNATURE',
    name: match.name,
    severity: match.severity,
    lineNumber: match.lineNumber,
    redactedToken: match.redactedString,
  }));

  for (const candidate of entropyReport.candidates) {
    if (!registeredTokens.has(candidate.token)) {
      findings.push({
        type: 'HIGH_ENTROPY',
        name: 'High-Entropy Secret Literal',
        severity: candidate.entropy > 4.5 ? 'CRITICAL' : 'HIGH',
        lineNumber: candidate.lineNumber,
        redactedToken: redactSecret(candidate.token),
        entropy: candidate.entropy,
      });
    }
  }

  const riskScore = findings.some((finding) => finding.severity === 'CRITICAL')
    ? 100
    : findings.some((finding) => finding.severity === 'HIGH')
      ? 75
      : findings.length > 0
        ? 40
        : 0;
  const verdict = riskScore >= 75 ? 'DANGEROUS' : riskScore >= 25 ? 'SUSPICIOUS' : 'SAFE';

  const recommendations = findings.length > 0
    ? [
        'Rotate every flagged credential and treat it as compromised.',
        'Move secrets into an environment or managed secret store.',
        'Keep GitShield enabled as a pre-commit gate for future changes.',
      ]
    : ['No known secret signature or high-entropy literal was detected.'];

  return {
    mode: 'offline',
    verdict,
    riskScore,
    summary:
      findings.length > 0
        ? `Local Aegis heuristics identified ${findings.length} credential candidate${findings.length === 1 ? '' : 's'}.`
        : 'Local Aegis heuristics found no credential candidates.',
    findings,
    entropy: {
      highestEntropy: entropyReport.highestEntropy,
      candidateCount: entropyReport.candidates.length,
    },
    recommendations,
  };
}
