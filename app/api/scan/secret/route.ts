// ============================================================================
// PROJECT AEGIS: GITSHIELD SECRET AUDITOR ROUTE HANDLER
// ============================================================================

import { NextResponse } from 'next/server';
import { resolveAuthContext } from '@/lib/auth/dual-auth';
import { checkAndIncrementQuota } from '@/lib/quota';
import { scanCodeForPatterns, redactSecret } from '@/lib/scanners/regex-patterns';
import { extractHighEntropyTokens } from '@/lib/scanners/entropy';
import { getServiceSupabase } from '@/lib/supabase/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const MAX_PAYLOAD_BYTES = 512 * 1024; // 512 KB payload threshold

interface SecretFinding {
  type: 'KNOWN_SIGNATURE' | 'HIGH_ENTROPY';
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  lineNumber: number;
  redactedToken: string;
  rawToken: string;
  suggestedEnvKey: string;
  entropy?: number;
}

export async function POST(req: Request) {
  try {
    const authContext = await resolveAuthContext(req);
    if (!authContext) {
      return NextResponse.json(
        { error: 'Unauthorized: Missing or invalid API key / session.' },
        { status: 401 }
      );
    }

    const quota = await checkAndIncrementQuota(authContext.userId);
    if (!quota.allowed) {
      return NextResponse.json(
        {
          error: 'Rate limit exceeded: Daily scan quota exhausted.',
          resetsAt: quota.resetsAt,
        },
        { status: 429 }
      );
    }

    const body = await req.json().catch(() => null);
    if (!body || typeof body.content !== 'string') {
      return NextResponse.json(
        { error: 'Bad Request: Missing "content" property in request body.' },
        { status: 400 }
      );
    }

    const filename = typeof body.filename === 'string' ? body.filename : 'staged_diff.txt';
    const content = body.content;

    if (Buffer.byteLength(content, 'utf-8') > MAX_PAYLOAD_BYTES) {
      return NextResponse.json(
        { error: 'Payload Too Large: Content exceeds 512 KB scan ceiling.' },
        { status: 413 }
      );
    }

    // 1. Execute Pattern Scanner
    const patternMatches = scanCodeForPatterns(content);

    // 2. Execute Shannon Entropy Scanner
    const entropyReport = extractHighEntropyTokens(content);

    // 3. Consolidate & Deduplicate Findings
    const findings: SecretFinding[] = [];
    const registeredTokens = new Set<string>();

    for (const match of patternMatches) {
      registeredTokens.add(match.matchedString);
      findings.push({
        type: 'KNOWN_SIGNATURE',
        name: match.name,
        severity: match.severity,
        lineNumber: match.lineNumber,
        redactedToken: match.redactedString,
        rawToken: match.matchedString,
        suggestedEnvKey: match.suggestedEnvKey,
      });
    }

    for (const candidate of entropyReport.candidates) {
      if (!registeredTokens.has(candidate.token)) {
        findings.push({
          type: 'HIGH_ENTROPY',
          name: 'High-Entropy Secret Literal',
          severity: candidate.entropy > 4.5 ? 'CRITICAL' : 'HIGH',
          lineNumber: candidate.lineNumber,
          redactedToken: redactSecret(candidate.token),
          rawToken: candidate.token,
          suggestedEnvKey: `SECRET_TOKEN_${candidate.lineNumber}`,
          entropy: candidate.entropy,
        });
      }
    }

    // 4. Calculate Risk Score & Verdict
    let riskScore = 0;
    if (findings.some((f) => f.severity === 'CRITICAL')) {
      riskScore = 100;
    } else if (findings.some((f) => f.severity === 'HIGH')) {
      riskScore = 75;
    } else if (findings.length > 0) {
      riskScore = 40;
    }

    const verdict = riskScore >= 75 ? 'DANGEROUS' : riskScore >= 25 ? 'SUSPICIOUS' : 'SAFE';

    // 5. Generate Automated Remediation Patch
    const envAdditions: string[] = [];
    let patchedContent = content;

    findings.forEach((finding, index) => {
      const sanitizedKey = `${finding.suggestedEnvKey}_${index + 1}`.toUpperCase();
      envAdditions.push(`${sanitizedKey}="${finding.rawToken}"`);
      patchedContent = patchedContent.split(finding.rawToken).join(`process.env.${sanitizedKey}`);
    });

    const remediation = {
      hasSecrets: findings.length > 0,
      envFileSnippet: envAdditions.join('\n'),
      sanitizedContent: patchedContent,
      gitignoreRecommendation: '.env\n.env.local\n*.pem\n*.key',
    };

    // 6. Record Audit in Supabase (skipped safely when not configured)
    const supabase = getServiceSupabase();
    if (supabase) {
      await supabase.from('scans').insert({
        user_id: authContext.userId,
        scan_type: authContext.authMethod === 'api_key' ? 'cli_precommit' : 'code',
        target: filename,
        risk_score: riskScore,
        verdict,
        summary: `GitShield detected ${findings.length} secret token(s) in ${filename}.`,
        details: {
          filename,
          findingsCount: findings.length,
          highestEntropy: entropyReport.highestEntropy,
          findings: findings.map((f) => ({
            name: f.name,
            severity: f.severity,
            lineNumber: f.lineNumber,
            redactedToken: f.redactedToken,
          })),
        },
      });
    } else {
      console.warn('[scan/secret] Supabase not configured - skipping audit log.');
    }

    return NextResponse.json({
      success: true,
      verdict,
      riskScore,
      findingsCount: findings.length,
      findings: findings.map((f) => ({
        type: f.type,
        name: f.name,
        severity: f.severity,
        lineNumber: f.lineNumber,
        redactedToken: f.redactedToken,
        entropy: f.entropy,
        suggestedEnvKey: f.suggestedEnvKey,
      })),
      remediation,
    });
  } catch (err) {
    const error = err as Error;
    return NextResponse.json(
      { error: 'Internal Server Error', message: error.message },
      { status: 500 }
    );
  }
}
