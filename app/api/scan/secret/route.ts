// ============================================================================
// PROJECT AEGIS: GITSHIELD SECRET AUDITOR ROUTE HANDLER
// ============================================================================

import { NextResponse } from 'next/server';
import { resolveAuthContextOrFallback } from '@/lib/auth/dual-auth';
import { checkAndIncrementQuota } from '@/lib/quota';
import { analyzeCode } from '@/lib/scanners/code-analysis';
import { getServiceSupabase } from '@/lib/supabase/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const MAX_PAYLOAD_BYTES = 512 * 1024; // 512 KB payload threshold

export async function POST(req: Request) {
  try {
    const authContext = await resolveAuthContextOrFallback(req);

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

    const { findings, riskScore, verdict, remediation, highestEntropy } = analyzeCode(content, filename);

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
          highestEntropy,
          findings: findings.map((f) => ({
            name: f.name,
            severity: f.severity,
            lineNumber: f.lineNumber,
            redactedToken: f.redactedToken,
          })),
        },
      });
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
