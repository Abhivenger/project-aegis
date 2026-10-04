// ============================================================================
// PROJECT AEGIS: SAFELINK URL INSPECTION ROUTE HANDLER
// ============================================================================

import { NextResponse } from 'next/server';
import { resolveAuthContextOrFallback, type AuthContext } from '@/lib/auth/dual-auth';
import { checkAndIncrementQuota, type QuotaStatus } from '@/lib/quota';
import { analyzeUrl } from '@/lib/scanners/url-analyzer';
import { getServiceSupabase } from '@/lib/supabase/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Normalizes user-supplied URL input: auto-prepends https:// when the value
 * has no protocol scheme, so inputs like "github.com/login" are scannable.
 */
function normalizeUrlInput(raw: string): string {
  const trimmed = raw.trim();
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    return trimmed; // Already has a scheme (http, https, ftp, etc.)
  }
  return `https://${trimmed}`;
}

/** Shared identity used when real authentication is unavailable or fails. */
async function resolveUserId(req: Request): Promise<AuthContext> {
  // Reuse the shared fallback resolver so /api/scan/url and /api/scan/secret
  // behave identically when no real auth is present.
  return resolveAuthContextOrFallback(req);
}

export async function POST(req: Request) {
  try {
    const authContext = await resolveUserId(req);

    // Quota check is fail-open: any error in the quota backend allows the scan
    // so that quota/DB outages can never take down the scanning feature.
    let quota: QuotaStatus = {
      allowed: true,
      dailyScanCount: 0,
      maxDailyQuota: Number.MAX_SAFE_INTEGER,
      plan: 'free',
      resetsAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    };
    try {
      quota = await checkAndIncrementQuota(authContext.userId);
    } catch (quotaError) {
      console.error('[scan/url] Quota check failed (fail-open):', quotaError);
    }
    if (!quota.allowed) {
      return NextResponse.json(
        {
          error: 'Rate limit exceeded: Daily scan quota exhausted.',
          resetsAt: quota.resetsAt,
          dailyScanCount: quota.dailyScanCount,
          maxDailyQuota: quota.maxDailyQuota,
        },
        { status: 429 }
      );
    }

    const body = await req.json().catch(() => null);
    if (!body || typeof body.url !== 'string' || body.url.trim().length === 0) {
      return NextResponse.json(
        { error: 'Bad Request: "url" property string is required.' },
        { status: 400 }
      );
    }

    const targetUrl = normalizeUrlInput(body.url);
    const report = await analyzeUrl(targetUrl);

    // Persist scan audit record to Supabase.
    // Fire-and-forget: logging must never block or fail the scan response.
    // Skipped entirely when Supabase is not configured (client is null).
    const supabase = getServiceSupabase();
    if (supabase) {
      void supabase
        .from('scans')
        .insert({
          user_id: authContext.userId,
          scan_type: 'url',
          target: targetUrl,
          risk_score: report.riskScore,
          verdict: report.verdict,
          summary: `SafeLink classified URL as ${report.verdict} with risk score ${report.riskScore}/100.`,
          details: report,
        })
        .then(
          ({ error: insertError }) => {
            if (insertError) {
              console.error('[scan/url] Audit insert failed:', insertError.message);
            }
          },
          (unexpected: unknown) => {
            console.error('[scan/url] Audit insert threw:', unexpected);
          }
        );
    } else {
      console.warn('[scan/url] Supabase not configured - skipping audit log.');
    }

    return NextResponse.json({
      success: true,
      report,
      quota: {
        remaining: Math.max(0, quota.maxDailyQuota - quota.dailyScanCount),
        dailyScanCount: quota.dailyScanCount,
        maxDailyQuota: quota.maxDailyQuota,
        resetsAt: quota.resetsAt,
      },
    });
  } catch (err) {
    const error = err as Error;
    return NextResponse.json(
      { error: 'Internal Server Error', message: error.message },
      { status: 500 }
    );
  }
}
