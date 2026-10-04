// ============================================================================
// PROJECT AEGIS: DUAL AUTHENTICATION RESOLVER
// Supports Clerk Web Session Cookies & Bearer Developer API Keys
// ============================================================================

import { auth } from '@clerk/nextjs/server';
import { createHash } from 'crypto';
import { getServiceSupabase } from '@/lib/supabase/server';

export interface AuthContext {
  userId: string;
  authMethod: 'clerk_session' | 'api_key';
  keyPrefix?: string;
}

/** Shared audience for scans/run without real auth. */
export const FAILED_OPEN_OPERATOR: AuthContext = {
  userId: 'local-operator-001',
  authMethod: 'clerk_session',
};

export const fallbackOperatorId = FAILED_OPEN_OPERATOR.userId;

/**
 * Resolves user identity from either an incoming Bearer API Key or an active
 * Clerk session. Returns `null` if both authentication methods fail or are
 * missing.
 */
export async function resolveAuthContext(req: Request): Promise<AuthContext | null> {
  const authHeader = req.headers.get('authorization') || req.headers.get('Authorization');

  // Strategy A: Developer API Key (Bearer aegis_live_...)
  if (authHeader && authHeader.startsWith('Bearer aegis_live_')) {
    const rawKey = authHeader.replace(/^Bearer\s+/i, '').trim();
    const hashedKey = createHash('sha256').update(rawKey).digest('hex');

    const supabase = getServiceSupabase();
    if (!supabase) {
      // Database not configured: API key validation is impossible.
      // Fall through to Clerk session strategy, which may still succeed.
      console.warn('[auth] Supabase not configured - cannot validate API keys.');
    } else {
      const { data: apiKeyRecord, error } = await supabase
        .from('api_keys')
        .select('id, user_id, key_prefix')
        .eq('hashed_key', hashedKey)
        .single();

      if (error || !apiKeyRecord) {
        return null;
      }

      // Touch last_used_at timestamp asynchronously
      void supabase
        .from('api_keys')
        .update({ last_used_at: new Date().toISOString() })
        .eq('id', apiKeyRecord.id);

      return {
        userId: apiKeyRecord.user_id,
        authMethod: 'api_key',
        keyPrefix: apiKeyRecord.key_prefix,
      };
    }
  }

  // Strategy B: Clerk Session Authentication (Web Dashboard)
  try {
    const session = await auth();
    if (session && session.userId) {
      return {
        userId: session.userId,
        authMethod: 'clerk_session',
      };
    }
  } catch {
    // Non-Clerk request context (e.g. headless scripts without cookies)
  }

  return null;
}

/**
 * Resolves a request identity, falling back to a local-operator context when
 * real authentication is unavailable, fails, or throws. This is the resolver
 * used by scan route handlers so that public / postman / dashboard usage never
 * receives a 401 — it scans under the `local-operator-001` audience instead.
 *
 * IMPORTantly: quota/DB errors must never take down scans, so the returned
 * context is always valid.
 */
export async function resolveAuthContextOrFallback(
  req: Request
): Promise<AuthContext> {
  try {
    const context = await resolveAuthContext(req);
    if (context) {
      return context;
    }
  } catch (authError) {
    console.warn('[auth-resolver] auth resolution failed, using fallback operator:', authError);
  }

  return FAILED_OPEN_OPERATOR;
}
