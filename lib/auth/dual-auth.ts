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

/**
 * Resolves user identity from either an incoming Bearer API Key or an active Clerk session.
 * Returns null if both authentication methods fail or are missing.
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
