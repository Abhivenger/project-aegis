// ============================================================================
// PROJECT AEGIS: DEVELOPER API KEY MANAGEMENT (CRUD)
// ============================================================================

import { NextResponse } from 'next/server';
import { randomBytes, createHash } from 'crypto';
import { getServiceSupabase } from '@/lib/supabase/server';
import {
  resolveAuthContextOrFallback,
} from '@/lib/auth/dual-auth';
import {
  generateStoredApiKey,
  listStoredKeys,
  removeStoredKey,
} from '@/lib/key-store';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Every request — whether from the dashboard, a CLI, Postman, or curl —
 * resolves through a shared fallback resolver. When no real Clerk/Supabase
 * auth material is present, the API key endpoints run under the local
 * operator context instead of returning 401.
 */
async function resolveUserId(req: Request, fallbackUserId = 'local-operator-001'): Promise<string> {
  try {
    const context = await resolveAuthContextOrFallback(req);
    return context.userId;
  } catch (err) {
    console.warn('[keys] auth resolution failed during key management, using fallback userId:', err);
    return fallbackUserId;
  }
}

/**
 * List active API keys for the current audience.
 */
export async function GET() {
  const userId = await resolveUserId(new Request('http://localhost/api/keys'));

  // Try Supabase first; fall back to the local store when it is unavailable.
  const supabase = getServiceSupabase();
  if (supabase) {
    const { data: dbKeys, error } = await supabase
      .from('api_keys')
      .select('id, key_name, key_prefix, last_used_at, created_at')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) {
      return NextResponse.json(
        { error: error.message },
        { status: 500 }
      );
    }

    return NextResponse.json({ success: true, keys: dbKeys ?? [] });
  }

  const localKeys = listStoredKeys(userId);
  return NextResponse.json({ success: true, keys: localKeys });
}

/**
 * Generate a new developer API key with one-time plaintext reveal.
 * Stores it to the active backend (Supabase if available, else local store),
 * then returns the generated record (including the plaintext secret).
 */
export async function POST(req: Request) {
  const userId = await resolveUserId(req);

  // Conservative early-return on bad JSON; do not attempt to generate a key
  // from a malformed request body.
  let body: Record<string, unknown> = {};
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { error: 'Bad Request: invalid JSON body' },
      { status: 400 }
    );
  }

  const keyName =
    typeof body.name === 'string' && body.name.trim().length > 0
      ? body.name.trim()
      : 'Default Pre-Commit Hook Key';

  // Format: aegis_live_ + 48 hex characters
  const rawToken = `aegis_live_${randomBytes(24).toString('hex')}`;
  const keyPrefix = rawToken.slice(0, 19); // aegis_live_ + first 8 characters
  const hashedKey = createHash('sha256').update(rawToken).digest('hex');

  // Try Supabase first.
  const supabase = getServiceSupabase();
  if (supabase) {
    const { data: inserted, error } = await supabase
      .from('api_keys')
      .insert({
        user_id: userId,
        key_name: keyName,
        key_prefix: keyPrefix,
        hashed_key: hashedKey,
      })
      .select('id, key_name, key_prefix, created_at')
      .single();

    if (error || !inserted) {
      return NextResponse.json(
        { error: error?.message || 'Failed to generate API key' },
        { status: 500 }
      );
    }

    return NextResponse.json({
      success: true,
      key: {
        id: inserted.id,
        name: inserted.key_name,
        prefix: inserted.key_prefix,
        plaintextSecret: rawToken, // Display once in dashboard modal
        createdAt: inserted.created_at,
      },
    });
  }

  // Fallback: local store — persists keys to disk when Supabase is missing.
  const generated = await generateStoredApiKey(userId, keyName);

  return NextResponse.json({
    success: true,
    key: {
      id: generated.id,
      name: generated.key_name,
      prefix: generated.key_prefix,
      plaintextSecret: generated.plaintext_secret,
      createdAt: generated.created_at,
    },
  });
}

/**
 * Revoke an existing API key.
 */
export async function DELETE(req: Request) {
  const userId = await resolveUserId(req);

  const { searchParams } = new URL(req.url);
  const keyId = searchParams.get('id');

  if (!keyId) {
    return NextResponse.json(
      { error: 'Query param "id" is required.' },
      { status: 400 }
    );
  }

  try {
    // Try Supabase first.
    const supabase = getServiceSupabase();
    if (supabase) {
      const { error } = await supabase
        .from('api_keys')
        .delete()
        .eq('id', keyId)
        .eq('user_id', userId);

      if (error) throw new Error(error.message);

      return NextResponse.json({ success: true, revokedId: keyId });
    }

    // Fallback: remove from local store.
    removeStoredKey(userId, keyId);
    return NextResponse.json({ success: true, revokedId: keyId });
  } catch (err) {
    return NextResponse.json(
      { error: (err as Error).message || 'Failed to revoke API key' },
      { status: 500 }
    );
  }
}
