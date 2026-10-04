// ============================================================================
// PROJECT AEGIS: DEVELOPER API KEY MANAGEMENT (CRUD)
// ============================================================================

import { NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { randomBytes, createHash } from 'crypto';
import { getServiceSupabase } from '@/lib/supabase/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Resolves the Clerk session user id defensively. When Clerk is not configured
 * (or its middleware is bypassed in local mode) `auth()` can throw; we treat
 * any failure as an unauthenticated request instead of a 500 error.
 */
async function getClerkUserId(): Promise<string | null> {
  try {
    const session = await auth();
    return session?.userId ?? null;
  } catch {
    return null;
  }
}

/**
 * List active API keys for the authenticated session.
 */
export async function GET() {
  const userId = await getClerkUserId();
  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const supabase = getServiceSupabase();
  if (!supabase) {
    return NextResponse.json(
      { error: 'Service Unavailable: Supabase is not configured.' },
      { status: 503 }
    );
  }
  const { data: keys, error } = await supabase
    .from('api_keys')
    .select('id, key_name, key_prefix, last_used_at, created_at')
    .eq('user_id', userId)
    .order('created_at', { ascending: false });

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ success: true, keys });
}

/**
 * Generate a new developer API key with one-time plaintext reveal.
 */
export async function POST(req: Request) {
  const userId = await getClerkUserId();
  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const body = await req.json().catch(() => ({}));
  const keyName =
    typeof body.name === 'string' && body.name.trim().length > 0
      ? body.name.trim()
      : 'Default Pre-Commit Hook Key';

  // Format: aegis_live_ + 48 hex characters
  const rawToken = `aegis_live_${randomBytes(24).toString('hex')}`;
  const keyPrefix = rawToken.slice(0, 19); // aegis_live_ + first 8 characters
  const hashedKey = createHash('sha256').update(rawToken).digest('hex');

  const supabase = getServiceSupabase();
  if (!supabase) {
    return NextResponse.json(
      { error: 'Service Unavailable: Supabase is not configured.' },
      { status: 503 }
    );
  }
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
    return NextResponse.json({ error: error?.message || 'Database error' }, { status: 500 });
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

/**
 * Revoke an existing API key.
 */
export async function DELETE(req: Request) {
  const userId = await getClerkUserId();
  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { searchParams } = new URL(req.url);
  const keyId = searchParams.get('id');

  if (!keyId) {
    return NextResponse.json({ error: 'Query param "id" is required.' }, { status: 400 });
  }

  const supabase = getServiceSupabase();
  if (!supabase) {
    return NextResponse.json(
      { error: 'Service Unavailable: Supabase is not configured.' },
      { status: 503 }
    );
  }
  const { error } = await supabase
    .from('api_keys')
    .delete()
    .eq('id', keyId)
    .eq('user_id', userId);

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ success: true, revokedId: keyId });
}
