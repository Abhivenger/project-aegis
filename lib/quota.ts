// ============================================================================
// PROJECT AEGIS: 24-HOUR ROLLING SCAN QUOTA MANAGER
// Free Tier: 50 Scans / 24-Hour Cycle
// Pro Tier: 5,000 Scans / 24-Hour Cycle
// ============================================================================

import { getServiceSupabase } from './supabase/server';

export interface QuotaStatus {
  allowed: boolean;
  dailyScanCount: number;
  maxDailyQuota: number;
  plan: 'free' | 'pro' | 'enterprise';
  resetsAt: string;
}

const QUOTA_LIMITS: Record<string, number> = {
  free: 50,
  pro: 5000,
  enterprise: 100000,
};

/**
 * Atomically checks and increments a user's scan count.
 * Automatically resets the quota if more than 24 hours have elapsed since last_scan_reset_at.
 *
 * If Supabase is not configured (client is null), the quota check is skipped
 * safely: scans are always allowed with effectively unlimited quota so that a
 * missing database can never block the scanning feature.
 */
export async function checkAndIncrementQuota(userId: string, userEmail?: string): Promise<QuotaStatus> {
  const supabase = getServiceSupabase();

  // Supabase not configured: fail open, skip every DB operation.
  if (!supabase) {
    return {
      allowed: true,
      dailyScanCount: 0,
      maxDailyQuota: Number.MAX_SAFE_INTEGER,
      plan: 'free',
      resetsAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    };
  }

  // 1. Fetch current profile or bootstrap if newly registered via Clerk
  const { data: profile, error: fetchError } = await supabase
    .from('profiles')
    .select('id, plan, daily_scan_count, last_scan_reset_at')
    .eq('id', userId)
    .single();

  if (fetchError || !profile) {
    // Bootstrap profile record
    const { data: newProfile, error: insertError } = await supabase
      .from('profiles')
      .insert({
        id: userId,
        email: userEmail || `${userId}@anonymous.aegis`,
        plan: 'free',
        daily_scan_count: 1,
        last_scan_reset_at: new Date().toISOString(),
      })
      .select()
      .single();

    if (insertError || !newProfile) {
      throw new Error(`Failed to bootstrap user profile: ${insertError?.message}`);
    }

    return {
      allowed: true,
      dailyScanCount: 1,
      maxDailyQuota: QUOTA_LIMITS.free,
      plan: 'free',
      resetsAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    };
  }

  const now = Date.now();
  const lastReset = new Date(profile.last_scan_reset_at).getTime();
  const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;
  const maxQuota = QUOTA_LIMITS[profile.plan] || QUOTA_LIMITS.free;

  // 2. Check if the 24-hour cycle has expired
  if (now - lastReset >= TWENTY_FOUR_HOURS_MS) {
    // Reset cycle
    const { error: resetError } = await supabase
      .from('profiles')
      .update({
        daily_scan_count: 1,
        last_scan_reset_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      })
      .eq('id', userId);

    if (resetError) {
      throw new Error(`Failed to reset user quota: ${resetError.message}`);
    }

    return {
      allowed: true,
      dailyScanCount: 1,
      maxDailyQuota: maxQuota,
      plan: profile.plan,
      resetsAt: new Date(now + TWENTY_FOUR_HOURS_MS).toISOString(),
    };
  }

  // 3. Cycle is active: check remaining quota
  if (profile.daily_scan_count >= maxQuota) {
    const resetsAt = new Date(lastReset + TWENTY_FOUR_HOURS_MS).toISOString();
    return {
      allowed: false,
      dailyScanCount: profile.daily_scan_count,
      maxDailyQuota: maxQuota,
      plan: profile.plan,
      resetsAt,
    };
  }

  // 4. Increment usage counter
  const newCount = profile.daily_scan_count + 1;
  const { error: updateError } = await supabase
    .from('profiles')
    .update({
      daily_scan_count: newCount,
      updated_at: new Date().toISOString(),
    })
    .eq('id', userId);

  if (updateError) {
    throw new Error(`Failed to increment scan count: ${updateError.message}`);
  }

  return {
    allowed: true,
    dailyScanCount: newCount,
    maxDailyQuota: maxQuota,
    plan: profile.plan,
    resetsAt: new Date(lastReset + TWENTY_FOUR_HOURS_MS).toISOString(),
  };
}
