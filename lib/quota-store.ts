// ============================================================================
// PROJECT AEGIS: PERSISTED QUOTA TELEMETRY STORE
// Pure, side-effect-free reducers + validation for the client-side scan quota.
// Every transition is a deterministic function of the previous snapshot, which
// keeps React state updates race-free even under rapid / concurrent events.
// ============================================================================

export const FREE_TIER_SCAN_LIMIT = 50;
export const QUOTA_STORAGE_KEY = 'aegis:quota-v1';
/** Seed shown before localStorage hydration: mirrors a couple of prior scans. */
export const INITIAL_SCAN_COUNT = 2;

export type QuotaTier = 'Free' | 'Enterprise';

export interface QuotaSnapshot {
  tier: QuotaTier;
  dailyScanCount: number;
  maxDailyQuota: number;
  remaining: number;
  /** Epoch ms of the last mutation; used for last-write-wins reconciliation. */
  updatedAt: number;
}

export const DEFAULT_QUOTA_SNAPSHOT: QuotaSnapshot = {
  tier: 'Free',
  dailyScanCount: INITIAL_SCAN_COUNT,
  maxDailyQuota: FREE_TIER_SCAN_LIMIT,
  remaining: FREE_TIER_SCAN_LIMIT - INITIAL_SCAN_COUNT,
  updatedAt: 0,
};

function clampCount(value: number): number {
  if (!Number.isFinite(value)) {
    return INITIAL_SCAN_COUNT;
  }
  return Math.min(Math.max(Math.trunc(value), 0), FREE_TIER_SCAN_LIMIT);
}

function freeSnapshot(count: number, updatedAt: number): QuotaSnapshot {
  const dailyScanCount = clampCount(count);
  return {
    tier: 'Free',
    dailyScanCount,
    maxDailyQuota: FREE_TIER_SCAN_LIMIT,
    remaining: Math.max(0, FREE_TIER_SCAN_LIMIT - dailyScanCount),
    updatedAt,
  };
}

/**
 * Validates and parses a persisted snapshot. Any malformed, missing, or
 * out-of-range field falls back to a safe default rather than crashing.
 */
export function hydrateQuotaSnapshot(raw: string | null): QuotaSnapshot {
  if (!raw) {
    return { ...DEFAULT_QUOTA_SNAPSHOT };
  }

  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) {
      return { ...DEFAULT_QUOTA_SNAPSHOT };
    }

    const candidate = parsed as Partial<Record<keyof QuotaSnapshot, unknown>>;
    const tier: QuotaTier = candidate.tier === 'Enterprise' ? 'Enterprise' : 'Free';
    const updatedAt =
      typeof candidate.updatedAt === 'number' && Number.isFinite(candidate.updatedAt)
        ? candidate.updatedAt
        : 0;

    if (tier === 'Enterprise') {
      const count =
        typeof candidate.dailyScanCount === 'number' && Number.isFinite(candidate.dailyScanCount)
          ? Math.max(0, Math.trunc(candidate.dailyScanCount))
          : 0;
      return {
        tier: 'Enterprise',
        dailyScanCount: count,
        maxDailyQuota: Number.MAX_SAFE_INTEGER,
        remaining: Number.MAX_SAFE_INTEGER,
        updatedAt,
      };
    }

    const count = typeof candidate.dailyScanCount === 'number' ? candidate.dailyScanCount : INITIAL_SCAN_COUNT;
    return freeSnapshot(count, updatedAt);
  } catch {
    return { ...DEFAULT_QUOTA_SNAPSHOT };
  }
}

export function serializeQuotaSnapshot(snapshot: QuotaSnapshot): string {
  return JSON.stringify(snapshot);
}

/** Returns a NEW snapshot after one completed scan. Never mutates the input. */
export function incrementQuotaSnapshot(
  prev: QuotaSnapshot,
  options?: { enterpriseUnlimited?: boolean }
): QuotaSnapshot {
  const enterprise = prev.tier === 'Enterprise' || options?.enterpriseUnlimited === true;
  const updatedAt = Date.now();

  if (enterprise) {
    return {
      tier: 'Enterprise',
      dailyScanCount: Math.max(0, Math.trunc(prev.dailyScanCount)) + 1,
      maxDailyQuota: Number.MAX_SAFE_INTEGER,
      remaining: Number.MAX_SAFE_INTEGER,
      updatedAt,
    };
  }

  if (prev.dailyScanCount >= FREE_TIER_SCAN_LIMIT) {
    return { ...prev, remaining: 0, updatedAt };
  }

  return freeSnapshot(prev.dailyScanCount + 1, updatedAt);
}

/** Grants unlimited Enterprise quota. */
export function upgradeQuotaSnapshot(prev: QuotaSnapshot): QuotaSnapshot {
  return {
    tier: 'Enterprise',
    dailyScanCount: Math.max(0, Math.trunc(prev.dailyScanCount)),
    maxDailyQuota: Number.MAX_SAFE_INTEGER,
    remaining: Number.MAX_SAFE_INTEGER,
    updatedAt: Date.now(),
  };
}

/**
 * Reconciles this tab's snapshot with one received from another tab. Enterprise
 * always wins; otherwise the higher scan count is kept (counts are monotonic,
 * so scans are never lost to a last-write-wins race).
 */
export function reconcileQuotaSnapshots(local: QuotaSnapshot, incoming: QuotaSnapshot): QuotaSnapshot {
  if (local.tier === 'Enterprise' || incoming.tier === 'Enterprise') {
    const elevated =
      local.updatedAt >= incoming.updatedAt
        ? local.tier === 'Enterprise'
          ? local
          : incoming
        : incoming.tier === 'Enterprise'
          ? incoming
          : local;
    return {
      ...elevated,
      tier: 'Enterprise',
      maxDailyQuota: Number.MAX_SAFE_INTEGER,
      remaining: Number.MAX_SAFE_INTEGER,
    };
  }

  const count = Math.max(local.dailyScanCount, incoming.dailyScanCount);
  return freeSnapshot(count, Math.max(local.updatedAt, incoming.updatedAt));
}

export function isQuotaExhausted(snapshot: QuotaSnapshot): boolean {
  return snapshot.tier === 'Free' && snapshot.dailyScanCount >= FREE_TIER_SCAN_LIMIT;
}

export function quotaUsagePercent(snapshot: QuotaSnapshot): number {
  if (snapshot.tier === 'Enterprise') {
    return 100;
  }
  return Math.min(100, Math.round((snapshot.dailyScanCount / FREE_TIER_SCAN_LIMIT) * 100));
}
