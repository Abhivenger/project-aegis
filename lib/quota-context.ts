"use client";

import { createContext, useContext } from 'react';

/** Hard scan cap for the Free tier. Enterprise bypasses this entirely. */
export const FREE_TIER_SCAN_LIMIT = 50;

export interface DashboardQuotaState {
  /** 'Free' is subject to the 50-scan cap; 'Enterprise' is unlimited. */
  tier: 'Free' | 'Enterprise';
  dailyScanCount: number;
  maxDailyQuota: number;
  remaining: number;
  /** True only when tier !== 'Enterprise' AND dailyScanCount >= FREE_TIER_SCAN_LIMIT. */
  quotaExhausted: boolean;
}

/**
 * Live quota state owned by app/dashboard/layout.tsx and consumed by the
 * dashboard pages to enforce the Free-tier limit before sending scan requests.
 * Null only if a consumer renders outside the dashboard layout.
 */
export const QuotaContext = createContext<DashboardQuotaState | null>(null);

export function useDashboardQuota(): DashboardQuotaState | null {
  return useContext(QuotaContext);
}
