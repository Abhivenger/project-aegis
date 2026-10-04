"use client";

import React, { createContext, useContext, useMemo } from 'react';

// ============================================================================
// PROJECT AEGIS: APPLICATION AUTH CONTEXT
// Provides a single source of truth for whether Clerk is active, plus a local
// fallback operator identity used when the app runs without a real Clerk key.
// ============================================================================

export interface AppUserProfile {
  displayName: string;
  email: string;
  initials: string;
}

export interface AppAuthState {
  /** True only when a valid Clerk provider is mounted. */
  clerkEnabled: boolean;
  /** Local fallback identity; null while Clerk is authoritative. */
  user: AppUserProfile | null;
}

export const LOCAL_OPERATOR: AppUserProfile = {
  displayName: 'Local Operator',
  email: 'operator@aegis.local',
  initials: 'LO',
};

const AppAuthContext = createContext<AppAuthState>({
  clerkEnabled: false,
  user: LOCAL_OPERATOR,
});

export function AppAuthProvider({
  clerkEnabled,
  children,
}: {
  clerkEnabled: boolean;
  children: React.ReactNode;
}) {
  const value = useMemo<AppAuthState>(
    () => ({ clerkEnabled, user: clerkEnabled ? null : LOCAL_OPERATOR }),
    [clerkEnabled]
  );

  return <AppAuthContext.Provider value={value}>{children}</AppAuthContext.Provider>;
}

export function useAppAuth(): AppAuthState {
  return useContext(AppAuthContext);
}
