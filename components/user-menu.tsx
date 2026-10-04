"use client";

import React from "react";
import { UserButton } from "@clerk/nextjs";
import { LOCAL_OPERATOR, useAppAuth } from "@/lib/auth/app-auth";

/**
 * Renders Clerk's native account button when a real Clerk provider is active,
 * and a static local-operator badge otherwise. This keeps the dashboard fully
 * renderable without a Clerk publishable key (and never mounts Clerk UI or its
 * client script when Clerk is disabled).
 *
 * `compact` renders the avatar only (used in the mobile header).
 * Full mode also renders the workspace/identity label.
 */
export function UserMenu({ compact = false }: { compact?: boolean }) {
  const { clerkEnabled, user } = useAppAuth();

  if (clerkEnabled) {
    return (
      <div className="flex items-center gap-2.5">
        <UserButton afterSignOutUrl="/" />
        {!compact && (
          <div className="text-xs leading-tight">
            <span className="text-slate-300 font-semibold block">My Workspace</span>
            <span className="text-[10px] text-emerald-400 font-mono">● Live Protection</span>
          </div>
        )}
      </div>
    );
  }

  const profile = user ?? LOCAL_OPERATOR;

  return (
    <div
      className="flex items-center gap-2.5"
      title={`${profile.displayName} <${profile.email}> — local fallback identity`}
    >
      <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-emerald-500 to-cyan-500 text-slate-950 font-extrabold text-[10px] flex items-center justify-center shadow-lg shadow-emerald-500/20">
        {profile.initials}
      </div>
      {!compact && (
        <div className="text-xs leading-tight">
          <span className="text-slate-300 font-semibold block">{profile.displayName}</span>
          <span className="text-[10px] text-amber-400 font-mono">● Local Mode</span>
        </div>
      )}
    </div>
  );
}
