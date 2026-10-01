"use client";

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { UserButton } from '@clerk/nextjs';
import { SpotlightCard } from '@/components/ui/spotlight-card';
import { MockCheckoutModal } from '@/components/mock-checkout-modal';
import { QuotaContext, FREE_TIER_SCAN_LIMIT, type DashboardQuotaState } from '@/lib/quota-context';
import {
  Shield,
  Globe,
  Code2,
  Key,
  Menu,
  X,
  ExternalLink,
  Flame,
  Activity,
  Radar,
  GitCommitHorizontal,
  Zap,
  Sparkles,
} from 'lucide-react';

interface QuotaState {
  remaining: number;
  dailyScanCount: number;
  maxDailyQuota: number;
}

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [checkoutOpen, setCheckoutOpen] = useState(false);
  const [tierName, setTierName] = useState('Free Tier');
  const [quota, setQuota] = useState<QuotaState>({
    remaining: 48,
    dailyScanCount: 2,
    maxDailyQuota: 50,
  });

  const isUnlimited = tierName === 'Enterprise Tier';

  // Live scan counter: any page that completes a scan dispatches 'aegis:scan'.
  // Free tier is hard-clamped at 50; Enterprise scans are uncapped.
  useEffect(() => {
    const onScan = () => {
      setQuota((prev) => {
        const newCount = prev.dailyScanCount + 1;
        const cappedCount = isUnlimited ? newCount : Math.min(newCount, FREE_TIER_SCAN_LIMIT);
        return {
          ...prev,
          dailyScanCount: cappedCount,
          remaining: Math.max(0, prev.remaining - (cappedCount - prev.dailyScanCount)),
        };
      });
    };
    window.addEventListener('aegis:scan', onScan);
    return () => window.removeEventListener('aegis:scan', onScan);
  }, [isUnlimited]);

  // Pages dispatch 'aegis:scan-blocked' when the Free-tier limit is hit,
  // which pops the mock checkout modal for an immediate upgrade path.
  useEffect(() => {
    const onScanBlocked = () => {
      if (!isUnlimited && quota.dailyScanCount >= FREE_TIER_SCAN_LIMIT) {
        setCheckoutOpen(true);
      }
    };
    window.addEventListener('aegis:scan-blocked', onScanBlocked);
    return () => window.removeEventListener('aegis:scan-blocked', onScanBlocked);
  }, [isUnlimited, quota.dailyScanCount]);

  // Upgrade flow: Enterprise = unlimited quota display.
  const handleUpgradeSuccess = () => {
    setTierName('Enterprise Tier');
    setQuota((prev) => ({
      ...prev,
      remaining: Number.MAX_SAFE_INTEGER,
      maxDailyQuota: Number.MAX_SAFE_INTEGER,
    }));
  };

  const navItems = [
    {
      name: 'SafeLink URL Inspector',
      href: '/dashboard/url-inspector',
      icon: Globe,
      badge: 'SSRF Safe',
    },
    {
      name: 'GitShield Code Auditor',
      href: '/dashboard/code-auditor',
      icon: Code2,
      badge: 'Entropy + Regex',
    },
    {
      name: 'Developer API Keys',
      href: '/dashboard/api-keys',
      icon: Key,
      badge: 'CLI Hook',
    },
  ];

  const quotaPercent = isUnlimited
    ? 100
    : Math.min(100, Math.round((quota.dailyScanCount / quota.maxDailyQuota) * 100));

  // Quota snapshot shared with dashboard pages via context.
  const quotaContextValue: DashboardQuotaState = {
    tier: isUnlimited ? 'Enterprise' : 'Free',
    dailyScanCount: quota.dailyScanCount,
    maxDailyQuota: quota.maxDailyQuota,
    remaining: quota.remaining,
    quotaExhausted: !isUnlimited && quota.dailyScanCount >= FREE_TIER_SCAN_LIMIT,
  };

  // Cyber Bento Grid: headline defense metrics in spotlight cards.
  const bentoCards = [
    {
      title: 'Live Threat Defenses',
      value: '27',
      unit: 'SIGNATURES ARMED',
      icon: Radar,
      glowColor: '#22d3ee', // cyan
      accent: 'text-cyan-400',
      desc: 'Regex + Shannon entropy engines patrolling every payload.',
    },
    {
      title: 'Pre-Commit Hooks',
      value: 'aegis.py',
      unit: 'ZERO-DEP CLI GUARD',
      icon: GitCommitHorizontal,
      glowColor: '#34d399', // emerald
      accent: 'text-emerald-400',
      desc: 'Blocks leaked secrets before they ever reach the remote.',
    },
    {
      title: 'SSRF Interceptions',
      value: 'ACTIVE',
      unit: 'PER-HOP ENFORCEMENT',
      icon: Zap,
      glowColor: '#818cf8', // indigo
      accent: 'text-indigo-400',
      desc: 'Private, metadata & loopback destinations hard-blocked.',
    },
  ];

  return (
    <div className="min-h-screen bg-[#030712] text-slate-100 flex flex-col md:flex-row antialiased">
      {/* Mobile Top Header */}
      <header className="md:hidden flex items-center justify-between px-4 py-3 bg-[#060b18] border-b border-slate-800">
        <Link href="/dashboard/url-inspector" className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <span className="font-bold text-white tracking-wide text-sm">AEGIS</span>
        </Link>
        <div className="flex items-center gap-3">
          <UserButton afterSignOutUrl="/" />
          <button
            onClick={() => setMobileNavOpen(!mobileNavOpen)}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300"
          >
            {mobileNavOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </header>

      {/* Sidebar Navigation */}
      <aside
        className={`fixed md:sticky top-0 h-screen w-64 bg-[#050a16] border-r border-slate-800/80 flex flex-col justify-between z-40 transition-transform duration-300 ${
          mobileNavOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
        }`}
      >
        <div>
          {/* Logo & Brand */}
          <div className="p-5 border-b border-slate-800/80 flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 via-sky-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/25">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="font-extrabold text-white tracking-wider text-base flex items-center gap-1.5">
                PROJECT AEGIS
              </div>
              <span className="text-[10px] text-cyan-400 font-mono tracking-wide block">
                CYBER DEFENSE PLATFORM
              </span>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="p-3 space-y-1">
            <span className="text-[10px] uppercase font-bold text-slate-400 px-3 tracking-wider block mb-2">
              Security Engines
            </span>

            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={() => setMobileNavOpen(false)}
                  className={`flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-semibold transition ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/10 text-cyan-400 border border-cyan-500/30'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                    <span>{item.name}</span>
                  </div>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Bottom Section: Quota & User Profile */}
        <div className="p-4 border-t border-slate-800/80 space-y-4">
          {/* Daily Quota Tracker */}
          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="flex justify-between items-center text-xs mb-1.5">
              <span className="text-slate-400 font-medium flex items-center gap-1">
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                Daily Scan Quota
              </span>
              <span className="font-mono text-cyan-400 text-[11px] font-semibold">
                {isUnlimited ? 'Unlimited (∞ / ∞)' : `${quota.dailyScanCount} / ${quota.maxDailyQuota}`}
              </span>
            </div>

            <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-emerald-400 transition-all duration-500"
                style={{ width: `${quotaPercent}%` }}
              />
            </div>
            <div className="text-[10px] text-slate-400 mt-1.5 flex justify-between">
              <span className={isUnlimited ? 'text-amber-400 font-semibold' : ''}>{tierName}</span>
              <span>Resets in 24h</span>
            </div>

            {/* Upgrade Tier (opens mock checkout) */}
            {!isUnlimited && (
              <button
                onClick={() => setCheckoutOpen(true)}
                className="mt-2.5 w-full flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 text-slate-950 text-[11px] font-extrabold uppercase tracking-wide transition shadow-lg shadow-amber-500/20"
              >
                <Sparkles className="w-3.5 h-3.5" />
                Upgrade Tier
              </button>
            )}
          </div>

          {/* Desktop User Section */}
          <div className="hidden md:flex items-center justify-between pt-1">
            <div className="flex items-center gap-2.5">
              <UserButton afterSignOutUrl="/" />
              <div className="text-xs">
                <span className="text-slate-300 font-semibold block leading-tight">My Workspace</span>
                <span className="text-[10px] text-emerald-400 font-mono">● Live Protection</span>
              </div>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 min-h-screen overflow-x-hidden p-4 sm:p-6 md:p-8">
        <div className="max-w-6xl mx-auto space-y-6">
          <QuotaContext.Provider value={quotaContextValue}>
          {/* Cyber Bento Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">            {bentoCards.map((card) => {
              const Icon = card.icon;
              return (
                <SpotlightCard key={card.title} glowColor={card.glowColor}>
                  <div className="p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <div
                        className="w-9 h-9 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-center"
                        style={{ boxShadow: `0 0 14px ${card.glowColor}33` }}
                      >
                        <Icon className={`h-4 w-4 ${card.accent}`} />
                      </div>
                      <span className="text-[9px] font-mono uppercase tracking-widest text-slate-500">
                        {card.unit}
                      </span>
                    </div>

                    <div>
                      <div className={`font-mono font-extrabold text-2xl tracking-tight ${card.accent}`}>
                        {card.value}
                      </div>
                      <div className="text-sm font-bold text-white mt-0.5">{card.title}</div>
                    </div>

                    <p className="text-[11px] text-slate-400 leading-relaxed">{card.desc}</p>
                  </div>
                </SpotlightCard>
              );
            })}
          </div>

          {children}
          </QuotaContext.Provider>
        </div>
      </main>

      {/* Mock Enterprise Checkout */}
      <MockCheckoutModal
        isOpen={checkoutOpen}
        onClose={() => setCheckoutOpen(false)}
        onSuccess={handleUpgradeSuccess}
      />
    </div>
  );
}
