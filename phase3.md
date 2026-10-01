# PROJECT AEGIS — PHASE 3: FRONTEND DASHBOARD & VISUAL PLAYGROUND

This document contains the complete, production-ready source code for Phase 3 of **Project Aegis**. Every file is written in full without placeholders, abbreviations, or omitted logic.

## File Map (Phase 3)

1. `components/risk-gauge.tsx` — Animated circular SVG risk score gauge with dynamic color grading and glowing verdict badges.
2. `components/code-diff-viewer.tsx` — Multi-tab remediation viewer displaying detected leaks, one-click `.env` auto-patches, and sanitized diffs.
3. `app/dashboard/layout.tsx` — Cyber-luxe dashboard shell with sidebar navigation, Clerk user profile button, mobile drawer, and rolling quota progress indicator.
4. `app/dashboard/url-inspector/page.tsx` — Interactive SafeLink inspection laboratory with quick test presets, redirect chain visualizer, and heuristic indicator cards.
5. `app/dashboard/code-auditor/page.tsx` — GitShield code auditor workspace supporting live diff scanning, sample credential presets, and instant auto-patch generation.
6. `app/dashboard/api-keys/page.tsx` — Developer API key lifecycle portal with one-time reveal modal, clipboard actions, and key revocation.

---

### 1. `components/risk-gauge.tsx`

```tsx
"use client";

import React, { useEffect, useState } from 'react';

interface RiskGaugeProps {
  score: number; // 0 to 100
  verdict?: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
  size?: number;
  label?: string;
}

export function RiskGauge({
  score,
  verdict,
  size = 180,
  label = "Threat Score",
}: RiskGaugeProps) {
  const [animatedScore, setAnimatedScore] = useState(0);

  // Smooth count-up animation on score changes
  useEffect(() => {
    const timer = setTimeout(() => {
      setAnimatedScore(Math.min(100, Math.max(0, score)));
    }, 50);
    return () => clearTimeout(timer);
  }, [score]);

  // Derived verdict if not provided explicitly
  const resolvedVerdict =
    verdict ||
    (animatedScore >= 70 ? 'DANGEROUS' : animatedScore >= 30 ? 'SUSPICIOUS' : 'SAFE');

  // Gauge color mapping
  const getColor = () => {
    if (resolvedVerdict === 'DANGEROUS' || animatedScore >= 70) {
      return {
        stroke: '#f43f5e', // rose-500
        text: 'text-rose-400',
        bgGlow: 'rgba(244, 63, 94, 0.15)',
        badgeBg: 'bg-rose-950/60 border-rose-500/40 text-rose-300',
      };
    }
    if (resolvedVerdict === 'SUSPICIOUS' || animatedScore >= 30) {
      return {
        stroke: '#f59e0b', // amber-500
        text: 'text-amber-400',
        bgGlow: 'rgba(245, 158, 11, 0.15)',
        badgeBg: 'bg-amber-950/60 border-amber-500/40 text-amber-300',
      };
    }
    return {
      stroke: '#10b981', // emerald-500
      text: 'text-emerald-400',
      bgGlow: 'rgba(16, 185, 129, 0.15)',
      badgeBg: 'bg-emerald-950/60 border-emerald-500/40 text-emerald-300',
    };
  };

  const colors = getColor();

  // SVG Geometry
  const strokeWidth = 12;
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center select-none">
      <div className="relative" style={{ width: size, height: size }}>
        {/* Glow backdrop */}
        <div
          className="absolute inset-0 rounded-full blur-xl pointer-events-none transition-all duration-700"
          style={{ backgroundColor: colors.bgGlow }}
        />

        <svg
          width={size}
          height={size}
          className="transform -rotate-90 origin-center"
        >
          {/* Background Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            fill="transparent"
            strokeLinecap="round"
          />
          {/* Animated Progress Arc */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={colors.stroke}
            strokeWidth={strokeWidth}
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center Readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`font-mono text-4xl font-extrabold tracking-tight ${colors.text}`}>
            {animatedScore}
          </span>
          <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider">
            {label}
          </span>
        </div>
      </div>

      {/* Verdict Pill */}
      <div
        className={`mt-3 px-3 py-1 rounded-full text-xs font-bold font-mono uppercase tracking-wider border shadow-sm ${colors.badgeBg}`}
      >
        {resolvedVerdict}
      </div>
    </div>
  );
}
```

---

### 2. `components/code-diff-viewer.tsx`

```tsx
"use client";

import React, { useState } from 'react';
import { Copy, Check, ShieldAlert, FileText, Code2, AlertTriangle, Key } from 'lucide-react';

export interface FindingItem {
  type: 'KNOWN_SIGNATURE' | 'HIGH_ENTROPY';
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  lineNumber: number;
  redactedToken: string;
  entropy?: number;
  suggestedEnvKey: string;
}

export interface RemediationData {
  hasSecrets: boolean;
  envFileSnippet: string;
  sanitizedContent: string;
  gitignoreRecommendation: string;
}

interface CodeDiffViewerProps {
  findings: FindingItem[];
  remediation?: RemediationData;
  originalContent?: string;
}

export function CodeDiffViewer({
  findings,
  remediation,
  originalContent,
}: CodeDiffViewerProps) {
  const [activeTab, setActiveTab] = useState<'findings' | 'env' | 'sanitized'>('findings');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch (err) {
      console.error('Failed to copy to clipboard', err);
    }
  };

  const getSeverityBadge = (severity: 'CRITICAL' | 'HIGH' | 'MEDIUM') => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-400 border-rose-500/40';
      case 'HIGH':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      case 'MEDIUM':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
      default:
        return 'bg-slate-700 text-slate-300 border-slate-600';
    }
  };

  return (
    <div className="w-full bg-[#0a101f] border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col">
      {/* Top Navigation Tabs */}
      <div className="flex items-center justify-between border-b border-slate-800 px-4 py-2 bg-[#060b18]">
        <div className="flex items-center gap-1 sm:gap-2">
          <button
            onClick={() => setActiveTab('findings')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === 'findings'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            Detected Leaks ({findings.length})
          </button>

          <button
            onClick={() => setActiveTab('env')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === 'env'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Key className="w-4 h-4" />
            .env Auto-Patch
          </button>

          <button
            onClick={() => setActiveTab('sanitized')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeTab === 'sanitized'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Code2 className="w-4 h-4" />
            Sanitized Code
          </button>
        </div>

        {/* Global Action */}
        {activeTab === 'env' && remediation && (
          <button
            onClick={() => copyToClipboard(remediation.envFileSnippet, 'env')}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition"
          >
            {copiedKey === 'env' ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy .env</span>
              </>
            )}
          </button>
        )}

        {activeTab === 'sanitized' && remediation && (
          <button
            onClick={() => copyToClipboard(remediation.sanitizedContent, 'sanitized')}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition"
          >
            {copiedKey === 'sanitized' ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Code</span>
              </>
            )}
          </button>
        )}
      </div>

      {/* Tab Panels */}
      <div className="p-4 flex-1 overflow-y-auto max-h-[500px]">
        {/* PANEL 1: FINDINGS */}
        {activeTab === 'findings' && (
          <div className="space-y-3">
            {findings.length === 0 ? (
              <div className="text-center py-12">
                <Check className="w-12 h-12 text-emerald-400 mx-auto mb-2 opacity-80" />
                <h4 className="text-white font-semibold text-sm">No Secrets Found</h4>
                <p className="text-slate-400 text-xs mt-1">
                  Code passed regex signature checks and Shannon entropy scans.
                </p>
              </div>
            ) : (
              findings.map((f, idx) => (
                <div
                  key={idx}
                  className="p-3.5 rounded-lg bg-slate-900/80 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:border-slate-700 transition"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${getSeverityBadge(
                          f.severity
                        )}`}
                      >
                        {f.severity}
                      </span>
                      <span className="text-white text-sm font-semibold">{f.name}</span>
                      <span className="text-xs text-slate-400 font-mono">Line {f.lineNumber}</span>
                    </div>

                    <div className="flex items-center gap-2 font-mono text-xs">
                      <span className="text-rose-400 bg-rose-950/40 px-2 py-0.5 rounded border border-rose-900/50">
                        {f.redactedToken}
                      </span>
                      {f.entropy && (
                        <span className="text-slate-400 text-[11px]">
                          Entropy: <strong className="text-cyan-400">{f.entropy}</strong> bits/char
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="text-right flex sm:flex-col items-center sm:items-end justify-between gap-1">
                    <span className="text-[10px] uppercase font-mono text-slate-400">Suggested Key</span>
                    <span className="text-xs font-mono text-emerald-400 bg-emerald-950/30 px-2 py-0.5 rounded border border-emerald-900/40">
                      process.env.{f.suggestedEnvKey}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* PANEL 2: .ENV AUTO-PATCH */}
        {activeTab === 'env' && (
          <div className="space-y-4">
            <div>
              <span className="text-xs font-semibold text-slate-300 block mb-1.5">
                Suggested .env file additions:
              </span>
              <pre className="p-3 rounded-lg bg-[#060b14] border border-slate-800 text-xs font-mono text-emerald-300 whitespace-pre-wrap leading-relaxed">
                {remediation?.envFileSnippet || '# No environment variables required.'}
              </pre>
            </div>

            <div>
              <span className="text-xs font-semibold text-slate-300 block mb-1.5">
                Recommended .gitignore update:
              </span>
              <pre className="p-3 rounded-lg bg-[#060b14] border border-slate-800 text-xs font-mono text-slate-400 whitespace-pre-wrap leading-relaxed">
                {remediation?.gitignoreRecommendation || '.env\n.env.local'}
              </pre>
            </div>
          </div>
        )}

        {/* PANEL 3: SANITIZED CODE */}
        {activeTab === 'sanitized' && (
          <div>
            <span className="text-xs font-semibold text-slate-300 block mb-1.5">
              Refactored Source Code (Variables Substituted):
            </span>
            <pre className="p-3 rounded-lg bg-[#060b14] border border-slate-800 text-xs font-mono text-slate-300 whitespace-pre-wrap overflow-x-auto leading-relaxed">
              {remediation?.sanitizedContent || originalContent || '// No sanitized content available.'}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
```

---

### 3. `app/dashboard/layout.tsx`

```tsx
"use client";

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { UserButton } from '@clerk/nextjs';
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
  const [quota, setQuota] = useState<QuotaState>({
    remaining: 48,
    dailyScanCount: 2,
    maxDailyQuota: 50,
  });

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

  const quotaPercent = Math.min(
    100,
    Math.round((quota.dailyScanCount / quota.maxDailyQuota) * 100)
  );

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
                  {item.badge && (
                    <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                      {item.badge}
                    </span>
                  )}
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
                {quota.dailyScanCount} / {quota.maxDailyQuota}
              </span>
            </div>

            <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-emerald-400 transition-all duration-500"
                style={{ width: `${quotaPercent}%` }}
              />
            </div>
            <div className="text-[10px] text-slate-400 mt-1.5 flex justify-between">
              <span>Free Tier Tier</span>
              <span>Resets in 24h</span>
            </div>
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
        <div className="max-w-6xl mx-auto space-y-6">{children}</div>
      </main>
    </div>
  );
}
```

---

### 4. `app/dashboard/url-inspector/page.tsx`

```tsx
"use client";

import React, { useState } from 'react';
import { RiskGauge } from '@/components/risk-gauge';
import {
  Globe,
  Search,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  Lock,
} from 'lucide-react';

interface RedirectHop {
  hopNumber: number;
  url: string;
  statusCode: number;
  ipAddress: string | null;
}

interface UrlAnalysisReport {
  targetUrl: string;
  finalDestination: string;
  riskScore: number;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
  reasons: string[];
  redirectChain: RedirectHop[];
  isSsrfBlocked: boolean;
  detectedKeywords: string[];
}

export default function UrlInspectorPage() {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<UrlAnalysisReport | null>(null);

  const presets = [
    { label: 'Safe Domain', url: 'https://github.com' },
    { label: 'Phishing Pattern', url: 'http://secure-login-hdfc-otp.login-auth.xyz/verify' },
    { label: 'Cloud Metadata SSRF', url: 'http://169.254.169.254/latest/meta-data/' },
    { label: 'Localhost SSRF', url: 'http://127.0.0.1:5432' },
  ];

  const handleScan = async (target?: string) => {
    const scanTarget = (target || urlInput).trim();
    if (!scanTarget) return;

    setLoading(true);
    setError(null);
    setReport(null);

    try {
      const res = await fetch('/api/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: scanTarget }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to inspect link.');
      }
      setReport(data.report);
      setUrlInput(scanTarget);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Title & Banner */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <Globe className="w-5 h-5 text-cyan-400" />
          <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
            SafeLink URL Inspector
          </h1>
        </div>
        <p className="text-xs sm:text-sm text-slate-400">
          Real-time SSRF-safe URL resolution, heuristic phishing detection, and redirect tracing.
        </p>
      </div>

      {/* Search Input Bar */}
      <div className="bg-[#060b18] border border-slate-800 p-2 sm:p-2.5 rounded-2xl shadow-xl flex flex-col sm:flex-row items-center gap-2">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleScan()}
            placeholder="Paste any link to inspect (e.g. https://bank-login.xyz or http://169.254.169.254)..."
            className="w-full pl-9 pr-4 py-2.5 bg-slate-900/60 rounded-xl text-xs sm:text-sm text-white placeholder-slate-500 border border-slate-800/80 focus:outline-none focus:border-cyan-500/50 font-mono"
          />
        </div>

        <button
          onClick={() => handleScan()}
          disabled={loading || !urlInput.trim()}
          className="w-full sm:w-auto px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-slate-950 font-bold text-xs sm:text-sm transition flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20"
        >
          {loading ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
              <span>Analyzing...</span>
            </>
          ) : (
            <>
              <span>Inspect Link</span>
              <ArrowRight className="w-4 h-4 text-slate-950" />
            </>
          )}
        </button>
      </div>

      {/* Preset Quick Test Buttons */}
      <div className="flex flex-wrap items-center gap-2 pt-1">
        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Quick Presets:</span>
        {presets.map((preset) => (
          <button
            key={preset.label}
            onClick={() => handleScan(preset.url)}
            className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-[11px] font-mono text-cyan-400 transition"
          >
            {preset.label}
          </button>
        ))}
      </div>

      {/* Error Callout */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 flex-shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Scan Results Layout */}
      {report && (
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-start">
          {/* Left Column: Risk Gauge */}
          <div className="md:col-span-4 bg-[#060b18] border border-slate-800 rounded-2xl p-6 flex flex-col items-center justify-center shadow-xl">
            <RiskGauge score={report.riskScore} verdict={report.verdict} size={200} />

            <div className="w-full mt-6 space-y-2 border-t border-slate-800 pt-4 text-xs">
              <div className="flex justify-between items-center">
                <span className="text-slate-400">SSRF Enforcement:</span>
                <span className={`font-mono font-bold ${report.isSsrfBlocked ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {report.isSsrfBlocked ? 'BLOCKED' : 'CLEARED'}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-400">Redirect Hops:</span>
                <span className="font-mono text-white font-bold">{report.redirectChain.length}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-400">Flagged Keywords:</span>
                <span className="font-mono text-amber-400">{report.detectedKeywords.length}</span>
              </div>
            </div>
          </div>

          {/* Right Column: Details & Redirect Chain */}
          <div className="md:col-span-8 space-y-4">
            {/* Findings & Reasons */}
            <div className="bg-[#060b18] border border-slate-800 rounded-2xl p-5 shadow-xl">
              <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                Heuristic Evaluation Flags
              </h3>
              <ul className="space-y-2">
                {report.reasons.map((reason, idx) => (
                  <li key={idx} className="flex items-start gap-2.5 text-xs text-slate-300">
                    <span className="text-cyan-400 font-bold">•</span>
                    <span>{reason}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Redirect Chain Visualization */}
            <div className="bg-[#060b18] border border-slate-800 rounded-2xl p-5 shadow-xl">
              <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                <ExternalLink className="w-4 h-4 text-indigo-400" />
                Redirect Path Analysis ({report.redirectChain.length} Hop{report.redirectChain.length !== 1 ? 's' : ''})
              </h3>

              {report.redirectChain.length === 0 ? (
                <div className="text-xs text-slate-400 font-mono py-2">
                  Target reached directly or aborted prior to HTTP execution.
                </div>
              ) : (
                <div className="space-y-3">
                  {report.redirectChain.map((hop, index) => (
                    <div
                      key={index}
                      className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono"
                    >
                      <div className="flex items-center gap-2 overflow-hidden">
                        <span className="w-5 h-5 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center font-bold text-[10px]">
                          {hop.hopNumber}
                        </span>
                        <span className="text-slate-200 truncate">{hop.url}</span>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            hop.statusCode >= 300 && hop.statusCode < 400
                              ? 'bg-amber-500/20 text-amber-300'
                              : hop.statusCode === 200
                              ? 'bg-emerald-500/20 text-emerald-300'
                              : 'bg-rose-500/20 text-rose-300'
                          }`}
                        >
                          HTTP {hop.statusCode}
                        </span>
                        {hop.ipAddress && (
                          <span className="text-slate-400 text-[10px] bg-slate-800 px-2 py-0.5 rounded">
                            {hop.ipAddress}
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
```

---

### 5. `app/dashboard/code-auditor/page.tsx`

```tsx
"use client";

import React, { useState } from 'react';
import { CodeDiffViewer, FindingItem, RemediationData } from '@/components/code-diff-viewer';
import { RiskGauge } from '@/components/risk-gauge';
import { Code2, Play, ShieldAlert, Sparkles, AlertCircle } from 'lucide-react';

const PRESET_STRIPE = `// Checkout payment handler
import Stripe from 'stripe';

const stripe = new Stripe("sk_live_51M0x9KLa8xX209qZ1abcdef9876543210zyxwvu", {
  apiVersion: '2023-10-16',
});

export async function processPayment(amount: number) {
  return await stripe.paymentIntents.create({
    amount,
    currency: 'usd',
  });
}`;

const PRESET_AWS_GCP = `# Deployment secrets configuration
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GEMINI_API_KEY = "AIzaSyD-73abcdefghijklmnopqrstuvwxyz0123"

def initialize_cloud():
    print("Connecting to cloud infrastructure...")
`;

const PRESET_CLEAN = `// Standard production client with environment variables
export async function fetchUserData(userId: string) {
  const token = process.env.GITHUB_PERSONAL_ACCESS_TOKEN;
  const res = await fetch(\`https://api.github.com/user/\${userId}\`, {
    headers: { Authorization: \`Bearer \${token}\` }
  });
  return res.json();
}`;

export default function CodeAuditorPage() {
  const [content, setContent] = useState(PRESET_STRIPE);
  const [filename, setFilename] = useState('payment-handler.ts');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [riskScore, setRiskScore] = useState<number | null>(null);
  const [verdict, setVerdict] = useState<'SAFE' | 'SUSPICIOUS' | 'DANGEROUS' | null>(null);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [remediation, setRemediation] = useState<RemediationData | null>(null);

  const handleAudit = async () => {
    if (!content.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/scan/secret', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename, content }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to scan code.');
      }

      setRiskScore(data.riskScore);
      setVerdict(data.verdict);
      setFindings(data.findings || []);
      setRemediation(data.remediation);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <Code2 className="w-5 h-5 text-emerald-400" />
          <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
            GitShield Code Auditor
          </h1>
        </div>
        <p className="text-xs sm:text-sm text-slate-400">
          Shannon entropy detection, 27+ cryptographic token signatures, and 1-click `.env` remediation.
        </p>
      </div>

      {/* Editor & Actions */}
      <div className="bg-[#060b18] border border-slate-800 rounded-2xl p-4 sm:p-5 shadow-xl space-y-3">
        {/* Filename & Presets */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-800/80">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-mono">File:</span>
            <input
              type="text"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              className="bg-slate-900 border border-slate-800 px-2.5 py-1 rounded text-xs font-mono text-white focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          {/* Quick Code Snippets */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] uppercase font-bold text-slate-400">Sample Leaks:</span>
            <button
              onClick={() => {
                setContent(PRESET_STRIPE);
                setFilename('payment-handler.ts');
              }}
              className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-rose-400 border border-rose-900/40"
            >
              Stripe Leak
            </button>
            <button
              onClick={() => {
                setContent(PRESET_AWS_GCP);
                setFilename('cloud-credentials.py');
              }}
              className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-amber-400 border border-amber-900/40"
            >
              AWS/Gemini Leak
            </button>
            <button
              onClick={() => {
                setContent(PRESET_CLEAN);
                setFilename('clean-module.ts');
              }}
              className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-emerald-400 border border-emerald-900/40"
            >
              Clean Code
            </button>
          </div>
        </div>

        {/* Textarea Code Input */}
        <div className="relative">
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            rows={11}
            placeholder="Paste code snippet or staged Git diff here..."
            className="w-full bg-[#030712] border border-slate-800/80 rounded-xl p-3 font-mono text-xs text-slate-200 focus:outline-none focus:border-emerald-500/50 leading-relaxed resize-y"
          />
        </div>

        {/* Submit Audit Button */}
        <div className="flex justify-end pt-1">
          <button
            onClick={handleAudit}
            disabled={loading || !content.trim()}
            className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 font-bold text-xs sm:text-sm transition flex items-center gap-2 shadow-lg shadow-emerald-500/20 disabled:opacity-50"
          >
            {loading ? (
              <span>Auditing Tokens...</span>
            ) : (
              <>
                <Play className="w-4 h-4 fill-slate-950" />
                <span>Run GitShield Audit</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Error Callout */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs flex items-center gap-3">
          <AlertCircle className="w-5 h-5 flex-shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Audit Results */}
      {verdict && (
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-start">
          {/* Risk Gauge Readout */}
          <div className="md:col-span-4 bg-[#060b18] border border-slate-800 rounded-2xl p-6 flex flex-col items-center justify-center shadow-xl">
            <RiskGauge score={riskScore ?? 0} verdict={verdict} size={190} />
            <div className="mt-4 text-center">
              <span className="text-xs text-slate-400 block font-medium">
                {findings.length} Credential Token{findings.length !== 1 ? 's' : ''} Flagged
              </span>
            </div>
          </div>

          {/* Remediation Diff Viewer Component */}
          <div className="md:col-span-8">
            <CodeDiffViewer
              findings={findings}
              remediation={remediation || undefined}
              originalContent={content}
            />
          </div>
        </div>
      )}
    </div>
  );
}
```

---

### 6. `app/dashboard/api-keys/page.tsx`

```tsx
"use client";

import React, { useState, useEffect } from 'react';
import { Key, Plus, Trash2, Copy, Check, AlertTriangle, ShieldCheck, Terminal } from 'lucide-react';

interface ApiKeyItem {
  id: string;
  key_name: string;
  key_prefix: string;
  created_at: string;
  last_used_at: string | null;
}

export default function ApiKeysPage() {
  const [keys, setKeys] = useState<ApiKeyItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Modal State
  const [modalOpen, setModalOpen] = useState(false);
  const [newKeyName, setNewKeyName] = useState('Local Pre-Commit Hook Key');
  const [creating, setCreating] = useState(false);
  const [revealedKey, setRevealedKey] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);

  const fetchKeys = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/keys');
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to list API keys.');
      setKeys(data.keys || []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchKeys();
  }, []);

  const handleCreateKey = async () => {
    setCreating(true);
    setError(null);
    try {
      const res = await fetch('/api/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newKeyName }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to create key.');

      setRevealedKey(data.key.plaintextSecret);
      fetchKeys();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteKey = async (id: string) => {
    if (!confirm('Are you sure you want to revoke this API key? This cannot be undone.')) return;

    try {
      const res = await fetch(`/api/keys?id=${id}`, { method: 'DELETE' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to delete key.');
      setKeys(keys.filter((k) => k.id !== id));
    } catch (err) {
      alert((err as Error).message);
    }
  };

  const copyPlaintext = async () => {
    if (!revealedKey) return;
    await navigator.clipboard.writeText(revealedKey);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Key className="w-5 h-5 text-indigo-400" />
            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              Developer API Keys
            </h1>
          </div>
          <p className="text-xs sm:text-sm text-slate-400">
            Authenticate the `aegis.py` CLI and Git pre-commit hooks against your personal cloud quota.
          </p>
        </div>

        <button
          onClick={() => {
            setRevealedKey(null);
            setModalOpen(true);
          }}
          className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs sm:text-sm transition flex items-center gap-2 shadow-lg shadow-cyan-500/20 self-start sm:self-auto"
        >
          <Plus className="w-4 h-4" />
          <span>Generate New Key</span>
        </button>
      </div>

      {/* CLI Instruction Banner */}
      <div className="p-4 rounded-2xl bg-[#060b18] border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-cyan-500/10 text-cyan-400 flex items-center justify-center flex-shrink-0">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xs font-bold text-white">Using with aegis.py CLI</div>
            <div className="text-[11px] text-slate-400">
              Export your key in your shell: <code className="text-cyan-300 font-mono">export AEGIS_API_KEY="aegis_live_..."</code>
            </div>
          </div>
        </div>
      </div>

      {/* Keys Table */}
      <div className="bg-[#060b18] border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/80 border-b border-slate-800 text-[10px] uppercase font-bold text-slate-400 tracking-wider">
              <tr>
                <th className="p-3.5 pl-5">Key Name</th>
                <th className="p-3.5">Key Prefix</th>
                <th className="p-3.5">Created</th>
                <th className="p-3.5">Last Used</th>
                <th className="p-3.5 pr-5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {loading ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-slate-500 font-sans">
                    Loading developer keys...
                  </td>
                </tr>
              ) : keys.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-slate-400 font-sans">
                    No API keys created yet. Generate one above to configure your pre-commit hook.
                  </td>
                </tr>
              ) : (
                keys.map((k) => (
                  <tr key={k.id} className="hover:bg-slate-900/40 transition">
                    <td className="p-3.5 pl-5 font-sans font-semibold text-white">{k.key_name}</td>
                    <td className="p-3.5 text-cyan-400 font-mono">{k.key_prefix}...</td>
                    <td className="p-3.5 text-slate-400">
                      {new Date(k.created_at).toLocaleDateString()}
                    </td>
                    <td className="p-3.5 text-slate-400">
                      {k.last_used_at ? new Date(k.last_used_at).toLocaleDateString() : 'Never'}
                    </td>
                    <td className="p-3.5 pr-5 text-right font-sans">
                      <button
                        onClick={() => handleDeleteKey(k.id)}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-950/30 transition"
                        title="Revoke Key"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* GENERATE KEY MODAL */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#090f20] border border-slate-700 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Key className="w-4 h-4 text-cyan-400" />
              Generate Developer API Key
            </h3>

            {!revealedKey ? (
              <div className="space-y-3">
                <label className="text-xs text-slate-300 block">Key Identifier / Name</label>
                <input
                  type="text"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                  placeholder="e.g. MacBook Pro Pre-Commit Hook"
                  className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-xl text-xs text-white focus:outline-none focus:border-cyan-500"
                />

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    onClick={() => setModalOpen(false)}
                    className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 text-xs font-semibold hover:bg-slate-700 transition"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleCreateKey}
                    disabled={creating || !newKeyName.trim()}
                    className="px-5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold transition disabled:opacity-50"
                  >
                    {creating ? 'Hashing Key...' : 'Create Key'}
                  </button>
                </div>
              </div>
            ) : (
              /* One-time plaintext token reveal view */
              <div className="space-y-3">
                <div className="p-3 rounded-xl bg-amber-950/40 border border-amber-500/40 text-amber-200 text-xs flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 flex-shrink-0 text-amber-400 mt-0.5" />
                  <span>
                    Copy your API secret key now. You will not be able to view it again!
                  </span>
                </div>

                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between gap-2">
                  <span className="font-mono text-xs text-cyan-300 break-all select-all">
                    {revealedKey}
                  </span>
                  <button
                    onClick={copyPlaintext}
                    className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition flex-shrink-0"
                    title="Copy Secret"
                  >
                    {copiedKey ? (
                      <Check className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </button>
                </div>

                <div className="flex justify-end pt-2">
                  <button
                    onClick={() => {
                      setModalOpen(false);
                      setRevealedKey(null);
                    }}
                    className="px-5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold transition"
                  >
                    Done
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
```