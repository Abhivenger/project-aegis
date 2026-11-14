"use client";

import React, { useMemo, useRef, useState } from "react";
import { MotionConfig, motion } from "motion/react";
import {
  ChevronRight,
  CircleDot,
  Code2,
  Github,
  Globe,
  Menu,
  PlayCircle,
  Shield,
  Terminal,
  X,
  type LucideIcon,
} from "lucide-react";
import { analyzeCode } from "@/lib/scanners/code-analysis";
import { STRIPE_PRESET, type SecurityPreset } from "@/lib/demo-presets";
import { SecurityPresets } from "@/components/security-presets";
import { VulnerabilityCard } from "@/components/vulnerability-card";
import { SafeLinkResult } from "@/components/safelink-result";
import type { UrlAnalysisReport } from "@/lib/scanners/url-analyzer";

const springCard = { type: "spring" as const, stiffness: 320, damping: 28 };

function Wordmark() {
  return (
    <div className="flex items-center gap-2.5">
      <div className="flex h-8 w-8 items-center justify-center rounded-[10px] border border-cyan-200/20 bg-cyan-300/[0.08] text-cyan-200">
        <Shield className="h-4 w-4" strokeWidth={1.8} aria-hidden />
      </div>
      <span className="text-sm font-semibold tracking-[0.18em] text-white">AEGIS</span>
    </div>
  );
}

function SandboxWidget() {
  const [source, setSource] = useState(STRIPE_PRESET.content);
  const [filename, setFilename] = useState(STRIPE_PRESET.filename);
  const [selected, setSelected] = useState<string | null>("stripe");
  const [urlReport, setUrlReport] = useState<UrlAnalysisReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scanVersion = useRef(0);
  const result = useMemo(() => analyzeCode(source, filename), [source, filename]);
  const urlMode = /^https?:\/\//i.test(source.trim());

  const inspectUrl = async (url: string, version: number) => {
    setLoading(true);
    setError(null);
    setUrlReport(null);
    try {
      const response = await fetch("/api/scan/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "SafeLink inspection failed.");
      if (scanVersion.current === version) setUrlReport(data.report);
    } catch (err) {
      if (scanVersion.current === version) setError(err instanceof Error ? err.message : "SafeLink inspection failed.");
    } finally {
      if (scanVersion.current === version) setLoading(false);
    }
  };

  const selectPreset = (preset: SecurityPreset) => {
    const version = ++scanVersion.current;
    setSource(preset.content);
    setFilename(preset.filename);
    setSelected(preset.id);
    setUrlReport(null);
    setError(null);
    setLoading(false);
    if (preset.id === "metadata") void inspectUrl(preset.content, version);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ ...springCard, delay: 0.05 }}
      className="relative mx-auto w-full max-w-[820px] overflow-hidden rounded-2xl border border-white/[0.09] bg-[#0c1017]/85 text-left shadow-[0_24px_80px_rgba(0,0,0,0.35)] backdrop-blur-xl"
    >
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/40 to-transparent" />
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.08] px-5 py-4">
        <div>
          <h2 className="text-sm font-semibold text-white">Try Aegis. See a threat. Fix it.</h2>
          <p className="mt-1 text-[11px] text-zinc-400">No account, no setup. Pick an example.</p>
        </div>
        <div className="flex items-center gap-1.5 font-mono text-[10px] text-emerald-300">
          <CircleDot className="h-3 w-3" aria-hidden />
          {urlMode ? "SAFELINK API" : "LOCAL ENGINE"}
        </div>
      </div>
      <div className="space-y-4 p-4 sm:p-5">
        <div className="[&_button]:min-h-11 [&_button]:cursor-pointer">
          <SecurityPresets onSelect={selectPreset} selected={selected} />
        </div>
        <textarea
          aria-label="Local Aegis code audit input"
          value={source}
          maxLength={120000}
          onChange={(event) => {
            ++scanVersion.current;
            setSource(event.target.value);
            setSelected(null);
            setUrlReport(null);
            setLoading(false);
            setError(null);
          }}
          spellCheck={false}
          placeholder="Paste code or pick an example above..."
          className="h-[205px] w-full resize-y rounded-xl border border-white/[0.09] bg-[#07090e]/80 p-4 font-mono text-xs leading-6 text-zinc-300 outline-none focus-visible:border-cyan-300/40 focus-visible:ring-1 focus-visible:ring-cyan-300/40"
        />
        {urlMode && (
          <button
            type="button"
            disabled={loading}
            onClick={() => void inspectUrl(source.trim(), ++scanVersion.current)}
            className="flex min-h-11 cursor-pointer items-center gap-2 rounded-xl border border-cyan-300/25 bg-cyan-300/10 px-4 text-xs font-semibold text-cyan-100 transition-colors hover:bg-cyan-300/[0.16] disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Shield className="h-4 w-4" aria-hidden />
            {loading ? "Checking destination..." : "Inspect with SafeLink"}
          </button>
        )}
        {error && (
          <p role="alert" className="rounded-xl border border-rose-300/20 bg-rose-300/5 p-3 text-xs text-rose-200">
            {error}
          </p>
        )}
        {loading && (
          <p role="status" className="text-xs text-cyan-200">
            Checking destination against reserved network ranges...
          </p>
        )}
        {urlMode ? (
          urlReport && <SafeLinkResult report={urlReport} />
        ) : source.trim() ? (
          <VulnerabilityCard
            key={source}
            findings={result.findings}
            remediation={result.remediation}
            originalContent={source}
            filename={filename}
          />
        ) : (
          <p className="text-xs text-zinc-400">Pick an example to run a security check.</p>
        )}
      </div>
    </motion.div>
  );
}

function FlowNode({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="rounded-xl border border-white/[0.09] bg-[#0c1017] p-3.5">
      <div className="mb-4 flex h-7 w-7 items-center justify-center rounded-lg border border-white/[0.10] text-zinc-300">{icon}</div>
      <div className="font-mono text-[10px] text-zinc-400">{label}</div>
      <div className="mt-1 truncate font-mono text-[11px] text-zinc-200">{value}</div>
    </div>
  );
}

function FlowArrow() {
  return (
    <div className="hidden justify-center text-zinc-600 sm:flex">
      <ChevronRight className="h-4 w-4" aria-hidden />
    </div>
  );
}

function GitHubShowcase() {
  return (
    <div className="mt-8 rounded-2xl border border-white/[0.09] bg-[#0c1017] p-5 sm:p-7">
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="font-mono text-[11px] text-zinc-400">GitHub REST API</p>
          <h3 className="mt-2 max-w-md text-lg font-semibold tracking-[-0.02em] text-white">
            Point Aegis at a repository. Read the scanner's own findings.
          </h3>
        </div>
        <a
          href="/dashboard"
          className="inline-flex min-h-11 items-center rounded-xl border border-white/[0.10] bg-white/[0.03] px-4 text-xs font-semibold text-zinc-200 transition-colors hover:border-cyan-300/30 hover:text-cyan-100"
        >
          Open the repo scanner
        </a>
      </div>
      <div className="grid items-center gap-3 sm:grid-cols-[1fr_48px_1fr_48px_1fr]">
        <FlowNode icon={<Github className="h-4 w-4" aria-hidden />} label="Repository" value="owner / repo" />
        <FlowArrow />
        <FlowNode icon={<Shield className="h-4 w-4" aria-hidden />} label="Scan" value="20 files, 100 KB cap" />
        <FlowArrow />
        <FlowNode icon={<Code2 className="h-4 w-4" aria-hidden />} label="Decision" value="score + .env diff" />
      </div>
      <p className="mt-6 border-t border-white/[0.08] pt-4 font-mono text-[10px] text-zinc-400">
        Streams per-file progress as NDJSON.
      </p>
    </div>
  );
}

interface Surface {
  id: string;
  icon: LucideIcon;
  name: string;
  trigger: string;
  detail: string;
  code: string;
  href: string;
  cta: string;
}

const SURFACES: readonly Surface[] = [
  {
    id: "cli",
    icon: Terminal,
    name: "cli/aegis.py",
    trigger: "pre-commit",
    detail:
      "Reads git diff --cached, runs 27 signatures and H >= 4.55, then exits 1 before the commit leaves the machine.",
    code: "python3 cli/aegis.py --install",
    href: "/dashboard/code-auditor",
    cta: "Open the sandbox",
  },
  {
    id: "repo",
    icon: Github,
    name: "POST /api/scan/github",
    trigger: "repository",
    detail:
      "Streams GitHub REST API results for the 20 highest-risk files, capped at 100 KB each, as NDJSON progress events.",
    code: "Accept: application/x-ndjson",
    href: "/dashboard",
    cta: "Open the repo scanner",
  },
  {
    id: "safelink",
    icon: Globe,
    name: "POST /api/scan/url",
    trigger: "any URL",
    detail:
      "Validates every redirect hop against private, loopback, and metadata ranges. Stops at 5 hops or 3.5s per probe.",
    code: "max 5 hops / 3.5s per probe",
    href: "/dashboard/url-inspector",
    cta: "Open SafeLink",
  },
];

interface PricingTier {
  name: string;
  price: string;
  suffix?: string;
  audience: string;
  features: string[];
  cta: string;
  href: string;
}

const PRICING: readonly PricingTier[] = [
  {
    name: "Community",
    price: "$0",
    suffix: "/ forever",
    audience: "One developer, offline.",
    features: ["Zero-dependency Python CLI", "27 signatures + H >= 4.55", "Pre-commit hook and .env extraction", "No network calls"],
    cta: "Open the code sandbox",
    href: "/dashboard/code-auditor",
  },
  {
    name: "Team",
    price: "$19",
    suffix: "/ seat / mo",
    audience: "Teams scanning repositories.",
    features: ["Live GitHub repository scanner", "SafeLink URL inspector", "Encrypted Web Vault", "Streaming scan progress"],
    cta: "Open the dashboard",
    href: "/dashboard",
  },
  {
    name: "Enterprise",
    price: "Custom",
    audience: "Controlled deployments.",
    features: ["Unlimited scan quota", "Bring your own model endpoint", "Redacted JSON audit exports", "NDJSON scan API"],
    cta: "Open the API keys page",
    href: "/dashboard/api-keys",
  },
];

export default function AegisLanding() {
  const [mobileOpen, setMobileOpen] = useState(false);

  const scrollTo = (id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
    setMobileOpen(false);
  };

  return (
    <MotionConfig reducedMotion="user">
      <main className="min-h-screen overflow-hidden bg-[#07090e] text-zinc-100 selection:bg-cyan-300/20 selection:text-cyan-100">
        <nav className="relative z-20 mx-auto flex max-w-7xl items-center justify-between px-5 py-4 sm:px-8 lg:px-10">
          <Wordmark />
          <div className="hidden items-center gap-6 text-xs text-zinc-400 md:flex">
            {[
              { id: "product", label: "Product" },
              { id: "surfaces", label: "Surfaces" },
              { id: "pricing", label: "Pricing" },
            ].map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => scrollTo(item.id)}
                className="cursor-pointer py-2 transition-colors hover:text-white focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-300"
              >
                {item.label}
              </button>
            ))}
          </div>
          <div className="hidden items-center gap-2 md:flex">
            <a
              href="/dashboard"
              className="inline-flex min-h-10 items-center rounded-xl px-3 text-xs text-zinc-300 transition-colors hover:text-white"
            >
              Open dashboard
            </a>
            <a
              href="/dashboard?tour=1"
              className="inline-flex min-h-10 items-center rounded-xl border border-cyan-200/25 bg-cyan-300/[0.10] px-4 text-xs font-semibold text-cyan-100 transition-colors hover:bg-cyan-300/[0.16]"
            >
              Run the tour
            </a>
          </div>
          <button
            type="button"
            onClick={() => setMobileOpen((value) => !value)}
            className="flex h-11 w-11 cursor-pointer items-center justify-center rounded-lg border border-white/[0.10] text-zinc-300 md:hidden"
            aria-label="Toggle navigation"
            aria-expanded={mobileOpen}
          >
            {mobileOpen ? <X className="h-4 w-4" aria-hidden /> : <Menu className="h-4 w-4" aria-hidden />}
          </button>
        </nav>

        {mobileOpen && (
          <div className="relative z-20 mx-5 flex flex-col gap-1 rounded-2xl border border-white/[0.10] bg-[#0f1420]/95 p-2 backdrop-blur-xl md:hidden">
            {[
              { id: "product", label: "Product" },
              { id: "surfaces", label: "Surfaces" },
              { id: "pricing", label: "Pricing" },
            ].map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => scrollTo(item.id)}
                className="min-h-11 cursor-pointer rounded-xl px-3 text-left text-sm text-zinc-300 transition-colors hover:bg-white/[0.04] hover:text-white"
              >
                {item.label}
              </button>
            ))}
            <a
              href="/dashboard"
              className="flex min-h-11 items-center rounded-xl px-3 text-sm font-semibold text-cyan-100 transition-colors hover:bg-cyan-300/[0.10]"
            >
              Open dashboard
            </a>
          </div>
        )}

        <section className="relative mx-auto max-w-7xl px-5 pb-16 pt-14 sm:px-8 sm:pt-20 lg:px-10 lg:pb-24">
          <div className="mx-auto max-w-3xl text-center">
            <h1 className="mx-auto max-w-3xl text-5xl font-semibold tracking-[-0.06em] text-white sm:text-6xl lg:text-7xl">
              Commit clean.
              <br />
              <span className="text-cyan-200">Leak nothing.</span>
            </h1>
            <p className="mx-auto mt-6 max-w-2xl text-sm leading-7 text-zinc-400 sm:text-base">
              Aegis scans staged diffs before they leave your machine, streams repository scans through the GitHub
              REST API, and traces links hop by hop before any request runs. The same engine runs in the CLI, the
              dashboard, and the sandbox below.
            </p>
            <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
              <a
                href="/dashboard"
                className="flex min-h-11 w-full items-center justify-center gap-2 rounded-xl border border-cyan-200/25 bg-cyan-300/[0.13] px-5 text-sm font-semibold text-cyan-50 transition-colors hover:bg-cyan-300/[0.19] sm:w-auto"
              >
                Open the dashboard
              </a>
              <a
                href="/dashboard?tour=1"
                className="flex min-h-11 w-full items-center justify-center gap-2 rounded-xl border border-emerald-300/20 bg-emerald-300/[0.06] px-5 text-sm text-emerald-100 transition-colors hover:bg-emerald-300/[0.12] sm:w-auto"
              >
                <PlayCircle className="h-4 w-4" aria-hidden />
                Run the 5-tab tour
              </a>
              <a
                href="/dashboard/code-auditor"
                className="flex min-h-11 w-full items-center justify-center gap-2 rounded-xl border border-white/[0.10] bg-white/[0.03] px-5 text-sm text-zinc-300 transition-colors hover:bg-white/[0.07] sm:w-auto"
              >
                <Code2 className="h-4 w-4" aria-hidden />
                Open the code sandbox
              </a>
            </div>
            <p className="mt-5 font-mono text-[11px] text-zinc-400">
              27 signatures / H ≥ 4.55 / 20 files per repo scan
            </p>
          </div>

          <div id="product" className="mt-12 scroll-mt-10 sm:mt-16">
            <SandboxWidget />
          </div>
          <div className="mt-5 flex flex-wrap items-center justify-center gap-x-5 gap-y-2 font-mono text-[11px] text-zinc-400">
            <span>git diff --cached</span>
            <span aria-hidden className="text-zinc-600">/</span>
            <span>H ≥ 4.55</span>
            <span aria-hidden className="text-zinc-600">/</span>
            <span>SSRF pre-flight</span>
          </div>
        </section>

        <section id="surfaces" className="relative mx-auto max-w-6xl scroll-mt-10 px-5 py-16 sm:px-8 sm:py-24">
          <div className="mb-8 max-w-2xl">
            <p className="font-mono text-[11px] text-zinc-400">Runtime surfaces</p>
            <h2 className="mt-3 text-3xl font-semibold tracking-[-0.04em] text-white sm:text-4xl">
              Three surfaces, one scanner.
            </h2>
            <p className="mt-4 text-sm leading-7 text-zinc-400 sm:text-base">
              The same entropy and signature engine runs in the pre-commit hook, the dashboard, and the browser
              sandbox.
            </p>
          </div>

          <div className="border-t border-white/[0.08]">
            {SURFACES.map((surface) => {
              const Icon = surface.icon;
              return (
                <div
                  key={surface.id}
                  className="grid gap-4 border-b border-white/[0.08] py-6 md:grid-cols-[minmax(0,240px)_minmax(0,1fr)_auto] md:items-start"
                >
                  <div className="flex items-start gap-3">
                    <span className="mt-0.5 flex h-8 w-8 items-center justify-center rounded-lg border border-white/[0.10] text-zinc-300">
                      <Icon className="h-4 w-4" aria-hidden />
                    </span>
                    <div>
                      <div className="font-mono text-xs text-zinc-100">{surface.name}</div>
                      <div className="mt-1 font-mono text-[10px] text-zinc-400">{surface.trigger}</div>
                    </div>
                  </div>
                  <div>
                    <p className="text-xs leading-6 text-zinc-400">{surface.detail}</p>
                    <code className="mt-2 inline-block rounded-lg border border-white/[0.08] bg-[#07090e] px-2 py-1 font-mono text-[10px] text-cyan-200">
                      {surface.code}
                    </code>
                  </div>
                  <a
                    href={surface.href}
                    className="inline-flex min-h-11 items-center justify-center rounded-xl border border-white/[0.10] bg-white/[0.03] px-4 text-xs font-semibold text-zinc-200 transition-colors hover:border-cyan-300/30 hover:text-cyan-100"
                  >
                    {surface.cta}
                  </a>
                </div>
              );
            })}
          </div>

          <GitHubShowcase />
        </section>

        <section id="pricing" className="relative mx-auto max-w-6xl scroll-mt-10 px-5 py-20 sm:px-8 sm:py-28">
          <div className="max-w-2xl">
            <h2 className="text-3xl font-semibold tracking-[-0.04em] text-white sm:text-4xl">
              Start with the CLI. Add the dashboard when you need it.
            </h2>
            <p className="mt-4 text-sm leading-7 text-zinc-400 sm:text-base">
              The CLI runs offline with no dependencies. The dashboard adds live repository scans, SafeLink, and the
              vault.
            </p>
          </div>

          <div className="mt-10 border-t border-white/[0.08]">
            {PRICING.map((tier) => (
              <div
                key={tier.name}
                className="grid gap-5 border-b border-white/[0.08] py-6 sm:grid-cols-[190px_minmax(0,1fr)_auto] sm:items-start"
              >
                <div>
                  <h3 className="text-sm font-semibold text-white">{tier.name}</h3>
                  <div className="mt-2 flex items-baseline gap-1">
                    <span className="font-mono text-2xl tabular-nums tracking-[-0.04em] text-white">{tier.price}</span>
                    {tier.suffix && <span className="font-mono text-[10px] text-zinc-400">{tier.suffix}</span>}
                  </div>
                  <p className="mt-1 text-[11px] text-zinc-400">{tier.audience}</p>
                </div>
                <ul className="grid gap-2 text-xs text-zinc-300 sm:grid-cols-2">
                  {tier.features.map((feature) => (
                    <li key={feature} className="flex gap-2">
                      <span aria-hidden className="font-mono text-zinc-600">/</span>
                      {feature}
                    </li>
                  ))}
                </ul>
                <a
                  href={tier.href}
                  className="inline-flex min-h-11 items-center justify-center rounded-xl border border-white/[0.10] bg-white/[0.03] px-4 text-xs font-semibold text-zinc-200 transition-colors hover:border-cyan-300/30 hover:text-cyan-100"
                >
                  {tier.cta}
                </a>
              </div>
            ))}
          </div>
          <p className="mt-4 font-mono text-[10px] text-zinc-400">Demo pricing. Checkout is simulated.</p>
        </section>

        <footer className="relative z-10 border-t border-white/[0.08] px-5 py-8 sm:px-8">
          <div className="mx-auto flex max-w-7xl flex-col gap-4 text-xs text-zinc-400 sm:flex-row sm:items-center sm:justify-between">
            <Wordmark />
            <span>© 2026 Project Aegis. GitShield CLI, dashboard, SafeLink.</span>
            <a href="/dashboard" className="flex items-center gap-1.5 transition-colors hover:text-white">
              Open dashboard
            </a>
          </div>
        </footer>
      </main>
    </MotionConfig>
  );
}
