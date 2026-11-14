"use client";

import React, { useMemo, useRef, useState } from "react";
import { motion } from "motion/react";
import { toast } from "sonner";
import {
  ArrowRight,
  BadgeCheck,
  Check,
  ChevronRight,
  CircleDot,
  Code2,
  Cloud,
  Github,
  KeyRound,
  LockKeyhole,
  Menu,
  Radar,
  Shield,
  X,
} from "lucide-react";
import { analyzeCode } from "@/lib/scanners/code-analysis";
import { STRIPE_PRESET, type SecurityPreset } from "@/lib/demo-presets";
import { SecurityPresets } from "@/components/security-presets";
import { VulnerabilityCard } from "@/components/vulnerability-card";
import { SafeLinkResult } from "@/components/safelink-result";
import type { UrlAnalysisReport } from "@/lib/scanners/url-analyzer";

const springInteraction = { type: "spring" as const, stiffness: 400, damping: 30 };
const springCard = { type: "spring" as const, stiffness: 350, damping: 25 };

function Pill({ children, tone = "cyan" }: { children: React.ReactNode; tone?: "cyan" | "emerald" | "slate" }) {
  const toneClass = {
    cyan: "border-cyan-300/20 bg-cyan-300/[0.07] text-cyan-200",
    emerald: "border-emerald-300/20 bg-emerald-300/[0.07] text-emerald-200",
    slate: "border-white/[0.10] bg-white/[0.04] text-zinc-300",
  }[tone];

  return <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[10px] font-medium tracking-[0.16em] uppercase ${toneClass}`}>{children}</span>;
}

function Wordmark() {
  return (
    <div className="flex items-center gap-2.5">
      <div className="relative flex h-8 w-8 items-center justify-center rounded-[10px] border border-cyan-200/20 bg-cyan-300/[0.10] text-cyan-200">
        <Shield className="h-4 w-4" strokeWidth={1.8} />
        <span className="absolute -right-0.5 -top-0.5 h-1.5 w-1.5 rounded-full bg-emerald-300 shadow-[0_0_10px_rgba(110,231,183,0.85)]" />
      </div>
      <span className="text-sm font-semibold tracking-[0.20em] text-white">AEGIS</span>
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
    <motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ ...springCard, delay: 0.18 }} className="relative mx-auto w-full max-w-[820px] overflow-hidden rounded-[22px] border border-white/[0.11] bg-[#0f1420]/80 text-left shadow-[0_24px_90px_rgba(0,0,0,0.30)] backdrop-blur-xl">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/70 to-transparent" />
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.08] px-5 py-4">
        <div><h2 className="text-sm font-semibold text-white">Try Aegis. See a threat. Fix it.</h2><p className="mt-1 text-[11px] text-zinc-500">No account. No setup. Pick an example below.</p></div>
        <div className="flex items-center gap-1.5 text-[10px] text-emerald-300"><CircleDot className="h-3 w-3" /> {urlMode ? "SAFELINK API" : "LOCAL ENGINE"}</div>
      </div>
      <div className="space-y-4 p-4 sm:p-5">
        <SecurityPresets onSelect={selectPreset} selected={selected} />
        <textarea aria-label="Local Aegis code audit input" value={source} maxLength={120000} onChange={(event) => {
          ++scanVersion.current;
          setSource(event.target.value);
          setSelected(null);
          setUrlReport(null);
          setLoading(false);
          setError(null);
        }} spellCheck={false} placeholder="Paste code or pick an example above..." className="h-[205px] w-full resize-y rounded-xl border border-white/[0.09] bg-[#07090E]/70 p-4 font-mono text-xs leading-6 text-zinc-300 outline-none focus-visible:border-cyan-300/40 focus-visible:ring-1 focus-visible:ring-cyan-300/40" />
        {urlMode && <button type="button" disabled={loading} onClick={() => void inspectUrl(source.trim(), ++scanVersion.current)} className="flex min-h-10 items-center gap-2 rounded-xl border border-cyan-300/25 bg-cyan-300/10 px-4 py-2 text-xs font-semibold text-cyan-100 disabled:opacity-50"><Shield className="h-4 w-4" />{loading ? "Intercepting destination..." : "Inspect with SafeLink"}</button>}
        {error && <p role="alert" className="rounded-xl border border-rose-300/20 bg-rose-300/5 p-3 text-xs text-rose-200">{error}</p>}
        {loading && <p role="status" className="text-xs text-cyan-200">Checking destination against reserved network rules...</p>}
        {urlMode ? urlReport && <SafeLinkResult report={urlReport} /> : source.trim() ? <VulnerabilityCard key={source} findings={result.findings} remediation={result.remediation} originalContent={source} filename={filename} /> : <p className="text-xs text-zinc-400">Pick an example to get an instant security check.</p>}
      </div>
    </motion.div>
  );
}

function GitHubShowcase() {
  return (
    <div className="relative overflow-hidden rounded-[24px] border border-white/[0.10] bg-[#0f1420]/70 p-5 backdrop-blur-xl sm:p-7">
      <div className="absolute right-0 top-0 h-40 w-40 rounded-full bg-cyan-300/[0.08] blur-3xl" />
      <div className="relative mb-8">
        <Pill tone="slate"><Github className="mr-1.5 h-3 w-3" /> GitHub Shield</Pill>
        <h3 className="mt-4 max-w-md text-xl font-semibold tracking-[-0.03em] text-white">Point Aegis at a repository. See every leak before it ships.</h3>
      </div>
      <div className="relative grid items-center gap-3 sm:grid-cols-[1fr_48px_1fr_48px_1fr]">
        <FlowNode icon={<Github className="h-4 w-4" />} label="Repository" value="owner / repo" />
        <FlowArrow />
        <FlowNode icon={<Radar className="h-4 w-4" />} label="Entropy + signatures" value="20 high-risk files" />
        <FlowArrow />
        <FlowNode icon={<Shield className="h-4 w-4" />} label="Aegis decision" value="score + .env fix" />
      </div>
      <div className="relative mt-6 flex flex-col justify-between gap-3 border-t border-white/[0.08] pt-4 text-[11px] sm:flex-row sm:items-center">
        <span className="text-zinc-400">Runs live against the GitHub API from your dashboard.</span>
        <motion.a href="/dashboard" whileHover={{ scale: 1.01 }} whileTap={{ scale: 0.98 }} transition={springInteraction} className="flex items-center justify-center gap-2 rounded-xl border border-cyan-200/20 bg-cyan-300/[0.09] px-3.5 py-2 font-medium text-cyan-100 transition hover:bg-cyan-300/[0.14]">Scan a real repository <ArrowRight className="h-3.5 w-3.5" /></motion.a>
      </div>
    </div>
  );
}

function FlowNode({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-cyan-300/20 bg-cyan-300/[0.05] p-3.5">
      <div className="mb-4 flex h-7 w-7 items-center justify-center rounded-lg border border-cyan-300/20 text-cyan-200">{icon}</div>
      <div className="text-[10px] uppercase tracking-[0.14em] text-zinc-500">{label}</div>
      <div className="mt-1 truncate font-mono text-[11px] text-zinc-200">{value}</div>
    </div>
  );
}

function FlowArrow() {
  return <div className="hidden justify-center text-zinc-500 sm:flex"><ChevronRight className="h-4 w-4" /></div>;
}

interface PricingTier {
  name: string;
  price: string;
  suffix?: string;
  description: string;
  features: string[];
  cta: string;
  featured?: boolean;
}

const PRICING: PricingTier[] = [
  { name: "Community", price: "$0", suffix: "/ forever", description: "The local defense layer for every developer.", features: ["Open-source CLI", "Shannon entropy engine", "Local pre-commit hooks", "Community support"], cta: "Start locally" },
  { name: "Pro / Team", price: "$19", suffix: "/ seat / mo", description: "Cloud protection that keeps your team moving.", features: ["1-click GitHub PR Shield", "Cloud secret auditor", "Encrypted Web Vault", "Automated AI patch generator"], cta: "Start protecting", featured: true },
  { name: "Enterprise", price: "Custom", description: "Aegis shaped around your security program.", features: ["Dedicated LLM gateways", "SOC2 compliance reporting", "Custom regex engines", "Priority security engineering"], cta: "Talk to Aegis" },
];

function PricingSection() {
  return (
    <section id="pricing" className="mx-auto max-w-6xl scroll-mt-24 px-5 py-28 sm:px-8">
      <div className="mx-auto max-w-2xl text-center">
        <Pill tone="emerald">Simple by design</Pill>
        <h2 className="mt-5 text-3xl font-semibold tracking-[-0.05em] text-white sm:text-5xl">Protection that scales with your ambition.</h2>
        <p className="mt-5 text-sm leading-7 text-zinc-400 sm:text-base">Start with the local engine. Add the cloud when your team is ready to ship without secrets in the diff.</p>
      </div>
      <div className="mt-12 grid gap-4 lg:grid-cols-3">
        {PRICING.map((tier, index) => (
          <motion.div key={tier.name} initial={{ opacity: 0, y: 14 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true, amount: 0.2 }} transition={{ ...springCard, delay: index * 0.08 }} className={`relative overflow-hidden rounded-[24px] border p-6 ${tier.featured ? "border-cyan-300/30 bg-[#101b29]" : "border-white/[0.09] bg-[#0f1420]/70"}`}>
            {tier.featured && <motion.div aria-hidden animate={{ rotate: 360 }} transition={{ duration: 8, repeat: Infinity, ease: "linear" }} className="absolute -right-24 -top-24 h-48 w-48 rounded-full bg-[conic-gradient(from_90deg,transparent,rgba(103,232,249,0.8),transparent_35%)] opacity-60 blur-2xl" />}
            <div className="relative">
              <div className="flex items-center justify-between"><h3 className="text-sm font-semibold text-white">{tier.name}</h3>{tier.featured && <Pill>Most popular</Pill>}</div>
              <div className="mt-7 flex items-baseline gap-1"><span className="text-4xl font-semibold tracking-[-0.07em] tabular-nums text-white">{tier.price}</span>{tier.suffix && <span className="font-mono text-[10px] text-zinc-500">{tier.suffix}</span>}</div>
              <p className="mt-3 min-h-10 text-xs leading-5 text-zinc-400">{tier.description}</p>
              <div className="my-6 h-px bg-white/[0.08]" />
              <ul className="space-y-3 text-xs text-zinc-300">{tier.features.map((feature) => <li key={feature} className="flex items-start gap-2"><Check className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${tier.featured ? "text-cyan-300" : "text-emerald-300"}`} />{feature}</li>)}</ul>
              <motion.button type="button" whileHover={{ scale: 1.01 }} whileTap={{ scale: 0.98 }} transition={springInteraction} onClick={() => toast.success(`${tier.name} selected`, { description: "Your Aegis workspace is ready when you are." })} className={`mt-8 flex w-full items-center justify-center gap-2 rounded-xl border px-4 py-2.5 text-xs font-semibold transition ${tier.featured ? "border-cyan-200/30 bg-cyan-300/[0.12] text-cyan-100 hover:bg-cyan-300/[0.18]" : "border-white/[0.11] bg-white/[0.04] text-zinc-200 hover:bg-white/[0.08]"}`}>{tier.cta}<ArrowRight className="h-3.5 w-3.5" /></motion.button>
            </div>
          </motion.div>
        ))}
      </div>
    </section>
  );
}

export default function AegisLanding() {
  const [mobileOpen, setMobileOpen] = useState(false);

  const scrollTo = (id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
    setMobileOpen(false);
  };

  return (
    <main className="min-h-screen overflow-hidden bg-[#07090e] text-zinc-100 selection:bg-cyan-300/20 selection:text-cyan-100">
      <div className="pointer-events-none fixed inset-0 -z-0 bg-[radial-gradient(circle_at_50%_-10%,rgba(0,240,255,0.12),transparent_33%),radial-gradient(circle_at_90%_30%,rgba(16,185,129,0.07),transparent_25%)]" />
      <nav className="relative z-20 mx-auto flex max-w-7xl items-center justify-between px-5 py-5 sm:px-8 lg:px-10">
        <Wordmark />
        <div className="hidden items-center gap-7 text-xs text-zinc-400 md:flex"><button onClick={() => scrollTo("product")} className="transition hover:text-white">Product</button><button onClick={() => scrollTo("workflow")} className="transition hover:text-white">How it works</button><button onClick={() => scrollTo("pricing")} className="transition hover:text-white">Pricing</button></div>
        <div className="hidden items-center gap-2.5 md:flex"><a href="/dashboard" className="rounded-xl px-3.5 py-2 text-xs text-zinc-300 transition hover:text-white">Sign in</a><motion.a href="/dashboard" whileHover={{ scale: 1.01 }} whileTap={{ scale: 0.98 }} transition={springInteraction} className="rounded-xl border border-cyan-200/20 bg-cyan-300/[0.10] px-4 py-2 text-xs font-semibold text-cyan-100 transition hover:bg-cyan-300/[0.16]">Launch Dashboard</motion.a></div>
        <button type="button" onClick={() => setMobileOpen((value) => !value)} className="rounded-lg border border-white/[0.10] p-2 text-zinc-300 md:hidden" aria-label="Toggle navigation">{mobileOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}</button>
      </nav>
      {mobileOpen && <div className="relative z-20 mx-5 flex flex-col gap-2 rounded-2xl border border-white/[0.10] bg-[#0f1420]/95 p-3 backdrop-blur-xl md:hidden"><button onClick={() => scrollTo("product")} className="rounded-xl p-3 text-left text-sm text-zinc-300">Product</button><button onClick={() => scrollTo("workflow")} className="rounded-xl p-3 text-left text-sm text-zinc-300">How it works</button><button onClick={() => scrollTo("pricing")} className="rounded-xl p-3 text-left text-sm text-zinc-300">Pricing</button></div>}

      <section className="relative z-10 mx-auto max-w-7xl px-5 pb-20 pt-16 sm:px-8 sm:pt-24 lg:px-10 lg:pb-28">
        <div className="mx-auto max-w-4xl text-center">
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ ...springCard, delay: 0.04 }}><Pill><span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-emerald-300 shadow-[0_0_9px_rgba(110,231,183,0.9)]" /> Aegis Cloud is live</Pill></motion.div>
          <motion.h1 initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ ...springCard, delay: 0.10 }} className="mx-auto mt-7 max-w-4xl text-5xl font-semibold tracking-[-0.075em] text-white sm:text-7xl lg:text-[84px] lg:leading-[0.98]">Ship faster.<br /><span className="bg-gradient-to-r from-cyan-200 via-white to-emerald-200 bg-clip-text text-transparent">Leak nothing.</span></motion.h1>
          <motion.p initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ ...springCard, delay: 0.15 }} className="mx-auto mt-7 max-w-2xl text-sm leading-7 text-zinc-400 sm:text-base">The zero-trust defense platform for modern engineering teams. Aegis catches secrets locally, blocks risky pull requests, and gives your team a calm, encrypted place to manage them.</motion.p>
          <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ ...springCard, delay: 0.20 }} className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row"><motion.a href="/dashboard" whileHover={{ scale: 1.01 }} whileTap={{ scale: 0.98 }} transition={springInteraction} className="group flex w-full items-center justify-center gap-2 rounded-xl border border-cyan-200/25 bg-cyan-300/[0.13] px-5 py-3 text-sm font-semibold text-cyan-50 transition-all duration-200 ease-out hover:bg-cyan-300/[0.19] sm:w-auto">Launch Dashboard <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" /></motion.a><a href="/dashboard?tour=1" className="flex w-full items-center justify-center gap-2 rounded-xl border border-emerald-300/20 bg-emerald-300/[0.06] px-5 py-3 text-sm text-emerald-100 transition-all duration-200 ease-out hover:bg-emerald-300/[0.12] sm:w-auto"><span aria-hidden className="text-[13px] leading-none">✨</span> Launch Guided Tour</a><a href="/dashboard/code-auditor" className="flex w-full items-center justify-center gap-2 rounded-xl border border-white/[0.10] bg-white/[0.03] px-5 py-3 text-sm text-zinc-300 transition-all duration-200 ease-out hover:bg-white/[0.07] sm:w-auto"><Code2 className="h-4 w-4" /> Try Code Auditor</a></motion.div>
        </div>
        <div id="product" className="relative mt-12 scroll-mt-10 sm:mt-16"><div className="absolute left-1/2 top-1/2 h-72 w-72 -translate-x-1/2 -translate-y-1/2 rounded-full bg-cyan-300/[0.08] blur-[100px]" /><SandboxWidget /></div>
        <div className="mt-5 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 font-mono text-[10px] uppercase tracking-[0.16em] text-zinc-500"><span className="flex items-center gap-1.5"><LockKeyhole className="h-3 w-3 text-emerald-300/70" /> local-first</span><span className="flex items-center gap-1.5"><Radar className="h-3 w-3 text-cyan-300/70" /> entropy aware</span><span className="flex items-center gap-1.5"><Cloud className="h-3 w-3 text-zinc-500" /> encrypted cloud</span></div>
      </section>

      <section id="workflow" className="relative z-10 mx-auto max-w-6xl scroll-mt-8 px-5 py-16 sm:px-8 sm:py-24"><div className="mb-10 max-w-xl"><Pill tone="cyan">The calm path to secure</Pill><h2 className="mt-5 text-3xl font-semibold tracking-[-0.05em] text-white sm:text-5xl">Security that feels like part of the flow.</h2><p className="mt-5 text-sm leading-7 text-zinc-400 sm:text-base">No scripts to clone. No configuration maze. Connect your repository, keep secrets in the Vault, and let Aegis make the secure path the easiest path.</p></div><GitHubShowcase /></section>

      <section className="relative z-10 mx-auto grid max-w-6xl gap-4 px-5 py-8 sm:grid-cols-3 sm:px-8 sm:py-16">
        {[
          { icon: <Code2 className="h-4 w-4" />, label: "01 / Detect", title: "Entropy over regex", copy: "Find the credential that looks almost like normal code, before it becomes an incident." },
          { icon: <KeyRound className="h-4 w-4" />, label: "02 / Protect", title: "Vault without friction", copy: "Encrypted references replace brittle local .env rituals while keeping developers in control." },
          { icon: <BadgeCheck className="h-4 w-4" />, label: "03 / Prove", title: "Evidence for every merge", copy: "A clear PR decision, remediation diff, and audit trail your security team can trust." },
        ].map((item, index) => <motion.div key={item.label} initial={{ opacity: 0, y: 12 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true, amount: 0.3 }} transition={{ ...springCard, delay: index * 0.08 }} className="rounded-[22px] border border-white/[0.09] bg-[#0f1420]/60 p-5"><div className="mb-12 flex items-center justify-between"><div className="flex h-8 w-8 items-center justify-center rounded-lg border border-cyan-300/20 bg-cyan-300/[0.07] text-cyan-200">{item.icon}</div><span className="font-mono text-[10px] text-zinc-500">{item.label}</span></div><h3 className="text-base font-semibold tracking-[-0.02em] text-white">{item.title}</h3><p className="mt-2 text-xs leading-5 text-zinc-400">{item.copy}</p></motion.div>)}
      </section>

      <PricingSection />

      <footer className="relative z-10 border-t border-white/[0.08] px-5 py-8 sm:px-8"><div className="mx-auto flex max-w-7xl flex-col gap-4 text-xs text-zinc-500 sm:flex-row sm:items-center sm:justify-between"><Wordmark /><span>© 2026 Project Aegis · built for teams that ship.</span><a href="/dashboard" className="flex items-center gap-1.5 text-zinc-400 transition hover:text-white">Open dashboard <ArrowRight className="h-3 w-3" /></a></div></footer>
    </main>
  );
}
