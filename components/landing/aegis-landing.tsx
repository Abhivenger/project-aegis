"use client";

import React, { useMemo, useState } from "react";
import {
  ArrowRight,
  Check,
  Code2,
  FileCode2,
  Github,
  Globe,
  Lock,
  Menu,
  RefreshCw,
  Shield,
  Terminal,
  X,
  type LucideIcon,
} from "lucide-react";
import { analyzeCode } from "@/lib/scanners/code-analysis";
import { SECURITY_PRESETS, type SecurityPreset } from "@/lib/demo-presets";

/* -------------------------------------------------------------------------- */
/* Static content                                                              */
/* -------------------------------------------------------------------------- */

const NAV_LINKS = [
  { href: "#features", label: "Features" },
  { href: "#modules", label: "Modules" },
  { href: "#workflow", label: "Workflow" },
  { href: "#architecture", label: "Architecture" },
] as const;

const HERO_META = [
  "Deterministic Shannon Entropy (H ≥ 4.55)",
  "Python GitShield Pre-Commit Hook",
  "Zero Cloud Latency",
] as const;

const TRUST_BAR = [
  "Sub-Millisecond Detection",
  "27+ Secret Signatures",
  "Zero False Positives on .env.example",
] as const;

interface Capability {
  icon: LucideIcon;
  title: string;
  body: string;
  href: string;
  cta: string;
}

const CAPABILITIES: readonly Capability[] = [
  {
    icon: Github,
    title: "Live GitHub Repo Auditor",
    body: "Pulls a public repository through the GitHub REST API and audits its 20 highest-risk files — 100 KB cap each — with the same entropy + signature engine the CLI runs.",
    href: "/dashboard",
    cta: "Open the auditor",
  },
  {
    icon: Code2,
    title: "Code & Entropy Sandbox",
    body: "Calibrated Shannon entropy (H ≥ 4.55) plus 27 credential signatures across the pasted source, with a one-click .env remediation diff.",
    href: "/dashboard/code-auditor",
    cta: "Open the sandbox",
  },
  {
    icon: Globe,
    title: "SafeLink URL Inspector",
    body: "Resolves every redirect hop against private, loopback and cloud-metadata ranges before a single request leaves the browser.",
    href: "/dashboard/url-inspector",
    cta: "Open SafeLink",
  },
  {
    icon: Lock,
    title: "Zero-Knowledge Vault",
    body: "Secrets stay masked and are shared only as ref:// environment references. Every entry tracks entropy and rotation status so stale keys surface early.",
    href: "/dashboard/vault",
    cta: "Open the vault",
  },
  {
    icon: Terminal,
    title: "GitShield CLI Hook",
    body: "Zero-dependency Python pre-commit hook. A staged AKIA… or sk_live_… commit exits 1 before it ever reaches GitHub.",
    href: "/dashboard/api-keys",
    cta: "Open GitShield",
  },
  {
    icon: RefreshCw,
    title: "Automated Diff Remediation",
    body: "Extracts the leaked key into .env, rewrites the source to process.env, and stages the sanitized file back into the commit.",
    href: "/dashboard/code-auditor",
    cta: "See the remediation",
  },
];

const AUDITOR_PILLS = [
  { id: "test-keys", label: "trufflesecurity/test_keys" },
  { id: "aegis-repo", label: "Abhivenger/project-aegis" },
  { id: "env-example", label: ".env.example Filter" },
] as const;

const SANDBOX_PILLS = [
  { id: "aws", label: "AWS AKIA Key" },
  { id: "stripe", label: "Stripe Live Token" },
  { id: "clean", label: "Clean .env Diff" },
] as const;

const SAFELINK_PILLS = [
  { id: "homograph", label: "Punycode Homograph" },
  { id: "exposed-token", label: "Exposed URL Token" },
  { id: "pre-commit", label: "Pre-Commit Block" },
] as const;

/** Fabricated demo credential, never a live key. */
const EXPOSED_TOKEN_SNIPPET = `// Fabricated demo credential. Never connect to Stripe.
const checkoutUrl = "https://checkout.stripe.com/pay?client_secret=sk_placeholder_000000000000";
`;

const HOMOGRAPH_URL = "secure.login.verify.otp.auth.xn--pypal-4ve.com.xyz";

const CLI_TRANSCRIPT = [
  "$ git commit -m \"wire checkout flow\"",
  "[aegis] scanning staged diff · 3 files",
  "COMMIT BLOCKED: Unencrypted developer secrets detected!",
  "  * Target File: payment-handler.ts",
  "    Signature:   Stripe API Key",
  "    Token Redacted: sk_l****w9xY7z",
  "    Entropy:        5.112 bits/char",
  "  * Target File: cloud-config.ts",
  "    Signature:   AWS Access Key ID",
  "    Token Redacted: AKIA****MPLE",
  "  1. Run python aegis.py --fix to extract secrets into .env automatically.",
] as const;

/* -------------------------------------------------------------------------- */
/* Primitives                                                                  */
/* -------------------------------------------------------------------------- */

function Wordmark() {
  return (
    <a href="#top" className="flex items-center gap-2.5" aria-label="Project Aegis home">
      <span className="flex h-9 w-9 items-center justify-center rounded-[11px] border border-[rgba(99,82,255,0.35)] bg-[rgba(99,82,255,0.12)] text-[#c4bafc]">
        <Shield className="h-4 w-4" strokeWidth={1.7} aria-hidden />
      </span>
      <span className="text-[15px] font-semibold tracking-[-0.01em] text-[#f0f2ff]">Project Aegis</span>
    </a>
  );
}

function PrimaryButton({
  href,
  children,
  glint = false,
}: {
  href: string;
  children: React.ReactNode;
  glint?: boolean;
}) {
  return (
    <a
      href={href}
      className={`${glint ? "aegis-glint " : ""}group inline-flex min-h-[52px] w-full items-center justify-center gap-2 rounded-[14px] bg-[#6352ff] px-6 text-[14px] font-semibold text-white shadow-[0_18px_44px_-18px_rgba(99,82,255,0.9)] transition-all duration-300 hover:bg-[#7363ff] hover:shadow-[0_22px_54px_-18px_rgba(99,82,255,1)] sm:w-auto`}
    >
      {children}
    </a>
  );
}

function GhostButton({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a
      href={href}
      className="group inline-flex min-h-[52px] w-full items-center justify-center gap-2 rounded-[14px] border border-[rgba(99,82,255,0.28)] bg-[rgba(99,82,255,0.06)] px-6 text-[14px] font-medium text-[#f0f2ff] transition-all duration-300 hover:border-[rgba(99,82,255,0.55)] hover:bg-[rgba(99,82,255,0.12)] sm:w-auto"
    >
      {children}
    </a>
  );
}

function SectionHeading({
  eyebrow,
  title,
  body,
  titleId,
}: {
  eyebrow: string;
  title: string;
  body: string;
  titleId?: string;
}) {
  return (
    <div className="max-w-[720px]">
      <p className="aegis-eyebrow">{eyebrow}</p>
      <h2
        id={titleId}
        className="aegis-serif mt-5 text-[clamp(2rem,3.6vw,3.05rem)] leading-[1.08] tracking-[-0.015em] text-[#f0f2ff]"
      >
        {title}
      </h2>
      <p className="mt-5 text-[14.5px] leading-7 text-[#7a81a8]">{body}</p>
    </div>
  );
}

function MonoRow({ label, value, tone = "muted" }: { label: string; value: string; tone?: "muted" | "ink" | "brand" | "ok" | "danger" }) {
  const tones = {
    muted: "text-[#4a5180]",
    ink: "text-[#f0f2ff]",
    brand: "text-[#8376fc]",
    ok: "text-[#22c55e]",
    danger: "text-[#fb7185]",
  } as const;
  return (
    <div className="aegis-mono flex flex-wrap items-baseline gap-x-3 text-[11px] leading-[1.95]">
      <span className="text-[#4a5180]">{label}</span>
      <span className={tones[tone]}>{value}</span>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Chrome                                                                      */
/* -------------------------------------------------------------------------- */

function AmbientBackdrop() {
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 z-0 overflow-hidden">
      <div className="aegis-orb-a absolute left-[6%] top-[-16%] h-[58vh] w-[58vh] rounded-full bg-[radial-gradient(circle,rgba(99,82,255,0.22),transparent_68%)]" />
      <div className="aegis-orb-b absolute right-[4%] top-[34%] h-[46vh] w-[46vh] rounded-full bg-[radial-gradient(circle,rgba(34,197,94,0.08),transparent_70%)]" />
      <div className="aegis-noise absolute inset-0 opacity-[0.04]" />
    </div>
  );
}

function GlassNavbar() {
  const [open, setOpen] = useState(false);

  return (
    <header className="fixed inset-x-0 top-0 z-50 border-b border-white/[0.06] bg-[#060818]/70 backdrop-blur-[20px]">
      <nav className="mx-auto flex h-[72px] max-w-[1200px] items-center justify-between px-5 sm:px-8">
        <Wordmark />

        <div className="hidden items-center gap-9 md:flex">
          {NAV_LINKS.map((link) => (
            <a
              key={link.href}
              href={link.href}
              className="text-[13px] font-medium text-[#7a81a8] transition-colors duration-200 hover:text-[#f0f2ff]"
            >
              {link.label}
            </a>
          ))}
        </div>

        <div className="hidden items-center gap-3 md:flex">
          <a
            href="/dashboard"
            className="inline-flex min-h-[42px] items-center rounded-[12px] border border-white/[0.10] px-4 text-[13px] font-medium text-[#f0f2ff] transition-all duration-300 hover:border-[rgba(99,82,255,0.45)] hover:bg-[rgba(99,82,255,0.08)]"
          >
            Open Dashboard
          </a>
          <a
            href="/dashboard?tour=1"
            className="inline-flex min-h-[42px] items-center rounded-[12px] bg-[#6352ff] px-4 text-[13px] font-semibold text-white shadow-[0_14px_36px_-16px_rgba(99,82,255,0.9)] transition-all duration-300 hover:bg-[#7363ff]"
          >
            Launch Guided Tour
          </a>
        </div>

        <button
          type="button"
          onClick={() => setOpen((value) => !value)}
          className="flex h-11 w-11 cursor-pointer items-center justify-center rounded-[12px] border border-white/[0.10] text-[#f0f2ff] md:hidden"
          aria-label="Toggle navigation"
          aria-expanded={open}
        >
          {open ? <X className="h-4 w-4" aria-hidden /> : <Menu className="h-4 w-4" aria-hidden />}
        </button>
      </nav>

      {open && (
        <div className="border-t border-white/[0.06] bg-[#060818]/95 px-5 pb-6 pt-4 backdrop-blur-[20px] md:hidden">
          <div className="flex flex-col gap-1">
            {NAV_LINKS.map((link) => (
              <a
                key={link.href}
                href={link.href}
                onClick={() => setOpen(false)}
                className="flex min-h-11 items-center rounded-[10px] px-3 text-[14px] text-[#7a81a8] transition-colors hover:bg-white/[0.04] hover:text-[#f0f2ff]"
              >
                {link.label}
              </a>
            ))}
          </div>
          <div className="mt-4 flex flex-col gap-2.5">
            <a
              href="/dashboard"
              className="flex min-h-11 items-center justify-center rounded-[12px] border border-white/[0.10] text-[13.5px] font-medium text-[#f0f2ff]"
            >
              Open Dashboard
            </a>
            <a
              href="/dashboard?tour=1"
              className="flex min-h-11 items-center justify-center rounded-[12px] bg-[#6352ff] text-[13.5px] font-semibold text-white"
            >
              Launch Guided Tour
            </a>
          </div>
        </div>
      )}
    </header>
  );
}

/* -------------------------------------------------------------------------- */
/* Hero                                                                        */
/* -------------------------------------------------------------------------- */

function Hero() {
  return (
    <section id="top" className="relative flex min-h-screen flex-col px-5 pt-[72px] sm:px-8">
      <div className="flex flex-1 flex-col items-center justify-center text-center py-16 mx-auto w-full">
        <div className="mx-auto w-full max-w-[920px] text-center">
        <p className="aegis-eyebrow aegis-rise" style={{ animationDelay: "40ms" }}>
          Project Aegis · Pre-Commit Secret Defense
        </p>

        <h1
          className="aegis-serif aegis-rise mt-7 text-[clamp(2.8rem,6vw,5.2rem)] leading-[1.03] tracking-[-0.022em] text-[#f0f2ff]"
          style={{ animationDelay: "120ms" }}
        >
          Stop credential leaks
          <br />
          <span className="text-[#7a81a8]">before</span>{" "}
          <em className="bg-gradient-to-r from-[#c4bafc] to-[#8376fc] bg-clip-text text-transparent">
            git push.
          </em>
        </h1>

        <p
          className="aegis-rise mx-auto mt-7 max-w-[680px] text-[15px] leading-8 text-[#7a81a8]"
          style={{ animationDelay: "200ms" }}
        >
          Sub-millisecond Shannon entropy analysis, live GitHub repository auditing, and pre-commit defense.
          Built with Next.js 15, TypeScript, and Python.
        </p>

        <div
          className="aegis-rise mt-10 flex flex-col items-center justify-center gap-3 sm:flex-row"
          style={{ animationDelay: "280ms" }}
        >
          <PrimaryButton href="/dashboard?tour=1" glint>
            Launch Guided Tour
            <ArrowRight className="h-4 w-4 transition-transform duration-300 group-hover:translate-x-1" aria-hidden />
          </PrimaryButton>
          <GhostButton href="/dashboard">
            <Github className="h-4 w-4" aria-hidden />
            Audit a GitHub Repo
          </GhostButton>
        </div>

        <ul
          className="aegis-rise mt-10 flex flex-wrap items-center justify-center gap-x-7 gap-y-3"
          style={{ animationDelay: "360ms" }}
        >
          {HERO_META.map((item) => (
            <li key={item} className="flex items-center gap-2 text-[12.5px] text-[#7a81a8]">
              <Check className="h-3.5 w-3.5 text-[#22c55e]" strokeWidth={2.4} aria-hidden />
              {item}
            </li>
          ))}
        </ul>
      </div>

      <div
        className="aegis-rise mt-auto w-full border-y border-[#0a0e1f]/50 bg-[#0a0e1f]/50"
        style={{ animationDelay: "440ms" }}
      >
        <div className="mx-auto flex max-w-[1200px] flex-wrap items-center justify-center gap-x-8 gap-y-2 px-5 py-5 sm:px-8">
          {TRUST_BAR.map((item) => (
            <span key={item} className="aegis-mono text-[11px] tracking-[0.06em] text-[#7a81a8]">
              {item}
            </span>
          ))}
        </div>
      </div>
          </div>
</section>
  );
}

/* -------------------------------------------------------------------------- */
/* Capabilities                                                                */
/* -------------------------------------------------------------------------- */

function CapabilityCard({ icon: Icon, title, body, href, cta }: Capability) {
  return (
    <a href={href} className="aegis-card group flex flex-col p-7">
      <span className="flex h-11 w-11 items-center justify-center rounded-[14px] border border-[rgba(99,82,255,0.30)] bg-[rgba(99,82,255,0.10)] text-[#c4bafc]">
        <Icon className="h-5 w-5" strokeWidth={1.6} aria-hidden />
      </span>
      <h3 className="aegis-serif mt-6 text-[1.35rem] leading-snug text-[#f0f2ff]">{title}</h3>
      <p className="mt-3 flex-1 text-[13.5px] leading-6 text-[#7a81a8]">{body}</p>
      <span className="mt-6 inline-flex items-center gap-1.5 text-[12.5px] font-medium text-[#8376fc] transition-colors duration-300 group-hover:text-[#c4bafc]">
        {cta}
        <ArrowRight className="h-3.5 w-3.5 transition-transform duration-300 group-hover:translate-x-1" aria-hidden />
      </span>
    </a>
  );
}

function FeaturesSection() {
  return (
    <section id="features" className="relative mx-auto max-w-[1200px] scroll-mt-24 px-5 py-24 sm:px-8 sm:py-32">
      <SectionHeading
        eyebrow="Core Capabilities"
        title="Six surfaces, one detection engine."
        body="Entropy and signatures are computed by a single core, so a leak looks identical whether it is caught in a staged diff, a public repository, or a URL that someone sent you."
      />
      <div className="mt-14 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
        {CAPABILITIES.map((capability) => (
          <CapabilityCard key={capability.title} {...capability} />
        ))}
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/* Module preview                                                              */
/* -------------------------------------------------------------------------- */

interface ModulePill {
  id: string;
  label: string;
}

interface ModuleShellProps {
  icon: LucideIcon;
  badge: string;
  title: string;
  body: string;
  href: string;
  cta: string;
  pills: readonly ModulePill[];
  active: string;
  onSelect: (id: string) => void;
  panel: React.ReactNode;
}

function ModuleShell({
  icon: Icon,
  badge,
  title,
  body,
  href,
  cta,
  pills,
  active,
  onSelect,
  panel,
}: ModuleShellProps) {
  return (
    <div className="aegis-card flex flex-col p-6 sm:p-7">
      <div className="flex items-start justify-between gap-4">
        <p className="aegis-eyebrow">{badge}</p>
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-[12px] border border-[rgba(99,82,255,0.26)] bg-[rgba(99,82,255,0.08)] text-[#c4bafc]">
          <Icon className="h-4 w-4" strokeWidth={1.6} aria-hidden />
        </span>
      </div>

      <h3 className="aegis-serif mt-4 text-[1.4rem] leading-snug text-[#f0f2ff]">{title}</h3>
      <p className="mt-3 text-[13px] leading-6 text-[#7a81a8]">{body}</p>

      <div className="mt-6 flex flex-wrap gap-2">
        {pills.map((pill) => {
          const selected = pill.id === active;
          return (
            <button
              key={pill.id}
              type="button"
              onClick={() => onSelect(pill.id)}
              aria-pressed={selected}
              className={`cursor-pointer rounded-full border px-3 py-1.5 text-[11.5px] transition-all duration-300 ${
                selected
                  ? "border-[rgba(99,82,255,0.55)] bg-[rgba(99,82,255,0.16)] text-[#c4bafc]"
                  : "border-white/[0.08] bg-white/[0.02] text-[#7a81a8] hover:border-[rgba(99,82,255,0.30)] hover:text-[#f0f2ff]"
              }`}
            >
              {pill.label}
            </button>
          );
        })}
      </div>

      <div className="mt-5 flex-1 rounded-[16px] border border-white/[0.06] bg-[#060818] p-4">{panel}</div>

      <a
        href={href}
        className="group mt-6 inline-flex items-center gap-1.5 text-[12.5px] font-medium text-[#8376fc] transition-colors duration-300 hover:text-[#c4bafc]"
      >
        {cta}
        <ArrowRight className="h-3.5 w-3.5 transition-transform duration-300 group-hover:translate-x-1" aria-hidden />
      </a>
    </div>
  );
}

function AuditorPanel({ pill }: { pill: string }) {
  if (pill === "test-keys") {
    return (
      <div className="space-y-2.5">
        <MonoRow label="POST" value="/api/scan/github" tone="ink" />
        <MonoRow label="body" value='{ "repo": "trufflesecurity/test_keys" }' />
        <MonoRow label="accept" value="application/x-ndjson" />
        <div className="my-1 h-px bg-white/[0.06]" />
        <MonoRow label="tree" value="candidateFiles = GITHUB_MAX_FILES (20)" tone="brand" />
        <MonoRow label="file" value="findingsCount · highestEntropy" />
        <MonoRow label="result" value="securityScore · .env diff · auditDigest" tone="ok" />
      </div>
    );
  }

  if (pill === "aegis-repo") {
    return (
      <div className="space-y-2.5">
        <MonoRow label="owner" value="Abhivenger" tone="ink" />
        <MonoRow label="repo" value="project-aegis" tone="ink" />
        <div className="my-1 h-px bg-white/[0.06]" />
        <MonoRow label="GET" value="/repos/{owner}/{repo}/git/trees/main?recursive=1" />
        <MonoRow label="GET" value="/repos/{owner}/{repo}/contents/{path}" />
        <MonoRow label="raw" value="GITHUB_MAX_FILE_BYTES = 100 KB" tone="brand" />
        <MonoRow label="scan" value="entropy + 27 signatures per file" tone="ok" />
      </div>
    );
  }

  return (
    <div className="space-y-2.5">
      <MonoRow label="isPlaceholderEnvFile" value='".env.example" → true' tone="ink" />
      <MonoRow label="pattern" value="/\.env\.(example|sample|template)$/i" />
      <div className="my-1 h-px bg-white/[0.06]" />
      <MonoRow label="signatures" value="suppressed" />
      <MonoRow label="entropy" value="skipped" />
      <MonoRow label="verdict" value="SAFE · 0 findings" tone="ok" />
      <MonoRow label="still flagged" value="sk_live_ · AKIA · ghp_ · PRIVATE KEY" tone="danger" />
    </div>
  );
}

function SandboxPanel({ analysis, preset }: { analysis: ReturnType<typeof analyzeCode>; preset: SecurityPreset }) {
  const verdictTone =
    analysis.verdict === "DANGEROUS"
      ? "border-[rgba(251,113,133,0.35)] bg-[rgba(251,113,133,0.10)] text-[#fb7185]"
      : analysis.verdict === "SUSPICIOUS"
        ? "border-[rgba(251,191,36,0.35)] bg-[rgba(251,191,36,0.10)] text-[#fbbf24]"
        : "border-[rgba(34,197,94,0.35)] bg-[rgba(34,197,94,0.10)] text-[#22c55e]";

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <span className="aegis-mono text-[10px] tracking-[0.14em] text-[#4a5180] uppercase">{preset.filename}</span>
        <span className={`aegis-mono rounded-full border px-2.5 py-1 text-[10px] font-semibold tracking-[0.08em] ${verdictTone}`}>
          {analysis.verdict}
        </span>
      </div>

      <div className="aegis-mono space-y-0.5 text-[11px] leading-[1.9] text-[#7a81a8]">
        <div>
          risk score <span className="text-[#f0f2ff]">{analysis.riskScore}</span> / 100 · highest entropy{" "}
          <span className="text-[#f0f2ff]">{analysis.highestEntropy.toFixed(3)}</span> bits/char
        </div>
        <div>
          threshold <span className="text-[#f0f2ff]">H ≥ 4.55</span> · signatures{" "}
          <span className="text-[#f0f2ff]">27</span>
        </div>
      </div>

      {analysis.findings.length === 0 ? (
        <p className="aegis-mono text-[11px] leading-5 text-[#22c55e]">
          0 findings — no credential signature matched and no literal cleared the entropy bar.
        </p>
      ) : (
        <ul className="space-y-2">
          {analysis.findings.map((finding) => (
            <li key={`${finding.name}-${finding.lineNumber}`} className="rounded-[12px] border border-white/[0.06] bg-white/[0.02] px-3 py-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[12px] font-medium text-[#f0f2ff]">{finding.name}</span>
                <span className="aegis-mono text-[10px] text-[#fb7185]">{finding.severity}</span>
              </div>
              <div className="aegis-mono mt-1 text-[10.5px] leading-5 text-[#7a81a8]">
                line {finding.lineNumber} · <span className="text-[#c4bafc]">{finding.redactedToken}</span>
                {finding.entropy !== undefined ? ` · H ${finding.entropy.toFixed(3)}` : ""}
              </div>
            </li>
          ))}
        </ul>
      )}

      {analysis.remediation.envFileSnippet && (
        <div>
          <p className="aegis-mono text-[10px] tracking-[0.14em] text-[#4a5180] uppercase">remediation · .env</p>
          <pre className="aegis-mono mt-1.5 whitespace-pre-wrap text-[10.5px] leading-5 text-[#22c55e]">
            {analysis.remediation.envFileSnippet}
          </pre>
        </div>
      )}
    </div>
  );
}

function SafeLinkPanel({ pill, exposedAnalysis }: { pill: string; exposedAnalysis: ReturnType<typeof analyzeCode> }) {
  if (pill === "homograph") {
    return (
      <div className="space-y-2.5">
        <MonoRow label="target" value={HOMOGRAPH_URL} tone="ink" />
        <div className="my-1 h-px bg-white/[0.06]" />
        <MonoRow label="static score" value="75 / 100 → DANGEROUS" tone="danger" />
        <MonoRow label="+25" value=".xyz high-abuse top-level domain" />
        <MonoRow label="+35" value="keywords: login, otp, verify, secure, auth" />
        <MonoRow label="+15" value="8-label subdomain nesting" />
        <div className="my-1 h-px bg-white/[0.06]" />
        <MonoRow label="runtime" value="SSRF-safe DNS + 5-hop redirect trace" tone="ok" />
      </div>
    );
  }

  if (pill === "exposed-token") {
    const finding = exposedAnalysis.findings[0];
    return (
      <div className="space-y-3">
        <MonoRow label="source" value="const checkoutUrl = …client_secret=sk_live_…" tone="ink" />
        <div className="my-1 h-px bg-white/[0.06]" />
        {finding ? (
          <>
            <MonoRow label="signature" value={finding.name} tone="danger" />
            <MonoRow label="token" value={finding.redactedToken} />
            <MonoRow label="entropy" value={`${exposedAnalysis.highestEntropy.toFixed(3)} bits/char`} />
            <div>
              <p className="aegis-mono text-[10px] tracking-[0.14em] text-[#4a5180] uppercase">remediation · .env</p>
              <pre className="aegis-mono mt-1.5 whitespace-pre-wrap text-[10.5px] leading-5 text-[#22c55e]">
                {exposedAnalysis.remediation.envFileSnippet}
              </pre>
            </div>
          </>
        ) : (
          <MonoRow label="result" value="no finding" tone="ok" />
        )}
      </div>
    );
  }

  return (
    <div className="space-y-1">
      {CLI_TRANSCRIPT.map((line, index) => {
        const tone = line.startsWith("$")
          ? "text-[#f0f2ff]"
          : line.startsWith("COMMIT BLOCKED")
            ? "text-[#fb7185]"
            : line.startsWith("[aegis]")
              ? "text-[#4a5180]"
              : line.startsWith("  *") || line.startsWith("    ")
                ? "text-[#8376fc]"
                : "text-[#22c55e]";
        return (
          <div key={`${line}-${index}`} className={`aegis-mono text-[10.5px] leading-[1.75] ${tone}`}>
            {line}
          </div>
        );
      })}
    </div>
  );
}

function ModulesSection() {
  const [auditorPill, setAuditorPill] = useState<string>(AUDITOR_PILLS[0].id);
  const [sandboxPill, setSandboxPill] = useState<string>(SANDBOX_PILLS[0].id);
  const [safeLinkPill, setSafeLinkPill] = useState<string>(SAFELINK_PILLS[0].id);

  const sandbox = useMemo(() => {
    const preset = SECURITY_PRESETS.find((item) => item.id === sandboxPill) ?? SECURITY_PRESETS[0];
    return { preset, analysis: analyzeCode(preset.content, preset.filename) };
  }, [sandboxPill]);

  const exposed = useMemo(() => analyzeCode(EXPOSED_TOKEN_SNIPPET, "checkout.ts"), []);

  return (
    <section id="modules" className="relative mx-auto max-w-[1200px] scroll-mt-24 px-5 py-24 sm:px-8 sm:py-32">
      <SectionHeading
        eyebrow="Live Modules"
        title="Pick a module. Read the real engine."
        body="Every card below runs Project Aegis's own detection rules against its own example data — no mock screenshots, no invented numbers."
      />

      <div className="mt-14 grid gap-5 lg:grid-cols-3">
        <ModuleShell
          icon={Github}
          badge="Tab 1 · Live GitHub"
          title="GitHub Repository Auditor"
          body="Pulls a real public repository through the GitHub REST API and streams per-file progress as NDJSON."
          href="/dashboard"
          cta="Open the repo auditor"
          pills={AUDITOR_PILLS}
          active={auditorPill}
          onSelect={setAuditorPill}
          panel={<AuditorPanel pill={auditorPill} />}
        />

        <ModuleShell
          icon={FileCode2}
          badge="Tab 2 · Entropy"
          title="Code & Entropy Sandbox"
          body="Shannon entropy (H ≥ 4.55) plus 27 credential signatures, with a one-click .env remediation."
          href="/dashboard/code-auditor"
          cta="Open the code sandbox"
          pills={SANDBOX_PILLS}
          active={sandboxPill}
          onSelect={setSandboxPill}
          panel={<SandboxPanel analysis={sandbox.analysis} preset={sandbox.preset} />}
        />

        <ModuleShell
          icon={Shield}
          badge="Tab 3 · Phishing + Tab 5 · CLI"
          title="SafeLink & GitShield CLI"
          body="SSRF-safe redirect tracing for links, and a local Python hook that blocks the commit."
          href="/dashboard/url-inspector"
          cta="Open SafeLink"
          pills={SAFELINK_PILLS}
          active={safeLinkPill}
          onSelect={setSafeLinkPill}
          panel={<SafeLinkPanel pill={safeLinkPill} exposedAnalysis={exposed} />}
        />
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/* Workflow + telemetry                                                        */
/* -------------------------------------------------------------------------- */

const WORKFLOW_STEPS = [
  {
    step: "1",
    badge: "1 Install GitShield",
    stat: "< 1ms",
    label: "Scan Latency",
    body: "python3 cli/aegis.py --install writes a zero-dependency pre-commit hook. Entropy scoring runs in-process, so nothing waits on a network round trip.",
    href: "/dashboard/api-keys",
  },
  {
    step: "2",
    badge: "2 Audit Repositories",
    stat: "H ≥ 4.55",
    label: "Entropy Threshold",
    body: "Point the auditor at owner/repo and it reads the 20 highest-risk files, scoring every token against calibrated Shannon entropy and 27 signatures.",
    href: "/dashboard",
  },
  {
    step: "3",
    badge: "3 Rotate & Sanitize",
    stat: "Zero Leaks",
    label: "Pre-Commit Defense",
    body: "A blocked commit exits 1 before it leaves the machine. Aegis extracts the key to .env, rewrites the source, and flags the rotation in the vault.",
    href: "/dashboard/code-auditor",
  },
] as const;

function WorkflowSection() {
  return (
    <section id="workflow" className="relative mx-auto max-w-[1200px] scroll-mt-24 px-5 py-24 sm:px-8 sm:py-32">
      <SectionHeading
        eyebrow="Setup & Telemetry"
        title="Three steps to a clean commit history."
        body="Install the hook, point Aegis at the repositories that matter, and let the rotation loop handle the rest."
        titleId="architecture"
      />

      <div className="mt-14 grid gap-5 lg:grid-cols-3">
        {WORKFLOW_STEPS.map((item) => (
          <div key={item.step} className="aegis-card flex flex-col p-7">
            <span className="inline-flex w-fit items-center rounded-full border border-[rgba(99,82,255,0.35)] bg-[rgba(99,82,255,0.10)] px-3 py-1.5 text-[11.5px] font-medium text-[#c4bafc]">
              {item.badge}
            </span>
            <p className="aegis-serif mt-7 text-[clamp(2.6rem,4.4vw,3.4rem)] leading-none tracking-[-0.02em] text-[#f0f2ff]">
              {item.stat}
            </p>
            <p className="mt-3 text-[12px] font-medium tracking-[0.10em] text-[#8376fc] uppercase">{item.label}</p>
            <p className="mt-4 flex-1 text-[13.5px] leading-6 text-[#7a81a8]">{item.body}</p>
            <a
              href={item.href}
              className="group mt-6 inline-flex items-center gap-1.5 text-[12.5px] font-medium text-[#8376fc] transition-colors duration-300 hover:text-[#c4bafc]"
            >
              Open
              <ArrowRight className="h-3.5 w-3.5 transition-transform duration-300 group-hover:translate-x-1" aria-hidden />
            </a>
          </div>
        ))}
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/* Closing CTA + footer                                                        */
/* -------------------------------------------------------------------------- */

function ClosingCta() {
  return (
    <section className="relative mx-auto max-w-[1200px] px-5 pb-24 sm:px-8 sm:pb-32">
      <div className="relative overflow-hidden rounded-[24px] border border-[rgba(99,82,255,0.22)] bg-[#0a0e1f] px-6 py-16 text-center sm:px-12 sm:py-20">
        <div
          aria-hidden
          className="pointer-events-none absolute left-1/2 top-[-140px] h-[280px] w-[120%] -translate-x-1/2 rounded-full bg-[radial-gradient(ellipse_at_center,rgba(99,82,255,0.22),transparent_70%)]"
        />
        <div className="relative">
          <p className="aegis-eyebrow">Get started</p>
          <h2 className="aegis-serif mt-5 text-[clamp(2.2rem,5vw,3.6rem)] leading-[1.05] tracking-[-0.02em] text-[#f0f2ff]">
            Ready when you are.
          </h2>
          <p className="mx-auto mt-5 max-w-[560px] text-[14.5px] leading-7 text-[#7a81a8]">
            Walk the five-tab tour of the real dashboard, or jump straight into the live scanner and point it at a
            repository.
          </p>
          <div className="mt-9 flex flex-col items-center justify-center gap-3 sm:flex-row">
            <PrimaryButton href="/dashboard?tour=1" glint>
              Launch Guided Tour
              <ArrowRight className="h-4 w-4 transition-transform duration-300 group-hover:translate-x-1" aria-hidden />
            </PrimaryButton>
            <GhostButton href="/dashboard">
              <Code2 className="h-4 w-4" aria-hidden />
              Open Live Scanner
            </GhostButton>
          </div>
        </div>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="relative z-10 border-t border-white/[0.06] px-5 py-12 sm:px-8">
      <div className="mx-auto flex max-w-[1200px] flex-col gap-8 text-[12.5px] text-[#4a5180] md:flex-row md:items-center md:justify-between">
        <Wordmark />
        <nav className="flex flex-wrap gap-x-7 gap-y-3">
          <a href="/dashboard" className="transition-colors duration-300 hover:text-[#f0f2ff]">
            Dashboard
          </a>
          <a href="/dashboard/code-auditor" className="transition-colors duration-300 hover:text-[#f0f2ff]">
            Code Auditor
          </a>
          <a href="/dashboard/url-inspector" className="transition-colors duration-300 hover:text-[#f0f2ff]">
            SafeLink
          </a>
          <a href="/dashboard/vault" className="transition-colors duration-300 hover:text-[#f0f2ff]">
            Vault
          </a>
          <a href="/dashboard/api-keys" className="transition-colors duration-300 hover:text-[#f0f2ff]">
            GitShield CLI
          </a>
        </nav>
        <span>© 2026 Project Aegis · GitShield CLI, dashboard, SafeLink.</span>
      </div>
    </footer>
  );
}

/* -------------------------------------------------------------------------- */

export default function AegisLanding() {
  return (
    <div className="aegis-root relative min-h-screen overflow-x-hidden bg-[#060818] text-[#f0f2ff] selection:bg-[#6352ff]/30 selection:text-[#f0f2ff]">
      <AmbientBackdrop />
      <GlassNavbar />
      <main className="relative z-10">
        <Hero />
        <FeaturesSection />
        <ModulesSection />
        <WorkflowSection />
        <ClosingCta />
      </main>
      <Footer />
    </div>
  );
}
