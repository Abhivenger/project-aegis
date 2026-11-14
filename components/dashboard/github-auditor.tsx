"use client";

import React, { useEffect, useRef, useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import { toast } from "sonner";
import {
  AlertTriangle,
  BadgeCheck,
  CheckCircle2,
  ChevronDown,
  Circle,
  Code2,
  ExternalLink,
  FileText,
  Fingerprint,
  GitBranch,
  Github,
  Loader2,
  RefreshCw,
  Search,
  ShieldAlert,
  Star,
  XCircle,
  Zap,
} from "lucide-react";
import { VulnerabilityCard } from "@/components/vulnerability-card";
import { useDashboardQuota } from "@/lib/quota-context";
import { TOUR_SAMPLE_SCAN_EVENT, type SampleRepo } from "@/lib/tour-bus";
import {
  GITHUB_MAX_FILES,
  classifyRepoBadge,
  type FindingSeverity,
  type GithubRepositoryInfo,
  type GithubScanEvent,
  type GithubScanResult,
  type RepoBadge,
} from "@/lib/scanners/github-auditor";

const SAMPLE_REPOS = ["Abhivenger/project-aegis", "expressjs/express", "vercel/next.js"] as const;

type Phase = "idle" | "scanning" | "complete" | "error";
type StepState = "pending" | "active" | "done";
type FileProgressEvent = Extract<GithubScanEvent, { type: "file" }>;
type TreeProgress = Extract<GithubScanEvent, { type: "tree" }>;

interface ScanError {
  title: string;
  message: string;
}

class ScanRequestError extends Error {
  readonly title: string;

  constructor(title: string, message: string) {
    super(message);
    this.name = "ScanRequestError";
    this.title = title;
  }
}

function isAbortError(error: unknown): boolean {
  return (
    (error instanceof DOMException && error.name === "AbortError") ||
    (error instanceof Error && error.name === "AbortError")
  );
}

function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

function badgeClass(badge: RepoBadge): string {
  if (badge === "DANGEROUS")
    return "border-rose-500/40 bg-rose-500/10 text-rose-300 shadow-[inset_0_0_12px_rgba(244,63,94,0.14)]";
  if (badge === "CAUTION")
    return "border-amber-500/40 bg-amber-500/10 text-amber-300 shadow-[inset_0_0_12px_rgba(245,158,11,0.14)]";
  return "border-emerald-500/40 bg-emerald-500/10 text-emerald-300 shadow-[inset_0_0_12px_rgba(16,185,129,0.14)]";
}

function BadgeIcon({ badge }: { badge: RepoBadge }) {
  if (badge === "DANGEROUS") return <ShieldAlert className="h-3 w-3 shrink-0" />;
  if (badge === "CAUTION") return <AlertTriangle className="h-3 w-3 shrink-0" />;
  return <BadgeCheck className="h-3 w-3 shrink-0" />;
}

function badgeLabel(badge: RepoBadge): string {
  return badge === "VERIFIED_CLEAN" ? "VERIFIED CLEAN" : badge;
}

function severityClass(severity: FindingSeverity): string {
  if (severity === "CRITICAL") return "border-rose-500/40 bg-rose-500/10 text-rose-300";
  if (severity === "HIGH") return "border-orange-500/40 bg-orange-500/10 text-orange-300";
  return "border-amber-500/40 bg-amber-500/10 text-amber-300";
}

function scoreTone(score: number): string {
  if (score >= 90) return "text-emerald-300";
  if (score >= 60) return "text-amber-300";
  return "text-rose-300";
}

function Telemetry({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="min-w-0 rounded-xl border border-white/[0.06] bg-white/[0.02] px-3 py-2.5 transition-all duration-200 ease-out">
      <div className="flex items-center gap-1.5 text-[9px] uppercase tracking-widest text-zinc-500">
        {icon}
        {label}
      </div>
      <div className="mt-1 truncate font-mono text-sm font-semibold tabular-nums text-zinc-100" title={value}>
        {value}
      </div>
    </div>
  );
}

function Step({ state, label }: { state: StepState; label: string }) {
  return (
    <li className="flex items-center gap-2.5 text-xs">
      {state === "done" ? (
        <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
      ) : state === "active" ? (
        <Loader2 className="h-4 w-4 shrink-0 animate-spin text-cyan-300 motion-reduce:animate-none" />
      ) : (
        <Circle className="h-4 w-4 shrink-0 text-zinc-700" />
      )}
      <span
        className={
          state === "done" ? "text-zinc-400" : state === "active" ? "text-cyan-100" : "text-zinc-600"
        }
      >
        {label}
      </span>
    </li>
  );
}

export function GithubAuditor({ embedded = false }: { embedded?: boolean }) {
  const [input, setInput] = useState<string>(SAMPLE_REPOS[0]);
  const [phase, setPhase] = useState<Phase>("idle");
  const [repository, setRepository] = useState<GithubRepositoryInfo | null>(null);
  const [tree, setTree] = useState<TreeProgress | null>(null);
  const [fileEvents, setFileEvents] = useState<FileProgressEvent[]>([]);
  const [result, setResult] = useState<GithubScanResult | null>(null);
  const [error, setError] = useState<ScanError | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const reducedMotion = useReducedMotion();
  const quota = useDashboardQuota();
  const scanning = phase === "scanning";
  const fetchedCount = fileEvents.length;
  const candidateCount = tree?.candidateFiles ?? 0;
  const allFetched = tree !== null && fetchedCount >= candidateCount;
  const progressScale = candidateCount > 0 ? Math.min(1, fetchedCount / candidateCount) : 0;
  const Heading = embedded ? "h2" : "h1";

  useEffect(() => () => abortRef.current?.abort(), []);

  const steps: { state: StepState; label: string }[] = [
    {
      state: tree ? "done" : "active",
      label: repository
        ? `Fetching repository tree for ${repository.fullName}...`
        : "Fetching repository tree...",
    },
    {
      state: !tree ? "pending" : allFetched ? "done" : "active",
      label: `Auditing ${tree ? candidateCount : GITHUB_MAX_FILES} files with Shannon Entropy & regex signature rules...`,
    },
    { state: allFetched ? "active" : "pending", label: "Computing security score..." },
  ];
  const activeStep = steps.find((step) => step.state === "active")?.label ?? "";

  const copyCleanEnv = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success("Clean .env copied to clipboard", {
        description: "Paste it into .env.local, add rotated values, and keep it out of git.",
      });
    } catch {
      toast.error("Clipboard access was denied", { description: "Select and copy the template manually." });
    }
  };

  const copyDigest = async (digest: string) => {
    try {
      await navigator.clipboard.writeText(digest);
      toast.success("Audit digest copied");
    } catch {
      toast.error("Clipboard access was denied");
    }
  };

  const fail = (title: string, message: string) => {
    setPhase("error");
    setError({ title, message });
    toast.error(title, { description: message });
  };

  const runScan = async (raw: string) => {
    const repoUrl = raw.trim();
    if (!repoUrl) {
      setPhase("idle");
      setError({ title: "Invalid repository", message: "Enter a repository as owner/repo or a GitHub URL." });
      inputRef.current?.focus();
      return;
    }
    if (quota?.quotaExhausted) {
      window.dispatchEvent(new Event("aegis:scan-blocked"));
      fail(
        "Daily scan quota exhausted",
        `${quota.dailyScanCount}/${quota.maxDailyQuota} scans used today. Upgrade to Enterprise to keep scanning repositories.`
      );
      return;
    }

    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setPhase("scanning");
    setRepository(null);
    setTree(null);
    setFileEvents([]);
    setResult(null);
    setError(null);

    const handleEvent = (event: GithubScanEvent) => {
      switch (event.type) {
        case "metadata":
          setRepository(event.repository);
          break;
        case "tree":
          setTree(event);
          break;
        case "file":
          setFileEvents((previous) => [...previous, event]);
          break;
        case "result": {
          const { summary } = event.result;
          setResult(event.result);
          setPhase("complete");
          window.dispatchEvent(new Event("aegis:scan"));
          const unavailable =
            summary.filesFailed > 0 ? ` · ${plural(summary.filesFailed, "file")} unavailable` : "";
          if (summary.findingsCount > 0) {
            toast.error(`${plural(summary.findingsCount, "exposed secret")} found`, {
              description: `${event.result.repository.fullName} · score ${event.result.securityScore}/100${unavailable}`,
            });
          } else {
            toast.success("Verified clean — 0 exposed secrets", {
              description: `${plural(summary.filesScanned, "file")} audited in ${event.result.repository.fullName}${unavailable}`,
            });
          }
          break;
        }
        case "error":
          throw new ScanRequestError(event.error, event.message);
      }
    };

    try {
      const response = await fetch("/api/scan/github", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/x-ndjson" },
        body: JSON.stringify({ repoUrl }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const payload = (await response.json().catch(() => null)) as {
          error?: unknown;
          message?: unknown;
        } | null;
        const title = typeof payload?.error === "string" ? payload.error : "Repository scan failed";
        const message =
          typeof payload?.message === "string" ? payload.message : `The server returned HTTP ${response.status}.`;
        if (response.status === 429 && title.toLowerCase().includes("quota")) {
          window.dispatchEvent(new Event("aegis:scan-blocked"));
        }
        throw new ScanRequestError(title, message);
      }
      if (!response.body) {
        throw new ScanRequestError("Repository scan failed", "The server returned an empty scan stream.");
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      const parseLine = (line: string) => {
        try {
          return JSON.parse(line) as GithubScanEvent;
        } catch {
          throw new ScanRequestError("Repository scan failed", "The scan stream returned malformed data.");
        }
      };

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let newlineIndex: number;
          while ((newlineIndex = buffer.indexOf("\n")) !== -1) {
            const line = buffer.slice(0, newlineIndex).trim();
            buffer = buffer.slice(newlineIndex + 1);
            if (line) handleEvent(parseLine(line));
          }
        }
        const tail = buffer.trim();
        if (tail) handleEvent(parseLine(tail));
      } finally {
        reader.releaseLock();
      }
    } catch (err) {
      if (isAbortError(err)) return;
      if (err instanceof ScanRequestError) {
        fail(err.title, err.message);
      } else if (err instanceof TypeError) {
        fail("Network error", "Could not reach the Aegis scanner. Check your connection and retry.");
      } else {
        fail("Repository scan failed", err instanceof Error ? err.message : "Unexpected error.");
      }
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
    }
  };

  const runScanRef = useRef(runScan);
  useEffect(() => {
    runScanRef.current = runScan;
  });

  // The guided tour asks for a real sample scan through the event bus, so the
  // tour never has to know how the auditor is implemented.
  useEffect(() => {
    const onSampleScan = (event: Event) => {
      const repo = (event as CustomEvent<SampleRepo>).detail;
      if (!repo || abortRef.current) return;
      setInput(repo);
      void runScanRef.current(repo);
    };
    window.addEventListener(TOUR_SAMPLE_SCAN_EVENT, onSampleScan);
    return () => window.removeEventListener(TOUR_SAMPLE_SCAN_EVENT, onSampleScan);
  }, []);

  const verifiedClean =
    result !== null && result.summary.filesScanned > 0 && result.summary.findingsCount === 0;
  const badge = result ? classifyRepoBadge(result.securityScore, result.findings) : "VERIFIED_CLEAN";

  return (
    <section id="github-scanner" className="scroll-mt-6 space-y-6" aria-labelledby="github-scanner-title">
      <div>
        <div className="mb-1 flex items-center gap-2">
          <Github className="h-5 w-5 text-cyan-400" />
          <Heading id="github-scanner-title" className="text-xl font-bold tracking-tight text-white sm:text-2xl">
            Live GitHub Repository Scanner
          </Heading>
        </div>
        <p className="text-xs leading-relaxed text-zinc-400 sm:text-sm">
          Pulls a public repository through the GitHub REST API and audits its {GITHUB_MAX_FILES} highest-risk
          files with the same Shannon entropy and regex signature engines as GitShield.
        </p>
      </div>

      <div
        data-tour="repo-search"
        className="rounded-2xl border border-white/[0.08] bg-white/[0.02] p-4 shadow-2xl backdrop-blur-xl sm:p-5"
      >
        <form
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            void runScan(input);
          }}
        >
          <label htmlFor="github-repository" className="font-mono text-xs text-zinc-400">
            Repository
          </label>
          <div className="mt-2 flex flex-col gap-2 sm:flex-row">
            <div className="flex min-w-0 flex-1 items-center gap-2 rounded-xl border border-slate-800 bg-[#030712] px-3 focus-within:border-cyan-500/50">
              <Github className="h-4 w-4 shrink-0 text-zinc-500" aria-hidden="true" />
              <input
                ref={inputRef}
                id="github-repository"
                type="text"
                value={input}
                maxLength={300}
                autoComplete="off"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                aria-invalid={phase !== "error" && Boolean(error)}
                aria-describedby="github-repository-hint"
                onChange={(event) => {
                  setInput(event.target.value);
                  if (phase !== "error") setError(null);
                }}
                placeholder="owner/repo or https://github.com/owner/repo"
                className="h-11 w-full min-w-0 bg-transparent font-mono text-sm text-white placeholder:text-zinc-600 focus:outline-none"
              />
            </div>
            <button
              type="submit"
              disabled={scanning}
              className="flex min-h-11 items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-5 text-xs font-bold text-slate-950 shadow-lg shadow-emerald-500/20 transition-all duration-200 ease-out hover:from-emerald-400 hover:to-cyan-400 disabled:opacity-50 sm:text-sm"
            >
              {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              {scanning ? "Scanning..." : "Scan repository"}
            </button>
          </div>
          <p id="github-repository-hint" className="mt-2 text-[11px] text-zinc-500">
            Public repositories only. Files are fetched from GitHub and scanned in memory; secrets are masked before
            they leave the server.
          </p>
          {phase !== "error" && error && (
            <p role="alert" className="mt-2 text-xs text-rose-300">
              {error.message}
            </p>
          )}
        </form>

        <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-slate-800/80 pt-3">
          <span className="text-[10px] uppercase tracking-widest text-zinc-500">Real repos</span>
          {SAMPLE_REPOS.map((repo) => (
            <button
              key={repo}
              type="button"
              disabled={scanning}
              onClick={() => {
                setInput(repo);
                void runScan(repo);
              }}
              className={`rounded-full border px-3 py-1.5 font-mono text-[11px] tabular-nums transition-all duration-200 ease-out disabled:cursor-wait disabled:opacity-50 ${
                input === repo
                  ? "border-cyan-500/40 bg-cyan-500/10 text-cyan-200"
                  : "border-slate-800 bg-slate-900/60 text-zinc-400 hover:border-slate-700 hover:text-zinc-200"
              }`}
            >
              {repo}
            </button>
          ))}
        </div>
      </div>

      {phase === "error" && error && (
        <div
          role="alert"
          className="flex flex-col gap-3 rounded-2xl border border-rose-500/30 bg-rose-950/20 p-4 sm:flex-row sm:items-center sm:justify-between"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-rose-400" />
            <div>
              <p className="text-sm font-semibold text-rose-200">{error.title}</p>
              <p className="mt-1 text-xs leading-5 text-rose-300">{error.message}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => void runScan(input)}
            className="flex min-h-10 shrink-0 items-center justify-center gap-2 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 text-xs font-semibold text-rose-200 transition hover:bg-rose-500/20"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Retry
          </button>
        </div>
      )}

      {scanning && (
        <div className="rounded-2xl border border-cyan-500/20 bg-cyan-500/[0.03] p-4 shadow-2xl backdrop-blur-xl sm:p-5">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <ol className="space-y-2.5" aria-label="Scan progress">
              {steps.map((step) => (
                <Step key={step.label} state={step.state} label={step.label} />
              ))}
            </ol>
            {tree && (
              <span className="shrink-0 font-mono text-[11px] tabular-nums text-zinc-400">
                {Math.min(fetchedCount, candidateCount)} / {candidateCount} files
              </span>
            )}
          </div>
          <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-slate-800">
            {candidateCount > 0 ? (
              <motion.div
                initial={false}
                animate={{ transform: `scaleX(${progressScale})` }}
                transition={{ duration: reducedMotion ? 0 : 0.2, ease: "easeOut" }}
                className="h-full w-full origin-left rounded-full bg-gradient-to-r from-cyan-400 to-emerald-400"
              />
            ) : (
              <div className="h-full w-full animate-pulse rounded-full bg-gradient-to-r from-cyan-500/50 to-emerald-500/50 motion-reduce:animate-none" />
            )}
          </div>
          <p role="status" aria-live="polite" className="sr-only">
            {activeStep}
          </p>

          {fileEvents.length > 0 && (
            <ul
              aria-label="Files fetched from GitHub"
              className="mt-3 max-h-56 space-y-1 overflow-auto rounded-xl border border-slate-800 bg-[#030712] p-2"
            >
              {fileEvents.map((event) => (
                <li
                  key={event.path}
                  className="flex min-w-0 items-center justify-between gap-3 rounded-lg px-2 py-1.5 text-[11px]"
                >
                  <span className="flex min-w-0 items-center gap-2">
                    {event.status === "scanned" ? (
                      <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-400" />
                    ) : (
                      <XCircle className="h-3.5 w-3.5 shrink-0 text-amber-400" />
                    )}
                    <span className="truncate font-mono text-zinc-300" title={event.path}>
                      {event.path}
                    </span>
                  </span>
                  <span
                    className={`shrink-0 ${
                      event.status === "failed"
                        ? "text-amber-300"
                        : event.findingsCount > 0
                          ? "text-rose-300"
                          : "text-emerald-300"
                    }`}
                  >
                    {event.status === "failed"
                      ? "unavailable"
                      : event.findingsCount > 0
                        ? plural(event.findingsCount, "finding")
                        : "clean"}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {result && (
        <div className="space-y-4">
          <div
            data-tour="repo-telemetry"
            className="rounded-2xl border border-white/[0.08] bg-white/[0.02] p-4 shadow-2xl backdrop-blur-xl sm:p-5"
          >
            <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="truncate text-base font-semibold tracking-tight text-white">
                    {result.repository.fullName}
                  </h3>
                  <span
                    className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-[10px] font-bold tabular-nums ${badgeClass(badge)}`}
                  >
                    <BadgeIcon badge={badge} />
                    {badgeLabel(badge)}
                  </span>
                  <a
                    href={result.repository.htmlUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center gap-1 text-[11px] text-zinc-400 transition-all duration-200 ease-out hover:text-cyan-200"
                  >
                    GitHub <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
                {result.repository.description && (
                  <p className="mt-1 line-clamp-2 text-xs leading-5 text-zinc-400">
                    {result.repository.description}
                  </p>
                )}
              </div>
              <div className="shrink-0 text-left sm:text-right">
                <div
                  className={`font-mono text-3xl font-extrabold tabular-nums tracking-tight ${scoreTone(result.securityScore)}`}
                >
                  {result.securityScore}
                  <span className="text-sm font-medium text-zinc-500">/100</span>
                </div>
                <div className="text-[9px] uppercase tracking-widest text-zinc-500">Security score</div>
              </div>
            </div>
            <div className="mt-4 grid grid-cols-2 gap-2 lg:grid-cols-4">
              <Telemetry
                icon={<Star className="h-3 w-3" />}
                label="Stars"
                value={result.repo.stars.toLocaleString()}
              />
              <Telemetry
                icon={<Code2 className="h-3 w-3" />}
                label="Primary language"
                value={result.repo.language ?? "Unknown"}
              />
              <Telemetry icon={<GitBranch className="h-3 w-3" />} label="Default branch" value={result.repo.branch} />
              <Telemetry
                icon={<FileText className="h-3 w-3" />}
                label="Files scanned"
                value={`${result.repo.scannedFilesCount} / ${result.repo.totalFilesInTree.toLocaleString()}`}
              />
            </div>
            <p className="mt-3 text-[10px] leading-5 tabular-nums text-zinc-500">
              {plural(result.summary.candidateFiles, "high-risk candidate")} selected from{" "}
              {result.repo.totalFilesInTree.toLocaleString()} files in the tree · peak entropy{" "}
              {result.summary.highestEntropy.toFixed(2)} bits/char
              {result.summary.filesFailed > 0 ? ` · ${plural(result.summary.filesFailed, "file")} unavailable` : ""}
              {result.treeTruncated ? " · GitHub truncated the recursive tree" : ""}
            </p>
          </div>

          {result.summary.candidateFiles === 0 ? (
            <div className="flex items-start gap-3 rounded-2xl border border-slate-700 bg-slate-900/40 p-5">
              <FileText className="mt-0.5 h-5 w-5 shrink-0 text-zinc-400" />
              <div>
                <h3 className="text-sm font-semibold text-white">No high-risk files matched the filter</h3>
                <p className="mt-1 text-xs leading-5 text-zinc-400">
                  The tree has no .env, config, secret, key, or supported source files under 100 KB, so nothing was
                  downloaded.
                </p>
              </div>
            </div>
          ) : verifiedClean ? (
            <div role="status" className="overflow-hidden rounded-2xl border border-emerald-500/30 bg-emerald-950/20">
              <div className="flex flex-col gap-4 p-5 sm:flex-row sm:items-center">
                <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border border-emerald-400/40 bg-emerald-500/10 shadow-[0_0_24px_rgba(52,211,153,0.25)]">
                  <BadgeCheck className="h-8 w-8 text-emerald-300" />
                </div>
                <div className="min-w-0">
                  <h3 className="text-base font-bold text-emerald-200 sm:text-lg">
                    Verified Clean — 0 Exposed Secrets Found
                  </h3>
                  <p className="mt-1 text-xs leading-5 text-zinc-400">
                    {plural(result.summary.filesScanned, "file")} on{" "}
                    <span className="font-mono text-zinc-300">{result.repo.branch}</span> passed every signature
                    and entropy check. This covers the files listed below, not every possible vulnerability.
                  </p>
                </div>
              </div>
              <div className="border-t border-emerald-500/15 bg-black/20 px-5 py-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="flex items-center gap-1.5 text-[10px] uppercase tracking-widest text-emerald-300/80">
                    <Fingerprint className="h-3.5 w-3.5" /> SHA-256 audit digest
                  </span>
                  <span className="font-mono text-[10px] text-zinc-500">
                    {new Date(result.scannedAt).toLocaleString()}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => void copyDigest(result.auditDigest)}
                  title="Copy audit digest"
                  className="mt-1.5 block w-full break-all text-left font-mono text-[11px] text-emerald-200/90 transition hover:text-emerald-100"
                >
                  {result.auditDigest}
                </button>
                <ul aria-label="Inspected files" className="mt-3 grid gap-1 sm:grid-cols-2">
                  {result.scannedFiles.map((path) => (
                    <li key={path} className="flex min-w-0 items-center gap-1.5 text-[11px]">
                      <CheckCircle2 className="h-3 w-3 shrink-0 text-emerald-400" />
                      <span className="truncate font-mono text-zinc-300" title={path}>
                        {path}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          ) : (
            <>
              <div className="rounded-2xl border border-rose-500/25 bg-rose-500/[0.04] p-4 backdrop-blur-xl sm:p-5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="flex items-center gap-2 text-sm font-bold text-white">
                    <ShieldAlert className="h-4 w-4 text-rose-400" /> Exposed secrets
                  </h3>
                  <span className="font-mono text-[10px] tabular-nums text-zinc-500">
                    {plural(result.summary.findingsCount, "finding")} ·{" "}
                    {plural(result.summary.filesWithFindings, "file")}
                  </span>
                </div>
                <ul className="mt-3 divide-y divide-slate-800/80 overflow-hidden rounded-xl border border-slate-800 bg-[#030712]">
                  {result.findings.map((finding, index) => (
                    <li
                      key={`${finding.filePath}:${finding.lineNumber}:${index}`}
                      className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-[11px]"
                    >
                      <span
                        className={`rounded border px-1.5 py-0.5 font-mono text-[9px] font-bold ${severityClass(finding.severity)}`}
                      >
                        {finding.severity}
                      </span>
                      <span className="font-semibold text-zinc-200">{finding.ruleName}</span>
                      <span className="min-w-0 truncate font-mono text-zinc-400" title={finding.filePath}>
                        {finding.filePath}:{finding.lineNumber}
                      </span>
                      <span className="ml-auto flex items-center gap-3 font-mono">
                        <span className="text-rose-200">{finding.maskedMatch}</span>
                        <span className="tabular-nums text-cyan-300">H={finding.entropy.toFixed(2)}</span>
                      </span>
                    </li>
                  ))}
                </ul>
              </div>

              {result.fixes.map((fix, index) =>
                index === 0 ? (
                  <div key={fix.filePath} data-tour="repo-remediation">
                    <VulnerabilityCard
                      findings={fix.findings}
                      remediation={fix.remediation}
                      originalContent={fix.originalContent}
                      filename={fix.filePath}
                    />
                  </div>
                ) : (
                  <VulnerabilityCard
                    key={fix.filePath}
                    findings={fix.findings}
                    remediation={fix.remediation}
                    originalContent={fix.originalContent}
                    filename={fix.filePath}
                  />
                )
              )}

              {result.fixes.length < result.summary.filesWithFindings && (
                <p className="rounded-xl border border-slate-800 bg-slate-900/40 p-3 text-[11px] leading-5 text-zinc-400">
                  Showing remediation for the {result.fixes.length} highest-risk files. Every finding is listed
                  above.
                </p>
              )}

              {result.aggregateEnvSnippet && (
                <div
                  data-tour="copy-clean-env"
                  className="rounded-2xl border border-emerald-500/20 bg-emerald-950/10 p-4 backdrop-blur-xl sm:p-5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="text-sm font-semibold tracking-tight text-emerald-200">
                      Repository .env template
                    </h3>
                    <button
                      type="button"
                      onClick={() => void copyCleanEnv(result.aggregateEnvSnippet)}
                      className="flex items-center gap-1.5 rounded-lg border border-emerald-400/40 bg-emerald-500/15 px-3 py-1.5 text-[11px] font-bold text-emerald-100 shadow-[inset_0_0_12px_rgba(16,185,129,0.12)] transition-all duration-200 ease-out hover:bg-emerald-500/25"
                    >
                      <Zap className="h-3.5 w-3.5" /> Copy Clean .env
                    </button>
                  </div>
                  <pre
                    aria-label="Aggregate environment variable template"
                    className="mt-3 overflow-x-auto rounded-xl border border-emerald-500/10 bg-black/30 p-3 font-mono text-[11px] leading-6 text-emerald-200"
                  >
                    {result.aggregateEnvSnippet}
                  </pre>
                  <p className="mt-2 text-[10px] leading-5 text-zinc-500">
                    Keys are empty placeholders. Rotate every exposed credential first. No repository files are
                    changed.
                  </p>
                </div>
              )}
            </>
          )}

          {result.files.length > 0 && (
            <details className="group rounded-2xl border border-white/[0.08] bg-white/[0.02] shadow-2xl backdrop-blur-xl">
              <summary className="flex cursor-pointer list-none items-center justify-between gap-2 p-4 sm:px-5 [&::-webkit-details-marker]:hidden">
                <span className="text-sm font-semibold tracking-tight text-white">Scanned files</span>
                <span className="flex items-center gap-2 font-mono text-[10px] tabular-nums text-zinc-500">
                  {result.summary.filesScanned} scanned · {result.summary.filesWithFindings} flagged ·{" "}
                  {result.summary.filesFailed} unavailable
                  <ChevronDown className="h-4 w-4 transition-transform group-open:rotate-180 motion-reduce:transition-none" />
                </span>
              </summary>
              <ul className="mx-4 mb-4 max-h-80 divide-y divide-slate-800/80 overflow-auto rounded-xl border border-slate-800 bg-[#030712] sm:mx-5">
                {result.files.map((file) => (
                  <li key={file.path} className="flex items-center gap-2 px-3 py-2 text-[11px]">
                    <FileText className="h-3.5 w-3.5 shrink-0 text-zinc-500" />
                    <span className="min-w-0 flex-1 truncate font-mono text-zinc-300" title={file.error ?? file.path}>
                      {file.path}
                    </span>
                    {file.status === "scanned" && (
                      <span className="hidden font-mono text-zinc-500 sm:inline">
                        {file.highestEntropy.toFixed(2)} bits
                      </span>
                    )}
                    <span
                      className={`shrink-0 rounded border px-1.5 py-0.5 font-mono text-[9px] font-bold ${
                        file.status === "failed"
                          ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
                          : file.findingsCount > 0
                            ? "border-rose-500/40 bg-rose-500/10 text-rose-300"
                            : "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                      }`}
                    >
                      {file.status === "failed"
                        ? "UNAVAILABLE"
                        : file.findingsCount > 0
                          ? `FLAGGED · ${file.findingsCount}`
                          : "CLEAN"}
                    </span>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}
    </section>
  );
}
