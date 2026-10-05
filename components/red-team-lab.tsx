"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import {
  Flame,
  Play,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Ban,
  ChevronRight,
  Lock,
  RotateCcw,
} from "lucide-react";
import { classifyIpAddress, describeIpScope, type IpScope } from "@/lib/scanners/ip-ranges";

// ============================================================================
// PROJECT AEGIS: RED TEAM EXPLOIT LAB
// Live, interactive SSRF simulation. Each scenario's interception decision is
// computed by the SAME pure CIDR classifier the server scanner uses, so the
// terminal never fakes a verdict — it reports the real filter outcome.
// ============================================================================

type ExploitId = "imdsv2" | "rebinding" | "rfc1918";
type LineTone = "cmd" | "info" | "ok" | "warn" | "danger";
type ExploitSeverity = "CRITICAL" | "HIGH";

interface ResolutionProbe {
  /** Human label for the probe, e.g. "Primary A record". */
  label: string;
  host: string;
  ip: string;
}

interface ExploitScenario {
  id: ExploitId;
  code: string;
  name: string;
  vector: string;
  severity: ExploitSeverity;
  targetUrl: string;
  objective: string;
  exfiltration: string;
  probes: ResolutionProbe[];
}

interface TerminalLine {
  id: string;
  tone: LineTone;
  text: string;
  delayMs: number;
}

interface ExploitRun {
  scenario: ExploitScenario;
  lines: TerminalLine[];
  blocked: boolean;
  latencyMs: number;
  bytesLeaked: number;
  offendingIp: string | null;
  offendingScope: IpScope | null;
}

const SCENARIOS: readonly ExploitScenario[] = [
  {
    id: "imdsv2",
    code: "AEGIS-XPL-001",
    name: "AWS IMDSv2 Metadata Exfiltration",
    vector: "SSRF · Cloud Metadata (169.254.0.0/16)",
    severity: "CRITICAL",
    targetUrl: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    objective: "Steal the attached IAM role's temporary STS credentials from the instance metadata service.",
    exfiltration: "IAM role credentials / STS session tokens",
    probes: [
      {
        label: "Metadata service A record",
        host: "169.254.169.254",
        ip: "169.254.169.254",
      },
    ],
  },
  {
    id: "rebinding",
    code: "AEGIS-XPL-002",
    name: "Dual-Resolve DNS Rebinding",
    vector: "SSRF · TOCTOU DNS Rebinding",
    severity: "CRITICAL",
    targetUrl: "http://rebind.attacker.tld/admin/internal",
    objective:
      "Pass the first public-IP validation, then flip the A record to loopback before the socket connects.",
    exfiltration: "Internal admin console on 127.0.0.1",
    probes: [
      {
        label: "First resolution (validation pass)",
        host: "rebind.attacker.tld",
        ip: "203.0.113.42",
      },
      {
        label: "Second resolution (post-validation flip)",
        host: "rebind.attacker.tld",
        ip: "127.0.0.1",
      },
    ],
  },
  {
    id: "rfc1918",
    code: "AEGIS-XPL-003",
    name: "Private RFC-1918 CIDR Lateral Pivot",
    vector: "SSRF · RFC 1918 (10.0.0.0/8)",
    severity: "HIGH",
    targetUrl: "http://10.0.0.1:8080/admin/secrets",
    objective: "Pivot from the public edge into an internal service and dump its secret store.",
    exfiltration: "Internal secret store on port 8080",
    probes: [
      {
        label: "Internal service A record",
        host: "10.0.0.1",
        ip: "10.0.0.1",
      },
    ],
  },
];

function now(): number {
  return typeof performance !== "undefined" && typeof performance.now === "function"
    ? performance.now()
    : Date.now();
}

/**
 * Runs the exploit against the real SafeLink CIDR classifier. Returns the full
 * diagnostic transcript plus the measured filter latency. All network I/O is
 * simulated (no packets leave the browser) — this is a safe, controlled lab.
 */
function simulateExploit(scenario: ExploitScenario): ExploitRun {
  const lines: TerminalLine[] = [];
  let sequence = 0;
  const push = (tone: LineTone, text: string, delayMs: number): void => {
    sequence += 1;
    lines.push({ id: `${scenario.id}-${sequence}`, tone, text, delayMs });
  };

  // Phase 1 — DNS query resolution.
  push("cmd", `aegis-exec --simulate --target ${scenario.targetUrl}`, 120);
  push("info", "[resolver] initializing isolated ephemeral resolver sandbox", 260);
  for (const probe of scenario.probes) {
    push("info", `[resolver] query A ${probe.host}  (${probe.label})`, 300);
    push("warn", `[resolver] ${probe.host} -> ${probe.ip}  captured socket endpoint`, 280);
  }

  // Phase 2 — CIDR validation & filter evaluation (timed; real computation).
  const startedAt = now();
  let offendingIp: string | null = null;
  let offendingScope: IpScope | null = null;

  push("info", "[safelink] evaluating destination against protected CIDR ranges", 320);
  for (const probe of scenario.probes) {
    const classification = classifyIpAddress(probe.ip);
    const label = classification.isPrivate
      ? `${classification.scope} — FLAGGED`
      : `${classification.scope} — permitted`;
    push(
      classification.isPrivate ? "danger" : "ok",
      `[safelink] classify ${probe.ip} => ${label}`,
      240
    );
    if (classification.isPrivate && offendingIp === null) {
      offendingIp = probe.ip;
      offendingScope = classification.scope;
    }
  }
  const latencyMs = now() - startedAt;

  // Phase 3 — interception decision & fail-closed abort.
  const blocked = offendingIp !== null;
  push(
    "info",
    `[filter] evaluation latency ${latencyMs.toFixed(3)} ms · rule verdict ${
      blocked ? "DENY" : "ALLOW"
    }`,
    220
  );

  if (blocked && offendingScope) {
    push(
      "danger",
      `[intercept] ${offendingIp} violates ${offendingScope} (${describeIpScope(offendingScope)})`,
      200
    );
    push("danger", "[intercept] fail-closed socket teardown — connection reset before body read", 180);
    push("ok", "[result] bytes leaked: 0 B · egress blocked · incident event emitted", 220);
  } else {
    push("warn", "[intercept] destination permitted — no protected range matched", 200);
    push("danger", "[result] SIMULATION ONLY — a real deployment would transmit the request", 220);
  }

  return {
    scenario,
    lines,
    blocked,
    latencyMs,
    bytesLeaked: 0,
    offendingIp,
    offendingScope,
  };
}

function getLineToneClass(tone: LineTone): string {
  switch (tone) {
    case "cmd":
      return "text-slate-200";
    case "ok":
      return "text-emerald-300";
    case "warn":
      return "text-amber-300";
    case "danger":
      return "text-rose-400";
    default:
      return "text-slate-400";
  }
}

function getSeverityBadge(severity: ExploitSeverity): string {
  return severity === "CRITICAL"
    ? "bg-rose-500/15 text-rose-300 border-rose-500/40"
    : "bg-amber-500/15 text-amber-300 border-amber-500/40";
}

export function RedTeamLab() {
  const [open, setOpen] = useState(false);
  const [selectedId, setSelectedId] = useState<ExploitId>(SCENARIOS[0].id);
  const [run, setRun] = useState<ExploitRun | null>(null);
  const [visibleLines, setVisibleLines] = useState(0);
  const [running, setRunning] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  const selectedScenario = useMemo(
    () => SCENARIOS.find((scenario) => scenario.id === selectedId) ?? SCENARIOS[0],
    [selectedId]
  );

  const launch = useCallback(() => {
    setRun(simulateExploit(selectedScenario));
    setVisibleLines(0);
    setRunning(true);
  }, [selectedScenario]);

  // Reveal the transcript line-by-line. A single effect owns every timer and
  // clears them all on unmount / re-run, so runs cannot leak or interleave.
  useEffect(() => {
    if (!run) {
      return;
    }
    const timers: Array<ReturnType<typeof setTimeout>> = [];
    let elapsed = 0;
    run.lines.forEach((line, index) => {
      elapsed += line.delayMs;
      timers.push(setTimeout(() => setVisibleLines(index + 1), elapsed));
    });
    timers.push(
      setTimeout(() => setRunning(false), elapsed + 250)
    );
    return () => {
      timers.forEach(clearTimeout);
    };
  }, [run]);

  // Auto-scroll the terminal as new lines stream in.
  useEffect(() => {
    const node = scrollRef.current;
    if (node) {
      node.scrollTop = node.scrollHeight;
    }
  }, [visibleLines]);

  const selectScenario = (id: ExploitId) => {
    setSelectedId(id);
    setRun(null);
    setVisibleLines(0);
    setRunning(false);
  };

  const visibleRunLines = run ? run.lines.slice(0, visibleLines) : [];
  const revealedAll = run !== null && visibleLines >= run.lines.length;

  return (
    <section
      data-tour="red-team-lab"
      className="rounded-2xl border border-slate-800 bg-[#060b18] shadow-xl overflow-hidden"
    >
      {/* Header / toggle */}
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="w-full flex items-center justify-between gap-3 px-5 py-4 text-left hover:bg-slate-900/40 transition"
      >
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-9 h-9 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center flex-shrink-0">
            <Flame className="w-4 h-4 text-rose-400" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-white">Red Team Exploit Lab</h2>
              <span className="text-[9px] font-mono uppercase tracking-widest text-rose-300 bg-rose-500/10 border border-rose-500/30 px-1.5 py-0.5 rounded">
                Sandboxed
              </span>
            </div>
            <p className="text-[11px] text-slate-400 truncate">
              Live SSRF attack simulations with real CIDR filter evaluation and fail-closed abort tracing.
            </p>
          </div>
        </div>
        <motion.span
          animate={{ rotate: open ? 90 : 0 }}
          transition={{ duration: 0.2 }}
          className="text-slate-400 flex-shrink-0"
        >
          <ChevronRight className="w-5 h-5" />
        </motion.span>
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            key="lab"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.28, ease: "easeInOut" }}
            className="overflow-hidden"
          >
            <div className="border-t border-slate-800 p-4 sm:p-5 space-y-4">
              {/* Scenario selector */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
                {SCENARIOS.map((scenario) => {
                  const active = scenario.id === selectedId;
                  return (
                    <button
                      key={scenario.id}
                      type="button"
                      onClick={() => selectScenario(scenario.id)}
                      className={`text-left rounded-xl border p-3.5 transition ${
                        active
                          ? "border-cyan-500/40 bg-cyan-500/10"
                          : "border-slate-800 bg-slate-900/50 hover:bg-slate-900"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2 mb-1.5">
                        <span className="text-[10px] font-mono text-slate-400">{scenario.code}</span>
                        <span
                          className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border ${getSeverityBadge(
                            scenario.severity
                          )}`}
                        >
                          {scenario.severity}
                        </span>
                      </div>
                      <div className="text-xs font-bold text-white leading-snug">{scenario.name}</div>
                      <div className="text-[10px] text-slate-400 font-mono mt-1">{scenario.vector}</div>
                    </button>
                  );
                })}
              </div>

              {/* Scenario detail */}
              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4 space-y-2">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px]">
                  <span className="text-slate-400">
                    Target: <code className="text-cyan-300 font-mono">{selectedScenario.targetUrl}</code>
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
                  <div>
                    <span className="text-slate-500 uppercase tracking-wider font-semibold">Objective</span>
                    <p className="text-slate-300 mt-0.5 leading-relaxed">{selectedScenario.objective}</p>
                  </div>
                  <div>
                    <span className="text-slate-500 uppercase tracking-wider font-semibold">
                      Exfiltration Target
                    </span>
                    <p className="text-slate-300 mt-0.5 leading-relaxed">
                      {selectedScenario.exfiltration}
                    </p>
                  </div>
                </div>
              </div>

              {/* Controls */}
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-widest text-slate-500">
                  <Lock className="w-3.5 h-3.5 text-emerald-400" />
                  Containment: no real network egress
                </div>
                <div className="flex items-center gap-2">
                  {run && (
                    <button
                      type="button"
                      onClick={() => {
                        setRun(null);
                        setVisibleLines(0);
                        setRunning(false);
                      }}
                      className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-700 text-slate-300 text-xs font-semibold hover:bg-slate-800 transition"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      Clear
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={launch}
                    disabled={running}
                    className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-rose-500 to-orange-500 hover:from-rose-400 hover:to-orange-400 text-slate-950 font-bold text-xs transition shadow-lg shadow-rose-500/20 disabled:opacity-60"
                  >
                    {running ? (
                      <>
                        <Terminal className="w-4 h-4 animate-pulse" />
                        <span>Simulating...</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 fill-slate-950" />
                        <span>Launch Exploit Simulation</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Terminal */}
              <div className="rounded-xl border border-slate-800 bg-[#030712] overflow-hidden">
                <div className="flex items-center justify-between px-3 py-2 border-b border-slate-800 bg-[#060b14]">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-rose-500/70" />
                    <span className="w-2.5 h-2.5 rounded-full bg-amber-500/70" />
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/70" />
                    <span className="ml-2 text-[10px] font-mono text-slate-500">
                      aegis-redteam://{selectedScenario.id}
                    </span>
                  </div>
                  {run && (
                    <span className="text-[10px] font-mono text-slate-500">
                      {running ? "STREAMING" : "COMPLETE"}
                    </span>
                  )}
                </div>

                <div ref={scrollRef} className="h-64 overflow-y-auto p-3 font-mono text-[11px] leading-relaxed">
                  <AnimatePresence mode="wait">
                    {!run ? (
                      <motion.p
                        key="idle"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="text-slate-500"
                      >
                        Awaiting launch.{" "}
                        <span className="text-cyan-400">$</span> Select a scenario and run the
                        simulation to stream the live socket diagnostic.
                      </motion.p>
                    ) : (
                      <motion.div key={run.scenario.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                        {visibleRunLines.map((line) => (
                          <motion.div
                            key={line.id}
                            initial={{ opacity: 0, x: -6 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ duration: 0.18 }}
                            className={`whitespace-pre-wrap break-words ${getLineToneClass(line.tone)}`}
                          >
                            <span className="text-slate-600 select-none">›</span> {line.text}
                          </motion.div>
                        ))}
                        {running && (
                          <motion.span
                            animate={{ opacity: [1, 0.2, 1] }}
                            transition={{ duration: 1, repeat: Infinity }}
                            className="inline-block w-2 h-3.5 bg-cyan-400 align-middle ml-1"
                          />
                        )}
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              </div>

              {/* Outcome metrics */}
              <AnimatePresence>
                {run && revealedAll && (
                  <motion.div
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.25 }}
                    className="grid grid-cols-2 sm:grid-cols-4 gap-3"
                  >
                    <OutcomeTile
                      label="Interception"
                      value={run.blocked ? "BLOCKED" : "PERMITTED"}
                      tone={run.blocked ? "danger" : "warn"}
                      icon={run.blocked ? Ban : ShieldAlert}
                    />
                    <OutcomeTile
                      label="Filter Latency"
                      value={`${run.latencyMs.toFixed(3)} ms`}
                      tone="info"
                      icon={Terminal}
                    />
                    <OutcomeTile
                      label="Bytes Leaked"
                      value={`${run.bytesLeaked} B`}
                      tone="ok"
                      icon={ShieldCheck}
                    />
                    <OutcomeTile
                      label="Offending IP"
                      value={run.offendingIp ?? "none"}
                      tone={run.offendingIp ? "danger" : "ok"}
                      icon={ShieldAlert}
                    />
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  );
}

type OutcomeTone = "danger" | "ok" | "warn" | "info";

const OUTCOME_TONE_CLASS: Record<OutcomeTone, string> = {
  danger: "text-rose-400 border-rose-500/30 bg-rose-500/5",
  ok: "text-emerald-400 border-emerald-500/30 bg-emerald-500/5",
  warn: "text-amber-400 border-amber-500/30 bg-amber-500/5",
  info: "text-cyan-400 border-cyan-500/30 bg-cyan-500/5",
};

function OutcomeTile({
  label,
  value,
  tone,
  icon: Icon,
}: {
  label: string;
  value: string;
  tone: OutcomeTone;
  icon: React.ComponentType<{ className?: string }>;
}) {
  return (
    <div className={`rounded-xl border px-3 py-2.5 ${OUTCOME_TONE_CLASS[tone]}`}>
      <div className="flex items-center gap-1.5 text-[9px] uppercase tracking-wider text-slate-400 font-semibold">
        <Icon className="w-3 h-3" />
        {label}
      </div>
      <div className="mt-1 font-mono text-sm font-bold">{value}</div>
    </div>
  );
}
