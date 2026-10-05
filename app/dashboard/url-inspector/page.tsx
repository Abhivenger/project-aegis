"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { motion } from "motion/react";
import { RiskGauge } from "@/components/risk-gauge";
import { RedTeamLab } from "@/components/red-team-lab";
import { ThreatReportModal } from "@/components/threat-report-modal";
import { useDashboardQuota, FREE_TIER_SCAN_LIMIT } from "@/lib/quota-context";
import {
  consumePendingPreset,
  PRESET_EVENT,
  type PresetEventDetail,
  type PresetId,
} from "@/lib/preset-bus";
import { buildUrlThreatReport } from "@/lib/report/threat-report";
import type { UrlAnalysisReport } from "@/lib/scanners/url-analyzer";
import {
  Globe,
  Search,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  FileText,
} from "lucide-react";

interface UrlPreset {
  id: PresetId;
  label: string;
  url: string;
}

const PRESETS: readonly UrlPreset[] = [
  { id: "github", label: "Safe Domain", url: "https://github.com" },
  { id: "phishing", label: "Phishing Pattern", url: "http://secure-login-hdfc-otp.login-auth.xyz/verify" },
  { id: "metadata", label: "Cloud Metadata SSRF", url: "http://169.254.169.254/latest/meta-data/" },
  { id: "localhost", label: "Localhost SSRF", url: "http://127.0.0.1:5432" },
];

const URL_PRESET_IDS: ReadonlySet<PresetId> = new Set(
  PRESETS.map((preset) => preset.id)
);

export default function UrlInspectorPage() {
  const [urlInput, setUrlInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<UrlAnalysisReport | null>(null);
  const [reportOpen, setReportOpen] = useState(false);
  const quota = useDashboardQuota();

  const handleScan = async (target?: string) => {
    const scanTarget = (target ?? urlInput).trim();
    if (!scanTarget) return;

    // Free-tier hard limit: block the request entirely before any network I/O.
    // Enterprise bypasses all limits (quotaExhausted is always false there).
    if (quota?.quotaExhausted) {
      setError(
        `Daily Quota Exhausted: ${FREE_TIER_SCAN_LIMIT}/${FREE_TIER_SCAN_LIMIT} scans used. Upgrade to Enterprise to continue.`
      );
      window.dispatchEvent(new Event("aegis:scan-blocked"));
      return;
    }

    setLoading(true);
    setError(null);
    setReport(null);

    try {
      const res = await fetch("/api/scan/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: scanTarget }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to inspect link.");
      }
      // Notify dashboard quota tracker that a scan completed.
      window.dispatchEvent(new Event("aegis:scan"));
      setReport(data.report);
      setUrlInput(scanTarget);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  // Keep a stable reference to the latest scan handler for the preset bus.
  const scanRef = useRef(handleScan);
  scanRef.current = handleScan;

  const runPresetById = useCallback((presetId: PresetId) => {
    const preset = PRESETS.find((candidate) => candidate.id === presetId);
    if (preset) {
      void scanRef.current(preset.url);
    }
  }, []);

  // Apply a pending preset from the command palette (cross-route handoff) and
  // listen for same-route preset events.
  useEffect(() => {
    const pending = consumePendingPreset();
    if (pending && URL_PRESET_IDS.has(pending)) {
      runPresetById(pending);
    }
    const onPreset = (event: Event) => {
      const detail = (event as CustomEvent<PresetEventDetail>).detail;
      if (detail && URL_PRESET_IDS.has(detail.preset)) {
        runPresetById(detail.preset);
      }
    };
    window.addEventListener(PRESET_EVENT, onPreset);
    return () => window.removeEventListener(PRESET_EVENT, onPreset);
  }, [runPresetById]);

  const threatReport = useMemo(
    () => (report ? buildUrlThreatReport(report) : null),
    [report]
  );

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
      <div
        data-tour="url-input"
        className="bg-[#060b18] border border-slate-800 p-2 sm:p-2.5 rounded-2xl shadow-xl flex flex-col sm:flex-row items-center gap-2"
      >
        <div className="relative flex-1 w-full overflow-hidden rounded-xl">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleScan()}
            placeholder="Paste any link to inspect (e.g. https://bank-login.xyz or http://169.254.169.254)..."
            className="w-full pl-9 pr-4 py-2.5 bg-slate-900/60 rounded-xl text-xs sm:text-sm text-white placeholder-slate-500 border border-slate-800/80 focus:outline-none focus:border-cyan-500/50 font-mono"
          />

          {/* Laser radar sweep: vertical light bar gliding across the input while scanning */}
          {loading && (
            <>
              <motion.div
                aria-hidden
                className="pointer-events-none absolute inset-y-0 w-24"
                style={{
                  background:
                    "linear-gradient(90deg, transparent, rgba(34,211,238,0.55) 35%, rgba(52,211,153,0.75) 50%, rgba(34,211,238,0.55) 65%, transparent)",
                  filter: "blur(1px)",
                }}
                initial={{ x: "-30%" }}
                animate={{ x: ["-30%", "420%"] }}
                transition={{
                  duration: 1.15,
                  repeat: Infinity,
                  ease: "easeInOut",
                  repeatType: "loop",
                }}
              />
              {/* Faint trailing glow band behind the beam */}
              <motion.div
                aria-hidden
                className="pointer-events-none absolute inset-y-0 left-0 right-0"
                style={{
                  background:
                    "linear-gradient(90deg, transparent 55%, rgba(34,211,238,0.08) 75%, transparent)",
                }}
                initial={{ opacity: 0 }}
                animate={{ opacity: [0, 1, 0] }}
                transition={{ duration: 1.15, repeat: Infinity, ease: "easeInOut" }}
              />
              {/* Track border ignition */}
              <div
                aria-hidden
                className="pointer-events-none absolute inset-0 rounded-xl border border-cyan-400/40 shadow-[0_0_18px_rgba(34,211,238,0.35)]"
              />
            </>
          )}
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
        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
          Quick Presets:
        </span>
        {PRESETS.map((preset) => (
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
        <div className="space-y-4">
          {/* Result actions */}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-[11px] font-mono text-emerald-400">
              <ShieldCheck className="w-4 h-4" />
              Inspection complete · {report.redirectChain.length} hop
              {report.redirectChain.length === 1 ? "" : "s"} traced
            </div>
            <button
              onClick={() => setReportOpen(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-xl border border-indigo-500/40 bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-200 text-xs font-bold transition"
            >
              <FileText className="w-3.5 h-3.5" />
              Export Security Audit Report
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-start">
            {/* Left Column: Risk Gauge */}
            <div className="md:col-span-4 bg-[#060b18] border border-slate-800 rounded-2xl p-6 flex flex-col items-center justify-center shadow-xl">
              <RiskGauge score={report.riskScore} verdict={report.verdict} size={200} />

              <div className="w-full mt-6 space-y-2 border-t border-slate-800 pt-4 text-xs">
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">SSRF Enforcement:</span>
                  <span
                    className={`font-mono font-bold ${
                      report.isSsrfBlocked ? "text-rose-400" : "text-emerald-400"
                    }`}
                  >
                    {report.isSsrfBlocked ? "BLOCKED" : "CLEARED"}
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
                  Redirect Path Analysis ({report.redirectChain.length} Hop
                  {report.redirectChain.length !== 1 ? "s" : ""})
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
                                ? "bg-amber-500/20 text-amber-300"
                                : hop.statusCode === 200
                                  ? "bg-emerald-500/20 text-amber-300"
                                  : "bg-rose-500/20 text-rose-300"
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
        </div>
      )}

      {/* Red Team Exploit Lab */}
      <RedTeamLab />

      {/* Threat report export modal */}
      <ThreatReportModal
        isOpen={reportOpen}
        onClose={() => setReportOpen(false)}
        report={threatReport}
      />
    </div>
  );
}
