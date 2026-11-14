"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import { CodeDiffViewer, FindingItem, RemediationData } from "@/components/code-diff-viewer";
import { SecurityPresets } from "@/components/security-presets";
import { SafeLinkResult } from "@/components/safelink-result";
import { SECURITY_PRESETS, STRIPE_PRESET, type SecurityPreset } from "@/lib/demo-presets";
import { analyzeCode } from "@/lib/scanners/code-analysis";
import type { UrlAnalysisReport } from "@/lib/scanners/url-analyzer";
import { ThreatReportModal } from "@/components/threat-report-modal";
import { GithubAuditor } from "@/components/dashboard/github-auditor";
import { useDashboardQuota, FREE_TIER_SCAN_LIMIT } from "@/lib/quota-context";
import {
  consumePendingPreset,
  PRESET_EVENT,
  type PresetEventDetail,
  type PresetId,
} from "@/lib/preset-bus";
import { buildCodeThreatReport } from "@/lib/report/threat-report";
import type { LocalAiAnalysis } from "@/lib/ai/fallback";
import { Code2, Play, FileText, AlertCircle, Sparkles } from "lucide-react";

const CODE_PRESET_IDS: ReadonlySet<PresetId> = new Set(
  SECURITY_PRESETS.map((preset) => preset.id)
);

type AiResult =
  | { provider: "offline"; analysis: LocalAiAnalysis }
  | { provider: "upstream"; analysis: string };

function extractUpstreamText(payload: string): string {
  const chunks: string[] = [];
  for (const line of payload.split(/\r?\n/)) {
    if (!line.startsWith("data:") || line.slice(5).trim() === "[DONE]") {
      continue;
    }
    const data = line.slice(5).trim();
    try {
      const parsed: unknown = JSON.parse(data);
      if (typeof parsed !== "object" || parsed === null) continue;
      const choices = (parsed as { choices?: unknown }).choices;
      if (!Array.isArray(choices) || choices.length === 0) continue;
      const choice = choices[0];
      if (typeof choice !== "object" || choice === null) continue;
      const delta = (choice as { delta?: unknown }).delta;
      if (typeof delta !== "object" || delta === null) continue;
      const content = (delta as { content?: unknown }).content;
      if (typeof content === "string") chunks.push(content);
    } catch {
      // A non-JSON provider stream is displayed as-is below.
    }
  }
  return chunks.join("") || payload;
}

export default function CodeAuditorPage() {
  const [content, setContent] = useState(STRIPE_PRESET.content);
  const [filename, setFilename] = useState(STRIPE_PRESET.filename);
  const [selectedPreset, setSelectedPreset] = useState<string | null>("stripe");
  const [urlReport, setUrlReport] = useState<UrlAnalysisReport | null>(null);
  const scanVersion = useRef(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [riskScore, setRiskScore] = useState<number | null>(null);
  const [verdict, setVerdict] = useState<"SAFE" | "SUSPICIOUS" | "DANGEROUS" | null>(null);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [remediation, setRemediation] = useState<RemediationData | null>(null);
  const [auditedContent, setAuditedContent] = useState("");
  const [reportOpen, setReportOpen] = useState(false);
  const [aiResult, setAiResult] = useState<AiResult | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const quota = useDashboardQuota();

  const handleAudit = async (overrideContent?: string, overrideFilename?: string, demo = false) => {
    const contentToScan = (overrideContent ?? content).trim();
    const filenameToScan = overrideFilename ?? filename;
    if (!contentToScan) return;
    const version = ++scanVersion.current;
    const urlMode = /^https?:\/\//i.test(contentToScan);
    setVerdict(null);
    setUrlReport(null);
    setAiResult(null);
    setAiError(null);
    setError(null);

    if (demo && !urlMode) {
      const result = analyzeCode(contentToScan, filenameToScan);
      setRiskScore(result.riskScore);
      setVerdict(result.verdict);
      setFindings(result.findings);
      setRemediation(result.remediation);
      setAuditedContent(contentToScan);
      setLoading(false);
      return;
    }

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

    try {
      const res = await fetch(urlMode ? "/api/scan/url" : "/api/scan/secret", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(urlMode ? { url: contentToScan } : { filename: filenameToScan, content: contentToScan }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to scan code.");
      }

      // Notify dashboard quota tracker that a scan completed.
      window.dispatchEvent(new Event("aegis:scan"));
      if (scanVersion.current !== version) return;
      if (urlMode) {
        setUrlReport(data.report);
        return;
      }

      setRiskScore(data.riskScore);
      setVerdict(data.verdict);
      setFindings(data.findings || []);
      setRemediation(data.remediation);
      setAuditedContent(contentToScan);
    } catch (err) {
      if (scanVersion.current === version) setError((err as Error).message);
    } finally {
      if (scanVersion.current === version) setLoading(false);
    }
  };

  const selectPreset = (preset: SecurityPreset) => {
    setContent(preset.content);
    setFilename(preset.filename);
    setSelectedPreset(preset.id);
    void handleAudit(preset.content, preset.filename, true);
  };

  const handleAiAnalyze = async () => {
    const contentToAnalyze = content.trim();
    if (!contentToAnalyze) return;

    setAiLoading(true);
    setAiError(null);
    setAiResult(null);

    try {
      const res = await fetch("/api/ai-analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "text/event-stream, application/json",
        },
        body: JSON.stringify({
          content: contentToAnalyze,
          context: `Filename: ${filename}`,
        }),
      });

      if (!res.ok) {
        const data = (await res.json().catch(() => null)) as { error?: string } | null;
        throw new Error(data?.error ?? "AI analysis failed.");
      }

      const mode = res.headers.get("x-aegis-analysis-mode");
      if (mode === "offline" || res.headers.get("content-type")?.includes("application/json")) {
        const data = (await res.json()) as { analysis?: unknown };
        if (typeof data.analysis !== "object" || data.analysis === null) {
          throw new Error("Offline analysis returned an invalid result.");
        }
        setAiResult({ provider: "offline", analysis: data.analysis as LocalAiAnalysis });
        return;
      }

      const payload = await res.text();
      setAiResult({ provider: "upstream", analysis: extractUpstreamText(payload) });
    } catch (err) {
      setAiError(err instanceof Error ? err.message : "AI analysis failed.");
    } finally {
      setAiLoading(false);
    }
  };

  // Stable reference to the latest audit handler for the preset bus.
  const scanRef = useRef(handleAudit);
  scanRef.current = handleAudit;

  // Apply a pending preset from the command palette (cross-route handoff) and
  // listen for same-route preset events.
  useEffect(() => {
    const applyPreset = (preset: SecurityPreset) => {
      setContent(preset.content);
      setFilename(preset.filename);
      setSelectedPreset(preset.id);
      void scanRef.current(preset.content, preset.filename, true);
    };

    const findPreset = (id: PresetId): SecurityPreset | undefined =>
      SECURITY_PRESETS.find((preset) => preset.id === id);

    const pending = consumePendingPreset();
    if (pending && CODE_PRESET_IDS.has(pending)) {
      const preset = findPreset(pending);
      if (preset) applyPreset(preset);
    }

    const onPreset = (event: Event) => {
      const detail = (event as CustomEvent<PresetEventDetail>).detail;
      if (detail && CODE_PRESET_IDS.has(detail.preset)) {
        const preset = findPreset(detail.preset);
        if (preset) applyPreset(preset);
      }
    };
    window.addEventListener(PRESET_EVENT, onPreset);
    return () => window.removeEventListener(PRESET_EVENT, onPreset);
  }, []);

  const threatReport = useMemo(
    () =>
      verdict
        ? buildCodeThreatReport({
            filename,
            riskScore: riskScore ?? 0,
            verdict,
            findings,
            remediation: remediation ?? undefined,
            originalContent: auditedContent,
          })
        : null,
    [verdict, riskScore, findings, remediation, filename, auditedContent]
  );

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

        </div>

        <SecurityPresets onSelect={selectPreset} selected={selectedPreset} />

        {/* Textarea Code Input */}
        <div className="relative" data-tour="code-editor">
          <textarea
            value={content}
            aria-label="Code or URL to audit"
            onChange={(e) => {
              ++scanVersion.current;
              setContent(e.target.value);
              setSelectedPreset(null);
              setVerdict(null);
              setUrlReport(null);
              setLoading(false);
              setError(null);
              setAiResult(null);
            }}
            rows={11}
            placeholder="Paste code snippet or staged Git diff here..."
            className="w-full bg-[#030712] border border-slate-800/80 rounded-xl p-3 font-mono text-xs text-slate-200 focus:outline-none focus:border-emerald-500/50 leading-relaxed resize-y"
          />
        </div>

        {/* Submit Audit Button */}
        <div className="flex justify-end pt-1">
          <button
            onClick={() => handleAudit()}
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

      {loading && <p role="status" className="text-xs text-cyan-200">Scanning for threats...</p>}
      {urlReport && <SafeLinkResult report={urlReport} />}
      {verdict && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div role="status" className="text-[11px] text-emerald-300">Audit complete · {findings.length} finding{findings.length === 1 ? "" : "s"}</div>
            <button onClick={() => setReportOpen(true)} data-tour="export-audit" className="flex items-center gap-2 rounded-xl border border-indigo-500/40 bg-indigo-500/10 px-4 py-2 text-xs font-bold text-indigo-200 transition-colors hover:bg-indigo-500/20"><FileText className="h-3.5 w-3.5" /> Export Security Audit Report</button>
          </div>
          <CodeDiffViewer findings={findings} remediation={remediation || undefined} originalContent={auditedContent} filename={filename} />
        </div>
      )}

      <div className="rounded-2xl border border-cyan-500/20 bg-cyan-950/10 p-4 shadow-xl">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2 text-sm font-bold text-white">
              <Sparkles className="h-4 w-4 text-cyan-300" />
              AI Security Review
            </div>
            <p className="mt-1 text-[11px] text-slate-400">
              Server-side provider analysis with an instant offline entropy and signature fallback.
            </p>
          </div>
          <button
            type="button"
            onClick={handleAiAnalyze}
            disabled={aiLoading || !content.trim()}
            className="flex items-center justify-center gap-2 rounded-xl border border-cyan-400/40 bg-cyan-500/10 px-4 py-2 text-xs font-bold text-cyan-200 transition hover:bg-cyan-500/20 disabled:opacity-50"
          >
            <Sparkles className={`h-3.5 w-3.5 ${aiLoading ? "animate-pulse" : ""}`} />
            {aiLoading ? "Reviewing..." : "Run AI Review"}
          </button>
        </div>
        {aiError && <p className="mt-3 text-xs text-rose-300">{aiError}</p>}
        {aiResult && (
          <div className="mt-4 rounded-xl border border-slate-800 bg-[#030712] p-3">
            <div className="mb-2 flex items-center justify-between gap-2">
              <span className="text-[10px] font-mono uppercase tracking-widest text-slate-500">
                {aiResult.provider === "offline" ? "LOCAL FALLBACK" : "UPSTREAM STREAM"}
              </span>
              {aiResult.provider === "offline" && (
                <span className="text-[10px] font-mono text-emerald-300">NETWORK INDEPENDENT</span>
              )}
            </div>
            {aiResult.provider === "offline" ? (
              <div className="space-y-2 text-xs">
                <p className="text-slate-200">{aiResult.analysis.summary}</p>
                <p className="font-mono text-cyan-300">
                  {aiResult.analysis.verdict} · risk {aiResult.analysis.riskScore}/100 · peak entropy {aiResult.analysis.entropy.highestEntropy.toFixed(2)}
                </p>
                <ul className="list-disc space-y-1 pl-4 text-slate-400">
                  {aiResult.analysis.recommendations.map((recommendation) => (
                    <li key={recommendation}>{recommendation}</li>
                  ))}
                </ul>
              </div>
            ) : (
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap text-xs leading-relaxed text-slate-300">
                {aiResult.analysis}
              </pre>
            )}
          </div>
        )}
      </div>

      <div className="border-t border-slate-800/80 pt-6">
        <GithubAuditor embedded />
      </div>

      {/* Threat report export modal */}
      <ThreatReportModal
        isOpen={reportOpen}
        onClose={() => setReportOpen(false)}
        report={threatReport}
      />
    </div>
  );
}
