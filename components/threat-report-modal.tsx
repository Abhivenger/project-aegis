"use client";

import React, { useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import {
  X,
  FileText,
  Braces,
  Copy,
  Check,
  Download,
  ShieldAlert,
  Fingerprint,
  Hash,
  CircleAlert,
  CircleCheck,
} from "lucide-react";
import {
  reportToJson,
  reportToMarkdown,
  reportFileStamp,
  type ThreatReport,
} from "@/lib/report/threat-report";

interface ThreatReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  report: ThreatReport | null;
}

function downloadTextFile(filename: string, content: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: "bg-rose-500/15 text-rose-300 border-rose-500/40",
  HIGH: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  MEDIUM: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  LOW: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
};

export function ThreatReportModal({ isOpen, onClose, report }: ThreatReportModalProps) {
  const [copied, setCopied] = useState<"markdown" | "json" | null>(null);

  const markdown = useMemo(() => (report ? reportToMarkdown(report) : ""), [report]);
  const json = useMemo(() => (report ? reportToJson(report) : ""), [report]);

  useEffect(() => {
    if (!isOpen) {
      return;
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [isOpen, onClose]);

  const handleCopy = async (kind: "markdown" | "json") => {
    const payload = kind === "markdown" ? markdown : json;
    if (!payload) {
      return;
    }
    try {
      await navigator.clipboard.writeText(payload);
      setCopied(kind);
      setTimeout(() => setCopied(null), 2000);
    } catch (error) {
      console.error("Failed to copy audit report", error);
    }
  };

  const stamp = report ? reportFileStamp(report) : "pending";

  return (
    <AnimatePresence>
      {isOpen && report && (
        <motion.div
          className="fixed inset-0 z-[70] flex items-center justify-center p-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.2 }}
          role="dialog"
          aria-modal="true"
          aria-label="Security audit report"
        >
          <div
            className="absolute inset-0 bg-black/80 backdrop-blur-sm"
            onClick={onClose}
          />

          <motion.div
            className="relative w-full max-w-3xl max-h-[88vh] flex flex-col rounded-2xl border border-slate-700 bg-[#090f20] shadow-2xl overflow-hidden"
            initial={{ opacity: 0, y: 24, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 16, scale: 0.98 }}
            transition={{ type: "spring", stiffness: 320, damping: 30 }}
          >
            {/* Header */}
            <div className="flex items-start justify-between gap-4 border-b border-slate-800 px-5 py-4">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-sm font-bold text-white">
                    Cryptographic Compliance &amp; Threat Audit
                  </h3>
                  <span
                    className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border ${
                      SEVERITY_CLASS[report.severity] ?? SEVERITY_CLASS.LOW
                    }`}
                  >
                    {report.severity}
                  </span>
                </div>
                <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] font-mono text-slate-400">
                  <span className="flex items-center gap-1.5">
                    <Hash className="w-3 h-3 text-cyan-400" />
                    {report.scanId}
                  </span>
                  <span className="flex items-center gap-1.5 min-w-0">
                    <Fingerprint className="w-3 h-3 text-indigo-400" />
                    <span className="truncate max-w-[280px]">sha256:{report.fingerprint}</span>
                  </span>
                </div>
              </div>
              <button
                onClick={onClose}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition flex-shrink-0"
                aria-label="Close report"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Summary strip */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-px bg-slate-800 border-b border-slate-800">
              <SummaryCell label="Risk Score" value={`${report.riskScore}/100`} accent="text-cyan-300" />
              <SummaryCell label="Verdict" value={report.verdict} accent="text-amber-300" />
              <SummaryCell
                label={report.kind === "code" ? "Findings" : "SSRF"}
                value={
                  report.kind === "code"
                    ? String(report.findings.length)
                    : report.isSsrfBlocked
                      ? "BLOCKED"
                      : "CLEARED"
                }
                accent={report.kind === "url" && report.isSsrfBlocked ? "text-rose-300" : "text-emerald-300"}
              />
              <SummaryCell
                label="Entropy Artifacts"
                value={String(report.entropyArtifacts.length)}
                accent="text-indigo-300"
              />
            </div>

            {/* Markdown preview */}
            <div className="flex-1 min-h-0 overflow-y-auto p-5">
              <div className="flex items-center gap-2 mb-2 text-[10px] uppercase tracking-widest text-slate-500 font-semibold">
                <FileText className="w-3.5 h-3.5" />
                Rendered audit preview
              </div>
              <pre className="whitespace-pre-wrap rounded-xl border border-slate-800 bg-[#030712] p-4 font-mono text-[11px] leading-relaxed text-slate-300 max-h-[38vh] overflow-y-auto">
                {markdown}
              </pre>
            </div>

            {/* Footer actions */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 border-t border-slate-800 px-5 py-4 bg-[#060b14]">
              <div className="flex items-center gap-2 text-[10px] text-slate-500 font-mono">
                <CircleAlert className="w-3.5 h-3.5 text-amber-400" />
                Report generated {new Date(report.generatedAt).toLocaleString()}
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={() => handleCopy("markdown")}
                  className="flex items-center gap-1.5 px-2.5 py-2 rounded-xl border border-slate-700 text-slate-300 text-xs font-semibold hover:bg-slate-800 transition"
                >
                  {copied === "markdown" ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                  Copy MD
                </button>
                <button
                  onClick={() => handleCopy("json")}
                  className="flex items-center gap-1.5 px-2.5 py-2 rounded-xl border border-slate-700 text-slate-300 text-xs font-semibold hover:bg-slate-800 transition"
                >
                  {copied === "json" ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                  Copy JSON
                </button>
                <button
                  onClick={() =>
                    downloadTextFile(
                      `aegis-audit-${stamp}.json`,
                      json,
                      "application/json"
                    )
                  }
                  className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-indigo-500/40 bg-indigo-500/10 text-indigo-200 text-xs font-semibold hover:bg-indigo-500/20 transition"
                >
                  <Braces className="w-3.5 h-3.5" />
                  Export Raw Telemetry as JSON
                </button>
                <button
                  onClick={() =>
                    downloadTextFile(
                      `aegis-audit-${stamp}.md`,
                      markdown,
                      "text/markdown"
                    )
                  }
                  className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 text-xs font-bold transition shadow-lg shadow-cyan-500/20"
                >
                  <Download className="w-3.5 h-3.5" />
                  Export Security Audit as Markdown
                </button>
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function SummaryCell({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent: string;
}) {
  return (
    <div className="bg-[#090f20] px-4 py-3">
      <div className="text-[9px] uppercase tracking-widest text-slate-500 font-semibold">{label}</div>
      <div className={`mt-1 font-mono text-sm font-bold ${accent}`}>{value}</div>
    </div>
  );
}

/** Small inline indicator used by pages to advertise the export capability. */
export function ReportReadyBadge({ label }: { label: string }) {
  return (
    <span className="flex items-center gap-1.5 text-[10px] font-mono text-emerald-400">
      <CircleCheck className="w-3.5 h-3.5" />
      {label}
    </span>
  );
}
