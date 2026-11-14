"use client";

import { ShieldCheck, ShieldAlert, Check, Ban } from "lucide-react";
import type { UrlAnalysisReport } from "@/lib/scanners/url-analyzer";

export function SafeLinkResult({ report }: { report: UrlAnalysisReport }) {
  return (
    <section role="status" aria-label="SafeLink interception telemetry" className="overflow-hidden rounded-2xl border border-cyan-300/20 bg-[#0c111c] p-5">
      <div className="flex items-start gap-3">
        {report.isSsrfBlocked ? <ShieldCheck className="h-8 w-8 shrink-0 text-emerald-300" /> : <ShieldAlert className="h-8 w-8 shrink-0 text-amber-300" />}
        <div><span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-cyan-300">SafeLink interception</span><h3 className="mt-1 text-lg font-semibold tracking-tight text-white">{report.isSsrfBlocked ? "Metadata exploit blocked. Credentials protected." : "URL inspection complete"}</h3><p className="mt-2 text-xs leading-5 text-slate-400">{report.isSsrfBlocked ? "SafeLink denied the internal destination before any outbound request was sent." : "Review the inspection results before opening this destination."}</p></div>
      </div>
      <div className="mt-4 break-all rounded-xl border border-white/[0.08] bg-black/20 p-3 font-mono text-[11px] text-slate-300">{report.targetUrl}</div>
      {report.isSsrfBlocked && <ol className="mt-4 grid gap-3 text-xs sm:grid-cols-3">{["Destination checked", "Reserved IP intercepted", "Outbound request denied"].map((label, index) => <li key={label} className="flex items-center gap-2 text-emerald-200">{index === 2 ? <Ban className="h-4 w-4" /> : <Check className="h-4 w-4" />}{label}</li>)}</ol>}
      <ul className="mt-4 space-y-1 border-t border-white/[0.08] pt-3 text-[10px] leading-5 text-slate-500">{report.reasons.map((reason) => <li key={reason} className="break-words">{reason}</li>)}</ul>
      <p className="mt-2 text-[10px] text-slate-500">{report.isSsrfBlocked ? "0 outbound requests · 0 redirects followed · enforced by the SafeLink API" : `${report.redirectChain.length} observed redirect hops`}</p>
    </section>
  );
}
