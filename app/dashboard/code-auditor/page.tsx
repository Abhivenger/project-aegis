"use client";

import React, { useState } from 'react';
import { CodeDiffViewer, FindingItem, RemediationData } from '@/components/code-diff-viewer';
import { RiskGauge } from '@/components/risk-gauge';
import { useDashboardQuota, FREE_TIER_SCAN_LIMIT } from '@/lib/quota-context';
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
  const quota = useDashboardQuota();

  const handleAudit = async () => {
    if (!content.trim()) return;

    // Free-tier hard limit: block the request entirely before any network I/O.
    // Enterprise bypasses all limits (quotaExhausted is always false there).
    if (quota?.quotaExhausted) {
      setError(
        `Daily Quota Exhausted: ${FREE_TIER_SCAN_LIMIT}/${FREE_TIER_SCAN_LIMIT} scans used. Upgrade to Enterprise to continue.`
      );
      window.dispatchEvent(new Event('aegis:scan-blocked'));
      return;
    }

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

      // Notify dashboard quota tracker that a scan completed.
      window.dispatchEvent(new Event('aegis:scan'));

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
