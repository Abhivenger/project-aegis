"use client";

import React, { useState } from 'react';
import { motion } from 'motion/react';
import { Copy, Check, ShieldAlert, FileText, Code2, AlertTriangle, Key } from 'lucide-react';

export interface FindingItem {
  type: 'KNOWN_SIGNATURE' | 'HIGH_ENTROPY';
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  lineNumber: number;
  redactedToken: string;
  entropy?: number;
  suggestedEnvKey: string;
}

export interface RemediationData {
  hasSecrets: boolean;
  envFileSnippet: string;
  sanitizedContent: string;
  gitignoreRecommendation: string;
}

interface CodeDiffViewerProps {
  findings: FindingItem[];
  remediation?: RemediationData;
  originalContent?: string;
}

export function CodeDiffViewer({
  findings,
  remediation,
  originalContent,
}: CodeDiffViewerProps) {
  const [activeTab, setActiveTab] = useState<'findings' | 'env' | 'sanitized'>('findings');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch (err) {
      console.error('Failed to copy to clipboard', err);
    }
  };

  const getSeverityBadge = (severity: 'CRITICAL' | 'HIGH' | 'MEDIUM') => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-400 border-rose-500/40';
      case 'HIGH':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      case 'MEDIUM':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
      default:
        return 'bg-slate-700 text-slate-300 border-slate-600';
    }
  };

  return (
    <div className="w-full bg-[#0a101f] border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col">
      {/* Top Navigation Tabs */}
      <div className="flex items-center justify-between border-b border-slate-800 px-4 py-2 bg-[#060b18]">
        <div className="flex items-center gap-1 sm:gap-2">
          <button
            onClick={() => setActiveTab('findings')}
            className={`relative flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              activeTab === 'findings'
                ? 'text-cyan-300'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {activeTab === 'findings' && (
              <motion.span
                layoutId="aegis-tab-pill"
                className="absolute inset-0 rounded-lg bg-cyan-500/20 border border-cyan-500/30"
                transition={{ type: 'spring', stiffness: 420, damping: 34 }}
              />
            )}
            <ShieldAlert className="relative w-4 h-4" />
            <span className="relative">Detected Leaks ({findings.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('env')}
            className={`relative flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              activeTab === 'env'
                ? 'text-cyan-300'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {activeTab === 'env' && (
              <motion.span
                layoutId="aegis-tab-pill"
                className="absolute inset-0 rounded-lg bg-cyan-500/20 border border-cyan-500/30"
                transition={{ type: 'spring', stiffness: 420, damping: 34 }}
              />
            )}
            <Key className="relative w-4 h-4" />
            <span className="relative">.env Auto-Patch</span>
          </button>

          <button
            onClick={() => setActiveTab('sanitized')}
            className={`relative flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              activeTab === 'sanitized'
                ? 'text-cyan-300'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {activeTab === 'sanitized' && (
              <motion.span
                layoutId="aegis-tab-pill"
                className="absolute inset-0 rounded-lg bg-cyan-500/20 border border-cyan-500/30"
                transition={{ type: 'spring', stiffness: 420, damping: 34 }}
              />
            )}
            <Code2 className="relative w-4 h-4" />
            <span className="relative">Sanitized Code</span>
          </button>
        </div>

        {/* Global Action */}
        {activeTab === 'env' && remediation && (
          <button
            onClick={() => copyToClipboard(remediation.envFileSnippet, 'env')}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition"
          >
            {copiedKey === 'env' ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy .env</span>
              </>
            )}
          </button>
        )}

        {activeTab === 'sanitized' && remediation && (
          <button
            onClick={() => copyToClipboard(remediation.sanitizedContent, 'sanitized')}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition"
          >
            {copiedKey === 'sanitized' ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Code</span>
              </>
            )}
          </button>
        )}
      </div>

      {/* Tab Panels */}
      <div className="p-4 flex-1 overflow-y-auto max-h-[500px]">
        {/* PANEL 1: FINDINGS */}
        {activeTab === 'findings' && (
          <div className="space-y-3">
            {findings.length === 0 ? (
              <div className="text-center py-12">
                <Check className="w-12 h-12 text-emerald-400 mx-auto mb-2 opacity-80" />
                <h4 className="text-white font-semibold text-sm">No Secrets Found</h4>
                <p className="text-slate-400 text-xs mt-1">
                  Code passed regex signature checks and Shannon entropy scans.
                </p>
              </div>
            ) : (
              findings.map((f, idx) => (
                <div
                  key={idx}
                  className="p-3.5 rounded-lg bg-slate-900/80 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:border-slate-700 transition"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${getSeverityBadge(
                          f.severity
                        )}`}
                      >
                        {f.severity}
                      </span>
                      <span className="text-white text-sm font-semibold">{f.name}</span>
                      <span className="text-xs text-slate-400 font-mono">Line {f.lineNumber}</span>
                    </div>

                    <div className="flex items-center gap-2 font-mono text-xs">
                      <span className="text-rose-400 bg-rose-950/40 px-2 py-0.5 rounded border border-rose-900/50">
                        {f.redactedToken}
                      </span>
                      {f.entropy && (
                        <span className="text-slate-400 text-[11px]">
                          Entropy: <strong className="text-cyan-400">{f.entropy}</strong> bits/char
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="text-right flex sm:flex-col items-center sm:items-end justify-between gap-1">
                    <span className="text-[10px] uppercase font-mono text-slate-400">Suggested Key</span>
                    <span className="text-xs font-mono text-emerald-400 bg-emerald-950/30 px-2 py-0.5 rounded border border-emerald-900/40">
                      process.env.{f.suggestedEnvKey}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* PANEL 2: .ENV AUTO-PATCH */}
        {activeTab === 'env' && (
          <div className="space-y-4">
            <div>
              <span className="text-xs font-semibold text-slate-300 block mb-1.5">
                Suggested .env file additions:
              </span>
              <pre className="p-3 rounded-lg bg-[#060b14] border border-slate-800 text-xs font-mono text-emerald-300 whitespace-pre-wrap leading-relaxed">
                {remediation?.envFileSnippet || '# No environment variables required.'}
              </pre>
            </div>

            <div>
              <span className="text-xs font-semibold text-slate-300 block mb-1.5">
                Recommended .gitignore update:
              </span>
              <pre className="p-3 rounded-lg bg-[#060b14] border border-slate-800 text-xs font-mono text-slate-400 whitespace-pre-wrap leading-relaxed">
                {remediation?.gitignoreRecommendation || '.env\n.env.local'}
              </pre>
            </div>
          </div>
        )}

        {/* PANEL 3: SANITIZED CODE */}
        {activeTab === 'sanitized' && (
          <div>
            <span className="text-xs font-semibold text-slate-300 block mb-1.5">
              Refactored Source Code (Variables Substituted):
            </span>
            <pre className="p-3 rounded-lg bg-[#060b14] border border-slate-800 text-xs font-mono text-slate-300 whitespace-pre-wrap overflow-x-auto leading-relaxed">
              {remediation?.sanitizedContent || originalContent || '// No sanitized content available.'}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
