"use client";

import React, { useCallback, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { motion } from "motion/react";
import {
  Copy,
  Check,
  ShieldAlert,
  FileText,
  Code2,
  AlertTriangle,
  Key,
  GitCompare,
  Flame,
} from "lucide-react";

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

// ============================================================================
// ENTROPY HEATMAP: SHANNON METRIC + TOKEN ANALYSIS
// Equation: H(X) = -SUM( P(x_i) * log2(P(x_i)) )
// ============================================================================

type ViewMode = 'diff' | 'heatmap';
type EntropyLevel = 'normal' | 'elevated' | 'critical';

export interface EntropyToken {
  /** Raw source text. Whitespace tokens carry spaces/newlines so layout survives. */
  value: string;
  /** Shannon entropy in bits per character for this token. */
  entropy: number;
  /** Character count measured in Unicode code points. */
  charCount: number;
  /** Heat classification band derived from the entropy score. */
  level: EntropyLevel;
  /** Whitespace-only tokens are rendered verbatim and never flagged. */
  isWhitespace: boolean;
}

/** Tokens at or above this entropy are rendered as elevated risk (amber). */
export const ENTROPY_ELEVATED_THRESHOLD = 3.2;
/** Tokens above this entropy are treated as secret candidates (crimson). */
export const ENTROPY_CRITICAL_THRESHOLD = 4.2;
/** Upper bound on how many source characters are tokenized for the heatmap. */
export const ENTROPY_HEATMAP_CHAR_LIMIT = 120_000;

/**
 * Splits source code into entropy-classified tokens while preserving every
 * character. Each token is either a whitespace run, an identifier/number run,
 * or a run of punctuation/operators, so the original structure is reproduced
 * exactly when the tokens are rendered in order.
 */
const HEATMAP_TOKEN_PATTERN = /\s+|[A-Za-z0-9_]+|[^\sA-Za-z0-9_]+/g;

/**
 * Computes Shannon entropy in bits per character for an arbitrary string.
 * Iterates by Unicode code point (not UTF-16 unit) so surrogate pairs and
 * astral characters are counted as a single symbol.
 */
export function calculateShannonEntropy(input: string): number {
  if (!input) {
    return 0;
  }

  const frequencies = new Map<string, number>();
  let length = 0;

  for (const char of input) {
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
    length += 1;
  }

  if (length <= 1) {
    return 0;
  }

  let entropy = 0;
  for (const count of frequencies.values()) {
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

/** Maps a raw entropy score onto a heat classification band. */
export function classifyEntropy(entropy: number): EntropyLevel {
  if (entropy > ENTROPY_CRITICAL_THRESHOLD) {
    return 'critical';
  }
  if (entropy >= ENTROPY_ELEVATED_THRESHOLD) {
    return 'elevated';
  }
  return 'normal';
}

/** Human-readable classification surfaced in the token tooltip. */
export function entropyClassificationLabel(level: EntropyLevel): string {
  return level === 'critical' ? 'Cryptographic Entropy' : 'Natural Code Syntax';
}

/**
 * Tokenizes source code into entropy-scored tokens. Repeated substrings are
 * scored once and reused, keeping analysis linear even for large payloads.
 */
export function tokenizeWithEntropy(source: string): EntropyToken[] {
  const tokens: EntropyToken[] = [];
  if (!source) {
    return tokens;
  }

  const matches = source.match(HEATMAP_TOKEN_PATTERN);
  if (!matches) {
    return tokens;
  }

  const cache = new Map<string, EntropyToken>();

  for (const value of matches) {
    const cached = cache.get(value);
    if (cached) {
      tokens.push(cached);
      continue;
    }

    const isWhitespace = /^\s+$/.test(value);
    const entropy = isWhitespace ? 0 : calculateShannonEntropy(value);
    const token: EntropyToken = {
      value,
      entropy,
      charCount: Array.from(value).length,
      level: isWhitespace ? 'normal' : classifyEntropy(entropy),
      isWhitespace,
    };

    cache.set(value, token);
    tokens.push(token);
  }

  return tokens;
}

export interface HeatmapAnalysis {
  tokens: EntropyToken[];
  truncated: boolean;
  criticalCount: number;
  elevatedCount: number;
  maxEntropy: number;
}

/** Tokenizes source content (bounded for performance) and aggregates stats. */
export function analyzeSourceForHeatmap(source: string): HeatmapAnalysis {
  const truncated = source.length > ENTROPY_HEATMAP_CHAR_LIMIT;
  const effective = truncated ? source.slice(0, ENTROPY_HEATMAP_CHAR_LIMIT) : source;
  const tokens = tokenizeWithEntropy(effective);

  let criticalCount = 0;
  let elevatedCount = 0;
  let maxEntropy = 0;

  for (const token of tokens) {
    if (token.isWhitespace) {
      continue;
    }
    if (token.level === 'critical') {
      criticalCount += 1;
    } else if (token.level === 'elevated') {
      elevatedCount += 1;
    }
    if (token.entropy > maxEntropy) {
      maxEntropy = token.entropy;
    }
  }

  return { tokens, truncated, criticalCount, elevatedCount, maxEntropy };
}

function getTokenClassName(level: EntropyLevel): string {
  const base =
    'cursor-help rounded-[3px] transition-colors [-webkit-box-decoration-break:clone] [box-decoration-break:clone]';

  switch (level) {
    case 'critical':
      return `${base} text-rose-200 bg-rose-600/25 border border-rose-500 ring-1 ring-rose-500/70 animate-entropy-pulse motion-reduce:animate-none`;
    case 'elevated':
      return `${base} text-amber-200 bg-amber-500/20 border border-amber-500/60`;
    default:
      return `${base} text-slate-400 hover:text-cyan-300`;
  }
}

interface HoverState {
  token: EntropyToken;
  left: number;
  top: number;
  placement: 'above' | 'below';
}

function LegendSwatch({
  tone,
  label,
  range,
}: {
  tone: 'slate' | 'amber' | 'rose';
  label: string;
  range: string;
}) {
  const dot =
    tone === 'rose' ? 'bg-rose-500' : tone === 'amber' ? 'bg-amber-500' : 'bg-slate-500';

  return (
    <span className="flex items-center gap-1.5 text-[10px]">
      <span className={`inline-block h-2.5 w-2.5 rounded-sm ${dot}`} />
      <span className="font-medium text-slate-300">{label}</span>
      <span className="hidden font-mono text-slate-500 sm:inline">{range}</span>
    </span>
  );
}

/**
 * Pure presentational token stream. Memoized so hover state in the parent
 * does not re-render thousands of token spans on every pointer move.
 */
const HeatmapTokenStream = React.memo(function HeatmapTokenStream({
  tokens,
}: {
  tokens: EntropyToken[];
}) {
  return (
    <pre className="m-0 whitespace-pre-wrap break-words font-mono text-xs leading-relaxed text-slate-400">
      {tokens.map((token, index) =>
        token.isWhitespace ? (
          <span key={index}>{token.value}</span>
        ) : (
          <span key={index} data-token-index={index} className={getTokenClassName(token.level)}>
            {token.value}
          </span>
        )
      )}
    </pre>
  );
});

function EntropyHeatmapPanel({ content }: { content?: string }) {
  const analysis = useMemo(() => analyzeSourceForHeatmap(content ?? ''), [content]);
  const [hover, setHover] = useState<HoverState | null>(null);

  const handlePointerOver = useCallback(
    (event: React.MouseEvent<HTMLDivElement>) => {
      const target = event.target as HTMLElement;
      const tokenElement = target.closest<HTMLElement>('[data-token-index]');
      if (!tokenElement) {
        setHover(null);
        return;
      }

      const index = Number.parseInt(tokenElement.dataset.tokenIndex ?? '', 10);
      if (!Number.isInteger(index) || index < 0 || index >= analysis.tokens.length) {
        return;
      }

      const token = analysis.tokens[index];
      if (!token || token.isWhitespace) {
        return;
      }

      const rect = tokenElement.getBoundingClientRect();
      const placeBelow = rect.top < 170;
      const halfWidth = 150;
      const viewportWidth = typeof window !== 'undefined' ? window.innerWidth : 1280;
      const left = Math.min(
        Math.max(rect.left + rect.width / 2, halfWidth),
        Math.max(viewportWidth - halfWidth, halfWidth)
      );

      setHover({
        token,
        left,
        top: placeBelow ? rect.bottom + 12 : rect.top - 12,
        placement: placeBelow ? 'below' : 'above',
      });
    },
    [analysis.tokens]
  );

  const handlePointerLeave = useCallback(() => setHover(null), []);

  if (!content) {
    return (
      <div className="py-12 text-center">
        <FileText className="mx-auto mb-2 h-12 w-12 text-slate-600" />
        <h4 className="text-sm font-semibold text-white">No Source Content</h4>
        <p className="mt-1 text-xs text-slate-400">
          Run an audit to visualize token-level Shannon entropy across the scanned code.
        </p>
      </div>
    );
  }

  const classification = hover ? entropyClassificationLabel(hover.token.level) : '';
  const isAbove = hover?.placement === 'above';

  return (
    <div className="space-y-3">
      {/* Legend + aggregate readout */}
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
          <LegendSwatch tone="slate" label="Natural syntax" range="< 3.2 bits" />
          <LegendSwatch tone="amber" label="Elevated" range="3.2–4.2 bits" />
          <LegendSwatch tone="rose" label="Secret candidate" range="> 4.2 bits" />
        </div>
        <div className="flex items-center gap-4 font-mono text-[10px]">
          <span className="text-slate-400">
            Elevated <strong className="text-amber-400">{analysis.elevatedCount}</strong>
          </span>
          <span className="text-slate-400">
            Secret candidates <strong className="text-rose-400">{analysis.criticalCount}</strong>
          </span>
          <span className="text-slate-400">
            Peak <strong className="text-cyan-300">{analysis.maxEntropy.toFixed(2)}</strong>
          </span>
        </div>
      </div>

      {/* Heatmap surface */}
      <div className="overflow-hidden rounded-lg border border-slate-800 bg-[#060b14]">
        <div
          className="max-h-[440px] overflow-auto p-3"
          onMouseOver={handlePointerOver}
          onMouseLeave={handlePointerLeave}
        >
          <HeatmapTokenStream tokens={analysis.tokens} />
        </div>

        {analysis.truncated && (
          <div className="flex items-center gap-2 border-t border-slate-800 bg-amber-950/20 px-3 py-2 text-[10px] text-amber-300">
            <AlertTriangle className="h-3.5 w-3.5 flex-shrink-0" />
            <span>
              Heatmap truncated to the first{' '}
              {ENTROPY_HEATMAP_CHAR_LIMIT.toLocaleString('en-US')} characters for performance.
            </span>
          </div>
        )}
      </div>

      {/* Token inspector tooltip (portaled so overflow containers never clip it) */}
      {hover &&
        typeof document !== 'undefined' &&
        createPortal(
          <motion.div
            role="tooltip"
            initial={{ opacity: 0, x: '-50%', y: isAbove ? '-92%' : 8, scale: 0.96 }}
            animate={{ opacity: 1, x: '-50%', y: isAbove ? '-100%' : 0, scale: 1 }}
            transition={{ duration: 0.12, ease: 'easeOut' }}
            style={{ left: hover.left, top: hover.top }}
            className={`pointer-events-none fixed z-50 w-64 ${
              hover.placement === 'below' ? 'origin-top' : 'origin-bottom'
            }`}
          >
            <div className="rounded-lg border border-slate-700 bg-[#0b1120]/95 px-3 py-2.5 shadow-2xl shadow-black/60 backdrop-blur">
              <div className="mb-2 flex items-center justify-between gap-2 border-b border-slate-800 pb-1.5">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                  Entropy Inspector
                </span>
                {hover.token.level === 'critical' ? (
                  <span className="flex items-center gap-1 text-[9px] font-bold uppercase text-rose-300">
                    <AlertTriangle className="h-3 w-3" />
                    High Risk
                  </span>
                ) : hover.token.level === 'elevated' ? (
                  <span className="text-[9px] font-bold uppercase text-amber-300">Elevated</span>
                ) : (
                  <span className="text-[9px] font-bold uppercase text-emerald-300">Normal</span>
                )}
              </div>

              <dl className="space-y-1.5 text-[11px]">
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-slate-400">Shannon Metric</dt>
                  <dd className="font-mono text-cyan-300">
                    {hover.token.entropy.toFixed(2)} bits/char
                  </dd>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-slate-400">Character Count</dt>
                  <dd className="font-mono text-slate-200">{hover.token.charCount}</dd>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-slate-400">Classification</dt>
                  <dd
                    className={`font-mono ${
                      hover.token.level === 'critical'
                        ? 'text-rose-300'
                        : hover.token.level === 'elevated'
                          ? 'text-amber-300'
                          : 'text-emerald-300'
                    }`}
                  >
                    {classification}
                  </dd>
                </div>
              </dl>
            </div>
          </motion.div>,
          document.body
        )}
    </div>
  );
}

export function CodeDiffViewer({
  findings,
  remediation,
  originalContent,
}: CodeDiffViewerProps) {
  const [activeTab, setActiveTab] = useState<'findings' | 'env' | 'sanitized'>('findings');
  const [viewMode, setViewMode] = useState<ViewMode>('diff');
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
    <div
      data-tour="remediation-diff"
      className="flex w-full flex-col overflow-hidden rounded-xl border border-slate-800 bg-[#0a101f] shadow-2xl"
    >
      {/* Top Navigation Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 bg-[#060b18] px-4 py-2">
        <div className="flex min-w-0 items-center gap-1 sm:gap-2">
          {viewMode === 'diff' ? (
            <>
              <button
                onClick={() => setActiveTab('findings')}
                className={`relative flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors ${
                  activeTab === 'findings'
                    ? 'text-cyan-300'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {activeTab === 'findings' && (
                  <motion.span
                    layoutId="aegis-tab-pill"
                    className="absolute inset-0 rounded-lg border border-cyan-500/30 bg-cyan-500/20"
                    transition={{ type: 'spring', stiffness: 420, damping: 34 }}
                  />
                )}
                <ShieldAlert className="relative h-4 w-4" />
                <span className="relative">Detected Leaks ({findings.length})</span>
              </button>

              <button
                onClick={() => setActiveTab('env')}
                className={`relative flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors ${
                  activeTab === 'env'
                    ? 'text-cyan-300'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {activeTab === 'env' && (
                  <motion.span
                    layoutId="aegis-tab-pill"
                    className="absolute inset-0 rounded-lg border border-cyan-500/30 bg-cyan-500/20"
                    transition={{ type: 'spring', stiffness: 420, damping: 34 }}
                  />
                )}
                <Key className="relative h-4 w-4" />
                <span className="relative">.env Auto-Patch</span>
              </button>

              <button
                onClick={() => setActiveTab('sanitized')}
                className={`relative flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors ${
                  activeTab === 'sanitized'
                    ? 'text-cyan-300'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {activeTab === 'sanitized' && (
                  <motion.span
                    layoutId="aegis-tab-pill"
                    className="absolute inset-0 rounded-lg border border-cyan-500/30 bg-cyan-500/20"
                    transition={{ type: 'spring', stiffness: 420, damping: 34 }}
                  />
                )}
                <Code2 className="relative h-4 w-4" />
                <span className="relative">Sanitized Code</span>
              </button>
            </>
          ) : (
            <div className="flex items-center gap-2 px-1 text-xs">
              <Flame className="h-4 w-4 text-rose-400" />
              <span className="font-semibold text-slate-200">Entropy Heatmap</span>
              <span className="hidden font-mono text-[10px] text-slate-500 sm:inline">
                token-level Shannon analysis
              </span>
            </div>
          )}
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {/* Global Actions (diff mode only) */}
          {viewMode === 'diff' && activeTab === 'env' && remediation && (
            <button
              onClick={() => copyToClipboard(remediation.envFileSnippet, 'env')}
              className="flex items-center gap-1.5 rounded bg-slate-800 px-2.5 py-1 font-mono text-xs text-slate-200 transition hover:bg-slate-700"
            >
              {copiedKey === 'env' ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400" />
                  <span className="text-emerald-400">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" />
                  <span>Copy .env</span>
                </>
              )}
            </button>
          )}

          {viewMode === 'diff' && activeTab === 'sanitized' && remediation && (
            <button
              onClick={() => copyToClipboard(remediation.sanitizedContent, 'sanitized')}
              className="flex items-center gap-1.5 rounded bg-slate-800 px-2.5 py-1 font-mono text-xs text-slate-200 transition hover:bg-slate-700"
            >
              {copiedKey === 'sanitized' ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400" />
                  <span className="text-emerald-400">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" />
                  <span>Copy Code</span>
                </>
              )}
            </button>
          )}

          {/* View Mode Toggle */}
          <div
            data-tour="entropy-toggle"
            className="relative flex items-center gap-0.5 rounded-lg border border-slate-800 bg-slate-900/80 p-0.5"
          >
            <button
              onClick={() => setViewMode('diff')}
              data-tour-action="diff-view"
              aria-pressed={viewMode === 'diff'}
              className={`relative flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11px] font-semibold transition-colors ${
                viewMode === 'diff' ? 'text-cyan-300' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {viewMode === 'diff' && (
                <motion.span
                  layoutId="aegis-view-pill"
                  className="absolute inset-0 rounded-md border border-cyan-500/30 bg-cyan-500/20"
                  transition={{ type: 'spring', stiffness: 420, damping: 34 }}
                />
              )}
              <GitCompare className="relative h-3.5 w-3.5" />
              <span className="relative">Diff View</span>
            </button>

            <button
              onClick={() => setViewMode('heatmap')}
              data-tour-action="entropy-heatmap"
              aria-pressed={viewMode === 'heatmap'}
              className={`relative flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11px] font-semibold transition-colors ${
                viewMode === 'heatmap' ? 'text-rose-300' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {viewMode === 'heatmap' && (
                <motion.span
                  layoutId="aegis-view-pill"
                  className="absolute inset-0 rounded-md border border-rose-500/30 bg-rose-500/20"
                  transition={{ type: 'spring', stiffness: 420, damping: 34 }}
                />
              )}
              <Flame className="relative h-3.5 w-3.5" />
              <span className="relative">Entropy Heatmap</span>
            </button>
          </div>
        </div>
      </div>

      {/* Panels */}
      <div className="max-h-[500px] flex-1 overflow-y-auto p-4">
        {viewMode === 'heatmap' ? (
          <EntropyHeatmapPanel content={originalContent} />
        ) : (
          <>
            {/* PANEL 1: FINDINGS */}
            {activeTab === 'findings' && (
              <div className="space-y-3">
                {findings.length === 0 ? (
                  <div className="py-12 text-center">
                    <Check className="mx-auto mb-2 h-12 w-12 text-emerald-400 opacity-80" />
                    <h4 className="text-sm font-semibold text-white">No Secrets Found</h4>
                    <p className="mt-1 text-xs text-slate-400">
                      Code passed regex signature checks and Shannon entropy scans.
                    </p>
                  </div>
                ) : (
                  findings.map((f, idx) => (
                    <div
                      key={idx}
                      className="flex flex-col justify-between gap-3 rounded-lg border border-slate-800 bg-slate-900/80 p-3.5 transition hover:border-slate-700 sm:flex-row sm:items-center"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span
                            className={`rounded border px-2 py-0.5 font-mono text-[10px] font-bold ${getSeverityBadge(
                              f.severity
                            )}`}
                          >
                            {f.severity}
                          </span>
                          <span className="text-sm font-semibold text-white">{f.name}</span>
                          <span className="font-mono text-xs text-slate-400">
                            Line {f.lineNumber}
                          </span>
                        </div>

                        <div className="flex items-center gap-2 font-mono text-xs">
                          <span className="rounded border border-rose-900/50 bg-rose-950/40 px-2 py-0.5 text-rose-400">
                            {f.redactedToken}
                          </span>
                          {f.entropy && (
                            <span className="text-[11px] text-slate-400">
                              Entropy:{' '}
                              <strong className="text-cyan-400">{f.entropy}</strong> bits/char
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="flex items-center justify-between gap-1 text-right sm:flex-col sm:items-end">
                        <span className="font-mono text-[10px] uppercase text-slate-400">
                          Suggested Key
                        </span>
                        <span className="rounded border border-emerald-900/40 bg-emerald-950/30 px-2 py-0.5 font-mono text-xs text-emerald-400">
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
                  <span className="mb-1.5 block text-xs font-semibold text-slate-300">
                    Suggested .env file additions:
                  </span>
                  <pre className="whitespace-pre-wrap rounded-lg border border-slate-800 bg-[#060b14] p-3 font-mono text-xs leading-relaxed text-emerald-300">
                    {remediation?.envFileSnippet || '# No environment variables required.'}
                  </pre>
                </div>

                <div>
                  <span className="mb-1.5 block text-xs font-semibold text-slate-300">
                    Recommended .gitignore update:
                  </span>
                  <pre className="whitespace-pre-wrap rounded-lg border border-slate-800 bg-[#060b14] p-3 font-mono text-xs leading-relaxed text-slate-400">
                    {remediation?.gitignoreRecommendation || '.env\n.env.local'}
                  </pre>
                </div>
              </div>
            )}

            {/* PANEL 3: SANITIZED CODE */}
            {activeTab === 'sanitized' && (
              <div>
                <span className="mb-1.5 block text-xs font-semibold text-slate-300">
                  Refactored Source Code (Variables Substituted):
                </span>
                <pre className="overflow-x-auto whitespace-pre-wrap rounded-lg border border-slate-800 bg-[#060b14] p-3 font-mono text-xs leading-relaxed text-slate-300">
                  {remediation?.sanitizedContent ||
                    originalContent ||
                    '// No sanitized content available.'}
                </pre>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
