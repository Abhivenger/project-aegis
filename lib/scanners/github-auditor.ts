// ============================================================================
// PROJECT AEGIS: GITHUB REPOSITORY AUDITOR — SHARED TYPES & HELPERS
// ============================================================================

import { calculateShannonEntropy, extractHighEntropyTokens } from './entropy';
import { redactSecret, scanCodeForPatterns } from './regex-patterns';

export const GITHUB_MAX_FILES = 20;
export const GITHUB_MAX_FILE_BYTES = 100 * 1024;
export const GITHUB_MAX_FIX_FILES = 6;

export type RepoVerdict = 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM';

const SEVERITY_PENALTY: Record<FindingSeverity, number> = { CRITICAL: 25, HIGH: 15, MEDIUM: 8 };

/** 100 = no findings; each finding subtracts a severity-weighted penalty, floored at 0. */
export function calculateSecurityScore(findings: { severity: FindingSeverity }[]): number {
  const penalty = findings.reduce((total, finding) => total + SEVERITY_PENALTY[finding.severity], 0);
  return Math.max(0, 100 - penalty);
}

export type RepoBadge = 'VERIFIED_CLEAN' | 'CAUTION' | 'DANGEROUS';

/**
 * Badge calibration: a single weak finding should not paint a whole repo red.
 * DANGEROUS requires a score below 60 or any critical secret.
 */
export function classifyRepoBadge(
  securityScore: number,
  findings: { severity: FindingSeverity }[]
): RepoBadge {
  if (securityScore < 60 || findings.some((finding) => finding.severity === 'CRITICAL')) {
    return 'DANGEROUS';
  }
  return securityScore >= 90 ? 'VERIFIED_CLEAN' : 'CAUTION';
}

export interface GithubRepositoryInfo {
  owner: string;
  name: string;
  fullName: string;
  description: string | null;
  defaultBranch: string;
  private: boolean;
  stars: number;
  language: string | null;
  htmlUrl: string;
  updatedAt: string;
}

export interface GithubFinding {
  type: 'KNOWN_SIGNATURE' | 'HIGH_ENTROPY';
  name: string;
  severity: FindingSeverity;
  lineNumber: number;
  redactedToken: string;
  entropy?: number;
  suggestedEnvKey: string;
  filePath: string;
}

export interface GithubApiFinding {
  filePath: string;
  lineNumber: number;
  ruleName: string;
  type: GithubFinding['type'];
  severity: FindingSeverity;
  entropy: number;
  maskedMatch: string;
  suggestedEnvKey: string;
  remediationDiff: string;
}

export interface GithubRepoTelemetry {
  owner: string;
  name: string;
  branch: string;
  stars: number;
  language: string | null;
  totalFilesInTree: number;
  scannedFilesCount: number;
}

export interface GithubRemediation {
  hasSecrets: boolean;
  envFileSnippet: string;
  sanitizedContent: string;
  gitignoreRecommendation: string;
}

export interface GithubFix {
  filePath: string;
  findings: Omit<GithubFinding, 'filePath'>[];
  remediation: GithubRemediation;
  originalContent: string;
  riskScore: number;
  verdict: RepoVerdict;
  highestEntropy: number;
}

export interface GithubScannedFile {
  path: string;
  size: number;
  status: 'scanned' | 'failed';
  findingsCount: number;
  highestEntropy: number;
  riskScore: number;
  verdict: RepoVerdict;
  error?: string;
}

export interface GithubScanSummary {
  totalFiles: number;
  candidateFiles: number;
  filesScanned: number;
  filesFailed: number;
  filesWithFindings: number;
  findingsCount: number;
  highestEntropy: number;
  riskScore: number;
  verdict: RepoVerdict;
}

export interface GithubScanResult {
  repo: GithubRepoTelemetry;
  scannedFiles: string[];
  findings: GithubApiFinding[];
  securityScore: number;
  /** SHA-256 over repo@branch and each scanned file's path + content hash. */
  auditDigest: string;
  scannedAt: string;
  repository: GithubRepositoryInfo;
  summary: GithubScanSummary;
  files: GithubScannedFile[];
  fixes: GithubFix[];
  aggregateEnvSnippet: string;
  treeTruncated: boolean;
}

export type GithubScanEvent =
  | { type: 'metadata'; repository: GithubRepositoryInfo }
  | { type: 'tree'; totalFiles: number; candidateFiles: number; treeTruncated: boolean }
  | {
      type: 'file';
      path: string;
      status: 'scanned' | 'failed';
      findingsCount: number;
      highestEntropy: number;
      error?: string;
    }
  | { type: 'result'; result: GithubScanResult }
  | { type: 'error'; error: string; message: string };

export type RepositoryParseResult =
  | { ok: true; owner: string; repo: string; slug: string }
  | { ok: false; error: string };

const OWNER_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const REPO_PATTERN = /^[A-Za-z0-9_.-]{1,100}$/;

/**
 * Accepts `owner/repo`, `github.com/owner/repo`, or
 * `https://github.com/owner/repo` (optionally with a trailing slash or .git).
 */
export function parseRepositoryInput(raw: unknown): RepositoryParseResult {
  if (typeof raw !== 'string') {
    return { ok: false, error: 'Enter a repository as owner/repo or a GitHub URL.' };
  }

  const value = raw.trim();
  if (!value) {
    return { ok: false, error: 'Enter a repository as owner/repo or a GitHub URL.' };
  }
  if (/[?#\s]/.test(value) || value.includes('@')) {
    return {
      ok: false,
      error: 'Only plain GitHub repository URLs are supported: no query strings, fragments, credentials, or whitespace.',
    };
  }

  const urlMatch = /^(?:https?:\/\/)?(?:www\.)?github\.com\/(.+)$/i.exec(value);
  let slug: string;
  if (urlMatch) {
    slug = urlMatch[1];
  } else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    return { ok: false, error: 'Only github.com repository URLs are supported.' };
  } else {
    slug = value;
  }

  if (slug.endsWith('/')) {
    slug = slug.slice(0, -1);
  }
  if (slug.toLowerCase().endsWith('.git')) {
    slug = slug.slice(0, -4);
  }

  const parts = slug.split('/');
  if (parts.length !== 2) {
    return {
      ok: false,
      error: 'Use owner/repo or https://github.com/owner/repo. Extra path segments are not accepted.',
    };
  }

  const [owner, repo] = parts;
  if (!OWNER_PATTERN.test(owner)) {
    return {
      ok: false,
      error: 'GitHub owners must be 1–39 letters, numbers, or single hyphens, with no leading or trailing hyphen.',
    };
  }
  if (!REPO_PATTERN.test(repo) || repo === '.' || repo === '..') {
    return {
      ok: false,
      error: 'Repository names must be 1–100 letters, numbers, dots, underscores, or hyphens, and cannot consist only of dots.',
    };
  }

  return { ok: true, owner, repo, slug: `${owner}/${repo}` };
}

const EXCLUDED_SEGMENTS = new Set([
  'node_modules',
  'vendor',
  'dist',
  'build',
  '.next',
  'coverage',
  '.git',
  'snapshots',
]);

const LOCKFILES = new Set([
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'composer.lock',
  'bun.lockb',
]);

const SENSITIVE_FILES = new Set([
  '.npmrc',
  '.pypirc',
  '.netrc',
  '.htpasswd',
  '.git-credentials',
  'id_rsa',
  'id_ed25519',
  'dockerfile',
]);

const ALLOWED_EXTENSION = /\.(?:m?js|cjs|jsx|tsx?|py|json|ya?ml|env|ini|cfg|conf|toml)$/i;
const RISKY_NAME = /(?:^|[._-])(?:secrets?|credentials?|tokens?|api[-_]?keys?|keys?|config(?:uration)?|settings|env)(?:[._-]|$)/i;

/** True for code/config files that commonly carry committed credentials. */
export function isHighRiskRepoPath(path: string, size: number): boolean {
  const lower = path.toLowerCase();
  if (!lower || lower.endsWith('/')) {
    return false;
  }
  if (lower.startsWith('/') || lower.includes('\\') || lower.split('/').some((part) => part === '..')) {
    return false;
  }
  const segments = lower.split('/');
  if (segments.some((segment) => EXCLUDED_SEGMENTS.has(segment))) {
    return false;
  }
  const base = segments[segments.length - 1];
  if (!base || LOCKFILES.has(base) || /\.min\.(?:js|css)$/.test(base) || /\.map$/.test(base)) {
    return false;
  }
  if (size > GITHUB_MAX_FILE_BYTES) {
    return false;
  }
  if (base === '.env' || base.startsWith('.env.') || base.endsWith('.env')) {
    return true;
  }
  return SENSITIVE_FILES.has(base) || ALLOWED_EXTENSION.test(base) || RISKY_NAME.test(base);
}

/** Lower numbers are fetched first so `.env` and credential files win the file budget. */
export function repoPathPriority(path: string): number {
  const base = path.toLowerCase().split('/').pop() ?? path.toLowerCase();
  if (base === '.env' || base.startsWith('.env.') || base.endsWith('.env')) {
    return 0;
  }
  if (SENSITIVE_FILES.has(base) || /(?:secret|credential|token|key)/.test(base)) {
    return 1;
  }
  if (/(?:config|settings|env)/.test(base)) {
    return 2;
  }
  return 3;
}

export function buildGithubRawUrl(owner: string, repo: string, branch: string, filePath: string): string {
  const encodedBranch = branch.split('/').map(encodeURIComponent).join('/');
  const encodedPath = filePath.split('/').map(encodeURIComponent).join('/');
  return `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodedBranch}/${encodedPath}`;
}

/**
 * Replaces detected secret values with redacted previews before source content
 * leaves the server. Findings keep their redacted previews and line numbers.
 */
export function redactSecretsForDisplay(content: string): string {
  let redacted = content;
  for (const match of scanCodeForPatterns(content)) {
    if (match.matchedString) {
      redacted = redacted.split(match.matchedString).join(match.redactedString);
    }
  }
  for (const candidate of extractHighEntropyTokens(content).candidates) {
    redacted = redacted.split(candidate.token).join(redactSecret(candidate.token));
  }
  return redacted;
}

/** Shannon entropy of each signature match, keyed by `line:rule:redacted`. */
export function signatureEntropyIndex(content: string): Map<string, number> {
  const index = new Map<string, number>();
  for (const match of scanCodeForPatterns(content)) {
    index.set(
      `${match.lineNumber}:${match.name}:${match.redactedString}`,
      calculateShannonEntropy(match.matchedString)
    );
  }
  return index;
}

/**
 * Single-hunk unified diff for one finding. `redactedContent` and
 * `sanitizedContent` are line-aligned, except Python fixes may prepend `import os`.
 */
export function buildRemediationDiff(
  filePath: string,
  lineNumber: number,
  redactedContent: string,
  sanitizedContent: string
): string {
  const before = redactedContent.split(/\r?\n/);
  const after = sanitizedContent.split(/\r?\n/);
  const offset = Math.max(0, after.length - before.length);
  const removed = before[lineNumber - 1] ?? '';
  const added = after[lineNumber - 1 + offset] ?? '';
  return [
    `--- a/${filePath}`,
    `+++ b/${filePath}`,
    `@@ -${lineNumber} +${lineNumber + offset} @@`,
    `-${removed}`,
    `+${added}`,
  ].join('\n');
}
