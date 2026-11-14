// ============================================================================
// PROJECT AEGIS: LIVE GITHUB REPOSITORY SCANNER ROUTE HANDLER
// Fetches real public repository files through the GitHub REST API and runs the
// shared Shannon entropy + regex signature engine over each file.
//
// Responds with a single JSON document by default. Clients that send
// `Accept: application/x-ndjson` receive per-file progress events instead,
// ending in a `result` event carrying the same JSON document.
// ============================================================================

import { createHash } from 'node:crypto';
import { NextResponse } from 'next/server';
import { resolveAuthContextOrFallback } from '@/lib/auth/dual-auth';
import { checkAndIncrementQuota, type QuotaStatus } from '@/lib/quota';
import { analyzeCode } from '@/lib/scanners/code-analysis';
import {
  GITHUB_MAX_FILES,
  GITHUB_MAX_FILE_BYTES,
  GITHUB_MAX_FIX_FILES,
  buildGithubRawUrl,
  buildRemediationDiff,
  calculateSecurityScore,
  isHighRiskRepoPath,
  parseRepositoryInput,
  redactSecretsForDisplay,
  repoPathPriority,
  signatureEntropyIndex,
  type GithubApiFinding,
  type GithubFix,
  type GithubRepositoryInfo,
  type GithubScanEvent,
  type GithubScanResult,
  type GithubScannedFile,
  type RepoVerdict,
} from '@/lib/scanners/github-auditor';
import { getServiceSupabase } from '@/lib/supabase/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const GITHUB_API = 'https://api.github.com';
const USER_AGENT = 'Project-Aegis-Scanner';
const API_TIMEOUT_MS = 10_000;
const RAW_TIMEOUT_MS = 8_000;

interface GitHubTreeEntry {
  path: string;
  size: number;
}

interface ScanContext {
  owner: string;
  repo: string;
  userId: string;
  repository: GithubRepositoryInfo;
  totalFiles: number;
  treeTruncated: boolean;
  candidates: GitHubTreeEntry[];
}

interface ScanFailure {
  status: number;
  error: string;
  message: string;
}

type FileScanOutcome =
  | { ok: true; path: string; size: number; content: string; analysis: ReturnType<typeof analyzeCode> }
  | { ok: false; path: string; size: number; error: string };

function authHeaders(base: Record<string, string>): Record<string, string> {
  const token = process.env.GITHUB_TOKEN?.trim();
  return token ? { ...base, Authorization: `Bearer ${token}` } : base;
}

function githubHeaders() {
  return authHeaders({
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': USER_AGENT,
  });
}

function rawHeaders() {
  return authHeaders({ Accept: 'text/plain', 'User-Agent': USER_AGENT });
}

function jsonError({ status, error, message }: ScanFailure) {
  return NextResponse.json({ error, message }, { status });
}

function githubFailure(response: Response): ScanFailure {
  const { status } = response;
  if (status === 404) {
    return {
      status: 404,
      error: 'Repository not found or private',
      message: 'GitHub could not find that repository. Check the spelling, or confirm the repository is public.',
    };
  }
  if (status === 403 || status === 429) {
    const reset = Number(response.headers.get('x-ratelimit-reset'));
    const resetHint =
      Number.isFinite(reset) && reset > 0
        ? ` The limit resets at ${new Date(reset * 1000).toLocaleTimeString('en-US', { timeZone: 'UTC' })} UTC.`
        : '';
    return {
      status: 429,
      error: 'GitHub API rate limit reached',
      message: `GitHub API rate limit reached — add GITHUB_TOKEN or retry shortly.${resetHint}`,
    };
  }
  if (status === 401) {
    return {
      status: 502,
      error: 'GitHub token rejected',
      message: 'GitHub rejected the configured GITHUB_TOKEN. Update or remove it in .env.local and restart the server.',
    };
  }
  return {
    status: 502,
    error: 'GitHub request failed',
    message: `GitHub returned HTTP ${status}. Try again in a moment.`,
  };
}

const NETWORK_FAILURE: ScanFailure = {
  status: 502,
  error: 'GitHub unreachable',
  message: 'Could not reach the GitHub API. Check the server network connection and try again.',
};

async function githubJson(url: string): Promise<{ ok: true; payload: unknown } | { ok: false; failure: ScanFailure }> {
  let response: Response;
  try {
    response = await fetch(url, {
      headers: githubHeaders(),
      cache: 'no-store',
      signal: AbortSignal.timeout(API_TIMEOUT_MS),
    });
  } catch {
    return { ok: false, failure: NETWORK_FAILURE };
  }
  if (!response.ok) {
    return { ok: false, failure: githubFailure(response) };
  }
  try {
    return { ok: true, payload: await response.json() };
  } catch {
    return {
      ok: false,
      failure: { status: 502, error: 'GitHub request failed', message: 'GitHub returned an unreadable response.' },
    };
  }
}

function parseRepositoryMetadata(payload: unknown, owner: string, repo: string): GithubRepositoryInfo {
  const record =
    typeof payload === 'object' && payload !== null ? (payload as Record<string, unknown>) : {};
  const ownerRecord =
    typeof record.owner === 'object' && record.owner !== null
      ? (record.owner as Record<string, unknown>)
      : {};

  const defaultBranch =
    typeof record.default_branch === 'string' && record.default_branch.trim()
      ? record.default_branch
      : 'main';
  const htmlUrl =
    typeof record.html_url === 'string' && /^https:\/\/github\.com\//.test(record.html_url)
      ? record.html_url
      : `https://github.com/${owner}/${repo}`;

  return {
    owner: typeof ownerRecord.login === 'string' ? ownerRecord.login : owner,
    name: typeof record.name === 'string' ? record.name : repo,
    fullName: typeof record.full_name === 'string' ? record.full_name : `${owner}/${repo}`,
    description: typeof record.description === 'string' ? record.description : null,
    defaultBranch,
    private: record.private === true,
    stars: typeof record.stargazers_count === 'number' ? record.stargazers_count : 0,
    language: typeof record.language === 'string' ? record.language : null,
    htmlUrl,
    updatedAt: typeof record.updated_at === 'string' ? record.updated_at : '',
  };
}

function parseTreePayload(payload: unknown): { entries: GitHubTreeEntry[]; truncated: boolean } {
  if (typeof payload !== 'object' || payload === null) {
    return { entries: [], truncated: false };
  }
  const record = payload as { tree?: unknown; truncated?: unknown };
  const entries = Array.isArray(record.tree)
    ? record.tree.flatMap((item): GitHubTreeEntry[] => {
        if (typeof item !== 'object' || item === null) {
          return [];
        }
        const entry = item as { path?: unknown; type?: unknown; size?: unknown };
        if (typeof entry.path !== 'string' || entry.type !== 'blob') {
          return [];
        }
        return [{ path: entry.path, size: typeof entry.size === 'number' ? entry.size : 0 }];
      })
    : [];
  return { entries, truncated: record.truncated === true };
}

function higherVerdict(a: RepoVerdict, b: RepoVerdict): RepoVerdict {
  const rank: Record<RepoVerdict, number> = { SAFE: 0, SUSPICIOUS: 1, DANGEROUS: 2 };
  return rank[b] > rank[a] ? b : a;
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

async function prepareScan(req: Request): Promise<{ ok: true; context: ScanContext } | { ok: false; failure: ScanFailure }> {
  const body = (await req.json().catch(() => null)) as { repoUrl?: unknown } | null;
  const parsed = parseRepositoryInput(body?.repoUrl);
  if (!parsed.ok) {
    return { ok: false, failure: { status: 400, error: 'Invalid repository', message: parsed.error } };
  }
  const { owner, repo } = parsed;

  const authContext = await resolveAuthContextOrFallback(req);
  let quota: QuotaStatus;
  try {
    quota = await checkAndIncrementQuota(authContext.userId);
  } catch {
    quota = {
      allowed: true,
      dailyScanCount: 0,
      maxDailyQuota: Number.MAX_SAFE_INTEGER,
      plan: 'free',
      resetsAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    };
  }
  if (!quota.allowed) {
    return {
      ok: false,
      failure: {
        status: 429,
        error: 'Daily scan quota exhausted',
        message: `Daily scan quota exhausted. Resets at ${quota.resetsAt}.`,
      },
    };
  }

  const repoPath = `${GITHUB_API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
  const metadata = await githubJson(repoPath);
  if (!metadata.ok) {
    return metadata;
  }
  const repository = parseRepositoryMetadata(metadata.payload, owner, repo);

  const tree = await githubJson(
    `${repoPath}/git/trees/${encodeURIComponent(repository.defaultBranch)}?recursive=1`
  );
  if (!tree.ok) {
    return tree;
  }
  const { entries, truncated } = parseTreePayload(tree.payload);

  const candidates = entries
    .filter((entry) => isHighRiskRepoPath(entry.path, entry.size))
    .sort(
      (a, b) =>
        repoPathPriority(a.path) - repoPathPriority(b.path) ||
        a.path.split('/').length - b.path.split('/').length ||
        a.path.localeCompare(b.path)
    )
    .slice(0, GITHUB_MAX_FILES);

  return {
    ok: true,
    context: {
      owner,
      repo,
      userId: authContext.userId,
      repository,
      totalFiles: entries.length,
      treeTruncated: truncated,
      candidates,
    },
  };
}

async function fetchAndAnalyze(context: ScanContext, entry: GitHubTreeEntry): Promise<FileScanOutcome> {
  try {
    const response = await fetch(
      buildGithubRawUrl(context.owner, context.repo, context.repository.defaultBranch, entry.path),
      { headers: rawHeaders(), cache: 'no-store', signal: AbortSignal.timeout(RAW_TIMEOUT_MS) }
    );
    if (!response.ok) {
      throw new Error(`GitHub returned HTTP ${response.status}`);
    }
    const text = await response.text();
    if (text.includes('\u0000')) {
      throw new Error('Binary content skipped');
    }
    const content = text.length > GITHUB_MAX_FILE_BYTES ? text.slice(0, GITHUB_MAX_FILE_BYTES) : text;
    return { ok: true, path: entry.path, size: entry.size, content, analysis: analyzeCode(content, entry.path) };
  } catch (error) {
    return {
      ok: false,
      path: entry.path,
      size: entry.size,
      error: error instanceof Error ? error.message : 'File fetch failed',
    };
  }
}

async function executeScan(
  context: ScanContext,
  emit: (event: GithubScanEvent) => void
): Promise<{ ok: true; result: GithubScanResult } | { ok: false; failure: ScanFailure }> {
  const { repository, candidates } = context;

  const settled = await Promise.allSettled(
    candidates.map(async (entry) => {
      const outcome = await fetchAndAnalyze(context, entry);
      emit({
        type: 'file',
        path: outcome.path,
        status: outcome.ok ? 'scanned' : 'failed',
        findingsCount: outcome.ok ? outcome.analysis.findingsCount : 0,
        highestEntropy: outcome.ok ? outcome.analysis.highestEntropy : 0,
        ...(outcome.ok ? {} : { error: outcome.error }),
      });
      return outcome;
    })
  );

  const files: GithubScannedFile[] = [];
  const findings: GithubApiFinding[] = [];
  const fixes: GithubFix[] = [];
  const envKeys = new Set<string>();
  const digestLines: string[] = [];
  let filesFailed = 0;
  let filesWithFindings = 0;
  let highestEntropy = 0;
  let riskScore = 0;
  let verdict: RepoVerdict = 'SAFE';

  settled.forEach((settledOutcome, index) => {
    const file: FileScanOutcome =
      settledOutcome.status === 'fulfilled'
        ? settledOutcome.value
        : { ok: false, path: candidates[index].path, size: candidates[index].size, error: 'File fetch failed' };

    if (!file.ok) {
      filesFailed += 1;
      files.push({
        path: file.path,
        size: file.size,
        status: 'failed',
        findingsCount: 0,
        highestEntropy: 0,
        riskScore: 0,
        verdict: 'SAFE',
        error: file.error,
      });
      return;
    }

    const { analysis } = file;
    digestLines.push(`${file.path}:${sha256(file.content)}`);
    highestEntropy = Math.max(highestEntropy, analysis.highestEntropy);
    riskScore = Math.max(riskScore, analysis.riskScore);
    verdict = higherVerdict(verdict, analysis.verdict);
    files.push({
      path: file.path,
      size: file.size,
      status: 'scanned',
      findingsCount: analysis.findingsCount,
      highestEntropy: analysis.highestEntropy,
      riskScore: analysis.riskScore,
      verdict: analysis.verdict,
    });

    if (analysis.findings.length === 0) {
      return;
    }

    filesWithFindings += 1;
    const redactedContent = redactSecretsForDisplay(file.content);
    const signatureEntropy = signatureEntropyIndex(file.content);
    for (const finding of analysis.findings) {
      findings.push({
        filePath: file.path,
        lineNumber: finding.lineNumber,
        ruleName: finding.name,
        type: finding.type,
        severity: finding.severity,
        entropy:
          finding.entropy ??
          signatureEntropy.get(`${finding.lineNumber}:${finding.name}:${finding.redactedToken}`) ??
          0,
        maskedMatch: finding.redactedToken,
        suggestedEnvKey: finding.suggestedEnvKey,
        remediationDiff: buildRemediationDiff(
          file.path,
          finding.lineNumber,
          redactedContent,
          analysis.remediation.sanitizedContent
        ),
      });
    }
    for (const line of analysis.remediation.envFileSnippet.split('\n')) {
      const key = line.split('=')[0]?.trim();
      if (key) {
        envKeys.add(key);
      }
    }
    fixes.push({
      filePath: file.path,
      findings: analysis.findings,
      remediation: analysis.remediation,
      originalContent: redactedContent,
      riskScore: analysis.riskScore,
      verdict: analysis.verdict,
      highestEntropy: analysis.highestEntropy,
    });
  });

  const filesScanned = files.length - filesFailed;
  if (candidates.length > 0 && filesScanned === 0) {
    return {
      ok: false,
      failure: {
        status: 502,
        error: 'Repository scan failed',
        message:
          'GitHub did not return any of the candidate files. The repository may be empty, or raw content could not be fetched.',
      },
    };
  }

  fixes.sort(
    (a, b) =>
      b.riskScore - a.riskScore ||
      b.findings.length - a.findings.length ||
      a.filePath.localeCompare(b.filePath)
  );
  digestLines.sort();
  const scannedFiles = files.filter((file) => file.status === 'scanned').map((file) => file.path);

  const result: GithubScanResult = {
    repo: {
      owner: repository.owner,
      name: repository.name,
      branch: repository.defaultBranch,
      stars: repository.stars,
      language: repository.language,
      totalFilesInTree: context.totalFiles,
      scannedFilesCount: filesScanned,
    },
    scannedFiles,
    findings,
    securityScore: calculateSecurityScore(findings),
    auditDigest: sha256(`${repository.fullName}@${repository.defaultBranch}\n${digestLines.join('\n')}`),
    scannedAt: new Date().toISOString(),
    repository,
    summary: {
      totalFiles: context.totalFiles,
      candidateFiles: candidates.length,
      filesScanned,
      filesFailed,
      filesWithFindings,
      findingsCount: findings.length,
      highestEntropy,
      riskScore,
      verdict,
    },
    files,
    fixes: fixes.slice(0, GITHUB_MAX_FIX_FILES),
    aggregateEnvSnippet: [...envKeys].sort().map((key) => `${key}=""`).join('\n'),
    treeTruncated: context.treeTruncated,
  };
  return { ok: true, result };
}

function recordGithubScan(userId: string, result: GithubScanResult) {
  const supabase = getServiceSupabase();
  if (!supabase) {
    return;
  }
  const { repository, summary, findings } = result;
  void supabase
    .from('scans')
    .insert({
      user_id: userId,
      scan_type: 'code',
      target: repository.fullName,
      risk_score: summary.riskScore,
      verdict: summary.verdict,
      summary: `GitHub repository scan detected ${summary.findingsCount} secret token(s) across ${summary.filesScanned} file(s) in ${repository.fullName}.`,
      details: {
        source: 'github',
        repository: repository.fullName,
        defaultBranch: repository.defaultBranch,
        candidateFiles: summary.candidateFiles,
        filesScanned: summary.filesScanned,
        filesFailed: summary.filesFailed,
        findingsCount: summary.findingsCount,
        securityScore: result.securityScore,
        auditDigest: result.auditDigest,
        findings: findings.slice(0, 25).map((finding) => ({
          filePath: finding.filePath,
          ruleName: finding.ruleName,
          severity: finding.severity,
          lineNumber: finding.lineNumber,
          maskedMatch: finding.maskedMatch,
        })),
      },
    })
    .then(
      () => undefined,
      () => undefined
    );
}

export async function POST(req: Request) {
  const prepared = await prepareScan(req);
  if (!prepared.ok) {
    return jsonError(prepared.failure);
  }
  const { context } = prepared;

  const wantsStream = req.headers.get('accept')?.includes('application/x-ndjson') ?? false;
  if (!wantsStream) {
    const outcome = await executeScan(context, () => undefined);
    if (!outcome.ok) {
      return jsonError(outcome.failure);
    }
    recordGithubScan(context.userId, outcome.result);
    return NextResponse.json(outcome.result, { headers: { 'Cache-Control': 'no-store' } });
  }

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const encoder = new TextEncoder();
      let closed = false;
      const send = (event: GithubScanEvent) => {
        if (closed) {
          return;
        }
        try {
          controller.enqueue(encoder.encode(`${JSON.stringify(event)}\n`));
        } catch {
          closed = true;
        }
      };

      try {
        send({ type: 'metadata', repository: context.repository });
        send({
          type: 'tree',
          totalFiles: context.totalFiles,
          candidateFiles: context.candidates.length,
          treeTruncated: context.treeTruncated,
        });
        const outcome = await executeScan(context, send);
        if (outcome.ok) {
          send({ type: 'result', result: outcome.result });
          recordGithubScan(context.userId, outcome.result);
        } else {
          send({ type: 'error', error: outcome.failure.error, message: outcome.failure.message });
        }
      } catch (error) {
        send({
          type: 'error',
          error: 'Repository scan failed',
          message: error instanceof Error ? error.message : 'Unexpected scan error.',
        });
      } finally {
        if (!closed) {
          try {
            controller.close();
          } catch {
            // The client canceled the stream before scan completion.
          }
        }
      }
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'application/x-ndjson; charset=utf-8',
      'Cache-Control': 'no-store, no-transform',
      'X-Accel-Buffering': 'no',
    },
  });
}
