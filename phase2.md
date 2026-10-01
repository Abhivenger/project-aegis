# PROJECT AEGIS — PHASE 2: ROUTE HANDLERS & CLI CLIENT

This document contains the complete, production-ready source code for Phase 2 of **Project Aegis**. Every file is written in full without placeholders, abbreviations, or omitted logic.

---

## File Map (Phase 2)

1. `lib/auth/dual-auth.ts` — Unified authentication resolver supporting Clerk session cookies and Bearer Developer API Keys (`aegis_live_...`).
2. `app/api/scan/url/route.ts` — SafeLink URL inspection route handler with SSRF validation, quota decrements, and Supabase audit logging.
3. `app/api/scan/secret/route.ts` — GitShield secret scanner route handler with 512 KB payload ceilings, entropy checks, and auto-patch diff generation.
4. `app/api/keys/route.ts` — Developer API key lifecycle management (generation, listing, and revocation with SHA-256 hashing).
5. `cli/aegis.py` — Zero-dependency standalone Python 3 pre-commit hook script with offline entropy fallback, remote API checks, and `--fix` auto-remediation.

---

### 1. `lib/auth/dual-auth.ts`

```typescript
// ============================================================================
// PROJECT AEGIS: DUAL AUTHENTICATION RESOLVER
// Supports Clerk Web Session Cookies & Bearer Developer API Keys
// ============================================================================

import { auth } from '@clerk/nextjs/server';
import { createHash } from 'crypto';
import { getServiceSupabase } from '@/lib/supabase/server';

export interface AuthContext {
  userId: string;
  authMethod: 'clerk_session' | 'api_key';
  keyPrefix?: string;
}

/**
 * Resolves user identity from either an incoming Bearer API Key or an active Clerk session.
 * Returns null if both authentication methods fail or are missing.
 */
export async function resolveAuthContext(req: Request): Promise<AuthContext | null> {
  const authHeader = req.headers.get('authorization') || req.headers.get('Authorization');

  // Strategy A: Developer API Key (Bearer aegis_live_...)
  if (authHeader && authHeader.startsWith('Bearer aegis_live_')) {
    const rawKey = authHeader.replace(/^Bearer\s+/i, '').trim();
    const hashedKey = createHash('sha256').update(rawKey).digest('hex');

    const supabase = getServiceSupabase();
    const { data: apiKeyRecord, error } = await supabase
      .from('api_keys')
      .select('id, user_id, key_prefix')
      .eq('hashed_key', hashedKey)
      .single();

    if (error || !apiKeyRecord) {
      return null;
    }

    // Touch last_used_at timestamp asynchronously
    void supabase
      .from('api_keys')
      .update({ last_used_at: new Date().toISOString() })
      .eq('id', apiKeyRecord.id);

    return {
      userId: apiKeyRecord.user_id,
      authMethod: 'api_key',
      keyPrefix: apiKeyRecord.key_prefix,
    };
  }

  // Strategy B: Clerk Session Authentication (Web Dashboard)
  try {
    const session = await auth();
    if (session && session.userId) {
      return {
        userId: session.userId,
        authMethod: 'clerk_session',
      };
    }
  } catch {
    // Non-Clerk request context (e.g. headless scripts without cookies)
  }

  return null;
}
```

---

### 2. `app/api/scan/url/route.ts`

```typescript
// ============================================================================
// PROJECT AEGIS: SAFELINK URL INSPECTION ROUTE HANDLER
// ============================================================================

import { NextResponse } from 'next/server';
import { resolveAuthContext } from '@/lib/auth/dual-auth';
import { checkAndIncrementQuota } from '@/lib/quota';
import { analyzeUrl } from '@/lib/scanners/url-analyzer';
import { getServiceSupabase } from '@/lib/supabase/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(req: Request) {
  try {
    const authContext = await resolveAuthContext(req);
    if (!authContext) {
      return NextResponse.json(
        { error: 'Unauthorized: Invalid API key or missing session token.' },
        { status: 401 }
      );
    }

    const quota = await checkAndIncrementQuota(authContext.userId);
    if (!quota.allowed) {
      return NextResponse.json(
        {
          error: 'Rate limit exceeded: Daily scan quota exhausted.',
          resetsAt: quota.resetsAt,
          dailyScanCount: quota.dailyScanCount,
          maxDailyQuota: quota.maxDailyQuota,
        },
        { status: 429 }
      );
    }

    const body = await req.json().catch(() => null);
    if (!body || typeof body.url !== 'string' || body.url.trim().length === 0) {
      return NextResponse.json(
        { error: 'Bad Request: "url" property string is required.' },
        { status: 400 }
      );
    }

    const targetUrl = body.url.trim();
    const report = await analyzeUrl(targetUrl);

    // Persist scan audit record to Supabase
    const supabase = getServiceSupabase();
    await supabase.from('scans').insert({
      user_id: authContext.userId,
      scan_type: 'url',
      target: targetUrl,
      risk_score: report.riskScore,
      verdict: report.verdict,
      summary: `SafeLink classified URL as ${report.verdict} with risk score ${report.riskScore}/100.`,
      details: report,
    });

    return NextResponse.json({
      success: true,
      report,
      quota: {
        remaining: Math.max(0, quota.maxDailyQuota - quota.dailyScanCount),
        dailyScanCount: quota.dailyScanCount,
        maxDailyQuota: quota.maxDailyQuota,
        resetsAt: quota.resetsAt,
      },
    });
  } catch (err) {
    const error = err as Error;
    return NextResponse.json(
      { error: 'Internal Server Error', message: error.message },
      { status: 500 }
    );
  }
}
```

---

### 3. `app/api/scan/secret/route.ts`

```typescript
// ============================================================================
// PROJECT AEGIS: GITSHIELD SECRET AUDITOR ROUTE HANDLER
// ============================================================================

import { NextResponse } from 'next/server';
import { resolveAuthContext } from '@/lib/auth/dual-auth';
import { checkAndIncrementQuota } from '@/lib/quota';
import { scanCodeForPatterns, redactSecret } from '@/lib/scanners/regex-patterns';
import { extractHighEntropyTokens } from '@/lib/scanners/entropy';
import { getServiceSupabase } from '@/lib/supabase/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const MAX_PAYLOAD_BYTES = 512 * 1024; // 512 KB payload threshold

interface SecretFinding {
  type: 'KNOWN_SIGNATURE' | 'HIGH_ENTROPY';
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  lineNumber: number;
  redactedToken: string;
  rawToken: string;
  suggestedEnvKey: string;
  entropy?: number;
}

export async function POST(req: Request) {
  try {
    const authContext = await resolveAuthContext(req);
    if (!authContext) {
      return NextResponse.json(
        { error: 'Unauthorized: Missing or invalid API key / session.' },
        { status: 401 }
      );
    }

    const quota = await checkAndIncrementQuota(authContext.userId);
    if (!quota.allowed) {
      return NextResponse.json(
        {
          error: 'Rate limit exceeded: Daily scan quota exhausted.',
          resetsAt: quota.resetsAt,
        },
        { status: 429 }
      );
    }

    const body = await req.json().catch(() => null);
    if (!body || typeof body.content !== 'string') {
      return NextResponse.json(
        { error: 'Bad Request: Missing "content" property in request body.' },
        { status: 400 }
      );
    }

    const filename = typeof body.filename === 'string' ? body.filename : 'staged_diff.txt';
    const content = body.content;

    if (Buffer.byteLength(content, 'utf-8') > MAX_PAYLOAD_BYTES) {
      return NextResponse.json(
        { error: 'Payload Too Large: Content exceeds 512 KB scan ceiling.' },
        { status: 413 }
      );
    }

    // 1. Execute Pattern Scanner
    const patternMatches = scanCodeForPatterns(content);

    // 2. Execute Shannon Entropy Scanner
    const entropyReport = extractHighEntropyTokens(content);

    // 3. Consolidate & Deduplicate Findings
    const findings: SecretFinding[] = [];
    const registeredTokens = new Set<string>();

    for (const match of patternMatches) {
      registeredTokens.add(match.matchedString);
      findings.push({
        type: 'KNOWN_SIGNATURE',
        name: match.name,
        severity: match.severity,
        lineNumber: match.lineNumber,
        redactedToken: match.redactedString,
        rawToken: match.matchedString,
        suggestedEnvKey: match.suggestedEnvKey,
      });
    }

    for (const candidate of entropyReport.candidates) {
      if (!registeredTokens.has(candidate.token)) {
        findings.push({
          type: 'HIGH_ENTROPY',
          name: 'High-Entropy Secret Literal',
          severity: candidate.entropy > 4.5 ? 'CRITICAL' : 'HIGH',
          lineNumber: candidate.lineNumber,
          redactedToken: redactSecret(candidate.token),
          rawToken: candidate.token,
          suggestedEnvKey: `SECRET_TOKEN_${candidate.lineNumber}`,
          entropy: candidate.entropy,
        });
      }
    }

    // 4. Calculate Risk Score & Verdict
    let riskScore = 0;
    if (findings.some((f) => f.severity === 'CRITICAL')) {
      riskScore = 100;
    } else if (findings.some((f) => f.severity === 'HIGH')) {
      riskScore = 75;
    } else if (findings.length > 0) {
      riskScore = 40;
    }

    const verdict = riskScore >= 75 ? 'DANGEROUS' : riskScore >= 25 ? 'SUSPICIOUS' : 'SAFE';

    // 5. Generate Automated Remediation Patch
    const envAdditions: string[] = [];
    let patchedContent = content;

    findings.forEach((finding, index) => {
      const sanitizedKey = `${finding.suggestedEnvKey}_${index + 1}`.toUpperCase();
      envAdditions.push(`${sanitizedKey}="${finding.rawToken}"`);
      patchedContent = patchedContent.split(finding.rawToken).join(`process.env.${sanitizedKey}`);
    });

    const remediation = {
      hasSecrets: findings.length > 0,
      envFileSnippet: envAdditions.join('\n'),
      sanitizedContent: patchedContent,
      gitignoreRecommendation: '.env\n.env.local\n*.pem\n*.key',
    };

    // 6. Record Audit in Supabase
    const supabase = getServiceSupabase();
    await supabase.from('scans').insert({
      user_id: authContext.userId,
      scan_type: authContext.authMethod === 'api_key' ? 'cli_precommit' : 'code',
      target: filename,
      risk_score: riskScore,
      verdict,
      summary: `GitShield detected ${findings.length} secret token(s) in ${filename}.`,
      details: {
        filename,
        findingsCount: findings.length,
        highestEntropy: entropyReport.highestEntropy,
        findings: findings.map((f) => ({
          name: f.name,
          severity: f.severity,
          lineNumber: f.lineNumber,
          redactedToken: f.redactedToken,
        })),
      },
    });

    return NextResponse.json({
      success: true,
      verdict,
      riskScore,
      findingsCount: findings.length,
      findings: findings.map((f) => ({
        type: f.type,
        name: f.name,
        severity: f.severity,
        lineNumber: f.lineNumber,
        redactedToken: f.redactedToken,
        entropy: f.entropy,
        suggestedEnvKey: f.suggestedEnvKey,
      })),
      remediation,
    });
  } catch (err) {
    const error = err as Error;
    return NextResponse.json(
      { error: 'Internal Server Error', message: error.message },
      { status: 500 }
    );
  }
}
```

---

### 4. `app/api/keys/route.ts`

```typescript
// ============================================================================
// PROJECT AEGIS: DEVELOPER API KEY MANAGEMENT (CRUD)
// ============================================================================

import { NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { randomBytes, createHash } from 'crypto';
import { getServiceSupabase } from '@/lib/supabase/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * List active API keys for the authenticated session.
 */
export async function GET() {
  const session = await auth();
  if (!session || !session.userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const supabase = getServiceSupabase();
  const { data: keys, error } = await supabase
    .from('api_keys')
    .select('id, key_name, key_prefix, last_used_at, created_at')
    .eq('user_id', session.userId)
    .order('created_at', { ascending: false });

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ success: true, keys });
}

/**
 * Generate a new developer API key with one-time plaintext reveal.
 */
export async function POST(req: Request) {
  const session = await auth();
  if (!session || !session.userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const body = await req.json().catch(() => ({}));
  const keyName =
    typeof body.name === 'string' && body.name.trim().length > 0
      ? body.name.trim()
      : 'Default Pre-Commit Hook Key';

  // Format: aegis_live_ + 48 hex characters
  const rawToken = `aegis_live_${randomBytes(24).toString('hex')}`;
  const keyPrefix = rawToken.slice(0, 19); // aegis_live_ + first 8 characters
  const hashedKey = createHash('sha256').update(rawToken).digest('hex');

  const supabase = getServiceSupabase();
  const { data: inserted, error } = await supabase
    .from('api_keys')
    .insert({
      user_id: session.userId,
      key_name: keyName,
      key_prefix: keyPrefix,
      hashed_key: hashedKey,
    })
    .select('id, key_name, key_prefix, created_at')
    .single();

  if (error || !inserted) {
    return NextResponse.json({ error: error?.message || 'Database error' }, { status: 500 });
  }

  return NextResponse.json({
    success: true,
    key: {
      id: inserted.id,
      name: inserted.key_name,
      prefix: inserted.key_prefix,
      plaintextSecret: rawToken, // Display once in dashboard modal
      createdAt: inserted.created_at,
    },
  });
}

/**
 * Revoke an existing API key.
 */
export async function DELETE(req: Request) {
  const session = await auth();
  if (!session || !session.userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { searchParams } = new URL(req.url);
  const keyId = searchParams.get('id');

  if (!keyId) {
    return NextResponse.json({ error: 'Query param "id" is required.' }, { status: 400 });
  }

  const supabase = getServiceSupabase();
  const { error } = await supabase
    .from('api_keys')
    .delete()
    .eq('id', keyId)
    .eq('user_id', session.userId);

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ success: true, revokedId: keyId });
}
```

---

### 5. `cli/aegis.py`

```python
#!/usr/bin/env python3
"""
==============================================================================
PROJECT AEGIS: PRE-COMMIT SECURITY HOOK & DEVELOPER SECRET AUDITOR
Zero External Dependencies (Pure Python Standard Library)
Usage:
  python aegis.py             # Pre-commit staged diff inspection
  python aegis.py --fix       # Auto-extract leaked secrets to .env
==============================================================================
"""

import sys
import os
import re
import math
import json
import argparse
import subprocess
import urllib.request
import urllib.error

# ANSI Cyber-Luxe Color Codes
CYAN = "\033[96m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Core Local Signatures (Offline Fallback Engine)
LOCAL_PATTERNS = [
    (r"\b(AKIA[0-9A-Z]{16})\b", "AWS Access Key ID"),
    (r"\b(AIza[0-9A-Za-z\-_]{35})\b", "Google Cloud / Gemini Key"),
    (r"\b(ghp_[0-9a-zA-Z]{36})\b", "GitHub Classic PAT"),
    (r"\b(github_pat_[0-9a-zA-Z_]{82})\b", "GitHub Fine-Grained Token"),
    (r"\b(sk-[a-zA-Z0-9]{48})\b", "OpenAI Secret Key"),
    (r"\b(sk-proj-[a-zA-Z0-9_\-]{48,128})\b", "OpenAI Project Key"),
    (r"\b(sk_(?:live|test)_[0-9a-zA-Z]{24,99})\b", "Stripe API Key"),
    (r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b", "Slack Token"),
    (r"(-----BEGIN (?:RSA )?PRIVATE KEY-----)", "RSA Private Key"),
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy in bits per character."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)


def redact_token(token: str) -> str:
    """Redacts central characters of exposed secrets."""
    if len(token) <= 8:
        return "********"
    masked_length = min(len(token) - 8, 20)
    return f"{token[:4]}{'*' * masked_length}{token[-4:]}"


def get_staged_diff() -> str:
    """Extracts git diff for all currently staged files."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--unified=0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"{RED}[Aegis Error] Failed to execute git diff: {e}{RESET}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"{RED}[Aegis Error] 'git' binary not found in system PATH.{RESET}")
        sys.exit(1)


def parse_staged_lines(diff_text: str):
    """Parses git unified diff to locate staged file names and added lines."""
    staged_items = []
    current_file = None

    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            code_line = line[1:]
            staged_items.append((current_file, code_line))
    return staged_items


def run_local_audit(staged_items):
    """Offline Heuristic & Shannon Entropy Audit."""
    findings = []
    for filename, code_line in staged_items:
        # Check explicit patterns
        for pattern, name in LOCAL_PATTERNS:
            matches = re.findall(pattern, code_line)
            for match in matches:
                findings.append({
                    "file": filename,
                    "name": name,
                    "raw": match,
                    "redacted": redact_token(match),
                    "entropy": calculate_shannon_entropy(match)
                })

        # Check raw high-entropy string literals
        tokens = re.findall(r"[A-Za-z0-9_\-+=]{18,80}", code_line)
        for token in tokens:
            entropy = calculate_shannon_entropy(token)
            if entropy > 3.9 and len(set(token)) >= 10:
                if not any(f["raw"] == token for f in findings):
                    findings.append({
                        "file": filename,
                        "name": "High-Entropy Secret Literal",
                        "raw": token,
                        "redacted": redact_token(token),
                        "entropy": entropy
                    })
    return findings


def run_cloud_audit(api_key: str, endpoint: str, diff_text: str):
    """Transmits staged diff to Project Aegis GitShield Server for verification."""
    url = f"{endpoint.rstrip('/')}/api/scan/secret"
    payload = json.dumps({
        "filename": "staged_commit_diff",
        "content": diff_text
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "AegisCli/1.0"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                return data
    except urllib.error.HTTPError as e:
        print(f"{YELLOW}[Aegis Warning] Server audit returned HTTP {e.code}. Falling back to offline scan.{RESET}")
    except Exception as e:
        print(f"{YELLOW}[Aegis Warning] Cloud sync failed ({e}). Proceeding offline.{RESET}")
    return None


def apply_remediation(findings):
    """Extracts secrets to .env and replaces references in staged files."""
    if not findings:
        print(f"{GREEN}[Aegis] No secrets detected to remediate.{RESET}")
        return

    env_lines = []
    for i, finding in enumerate(findings):
        var_name = f"AEGIS_SECRET_{i+1}"
        env_lines.append(f"{var_name}=\"{finding['raw']}\"")

        # Replace in targeted file
        target_file = finding["file"]
        if target_file and os.path.exists(target_file):
            with open(target_file, "r", encoding="utf-8") as f:
                content = f.read()
            new_content = content.replace(finding["raw"], f"process.env.{var_name}")
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(new_content)
            subprocess.run(["git", "add", target_file])
            print(f"{CYAN}→ Sanitized {target_file} (replaced with process.env.{var_name}){RESET}")

    # Append to .env
    with open(".env", "a", encoding="utf-8") as f:
        f.write("\n# Auto-remediated by Project Aegis\n" + "\n".join(env_lines) + "\n")
    print(f"{GREEN}→ Appended {len(env_lines)} extracted secret(s) to .env{RESET}")

    # Ensure .env is in .gitignore
    gitignore_path = ".gitignore"
    needs_ignore = True
    if os.path.exists(gitignore_path):
        with open(gitignore_path, "r", encoding="utf-8") as f:
            if ".env" in f.read():
                needs_ignore = False

    if needs_ignore:
        with open(gitignore_path, "a", encoding="utf-8") as f:
            f.write("\n.env\n.env.local\n")
        subprocess.run(["git", "add", gitignore_path])
        print(f"{GREEN}→ Appended .env protection to .gitignore and staged.{RESET}")


def print_banner():
    print(f"{CYAN}{BOLD}")
    print("┌──────────────────────────────────────────────────────────────┐")
    print("│         🛡️  PROJECT AEGIS — GITSHIELD COMMIT DEFENSE          │")
    print("└──────────────────────────────────────────────────────────────┘")
    print(f"{RESET}")


def main():
    parser = argparse.ArgumentParser(description="Project Aegis GitShield Pre-Commit Guard")
    parser.add_argument("--fix", action="store_true", help="Auto-remediate secrets to .env")
    parser.add_argument("--endpoint", default=os.getenv("AEGIS_ENDPOINT", "http://localhost:3000"))
    args = parser.parse_args()

    diff = get_staged_diff()
    if not diff.strip():
        sys.exit(0)

    staged_items = parse_staged_lines(diff)
    local_findings = run_local_audit(staged_items)

    api_key = os.getenv("AEGIS_API_KEY")
    server_findings = None
    if api_key:
        server_findings = run_cloud_audit(api_key, args.endpoint, diff)

    # Prioritize server report if available, else local
    total_findings = local_findings
    if server_findings and "findings" in server_findings:
        total_findings = [
            {
                "file": "staged_file",
                "name": f["name"],
                "raw": f.get("rawToken", ""),
                "redacted": f["redactedToken"],
                "entropy": f.get("entropy", 0.0)
            }
            for f in server_findings["findings"]
        ]

    if not total_findings:
        sys.exit(0)

    print_banner()
    print(f"{RED}{BOLD}🚨 COMMIT BLOCKED: Unencrypted developer secrets detected!{RESET}\n")

    for finding in total_findings:
        print(f"  • {BOLD}Target File:{RESET} {finding.get('file', 'unknown')}")
        print(f"    {YELLOW}Signature:{RESET}   {finding['name']}")
        print(f"    {CYAN}Token Redacted:{RESET} {finding['redacted']}")
        if finding.get("entropy"):
            print(f"    {CYAN}Entropy:{RESET}        {finding['entropy']} bits/char")
        print()

    if args.fix:
        print(f"{CYAN}🔧 Applying automatic GitShield remediation patch...{RESET}")
        apply_remediation(local_findings)
        print(f"\n{GREEN}{BOLD}✨ Secrets extracted successfully. Re-run 'git commit' to complete.{RESET}\n")
        sys.exit(0)
    else:
        print(f"{YELLOW}Remediation options:{RESET}")
        print(f"  1. Run {BOLD}python aegis.py --fix{RESET} to extract secrets into .env automatically.")
        print(f"  2. Unstage changes manually: {BOLD}git reset HEAD <file>{RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
```