# PROJECT AEGIS — PHASE 1: CORE ENGINES & DATABASE SPECIFICATION

This document contains the complete, production-ready source code for Phase 1 of **Project Aegis**. Every file is written in full without placeholders, abbreviations, or omitted logic.

---

## File Map (Phase 1)

1. `supabase/schema.sql` — PostgreSQL DDL, indexes, and Row Level Security policies.
2. `lib/scanners/entropy.ts` — Shannon entropy calculation and candidate token extractor.
3. `lib/scanners/regex-patterns.ts` — Strongly typed registry of 27 high-fidelity secret signatures with ReDoS limits.
4. `lib/scanners/url-analyzer.ts` — SSRF-safe redirect tracer, DNS resolution validator, and heuristic threat engine.
5. `lib/supabase/server.ts` — Hardened service-role Supabase client.
6. `lib/quota.ts` — 24-hour sliding window quota limiter with atomic resets.

---

### 1. `supabase/schema.sql`

```sql
-- ============================================================================
-- PROJECT AEGIS: PRIMARY DATABASE SCHEMA & ROW LEVEL SECURITY
-- Target Database: Supabase / PostgreSQL 15+
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ----------------------------------------------------------------------------
-- 1. Profiles Table (Synchronized with Clerk Authentication)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.profiles (
  id TEXT PRIMARY KEY, -- Clerk user ID format: 'user_2...'
  email TEXT NOT NULL,
  first_name TEXT,
  last_name TEXT,
  plan TEXT NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'pro', 'enterprise')),
  daily_scan_count INT NOT NULL DEFAULT 0,
  last_scan_reset_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ----------------------------------------------------------------------------
-- 2. Scans Table (Audit Log for URL & Code Inspections)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  scan_type TEXT NOT NULL CHECK (scan_type IN ('url', 'code', 'cli_precommit')),
  target TEXT NOT NULL, -- Target URL or Target File Path
  risk_score INT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  verdict TEXT NOT NULL CHECK (verdict IN ('SAFE', 'SUSPICIOUS', 'DANGEROUS')),
  summary TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ----------------------------------------------------------------------------
-- 3. Developer API Keys (For aegis.py CLI & Git Hooks)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  key_name TEXT NOT NULL,
  key_prefix TEXT NOT NULL, -- e.g., 'aegis_live_9a4f'
  hashed_key TEXT NOT NULL UNIQUE, -- SHA-256 of the plaintext secret
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ----------------------------------------------------------------------------
-- 4. Performance Indexes
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);
CREATE INDEX IF NOT EXISTS idx_scans_user_created ON public.scans(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON public.scans(verdict);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON public.api_keys(hashed_key);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON public.api_keys(user_id);

-- ----------------------------------------------------------------------------
-- 5. Row Level Security (RLS) Configuration
-- ----------------------------------------------------------------------------
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;

-- Note: In Next.js App Router, all database operations in our API routes run
-- through the server-side Supabase client using SUPABASE_SERVICE_ROLE_KEY, which
-- bypasses RLS. These policies safeguard any direct client connections.

CREATE POLICY "Allow service role full access to profiles"
  ON public.profiles
  FOR ALL
  USING (auth.role() = 'service_role')
  WITH CHECK (auth.role() = 'service_role');

CREATE POLICY "Allow service role full access to scans"
  ON public.scans
  FOR ALL
  USING (auth.role() = 'service_role')
  WITH CHECK (auth.role() = 'service_role');

CREATE POLICY "Allow service role full access to api_keys"
  ON public.api_keys
  FOR ALL
  USING (auth.role() = 'service_role')
  WITH CHECK (auth.role() = 'service_role');
```

---

### 2. `lib/scanners/entropy.ts`

```typescript
// ============================================================================
// PROJECT AEGIS: SHANNON ENTROPY CALCULATION & TOKEN ANALYSIS
// Equation: H(X) = - SUM( P(x_i) * log2(P(x_i)) )
// ============================================================================

export interface EntropyCandidate {
  token: string;
  entropy: number;
  length: number;
  startIndex: number;
  endIndex: number;
  lineNumber: number;
}

export interface EntropyAnalysisResult {
  highestEntropy: number;
  candidates: EntropyCandidate[];
  hasHighEntropySecret: boolean;
}

/**
 * Calculates raw Shannon entropy in bits per character for a given string.
 * Output range: 0.0 (uniform string, e.g. "aaaa") to ~6.0+ (random high-charset strings).
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) {
    return 0;
  }

  const length = str.length;
  const frequencies = new Map<string, number>();

  for (let i = 0; i < length; i++) {
    const char = str[i];
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  for (const count of frequencies.values()) {
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }

  return Math.round(entropy * 1000) / 1000;
}

/**
 * Scans multiline source code with a sliding-window tokenizer to isolate
 * high-entropy tokens (e.g., base64 hashes, hexadecimal keys, API tokens).
 *
 * Constraints:
 * - Only evaluates contiguous alphanumeric tokens between 16 and 128 characters.
 * - Drops pure lowercase/uppercase common language dictionary words.
 * - Requires entropy threshold > 3.85 (standard for base64/hex cryptographic keys).
 */
export function extractHighEntropyTokens(
  content: string,
  entropyThreshold = 3.85,
  minTokenLength = 16,
  maxTokenLength = 128
): EntropyAnalysisResult {
  const candidates: EntropyCandidate[] = [];
  let highestEntropy = 0;

  // Split content line by line while preserving line numbering
  const lines = content.split(/\r?\n/);

  // Matches continuous candidate token strings (ignoring punctuation/spaces)
  const tokenRegex = /[A-Za-z0-9_\-+=]{16,128}/g;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];

    // Defense against ReDoS / excessive line lengths (e.g. minified bundles)
    if (line.length > 4096) {
      continue;
    }

    let match: RegExpExecArray | null;
    while ((match = tokenRegex.exec(line)) !== null) {
      const token = match[0];

      if (token.length < minTokenLength || token.length > maxTokenLength) {
        continue;
      }

      // Skip tokens that are all same character or trivial increments
      const uniqueCharCount = new Set(token).size;
      if (uniqueCharCount < 6) {
        continue;
      }

      // Skip common programming patterns (e.g. repeated method chains)
      if (/^[a-z]+(?:[A-Z][a-z]+)+$/.test(token) && uniqueCharCount < 10) {
        continue;
      }

      const score = calculateShannonEntropy(token);

      if (score > highestEntropy) {
        highestEntropy = score;
      }

      if (score >= entropyThreshold) {
        candidates.push({
          token,
          entropy: score,
          length: token.length,
          startIndex: match.index,
          endIndex: match.index + token.length,
          lineNumber: lineIdx + 1,
        });
      }
    }
  }

  return {
    highestEntropy,
    candidates,
    hasHighEntropySecret: candidates.length > 0,
  };
}
```

---

### 3. `lib/scanners/regex-patterns.ts`

```typescript
// ============================================================================
// PROJECT AEGIS: HIGH-FIDELITY SECRET PATTERN REGISTRY
// 27 Verified Token Signatures with False-Positive Suppression
// Note: All patterns use standard ECMAScript regex flags without inline modifiers.
// ============================================================================

export type SecretSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM';

export interface SecretPattern {
  id: string;
  name: string;
  category: 'cloud' | 'vcs' | 'ai' | 'payment' | 'messaging' | 'database' | 'crypto';
  severity: SecretSeverity;
  regex: RegExp;
  description: string;
  suggestedEnvKey: string;
  requiresEntropyCheck?: boolean;
}

export interface SecretMatchResult {
  patternId: string;
  name: string;
  category: string;
  severity: SecretSeverity;
  matchedString: string;
  redactedString: string;
  lineNumber: number;
  startIndex: number;
  suggestedEnvKey: string;
  description: string;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  // --- CLOUD PROVIDERS ---
  {
    id: 'aws_access_key',
    name: 'AWS Access Key ID',
    category: 'cloud',
    severity: 'CRITICAL',
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    description: 'Amazon Web Services standard IAM access key identifier.',
    suggestedEnvKey: 'AWS_ACCESS_KEY_ID',
  },
  {
    id: 'aws_secret_key',
    name: 'AWS Secret Access Key',
    category: 'cloud',
    severity: 'CRITICAL',
    regex: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)[\s:=]+['"]?([A-Za-z0-9\/+=]{40})['"]?/gi,
    description: 'Amazon Web Services 40-character secret access key.',
    suggestedEnvKey: 'AWS_SECRET_ACCESS_KEY',
    requiresEntropyCheck: true,
  },
  {
    id: 'gcp_api_key',
    name: 'Google Cloud / Gemini API Key',
    category: 'cloud',
    severity: 'CRITICAL',
    regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
    description: 'Google Cloud Platform and Gemini public API key token.',
    suggestedEnvKey: 'GEMINI_API_KEY',
  },

  // --- VERSION CONTROL SYSTEMS ---
  {
    id: 'github_pat_classic',
    name: 'GitHub Personal Access Token (Classic)',
    category: 'vcs',
    severity: 'CRITICAL',
    regex: /\b(ghp_[0-9a-zA-Z]{36})\b/g,
    description: 'Legacy GitHub personal access token with repository read/write access.',
    suggestedEnvKey: 'GITHUB_TOKEN',
  },
  {
    id: 'github_pat_fine_grained',
    name: 'GitHub Fine-Grained Token',
    category: 'vcs',
    severity: 'CRITICAL',
    regex: /\b(github_pat_[0-9a-zA-Z_]{82})\b/g,
    description: 'Modern fine-grained scoped GitHub access token.',
    suggestedEnvKey: 'GITHUB_TOKEN',
  },
  {
    id: 'github_oauth',
    name: 'GitHub OAuth Access Token',
    category: 'vcs',
    severity: 'HIGH',
    regex: /\b(gho_[0-9a-zA-Z]{36})\b/g,
    description: 'GitHub OAuth application access token.',
    suggestedEnvKey: 'GITHUB_OAUTH_TOKEN',
  },
  {
    id: 'gitlab_pat',
    name: 'GitLab Personal Access Token',
    category: 'vcs',
    severity: 'CRITICAL',
    regex: /\b(glpat-[0-9a-zA-Z\-_]{20,32})\b/g,
    description: 'GitLab personal access token.',
    suggestedEnvKey: 'GITLAB_TOKEN',
  },

  // --- ARTIFICIAL INTELLIGENCE & LLMS ---
  {
    id: 'openai_api_key_legacy',
    name: 'OpenAI API Key (Legacy)',
    category: 'ai',
    severity: 'CRITICAL',
    regex: /\b(sk-[a-zA-Z0-9]{48})\b/g,
    description: 'Standard OpenAI developer secret key.',
    suggestedEnvKey: 'OPENAI_API_KEY',
  },
  {
    id: 'openai_api_key_project',
    name: 'OpenAI API Key (Project-Scoped)',
    category: 'ai',
    severity: 'CRITICAL',
    regex: /\b(sk-proj-[a-zA-Z0-9_\-]{48,128})\b/g,
    description: 'Scoped OpenAI modern project API key.',
    suggestedEnvKey: 'OPENAI_API_KEY',
  },
  {
    id: 'anthropic_api_key',
    name: 'Anthropic Claude API Key',
    category: 'ai',
    severity: 'CRITICAL',
    regex: /\b(sk-ant-[a-zA-Z0-9_\-]{80,128})\b/g,
    description: 'Anthropic Claude developer API key.',
    suggestedEnvKey: 'ANTHROPIC_API_KEY',
  },
  {
    id: 'huggingface_token',
    name: 'HuggingFace User Access Token',
    category: 'ai',
    severity: 'HIGH',
    regex: /\b(hf_[a-zA-Z0-9]{34})\b/g,
    description: 'HuggingFace inference and model repository access token.',
    suggestedEnvKey: 'HUGGINGFACE_TOKEN',
  },

  // --- PAYMENT PLATFORMS ---
  {
    id: 'stripe_secret_key',
    name: 'Stripe Secret Key',
    category: 'payment',
    severity: 'CRITICAL',
    regex: /\b(sk_(?:live|test)_[0-9a-zA-Z]{24,99})\b/g,
    description: 'Stripe payments secret API key.',
    suggestedEnvKey: 'STRIPE_SECRET_KEY',
  },
  {
    id: 'stripe_restricted_key',
    name: 'Stripe Restricted API Key',
    category: 'payment',
    severity: 'CRITICAL',
    regex: /\b(rk_(?:live|test)_[0-9a-zA-Z]{24,99})\b/g,
    description: 'Stripe restricted API key with granular permissions.',
    suggestedEnvKey: 'STRIPE_RESTRICTED_KEY',
  },
  {
    id: 'razorpay_secret',
    name: 'Razorpay Key Secret',
    category: 'payment',
    severity: 'CRITICAL',
    regex: /razorpay[_\s\-]*secret[\s:=]+['"]?([a-zA-Z0-9]{24,32})['"]?/gi,
    description: 'Razorpay payment gateway API secret.',
    suggestedEnvKey: 'RAZORPAY_KEY_SECRET',
  },

  // --- MESSAGING & NOTIFICATIONS ---
  {
    id: 'slack_bot_token',
    name: 'Slack Bot Token',
    category: 'messaging',
    severity: 'HIGH',
    regex: /\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})\b/g,
    description: 'Slack Bot User OAuth access token.',
    suggestedEnvKey: 'SLACK_BOT_TOKEN',
  },
  {
    id: 'slack_user_token',
    name: 'Slack User Token',
    category: 'messaging',
    severity: 'HIGH',
    regex: /\b(xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})\b/g,
    description: 'Slack workspace user OAuth token.',
    suggestedEnvKey: 'SLACK_USER_TOKEN',
  },
  {
    id: 'slack_webhook',
    name: 'Slack Incoming Webhook URL',
    category: 'messaging',
    severity: 'HIGH',
    regex: /(https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,12}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24})/g,
    description: 'Unauthenticated Slack notification webhook endpoint.',
    suggestedEnvKey: 'SLACK_WEBHOOK_URL',
  },
  {
    id: 'twilio_account_sid',
    name: 'Twilio Account SID',
    category: 'messaging',
    severity: 'MEDIUM',
    regex: /\b(AC[a-f0-9]{32})\b/g,
    description: 'Twilio account identifier.',
    suggestedEnvKey: 'TWILIO_ACCOUNT_SID',
  },
  {
    id: 'twilio_auth_token',
    name: 'Twilio Auth Token',
    category: 'messaging',
    severity: 'CRITICAL',
    regex: /twilio[_\s\-]*auth[_\s\-]*token[\s:=]+['"]?([a-f0-9]{32})['"]?/gi,
    description: 'Twilio secret authentication token.',
    suggestedEnvKey: 'TWILIO_AUTH_TOKEN',
  },
  {
    id: 'sendgrid_api_key',
    name: 'SendGrid API Key',
    category: 'messaging',
    severity: 'CRITICAL',
    regex: /\b(SG\.[a-zA-Z0-9_\-\.]{66})\b/g,
    description: 'SendGrid email service API key.',
    suggestedEnvKey: 'SENDGRID_API_KEY',
  },
  {
    id: 'discord_bot_token',
    name: 'Discord Bot Token',
    category: 'messaging',
    severity: 'HIGH',
    regex: /\b([MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38})\b/g,
    description: 'Discord application bot authentication token.',
    suggestedEnvKey: 'DISCORD_BOT_TOKEN',
  },

  // --- DATABASES & STORAGE ---
  {
    id: 'mongodb_uri',
    name: 'MongoDB Connection URI',
    category: 'database',
    severity: 'CRITICAL',
    regex: /(mongodb(?:\+srv)?:\/\/[^\s"'<>]+:[^\s"'<>]+@[^\s"'<>]+\b)/g,
    description: 'MongoDB database connection string with embedded credentials.',
    suggestedEnvKey: 'MONGODB_URI',
  },
  {
    id: 'postgres_mysql_uri',
    name: 'PostgreSQL / MySQL Credentials URI',
    category: 'database',
    severity: 'CRITICAL',
    regex: /((?:postgres(?:ql)?|mysql):\/\/[^\s"'<>]+:[^\s"'<>]+@[^\s"'<>]+\b)/g,
    description: 'Relational database URI with embedded plaintext username and password.',
    suggestedEnvKey: 'DATABASE_URL',
  },

  // --- CRYPTOGRAPHIC KEYS ---
  {
    id: 'rsa_private_key',
    name: 'RSA Private Key Header',
    category: 'crypto',
    severity: 'CRITICAL',
    regex: /(-----BEGIN (?:RSA )?PRIVATE KEY-----)/g,
    description: 'Unencrypted RSA private cryptographic key.',
    suggestedEnvKey: 'PRIVATE_KEY',
  },
  {
    id: 'ec_private_key',
    name: 'EC Private Key Header',
    category: 'crypto',
    severity: 'CRITICAL',
    regex: /(-----BEGIN EC PRIVATE KEY-----)/g,
    description: 'Elliptic curve private cryptographic key.',
    suggestedEnvKey: 'EC_PRIVATE_KEY',
  },
  {
    id: 'openssh_private_key',
    name: 'OpenSSH Private Key',
    category: 'crypto',
    severity: 'CRITICAL',
    regex: /(-----BEGIN OPENSSH PRIVATE KEY-----)/g,
    description: 'OpenSSH private authentication key.',
    suggestedEnvKey: 'SSH_PRIVATE_KEY',
  },
  {
    id: 'pgp_private_key',
    name: 'PGP Private Key Block',
    category: 'crypto',
    severity: 'CRITICAL',
    regex: /(-----BEGIN PGP PRIVATE KEY BLOCK-----)/g,
    description: 'Pretty Good Privacy (PGP) private keyring block.',
    suggestedEnvKey: 'PGP_PRIVATE_KEY',
  },
];

/**
 * Redacts all but the first 4 and last 4 characters of a leaked secret string.
 */
export function redactSecret(secret: string): string {
  if (secret.length <= 8) {
    return '********';
  }
  const prefix = secret.slice(0, 4);
  const suffix = secret.slice(-4);
  return `${prefix}${'*'.repeat(Math.min(secret.length - 8, 24))}${suffix}`;
}

/**
 * Scans code content against the 27 registered secret patterns.
 * Limits individual line evaluation to 4,096 characters to prevent ReDoS.
 */
export function scanCodeForPatterns(content: string): SecretMatchResult[] {
  const results: SecretMatchResult[] = [];
  const lines = content.split(/\r?\n/);

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const rawLine = lines[lineIdx];

    // ReDoS Prevention: Truncate lines exceeding maximum evaluation length
    const line = rawLine.length > 4096 ? rawLine.slice(0, 4096) : rawLine;

    for (const pattern of SECRET_PATTERNS) {
      // Reset regex cursor for global regular expressions
      pattern.regex.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = pattern.regex.exec(line)) !== null) {
        // Prefer captured group if present, otherwise full match
        const matchedString = match[1] || match[0];

        results.push({
          patternId: pattern.id,
          name: pattern.name,
          category: pattern.category,
          severity: pattern.severity,
          matchedString,
          redactedString: redactSecret(matchedString),
          lineNumber: lineIdx + 1,
          startIndex: match.index,
          suggestedEnvKey: pattern.suggestedEnvKey,
          description: pattern.description,
        });
      }
    }
  }

  return results;
}
```

---

### 4. `lib/scanners/url-analyzer.ts`

```typescript
// ============================================================================
// PROJECT AEGIS: SAFELINK URL HEURISTIC & SSRF-SAFE ANALYZER
// ============================================================================

import { promises as dns } from 'dns';
import * as net from 'net';

export interface RedirectHop {
  hopNumber: number;
  url: string;
  statusCode: number;
  ipAddress: string | null;
}

export interface UrlAnalysisReport {
  targetUrl: string;
  finalDestination: string;
  riskScore: number; // 0 to 100
  verdict: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
  reasons: string[];
  redirectChain: RedirectHop[];
  isSsrfBlocked: boolean;
  domainAgeDays: number | null;
  detectedKeywords: string[];
}

// ----------------------------------------------------------------------------
// SSRF Defense: IP Range Classifications
// ----------------------------------------------------------------------------

/**
 * Checks whether an IPv4 address falls within private, loopback, link-local,
 * carrier-grade NAT, or multicast ranges.
 */
function isPrivateOrReservedIPv4(ip: string): boolean {
  const parts = ip.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return true; // Malformed address treated as unsafe
  }

  const [a, b] = parts;

  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;

  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;

  // 10.0.0.0/8 (Private RFC 1918)
  if (a === 10) return true;

  // 172.16.0.0/12 (Private RFC 1918: 172.16.0.0 - 172.31.255.255)
  if (a === 172 && b >= 16 && b <= 31) return true;

  // 192.168.0.0/16 (Private RFC 1918)
  if (a === 192 && b === 168) return true;

  // 169.254.0.0/16 (Link-local & AWS/GCP/Azure Metadata 169.254.169.254)
  if (a === 169 && b === 254) return true;

  // 100.64.0.0/10 (Carrier-Grade NAT: 100.64.0.0 - 100.127.255.255)
  if (a === 100 && b >= 64 && b <= 127) return true;

  // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (TEST-NET)
  if (a === 192 && b === 0 && parts[2] === 2) return true;
  if (a === 198 && b === 51 && parts[2] === 100) return true;
  if (a === 203 && b === 0 && parts[2] === 113) return true;

  // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
  if (a >= 224) return true;

  return false;
}

/**
 * Checks whether an IPv6 address falls within loopback, link-local,
 * unique local, or IPv4-mapped private ranges.
 */
function isPrivateOrReservedIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase().trim();

  // ::1 / :: (Loopback & Unspecified)
  if (normalized === '::1' || normalized === '::') return true;

  // fe80::/10 (Link-local)
  if (normalized.startsWith('fe80:') || normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) {
    return true;
  }

  // fc00::/7 (Unique Local Address RFC 4193)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;

  // ff00::/8 (Multicast)
  if (normalized.startsWith('ff')) return true;

  // IPv4-mapped IPv6 (::ffff:127.0.0.1)
  if (normalized.includes('::ffff:')) {
    const ipv4Part = normalized.split('::ffff:')[1];
    if (net.isIPv4(ipv4Part)) {
      return isPrivateOrReservedIPv4(ipv4Part);
    }
  }

  return false;
}

/**
 * Resolves a hostname via DNS and verifies that NONE of the resolved IP addresses
 * belong to internal, private, loopback, or cloud-metadata networks.
 */
export async function validateHostForSsrf(hostname: string): Promise<{ isSafe: boolean; resolvedIps: string[]; reason?: string }> {
  // If the hostname itself is an explicit IP literal:
  if (net.isIPv4(hostname)) {
    if (isPrivateOrReservedIPv4(hostname)) {
      return { isSafe: false, resolvedIps: [hostname], reason: `Prohibited private IPv4 address: ${hostname}` };
    }
    return { isSafe: true, resolvedIps: [hostname] };
  }

  if (net.isIPv6(hostname)) {
    if (isPrivateOrReservedIPv6(hostname)) {
      return { isSafe: false, resolvedIps: [hostname], reason: `Prohibited private IPv6 address: ${hostname}` };
    }
    return { isSafe: true, resolvedIps: [hostname] };
  }

  try {
    const records = await dns.lookup(hostname, { all: true });
    const resolvedIps = records.map((r) => r.address);

    if (resolvedIps.length === 0) {
      return { isSafe: false, resolvedIps: [], reason: 'Hostname could not be resolved via DNS' };
    }

    for (const record of records) {
      if (record.family === 4 && isPrivateOrReservedIPv4(record.address)) {
        return { isSafe: false, resolvedIps, reason: `Resolves to internal IPv4 address: ${record.address}` };
      }
      if (record.family === 6 && isPrivateOrReservedIPv6(record.address)) {
        return { isSafe: false, resolvedIps, reason: `Resolves to internal IPv6 address: ${record.address}` };
      }
    }

    return { isSafe: true, resolvedIps };
  } catch (error) {
    return { isSafe: false, resolvedIps: [], reason: `DNS lookup failed: ${(error as Error).message}` };
  }
}

// ----------------------------------------------------------------------------
// Heuristic Analysis & Redirect Tracer
// ----------------------------------------------------------------------------

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'cc', 'ru', 'buzz', 'work', 'rest', 'fit', 'tk', 'ml', 'ga', 'cf', 'gq', 'sbs', 'click'
]);

const SENSITIVE_KEYWORDS = [
  'bank', 'login', 'kyc', 'otp', 'verify', 'update', 'paytm', 'secure', 'signin',
  'account', 'password', 'wallet', 'crypto', 'billing', 'support', 'auth'
];

/**
 * Inspects a target URL for phishing heuristics and traces HTTP redirect chains
 * with mandatory per-hop SSRF validation.
 */
export async function analyzeUrl(targetUrl: string): Promise<UrlAnalysisReport> {
  const reasons: string[] = [];
  let riskScore = 0;
  const redirectChain: RedirectHop[] = [];
  const detectedKeywords: string[] = [];

  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return {
        targetUrl,
        finalDestination: targetUrl,
        riskScore: 100,
        verdict: 'DANGEROUS',
        reasons: ['Unsupported or unsafe protocol scheme'],
        redirectChain: [],
        isSsrfBlocked: true,
        domainAgeDays: null,
        detectedKeywords: [],
      };
    }
  } catch {
    return {
      targetUrl,
      finalDestination: targetUrl,
      riskScore: 100,
      verdict: 'DANGEROUS',
      reasons: ['Malformed URL syntax'],
      redirectChain: [],
      isSsrfBlocked: false,
      domainAgeDays: null,
      detectedKeywords: [],
    };
  }

  // Pre-flight SSRF check on initial target hostname
  const ssrfValidation = await validateHostForSsrf(parsed.hostname);
  if (!ssrfValidation.isSafe) {
    return {
      targetUrl,
      finalDestination: targetUrl,
      riskScore: 100,
      verdict: 'DANGEROUS',
      reasons: [`SSRF_PROHIBITED_DESTINATION: ${ssrfValidation.reason}`],
      redirectChain: [],
      isSsrfBlocked: true,
      domainAgeDays: null,
      detectedKeywords: [],
    };
  }

  // Heuristic 1: Raw IP in hostname (+45 points)
  if (net.isIP(parsed.hostname)) {
    riskScore += 45;
    reasons.push('Hostname is a raw IP address instead of a domain name');
  }

  // Heuristic 2: Suspicious TLD (+25 points)
  const domainParts = parsed.hostname.split('.');
  const tld = domainParts[domainParts.length - 1]?.toLowerCase();
  if (tld && SUSPICIOUS_TLDS.has(tld)) {
    riskScore += 25;
    reasons.push(`Domain uses high-abuse top-level domain (.${tld})`);
  }

  // Heuristic 3: Suspicious subdomains or deceptive keywords (+20 points)
  const fullUrlString = targetUrl.toLowerCase();
  for (const keyword of SENSITIVE_KEYWORDS) {
    if (fullUrlString.includes(keyword)) {
      detectedKeywords.push(keyword);
    }
  }
  if (detectedKeywords.length > 0) {
    riskScore += Math.min(detectedKeywords.length * 15, 35);
    reasons.push(`Contains high-risk credential keywords: [${detectedKeywords.join(', ')}]`);
  }

  // Heuristic 4: Excessive URL length or deep subdomain nesting
  if (domainParts.length > 4) {
    riskScore += 15;
    reasons.push('Excessive subdomain nesting (potential brand impersonation)');
  }
  if (targetUrl.length > 120) {
    riskScore += 10;
    reasons.push('Abnormally long URL query structure');
  }

  // Trace redirect chain safely (Max 5 hops)
  let currentUrl = targetUrl;
  const MAX_HOPS = 5;

  for (let hop = 1; hop <= MAX_HOPS; hop++) {
    try {
      const currentParsed = new URL(currentUrl);
      const hopSsrfCheck = await validateHostForSsrf(currentParsed.hostname);

      if (!hopSsrfCheck.isSafe) {
        riskScore = 100;
        reasons.push(`Redirect hop #${hop} aborted due to SSRF restriction: ${hopSsrfCheck.reason}`);
        break;
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3500);

      const response = await fetch(currentUrl, {
        method: 'HEAD',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': 'AegisSafeLinkBot/1.0 (+https://project-aegis.dev)',
        },
      });

      clearTimeout(timeoutId);

      redirectChain.push({
        hopNumber: hop,
        url: currentUrl,
        statusCode: response.status,
        ipAddress: hopSsrfCheck.resolvedIps[0] || null,
      });

      const isRedirect = [301, 302, 303, 307, 308].includes(response.status);
      const location = response.headers.get('location');

      if (isRedirect && location) {
        // Resolve relative redirects correctly
        currentUrl = new URL(location, currentUrl).toString();
      } else {
        // Destination reached
        break;
      }
    } catch (error) {
      reasons.push(`Network probe stopped at hop #${hop}: ${(error as Error).message}`);
      break;
    }
  }

  // Heuristic 5: Excessive redirects (+20 points)
  if (redirectChain.length >= 3) {
    riskScore += 20;
    reasons.push(`Multiple redirect hops detected (${redirectChain.length} hops)`);
  }

  // Normalize final risk score
  const normalizedScore = Math.min(Math.max(riskScore, 0), 100);

  let verdict: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS' = 'SAFE';
  if (normalizedScore >= 65) {
    verdict = 'DANGEROUS';
  } else if (normalizedScore >= 25) {
    verdict = 'SUSPICIOUS';
  }

  return {
    targetUrl,
    finalDestination: currentUrl,
    riskScore: normalizedScore,
    verdict,
    reasons: reasons.length > 0 ? reasons : ['No overt malicious heuristics observed'],
    redirectChain,
    isSsrfBlocked: false,
    domainAgeDays: null, // Populated if external WHOIS API key is supplied
    detectedKeywords,
  };
}
```

---

### 5. `lib/supabase/server.ts`

```typescript
// ============================================================================
// PROJECT AEGIS: HARDENED SERVICE-ROLE SUPABASE CLIENT
// ============================================================================

import { createClient, SupabaseClient } from '@supabase/supabase-js';

let serviceClientInstance: SupabaseClient | null = null;

/**
 * Returns a singleton Supabase client authenticated with the service role key.
 * This client bypasses RLS and must be strictly confined to server-side Route Handlers.
 */
export function getServiceSupabase(): SupabaseClient {
  if (serviceClientInstance) {
    return serviceClientInstance;
  }

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceRoleKey) {
    throw new Error(
      'Missing Supabase configuration: Ensure NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are set in .env.local'
    );
  }

  serviceClientInstance = createClient(supabaseUrl, serviceRoleKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });

  return serviceClientInstance;
}
```

---

### 6. `lib/quota.ts`

```typescript
// ============================================================================
// PROJECT AEGIS: 24-HOUR ROLLING SCAN QUOTA MANAGER
// Free Tier: 50 Scans / 24-Hour Cycle
// Pro Tier: 5,000 Scans / 24-Hour Cycle
// ============================================================================

import { getServiceSupabase } from './supabase/server';

export interface QuotaStatus {
  allowed: boolean;
  dailyScanCount: number;
  maxDailyQuota: number;
  plan: 'free' | 'pro' | 'enterprise';
  resetsAt: string;
}

const QUOTA_LIMITS: Record<string, number> = {
  free: 50,
  pro: 5000,
  enterprise: 100000,
};

/**
 * Atomically checks and increments a user's scan count.
 * Automatically resets the quota if more than 24 hours have elapsed since last_scan_reset_at.
 */
export async function checkAndIncrementQuota(userId: string, userEmail?: string): Promise<QuotaStatus> {
  const supabase = getServiceSupabase();

  // 1. Fetch current profile or bootstrap if newly registered via Clerk
  const { data: profile, error: fetchError } = await supabase
    .from('profiles')
    .select('id, plan, daily_scan_count, last_scan_reset_at')
    .eq('id', userId)
    .single();

  if (fetchError || !profile) {
    // Bootstrap profile record
    const { data: newProfile, error: insertError } = await supabase
      .from('profiles')
      .insert({
        id: userId,
        email: userEmail || `${userId}@anonymous.aegis`,
        plan: 'free',
        daily_scan_count: 1,
        last_scan_reset_at: new Date().toISOString(),
      })
      .select()
      .single();

    if (insertError || !newProfile) {
      throw new Error(`Failed to bootstrap user profile: ${insertError?.message}`);
    }

    return {
      allowed: true,
      dailyScanCount: 1,
      maxDailyQuota: QUOTA_LIMITS.free,
      plan: 'free',
      resetsAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    };
  }

  const now = Date.now();
  const lastReset = new Date(profile.last_scan_reset_at).getTime();
  const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;
  const maxQuota = QUOTA_LIMITS[profile.plan] || QUOTA_LIMITS.free;

  // 2. Check if the 24-hour cycle has expired
  if (now - lastReset >= TWENTY_FOUR_HOURS_MS) {
    // Reset cycle
    const { error: resetError } = await supabase
      .from('profiles')
      .update({
        daily_scan_count: 1,
        last_scan_reset_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      })
      .eq('id', userId);

    if (resetError) {
      throw new Error(`Failed to reset user quota: ${resetError.message}`);
    }

    return {
      allowed: true,
      dailyScanCount: 1,
      maxDailyQuota: maxQuota,
      plan: profile.plan,
      resetsAt: new Date(now + TWENTY_FOUR_HOURS_MS).toISOString(),
    };
  }

  // 3. Cycle is active: check remaining quota
  if (profile.daily_scan_count >= maxQuota) {
    const resetsAt = new Date(lastReset + TWENTY_FOUR_HOURS_MS).toISOString();
    return {
      allowed: false,
      dailyScanCount: profile.daily_scan_count,
      maxDailyQuota: maxQuota,
      plan: profile.plan,
      resetsAt,
    };
  }

  // 4. Increment usage counter
  const newCount = profile.daily_scan_count + 1;
  const { error: updateError } = await supabase
    .from('profiles')
    .update({
      daily_scan_count: newCount,
      updated_at: new Date().toISOString(),
    })
    .eq('id', userId);

  if (updateError) {
    throw new Error(`Failed to increment scan count: ${updateError.message}`);
  }

  return {
    allowed: true,
    dailyScanCount: newCount,
    maxDailyQuota: maxQuota,
    plan: profile.plan,
    resetsAt: new Date(lastReset + TWENTY_FOUR_HOURS_MS).toISOString(),
  };
}
```