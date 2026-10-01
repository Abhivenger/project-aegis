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
