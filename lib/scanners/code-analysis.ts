import {
  GENERIC_SECRET_MIN_ENTROPY,
  extractHighEntropyTokens,
  isLikelySecretLiteral,
} from "./entropy";
import { redactSecret, scanCodeForPatterns } from "./regex-patterns";

interface SecretFinding {
  type: "KNOWN_SIGNATURE" | "HIGH_ENTROPY";
  name: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  lineNumber: number;
  redactedToken: string;
  rawToken: string;
  suggestedEnvKey: string;
  entropy?: number;
}

/** Documentation env templates hold placeholders, not deployable credentials. */
const PLACEHOLDER_ENV_FILE = /(^|\/)\.env\.(?:example|sample|template)$/i;

/** Vendor key prefixes that are live-shaped even when found in a template. */
const STRICT_LIVE_SECRET = /^(?:sk_live_|AKIA|ghp_)/;

const PRIVATE_KEY_HEADER = /BEGIN [A-Z ]*PRIVATE KEY/;

/** `scheme://localhost/...` or `scheme://127.0.0.1/...` with no `user:pass@`. */
const LOCALHOST_URL_WITHOUT_CREDENTIALS =
  /[a-z][a-z0-9+.-]*:\/\/(?:localhost|127\.0\.0\.1)(?:[/:?#]|\s|$)/i;

export function isPlaceholderEnvFile(filename: string): boolean {
  return PLACEHOLDER_ENV_FILE.test(filename);
}

function localhostConfigLines(content: string): Set<number> {
  const lines = new Set<number>();
  content.split(/\r?\n/).forEach((line, index) => {
    if (LOCALHOST_URL_WITHOUT_CREDENTIALS.test(line)) {
      lines.add(index + 1);
    }
  });
  return lines;
}

export function analyzeCode(content: string, filename = "sample.ts") {
  const placeholderEnv = isPlaceholderEnvFile(filename);
  const findings: SecretFinding[] = scanCodeForPatterns(content)
    .filter(
      (match) =>
        !placeholderEnv ||
        STRICT_LIVE_SECRET.test(match.matchedString) ||
        PRIVATE_KEY_HEADER.test(match.matchedString)
    )
    .map((match) => ({
      type: "KNOWN_SIGNATURE",
      name: match.name,
      severity: match.severity,
      lineNumber: match.lineNumber,
      redactedToken: match.redactedString,
      rawToken: match.matchedString,
      suggestedEnvKey: match.suggestedEnvKey,
    }));
  const knownTokens = findings.map((finding) => finding.rawToken);
  const entropy = extractHighEntropyTokens(content);

  if (!placeholderEnv) {
    const localhostLines = localhostConfigLines(content);
    for (const candidate of entropy.candidates) {
      if (localhostLines.has(candidate.lineNumber)) continue;
      if (knownTokens.some((token) => token.includes(candidate.token))) continue;
      if (candidate.entropy < GENERIC_SECRET_MIN_ENTROPY) continue;
      if (!isLikelySecretLiteral(candidate.token)) continue;
      findings.push({
        type: "HIGH_ENTROPY",
        name: "High-Entropy Secret Literal",
        severity: candidate.entropy >= 5 ? "CRITICAL" : "HIGH",
        lineNumber: candidate.lineNumber,
        redactedToken: redactSecret(candidate.token),
        rawToken: candidate.token,
        suggestedEnvKey: `SECRET_TOKEN_${candidate.lineNumber}`,
        entropy: candidate.entropy,
      });
    }
  }

  const riskScore = findings.some((finding) => finding.severity === "CRITICAL")
    ? 100
    : findings.some((finding) => finding.severity === "HIGH")
      ? 75
      : findings.length > 0 ? 40 : 0;
  const verdict: "SAFE" | "SUSPICIOUS" | "DANGEROUS" =
    riskScore >= 75 ? "DANGEROUS" : riskScore >= 25 ? "SUSPICIOUS" : "SAFE";
  const envKeys = new Map<string, string>();
  let sanitizedContent = content;
  const python = filename.endsWith(".py");

  for (const finding of findings) {
    let key = envKeys.get(finding.rawToken);
    if (!key) {
      const base = finding.suggestedEnvKey.toUpperCase();
      key = base;
      let suffix = 2;
      while ([...envKeys.values()].includes(key)) key = `${base}_${suffix++}`;
      envKeys.set(finding.rawToken, key);
    }
    const reference = python ? `os.environ["${key}"]` : `process.env.${key}`;
    for (const quote of ['"', "'", "`"]) {
      sanitizedContent = sanitizedContent.split(`${quote}${finding.rawToken}${quote}`).join(reference);
    }
    sanitizedContent = sanitizedContent.split(finding.rawToken).join(reference);
  }
  if (python && envKeys.size > 0 && !/^import os\b/m.test(sanitizedContent)) {
    sanitizedContent = `import os\n${sanitizedContent}`;
  }

  return {
    highestEntropy: entropy.highestEntropy,
    riskScore,
    verdict,
    findingsCount: findings.length,
    findings: findings.map(({ rawToken, ...finding }) => finding),
    remediation: {
      hasSecrets: findings.length > 0,
      envFileSnippet: [...envKeys.values()].map((key) => `${key}=""`).join("\n"),
      sanitizedContent,
      gitignoreRecommendation: ".env\n.env.local\n*.pem\n*.key",
    },
  };
}
