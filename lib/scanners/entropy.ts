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
 * Generic literal gate. Extraction stays broad (it also drives redaction), but
 * only literals above this bar become "High-Entropy Secret Literal" findings.
 */
export const GENERIC_SECRET_MIN_ENTROPY = 4.55;
export const GENERIC_SECRET_MIN_LENGTH = 20;

/**
 * Generated credentials mix upper case, lower case, and digits/symbols.
 * Kebab-case English (payload-cms-collections), snake_case identifiers, and
 * lowercase URLs fail, so config values no longer masquerade as secrets.
 */
export function isLikelySecretLiteral(token: string): boolean {
  if (token.length < GENERIC_SECRET_MIN_LENGTH) {
    return false;
  }
  if (!/[A-Z]/.test(token) || !/[a-z]/.test(token)) {
    return false;
  }
  return /[0-9]/.test(token) || /[^A-Za-z0-9]/.test(token);
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
      const rawToken = match[0];
      let token = rawToken;
      let startIndex = match.index;

      // `.env` lines tokenize as NAME=value. Evaluate only the value so the
      // variable name is never reported, while real secrets are still scored.
      const assignmentIndex = rawToken.indexOf('=');
      if (assignmentIndex > 2) {
        const lhs = rawToken.slice(0, assignmentIndex);
        const isEnvName =
          /^[A-Z][A-Z0-9_]{2,}$/.test(lhs) ||
          /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/.test(lhs);
        if (isEnvName) {
          token = rawToken.slice(assignmentIndex + 1);
          startIndex = match.index + assignmentIndex + 1;
        }
      }

      if (token.length < minTokenLength || token.length > maxTokenLength) {
        continue;
      }

      // Skip tokens that are all same character or trivial increments
      const uniqueCharCount = new Set(token).size;
      if (uniqueCharCount < 6) {
        continue;
      }

      // Skip pure camelCase identifiers (e.g. trustProxyDefaultSymbol).
      // Real cryptographic secrets almost always include digits or symbols.
      if (/^[a-z]+(?:[A-Z][a-z]+)+$/.test(token)) {
        continue;
      }

      // Skip public publishable keys (Clerk/Stripe pk_test_ / pk_live_).
      if (/^pk_(?:test|live)_[A-Za-z0-9_\-+=]{8,}$/i.test(token)) {
        continue;
      }

      // Skip environment-variable names such as NEXT_PUBLIC_CMS_API_KEY= or
      // DATABASE_URL (uppercase snake_case with at least one underscore).
      if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+=?$/.test(token)) {
        continue;
      }

      // Skip lowercase snake_case identifiers (e.g. trust_proxy_default).
      if (/^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/.test(token) && !/\d/.test(token)) {
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
          startIndex,
          endIndex: startIndex + token.length,
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
