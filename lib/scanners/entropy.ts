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
