// ============================================================================
// PROJECT AEGIS: CLERK CONFIGURATION GUARD
// Determines whether a *real* Clerk publishable key is configured. The stock
// placeholder key decodes to `clerk.example.com`, which would force the browser
// into an unreachable handshake — so it is explicitly treated as "not
// configured" and the app runs in local/fallback mode instead.
//
// Edge-runtime safe: uses `atob` when available, falling back to Buffer, and
// imports nothing.
// ============================================================================

const EXAMPLE_PUBLISHABLE_KEY = 'pk_test_Y2xlcmsuZXhhbXBsZS5jb20k';

function base64Decode(value: string): string | null {
  try {
    if (typeof atob === 'function') {
      return atob(value);
    }
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(value, 'base64').toString('utf-8');
    }
  } catch {
    // Fall through: an undecodable key is treated as invalid.
  }
  return null;
}

/** Extracts the frontend-api domain encoded inside a Clerk publishable key. */
function decodeClerkDomain(publishableKey: string): string | null {
  const parts = publishableKey.split('_');
  // Format: pk_{test|live}_{base64(domain)} — the base64 segment may contain '_'.
  const encoded = parts.slice(2).join('_');
  if (!encoded) {
    return null;
  }
  const decoded = base64Decode(encoded);
  if (!decoded) {
    return null;
  }
  return decoded.replace(/\$+$/, '').trim().toLowerCase() || null;
}

/**
 * Returns the configured Clerk publishable key, or null when it is missing,
 * malformed, or a known placeholder (e.g. `clerk.example.com`).
 */
export function getClerkPublishableKey(): string | null {
  const raw = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY?.trim();
  if (!raw) {
    return null;
  }

  if (raw === EXAMPLE_PUBLISHABLE_KEY) {
    return null;
  }

  if (!/^pk_(test|live)_/.test(raw)) {
    return null;
  }

  const domain = decodeClerkDomain(raw);
  if (domain && /(^|\.)example\.com$/.test(domain)) {
    return null;
  }

  return raw;
}

/** True only when a valid, non-placeholder Clerk key is present. */
export function isClerkConfigured(): boolean {
  return getClerkPublishableKey() !== null;
}
