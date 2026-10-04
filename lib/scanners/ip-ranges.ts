// ============================================================================
// PROJECT AEGIS: ENVIRONMENT-AGNOSTIC IP RANGE CLASSIFICATION
// Pure TypeScript — no Node `net`/`dns` imports, so the identical CIDR
// validation logic runs in both the server scanner and the client-side
// Red Team Exploit Lab. Single source of truth for SSRF destination rules.
// ============================================================================

export type IpFamily = 4 | 6;

export type IpScope =
  | 'PUBLIC'
  | 'LOOPBACK'
  | 'UNSPECIFIED'
  | 'PRIVATE_RFC1918'
  | 'LINK_LOCAL_METADATA'
  | 'CARRIER_GRADE_NAT'
  | 'UNIQUE_LOCAL'
  | 'MULTICAST_RESERVED'
  | 'TEST_NET'
  | 'INVALID';

export interface IpClassification {
  address: string;
  family: IpFamily | null;
  isPrivate: boolean;
  scope: IpScope;
  /** Human-readable explanation when the address is prohibited. */
  reason: string | null;
}

/** Structural IPv4 check: four dotted-decimal octets, each 0-255. */
export function isIpv4(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 4) {
    return false;
  }
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

/** Structural IPv6 heuristic: contains a colon and only hex/colon/percent. */
export function isIpv6(value: string): boolean {
  return value.includes(':') && /^[0-9a-fA-F:.%\]]+$/.test(value);
}

const SCOPE_REASONS: Record<IpScope, string> = {
  PUBLIC: 'Publicly routable address outside protected ranges',
  LOOPBACK: 'Loopback address (host-local services)',
  UNSPECIFIED: 'Unspecified / current-network address',
  PRIVATE_RFC1918: 'RFC 1918 private address (internal network)',
  LINK_LOCAL_METADATA: 'Link-local range (cloud metadata / APIPA)',
  CARRIER_GRADE_NAT: 'Carrier-grade NAT (RFC 6598) address',
  UNIQUE_LOCAL: 'IPv6 unique local address (RFC 4193)',
  MULTICAST_RESERVED: 'Multicast / reserved address space',
  TEST_NET: 'Documentation TEST-NET address (RFC 5737)',
  INVALID: 'Malformed or unclassifiable IP address',
};

function classifyIpv4(ip: string): { isPrivate: boolean; scope: IpScope } {
  const parts = ip.split('.').map((part) => parseInt(part, 10));
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(part) || part < 0 || part > 255)) {
    return { isPrivate: true, scope: 'INVALID' };
  }

  const [a, b, c] = parts;

  if (a === 0) return { isPrivate: true, scope: 'UNSPECIFIED' };
  if (a === 127) return { isPrivate: true, scope: 'LOOPBACK' };
  if (a === 10) return { isPrivate: true, scope: 'PRIVATE_RFC1918' };
  if (a === 172 && b >= 16 && b <= 31) return { isPrivate: true, scope: 'PRIVATE_RFC1918' };
  if (a === 192 && b === 168) return { isPrivate: true, scope: 'PRIVATE_RFC1918' };
  if (a === 169 && b === 254) return { isPrivate: true, scope: 'LINK_LOCAL_METADATA' };
  if (a === 100 && b >= 64 && b <= 127) return { isPrivate: true, scope: 'CARRIER_GRADE_NAT' };
  if (a === 192 && b === 0 && c === 2) return { isPrivate: true, scope: 'TEST_NET' };
  if (a === 198 && b === 51 && c === 100) return { isPrivate: true, scope: 'TEST_NET' };
  if (a === 203 && b === 0 && c === 113) return { isPrivate: true, scope: 'TEST_NET' };
  if (a >= 224) return { isPrivate: true, scope: 'MULTICAST_RESERVED' };

  return { isPrivate: false, scope: 'PUBLIC' };
}

function classifyIpv6(ip: string): { isPrivate: boolean; scope: IpScope } {
  const normalized = ip.toLowerCase().trim();

  if (normalized === '::1') return { isPrivate: true, scope: 'LOOPBACK' };
  if (normalized === '::') return { isPrivate: true, scope: 'UNSPECIFIED' };

  if (
    normalized.startsWith('fe80:') ||
    normalized.startsWith('fe8') ||
    normalized.startsWith('fe9') ||
    normalized.startsWith('fea') ||
    normalized.startsWith('feb')
  ) {
    return { isPrivate: true, scope: 'LINK_LOCAL_METADATA' };
  }

  if (normalized.startsWith('fc') || normalized.startsWith('fd')) {
    return { isPrivate: true, scope: 'UNIQUE_LOCAL' };
  }

  if (normalized.startsWith('ff')) {
    return { isPrivate: true, scope: 'MULTICAST_RESERVED' };
  }

  if (normalized.includes('::ffff:')) {
    const ipv4Part = normalized.split('::ffff:')[1];
    if (isIpv4(ipv4Part)) {
      return classifyIpv4(ipv4Part);
    }
  }

  return { isPrivate: false, scope: 'PUBLIC' };
}

/** Backwards-compatible boolean check used by the server SSRF validator. */
export function isPrivateOrReservedIPv4(ip: string): boolean {
  return classifyIpv4(ip).isPrivate;
}

/** Backwards-compatible boolean check used by the server SSRF validator. */
export function isPrivateOrReservedIPv6(ip: string): boolean {
  return classifyIpv6(ip).isPrivate;
}

/**
 * Fully classifies an IP literal: family, protected-range scope, and whether
 * SafeLink would fail-closed on it. Hostnames (non-literals) return family null
 * with `isPrivate: false`; the caller performs DNS resolution separately.
 */
export function classifyIpAddress(address: string): IpClassification {
  const trimmed = address.trim();

  if (isIpv4(trimmed)) {
    const { isPrivate, scope } = classifyIpv4(trimmed);
    return {
      address: trimmed,
      family: 4,
      isPrivate,
      scope,
      reason: isPrivate ? SCOPE_REASONS[scope] : null,
    };
  }

  if (isIpv6(trimmed)) {
    const { isPrivate, scope } = classifyIpv6(trimmed);
    return {
      address: trimmed,
      family: 6,
      isPrivate,
      scope,
      reason: isPrivate ? SCOPE_REASONS[scope] : null,
    };
  }

  return {
    address: trimmed,
    family: null,
    isPrivate: false,
    scope: 'INVALID',
    reason: 'Not an IP address literal',
  };
}

/** Human-readable scope label for audit reports and terminals. */
export function describeIpScope(scope: IpScope): string {
  return SCOPE_REASONS[scope];
}
