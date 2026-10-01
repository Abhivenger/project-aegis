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
