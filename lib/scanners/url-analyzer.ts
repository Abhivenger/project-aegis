// ============================================================================
// PROJECT AEGIS: SAFELINK URL HEURISTIC & SSRF-SAFE ANALYZER
// ============================================================================

import { promises as dns } from 'dns';
import * as net from 'net';
import { isPrivateOrReservedIPv4, isPrivateOrReservedIPv6 } from './ip-ranges';

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
// The CIDR / reserved-range rules live in the environment-agnostic module
// `./ip-ranges` so the browser-side Red Team Exploit Lab evaluates the exact
// same filter decisions as this server scanner.

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
