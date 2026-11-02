/**
 * GuardAI — Server-Side Request Forgery (SSRF) Defense Engine
 *
 * Implements strict multi-layer egress validation:
 * 1. URL syntax and protocol constraints (http/https only, no userinfo).
 * 2. Hostname parsing with numeric, hex, octal, decimal IP normalization.
 * 3. Proactive DNS resolution (A and AAAA records) with full address validation.
 * 4. Comprehensive IP range blocklist (RFC 1918, RFC 3927, CGNAT, Loopback, Cloud Metadata, Multicast, IPv6 ULA/Link-local).
 * 5. IPv4-mapped IPv6 normalization (::ffff:127.0.0.1).
 * 6. Safe outbound HTTP transport with pinned destination IP and hop-by-hop redirect re-validation.
 */

import dns from "dns/promises";
import net from "net";
import http from "http";
import https from "https";

export interface SSRFValidationResult {
  allowed: boolean;
  reason?: string;
  normalizedUrl?: string;
  hostname?: string;
  resolvedIps?: string[];
  pinnedIp?: string;
}

// ---------------------------------------------------------------------------
// IP Parsing & Conversion Helpers
// ---------------------------------------------------------------------------

/**
 * Parses numeric IP strings (decimal, hex, octal, or dotted mixed) into canonical IPv4.
 * Examples:
 *   "2130706433" → "127.0.0.1"
 *   "0x7f.0.0.1" → "127.0.0.1"
 *   "0177.0.0.1" → "127.0.0.1"
 */
export function normalizeIPv4String(host: string): string | null {
  const trimmed = host.trim().toLowerCase();

  // If already standard dotted-decimal
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) {
    const parts = trimmed.split(".").map(Number);
    if (parts.every((p) => p >= 0 && p <= 255)) {
      return parts.join(".");
    }
    return null;
  }

  // Pure integer / decimal IP (e.g. 2130706433)
  if (/^\d+$/.test(trimmed)) {
    try {
      const num = BigInt(trimmed);
      if (num >= BigInt(0) && num <= BigInt(4294967295)) {
        const n = Number(num);
        return [
          (n >>> 24) & 255,
          (n >>> 16) & 255,
          (n >>> 8) & 255,
          n & 255,
        ].join(".");
      }
    } catch {
      return null;
    }
  }

  // Hexadecimal notation (e.g. 0x7f000001)
  if (/^0x[0-9a-f]+$/i.test(trimmed)) {
    try {
      const num = BigInt(trimmed);
      if (num >= BigInt(0) && num <= BigInt(4294967295)) {
        const n = Number(num);
        return [
          (n >>> 24) & 255,
          (n >>> 16) & 255,
          (n >>> 8) & 255,
          n & 255,
        ].join(".");
      }
    } catch {
      return null;
    }
  }

  // Dotted hex, octal, or decimal mixed notation (e.g. 0177.0.0.1 or 0x7f.0.0.1)
  if (trimmed.includes(".")) {
    const segments = trimmed.split(".");
    if (segments.length >= 1 && segments.length <= 4) {
      const parsedSegments: number[] = [];
      for (const seg of segments) {
        let val: number;
        if (/^0x[0-9a-f]+$/i.test(seg)) {
          val = parseInt(seg, 16);
        } else if (/^0[0-7]+$/.test(seg) && seg !== "0") {
          val = parseInt(seg, 8);
        } else if (/^\d+$/.test(seg)) {
          val = parseInt(seg, 10);
        } else {
          return null;
        }
        if (Number.isNaN(val) || val < 0) return null;
        parsedSegments.push(val);
      }

      // Convert according to standard inet_aton rules
      let fullNum = 0;
      if (parsedSegments.length === 4) {
        if (parsedSegments.some((p) => p > 255)) return null;
        return parsedSegments.join(".");
      } else if (parsedSegments.length === 3) {
        if (parsedSegments[0] > 255 || parsedSegments[1] > 255 || parsedSegments[2] > 65535) return null;
        fullNum = (parsedSegments[0] << 24) | (parsedSegments[1] << 16) | parsedSegments[2];
      } else if (parsedSegments.length === 2) {
        if (parsedSegments[0] > 255 || parsedSegments[1] > 16777215) return null;
        fullNum = (parsedSegments[0] << 24) | parsedSegments[1];
      } else if (parsedSegments.length === 1) {
        fullNum = parsedSegments[0];
      }
      return [
        (fullNum >>> 24) & 255,
        (fullNum >>> 16) & 255,
        (fullNum >>> 8) & 255,
        fullNum & 255,
      ].join(".");
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// IP Range Validation
// ---------------------------------------------------------------------------

/**
 * Checks whether an IPv4 address belongs to a private, loopback, link-local,
 * metadata, multicast, or reserved subnet.
 */
export function isDisallowedIPv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return true; // invalid IP is disallowed
  }

  const [b0, b1, b2, b3] = parts;

  // 0.0.0.0/8 — Current network (local identification)
  if (b0 === 0) return true;

  // 10.0.0.0/8 — Private network (RFC 1918)
  if (b0 === 10) return true;

  // 100.64.0.0/10 — Carrier-grade NAT (RFC 6598)
  if (b0 === 100 && b1 >= 64 && b1 <= 127) return true;

  // 100.100.100.200 — Alibaba Cloud metadata endpoint
  if (b0 === 100 && b1 === 100 && b2 === 100 && b3 === 200) return true;

  // 127.0.0.0/8 — Loopback (RFC 1122)
  if (b0 === 127) return true;

  // 169.254.0.0/16 — Link-local & cloud metadata (RFC 3927)
  if (b0 === 169 && b1 === 254) return true;

  // 172.16.0.0/12 — Private network (RFC 1918)
  if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;

  // 192.0.0.0/24 — IETF Protocol Assignments (RFC 6890)
  if (b0 === 192 && b1 === 0 && b2 === 0) return true;

  // 192.0.2.0/24 — TEST-NET-1 (RFC 5737)
  if (b0 === 192 && b1 === 0 && b2 === 2) return true;

  // 192.88.99.0/24 — 6to4 Relay Anycast (RFC 7526)
  if (b0 === 192 && b1 === 88 && b2 === 99) return true;

  // 192.168.0.0/16 — Private network (RFC 1918)
  if (b0 === 192 && b1 === 168) return true;

  // 198.18.0.0/15 — Network benchmark tests (RFC 2544)
  if (b0 === 198 && (b1 === 18 || b1 === 19)) return true;

  // 198.51.100.0/24 — TEST-NET-2 (RFC 5737)
  if (b0 === 198 && b1 === 51 && b2 === 100) return true;

  // 203.0.113.0/24 — TEST-NET-3 (RFC 5737)
  if (b0 === 203 && b1 === 0 && b2 === 113) return true;

  // 224.0.0.0/4 — Multicast (RFC 5771)
  if (b0 >= 224 && b0 <= 239) return true;

  // 240.0.0.0/4 — Reserved for future use (RFC 1112)
  if (b0 >= 240) return true;

  return false;
}

/**
 * Checks whether an IPv6 address is disallowed (loopback, link-local, ULA, unspecified, metadata).
 */
export function isDisallowedIPv6(ip: string): boolean {
  const clean = ip.toLowerCase().trim().replace(/^\[|\]$/g, "");

  // Unspecified
  if (clean === "::" || clean === "0:0:0:0:0:0:0:0") return true;

  // Loopback
  if (clean === "::1" || clean === "0:0:0:0:0:0:0:1") return true;

  // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (clean.startsWith("::ffff:") || clean.startsWith("0:0:0:0:0:ffff:")) {
    const lastPart = clean.split(":").pop();
    if (lastPart) {
      if (lastPart.includes(".")) {
        return isDisallowedIPv4(lastPart);
      }
      const norm = normalizeIPv4String("0x" + lastPart);
      if (norm) return isDisallowedIPv4(norm);
    }
    return true;
  }

  // Unique Local Address (ULA) — fc00::/7
  if (clean.startsWith("fc") || clean.startsWith("fd")) return true;

  // Link-Local Unicast — fe80::/10
  if (
    clean.startsWith("fe8") ||
    clean.startsWith("fe9") ||
    clean.startsWith("fea") ||
    clean.startsWith("feb")
  ) {
    return true;
  }

  // Multicast — ff00::/8
  if (clean.startsWith("ff")) return true;

  // Discard prefix / Documentation (100::/64, 2001:db8::/32)
  if (clean.startsWith("100:") || clean.startsWith("2001:db8:")) return true;

  // 6to4 prefix (2002::/16) - embeds IPv4
  if (clean.startsWith("2002:")) {
    const parts = clean.split(":");
    if (parts.length >= 3) {
      const hex = parts[1].padStart(4, "0") + parts[2].padStart(4, "0");
      const norm = normalizeIPv4String("0x" + hex);
      if (norm) return isDisallowedIPv4(norm);
    }
    return true;
  }

  return false;
}

/**
 * Validates any IP address (IPv4 or IPv6) against disallowed ranges.
 */
export function isDisallowedIP(ip: string): boolean {
  const version = net.isIP(ip);
  if (version === 4) return isDisallowedIPv4(ip);
  if (version === 6) return isDisallowedIPv6(ip);

  // Check if it's an alternate IPv4 format
  const norm = normalizeIPv4String(ip);
  if (norm) return isDisallowedIPv4(norm);

  return true; // Unknown/malformed is disallowed
}

// ---------------------------------------------------------------------------
// Hostname & DNS Validation
// ---------------------------------------------------------------------------

const BLOCKED_HOST_PATTERNS = [
  /^localhost$/i,
  /\.localhost$/i,
  /\.local$/i,
  /\.internal$/i,
  /\.lan$/i,
  /\.home$/i,
  /\.corp$/i,
  /\.intranet$/i,
  /^metadata\.google\.internal$/i,
  /^instance-data$/i,
  /\.nip\.io$/i,
  /\.sslip\.io$/i,
  /\.traffik\.me$/i,
];

/**
 * Checks whether a hostname pattern is explicitly disallowed.
 */
export function isDisallowedHostname(hostname: string): boolean {
  const h = hostname.toLowerCase().trim();
  if (!h) return true;

  for (const pattern of BLOCKED_HOST_PATTERNS) {
    if (pattern.test(h)) return true;
  }

  return false;
}

/**
 * Fully validates a target URL against SSRF and DNS rebinding risks.
 * Resolves all A and AAAA records, checking every returned IP.
 */
export async function validateTargetForSSRF(rawUrl: string): Promise<SSRFValidationResult> {
  let parsed: URL;
  try {
    const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(rawUrl);
    const normalized = hasScheme ? rawUrl : `https://${rawUrl}`;
    parsed = new URL(normalized);
  } catch {
    return { allowed: false, reason: "Malformed URL syntax" };
  }

  // Scheme constraint: Only HTTP and HTTPS are permitted
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return {
      allowed: false,
      reason: `Forbidden URL scheme "${parsed.protocol}". Only http: and https: are permitted.`,
    };
  }

  // Credentials in URL (e.g. http://user:pass@host) are rejected
  if (parsed.username || parsed.password) {
    return {
      allowed: false,
      reason: "User credentials in URLs are rejected to prevent credential masking attacks.",
    };
  }

  // Port constraint: Only standard web ports or explicitly permitted ports
  const port = parsed.port ? parseInt(parsed.port, 10) : parsed.protocol === "https:" ? 443 : 80;
  const ALLOWED_PORTS = new Set([80, 443, 8080, 8443]);
  if (!ALLOWED_PORTS.has(port)) {
    return {
      allowed: false,
      reason: `Destination port ${port} is restricted. Only standard web ports (80, 443, 8080, 8443) are allowed.`,
    };
  }

  const hostname = parsed.hostname.toLowerCase().trim();

  // Check hostname string against forbidden patterns
  if (isDisallowedHostname(hostname)) {
    return {
      allowed: false,
      reason: `Hostname "${hostname}" matches a reserved, internal, or loopback domain pattern.`,
      hostname,
    };
  }

  // Check if the hostname is a literal IP (including hex, octal, decimal)
  const normalizedIPv4 = normalizeIPv4String(hostname);
  if (normalizedIPv4) {
    if (isDisallowedIPv4(normalizedIPv4)) {
      return {
        allowed: false,
        reason: `Target IP ${normalizedIPv4} is within a private, loopback, or cloud-metadata range.`,
        hostname,
        resolvedIps: [normalizedIPv4],
      };
    }
    return {
      allowed: true,
      normalizedUrl: parsed.toString(),
      hostname,
      resolvedIps: [normalizedIPv4],
      pinnedIp: normalizedIPv4,
    };
  }

  if (net.isIPv6(hostname)) {
    if (isDisallowedIPv6(hostname)) {
      return {
        allowed: false,
        reason: `Target IPv6 ${hostname} is within a reserved or local address scope.`,
        hostname,
        resolvedIps: [hostname],
      };
    }
    return {
      allowed: true,
      normalizedUrl: parsed.toString(),
      hostname,
      resolvedIps: [hostname],
      pinnedIp: hostname,
    };
  }

  // Resolve DNS A and AAAA records
  const resolvedIps: string[] = [];
  try {
    const [ipv4Addresses, ipv6Addresses] = await Promise.allSettled([
      dns.resolve4(hostname),
      dns.resolve6(hostname),
    ]);

    if (ipv4Addresses.status === "fulfilled") {
      resolvedIps.push(...ipv4Addresses.value);
    }
    if (ipv6Addresses.status === "fulfilled") {
      resolvedIps.push(...ipv6Addresses.value);
    }
  } catch {
    return {
      allowed: false,
      reason: `DNS resolution failed for hostname "${hostname}". Target is unreachable.`,
      hostname,
    };
  }

  if (resolvedIps.length === 0) {
    return {
      allowed: false,
      reason: `No DNS A or AAAA records found for "${hostname}".`,
      hostname,
    };
  }

  // Validate EVERY resolved IP address
  for (const ip of resolvedIps) {
    if (isDisallowedIP(ip)) {
      return {
        allowed: false,
        reason: `Hostname "${hostname}" resolves to protected or internal IP address ${ip}.`,
        hostname,
        resolvedIps,
      };
    }
  }

  return {
    allowed: true,
    normalizedUrl: parsed.toString(),
    hostname,
    resolvedIps,
    pinnedIp: resolvedIps[0],
  };
}

// ---------------------------------------------------------------------------
// SSRF-Protected Outbound HTTP Client
// ---------------------------------------------------------------------------

export interface SafeFetchOptions {
  method?: "GET" | "HEAD" | "POST";
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  maxRedirects?: number;
  maxResponseSizeBytes?: number;
}

export interface SafeFetchResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  finalUrl: string;
  pinnedIp: string;
  redirectCount: number;
}

/**
 * Executes a secure HTTP/HTTPS request with:
 * - Pre-flight DNS & IP range validation.
 * - Pinned IP transport (prevents DNS rebinding).
 * - Hop-by-hop redirect inspection with full re-validation.
 * - Enforced timeouts and response size limits.
 */
export async function safeFetch(
  targetUrl: string,
  options: SafeFetchOptions = {}
): Promise<SafeFetchResponse> {
  const {
    method = "GET",
    headers = {},
    body,
    timeoutMs = 5000,
    maxRedirects = 5,
    maxResponseSizeBytes = 65536, // 64 KB safety cap
  } = options;

  let currentUrl = targetUrl;
  let redirectCount = 0;

  while (redirectCount <= maxRedirects) {
    const validation = await validateTargetForSSRF(currentUrl);
    if (!validation.allowed || !validation.pinnedIp) {
      throw new Error(`SSRF Blocked: ${validation.reason}`);
    }

    const parsed = new URL(validation.normalizedUrl!);
    const isHttps = parsed.protocol === "https:";
    const port = parsed.port ? parseInt(parsed.port, 10) : isHttps ? 443 : 80;

    const res = await new Promise<SafeFetchResponse>((resolve, reject) => {
      let settled = false;
      const settle = (err?: Error, val?: SafeFetchResponse) => {
        if (settled) return;
        settled = true;
        if (err) reject(err);
        else resolve(val!);
      };

      const timer = setTimeout(() => {
        req.destroy();
        settle(new Error(`Connection timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      const requestOptions: http.RequestOptions = {
        host: validation.pinnedIp, // Connect directly to pinned IP to defeat rebinding
        port,
        path: parsed.pathname + parsed.search,
        method,
        headers: {
          ...headers,
          Host: parsed.host, // Preserve canonical Host header
        },
        timeout: timeoutMs,
      };

      if (isHttps) {
        (requestOptions as https.RequestOptions).servername = parsed.hostname; // TLS SNI
        (requestOptions as https.RequestOptions).rejectUnauthorized = true;
      }

      const client = isHttps ? https : http;
      const req = client.request(requestOptions, (response) => {
        const responseHeaders: Record<string, string> = {};
        for (const [key, value] of Object.entries(response.headers)) {
          if (typeof value === "string") {
            responseHeaders[key.toLowerCase()] = value;
          } else if (Array.isArray(value)) {
            responseHeaders[key.toLowerCase()] = value.join(", ");
          }
        }

        const statusCode = response.statusCode || 0;

        // Check for redirects
        if (
          [301, 302, 303, 307, 308].includes(statusCode) &&
          responseHeaders["location"]
        ) {
          clearTimeout(timer);
          response.resume(); // discard body
          const nextLocation = new URL(responseHeaders["location"], currentUrl).toString();
          currentUrl = nextLocation;
          redirectCount++;
          settle(undefined, {
            status: statusCode,
            statusText: response.statusMessage || "",
            headers: responseHeaders,
            body: "",
            finalUrl: nextLocation,
            pinnedIp: validation.pinnedIp!,
            redirectCount,
          });
          return;
        }

        let rawData = "";
        let bytesRead = 0;

        response.on("data", (chunk: Buffer) => {
          bytesRead += chunk.length;
          if (bytesRead > maxResponseSizeBytes) {
            req.destroy();
            clearTimeout(timer);
            settle(new Error(`Response exceeded maximum size limit of ${maxResponseSizeBytes} bytes`));
            return;
          }
          rawData += chunk.toString("utf8");
        });

        response.on("end", () => {
          clearTimeout(timer);
          settle(undefined, {
            status: statusCode,
            statusText: response.statusMessage || "",
            headers: responseHeaders,
            body: rawData,
            finalUrl: currentUrl,
            pinnedIp: validation.pinnedIp!,
            redirectCount,
          });
        });
      });

      req.on("error", (err) => {
        clearTimeout(timer);
        settle(err);
      });

      if (body) {
        req.write(body);
      }
      req.end();
    });

    // If it was a redirect and we haven't reached max redirects, loop again
    if ([301, 302, 303, 307, 308].includes(res.status) && res.finalUrl !== currentUrl) {
      continue;
    }

    return res;
  }

  throw new Error(`Exceeded maximum redirect limit of ${maxRedirects}`);
}
