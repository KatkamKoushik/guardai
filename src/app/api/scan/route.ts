/**
 * GuardAI — Scan API (POST /api/scan)
 *
 * Lightweight synchronous endpoint used by non-streaming callers.
 * Primary features:
 *   1. Defanged URL sanitization — hxxp/hxxps → http/https.
 *   2. Strict input validation — rejects gibberish before any external call.
 *   3. Auto-protocol prepend — bare domains get https:// prepended.
 *   4. Private/local target block — SSRF protection.
 *   5. Real VirusTotal v3 integration (graceful skip if key absent / call fails).
 *   6. Real Google Safe Browsing v4 integration (graceful skip).
 *   7. GuardAI Lexical Heuristics Engine — always runs, no external dependency.
 *   8. Real SSL/TLS certificate probing via Node tls module.
 */

import { NextResponse } from "next/server";
import net from "net";
import tls from "tls";
import dns from "dns";
import { analyzeURL, isGibberish } from "@/lib/heuristics";

// ---------------------------------------------------------------------------
// SSL Certificate Probe
// ---------------------------------------------------------------------------

interface SSLResult {
  valid: boolean;
  issuer: string;
  expiry: string;
  error?: string;
}

/**
 * Connects to `hostname:443` via TLS and extracts cert metadata.
 *
 * Key implementation details:
 * - Strips protocol (https://) and any path/query from the raw URL before
 *   connecting — this was the root cause of the "Unknown" bug when callers
 *   passed full URLs rather than bare hostnames.
 * - Uses a `settled` flag so that neither the error handler nor the timeout
 *   can reject/resolve after the promise has already been settled, preventing
 *   unhandled-rejection crashes.
 * - 5-second timeout after which the socket is destroyed and we return a
 *   graceful fallback.
 */
async function probeSSL(rawUrl: string): Promise<SSLResult> {
  // Extract the bare hostname — strip protocol and path
  let hostname: string;
  try {
    const parsed = new URL(rawUrl.startsWith("http") ? rawUrl : `https://${rawUrl}`);
    hostname = parsed.hostname;
  } catch (err: any) {
    return { valid: false, issuer: "Unknown", expiry: "Unknown", error: "Invalid URL Format" };
  }

  // Only probe HTTPS targets
  if (!rawUrl.startsWith("https://") && !rawUrl.startsWith("//")) {
    // HTTP-only — no TLS
    return { valid: false, issuer: "N/A (HTTP)", expiry: "N/A", error: "Unencrypted Protocol" };
  }

  return new Promise<SSLResult>((resolve) => {
    let settled = false;

    const settle = (result: SSLResult) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const timeoutHandle = setTimeout(() => {
      socket.destroy();
      settle({ valid: false, issuer: "Unknown", expiry: "Unknown", error: "Connection Timeout" });
    }, 5000);

    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false },
      () => {
        clearTimeout(timeoutHandle);
        try {
          const cert = socket.getPeerCertificate();
          socket.destroy();

          if (!cert || !cert.valid_to) {
            settle({ valid: false, issuer: "Unknown", expiry: "Unknown", error: "No Certificate Returned" });
            return;
          }

          const issuerOrg = Array.isArray(cert.issuer?.O)
            ? cert.issuer.O[0]
            : cert.issuer?.O;
          const issuerCn = Array.isArray(cert.issuer?.CN)
            ? cert.issuer.CN[0]
            : cert.issuer?.CN;
          const issuer = issuerOrg || issuerCn || "Unknown";

          // cert.valid_to is in the format "Jul 31 00:00:00 2027 GMT"
          const expiry = new Date(cert.valid_to).toLocaleDateString("en-US", {
            year: "numeric",
            month: "short",
            day: "numeric",
          });

          settle({ valid: true, issuer, expiry });
        } catch (err: any) {
          settle({ valid: false, issuer: "Unknown", expiry: "Unknown", error: err.message || "Certificate Parsing Failed" });
        }
      }
    );
    socket.on("error", (err) => {
      clearTimeout(timeoutHandle);
      socket.destroy();
      settle({ valid: false, issuer: "Unknown", expiry: "Unknown", error: err.message || "Socket Error" });
    });
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Refang a defanged URL.
 * Analysts often share IOCs with "hxxp" to prevent accidental clicks.
 * This step must run BEFORE any validation so the downstream logic
 * always operates on a real protocol string.
 *   hxxp://example.com  → http://example.com
 *   hxxps://example.com → https://example.com
 *   HXXPS://example.com → https://example.com  (case-insensitive)
 */
function refangUrl(input: string): string {
  return input
    .replace(/^hxxps?:(\/\/)?/i, (match) =>
      match.toLowerCase().startsWith("hxxps") ? "https://" : "http://"
    )
    // Also handle bracket-style defanging: hxxp[://] or hxxp[s]://
    .replace(/^hxxp\[s?\]?\[:?\/\/\]/i, "https://")
    .replace(/^hxxp\[:?\/\/\]/i,         "http://");
}

/** Prepend https:// when the user omits the protocol (e.g. "google.com"). */
function normalizeUrl(input: string): string {
  const trimmed = input.trim();
  if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
    return trimmed;
  }
  return `https://${trimmed}`;
}

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 127) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  return false;
}

/** SSRF guard — blocks localhost, .local, and RFC-1918 / loopback addresses. */
function isDisallowedTarget(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local")) {
    return true;
  }
  const ipType = net.isIP(h);
  if (ipType === 4) return isPrivateIPv4(h);
  if (ipType === 6) return h === "::1" || h.startsWith("fc") || h.startsWith("fd");
  return false;
}

// ---------------------------------------------------------------------------
// POST /api/scan
// ---------------------------------------------------------------------------
export async function POST(request: Request) {
  try {
    // ── 1. Parse body ──────────────────────────────────────────────────────
    let body: { url?: string };
    try {
      body = await request.json();
    } catch {
      return NextResponse.json(
        { error: "Invalid request body. Expected JSON with a 'url' field." },
        { status: 400 }
      );
    }

    const rawInput = body.url?.trim() ?? "";

    if (!rawInput) {
      return NextResponse.json(
        { error: "URL is required." },
        { status: 400 }
      );
    }

    // ── 1b. Defanged URL sanitization ─────────────────────────────────────
    // Must run BEFORE isGibberish() so defanged IOCs are accepted.
    const sanitizedInput = refangUrl(rawInput);

    // ── 2. Gibberish / invalid input guard ────────────────────────────────
    if (isGibberish(sanitizedInput)) {
      return NextResponse.json(
        {
          error:
            "Invalid Input: Please enter a valid domain or URL (e.g. google.com or https://example.com).",
        },
        { status: 400 }
      );
    }

    // ── 3. Normalize & parse URL ──────────────────────────────────────────
    const targetUrl = normalizeUrl(sanitizedInput);
    let parsed: URL;
    try {
      parsed = new URL(targetUrl);
    } catch {
      return NextResponse.json(
        { error: "Invalid URL format. Could not parse the supplied address." },
        { status: 400 }
      );
    }

    // ── 4. SSRF protection ────────────────────────────────────────────────
    if (isDisallowedTarget(parsed.hostname)) {
      return NextResponse.json({
        url: targetUrl,
        threatLevel: "safe",
        score: 0,
        status: "LOCAL_IP_DETECTED",
        message: "Target is a private/internal network IP address (RFC 1918) and cannot be reached over the public internet.",
        scannedAt: new Date().toISOString(),
        details: {
          virusTotal: { status: "skipped", detections: 0, total: 1, skipped: true },
          googleSafeBrowsing: { status: "skipped", skipped: true },
          phishing: { probability: 0, indicators: [] },
          ssl: { valid: false, issuer: "Unknown", expiry: "Unknown" },
          reputation: { score: 100, category: "LOCAL_IP" }
        }
      });
    }

    const appHost = request.headers.get("host")?.split(":")[0];
    if (parsed.hostname === appHost || parsed.hostname === "guardai-six.vercel.app") {
      return NextResponse.json({
        url: targetUrl,
        threatLevel: "safe",
        score: 0,
        status: "SELF_DOMAIN_DETECTED",
        message: "Target is this application (GuardAI). Connection loop prevented.",
        scannedAt: new Date().toISOString(),
        details: {
          virusTotal: { status: "CLEAN", detections: 0, total: 1, skipped: true },
          googleSafeBrowsing: { status: "CLEAN", skipped: true },
          phishing: { probability: 0, indicators: [] },
          ssl: { valid: true, issuer: "Vercel / AWS", expiry: "Valid" },
          reputation: { score: 100, category: "SELF_DOMAIN" }
        }
      });
    }

    // ── 5. GuardAI Lexical Heuristics (always runs — no external dependency)
    const heuristicData = analyzeURL(targetUrl);

    // ── 6. VirusTotal v3 (graceful skip) ──────────────────────────────────
    let vtStatus: string = "skipped";
    let vtDetections = 0;
    let vtTotal = 0;
    let vtSkipped = true;

    const vtApiKey = process.env.VIRUSTOTAL_API_KEY?.trim();
    if (vtApiKey) {
      vtSkipped = false;
      try {
        // VT URL ID is url-safe base64 of the raw URL (no padding)
        const urlId = Buffer.from(targetUrl)
          .toString("base64")
          .replace(/=/g, "")
          .replace(/\+/g, "-")
          .replace(/\//g, "_");

        const vtRes = await fetch(
          `https://www.virustotal.com/api/v3/urls/${urlId}`,
          {
            headers: { "x-apikey": vtApiKey },
            signal: AbortSignal.timeout(8000),
          }
        );

        if (vtRes.ok) {
          const vtData = await vtRes.json();
          const stats = vtData?.data?.attributes?.last_analysis_stats;
          if (stats) {
            vtDetections = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
            vtTotal =
              (stats.malicious ?? 0) +
              (stats.suspicious ?? 0) +
              (stats.undetected ?? 0) +
              (stats.harmless ?? 0);
            vtStatus = vtDetections > 0 ? "flagged" : "clean";
          } else {
            vtStatus = "clean";
          }
        } else if (vtRes.status === 404) {
          // URL not yet in VT database — treat as unknown/clean
          vtStatus = "not_found";
        } else {
          vtStatus = "error";
        }
      } catch {
        // Network failure, timeout, parse error — degrade gracefully
        vtStatus = "unavailable";
        vtSkipped = true;
      }
    }

    // ── 7. Google Safe Browsing v4 (graceful skip) ────────────────────────
    let gsbStatus: string = "unavailable";
    let gsbSkipped = true;

    const gsbApiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY?.trim();
    if (gsbApiKey) {
      gsbSkipped = false;
      try {
        const gsbRes = await fetch(
          `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${gsbApiKey}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              client: { clientId: "guardai", clientVersion: "2.0.0" },
              threatInfo: {
                threatTypes: [
                  "MALWARE",
                  "SOCIAL_ENGINEERING",
                  "UNWANTED_SOFTWARE",
                  "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url: targetUrl }],
              },
            }),
            signal: AbortSignal.timeout(8000),
          }
        );

        if (gsbRes.ok) {
          const gsbData = await gsbRes.json();
          gsbStatus =
            Array.isArray(gsbData?.matches) && gsbData.matches.length > 0
              ? "flagged"
              : "clean";
        } else {
          gsbStatus = "unavailable";
        }
      } catch {
        gsbStatus = "unavailable";
        gsbSkipped = true;
      }
    }

    // ── 7.5. Additional Threat Intel (AbuseIPDB & URLhaus) ───────────────────
    let abuseIpDbScore = 0;
    let urlhausMalware = false;
    
    const abuseIpKey = process.env.ABUSEIPDB_KEY?.trim();
    const urlhausKey = process.env.URLHAUS_KEY?.trim();

    const threatPromises: Promise<void>[] = [];

    if (abuseIpKey) {
        threatPromises.push((async () => {
            try {
                // Resolve IP first for AbuseIPDB
                const addresses = await dns.promises.resolve(parsed.hostname);
                const resolvedIp = addresses[0];
                if (resolvedIp) {
                  const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${resolvedIp}&maxAgeInDays=90`, {
                      headers: { 'Key': abuseIpKey, 'Accept': 'application/json' },
                      signal: AbortSignal.timeout(2000)
                  });
                  if (res.ok) {
                      const data = await res.json();
                      if (data?.data?.abuseConfidenceScore >= 50) {
                          abuseIpDbScore = data.data.abuseConfidenceScore;
                      }
                  }
                }
            } catch (e) {
                // Fail gracefully
            }
        })());
    }

    if (urlhausKey) {
        threatPromises.push((async () => {
            try {
                const res = await fetch(`https://urlhaus-api.abuse.ch/v1/url/`, {
                    method: 'POST',
                    headers: { 'Auth-Key': urlhausKey, 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `url=${encodeURIComponent(targetUrl)}`,
                    signal: AbortSignal.timeout(2000)
                });
                if (res.ok) {
                    const data = await res.json();
                    if (data.query_status === "ok" && data.url_status === "online") {
                        urlhausMalware = true;
                    }
                }
            } catch (e) {
                // Fail gracefully
            }
        })());
    }

    if (threatPromises.length > 0) {
        await Promise.allSettled(threatPromises);
    }

    // ── 8a. Multi-Path Directory Probing ─────────────────────────────────
    let isDeadLink = false;
    let adminOrLoginFound = false;
    try {
      const baseUrl = targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`;
      const parsedBase = new URL(baseUrl);
      
      const pathsToProbe = [
        { name: "Root", url: `${parsedBase.origin}/` },
        { name: "Target", url: baseUrl },
        { name: "Login", url: `${parsedBase.origin}/login` },
        { name: "Admin", url: `${parsedBase.origin}/admin` }
      ];

      const uniqueProbes = pathsToProbe.filter((v, i, a) => a.findIndex(t => t.url === v.url) === i);

      const probeResults = await Promise.allSettled(
        uniqueProbes.map(async (probe) => {
          const res = await fetch(probe.url, { method: "HEAD", signal: AbortSignal.timeout(1500) });
          return { name: probe.name, status: res.status, ok: res.ok };
        })
      );

      let allFailed = true;

      for (const result of probeResults) {
        if (result.status === "fulfilled") {
          const { status, ok, name } = result.value;
          if (ok || (status < 500 && status !== 404)) {
             allFailed = false;
          }
          if ((name === "Login" || name === "Admin") && status === 200) {
             adminOrLoginFound = true;
          }
        }
      }

      if (allFailed) {
         try {
            const apiNinjasKey = process.env.API_NINJAS_KEY?.trim();
            if (!apiNinjasKey) {
               isDeadLink = true;
            } else {
               const fallbackRes = await fetch(`https://api.api-ninjas.com/v1/urllookup?url=${encodeURIComponent(targetUrl)}`, {
                 headers: { 'X-Api-Key': apiNinjasKey },
                 signal: AbortSignal.timeout(2000)
               });
               if (fallbackRes.ok) {
                 const fallbackData = await fallbackRes.json();
                 if (fallbackData.is_valid === false) {
                    isDeadLink = true;
                 } else {
                    isDeadLink = false;
                 }
               } else {
                 isDeadLink = true;
               }
            }
         } catch (fallbackErr) {
            isDeadLink = true;
         }
      }
    } catch (e) {
      isDeadLink = true;
    }

    // ── 8b. SSL/TLS Certificate Probe ────────────────────────────────────
    const sslResult = await probeSSL(targetUrl);

    // ── 8c. Aggregate Score & Threat Level ───────────────────────────────
    let score = heuristicData.probability;
    if (!sslResult.valid && score < 80) {
      score = Math.min(score + 20, 100);
    }
    if (adminOrLoginFound && score >= 30) {
      score = Math.min(score + 15, 100);
    }
    
    if (abuseIpDbScore >= 50) {
      score = Math.min(score + 30, 100);
    }

    if (urlhausMalware) {
      score = Math.min(score + 40, 100);
    }
    
    let threatLevel: "safe" | "suspicious" | "high" | "critical" | "offline" = "safe";

    if (isDeadLink) {
      threatLevel = "offline";
      score = 0;
    } else if (gsbStatus === "flagged" || vtDetections >= 5 || urlhausMalware) {
      threatLevel = "critical";
      score = 95;
    } else if (vtDetections >= 1) {
      threatLevel = "high";
      score = Math.max(80, score);
    } else if (score >= 60) {
      threatLevel = "suspicious";
    }

    // ── 9. Telemetry & Notifications (Awaited for Serverless) ──────
    // Await the IIFE so Vercel doesn't kill the lambda prematurely.
    await (async () => {
      try {
        if (score > 50) {
          const { prisma } = await import("@/lib/db");
          const isIPHostname = net.isIP(parsed.hostname) !== 0;

          const telemetryRecord = await prisma.threatTelemetry.create({
            data: {
              domain: parsed.hostname,
              threatType: threatLevel === "critical" ? "malware" : "suspicious",
              ipAddress: isIPHostname ? parsed.hostname : null,
              latitude: null,
              longitude: null,
              countryCode: null,
              timestamp: new Date(),
            },
          });

          if (score > 80) {
            const { auth } = await import("@/lib/auth");
            const session = await auth();
            if (session?.user?.email) {
              const user = await prisma.user.findUnique({
                where: { email: session.user.email },
              });
              if (user?.id) {
                const { notifyUserForScan } = await import("@/lib/notifications");
                await notifyUserForScan(user.id, {
                  url: targetUrl,
                  score,
                  severity: threatLevel === "critical" ? "critical" : "high",
                  explanation: "A Live Deep Scan detected a high-risk threat on this target.",
                  vtScore: vtSkipped
                    ? "VirusTotal: skipped"
                    : `${vtDetections} / ${Math.max(vtTotal, 1)} engines flagged`,
                  sslStatus: targetUrl.startsWith("https://")
                    ? "ENCRYPTED"
                    : "UNENCRYPTED (HTTP Only)",
                  missingHeaders: "Checked via heuristics",
                  mlScore: `Phishing Probability: ${heuristicData.probability}%`,
                  action: "Investigate immediately and block if necessary.",
                  scanId: telemetryRecord.id,
                });
              }
            }
          }
        }
      } catch (telemetryErr) {
        console.error("[scan/route] Telemetry/notification error:", telemetryErr);
      }
    })();

    // ── 9b. Persist Scan record (global counter) ───────────────────────────
    // ROOT CAUSE FIX: The previous version only wrote to threatTelemetry
    // (conditionally, score > 50). /api/telemetry counts prisma.scan — which
    // was always empty. Now EVERY completed scan persists a Scan row so the
    // homepage counter accurately reflects global activity across all users.
    await (async () => {
      try {
        const { prisma } = await import("@/lib/db");

        // Attempt to resolve the current user; null is fine (schema allows it).
        let userId: string | null = null;
        try {
          const { auth } = await import("@/lib/auth");
          const session = await auth();
          if (session?.user?.email) {
            const user = await prisma.user.findUnique({
              where: { email: session.user.email },
              select: { id: true },
            });
            userId = user?.id ?? null;
          }
        } catch {
          // Anonymous / unauthenticated scan — userId stays null
        }

        await prisma.scan.create({
          data: {
            url: targetUrl,
            threatLevel,
            score,
            details: {
              virusTotal: {
                status: vtStatus,
                detections: vtDetections,
                total: Math.max(vtTotal, 1),
                skipped: vtSkipped,
              },
              googleSafeBrowsing: { status: gsbStatus, skipped: gsbSkipped },
              phishing: {
                probability: heuristicData.probability,
                indicators: heuristicData.flags,
              },
              ssl: {
                valid: sslResult.valid,
                issuer: sslResult.issuer,
                expiry: sslResult.expiry,
              },
            },
            userId,
          },
        });
      } catch (scanWriteErr) {
        // Non-fatal — the response has already been prepared; log and continue.
        console.error("[scan/route] Failed to persist Scan record:", scanWriteErr);
      }
    })();

    // ── 10. Build & Return Response ───────────────────────────────────────
    return NextResponse.json({
      url: targetUrl,
      threatLevel,
      score,
      scannedAt: new Date().toISOString(),
      details: {
        virusTotal: {
          status: vtStatus,
          detections: vtDetections,
          total: Math.max(vtTotal, 1),
          skipped: vtSkipped,
        },
        googleSafeBrowsing: {
          status: gsbStatus,
          skipped: gsbSkipped,
        },
        phishing: {
          probability: heuristicData.probability,
          indicators: heuristicData.flags,
        },
        ssl: {
          valid: sslResult.valid,
          issuer: sslResult.issuer,
          expiry: sslResult.expiry,
        },
        reputation: {
          score: 100 - score,
          category: "Unknown",
        },
      },
    });
  } catch (error) {
    console.error("[scan/route] Unhandled error:", error);
    return NextResponse.json(
      { error: "Internal server error. Please try again." },
      { status: 500 }
    );
  }
}
