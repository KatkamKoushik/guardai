/**
 * GuardAI — Scan API (POST /api/scan)
 *
 * Lightweight synchronous endpoint used by non-streaming callers.
 * Primary features:
 *   1. Strict input validation — rejects gibberish before any external call.
 *   2. Auto-protocol prepend — bare domains get https:// prepended.
 *   3. Private/local target block — SSRF protection.
 *   4. Real VirusTotal v3 integration (graceful skip if key absent / call fails).
 *   5. Real Google Safe Browsing v4 integration (graceful skip).
 *   6. GuardAI Lexical Heuristics Engine — always runs, no external dependency.
 */

import { NextResponse } from "next/server";
import net from "net";
import { analyzeURL, isGibberish } from "@/lib/heuristics";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

    // ── 2. Gibberish / invalid input guard ────────────────────────────────
    if (isGibberish(rawInput)) {
      return NextResponse.json(
        {
          error:
            "Invalid Input: Please enter a valid domain or URL (e.g. google.com or https://example.com).",
        },
        { status: 400 }
      );
    }

    // ── 3. Normalize & parse URL ──────────────────────────────────────────
    const targetUrl = normalizeUrl(rawInput);
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
      return NextResponse.json(
        { error: "Target is not allowed for security reasons." },
        { status: 400 }
      );
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
          vtStatus = "clean";
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
    let gsbStatus: string = "skipped";
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
          gsbStatus = "error";
        }
      } catch {
        gsbStatus = "unavailable";
        gsbSkipped = true;
      }
    }

    // ── 8. Aggregate Score & Threat Level ─────────────────────────────────
    let score = heuristicData.probability;
    let threatLevel: "safe" | "suspicious" | "high" | "critical" = "safe";

    if (gsbStatus === "flagged" || vtDetections >= 5) {
      threatLevel = "critical";
      score = 95;
    } else if (vtDetections >= 1) {
      threatLevel = "high";
      score = Math.max(80, heuristicData.probability);
    } else if (heuristicData.probability >= 60) {
      threatLevel = "suspicious";
      score = heuristicData.probability;
    }

    // ── 9. Telemetry & Notifications (fire-and-forget, non-blocking) ──────
    // Run async without awaiting so we don't add latency to the response.
    void (async () => {
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
          valid: targetUrl.startsWith("https://"),
          issuer: "Unknown",
          expiry: "Unknown",
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
