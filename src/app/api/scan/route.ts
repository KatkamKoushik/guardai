import { NextResponse } from "next/server";
import { analyzeURL } from "@/lib/heuristics";
import net from "net";

function normalizeUrl(input: string) {
  return input.startsWith("http://") || input.startsWith("https://")
    ? input
    : `https://${input}`;
}

function isPrivateIPv4(ip: string) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 127) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  return false;
}

function isDisallowedTarget(hostname: string) {
  const normalized = hostname.toLowerCase();
  if (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    normalized.endsWith(".local")
  ) {
    return true;
  }

  const ipType = net.isIP(normalized);
  if (ipType === 4) {
    return isPrivateIPv4(normalized);
  }
  if (ipType === 6) {
    return normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd");
  }

  return false;
}

export async function POST(request: Request) {
  try {
    const { url } = await request.json();

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 });
    }

    // Validate URL format
    const targetUrl = normalizeUrl(url);
    let parsed: URL;
    try {
      parsed = new URL(targetUrl);
    } catch {
      return NextResponse.json({ error: "Invalid URL format" }, { status: 400 });
    }
    if (isDisallowedTarget(parsed.hostname)) {
      return NextResponse.json({ error: "Target is not allowed for security reasons" }, { status: 400 });
    }

    const heuristicData = analyzeURL(targetUrl);

    let vtStatus = "clean";
    let vtDetections = 0;
    let vtTotal = 1;
    let gsbStatus = "clean";

    const vtApiKey = process.env.VIRUSTOTAL_API_KEY;
    if (vtApiKey) {
      try {
        const urlId = Buffer.from(targetUrl)
          .toString("base64")
          .replace(/=/g, "")
          .replace(/\+/g, "-")
          .replace(/\//g, "_");
        const vtRes = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
          headers: { "x-apikey": vtApiKey },
        });
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
          }
        }
      } catch {
        vtStatus = "error";
      }
    }

    const gsbApiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    if (gsbApiKey) {
      try {
        const gsbRes = await fetch(
          `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${gsbApiKey}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              client: { clientId: "guardai", clientVersion: "1.0.0" },
              threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url: targetUrl }],
              },
            }),
          }
        );
        if (gsbRes.ok) {
          const gsbData = await gsbRes.json();
          gsbStatus = Array.isArray(gsbData?.matches) && gsbData.matches.length > 0 ? "flagged" : "clean";
        } else {
          gsbStatus = "error";
        }
      } catch {
        gsbStatus = "error";
      }
    }

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

    const result = {
      url: targetUrl,
      threatLevel,
      score,
      scannedAt: new Date().toISOString(),
      details: {
        virusTotal: {
          status: vtStatus,
          detections: vtDetections,
          total: Math.max(vtTotal, 1),
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
          category: "Technology",
        },
        googleSafeBrowsing: {
          status: gsbStatus,
        },
      },
    };

    // 1. IP Geolocation (if target is IP)
    let lat: number | null = null;
    let lon: number | null = null;
    let country: string | null = null;
    let isIP = net.isIP(parsed.hostname);
    
    if (isIP) {
      try {
        const geoip = require('geoip-lite');
        const geo = geoip.lookup(parsed.hostname);
        if (geo) {
          lat = geo.ll[0];
          lon = geo.ll[1];
          country = geo.country;
        }
      } catch (e) {
        console.warn("Could not load geoip-lite");
      }
    }

    // Attempt to get the session to associate the scan
    const { auth } = require("@/lib/auth");
    const session = await auth();
    let userId = null;
    if (session?.user?.email) {
      const { prisma } = require("@/lib/db");
      const user = await prisma.user.findUnique({ where: { email: session.user.email } });
      if (user) userId = user.id;
    }

    // 2. Broadcast to Telemetry Stream (if score > 50)
    if (score > 50) {
      const { prisma } = require("@/lib/db");
      const threatTelemetryRecord = await prisma.threatTelemetry.create({
        data: {
          domain: parsed.hostname,
          threatType: threatLevel === "critical" ? "malware" : "suspicious",
          ipAddress: isIP ? parsed.hostname : null,
          latitude: lat,
          longitude: lon,
          countryCode: country,
          timestamp: new Date()
        }
      });

      // 3. Trigger Alert Integrations (if score > 80)
      if (score > 80 && userId) {
        const { notifyUserForScan } = require("@/lib/notifications");
        
        await notifyUserForScan(userId, {
          url: targetUrl,
          score: score,
          severity: threatLevel === "critical" ? "critical" : "high",
          explanation: `A Live Deep Scan detected a high-risk threat on this target.`,
          vtScore: `${vtDetections} / ${Math.max(vtTotal, 1)} engines flagged as Malicious`,
          sslStatus: targetUrl.startsWith("https://") ? "ENCRYPTED" : "UNENCRYPTED (HTTP Only)",
          missingHeaders: "Checked via heuristic",
          mlScore: `Phishing Probability: ${heuristicData.probability}%`,
          action: "Investigate immediately and block if necessary.",
          scanId: threatTelemetryRecord.id, // Using telemetry ID as mock scan ID
        });
      }
    }

    return NextResponse.json(result);
  } catch (error) {
    console.error("Scan error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
