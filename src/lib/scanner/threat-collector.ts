import type { ProviderReport } from "@/lib/threat-intel";

export interface ThreatCollectorOptions {
  onProviderResult?: (report: ProviderReport) => void;
}

/**
 * Orchestrates multi-engine threat intelligence collection across VirusTotal,
 * Google Safe Browsing, AbuseIPDB, and URLhaus with deterministic error handling
 * and explicit provider status reporting.
 */
export async function collectThreatIntel(
  targetUrl: string,
  pinnedIp?: string,
  options?: ThreatCollectorOptions
): Promise<Record<string, ProviderReport>> {
  const providers: Record<string, ProviderReport> = {};

  const recordResult = (report: ProviderReport) => {
    providers[report.name] = report;
    if (options?.onProviderResult) {
      options.onProviderResult(report);
    }
  };

  // ── 1. VirusTotal ───────────────────────────────────────────────────────────
  const vtApiKey = process.env.VIRUSTOTAL_API_KEY?.trim();
  if (vtApiKey) {
    const start = Date.now();
    try {
      const urlId = Buffer.from(targetUrl)
        .toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");

      const vtRes = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: { "x-apikey": vtApiKey },
        signal: AbortSignal.timeout(6000),
      });

      const latencyMs = Date.now() - start;
      if (vtRes.ok) {
        const vtData = await vtRes.json();
        const stats = vtData?.data?.attributes?.last_analysis_stats;
        const malicious = stats?.malicious ?? 0;
        const suspicious = stats?.suspicious ?? 0;
        const detections = malicious + suspicious;
        const total = detections + (stats?.undetected ?? 0) + (stats?.harmless ?? 0);

        recordResult({
          name: "VirusTotal",
          status: detections > 0 ? (malicious >= 3 ? "malicious" : "suspicious") : "clean",
          detections,
          totalEngines: Math.max(total, 1),
          latencyMs,
          details: `${detections}/${total} engines flagged`,
          queriedAt: new Date().toISOString(),
        });
      } else if (vtRes.status === 404) {
        recordResult({
          name: "VirusTotal",
          status: "not_found",
          detections: 0,
          totalEngines: 0,
          latencyMs,
          details: "URL not previously observed in VirusTotal database",
          queriedAt: new Date().toISOString(),
        });
      } else {
        recordResult({
          name: "VirusTotal",
          status: "error",
          detections: 0,
          totalEngines: 0,
          latencyMs,
          details: `HTTP ${vtRes.status}`,
          queriedAt: new Date().toISOString(),
        });
      }
    } catch (e: any) {
      recordResult({
        name: "VirusTotal",
        status: e.name === "TimeoutError" ? "timeout" : "error",
        detections: 0,
        totalEngines: 0,
        latencyMs: Date.now() - start,
        details: e.message,
        queriedAt: new Date().toISOString(),
      });
    }
  } else {
    recordResult({
      name: "VirusTotal",
      status: "disabled",
      detections: 0,
      totalEngines: 0,
      latencyMs: 0,
      limitation: "VIRUSTOTAL_API_KEY environment variable not configured",
      queriedAt: new Date().toISOString(),
    });
  }

  // ── 2. Google Safe Browsing ─────────────────────────────────────────────────
  const gsbApiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY?.trim();
  if (gsbApiKey) {
    const start = Date.now();
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
          signal: AbortSignal.timeout(6000),
        }
      );

      const latencyMs = Date.now() - start;
      if (gsbRes.ok) {
        const gsbData = await gsbRes.json();
        const isFlagged = Array.isArray(gsbData?.matches) && gsbData.matches.length > 0;
        recordResult({
          name: "Google Safe Browsing",
          status: isFlagged ? "malicious" : "clean",
          detections: isFlagged ? gsbData.matches.length : 0,
          totalEngines: 1,
          latencyMs,
          details: isFlagged ? gsbData.matches[0].threatType : "Clean",
          queriedAt: new Date().toISOString(),
        });
      } else {
        recordResult({
          name: "Google Safe Browsing",
          status: "error",
          detections: 0,
          totalEngines: 0,
          latencyMs,
          details: `HTTP ${gsbRes.status}`,
          queriedAt: new Date().toISOString(),
        });
      }
    } catch (e: any) {
      recordResult({
        name: "Google Safe Browsing",
        status: e.name === "TimeoutError" ? "timeout" : "error",
        detections: 0,
        totalEngines: 0,
        latencyMs: Date.now() - start,
        details: e.message,
        queriedAt: new Date().toISOString(),
      });
    }
  } else {
    recordResult({
      name: "Google Safe Browsing",
      status: "disabled",
      detections: 0,
      totalEngines: 0,
      latencyMs: 0,
      limitation: "GOOGLE_SAFE_BROWSING_API_KEY not configured",
      queriedAt: new Date().toISOString(),
    });
  }

  // ── 3. AbuseIPDB (IP Reputation) ───────────────────────────────────────────
  const abuseIpKey = process.env.ABUSEIPDB_KEY?.trim();
  if (abuseIpKey && pinnedIp) {
    const start = Date.now();
    try {
      const abuseRes = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(pinnedIp)}&maxAgeInDays=90`,
        {
          headers: { Key: abuseIpKey, Accept: "application/json" },
          signal: AbortSignal.timeout(3500),
        }
      );
      if (abuseRes.ok) {
        const data = await abuseRes.json();
        const score = data?.data?.abuseConfidenceScore ?? 0;
        recordResult({
          name: "AbuseIPDB",
          status: score >= 50 ? "malicious" : score > 0 ? "suspicious" : "clean",
          detections: score,
          totalEngines: 1,
          latencyMs: Date.now() - start,
          details: `Abuse confidence score: ${score}%`,
          queriedAt: new Date().toISOString(),
        });
      }
    } catch {
      // Degrade gracefully
    }
  }

  // ── 4. URLhaus (Active Malware Tracking) ────────────────────────────────────
  const urlhausKey = process.env.URLHAUS_KEY?.trim();
  if (urlhausKey) {
    const start = Date.now();
    try {
      const res = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
        method: "POST",
        headers: {
          "Auth-Key": urlhausKey,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `url=${encodeURIComponent(targetUrl)}`,
        signal: AbortSignal.timeout(3500),
      });
      if (res.ok) {
        const data = await res.json();
        const isMalware = data.query_status === "ok" && data.url_status === "online";
        recordResult({
          name: "URLhaus",
          status: isMalware ? "malicious" : "clean",
          detections: isMalware ? 1 : 0,
          totalEngines: 1,
          latencyMs: Date.now() - start,
          details: isMalware ? data.threat : "Clean",
          queriedAt: new Date().toISOString(),
        });
      }
    } catch {
      // Degrade gracefully
    }
  }

  return providers;
}

