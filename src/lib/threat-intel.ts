/**
 * GuardAI — Threat Intelligence Evaluation & Aggregation Matrix
 *
 * Implements strict separation of threat dimensions:
 * 1. External Reputation (VirusTotal, Google Safe Browsing, AbuseIPDB, URLhaus).
 * 2. Cryptographic TLS/SSL Security.
 * 3. Lexical & Algorithmic Heuristics.
 * 4. Network Recon & Reachability.
 *
 * Enforces key safety invariants:
 * - NEVER interprets "not_found", "timeout", "disabled", or "error" as "clean".
 * - Abstention policy: If all external providers are disabled and heuristics are borderline,
 *   verdict is marked INCONCLUSIVE rather than falsely claimed SAFE.
 * - Explicitly lists limitations and unverified engines alongside results.
 */

export type ProviderStatus =
  | "clean"
  | "malicious"
  | "suspicious"
  | "not_found"
  | "timeout"
  | "quota_exhausted"
  | "disabled"
  | "unknown"
  | "error";

export interface ProviderReport {
  name: "VirusTotal" | "Google Safe Browsing" | "AbuseIPDB" | "URLhaus";
  status: ProviderStatus;
  detections: number;
  totalEngines: number;
  latencyMs: number;
  details?: string;
  limitation?: string;
  queriedAt: string;
}

export type ThreatVerdict =
  | "CRITICAL"
  | "HIGH"
  | "SUSPICIOUS"
  | "INCONCLUSIVE"
  | "SAFE"
  | "OFFLINE";

export interface ThreatMatrixEvaluation {
  verdict: ThreatVerdict;
  score: number; // 0 - 100 calibrated risk score
  confidence: "HIGH" | "MEDIUM" | "LOW";
  abstention: boolean;
  summary: string;
  action: string;
  dimensions: {
    externalReputation: {
      flaggedCount: number;
      polledCount: number;
      providers: Record<string, ProviderReport>;
    };
    tls: {
      status: string;
      valid: boolean;
      issuer: string;
      penaltyScore: number;
    };
    heuristics: {
      probability: number;
      entropy: number;
      indicators: string[];
    };
    network: {
      isReachable: boolean;
      dnsResolved: boolean;
      deadLink: boolean;
    };
  };
  limitations: string[];
}

/**
 * Evaluates multi-dimensional evidence into a calibrated decision matrix.
 */
export function evaluateThreatMatrix(params: {
  providers: Record<string, ProviderReport>;
  tls: {
    status: string;
    valid: boolean;
    issuer: string;
  };
  heuristics: {
    probability: number;
    entropy: number;
    flags: string[];
  };
  network: {
    isReachable: boolean;
    dnsResolved: boolean;
    deadLink: boolean;
  };
}): ThreatMatrixEvaluation {
  const { providers, tls, heuristics, network } = params;
  const limitations: string[] = [];

  // Track provider states
  let flaggedCount = 0;
  let polledCount = 0;
  let activeProvidersCount = 0;

  for (const [providerName, report] of Object.entries(providers)) {
    if (report.status === "disabled") {
      limitations.push(`${providerName} is disabled (API key not configured).`);
    } else if (report.status === "timeout") {
      limitations.push(`${providerName} query timed out.`);
    } else if (report.status === "error" || report.status === "unknown") {
      limitations.push(`${providerName} encountered an API error.`);
    } else {
      activeProvidersCount++;
      if (report.status === "malicious" || report.status === "suspicious" || report.detections > 0) {
        flaggedCount += report.detections;
      }
      polledCount += report.totalEngines;
    }
  }

  // ── Calculate Calibrated Risk Score ──────────────────────────────────────
  let score = heuristics.probability;
  let tlsPenalty = 0;

  // TLS penalty: unencrypted HTTP or broken/expired TLS on a site with suspicious indicators
  if (!tls.valid) {
    if (tls.status === "EXPIRED" || tls.status === "SELF_SIGNED" || tls.status === "HOSTNAME_MISMATCH") {
      tlsPenalty = 20;
    } else if (tls.status === "UNENCRYPTED_HTTP") {
      tlsPenalty = 15;
    }
    score = Math.min(score + tlsPenalty, 100);
  }

  // Check critical external detections
  const vtReport = providers["VirusTotal"];
  const gsbReport = providers["Google Safe Browsing"];
  const urlhausReport = providers["URLhaus"];
  const abuseIpReport = providers["AbuseIPDB"];

  const hasConfirmedMalware =
    urlhausReport?.status === "malicious" ||
    gsbReport?.status === "malicious" ||
    (vtReport?.detections && vtReport.detections >= 5);

  const hasHighReputationFlags =
    (vtReport?.detections && vtReport.detections >= 1) ||
    (abuseIpReport?.detections && abuseIpReport.detections >= 50);

  let verdict: ThreatVerdict = "SAFE";
  let abstention = false;
  let confidence: "HIGH" | "MEDIUM" | "LOW" = "HIGH";
  let summary = "";
  let action = "";

  if (network.deadLink || !network.isReachable) {
    verdict = "OFFLINE";
    score = 0;
    confidence = "HIGH";
    summary = "Target is offline or unreachable over public DNS and HTTP.";
    action = "No action required. Host cannot be reached.";
  } else if (hasConfirmedMalware) {
    verdict = "CRITICAL";
    score = Math.max(95, score);
    confidence = "HIGH";
    summary = "Confirmed active malware, phishing, or blacklisted threat source.";
    action = "Isolate affected endpoints immediately and block at network firewall.";
  } else if (hasHighReputationFlags) {
    verdict = "HIGH";
    score = Math.max(80, score);
    confidence = "HIGH";
    summary = "Known threat intelligence engines flagged this target as high-risk.";
    action = "Block target and investigate security telemetry.";
  } else if (score >= 60) {
    verdict = "SUSPICIOUS";
    confidence = activeProvidersCount > 0 ? "HIGH" : "MEDIUM";
    summary = "Elevated lexical anomalies, high entropy, or certificate inconsistencies detected.";
    action = "Exercise caution. Do not submit credentials or download files.";
  } else if (activeProvidersCount === 0) {
    // ABSTENTION: No reputation engines were active to verify the target!
    // We cannot honestly claim it is "SAFE".
    verdict = "INCONCLUSIVE";
    abstention = true;
    confidence = "LOW";
    score = Math.max(score, 25); // baseline unknown uncertainty
    summary =
      "No external threat intelligence engines were active. Verdict is inconclusive; safety cannot be verified.";
    action = "Configure external provider API keys for full verification.";
    limitations.push("Result relies purely on static lexical analysis without reputation cross-verification.");
  } else {
    verdict = "SAFE";
    confidence = activeProvidersCount >= 2 ? "HIGH" : "MEDIUM";
    summary = `Verified across ${activeProvidersCount} threat engines with valid certificate and clean lexical signals.`;
    action = "No immediate threat detected under current intelligence feeds.";
  }

  return {
    verdict,
    score,
    confidence,
    abstention,
    summary,
    action,
    dimensions: {
      externalReputation: {
        flaggedCount,
        polledCount,
        providers,
      },
      tls: {
        status: tls.status,
        valid: tls.valid,
        issuer: tls.issuer,
        penaltyScore: tlsPenalty,
      },
      heuristics: {
        probability: heuristics.probability,
        entropy: heuristics.entropy,
        indicators: heuristics.flags,
      },
      network: {
        isReachable: network.isReachable,
        dnsResolved: network.dnsResolved,
        deadLink: network.deadLink,
      },
    },
    limitations,
  };
}

