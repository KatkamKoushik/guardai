import { NextRequest } from "next/server";
import type { Prisma } from "@prisma/client";
import { analyzeURL, isGibberish } from "@/lib/heuristics";
import { auth } from "@/lib/auth";
import { logAuditAction } from "@/lib/audit";
import { validateTargetForSSRF, safeFetch } from "@/lib/ssrf";
import { probeTLS } from "@/lib/tls-probe";
import { evaluateThreatMatrix } from "@/lib/threat-intel";
import {
  lookupGeoIp,
  lookupDomainRegistration,
  analyzeSecurityHeaders,
  collectThreatIntel,
} from "@/lib/scanner";

export const dynamic = "force-dynamic";

function refangUrl(input: string): string {
  return input
    .replace(/^hxxps?:(\/\/)?/i, (match) =>
      match.toLowerCase().startsWith("hxxps") ? "https://" : "http://"
    )
    .replace(/^hxxp\[s?\]?\[:?\/\/\]/i, "https://")
    .replace(/^hxxp\[:?\/\/\]/i, "http://");
}

export async function GET(req: NextRequest) {
  const session = await auth();
  const userId = session?.user?.email || "Anonymous";

  const urlParams = new URL(req.url);
  const targetUrl = urlParams.searchParams.get("url");

  if (!targetUrl) {
    return new Response("Missing URL parameter", { status: 400 });
  }

  let isClosed = false;

  const stream = new ReadableStream({
    async start(controller) {
      const sendEvent = (data: any) => {
        if (!isClosed) {
          try {
            controller.enqueue(`data: ${JSON.stringify(data)}\n\n`);
          } catch {
            isClosed = true;
          }
        }
      };

      try {
        // ── 1. Defanged URL sanitization ─────────────────────────────────────
        const refangedUrl = refangUrl(targetUrl);

        // ── 2. Input Validation Gate ─────────────────────────────────────────
        if (isGibberish(refangedUrl)) {
          sendEvent({
            step: "Initialization",
            status: "error",
            progress: 0,
            log: "Invalid Input: Please enter a valid domain or URL (e.g. google.com or https://example.com).",
          });
          controller.close();
          return;
        }

        const normalizedTarget = refangedUrl.startsWith("http")
          ? refangedUrl
          : `https://${refangedUrl}`;

        // ── 3. SSRF & DNS Rebinding Security Gate ────────────────────────────
        sendEvent({
          step: "Initialization",
          status: "pending",
          progress: 5,
          log: "Running SSRF and egress safety validation...",
        });

        const ssrfValidation = await validateTargetForSSRF(normalizedTarget);
        if (!ssrfValidation.allowed) {
          sendEvent({
            step: "Initialization",
            status: "error",
            progress: 10,
            log: `SSRF Blocked: ${ssrfValidation.reason}`,
          });
          controller.close();
          return;
        }

        const hostname = ssrfValidation.hostname!;
        const pinnedIp = ssrfValidation.pinnedIp!;

        // Prevent self-scanning loops
        const appHost = req.headers.get("host")?.split(":")[0];
        if (hostname === appHost || hostname === "guardai-six.vercel.app") {
          sendEvent({
            step: "Initialization",
            status: "error",
            progress: 10,
            log: "Self-scan prohibited: Loop detection prevented scanning of GuardAI itself.",
          });
          controller.close();
          return;
        }

        sendEvent({
          step: "Initialization",
          status: "success",
          progress: 10,
          log: `Target verified safe for public scan: ${hostname} (Pinned IP: ${pinnedIp})`,
        });

        // ── STEP 1: DNS & Network Recon ──────────────────────────────────────
        sendEvent({
          step: "Network Recon",
          status: "pending",
          progress: 15,
          log: `Validated DNS records: [ ${ssrfValidation.resolvedIps?.join(", ")} ]`,
        });

        sendEvent({
          step: "Network Recon",
          status: "pending",
          progress: 20,
          log: `Resolving Geolocation & ASN telemetry for ${pinnedIp}...`,
        });

        const [geoIp, whois] = await Promise.all([
          lookupGeoIp(pinnedIp),
          lookupDomainRegistration(hostname),
        ]);

        if (geoIp) {
          sendEvent({
            step: "Network Recon",
            status: "success",
            progress: 25,
            log: `GeoIP: ${geoIp.city || "Unknown City"}, ${geoIp.country || "Unknown Country"} | ASN: ${geoIp.asn || "Unknown"}`,
          });
        }

        if (whois && whois.registrar !== "Data Unavailable") {
          sendEvent({
            step: "Network Recon",
            status: "success",
            progress: 28,
            log: `WHOIS/RDAP: Registrar: ${whois.registrar} | Domain Age: ${whois.domainAgeFormatted}`,
          });
        }

        // ── STEP 2: Cryptographic SSL/TLS Certificate Verification ───────────
        sendEvent({
          step: "Network Recon",
          status: "pending",
          progress: 30,
          log: "Performing cryptographic TLS handshake & certificate-chain validation...",
        });

        const sslProbe = await probeTLS(normalizedTarget, pinnedIp, 5000);
        if (sslProbe.valid) {
          sendEvent({
            step: "Network Recon",
            status: "success",
            progress: 35,
            log: `TLS Certificate cryptographically verified: ${sslProbe.status} | Issuer: ${sslProbe.issuer}`,
          });
        } else {
          sendEvent({
            step: "Network Recon",
            status: "flagged",
            progress: 35,
            log: `TLS Certificate verification failed: ${sslProbe.status} (${sslProbe.error || "Untrusted"})`,
          });
        }

        // ── STEP 3: Multi-Path Directory Probing (SSRF Pinned Transport) ──────
        sendEvent({
          step: "Network Recon",
          status: "pending",
          progress: 40,
          log: "Running SSRF-safe multi-path directory probes...",
        });

        let rawHeaders: Record<string, string | undefined> = {};
        let isDeadLink = false;

        try {
          const probeRes = await safeFetch(normalizedTarget, {
            method: "HEAD",
            timeoutMs: 3000,
          });
          rawHeaders = probeRes.headers;

          sendEvent({
            step: "Network Recon",
            status: "success",
            progress: 45,
            log: `Target responded with HTTP ${probeRes.status}. Pinned transport validated.`,
          });
        } catch (e: any) {
          isDeadLink = true;
          sendEvent({
            step: "Network Recon",
            status: "flagged",
            progress: 45,
            log: `Target network probe failed: ${e.message}`,
          });
        }

        const securityHeaders = analyzeSecurityHeaders(rawHeaders);

        // ── STEP 4: Threat Intelligence Feeds ─────────────────────────────────
        sendEvent({
          step: "Threat Intel",
          status: "pending",
          progress: 50,
          log: "Querying external threat intelligence engines...",
        });

        const providers = await collectThreatIntel(normalizedTarget, pinnedIp, {
          onProviderResult: (report) => {
            sendEvent({
              step: "Threat Intel",
              status: report.status === "clean" ? "success" : report.status === "disabled" ? "pending" : "flagged",
              progress: 65,
              log: `${report.name}: ${report.status.toUpperCase()} (${report.details || report.limitation || "Processed"})`,
            });
          },
        });

        // ── STEP 5: Lexical & Algorithmic Heuristics ─────────────────────────
        sendEvent({
          step: "Lexical Analysis",
          status: "pending",
          progress: 80,
          log: "Running Shannon entropy & phishing lexical analyzers...",
        });

        const heuristicData = analyzeURL(normalizedTarget);

        sendEvent({
          step: "Lexical Analysis",
          status: "success",
          progress: 85,
          log: `Entropy: ${heuristicData.entropy.toFixed(3)} | Phishing probability: ${heuristicData.probability}%`,
        });

        // ── STEP 6: Multi-Dimensional Matrix Evaluation ───────────────────────
        sendEvent({
          step: "Score Matrix",
          status: "pending",
          progress: 90,
          log: "Synthesizing multi-dimensional evidence matrix...",
        });

        const evaluation = evaluateThreatMatrix({
          providers,
          tls: {
            status: sslProbe.status,
            valid: sslProbe.valid,
            issuer: sslProbe.issuer,
          },
          heuristics: {
            probability: heuristicData.probability,
            entropy: heuristicData.entropy,
            flags: heuristicData.flags,
          },
          network: {
            isReachable: !isDeadLink,
            dnsResolved: (ssrfValidation.resolvedIps?.length ?? 0) > 0,
            deadLink: isDeadLink,
          },
        });

        const threatLevel: "safe" | "suspicious" | "high" | "critical" | "offline" =
          evaluation.verdict === "CRITICAL"
            ? "critical"
            : evaluation.verdict === "HIGH"
            ? "high"
            : evaluation.verdict === "SUSPICIOUS" || evaluation.verdict === "INCONCLUSIVE"
            ? "suspicious"
            : evaluation.verdict === "OFFLINE"
            ? "offline"
            : "safe";

        sendEvent({
          step: "Score Matrix",
          status: threatLevel === "critical" || threatLevel === "high" ? "flagged" : "success",
          progress: 95,
          log: `Evaluation: ${evaluation.verdict} (Score: ${evaluation.score}/100, Confidence: ${evaluation.confidence})`,
        });

        const resultData = {
          url: normalizedTarget,
          threatLevel,
          score: evaluation.score,
          verdict: evaluation.verdict,
          confidence: evaluation.confidence,
          abstention: evaluation.abstention,
          summary: evaluation.summary,
          action: evaluation.action,
          limitations: evaluation.limitations,
          details: {
            evaluation,
            virusTotal: {
              status: providers["VirusTotal"]?.status ?? "skipped",
              detections: providers["VirusTotal"]?.detections ?? 0,
              total: providers["VirusTotal"]?.totalEngines ?? 1,
              skipped: providers["VirusTotal"]?.status === "disabled",
            },
            googleSafeBrowsing: {
              status: providers["Google Safe Browsing"]?.status ?? "skipped",
              skipped: providers["Google Safe Browsing"]?.status === "disabled",
            },
            phishing: {
              probability: heuristicData.probability,
              indicators: heuristicData.flags,
            },
            ssl: {
              valid: sslProbe.valid,
              status: sslProbe.status,
              issuer: sslProbe.issuer,
              expiry: sslProbe.validTo || "Unknown",
              error: sslProbe.error,
            },
            reputation: {
              score: 100 - evaluation.score,
              category: evaluation.verdict,
            },
            geoIp,
            securityHeaders,
            whois,
          },
        };

        // Audit Logging
        await logAuditAction(
          "DEEP_SCAN",
          normalizedTarget,
          "success",
          threatLevel,
          JSON.stringify(resultData),
          userId
        );

        // Persist Scan Record
        (async () => {
          try {
            const { prisma } = await import("@/lib/db");
            let resolvedUserId: string | null = null;
            if (session?.user?.email) {
              const u = await prisma.user.findUnique({
                where: { email: session.user.email },
                select: { id: true },
              });
              resolvedUserId = u?.id ?? null;
            }

            await prisma.scan.create({
              data: {
                url: normalizedTarget,
                threatLevel,
                score: evaluation.score,
                details: resultData.details as unknown as Prisma.InputJsonValue,
                userId: resolvedUserId,
              },
            });
          } catch (writeErr) {
            console.error("[stream/route] Failed to persist scan record:", writeErr);
          }
        })();

        // Notifications Dispatch (if critical/high)
        const alertUserEmail = session?.user?.email;
        if (evaluation.score >= 50 && alertUserEmail) {
          (async () => {
            try {
              const { prisma } = await import("@/lib/db");
              const user = await prisma.user.findUnique({
                where: { email: alertUserEmail },
              });
              if (user?.id) {
                const { notifyUserForScan } = await import("@/lib/notifications");
                await notifyUserForScan(user.id, {
                  url: normalizedTarget,
                  score: evaluation.score,
                  severity:
                    evaluation.score >= 90
                      ? "critical"
                      : evaluation.score >= 70
                      ? "high"
                      : "medium",
                  explanation: evaluation.summary,
                  vtScore: `${providers["VirusTotal"]?.detections ?? 0} detections`,
                  sslStatus: sslProbe.valid ? `Valid (${sslProbe.issuer})` : `Invalid: ${sslProbe.status}`,
                  missingHeaders: securityHeaders.missingHeaders.join(", ") || "None",
                  mlScore: `Phishing Probability: ${heuristicData.probability}%`,
                  action: evaluation.action,
                  scanId: user.id,
                });
              }
            } catch (notifErr) {
              console.error("[stream] Notification dispatch error:", notifErr);
            }
          })();
        }

        sendEvent({
          step: "Complete",
          status: "success",
          progress: 100,
          log: "Scan complete.",
          result: resultData,
        });
        controller.close();
      } catch (err: any) {
        await logAuditAction(
          "DEEP_SCAN",
          targetUrl || "unknown",
          "failed",
          "critical",
          `Scan failed: ${err.message}`,
          userId
        );
        sendEvent({
          step: "Error",
          status: "error",
          progress: 100,
          log: `Fatal error: ${err.message}`,
        });
        try {
          controller.close();
        } catch {}
      }
    },
    cancel() {
      isClosed = true;
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}
