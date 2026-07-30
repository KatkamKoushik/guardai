import { NextRequest } from "next/server";
import dns from "dns/promises";
import tls from "tls";
import net from "net";
import { analyzeURL } from "@/lib/heuristics";
import { auth } from "@/lib/auth";
import { logAuditAction } from "@/lib/audit";

export const dynamic = "force-dynamic";

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
          controller.enqueue(`data: ${JSON.stringify(data)}\n\n`);
        }
      };

      try {
        let hostname = "";
        try {
          const parsed = new URL(targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`);
          hostname = parsed.hostname;
          if (isDisallowedTarget(hostname)) {
            sendEvent({ step: "Initialization", status: "error", progress: 10, log: "Target is not allowed for security reasons." });
            controller.close();
            return;
          }
        } catch (e) {
          sendEvent({ step: "Initialization", status: "error", progress: 10, log: "Invalid URL format." });
          controller.close();
          return;
        }

        sendEvent({ step: "Initialization", status: "success", progress: 5, log: `Target locked: ${hostname}` });
        
        // ==============================================
        // STEP 1: DNS & Network Recon
        // ==============================================
        sendEvent({ step: "Network Recon", status: "pending", progress: 10, log: "Resolving DNS A/AAAA records..." });
        
        let dnsRecords: string[] = [];
        let dnsFailed = false;
        try {
          const records = await dns.resolveAny(hostname);
          dnsRecords = records.map((r: any) => r.address || r.value).filter(Boolean);
          sendEvent({ step: "Network Recon", status: "success", progress: 15, log: `DNS Resolved. Found ${dnsRecords.length} records.` });
        } catch (error: any) {
          dnsFailed = true;
          sendEvent({ step: "Network Recon", status: "flagged", progress: 15, log: `DNS lookup failed (ECONNREFUSED/NXDOMAIN): ${error.message}` });
        }

        let geoIp = null;
        if (dnsRecords.length > 0) {
          try {
            sendEvent({ step: "Network Recon", status: "pending", progress: 17, log: `Fetching GeoIP data for ${dnsRecords[0]}...` });
            const geoResponse = await fetch(`http://ip-api.com/json/${dnsRecords[0]}`);
            if (geoResponse.ok) {
              geoIp = await geoResponse.json();
              sendEvent({ step: "Network Recon", status: "success", progress: 19, log: `GeoIP: ${geoIp.city || 'Unknown'}, ${geoIp.country || 'Unknown'}` });
            }
          } catch (e) {
            console.error("GeoIP failed", e);
          }
        }

        sendEvent({ step: "Network Recon", status: "pending", progress: 20, log: "Checking SSL/TLS certificate validity..." });
        
        let sslValid = false;
        let sslIssuer = "Unknown";
        let sslExpiry = "Unknown";

        try {
          const cert = await new Promise<tls.PeerCertificate>((resolve, reject) => {
            const socket = tls.connect({ host: hostname, port: 443, servername: hostname }, () => {
              const cert = socket.getPeerCertificate();
              socket.end();
              resolve(cert);
            });
            socket.on('error', reject);
            setTimeout(() => { socket.destroy(); reject(new Error("Timeout")); }, 3000);
          });
          
          sslValid = true;
          const issuerOrg = Array.isArray(cert.issuer.O) ? cert.issuer.O[0] : cert.issuer.O;
          const issuerCn = Array.isArray(cert.issuer.CN) ? cert.issuer.CN[0] : cert.issuer.CN;
          sslIssuer = issuerOrg || issuerCn || "Unknown";
          sslExpiry = new Date(cert.valid_to).toLocaleDateString();
          sendEvent({ step: "Network Recon", status: "success", progress: 25, log: `SSL verified. Issuer: ${sslIssuer}` });
        } catch (error: any) {
          sendEvent({ step: "Network Recon", status: "flagged", progress: 25, log: `SSL verification failed or missing (HTTP).` });
        }

        let securityHeaders = { hsts: false, xFrameOptions: false, csp: false };
        try {
          sendEvent({ step: "Network Recon", status: "pending", progress: 28, log: "Fetching HTTP Security Headers..." });
          const headResponse = await fetch(targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`, { method: 'HEAD', signal: AbortSignal.timeout(3000) });
          const headers = headResponse.headers;
          securityHeaders.hsts = headers.has("strict-transport-security");
          securityHeaders.xFrameOptions = headers.has("x-frame-options");
          securityHeaders.csp = headers.has("content-security-policy");
          sendEvent({ step: "Network Recon", status: "success", progress: 29, log: "Security Headers analyzed." });
        } catch (e) {
          sendEvent({ step: "Network Recon", status: "flagged", progress: 29, log: "Could not fetch Security Headers." });
        }

        // ==============================================
        // STEP 2: Threat Intel Lookup (VirusTotal + Google Safe Browsing)
        // ==============================================
        sendEvent({ step: "Threat Intel", status: "pending", progress: 30, log: "Querying Threat Intelligence databases..." });
        
        let vtStatus = "clean";
        let vtDetections = 0;
        let vtTotal = 0;
        let vtSkipped = false;
        const vtApiKey = process.env.VIRUSTOTAL_API_KEY;

        if (vtApiKey && vtApiKey.trim() !== "") {
          try {
            const urlId = Buffer.from(targetUrl).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
            const vtResponse = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
              headers: { "x-apikey": vtApiKey }
            });
            
            if (vtResponse.ok) {
              try {
                const vtData = await vtResponse.json();
                const stats = vtData.data.attributes.last_analysis_stats;
                vtDetections = stats.malicious + stats.suspicious;
                vtTotal = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;
                vtStatus = vtDetections > 0 ? "flagged" : "clean";
                sendEvent({ step: "Threat Intel", status: vtDetections > 0 ? "flagged" : "success", progress: 40, log: `VirusTotal: ${vtDetections}/${vtTotal} engines flagged.` });
              } catch (parseError) {
                sendEvent({ step: "Threat Intel", status: "flagged", progress: 40, log: "VirusTotal: Failed to parse API response." });
              }
            } else if (vtResponse.status === 404) {
              sendEvent({ step: "Threat Intel", status: "success", progress: 40, log: "VirusTotal: URL not found in recent scans." });
            } else {
              sendEvent({ step: "Threat Intel", status: "flagged", progress: 40, log: `VirusTotal API error: ${vtResponse.status}` });
            }
          } catch (error: any) {
            sendEvent({ step: "Threat Intel", status: "flagged", progress: 40, log: `VirusTotal error: ${error.message}` });
          }
        } else {
          vtSkipped = true;
          sendEvent({ step: "Threat Intel", status: "flagged", progress: 40, log: "VirusTotal skipped (API key missing)." });
        }

        let gsbStatus = "clean";
        let gsbSkipped = false;
        const gsbApiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

        if (gsbApiKey && gsbApiKey.trim() !== "") {
          try {
            const gsbResponse = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${gsbApiKey}`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                client: { clientId: "guardai", clientVersion: "1.0.0" },
                threatInfo: {
                  threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                  platformTypes: ["ANY_PLATFORM"],
                  threatEntryTypes: ["URL"],
                  threatEntries: [{ url: targetUrl }]
                }
              })
            });

            if (gsbResponse.ok) {
              try {
                const gsbData = await gsbResponse.json();
                if (gsbData.matches && gsbData.matches.length > 0) {
                  gsbStatus = "flagged";
                  sendEvent({ step: "Threat Intel", status: "flagged", progress: 50, log: `[ FLAGGED ] Google Safe Browsing: Blacklisted (Malware/Phishing).` });
                } else {
                  sendEvent({ step: "Threat Intel", status: "success", progress: 50, log: `Google Safe Browsing: Clean.` });
                }
              } catch (parseError) {
                sendEvent({ step: "Threat Intel", status: "flagged", progress: 50, log: "Google Safe Browsing: Failed to parse API response." });
              }
            } else {
              sendEvent({ step: "Threat Intel", status: "flagged", progress: 50, log: `Google Safe Browsing API error: ${gsbResponse.status}` });
            }
          } catch (error: any) {
            sendEvent({ step: "Threat Intel", status: "flagged", progress: 50, log: `Google Safe Browsing error: ${error.message}` });
          }
        } else {
          gsbSkipped = true;
          sendEvent({ step: "Threat Intel", status: "flagged", progress: 50, log: "Google Safe Browsing skipped (API key missing)." });
        }

        // ==============================================
        // STEP 3: ML Lexical Analysis
        // ==============================================
        sendEvent({ step: "Lexical Analysis", status: "pending", progress: 55, log: "Extracting 15+ lexical features..." });
        await new Promise(r => setTimeout(r, 500)); 
        
        const heuristicData = analyzeURL(targetUrl);
        
        sendEvent({ step: "Lexical Analysis", status: "success", progress: 65, log: `Calculated Shannon Entropy: ${heuristicData.entropy.toFixed(3)}` });
        await new Promise(r => setTimeout(r, 500)); 
        
        if (heuristicData.flags.length > 0) {
          sendEvent({ step: "Lexical Analysis", status: "flagged", progress: 70, log: `Found indicators: ${heuristicData.flags.join(", ")}` });
        } else {
          sendEvent({ step: "Lexical Analysis", status: "success", progress: 70, log: "No suspicious lexical patterns found." });
        }
        
        sendEvent({ step: "Lexical Analysis", status: "success", progress: 75, log: `Phishing probability score: ${heuristicData.probability}%` });
        await new Promise(r => setTimeout(r, 500));

        // ==============================================
        // STEP 4: Final Matrix & Severity Overrides
        // ==============================================
        sendEvent({ step: "Score Matrix", status: "pending", progress: 85, log: "Aggregating threat matrices with severity overrides..." });
        await new Promise(r => setTimeout(r, 500));

        let finalScore = 0;
        let threatLevel = "safe";
        const isDataIncomplete = vtSkipped && gsbSkipped;

        if (gsbStatus === "flagged" || vtDetections > 4) {
          // CRITICAL OVERRIDE
          finalScore = 95;
          threatLevel = "critical";
          sendEvent({ step: "Score Matrix", status: "error", progress: 90, log: "CRITICAL OVERRIDE: Confirmed Blacklisted / High VT Detections." });
        } else if ((vtDetections >= 1 && vtDetections <= 3) || dnsFailed) {
          // HIGH RISK
          finalScore = 85;
          threatLevel = "high";
          sendEvent({ step: "Score Matrix", status: "error", progress: 90, log: "HIGH RISK OVERRIDE: Low VT Detections or DNS Failure." });
        } else if (heuristicData.probability > 60 || !sslValid) {
          // SUSPICIOUS
          finalScore = Math.max(60, heuristicData.probability);
          threatLevel = "suspicious";
          sendEvent({ step: "Score Matrix", status: "flagged", progress: 90, log: "SUSPICIOUS: High ML Probability or Invalid SSL." });
        } else if (isDataIncomplete) {
          // INCOMPLETE THREAT DATA
          finalScore = Math.max(30, heuristicData.probability);
          threatLevel = "suspicious";
          sendEvent({ step: "Score Matrix", status: "flagged", progress: 90, log: "INCOMPLETE DATA: Threat Intel engines skipped. Adjusting baseline risk." });
        } else {
          // SAFE
          finalScore = Math.max(0, heuristicData.probability);
          threatLevel = "safe";
          sendEvent({ step: "Score Matrix", status: "success", progress: 90, log: "SAFE: Clean Threat Intel and Low ML Probability." });
        }

        sendEvent({ step: "Score Matrix", status: "success", progress: 95, log: `Final risk score computed: ${finalScore}` });
        await new Promise(r => setTimeout(r, 500));

        const resultData = {
          url: targetUrl,
          threatLevel,
          score: finalScore,
          details: {
            virusTotal: { status: vtStatus, detections: vtDetections, total: Math.max(vtTotal, 1), skipped: vtSkipped },
            googleSafeBrowsing: { status: gsbStatus, skipped: gsbSkipped },
            phishing: { probability: heuristicData.probability, indicators: heuristicData.flags },
            ssl: { valid: sslValid, issuer: sslIssuer, expiry: sslExpiry },
            reputation: { score: 100 - finalScore, category: "Unknown" },
            geoIp,
            securityHeaders
          }
        };

        await logAuditAction(
          "DEEP_SCAN",
          targetUrl,
          "success",
          threatLevel,
          `Scan completed with score ${finalScore}`,
          userId
        );

        sendEvent({ step: "Complete", status: "success", progress: 100, log: "Scan complete.", result: resultData });
        controller.close();
      } catch (err: any) {
        await logAuditAction("DEEP_SCAN", targetUrl || "unknown", "failed", "critical", `Scan failed: ${err.message}`, userId);
        sendEvent({ step: "Error", status: "error", progress: 100, log: `Fatal error: ${err.message}` });
        controller.close();
      }
    },
    cancel() {
      isClosed = true;
    }
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      "Connection": "keep-alive",
    },
  });
}
