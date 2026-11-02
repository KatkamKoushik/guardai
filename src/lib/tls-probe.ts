/**
 * GuardAI — Cryptographic TLS & Certificate Verification Probe
 *
 * Provides rigorous, standards-compliant TLS verification:
 * 1. Strict CA root trust chain validation via standard Node.js trust store (`rejectUnauthorized: true`).
 * 2. Hostname identity matching via SNI and Subject Alternative Names (`tls.checkServerIdentity`).
 * 3. Exact validity window enforcement (`valid_from` <= now <= `valid_to`).
 * 4. Distinct status classification: VALID, EXPIRED, SELF_SIGNED, HOSTNAME_MISMATCH,
 *    UNTRUSTED_ROOT, REVOKED, TIMEOUT, CONNECTION_REFUSED, UNENCRYPTED_HTTP, ERROR.
 * 5. Pinned IP transport to prevent DNS-rebinding during probe.
 * 6. Never reports unverified or unauthorized certificates as "valid".
 */

import tls from "tls";
import net from "net";

export type TLSStatus =
  | "VALID"
  | "EXPIRED"
  | "SELF_SIGNED"
  | "HOSTNAME_MISMATCH"
  | "UNTRUSTED_ROOT"
  | "REVOKED"
  | "NO_CERTIFICATE"
  | "CONNECTION_REFUSED"
  | "TIMEOUT"
  | "UNENCRYPTED_HTTP"
  | "ERROR";

export interface TLSProbeResult {
  valid: boolean;
  status: TLSStatus;
  issuer: string;
  subject?: string;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  fingerprint256?: string;
  protocol?: string;
  cipher?: string;
  error?: string;
}

/**
 * Extracts a clean string representation of certificate issuer or subject.
 */
function formatCertField(field?: any): string {
  if (!field) return "Unknown";
  if (typeof field === "string") return field;
  const org = Array.isArray(field.O) ? field.O[0] : field.O;
  const cn = Array.isArray(field.CN) ? field.CN[0] : field.CN;
  return org || cn || (typeof field.toString === "function" ? field.toString() : "Unknown");
}

/**
 * Probes TLS on target host:port with strict validation and rich error categorization.
 */
export async function probeTLS(
  rawUrl: string,
  pinnedIp?: string,
  timeoutMs: number = 5000
): Promise<TLSProbeResult> {
  let parsed: URL;
  try {
    const normalized = rawUrl.startsWith("http://") || rawUrl.startsWith("https://")
      ? rawUrl
      : `https://${rawUrl}`;
    parsed = new URL(normalized);
  } catch {
    return {
      valid: false,
      status: "ERROR",
      issuer: "Unknown",
      error: "Invalid target URL syntax",
    };
  }

  // HTTP targets have no TLS
  if (parsed.protocol === "http:") {
    return {
      valid: false,
      status: "UNENCRYPTED_HTTP",
      issuer: "N/A (Unencrypted HTTP)",
      error: "Target does not use TLS encryption (HTTP only)",
    };
  }

  const hostname = parsed.hostname;
  const port = parsed.port ? parseInt(parsed.port, 10) : 443;
  const connectHost = pinnedIp || hostname;

  // ── Step 1: Strict Verified Probe (rejectUnauthorized: true) ─────────────
  const verifiedResult = await new Promise<TLSProbeResult>((resolve) => {
    let settled = false;
    const settle = (res: TLSProbeResult) => {
      if (settled) return;
      settled = true;
      resolve(res);
    };

    const timer = setTimeout(() => {
      socket.destroy();
      settle({
        valid: false,
        status: "TIMEOUT",
        issuer: "Unknown",
        error: `TLS handshake timed out after ${timeoutMs}ms`,
      });
    }, timeoutMs);

    const socket = tls.connect(
      {
        host: connectHost,
        port,
        servername: hostname, // SNI must match requested hostname
        rejectUnauthorized: true,
      },
      () => {
        clearTimeout(timer);
        try {
          const cert = socket.getPeerCertificate();
          const protocol = socket.getProtocol() || undefined;
          const cipher = socket.getCipher()?.name || undefined;
          socket.destroy();

          if (!cert || !cert.valid_to) {
            settle({
              valid: false,
              status: "NO_CERTIFICATE",
              issuer: "Unknown",
              error: "No peer certificate presented by server",
            });
            return;
          }

          // Check hostname match explicitly
          const hostError = tls.checkServerIdentity(hostname, cert);
          if (hostError) {
            settle({
              valid: false,
              status: "HOSTNAME_MISMATCH",
              issuer: formatCertField(cert.issuer),
              subject: formatCertField(cert.subject),
              error: hostError.message,
            });
            return;
          }

          // Check expiration dates
          const validFromDate = new Date(cert.valid_from);
          const validToDate = new Date(cert.valid_to);
          const now = new Date();

          if (now < validFromDate) {
            settle({
              valid: false,
              status: "EXPIRED",
              issuer: formatCertField(cert.issuer),
              subject: formatCertField(cert.subject),
              validFrom: cert.valid_from,
              validTo: cert.valid_to,
              error: `Certificate is not yet valid (valid from ${cert.valid_from})`,
            });
            return;
          }

          if (now > validToDate) {
            settle({
              valid: false,
              status: "EXPIRED",
              issuer: formatCertField(cert.issuer),
              subject: formatCertField(cert.subject),
              validFrom: cert.valid_from,
              validTo: cert.valid_to,
              error: `Certificate expired on ${cert.valid_to}`,
            });
            return;
          }

          const msRemaining = validToDate.getTime() - now.getTime();
          const daysRemaining = Math.max(0, Math.floor(msRemaining / (1000 * 60 * 60 * 24)));

          settle({
            valid: true,
            status: "VALID",
            issuer: formatCertField(cert.issuer),
            subject: formatCertField(cert.subject),
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            daysRemaining,
            fingerprint256: cert.fingerprint256,
            protocol,
            cipher,
          });
        } catch (err: any) {
          settle({
            valid: false,
            status: "ERROR",
            issuer: "Unknown",
            error: err.message || "Failed to process certificate",
          });
        }
      }
    );

    socket.on("error", (err: any) => {
      clearTimeout(timer);
      socket.destroy();

      const code = err.code || "";
      const msg = err.message || "";

      if (code === "ECONNREFUSED") {
        settle({
          valid: false,
          status: "CONNECTION_REFUSED",
          issuer: "Unknown",
          error: "Connection refused on port 443",
        });
        return;
      }

      if (code === "ETIMEDOUT") {
        settle({
          valid: false,
          status: "TIMEOUT",
          issuer: "Unknown",
          error: "Connection timed out",
        });
        return;
      }

      // Categorize TLS verification errors
      let status: TLSStatus = "ERROR";
      if (code === "CERT_HAS_EXPIRED") {
        status = "EXPIRED";
      } else if (
        code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
        code === "SELF_SIGNED_CERT_IN_CHAIN"
      ) {
        status = "SELF_SIGNED";
      } else if (
        code === "ERR_TLS_CERT_ALTNAME_INVALID" ||
        msg.includes("does not match certificate's altnames")
      ) {
        status = "HOSTNAME_MISMATCH";
      } else if (
        code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" ||
        code === "UNABLE_TO_GET_ISSUER_CERT" ||
        code === "UNABLE_TO_GET_ISSUER_CERT_LOCALLY"
      ) {
        status = "UNTRUSTED_ROOT";
      } else if (code === "CERT_REVOKED") {
        status = "REVOKED";
      }

      settle({
        valid: false,
        status,
        issuer: "Unknown",
        error: `${status}: ${msg}`,
      });
    });
  });

  // If verified, return immediately
  if (verifiedResult.valid) {
    return verifiedResult;
  }

  // ── Step 2: Metadata Inspection Fallback (for unverified/failing certs) ────
  // If the certificate was invalid (e.g. self-signed, expired, wrong host),
  // we do an inspection-only probe to retrieve the actual cert metadata so
  // users can see who issued it and when it expired, while KEEPING valid: false.
  if (
    [
      "EXPIRED",
      "SELF_SIGNED",
      "HOSTNAME_MISMATCH",
      "UNTRUSTED_ROOT",
      "REVOKED",
    ].includes(verifiedResult.status)
  ) {
    try {
      const inspectMeta = await new Promise<{
        issuer?: string;
        subject?: string;
        validFrom?: string;
        validTo?: string;
        fingerprint256?: string;
      }>((resolve) => {
        const inspectTimer = setTimeout(() => {
          inspectSocket.destroy();
          resolve({});
        }, 3000);

        const inspectSocket = tls.connect(
          {
            host: connectHost,
            port,
            servername: hostname,
            rejectUnauthorized: false, // ONLY for diagnostic inspection
          },
          () => {
            clearTimeout(inspectTimer);
            try {
              const cert = inspectSocket.getPeerCertificate();
              inspectSocket.destroy();
              if (cert) {
                resolve({
                  issuer: formatCertField(cert.issuer),
                  subject: formatCertField(cert.subject),
                  validFrom: cert.valid_from,
                  validTo: cert.valid_to,
                  fingerprint256: cert.fingerprint256,
                });
                return;
              }
            } catch {
              // Ignore inspection failure
            }
            resolve({});
          }
        );

        inspectSocket.on("error", () => {
          clearTimeout(inspectTimer);
          inspectSocket.destroy();
          resolve({});
        });
      });

      if (inspectMeta.issuer) {
        verifiedResult.issuer = inspectMeta.issuer;
      }
      if (inspectMeta.subject) {
        verifiedResult.subject = inspectMeta.subject;
      }
      if (inspectMeta.validFrom) {
        verifiedResult.validFrom = inspectMeta.validFrom;
      }
      if (inspectMeta.validTo) {
        verifiedResult.validTo = inspectMeta.validTo;
      }
      if (inspectMeta.fingerprint256) {
        verifiedResult.fingerprint256 = inspectMeta.fingerprint256;
      }
    } catch {
      // Retain verifiedResult as is
    }
  }

  return verifiedResult;
}
