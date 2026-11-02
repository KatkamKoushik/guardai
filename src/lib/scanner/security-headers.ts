import type { SecurityHeadersReport } from "./types";

/**
 * Evaluates HTTP security response headers and assigns an engineering grade.
 */
export function analyzeSecurityHeaders(
  headers: Record<string, string | undefined>
): SecurityHeadersReport {
  // Normalize header keys to lowercase
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value !== undefined) {
      normalized[key.toLowerCase()] = value;
    }
  }

  const hsts = Boolean(normalized["strict-transport-security"]);
  const xFrameOptions = Boolean(normalized["x-frame-options"]);
  const csp = Boolean(normalized["content-security-policy"]);
  const xContentTypeOptions = normalized["x-content-type-options"]?.toLowerCase() === "nosniff";
  const referrerPolicy = Boolean(normalized["referrer-policy"]);
  const permissionsPolicy = Boolean(normalized["permissions-policy"] || normalized["feature-policy"]);

  const missingHeaders: string[] = [];
  if (!hsts) missingHeaders.push("Strict-Transport-Security (HSTS)");
  if (!csp) missingHeaders.push("Content-Security-Policy (CSP)");
  if (!xFrameOptions) missingHeaders.push("X-Frame-Options");
  if (!xContentTypeOptions) missingHeaders.push("X-Content-Type-Options: nosniff");
  if (!referrerPolicy) missingHeaders.push("Referrer-Policy");
  if (!permissionsPolicy) missingHeaders.push("Permissions-Policy");

  // Grade calculation based on foundational defensive controls
  let score = 0;
  if (hsts) score += 25;
  if (csp) score += 30;
  if (xFrameOptions) score += 15;
  if (xContentTypeOptions) score += 15;
  if (referrerPolicy) score += 10;
  if (permissionsPolicy) score += 5;

  let grade: SecurityHeadersReport["grade"] = "F";
  if (score >= 90) grade = "A";
  else if (score >= 75) grade = "B";
  else if (score >= 50) grade = "C";
  else if (score >= 30) grade = "D";

  return {
    hsts,
    xFrameOptions,
    csp,
    xContentTypeOptions,
    referrerPolicy,
    permissionsPolicy,
    missingHeaders,
    grade,
  };
}

