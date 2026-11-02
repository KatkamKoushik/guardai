/**
 * GuardAI — Runtime Environment Validation & Configuration
 *
 * Validates critical environment variables at startup.
 * Enforces production invariants:
 * - NEXTAUTH_SECRET must be defined and sufficiently long in production.
 * - Warns if threat intelligence provider API keys are missing.
 * - Prevents startup in insecure states when NODE_ENV === 'production'.
 */

export interface AppConfig {
  nodeEnv: string;
  isProduction: boolean;
  databaseUrl?: string;
  nextAuthUrl?: string;
  nextAuthSecret?: string;
  virusTotalApiKey?: string;
  googleSafeBrowsingApiKey?: string;
  abuseIpDbApiKey?: string;
  urlhausApiKey?: string;
}

export function validateEnvironment(): { valid: boolean; errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];
  const nodeEnv = process.env.NODE_ENV || "development";
  const isProduction = nodeEnv === "production";

  // Production critical invariants
  if (isProduction) {
    if (!process.env.DATABASE_URL) {
      errors.push("CRITICAL: DATABASE_URL must be set in production.");
    }

    if (!process.env.NEXTAUTH_SECRET) {
      errors.push("CRITICAL: NEXTAUTH_SECRET is required in production.");
    } else if (process.env.NEXTAUTH_SECRET.length < 32) {
      errors.push("CRITICAL: NEXTAUTH_SECRET must be at least 32 characters long in production.");
    }
  }

  // Threat intel provider presence checks
  if (!process.env.VIRUSTOTAL_API_KEY) {
    warnings.push("VIRUSTOTAL_API_KEY is not configured. VirusTotal reputation lookups will be skipped.");
  }

  if (!process.env.GOOGLE_SAFE_BROWSING_API_KEY) {
    warnings.push("GOOGLE_SAFE_BROWSING_API_KEY is not configured. Safe Browsing checks will be skipped.");
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

export const envConfig: AppConfig = {
  nodeEnv: process.env.NODE_ENV || "development",
  isProduction: (process.env.NODE_ENV || "development") === "production",
  databaseUrl: process.env.DATABASE_URL,
  nextAuthUrl: process.env.NEXTAUTH_URL,
  nextAuthSecret: process.env.NEXTAUTH_SECRET,
  virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY,
  googleSafeBrowsingApiKey: process.env.GOOGLE_SAFE_BROWSING_API_KEY,
  abuseIpDbApiKey: process.env.ABUSEIPDB_KEY,
  urlhausApiKey: process.env.URLHAUS_KEY,
};

