import type { ProviderReport, ThreatMatrixEvaluation } from "@/lib/threat-intel";

export interface GeoIpData {
  query: string;
  city?: string;
  region?: string;
  country?: string;
  countryCode?: string;
  isp?: string;
  as?: string;
  asn?: string;
  lat?: number;
  lon?: number;
  timezone?: string;
}

export interface DomainRegistrationInfo {
  registrar: string;
  creationDate: string | null;
  expirationDate: string | null;
  domainAgeDays: number | null;
  domainAgeFormatted: string;
  isNewlyRegistered: boolean;
  status: string[];
}

export interface SecurityHeadersReport {
  hsts: boolean;
  xFrameOptions: boolean;
  csp: boolean;
  xContentTypeOptions: boolean;
  referrerPolicy: boolean;
  permissionsPolicy: boolean;
  missingHeaders: string[];
  grade: "A" | "B" | "C" | "D" | "F";
}

export interface ScanResultPayload {
  url: string;
  threatLevel: "safe" | "suspicious" | "high" | "critical" | "offline";
  score: number;
  verdict: string;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  abstention: boolean;
  summary: string;
  action: string;
  limitations: string[];
  details: {
    evaluation: ThreatMatrixEvaluation;
    virusTotal: {
      status: string;
      detections: number;
      total: number;
      skipped: boolean;
    };
    googleSafeBrowsing: {
      status: string;
      skipped: boolean;
    };
    phishing: {
      probability: number;
      indicators: string[];
    };
    ssl: {
      valid: boolean;
      status: string;
      issuer: string;
      expiry: string;
      error?: string;
    };
    reputation: {
      score: number;
      category: string;
    };
    geoIp: GeoIpData | null;
    securityHeaders: SecurityHeadersReport;
    whois?: DomainRegistrationInfo;
  };
}

