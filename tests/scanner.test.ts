import { describe, it, expect } from "vitest";
import { analyzeSecurityHeaders } from "@/lib/scanner/security-headers";
import { extractRootDomain } from "@/lib/scanner/rdap";
import { lookupGeoIp } from "@/lib/scanner/geoip";
import { collectThreatIntel } from "@/lib/scanner/threat-collector";

describe("Scanner Pipeline Modules", () => {
  describe("Security Headers Analyzer", () => {
    it("awards Grade A when all key defensive headers are present", () => {
      const report = analyzeSecurityHeaders({
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
      });

      expect(report.grade).toBe("A");
      expect(report.hsts).toBe(true);
      expect(report.csp).toBe(true);
      expect(report.xFrameOptions).toBe(true);
      expect(report.xContentTypeOptions).toBe(true);
      expect(report.missingHeaders.length).toBe(0);
    });

    it("awards Grade F and lists all missing headers when none are present", () => {
      const report = analyzeSecurityHeaders({});

      expect(report.grade).toBe("F");
      expect(report.hsts).toBe(false);
      expect(report.csp).toBe(false);
      expect(report.xFrameOptions).toBe(false);
      expect(report.missingHeaders).toContain("Strict-Transport-Security (HSTS)");
      expect(report.missingHeaders).toContain("Content-Security-Policy (CSP)");
      expect(report.missingHeaders.length).toBe(6);
    });

    it("handles case-insensitive header names properly", () => {
      const report = analyzeSecurityHeaders({
        "strict-transport-security": "max-age=31536000",
        "x-frame-options": "SAMEORIGIN",
      });

      expect(report.hsts).toBe(true);
      expect(report.xFrameOptions).toBe(true);
      expect(report.csp).toBe(false);
    });
  });

  describe("RDAP & Root Domain Extraction", () => {
    it("extracts root domain from standard hostnames", () => {
      expect(extractRootDomain("subdomain.example.com")).toBe("example.com");
      expect(extractRootDomain("deep.nested.subdomain.target.org")).toBe("target.org");
      expect(extractRootDomain("google.com")).toBe("google.com");
    });

    it("handles compound country-code second-level domains", () => {
      expect(extractRootDomain("portal.service.co.uk")).toBe("service.co.uk");
      expect(extractRootDomain("api.bank.com.au")).toBe("bank.com.au");
      expect(extractRootDomain("bbc.co.uk")).toBe("bbc.co.uk");
    });
  });

  describe("Offline-First GeoIP Resolution", () => {
    it("resolves geolocation instantly via local MaxMind database without network", async () => {
      const result = await lookupGeoIp("8.8.8.8");
      expect(result).not.toBeNull();
      expect(result?.countryCode).toBe("US");
      expect(result?.lat).toBeDefined();
      expect(result?.lon).toBeDefined();
    });

    it("safely handles empty or missing IP inputs", async () => {
      const result = await lookupGeoIp("");
      expect(result).toBeNull();
    });
  });

  describe("Threat Intelligence Collector", () => {
    it("marks missing API keys as explicitly disabled instead of failing", async () => {
      const prevVt = process.env.VIRUSTOTAL_API_KEY;
      const prevGsb = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

      delete process.env.VIRUSTOTAL_API_KEY;
      delete process.env.GOOGLE_SAFE_BROWSING_API_KEY;

      const providers = await collectThreatIntel("https://example.com");

      expect(providers["VirusTotal"].status).toBe("disabled");
      expect(providers["VirusTotal"].limitation).toBeDefined();
      expect(providers["Google Safe Browsing"].status).toBe("disabled");
      expect(providers["Google Safe Browsing"].limitation).toBeDefined();

      if (prevVt) process.env.VIRUSTOTAL_API_KEY = prevVt;
      if (prevGsb) process.env.GOOGLE_SAFE_BROWSING_API_KEY = prevGsb;
    });
  });
});
