import { describe, it, expect } from "vitest";
import { evaluateThreatMatrix, ProviderReport } from "../src/lib/threat-intel";

describe("Threat Intelligence Decision Matrix & Abstention Engine", () => {
  it("enforces abstention policy (INCONCLUSIVE) when all external providers are disabled", () => {
    const disabledProviders: Record<string, ProviderReport> = {
      VirusTotal: {
        name: "VirusTotal",
        status: "disabled",
        detections: 0,
        totalEngines: 0,
        latencyMs: 0,
        limitation: "API key not configured",
        queriedAt: new Date().toISOString(),
      },
      "Google Safe Browsing": {
        name: "Google Safe Browsing",
        status: "disabled",
        detections: 0,
        totalEngines: 0,
        latencyMs: 0,
        limitation: "API key not configured",
        queriedAt: new Date().toISOString(),
      },
    };

    const res = evaluateThreatMatrix({
      providers: disabledProviders,
      tls: { status: "VALID", valid: true, issuer: "Let's Encrypt" },
      heuristics: { probability: 10, entropy: 3.2, flags: [] },
      network: { isReachable: true, dnsResolved: true, deadLink: false },
    });

    expect(res.verdict).toBe("INCONCLUSIVE");
    expect(res.abstention).toBe(true);
    expect(res.confidence).toBe("LOW");
    expect(res.limitations.length).toBeGreaterThan(0);
    expect(res.summary).toContain("inconclusive");
  });

  it("assigns CRITICAL verdict when Google Safe Browsing or URLhaus flags malware", () => {
    const activeProviders: Record<string, ProviderReport> = {
      "Google Safe Browsing": {
        name: "Google Safe Browsing",
        status: "malicious",
        detections: 1,
        totalEngines: 1,
        latencyMs: 120,
        details: "MALWARE",
        queriedAt: new Date().toISOString(),
      },
      VirusTotal: {
        name: "VirusTotal",
        status: "clean",
        detections: 0,
        totalEngines: 70,
        latencyMs: 250,
        queriedAt: new Date().toISOString(),
      },
    };

    const res = evaluateThreatMatrix({
      providers: activeProviders,
      tls: { status: "VALID", valid: true, issuer: "DigiCert" },
      heuristics: { probability: 20, entropy: 3.5, flags: [] },
      network: { isReachable: true, dnsResolved: true, deadLink: false },
    });

    expect(res.verdict).toBe("CRITICAL");
    expect(res.score).toBeGreaterThanOrEqual(95);
    expect(res.action).toContain("Isolate");
  });

  it("assigns HIGH verdict when VirusTotal detects threats", () => {
    const activeProviders: Record<string, ProviderReport> = {
      VirusTotal: {
        name: "VirusTotal",
        status: "suspicious",
        detections: 2,
        totalEngines: 72,
        latencyMs: 210,
        queriedAt: new Date().toISOString(),
      },
      "Google Safe Browsing": {
        name: "Google Safe Browsing",
        status: "clean",
        detections: 0,
        totalEngines: 1,
        latencyMs: 100,
        queriedAt: new Date().toISOString(),
      },
    };

    const res = evaluateThreatMatrix({
      providers: activeProviders,
      tls: { status: "VALID", valid: true, issuer: "Let's Encrypt" },
      heuristics: { probability: 25, entropy: 3.4, flags: [] },
      network: { isReachable: true, dnsResolved: true, deadLink: false },
    });

    expect(res.verdict).toBe("HIGH");
    expect(res.score).toBeGreaterThanOrEqual(80);
  });

  it("assigns OFFLINE verdict when host is unreachable", () => {
    const res = evaluateThreatMatrix({
      providers: {},
      tls: { status: "TIMEOUT", valid: false, issuer: "Unknown" },
      heuristics: { probability: 40, entropy: 3.5, flags: [] },
      network: { isReachable: false, dnsResolved: false, deadLink: true },
    });

    expect(res.verdict).toBe("OFFLINE");
    expect(res.score).toBe(0);
  });

  it("applies TLS security penalty for expired or self-signed certificates", () => {
    const activeProviders: Record<string, ProviderReport> = {
      VirusTotal: {
        name: "VirusTotal",
        status: "clean",
        detections: 0,
        totalEngines: 70,
        latencyMs: 200,
        queriedAt: new Date().toISOString(),
      },
    };

    const resValid = evaluateThreatMatrix({
      providers: activeProviders,
      tls: { status: "VALID", valid: true, issuer: "Google Trust Services" },
      heuristics: { probability: 45, entropy: 3.8, flags: ["Multiple hyphens in domain"] },
      network: { isReachable: true, dnsResolved: true, deadLink: false },
    });

    const resExpired = evaluateThreatMatrix({
      providers: activeProviders,
      tls: { status: "EXPIRED", valid: false, issuer: "Self-Signed" },
      heuristics: { probability: 45, entropy: 3.8, flags: ["Multiple hyphens in domain"] },
      network: { isReachable: true, dnsResolved: true, deadLink: false },
    });

    expect(resExpired.score).toBeGreaterThan(resValid.score);
    expect(resExpired.dimensions.tls.penaltyScore).toBe(20);
  });

  it("assigns SAFE verdict only when verified across active engines with clean indicators", () => {
    const activeProviders: Record<string, ProviderReport> = {
      VirusTotal: {
        name: "VirusTotal",
        status: "clean",
        detections: 0,
        totalEngines: 70,
        latencyMs: 200,
        queriedAt: new Date().toISOString(),
      },
      "Google Safe Browsing": {
        name: "Google Safe Browsing",
        status: "clean",
        detections: 0,
        totalEngines: 1,
        latencyMs: 110,
        queriedAt: new Date().toISOString(),
      },
    };

    const res = evaluateThreatMatrix({
      providers: activeProviders,
      tls: { status: "VALID", valid: true, issuer: "Let's Encrypt" },
      heuristics: { probability: 5, entropy: 2.8, flags: [] },
      network: { isReachable: true, dnsResolved: true, deadLink: false },
    });

    expect(res.verdict).toBe("SAFE");
    expect(res.abstention).toBe(false);
    expect(res.score).toBeLessThan(30);
  });
});

