import { describe, it, expect } from "vitest";
import { calculateEntropy, isGibberish, analyzeURL } from "../src/lib/heuristics";

describe("Lexical Heuristics Engine", () => {
  describe("Shannon Entropy Calculation", () => {
    it("returns 0 for empty string", () => {
      expect(calculateEntropy("")).toBe(0);
    });

    it("returns 0 for single repeated character", () => {
      expect(calculateEntropy("aaaaaa")).toBe(0);
    });

    it("measures higher entropy for pseudo-random strings", () => {
      const normal = calculateEntropy("google.com");
      const random = calculateEntropy("q7z9k2m4x1p8.xyz");
      expect(random).toBeGreaterThan(normal);
    });
  });

  describe("Gibberish / Input Validity Detection", () => {
    it("identifies non-domains without TLD as gibberish", () => {
      expect(isGibberish("hello")).toBe(true);
      expect(isGibberish("testdomain")).toBe(true);
      expect(isGibberish("")).toBe(true);
    });

    it("identifies valid domains as non-gibberish", () => {
      expect(isGibberish("google.com")).toBe(false);
      expect(isGibberish("sub.domain.co.uk")).toBe(false);
      expect(isGibberish("https://example.com/path")).toBe(false);
    });

    it("accepts valid IP addresses as non-gibberish", () => {
      expect(isGibberish("192.168.1.1")).toBe(false);
      expect(isGibberish("8.8.8.8")).toBe(false);
    });
  });

  describe("analyzeURL Behavioral Checks", () => {
    it("detects dangerous URI schemes (data:, javascript:)", () => {
      const res = analyzeURL("javascript:alert(1)");
      expect(res.probability).toBe(100);
      expect(res.flags).toContain("Dangerous URI scheme (data: / javascript:)");
    });

    it("flags typosquatting of known brands", () => {
      const res = analyzeURL("https://paypa1-security-verify.com");
      expect(res.probability).toBeGreaterThan(50);
      expect(res.flags.some((f) => f.includes("typosquatting") || f.includes("paypal"))).toBe(true);
    });

    it("flags suspicious high-abuse TLDs (.tk, .xyz, .top)", () => {
      const res = analyzeURL("https://account-billing-update.tk");
      expect(res.flags.some((f) => f.includes(".tk"))).toBe(true);
      expect(res.probability).toBeGreaterThan(40);
    });

    it("flags phishing keywords in domain", () => {
      const res = analyzeURL("https://secure-login-verify-account.com");
      expect(res.suspiciousWordsCount).toBeGreaterThanOrEqual(3);
      expect(res.flags.some((f) => f.includes("phishing keyword"))).toBe(true);
    });

    it("does not falsely flag benign reputable domains", () => {
      const res = analyzeURL("https://google.com");
      expect(res.probability).toBeLessThan(25);
    });
  });
});

