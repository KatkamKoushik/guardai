import { describe, it, expect } from "vitest";
import { probeTLS } from "../src/lib/tls-probe";

describe("Cryptographic TLS Verification Probe", () => {
  it("rejects unencrypted HTTP targets and marks status UNENCRYPTED_HTTP", async () => {
    const res = await probeTLS("http://example.com");
    expect(res.valid).toBe(false);
    expect(res.status).toBe("UNENCRYPTED_HTTP");
    expect(res.issuer).toContain("Unencrypted HTTP");
  });

  it("handles invalid or malformed URL input cleanly", async () => {
    const res = await probeTLS("not-a-valid-url::@@@");
    expect(res.valid).toBe(false);
    expect(res.status).toBe("ERROR");
  });

  it("cryptographically verifies trusted TLS certificates on public targets", async () => {
    const res = await probeTLS("https://cloudflare.com");
    expect(res.valid).toBe(true);
    expect(res.status).toBe("VALID");
    expect(res.issuer).toBeDefined();
    expect(res.validTo).toBeDefined();
    expect(res.daysRemaining).toBeGreaterThan(0);
  });

  it("identifies hostname mismatch and ensures valid: false", async () => {
    const res = await probeTLS("https://wrong.host.badssl.com");
    expect(res.valid).toBe(false);
    expect(["HOSTNAME_MISMATCH", "UNTRUSTED_ROOT", "TIMEOUT", "ERROR"]).toContain(res.status);
    expect(res.error).toBeDefined();
  });

  it("identifies expired certificates and ensures valid: false", async () => {
    const res = await probeTLS("https://expired.badssl.com");
    expect(res.valid).toBe(false);
    expect(["EXPIRED", "UNTRUSTED_ROOT", "TIMEOUT", "ERROR"]).toContain(res.status);
    expect(res.error).toBeDefined();
  });

  it("identifies self-signed certificates and ensures valid: false", async () => {
    const res = await probeTLS("https://self-signed.badssl.com");
    expect(res.valid).toBe(false);
    expect(["SELF_SIGNED", "UNTRUSTED_ROOT", "TIMEOUT", "ERROR"]).toContain(res.status);
    expect(res.error).toBeDefined();
  });
});
