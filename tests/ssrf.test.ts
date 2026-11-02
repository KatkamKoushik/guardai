import { describe, it, expect } from "vitest";
import {
  isDisallowedIPv4,
  isDisallowedIPv6,
  isDisallowedIP,
  normalizeIPv4String,
  isDisallowedHostname,
  validateTargetForSSRF,
} from "../src/lib/ssrf";

describe("SSRF Protection Engine", () => {
  describe("IPv4 Range Validation", () => {
    it("blocks loopback addresses (127.0.0.0/8)", () => {
      expect(isDisallowedIPv4("127.0.0.1")).toBe(true);
      expect(isDisallowedIPv4("127.0.0.254")).toBe(true);
      expect(isDisallowedIPv4("127.255.255.254")).toBe(true);
    });

    it("blocks RFC 1918 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)", () => {
      expect(isDisallowedIPv4("10.0.0.1")).toBe(true);
      expect(isDisallowedIPv4("10.255.255.254")).toBe(true);
      expect(isDisallowedIPv4("172.16.0.1")).toBe(true);
      expect(isDisallowedIPv4("172.31.255.254")).toBe(true);
      expect(isDisallowedIPv4("192.168.1.1")).toBe(true);
      expect(isDisallowedIPv4("192.168.254.254")).toBe(true);
    });

    it("blocks cloud metadata & link-local addresses (169.254.0.0/16, 100.100.100.200)", () => {
      expect(isDisallowedIPv4("169.254.169.254")).toBe(true); // AWS / GCP / Azure metadata
      expect(isDisallowedIPv4("169.254.1.1")).toBe(true);
      expect(isDisallowedIPv4("100.100.100.200")).toBe(true); // Alibaba metadata
    });

    it("blocks current network, carrier NAT, multicast, and broadcast", () => {
      expect(isDisallowedIPv4("0.0.0.0")).toBe(true);
      expect(isDisallowedIPv4("100.64.0.1")).toBe(true); // CGNAT
      expect(isDisallowedIPv4("224.0.0.1")).toBe(true); // Multicast
      expect(isDisallowedIPv4("255.255.255.255")).toBe(true); // Broadcast
    });

    it("allows genuine public IPv4 addresses", () => {
      expect(isDisallowedIPv4("8.8.8.8")).toBe(false);
      expect(isDisallowedIPv4("1.1.1.1")).toBe(false);
      expect(isDisallowedIPv4("93.184.216.34")).toBe(false); // example.com
    });
  });

  describe("IPv6 Range Validation", () => {
    it("blocks IPv6 loopback (::1) and unspecified (::)", () => {
      expect(isDisallowedIPv6("::1")).toBe(true);
      expect(isDisallowedIPv6("::")).toBe(true);
    });

    it("blocks IPv6 Unique Local Addresses (fc00::/7)", () => {
      expect(isDisallowedIPv6("fc00::1")).toBe(true);
      expect(isDisallowedIPv6("fd12:3456:789a::1")).toBe(true);
    });

    it("blocks IPv6 Link-Local Unicast (fe80::/10)", () => {
      expect(isDisallowedIPv6("fe80::1")).toBe(true);
      expect(isDisallowedIPv6("fe80::200:5efe:10.0.0.1")).toBe(true);
    });

    it("blocks IPv4-mapped IPv6 addresses embedding private IPv4", () => {
      expect(isDisallowedIPv6("::ffff:127.0.0.1")).toBe(true);
      expect(isDisallowedIPv6("::ffff:10.0.0.1")).toBe(true);
      expect(isDisallowedIPv6("::ffff:169.254.169.254")).toBe(true);
    });
  });

  describe("Numeric, Hex, and Octal IP Normalization", () => {
    it("normalizes pure decimal integer IP notation (e.g. 2130706433 → 127.0.0.1)", () => {
      const norm = normalizeIPv4String("2130706433");
      expect(norm).toBe("127.0.0.1");
      expect(isDisallowedIP("2130706433")).toBe(true);
    });

    it("normalizes hexadecimal IP notation (e.g. 0x7f000001 → 127.0.0.1)", () => {
      const norm = normalizeIPv4String("0x7f000001");
      expect(norm).toBe("127.0.0.1");
      expect(isDisallowedIP("0x7f000001")).toBe(true);
    });

    it("normalizes octal IP notation (e.g. 0177.0.0.1 → 127.0.0.1)", () => {
      const norm = normalizeIPv4String("0177.0.0.1");
      expect(norm).toBe("127.0.0.1");
      expect(isDisallowedIP("0177.0.0.1")).toBe(true);
    });
  });

  describe("Forbidden Hostname Patterns", () => {
    it("blocks localhost, .local, and internal cloud metadata hostnames", () => {
      expect(isDisallowedHostname("localhost")).toBe(true);
      expect(isDisallowedHostname("service.localhost")).toBe(true);
      expect(isDisallowedHostname("intranet.local")).toBe(true);
      expect(isDisallowedHostname("metadata.google.internal")).toBe(true);
      expect(isDisallowedHostname("127.0.0.1.nip.io")).toBe(true);
    });

    it("allows standard public domains", () => {
      expect(isDisallowedHostname("google.com")).toBe(false);
      expect(isDisallowedHostname("github.com")).toBe(false);
      expect(isDisallowedHostname("cloudflare.com")).toBe(false);
    });
  });

  describe("End-to-End validateTargetForSSRF", () => {
    it("rejects non-HTTP protocols", async () => {
      const res = await validateTargetForSSRF("file:///etc/passwd");
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain("Forbidden URL scheme");
    });

    it("rejects user credentials embedded in URLs", async () => {
      const res = await validateTargetForSSRF("https://admin:secret@example.com");
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain("credentials");
    });

    it("rejects non-standard web ports (e.g. database/SSH ports)", async () => {
      const res = await validateTargetForSSRF("http://example.com:5432");
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain("Destination port 5432 is restricted");
    });

    it("rejects direct private IPs", async () => {
      const res = await validateTargetForSSRF("http://192.168.1.50/admin");
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain("private");
    });

    it("rejects cloud metadata IP 169.254.169.254", async () => {
      const res = await validateTargetForSSRF("http://169.254.169.254/latest/meta-data");
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain("metadata");
    });

    it("allows public domain targets", async () => {
      const res = await validateTargetForSSRF("https://example.com");
      expect(res.allowed).toBe(true);
      expect(res.pinnedIp).toBeDefined();
    });
  });
});

