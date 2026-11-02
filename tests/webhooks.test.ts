import { describe, it, expect } from "vitest";
import {
  validateDiscordWebhookUrl,
  validateTelegramConfig,
  checkRateLimit,
  timingSafeCompare,
} from "../src/lib/webhooks";

describe("Webhook & Integration Safety Engine", () => {
  describe("Discord Webhook Validation", () => {
    it("accepts valid canonical Discord webhook URLs", () => {
      const url =
        "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
      const res = validateDiscordWebhookUrl(url);
      expect(res.valid).toBe(true);
      if (res.valid) {
        expect(res.webhookId).toBe("123456789012345678");
        expect(res.maskedUrl).toContain("••••");
        expect(res.maskedUrl.startsWith("https://discord.com/api/webhooks/123456789012345678/")).toBe(true);
      }
    });

    it("accepts discordapp.com, canary.discord.com, and ptb.discord.com", () => {
      const token = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
      expect(
        validateDiscordWebhookUrl(`https://discordapp.com/api/webhooks/123456789012345678/${token}`).valid
      ).toBe(true);
      expect(
        validateDiscordWebhookUrl(`https://canary.discord.com/api/webhooks/123456789012345678/${token}`).valid
      ).toBe(true);
      expect(
        validateDiscordWebhookUrl(`https://ptb.discord.com/api/webhooks/123456789012345678/${token}`).valid
      ).toBe(true);
    });

    it("rejects non-Discord domains (SSRF prevention)", () => {
      expect(validateDiscordWebhookUrl("https://evil.com/api/webhooks/12345/token").valid).toBe(false);
      expect(validateDiscordWebhookUrl("http://127.0.0.1:8000/webhook").valid).toBe(false);
      expect(validateDiscordWebhookUrl("http://169.254.169.254/latest/meta-data").valid).toBe(false);
    });

    it("rejects unencrypted HTTP Discord URLs", () => {
      expect(
        validateDiscordWebhookUrl(
          "http://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        ).valid
      ).toBe(false);
    });

    it("rejects URLs containing query parameters or fragments", () => {
      const token = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
      expect(
        validateDiscordWebhookUrl(`https://discord.com/api/webhooks/123456789012345678/${token}?param=evil`).valid
      ).toBe(false);
      expect(
        validateDiscordWebhookUrl(`https://discord.com/api/webhooks/123456789012345678/${token}#frag`).valid
      ).toBe(false);
    });

    it("rejects malicious or malformed IDs and tokens", () => {
      expect(validateDiscordWebhookUrl("https://discord.com/api/webhooks/short/token").valid).toBe(false);
      expect(validateDiscordWebhookUrl("https://discord.com/api/webhooks/123456789012345678/short").valid).toBe(false);
      expect(
        validateDiscordWebhookUrl("https://discord.com/api/webhooks/123456789012345678/bad_char$token_that_is_long_enough_to_test")
          .valid
      ).toBe(false);
    });
  });

  describe("Telegram Config Validation", () => {
    it("accepts valid Telegram bot tokens and chat IDs", () => {
      const token = "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ123456789";
      const chatId = "-1001234567890";
      const res = validateTelegramConfig(token, chatId);
      expect(res.valid).toBe(true);
      expect(res.maskedToken).toContain("••••");
      expect(res.maskedToken?.startsWith("123456789:")).toBe(true);
    });

    it("accepts username-based chat IDs", () => {
      const token = "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ123456789";
      expect(validateTelegramConfig(token, "@security_alerts").valid).toBe(true);
    });

    it("rejects malformed bot tokens", () => {
      expect(validateTelegramConfig("not-a-token", "12345").valid).toBe(false);
      expect(validateTelegramConfig("1234:short", "12345").valid).toBe(false);
    });

    it("rejects invalid or injection chat IDs", () => {
      const token = "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ123456789";
      expect(validateTelegramConfig(token, "chat; rm -rf /").valid).toBe(false);
      expect(validateTelegramConfig(token, "").valid).toBe(false);
    });
  });

  describe("Rate Limiter", () => {
    it("allows requests up to the defined threshold and blocks subsequent calls", () => {
      const key = `test-user-${Date.now()}`;
      for (let i = 0; i < 3; i++) {
        const check = checkRateLimit(key, 3, 10_000);
        expect(check.allowed).toBe(true);
      }
      const blocked = checkRateLimit(key, 3, 10_000);
      expect(blocked.allowed).toBe(false);
      expect(blocked.remaining).toBe(0);
    });
  });

  describe("Cryptographic Constant-Time Comparison (Control 09-B017)", () => {
    it("accurately verifies matching strings in constant time", () => {
      const secret = "super-secret-token-1234567890";
      expect(timingSafeCompare(secret, secret)).toBe(true);
      expect(timingSafeCompare("short", "short")).toBe(true);
    });

    it("accurately rejects non-matching strings and differing lengths without timing leak", () => {
      const secret = "super-secret-token-1234567890";
      expect(timingSafeCompare(secret, "super-secret-token-1234567891")).toBe(false);
      expect(timingSafeCompare(secret, "short")).toBe(false);
      expect(timingSafeCompare("", "token")).toBe(false);
    });
  });
});
