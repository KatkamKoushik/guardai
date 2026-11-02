import { describe, it, expect } from "vitest";
import {
  validateDiscordWebhookUrl,
  validateTelegramConfig,
  checkRateLimit,
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
        validateDiscordWebhookUrl(
          `https://discord.com/api/webhooks/123456789012345678/${token}?test=true`
        ).valid
      ).toBe(false);
      expect(
        validateDiscordWebhookUrl(
          `https://discord.com/api/webhooks/123456789012345678/${token}#frag`
        ).valid
      ).toBe(false);
    });
  });

  describe("Telegram Credential Validation", () => {
    it("accepts valid Telegram bot token and numeric chat ID", () => {
      const token = "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ123456789";
      const chatId = "987654321";
      const res = validateTelegramConfig(token, chatId);
      expect(res.valid).toBe(true);
      expect(res.maskedToken).toContain("••••");
    });

    it("accepts channel usernames as chat ID (@my_channel)", () => {
      const token = "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ123456789";
      const chatId = "@guardai_alerts";
      const res = validateTelegramConfig(token, chatId);
      expect(res.valid).toBe(true);
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
});

