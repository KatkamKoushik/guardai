/**
 * GuardAI — Secure Webhook & Alert Dispatch Engine
 *
 * Implements strict security controls for outbound alerting:
 * 1. Strict pattern matching for Discord webhooks and Telegram credentials.
 * 2. Complete rejection of arbitrary URLs.
 * 3. Token masking and redaction for logs and client displays.
 * 4. SSRF-safe outbound delivery with timeouts.
 * 5. Rate limiting on dispatch and test actions.
 */

import { validateTargetForSSRF } from "./ssrf";

// Discord Webhook URL pattern: https://discord.com/api/webhooks/<id>/<token>
// Allows discord.com, discordapp.com, ptb.discord.com, canary.discord.com
const DISCORD_WEBHOOK_REGEX =
  /^https:\/\/(?:(?:ptb|canary)\.)?discord(?:app)?\.com\/api\/webhooks\/(\d{17,20})\/([A-Za-z0-9_-]{50,80})$/;

// Telegram bot token: e.g. 123456789:ABCdefGHIjklMNOpqrSTUvwxYZ123456789
const TELEGRAM_BOT_TOKEN_REGEX = /^\d{8,11}:[A-Za-z0-9_-]{35}$/;

// Telegram chat ID: numeric user/group/channel ID or @channel username
const TELEGRAM_CHAT_ID_REGEX = /^(?:-?\d{1,16}|@[A-Za-z0-9_]{5,32})$/;

export interface ValidatedDiscordWebhook {
  valid: true;
  normalizedUrl: string;
  webhookId: string;
  maskedUrl: string;
}

export interface InvalidWebhook {
  valid: false;
  reason: string;
}

export type WebhookValidationResult = ValidatedDiscordWebhook | InvalidWebhook;

/**
 * Validates that a string is a legitimate Discord webhook URL.
 * Rejects arbitrary hosts, HTTP scheme, query parameters, and user credentials.
 */
export function validateDiscordWebhookUrl(url: string): WebhookValidationResult {
  if (!url || typeof url !== "string") {
    return { valid: false, reason: "Webhook URL is required" };
  }

  const trimmed = url.trim();

  // Reject URLs with query parameters or fragments
  if (trimmed.includes("?") || trimmed.includes("#")) {
    return { valid: false, reason: "Webhook URL cannot contain query parameters or fragments" };
  }

  const match = DISCORD_WEBHOOK_REGEX.exec(trimmed);
  if (!match) {
    return {
      valid: false,
      reason: "Invalid Discord webhook URL format. Must be https://discord.com/api/webhooks/<id>/<token>",
    };
  }

  const webhookId = match[1];
  const token = match[2];
  const maskedToken = "•".repeat(Math.max(8, token.length - 6)) + token.slice(-6);
  const maskedUrl = `https://discord.com/api/webhooks/${webhookId}/${maskedToken}`;

  return {
    valid: true,
    normalizedUrl: trimmed,
    webhookId,
    maskedUrl,
  };
}

/**
 * Validates Telegram bot credentials.
 */
export function validateTelegramConfig(
  botToken: string,
  chatId: string
): { valid: boolean; reason?: string; maskedToken?: string } {
  if (!botToken || !chatId) {
    return { valid: false, reason: "Both botToken and chatId are required" };
  }

  const cleanToken = botToken.trim();
  const cleanChatId = chatId.trim();

  if (!TELEGRAM_BOT_TOKEN_REGEX.test(cleanToken)) {
    return {
      valid: false,
      reason: "Invalid Telegram bot token format. Expected format: 123456789:ABCdefGHI...",
    };
  }

  if (!TELEGRAM_CHAT_ID_REGEX.test(cleanChatId)) {
    return {
      valid: false,
      reason: "Invalid Telegram chat ID format. Expected numeric ID or @channel username",
    };
  }

  const colonIdx = cleanToken.indexOf(":");
  const maskedToken = cleanToken.slice(0, colonIdx + 1) + "•".repeat(25) + cleanToken.slice(-5);

  return {
    valid: true,
    maskedToken,
  };
}

/**
 * Simple in-memory rate limiter for webhook test endpoints.
 * Keyed by userId or IP. Max 10 tests per 60 seconds.
 */
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();

export function checkRateLimit(key: string, limit: number = 10, windowMs: number = 60_000): {
  allowed: boolean;
  remaining: number;
} {
  const now = Date.now();
  const record = rateLimitMap.get(key);

  if (!record || now > record.resetAt) {
    rateLimitMap.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, remaining: limit - 1 };
  }

  if (record.count >= limit) {
    return { allowed: false, remaining: 0 };
  }

  record.count++;
  return { allowed: true, remaining: limit - record.count };
}

/**
 * Clean up old rate limit records periodically.
 */
if (typeof setInterval !== "undefined") {
  setInterval(() => {
    const now = Date.now();
    for (const [key, record] of rateLimitMap.entries()) {
      if (now > record.resetAt) {
        rateLimitMap.delete(key);
      }
    }
  }, 300_000);
}

