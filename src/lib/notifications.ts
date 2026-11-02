/**
 * GuardAI — Notification Dispatcher Service
 *
 * Implements security-hardened notification delivery:
 * 1. Strict destination validation (Discord patterns, Telegram bot patterns).
 * 2. SSRF defense preventing internal redirection.
 * 3. Enforced request timeouts (8s) with graceful error handling.
 * 4. User-scoped configuration queries.
 */

import { prisma } from "./db";
import { validateDiscordWebhookUrl, validateTelegramConfig } from "./webhooks";
import { validateTargetForSSRF } from "./ssrf";

export interface AlertData {
  url: string;
  score: number;
  severity: "low" | "medium" | "high" | "critical";
  explanation: string;
  vtScore: string;
  sslStatus: string;
  missingHeaders: string;
  mlScore: string;
  action: string;
  scanId: string;
}

const buildMarkdownMessage = (alertData: AlertData): string => {
  const severityEmoji = alertData.severity === "critical" ? "🚨" : "⚠️";
  return `${severityEmoji} **[${alertData.severity.toUpperCase()} ALERT] GuardAI Threat Detection**

**Target URL:** \`${alertData.url}\`
**Risk Score:** **${alertData.score}/100** (${alertData.severity.toUpperCase()})

${alertData.explanation}

**Concrete Proof & Evidence Breakdown:**
• 🦠 **VirusTotal:** ${alertData.vtScore}
• 🔒 **SSL/TLS Status:** ${alertData.sslStatus}
• 🛡️ **Missing Headers:** ${alertData.missingHeaders}
• ⚡ **Lexical/ML Score:** ${alertData.mlScore}

**Recommended Action:** ${alertData.action}

[View Audit Log](${process.env.NEXTAUTH_URL || "http://localhost:3000"}/audit)`;
};

export async function sendDiscordWebhook(
  rawWebhookUrl: string,
  alertData: AlertData
): Promise<void> {
  const validation = validateDiscordWebhookUrl(rawWebhookUrl);
  if (!validation.valid) {
    throw new Error(`Invalid Discord webhook URL: ${validation.reason}`);
  }

  // Pre-flight SSRF check on discord endpoint
  const ssrfCheck = await validateTargetForSSRF(validation.normalizedUrl);
  if (!ssrfCheck.allowed) {
    throw new Error(`Discord webhook blocked by SSRF policy: ${ssrfCheck.reason}`);
  }

  const payload = {
    content: buildMarkdownMessage(alertData),
  };

  const res = await fetch(validation.normalizedUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(8000),
  });

  if (!res.ok) {
    const errorText = await res.text().catch(() => res.statusText);
    throw new Error(`Discord webhook delivery failed (${res.status}): ${errorText}`);
  }
}

export async function sendTelegramAlert(
  botToken: string,
  chatId: string,
  alertData: AlertData
): Promise<void> {
  const validation = validateTelegramConfig(botToken, chatId);
  if (!validation.valid) {
    throw new Error(`Invalid Telegram configuration: ${validation.reason}`);
  }

  const telegramUrl = `https://api.telegram.org/bot${botToken.trim()}/sendMessage`;

  const payload = {
    chat_id: chatId.trim(),
    text: buildMarkdownMessage(alertData),
    parse_mode: "Markdown",
    disable_web_page_preview: true,
  };

  const res = await fetch(telegramUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(8000),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.ok) {
    throw new Error(`Telegram alert delivery failed: ${data.description || res.statusText}`);
  }
}

export async function notifyUserForScan(userId: string, alertData: AlertData): Promise<void> {
  if (!userId) return;

  const notifications = await prisma.notification.findMany({
    where: { userId, isActive: true },
  });

  if (notifications.length === 0) return;

  for (const notif of notifications) {
    const config = notif.config as Record<string, any>;
    const sensitivity = config.alertSensitivity || "high_critical";

    let shouldAlert = false;
    if (sensitivity === "all") {
      shouldAlert = true;
    } else if (
      sensitivity === "high_critical" &&
      (alertData.severity === "high" || alertData.severity === "critical")
    ) {
      shouldAlert = true;
    } else if (sensitivity === "critical" && alertData.severity === "critical") {
      shouldAlert = true;
    }

    if (!shouldAlert) continue;

    if (notif.platform === "discord" && config.webhookUrl) {
      try {
        await sendDiscordWebhook(config.webhookUrl, alertData);
      } catch (e: any) {
        console.error(`[notifications] Discord notification failed for user ${userId}:`, e.message);
      }
    } else if (notif.platform === "telegram" && config.botToken && config.chatId) {
      try {
        await sendTelegramAlert(config.botToken, config.chatId, alertData);
      } catch (e: any) {
        console.error(`[notifications] Telegram notification failed for user ${userId}:`, e.message);
      }
    }
  }
}
