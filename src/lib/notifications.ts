import { prisma } from "./db";

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

const buildMarkdownMessage = (alertData: AlertData) => {
  const severityEmoji = alertData.severity === "critical" ? "🚨" : "⚠️";
  return `${severityEmoji} **[${alertData.severity.toUpperCase()} ALERT] GuardAI Threat Detection**

**Target URL:** ${alertData.url}
**Risk Score:** ${alertData.score}/100 (${alertData.severity.toUpperCase()})

${alertData.explanation}

**Concrete Proof & Evidence Breakdown:**
• 🦠 **VirusTotal:** ${alertData.vtScore}
• 🔒 **SSL/TLS Status:** ${alertData.sslStatus}
• 🛡️ **Missing Headers:** ${alertData.missingHeaders}
• ⚡ **Lexical/ML Score:** ${alertData.mlScore}

**Recommended Action:** ${alertData.action}

[View Audit Log](http://localhost:3000/audit/${alertData.scanId})`;
};

export async function sendDiscordWebhook(webhookUrl: string, alertData: AlertData) {
  const payload = {
    content: buildMarkdownMessage(alertData),
  };

  const res = await fetch(webhookUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    throw new Error(`Discord webhook failed: ${res.statusText}`);
  }
}

export async function sendTelegramAlert(botToken: string, chatId: string, alertData: AlertData) {
  const payload = {
    chat_id: chatId,
    text: buildMarkdownMessage(alertData),
    parse_mode: "Markdown",
    disable_web_page_preview: true,
  };

  const res = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  const data = await res.json();
  if (!res.ok || !data.ok) {
    throw new Error(`Telegram alert failed: ${data.description || res.statusText}`);
  }
}

export async function notifyUserForScan(userId: string, alertData: AlertData) {
  const notifications = await prisma.notification.findMany({
    where: { userId, isActive: true },
  });

  for (const notif of notifications) {
    const config = notif.config as any;
    const sensitivity = config.alertSensitivity || "high_critical";

    let shouldAlert = false;
    if (sensitivity === "all") {
      shouldAlert = true;
    } else if (sensitivity === "high_critical" && (alertData.severity === "high" || alertData.severity === "critical")) {
      shouldAlert = true;
    } else if (sensitivity === "critical" && alertData.severity === "critical") {
      shouldAlert = true;
    }

    if (shouldAlert) {
      if (notif.platform === "discord" && config.webhookUrl) {
        try {
          await sendDiscordWebhook(config.webhookUrl, alertData);
        } catch (e) {
          console.error("Failed to notify discord:", e);
        }
      } else if (notif.platform === "telegram" && config.botToken && config.chatId) {
        try {
          await sendTelegramAlert(config.botToken, config.chatId, alertData);
        } catch (e) {
          console.error("Failed to notify telegram:", e);
        }
      }
    }
  }
}
