/**
 * GuardAI — Notification Test Route (POST /api/notifications)
 *
 * Sends a rich, realistic sample alert to the configured platform.
 * The sample payload mirrors what a real scan alert looks like so users
 * can verify their integration is working correctly.
 */

import { NextResponse } from "next/server";

export async function POST(request: Request) {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    const { platform, webhookUrl, botToken, chatId } = await request.json();

    const controller = new AbortController();
    timeout = setTimeout(() => controller.abort(), 10_000);

    // ── Build the rich sample alert ────────────────────────────────────────
    const now = new Date();
    const timestamp = now.toISOString();
    const displayTime = now.toLocaleString("en-US", {
      dateStyle: "medium",
      timeStyle: "long",
    });

    const samplePayload = {
      targetUrl:    "https://secure-paypa1-login.verify-account.tk",
      score:        95,
      severity:     "CRITICAL",
      vtScore:      "18 / 92 engines flagged",
      gsbStatus:    "BLACKLISTED (Social Engineering)",
      sslStatus:    "Invalid / Missing",
      missingHeaders: "HSTS, X-Frame-Options, CSP",
      mlScore:      "Phishing Probability: 91% (Shannon Entropy: 4.72)",
      flags: [
        "Suspicious TLD \".tk\" — high abuse frequency",
        "Domain impersonates brand \"paypal\" (typosquatting)",
        "Digits in domain name — possible leet-speak substitution",
        "Contains 4 phishing keywords: secure, login, verify, account",
        "Elevated domain entropy (4.72) — potential obfuscation",
        "Punycode/IDN encoding detected",
      ],
      action:       "Isolate affected endpoints immediately and block all IOCs at network perimeter.",
      auditLink:    `${process.env.NEXTAUTH_URL || "https://guardai.app"}/audit`,
      timestamp,
      displayTime,
    };

    // ── Discord Rich Embed ─────────────────────────────────────────────────
    if (platform === "discord") {
      if (!webhookUrl) {
        return NextResponse.json({ error: "Discord webhook URL is required" }, { status: 400 });
      }

      let parsedUrl: URL;
      try {
        parsedUrl = new URL(webhookUrl);
      } catch {
        return NextResponse.json({ error: "Invalid webhook URL format" }, { status: 400 });
      }

      const isAllowedHost =
        parsedUrl.protocol === "https:" &&
        (parsedUrl.hostname === "discord.com" || parsedUrl.hostname === "discordapp.com");
      const isWebhookPath = parsedUrl.pathname.startsWith("/api/webhooks/");
      if (!isAllowedHost || !isWebhookPath) {
        return NextResponse.json({ error: "Only valid Discord webhook URLs are allowed" }, { status: 400 });
      }

      const response = await fetch(webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: controller.signal,
        body: JSON.stringify({
          embeds: [
            {
              title: "🚨 [CRITICAL ALERT] GuardAI Threat Detection — TEST",
              description:
                `**Target URL:** \`${samplePayload.targetUrl}\`\n` +
                `**Risk Score:** **${samplePayload.score}/100** (${samplePayload.severity})\n\n` +
                `GuardAI detected a confirmed high-confidence phishing/malware site. ` +
                `This is a sample alert verifying your Discord integration.`,
              color: 0xFF003C,
              fields: [
                { name: "🦠 VirusTotal",          value: samplePayload.vtScore,        inline: true  },
                { name: "🌐 Google Safe Browsing", value: samplePayload.gsbStatus,      inline: true  },
                { name: "🔒 SSL/TLS",              value: samplePayload.sslStatus,      inline: true  },
                { name: "🛡️ Missing Headers",      value: samplePayload.missingHeaders, inline: true  },
                { name: "⚡ ML Lexical Score",     value: samplePayload.mlScore,        inline: false },
                {
                  name: "🔍 Indicators",
                  value: samplePayload.flags.map(f => `• ${f}`).join("\n"),
                  inline: false,
                },
                { name: "✅ Recommended Action",   value: samplePayload.action,         inline: false },
                { name: "🕐 Timestamp",            value: samplePayload.displayTime,    inline: true  },
              ],
              footer: { text: "GuardAI Cybersecurity Platform — Test Alert" },
              timestamp,
            },
          ],
        }),
      });

      if (!response.ok) {
        const body = await response.text().catch(() => response.statusText);
        return NextResponse.json({ error: `Failed to send Discord webhook: ${body}` }, { status: 500 });
      }

      return NextResponse.json({ success: true, platform: "discord" });
    }

    // ── Telegram Rich HTML Message ─────────────────────────────────────────
    if (platform === "telegram") {
      if (!botToken || !chatId) {
        return NextResponse.json({ error: "Bot token and chat ID are required" }, { status: 400 });
      }

      const telegramText =
        `🚨 <b>[CRITICAL ALERT] GuardAI Threat Detection — TEST</b>\n\n` +
        `<b>Target:</b> <code>${samplePayload.targetUrl}</code>\n` +
        `<b>Risk Score:</b> <b>${samplePayload.score}/100</b> (${samplePayload.severity})\n\n` +
        `<i>GuardAI detected a confirmed high-confidence phishing/malware site. This is a sample alert verifying your Telegram integration.</i>\n\n` +
        `<b>📊 Evidence Breakdown:</b>\n` +
        `• 🦠 <b>VirusTotal:</b> ${samplePayload.vtScore}\n` +
        `• 🌐 <b>Google Safe Browsing:</b> ${samplePayload.gsbStatus}\n` +
        `• 🔒 <b>SSL/TLS:</b> ${samplePayload.sslStatus}\n` +
        `• 🛡️ <b>Missing Headers:</b> ${samplePayload.missingHeaders}\n` +
        `• ⚡ <b>ML Score:</b> ${samplePayload.mlScore}\n\n` +
        `<b>🔍 Indicators:</b>\n` +
        samplePayload.flags.map(f => `  · ${f}`).join("\n") + "\n\n" +
        `<b>✅ Action:</b> ${samplePayload.action}\n\n` +
        `<b>🕐 Timestamp:</b> ${samplePayload.displayTime}\n` +
        `<a href="${samplePayload.auditLink}">📋 View Audit Log</a>`;

      const response = await fetch(
        `https://api.telegram.org/bot${botToken}/sendMessage`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          signal: controller.signal,
          body: JSON.stringify({
            chat_id: chatId,
            text: telegramText,
            parse_mode: "HTML",
            disable_web_page_preview: true,
          }),
        }
      );

      const data = await response.json();
      if (!response.ok || !data.ok) {
        return NextResponse.json(
          { error: `Failed to send Telegram message: ${data.description || response.statusText}` },
          { status: 500 }
        );
      }

      return NextResponse.json({ success: true, platform: "telegram" });
    }

    return NextResponse.json({ error: "Invalid platform" }, { status: 400 });
  } catch (error) {
    if ((error as Error).name === "AbortError") {
      return NextResponse.json({ error: "Notification provider timeout" }, { status: 504 });
    }
    console.error("[notifications/route] Error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
  }
}
