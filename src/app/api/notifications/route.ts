/**
 * GuardAI — Authenticated Notification Test Route (POST /api/notifications)
 *
 * Dispatches a rich sample alert to verify the user's notification channel.
 * Hardened with strict session validation, URL pattern enforcement, SSRF checks,
 * and rate limiting.
 */

import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { validateDiscordWebhookUrl, validateTelegramConfig, checkRateLimit } from "@/lib/webhooks";
import { sendDiscordWebhook, sendTelegramAlert, AlertData } from "@/lib/notifications";

export async function POST(request: Request) {
  try {
    const session = await auth();
    if (!session?.user?.email) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const user = await prisma.user.findUnique({
      where: { email: session.user.email },
    });

    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    // Rate limiting: max 5 notification tests per minute
    const rateCheck = checkRateLimit(`notif-test:${user.id}`, 5, 60_000);
    if (!rateCheck.allowed) {
      return NextResponse.json(
        { error: "Too many test requests. Please wait a moment." },
        { status: 429 }
      );
    }

    let body: {
      platform?: string;
      webhookUrl?: string;
      botToken?: string;
      chatId?: string;
    };

    try {
      body = await request.json();
    } catch {
      return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
    }

    const { platform, webhookUrl, botToken, chatId } = body;

    const sampleAlert: AlertData = {
      url: "https://secure-sample.verify-account.preview",
      score: 95,
      severity: "critical",
      explanation: "GuardAI Sample Test Alert: Demonstrating detection notification.",
      vtScore: "18 / 92 engines flagged",
      sslStatus: "Invalid / Missing",
      missingHeaders: "HSTS, X-Frame-Options, CSP",
      mlScore: "Phishing Probability: 91% (Entropy: 4.72)",
      action: "Verification successful. Active alerts will be delivered via this channel.",
      scanId: "sample-test-scan",
    };

    if (platform === "discord") {
      if (!webhookUrl) {
        return NextResponse.json({ error: "Discord webhook URL is required" }, { status: 400 });
      }

      const validation = validateDiscordWebhookUrl(webhookUrl);
      if (!validation.valid) {
        return NextResponse.json({ error: validation.reason }, { status: 400 });
      }

      await sendDiscordWebhook(validation.normalizedUrl, sampleAlert);
      return NextResponse.json({ success: true, platform: "discord" });
    }

    if (platform === "telegram") {
      if (!botToken || !chatId) {
        return NextResponse.json({ error: "Bot token and chat ID are required" }, { status: 400 });
      }

      const validation = validateTelegramConfig(botToken, chatId);
      if (!validation.valid) {
        return NextResponse.json({ error: validation.reason }, { status: 400 });
      }

      await sendTelegramAlert(botToken, chatId, sampleAlert);
      return NextResponse.json({ success: true, platform: "telegram" });
    }

    return NextResponse.json({ error: "Invalid platform specified. Must be discord or telegram." }, { status: 400 });
  } catch (error: any) {
    console.error("[notifications/route] Error:", error);
    return NextResponse.json({ error: error.message || "Internal server error" }, { status: 500 });
  }
}
