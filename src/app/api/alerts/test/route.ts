import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { notifyUserForScan, AlertData, sendDiscordWebhook, sendTelegramAlert } from "@/lib/notifications";
import { prisma } from "@/lib/db";
import { checkRateLimit } from "@/lib/webhooks";

export async function POST(req: Request) {
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

    // Rate limit test alerts: max 5 per minute
    const rateCheck = checkRateLimit(`alert-test:${user.id}`, 5, 60_000);
    if (!rateCheck.allowed) {
      return NextResponse.json(
        { error: "Too many test requests. Please wait a moment." },
        { status: 429 }
      );
    }

    let body: { platform?: string };
    try {
      body = await req.json();
    } catch {
      body = {};
    }

    const { platform } = body;

    const mockAlertData: AlertData = {
      url: "https://test-threat.guardai.security",
      score: 95,
      severity: "critical",
      explanation: "Test Alert: GuardAI detected a simulated high-risk malware threat.",
      vtScore: "19 / 92 engines flagged as Malicious",
      sslStatus: "UNENCRYPTED (HTTP Only)",
      missingHeaders: "HSTS, X-Frame-Options, CSP",
      mlScore: "Shannon Entropy: 3.096",
      action: "Test alert verified successfully. No action required.",
      scanId: "test-scan-id-123",
    };

    if (platform) {
      // Must belong to this user
      const notif = await prisma.notification.findFirst({
        where: { userId: user.id, platform, isActive: true },
      });

      if (!notif) {
        return NextResponse.json({ error: "Integration not found or not active" }, { status: 404 });
      }

      const config = notif.config as Record<string, any>;

      if (platform === "discord" && config.webhookUrl) {
        await sendDiscordWebhook(config.webhookUrl, mockAlertData);
      } else if (platform === "telegram" && config.botToken && config.chatId) {
        await sendTelegramAlert(config.botToken, config.chatId, mockAlertData);
      } else {
        return NextResponse.json({ error: "Incomplete configuration for platform" }, { status: 400 });
      }
    } else {
      await notifyUserForScan(user.id, mockAlertData);
    }

    return NextResponse.json({ success: true, message: "Test alert dispatched" });
  } catch (error: any) {
    console.error("Test alert error:", error);
    return NextResponse.json({ error: error.message || "Failed to dispatch test alert" }, { status: 500 });
  }
}
