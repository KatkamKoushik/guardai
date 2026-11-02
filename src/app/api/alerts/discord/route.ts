import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { auth } from "@/lib/auth";
import { validateDiscordWebhookUrl, checkRateLimit } from "@/lib/webhooks";
import { sendDiscordWebhook, AlertData } from "@/lib/notifications";

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

    // Rate limiting: max 5 setup/test attempts per minute per user
    const rateCheck = checkRateLimit(`discord-setup:${user.id}`, 5, 60_000);
    if (!rateCheck.allowed) {
      return NextResponse.json(
        { error: "Too many setup requests. Please wait a moment before trying again." },
        { status: 429 }
      );
    }

    let body: { webhookUrl?: string; alertSensitivity?: string };
    try {
      body = await req.json();
    } catch {
      return NextResponse.json({ error: "Invalid JSON request body" }, { status: 400 });
    }

    const { webhookUrl, alertSensitivity = "high_critical" } = body;

    if (!webhookUrl) {
      return NextResponse.json({ error: "Webhook URL is required" }, { status: 400 });
    }

    // 1. Strict Discord URL format & SSRF validation
    const validation = validateDiscordWebhookUrl(webhookUrl);
    if (!validation.valid) {
      return NextResponse.json({ error: validation.reason }, { status: 400 });
    }

    // 2. Dispatch verification test message
    const testAlert: AlertData = {
      url: "https://guardai.app/security-check",
      score: 10,
      severity: "low",
      explanation: "GuardAI: Discord integration successfully connected and verified.",
      vtScore: "Verified",
      sslStatus: "VALID (TLS 1.3)",
      missingHeaders: "None",
      mlScore: "Normal",
      action: "Integration active. You will receive alerts according to your sensitivity preferences.",
      scanId: "integration-setup",
    };

    try {
      await sendDiscordWebhook(validation.normalizedUrl, testAlert);
    } catch (deliveryErr: any) {
      return NextResponse.json(
        { error: `Discord delivery failed: ${deliveryErr.message}` },
        { status: 400 }
      );
    }

    // 3. Upsert configuration in DB
    const existing = await prisma.notification.findFirst({
      where: { userId: user.id, platform: "discord" },
    });

    if (existing) {
      await prisma.notification.update({
        where: { id: existing.id },
        data: {
          config: {
            webhookUrl: validation.normalizedUrl,
            alertSensitivity,
          },
          isActive: true,
        },
      });
    } else {
      await prisma.notification.create({
        data: {
          platform: "discord",
          config: {
            webhookUrl: validation.normalizedUrl,
            alertSensitivity,
          },
          userId: user.id,
          isActive: true,
        },
      });
    }

    return NextResponse.json({
      success: true,
      maskedUrl: validation.maskedUrl,
    });
  } catch (error: any) {
    console.error("Discord alert setup error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
