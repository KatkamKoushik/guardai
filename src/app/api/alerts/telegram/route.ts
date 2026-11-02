import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { auth } from "@/lib/auth";
import { validateTelegramConfig, checkRateLimit } from "@/lib/webhooks";
import { sendTelegramAlert, AlertData } from "@/lib/notifications";

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
    const rateCheck = checkRateLimit(`telegram-setup:${user.id}`, 5, 60_000);
    if (!rateCheck.allowed) {
      return NextResponse.json(
        { error: "Too many setup requests. Please wait a moment before trying again." },
        { status: 429 }
      );
    }

    let body: { botToken?: string; chatId?: string; alertSensitivity?: string };
    try {
      body = await req.json();
    } catch {
      return NextResponse.json({ error: "Invalid JSON request body" }, { status: 400 });
    }

    const { botToken, chatId, alertSensitivity = "high_critical" } = body;

    if (!botToken || !chatId) {
      return NextResponse.json(
        { error: "Bot token and Chat ID are required" },
        { status: 400 }
      );
    }

    // 1. Strict Telegram credential validation
    const validation = validateTelegramConfig(botToken, chatId);
    if (!validation.valid) {
      return NextResponse.json({ error: validation.reason }, { status: 400 });
    }

    // 2. Dispatch verification test message
    const testAlert: AlertData = {
      url: "https://guardai.app/security-check",
      score: 10,
      severity: "low",
      explanation: "GuardAI: Telegram integration successfully connected and verified.",
      vtScore: "Verified",
      sslStatus: "VALID (TLS 1.3)",
      missingHeaders: "None",
      mlScore: "Normal",
      action: "Integration active. You will receive alerts according to your sensitivity preferences.",
      scanId: "integration-setup",
    };

    try {
      await sendTelegramAlert(botToken, chatId, testAlert);
    } catch (deliveryErr: any) {
      return NextResponse.json(
        { error: `Telegram delivery failed: ${deliveryErr.message}` },
        { status: 400 }
      );
    }

    // 3. Upsert configuration in DB
    const existing = await prisma.notification.findFirst({
      where: { userId: user.id, platform: "telegram" },
    });

    if (existing) {
      await prisma.notification.update({
        where: { id: existing.id },
        data: {
          config: {
            botToken: botToken.trim(),
            chatId: chatId.trim(),
            alertSensitivity,
          },
          isActive: true,
        },
      });
    } else {
      await prisma.notification.create({
        data: {
          platform: "telegram",
          config: {
            botToken: botToken.trim(),
            chatId: chatId.trim(),
            alertSensitivity,
          },
          userId: user.id,
          isActive: true,
        },
      });
    }

    return NextResponse.json({
      success: true,
      maskedToken: validation.maskedToken,
    });
  } catch (error: any) {
    console.error("Telegram alert setup error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
