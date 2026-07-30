import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { auth } from "@/lib/auth";

export async function POST(req: Request) {
  try {
    const session = await auth();
    if (!session?.user?.email) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { botToken, chatId } = await req.json();

    if (!botToken || !chatId) {
      return NextResponse.json(
        { error: "Bot token and Chat ID are required" },
        { status: 400 }
      );
    }

    // 1. Send test payload to Telegram
    const telegramRes = await fetch(
      `https://api.telegram.org/bot${botToken}/sendMessage`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          chat_id: chatId,
          text: "🛡️ *GuardAI*: Telegram integration successfully connected!",
          parse_mode: "Markdown",
        }),
      }
    );

    const telegramData = await telegramRes.json();

    if (!telegramRes.ok || !telegramData.ok) {
      return NextResponse.json(
        { error: telegramData.description || "Failed to send test message to Telegram" },
        { status: 400 }
      );
    }

    // 2. Save config to DB
    const user = await prisma.user.findUnique({
      where: { email: session.user.email },
    });

    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    await prisma.notification.create({
      data: {
        platform: "telegram",
        config: { botToken, chatId, alertSensitivity: "high_critical" },
        userId: user.id,
      },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Telegram alert setup error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
