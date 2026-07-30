import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { auth } from "@/lib/auth";

export async function POST(req: Request) {
  try {
    const session = await auth();
    if (!session?.user?.email) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { webhookUrl } = await req.json();

    if (!webhookUrl) {
      return NextResponse.json({ error: "Webhook URL is required" }, { status: 400 });
    }

    // 1. Send test payload to Discord
    const discordRes = await fetch(webhookUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        content: "🛡️ **GuardAI**: Discord integration successfully connected!",
      }),
    });

    if (!discordRes.ok) {
      return NextResponse.json(
        { error: "Failed to send test message to Discord" },
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
        platform: "discord",
        config: { webhookUrl, alertSensitivity: "high_critical" },
        userId: user.id,
      },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Discord alert setup error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
