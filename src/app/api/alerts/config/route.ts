import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { auth } from "@/lib/auth";
import { validateDiscordWebhookUrl, validateTelegramConfig } from "@/lib/webhooks";

export async function GET() {
  try {
    const session = await auth();
    if (!session?.user?.email) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const user = await prisma.user.findUnique({
      where: { email: session.user.email },
      include: { notifications: true },
    });

    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    // Mask sensitive secrets before sending to client
    const configs = user.notifications.map((notif) => {
      const configObj = notif.config as Record<string, any>;
      let maskedWebhook: string | undefined;
      let maskedToken: string | undefined;

      if (configObj.webhookUrl) {
        const val = validateDiscordWebhookUrl(configObj.webhookUrl);
        maskedWebhook = val.valid ? val.maskedUrl : "https://discord.com/api/webhooks/••••";
      }

      if (configObj.botToken) {
        const val = validateTelegramConfig(configObj.botToken, configObj.chatId || "0");
        maskedToken = val.valid ? val.maskedToken : "••••••••••••";
      }

      return {
        id: notif.id,
        platform: notif.platform,
        isActive: notif.isActive,
        alertSensitivity: configObj.alertSensitivity || "high_critical",
        webhookUrl: maskedWebhook,
        botToken: maskedToken,
        chatId: configObj.chatId,
        createdAt: notif.createdAt.toISOString(),
      };
    });

    return NextResponse.json({ configs });
  } catch (error) {
    console.error("Fetch configs error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function PATCH(req: Request) {
  try {
    const session = await auth();
    if (!session?.user?.email) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    let body: { platform?: string; alertSensitivity?: string; isActive?: boolean };
    try {
      body = await req.json();
    } catch {
      return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
    }

    const { platform, alertSensitivity, isActive } = body;

    if (!platform) {
      return NextResponse.json({ error: "Platform is required" }, { status: 400 });
    }

    const user = await prisma.user.findUnique({
      where: { email: session.user.email },
      include: { notifications: true },
    });

    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    // Strict user ownership check
    const notif = user.notifications.find((n) => n.platform === platform);
    if (!notif) {
      return NextResponse.json({ error: "Integration not found" }, { status: 404 });
    }

    const configObj = notif.config as Record<string, any>;
    if (alertSensitivity) {
      const validSensitivities = ["all", "high_critical", "critical"];
      if (!validSensitivities.includes(alertSensitivity)) {
        return NextResponse.json({ error: "Invalid alert sensitivity level" }, { status: 400 });
      }
      configObj.alertSensitivity = alertSensitivity;
    }

    await prisma.notification.update({
      where: { id: notif.id },
      data: {
        config: configObj,
        isActive: typeof isActive === "boolean" ? isActive : notif.isActive,
      },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Update config error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function DELETE(req: Request) {
  try {
    const session = await auth();
    if (!session?.user?.email) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const url = new URL(req.url);
    const platform = url.searchParams.get("platform");

    if (!platform) {
      return NextResponse.json({ error: "Platform parameter is required" }, { status: 400 });
    }

    const user = await prisma.user.findUnique({
      where: { email: session.user.email },
      include: { notifications: true },
    });

    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    const notif = user.notifications.find((n) => n.platform === platform);
    if (!notif) {
      return NextResponse.json({ error: "Integration not found" }, { status: 404 });
    }

    await prisma.notification.delete({
      where: { id: notif.id },
    });

    return NextResponse.json({ success: true, message: `Deleted ${platform} alert integration` });
  } catch (error) {
    console.error("Delete config error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
