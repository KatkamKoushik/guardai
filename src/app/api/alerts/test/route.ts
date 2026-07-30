import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { notifyUserForScan, AlertData } from "@/lib/notifications";
import { prisma } from "@/lib/db";

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

    const { platform } = await req.json();

    // Mock a realistic malware alert
    const mockAlertData: AlertData = {
      url: "http://wicar.org/test/eicar.com",
      score: 95,
      severity: "critical",
      explanation: "The target URL hosts an active remote code execution payload flagged by 19 malware vendors.",
      vtScore: "19 / 92 engines flagged as Malicious",
      sslStatus: "UNENCRYPTED (HTTP Only)",
      missingHeaders: "HSTS, X-Frame-Options, CSP",
      mlScore: "Shannon Entropy: 3.096",
      action: "Do not navigate to this site. Block traffic at firewall.",
      scanId: "test-scan-id-123",
    };

    // If platform is specified, we bypass the DB check and just send the test alert to that specific platform's config
    if (platform) {
      const notif = await prisma.notification.findFirst({
        where: { userId: user.id, platform, isActive: true },
      });

      if (!notif) {
        return NextResponse.json({ error: "Integration not found or not active" }, { status: 404 });
      }

      const config = notif.config as any;
      
      if (platform === "discord" && config.webhookUrl) {
        const { sendDiscordWebhook } = await import("@/lib/notifications");
        await sendDiscordWebhook(config.webhookUrl, mockAlertData);
      } else if (platform === "telegram" && config.botToken && config.chatId) {
        const { sendTelegramAlert } = await import("@/lib/notifications");
        await sendTelegramAlert(config.botToken, config.chatId, mockAlertData);
      }
    } else {
      // Default: test through the standard dispatch flow (which checks sensitivity)
      await notifyUserForScan(user.id, mockAlertData);
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Test alert error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
