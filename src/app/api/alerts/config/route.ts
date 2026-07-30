import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { auth } from "@/lib/auth";

export async function GET(req: Request) {
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

    // Mask sensitive details before sending to client
    const configs = user.notifications.map((notif) => {
      const configObj = notif.config as any;
      return {
        id: notif.id,
        platform: notif.platform,
        isActive: notif.isActive,
        alertSensitivity: configObj.alertSensitivity || "high_critical",
        // Mask webhook
        webhookUrl: configObj.webhookUrl ? configObj.webhookUrl.replace(/api\/webhooks\/.*/, "api/webhooks/...") : undefined,
        // Mask token
        botToken: configObj.botToken ? configObj.botToken.substring(0, 10) + "..." : undefined,
        chatId: configObj.chatId,
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

    const { platform, alertSensitivity } = await req.json();

    if (!platform || !alertSensitivity) {
      return NextResponse.json({ error: "Missing fields" }, { status: 400 });
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

    const configObj = notif.config as any;
    configObj.alertSensitivity = alertSensitivity;

    await prisma.notification.update({
      where: { id: notif.id },
      data: { config: configObj },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Update config error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
