import { NextResponse } from "next/server";

export async function POST(request: Request) {
  try {
    const { platform, webhookUrl, botToken, chatId } = await request.json();

    if (platform === "discord") {
      if (!webhookUrl) {
        return NextResponse.json({ error: "Discord webhook URL is required" }, { status: 400 });
      }

      // Test the Discord webhook
      const response = await fetch(webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          embeds: [
            {
              title: "🛡️ GuardAI Test Alert",
              description: "Successfully connected to GuardAI threat monitoring system.",
              color: 0x00F0FF,
              fields: [
                { name: "Status", value: "Connected", inline: true },
                { name: "Time", value: new Date().toISOString(), inline: true },
              ],
              footer: { text: "GuardAI Cybersecurity Platform" },
            },
          ],
        }),
      });

      if (!response.ok) {
        return NextResponse.json({ error: "Failed to send Discord webhook" }, { status: 500 });
      }

      return NextResponse.json({ success: true, platform: "discord" });
    }

    if (platform === "telegram") {
      if (!botToken || !chatId) {
        return NextResponse.json({ error: "Bot token and chat ID are required" }, { status: 400 });
      }

      // Test the Telegram bot
      const response = await fetch(
        `https://api.telegram.org/bot${botToken}/sendMessage`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chat_id: chatId,
            text: "🛡️ GuardAI Test Alert\n\nSuccessfully connected to GuardAI threat monitoring system.\n\nStatus: Connected\nTime: " + new Date().toISOString(),
            parse_mode: "HTML",
          }),
        }
      );

      if (!response.ok) {
        return NextResponse.json({ error: "Failed to send Telegram message" }, { status: 500 });
      }

      return NextResponse.json({ success: true, platform: "telegram" });
    }

    return NextResponse.json({ error: "Invalid platform" }, { status: 400 });
  } catch (error) {
    console.error("Notification error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
