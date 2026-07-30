import { NextResponse } from "next/server";

export async function POST(request: Request) {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    const { platform, webhookUrl, botToken, chatId } = await request.json();

    const controller = new AbortController();
    timeout = setTimeout(() => controller.abort(), 10_000);

    if (platform === "discord") {
      if (!webhookUrl) {
        return NextResponse.json({ error: "Discord webhook URL is required" }, { status: 400 });
      }

      let parsedUrl: URL;
      try {
        parsedUrl = new URL(webhookUrl);
      } catch {
        return NextResponse.json({ error: "Invalid webhook URL format" }, { status: 400 });
      }

      const isAllowedHost =
        parsedUrl.protocol === "https:" &&
        (parsedUrl.hostname === "discord.com" || parsedUrl.hostname === "discordapp.com");
      const isWebhookPath = parsedUrl.pathname.startsWith("/api/webhooks/");
      if (!isAllowedHost || !isWebhookPath) {
        return NextResponse.json({ error: "Only valid Discord webhook URLs are allowed" }, { status: 400 });
      }

      // Test the Discord webhook
      const response = await fetch(webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: controller.signal,
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
          signal: controller.signal,
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
    if ((error as Error).name === "AbortError") {
      return NextResponse.json({ error: "Notification provider timeout" }, { status: 504 });
    }
    console.error("Notification error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
  }
}
