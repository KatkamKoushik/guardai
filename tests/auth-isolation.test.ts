import { describe, it, expect, vi } from "vitest";
import { GET as getAudit } from "../src/app/api/audit/route";
import { GET as getAlertConfig, PATCH as patchAlertConfig, DELETE as deleteAlertConfig } from "../src/app/api/alerts/config/route";
import { POST as postDiscord } from "../src/app/api/alerts/discord/route";
import { POST as postTelegram } from "../src/app/api/alerts/telegram/route";
import { POST as postAlertTest } from "../src/app/api/alerts/test/route";
import { POST as postNotifications } from "../src/app/api/notifications/route";

// Mock auth module to return null session (unauthenticated anonymous user)
vi.mock("@/lib/auth", () => ({
  auth: vi.fn().mockResolvedValue(null),
}));

describe("Authentication & Negative Authorization Security Controls", () => {
  it("rejects unauthenticated GET /api/audit with 401 Unauthorized", async () => {
    const res = await getAudit();
    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.error).toBe("Unauthorized");
  });

  it("rejects unauthenticated GET /api/alerts/config with 401 Unauthorized", async () => {
    const res = await getAlertConfig();
    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.error).toBe("Unauthorized");
  });

  it("rejects unauthenticated PATCH /api/alerts/config with 401 Unauthorized", async () => {
    const req = new Request("http://localhost:3000/api/alerts/config", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ platform: "discord", alertSensitivity: "critical" }),
    });
    const res = await patchAlertConfig(req);
    expect(res.status).toBe(401);
  });

  it("rejects unauthenticated DELETE /api/alerts/config with 401 Unauthorized", async () => {
    const req = new Request("http://localhost:3000/api/alerts/config?platform=discord", {
      method: "DELETE",
    });
    const res = await deleteAlertConfig(req);
    expect(res.status).toBe(401);
  });

  it("rejects unauthenticated POST /api/alerts/discord with 401 Unauthorized", async () => {
    const req = new Request("http://localhost:3000/api/alerts/discord", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ webhookUrl: "https://discord.com/api/webhooks/123/abc" }),
    });
    const res = await postDiscord(req);
    expect(res.status).toBe(401);
  });

  it("rejects unauthenticated POST /api/alerts/telegram with 401 Unauthorized", async () => {
    const req = new Request("http://localhost:3000/api/alerts/telegram", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ botToken: "123:abc", chatId: "456" }),
    });
    const res = await postTelegram(req);
    expect(res.status).toBe(401);
  });

  it("rejects unauthenticated POST /api/alerts/test with 401 Unauthorized", async () => {
    const req = new Request("http://localhost:3000/api/alerts/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ platform: "discord" }),
    });
    const res = await postAlertTest(req);
    expect(res.status).toBe(401);
  });

  it("rejects unauthenticated POST /api/notifications with 401 Unauthorized", async () => {
    const req = new Request("http://localhost:3000/api/notifications", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ platform: "discord", webhookUrl: "https://discord.com/api/webhooks/123/abc" }),
    });
    const res = await postNotifications(req);
    expect(res.status).toBe(401);
  });
});

