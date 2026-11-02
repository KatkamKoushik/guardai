import { test, expect } from "@playwright/test";

test.describe("Scan API Security & Validation (E2E)", () => {
  test("POST /api/scan rejects missing or empty URL payload", async ({ request }) => {
    const res = await request.post("/api/scan", {
      data: {},
    });
    expect(res.status()).toBe(400);

    const body = await res.json();
    expect(body.error).toBeDefined();
  });

  test("POST /api/scan actively blocks SSRF targets attempting loopback access", async ({ request }) => {
    const res = await request.post("/api/scan", {
      data: { url: "http://127.0.0.1:8080/admin" },
    });
    expect(res.status()).toBe(400);

    const body = await res.json();
    expect(body.error).toContain("SSRF Blocked");
    expect(body.status).toBe("REJECTED_INTERNAL_TARGET");
  });

  test("POST /api/scan blocks AWS metadata cloud IP (169.254.169.254)", async ({ request }) => {
    const res = await request.post("/api/scan", {
      data: { url: "http://169.254.169.254/latest/meta-data/" },
    });
    expect(res.status()).toBe(400);

    const body = await res.json();
    expect(body.error).toContain("SSRF Blocked");
  });

  test("POST /api/scan rejects malformed gibberish input", async ({ request }) => {
    const res = await request.post("/api/scan", {
      data: { url: "not-a-valid-url" },
    });
    expect(res.status()).toBe(400);

    const body = await res.json();
    expect(body.error).toContain("Invalid Input");
  });
});
