import { test, expect } from "@playwright/test";

test.describe("API Health & Readiness Probes (E2E)", () => {
  test("GET /api/health returns healthy liveness state and memory diagnostics", async ({ request }) => {
    const res = await request.get("/api/health");
    expect(res.status()).toBe(200);

    const data = await res.json();
    expect(data.status).toBe("healthy");
    expect(data.service).toBe("guardai");
    expect(typeof data.uptimeSeconds).toBe("number");
    expect(data.memory).toHaveProperty("rssMb");
    expect(data.memory).toHaveProperty("heapUsedMb");
  });

  test("GET /api/ready returns operational dependency readiness probe", async ({ request }) => {
    const res = await request.get("/api/ready");
    // Depending on local DB availability, status is 200 (ready) or 503 (unhealthy)
    expect([200, 503]).toContain(res.status());

    const data = await res.json();
    expect(data).toHaveProperty("status");
    expect(data.dependencies).toHaveProperty("database");
  });
});
