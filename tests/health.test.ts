import { describe, it, expect, vi } from "vitest";
import { GET as healthHandler } from "@/app/api/health/route";
import { GET as readyHandler } from "@/app/api/ready/route";
import * as dbModule from "@/lib/db";

describe("Health & Readiness Probes", () => {
  it("GET /api/health returns 200 with runtime diagnostics", async () => {
    const res = await healthHandler();
    expect(res.status).toBe(200);

    const json = await res.json();
    expect(json.status).toBe("healthy");
    expect(json.service).toBe("guardai");
    expect(json.uptimeSeconds).toBeGreaterThanOrEqual(0);
    expect(json.nodeVersion).toBe(process.version);
    expect(json.memory).toHaveProperty("rssMb");
    expect(json.memory).toHaveProperty("heapUsedMb");
    expect(res.headers.get("Cache-Control")).toContain("no-store");
  });

  it("GET /api/ready returns 200 when database probe reports healthy", async () => {
    const spy = vi.spyOn(dbModule, "checkDatabaseHealth").mockResolvedValueOnce({
      status: "up",
      latencyMs: 3,
    });

    const res = await readyHandler();
    expect(res.status).toBe(200);

    const json = await res.json();
    expect(json.status).toBe("ready");
    expect(json.dependencies.database.status).toBe("up");
    expect(json.dependencies.database.latencyMs).toBe(3);

    spy.mockRestore();
  });

  it("GET /api/ready returns 503 when database is unreachable", async () => {
    const spy = vi.spyOn(dbModule, "checkDatabaseHealth").mockResolvedValueOnce({
      status: "down",
      latencyMs: 15,
      error: "Connection refused: postgres:5432",
    });

    const res = await readyHandler();
    expect(res.status).toBe(503);

    const json = await res.json();
    expect(json.status).toBe("unhealthy");
    expect(json.dependencies.database.status).toBe("down");
    expect(json.dependencies.database.error).toBe("Connection refused: postgres:5432");

    spy.mockRestore();
  });
});

