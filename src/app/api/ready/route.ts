import { NextResponse } from "next/server";
import { checkDatabaseHealth } from "@/lib/db";

export const dynamic = "force-dynamic";

export async function GET() {
  const dbHealth = await checkDatabaseHealth();
  const isReady = dbHealth.status === "up";

  return NextResponse.json(
    {
      status: isReady ? "ready" : "unhealthy",
      service: "guardai",
      timestamp: new Date().toISOString(),
      dependencies: {
        database: dbHealth,
      },
    },
    {
      status: isReady ? 200 : 503,
      headers: {
        "Cache-Control": "no-store, no-cache, must-revalidate",
      },
    }
  );
}

