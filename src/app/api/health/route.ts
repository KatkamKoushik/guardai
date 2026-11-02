import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET() {
  const mem = process.memoryUsage();
  return NextResponse.json(
    {
      status: "healthy",
      service: "guardai",
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.floor(process.uptime()),
      nodeVersion: process.version,
      memory: {
        rssMb: Math.round(mem.rss / 1024 / 1024),
        heapUsedMb: Math.round(mem.heapUsed / 1024 / 1024),
        heapTotalMb: Math.round(mem.heapTotal / 1024 / 1024),
      },
    },
    {
      status: 200,
      headers: {
        "Cache-Control": "no-store, no-cache, must-revalidate",
      },
    }
  );
}

