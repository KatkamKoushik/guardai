import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const threats: Array<{ id: string; threatType: string; timestamp: Date; domain: string; latitude: number | null; longitude: number | null; ipAddress: string | null; countryCode: string | null }> = await prisma.threatTelemetry.findMany({
      take: 100,
      orderBy: { timestamp: "desc" },
    });

    return NextResponse.json({
      threats,
      lastUpdated: new Date().toISOString(),
      stats: {
        total: threats.length,
        critical: threats.filter((t) => t.threatType.toLowerCase().includes("critical")).length,
        high: threats.filter((t) => t.threatType.toLowerCase().includes("high")).length,
        medium: threats.filter((t) => t.threatType.toLowerCase().includes("medium")).length,
        low: threats.filter((t) => t.threatType.toLowerCase().includes("low")).length,
      },
    });
  } catch (error) {
    console.error("Threats route error:", error);
    return NextResponse.json({ error: "Failed to fetch threats" }, { status: 500 });
  }
}
