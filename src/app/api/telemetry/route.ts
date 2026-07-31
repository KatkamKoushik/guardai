import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const scans = await prisma.scan.findMany({
      take: 10,
      orderBy: { createdAt: "desc" },
    });

    const items = scans.map(scan => {
      let domain = scan.url;
      try { domain = new URL(scan.url).hostname; } catch {}
      const details = scan.details as any;
      return {
        id: scan.id,
        target: domain,
        domain,
        score: scan.score,
        threatType: scan.threatLevel,
        ipAddress: details?.geoIp?.query || null,
        latitude: details?.geoIp?.lat || null,
        longitude: details?.geoIp?.lon || null,
        countryCode: details?.geoIp?.country || null,
        timestamp: scan.createdAt.toISOString()
      };
    });

    return NextResponse.json({ items });
  } catch (error) {
    console.error("Error fetching recent telemetry:", error);
    return NextResponse.json({ error: "Failed to fetch telemetry" }, { status: 500 });
  }
}
