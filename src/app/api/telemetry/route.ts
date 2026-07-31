/**
 * GuardAI — Telemetry API (GET /api/telemetry)
 *
 * Real-time stats endpoint polled by the LiveTelemetry client component.
 * Returns live Prisma data only — no mock fallbacks.
 *
 * Cache-busting:
 *   - `force-dynamic`  — disables Next.js static generation / route caching
 *   - `revalidate = 0` — ensures no CDN / ISR caching layer is applied
 */

import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET() {
  try {
    // Run all three Prisma queries concurrently for minimal latency.
    const [totalScans, totalThreats, rawScans] = await Promise.all([
      // Total number of scans ever recorded
      prisma.scan.count(),

      // Scans with a risk score >= 70 are classified as threats
      prisma.scan.count({
        where: { score: { gte: 70 } },
      }),

      // The 8 most recent scans for the live feed
      prisma.scan.findMany({
        take: 8,
        orderBy: { createdAt: "desc" },
        select: {
          id: true,
          url: true,
          score: true,
          threatLevel: true,
          createdAt: true,
          details: true,
        },
      }),
    ]);

    // Normalise each scan record for the client feed
    const recentScans = rawScans.map((scan) => {
      let domain = scan.url;
      try {
        domain = new URL(scan.url).hostname;
      } catch {
        // If URL parsing fails, fall back to the raw URL string
      }

      const details = scan.details as Record<string, any> | null;

      return {
        id: scan.id,
        target: domain,
        domain,
        score: scan.score,
        threatLevel: scan.threatLevel,
        // GeoIP data stored at scan time (may be null)
        ipAddress: details?.geoIp?.query ?? null,
        latitude: details?.geoIp?.lat ?? null,
        longitude: details?.geoIp?.lon ?? null,
        countryCode: details?.geoIp?.country ?? null,
        timestamp: scan.createdAt.toISOString(),
      };
    });

    const headers = {
      "Cache-Control": "no-store, max-age=0",
      "Pragma": "no-cache",
    };

    return NextResponse.json(
      {
        totalScans,
        totalThreats,
        recentScans,
        // Clients can use this flag to show "Waiting for live scans…"
        waitingForData: recentScans.length === 0,
      },
      { headers }
    );
  } catch (error) {
    console.error("TELEMETRY DB ERROR:", error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status: 500 }
    );
  }
}
