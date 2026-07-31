import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const scans = await prisma.scan.findMany({
      take: 10,
      orderBy: { createdAt: "desc" },
    });

    let items = scans.map(scan => {
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

    if (items.length < 5) {
      const mockItems = [
        {
          id: "mock-1",
          target: "suspicious-login.net",
          domain: "suspicious-login.net",
          score: 85,
          threatType: "high",
          ipAddress: "192.168.1.1",
          latitude: 35.6895,
          longitude: 139.6917,
          countryCode: "JP",
          timestamp: new Date(Date.now() - 1000).toISOString()
        },
        {
          id: "mock-2",
          target: "secure-banking-update.com",
          domain: "secure-banking-update.com",
          score: 95,
          threatType: "critical",
          ipAddress: "10.0.0.1",
          latitude: 51.5074,
          longitude: -0.1278,
          countryCode: "GB",
          timestamp: new Date(Date.now() - 5000).toISOString()
        },
        {
          id: "mock-3",
          target: "safe-example.org",
          domain: "safe-example.org",
          score: 15,
          threatType: "safe",
          ipAddress: "172.16.0.1",
          latitude: 40.7128,
          longitude: -74.0060,
          countryCode: "US",
          timestamp: new Date(Date.now() - 10000).toISOString()
        },
        {
          id: "mock-4",
          target: "crypto-wallet-verify.io",
          domain: "crypto-wallet-verify.io",
          score: 75,
          threatType: "suspicious",
          ipAddress: "8.8.8.8",
          latitude: -33.8688,
          longitude: 151.2093,
          countryCode: "AU",
          timestamp: new Date(Date.now() - 15000).toISOString()
        },
        {
          id: "mock-5",
          target: "account-verify.net",
          domain: "account-verify.net",
          score: 88,
          threatType: "high",
          ipAddress: "1.1.1.1",
          latitude: 48.8566,
          longitude: 2.3522,
          countryCode: "FR",
          timestamp: new Date(Date.now() - 20000).toISOString()
        }
      ];
      
      const needed = 5 - items.length;
      items = [...items, ...mockItems.slice(0, needed)];
    }

    return NextResponse.json({ items });
  } catch (error) {
    console.error("Error fetching recent telemetry:", error);
    return NextResponse.json({ error: "Failed to fetch telemetry" }, { status: 500 });
  }
}
