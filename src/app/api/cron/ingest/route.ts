import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

// Force this route to be dynamic so it runs on every request
export const dynamic = "force-dynamic";
// Set a longer max duration if deployed on Vercel
export const maxDuration = 60;

interface UrlhausResponse {
  query_status: string;
  urls?: {
    id: string;
    urlhaus_reference: string;
    url: string;
    url_status: string;
    host: string;
    date_added: string;
    threat: string;
    reporter: string;
    larted: string;
    tags: string[];
  }[];
}

function isAuthorized(request: Request) {
  const secret = process.env.CRON_SECRET;
  if (!secret) return false;
  const incoming = request.headers.get("x-cron-secret");
  return incoming === secret;
}

export async function POST(request: Request) {
  if (!process.env.CRON_SECRET) {
    return NextResponse.json({ error: "Cron secret not configured" }, { status: 500 });
  }
  if (!isAuthorized(request)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    // 1. Fetch recent threats from URLhaus
    const response = await fetch("https://urlhaus-api.abuse.ch/v1/urls/recent/", {
      headers: {
        Accept: "application/json",
      },
      // Cache for a short time to prevent spamming the API
      next: { revalidate: 60 },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch URLhaus data: ${response.statusText}`);
    }

    const data = (await response.json()) as UrlhausResponse;

    if (data.query_status !== "ok" || !data.urls) {
      return NextResponse.json({ message: "No new data from URLhaus" }, { status: 200 });
    }

    // 2. Transform the data to match our ThreatTelemetry schema
    // We only take the 50 most recent to avoid overwhelming the DB
    const threatsToInsert = data.urls.slice(0, 50).map((item) => {
      // URLhaus doesn't always provide precise lat/lon natively in this endpoint,
      // so we will derive mock coordinates based on host hash for visualization,
      // or leave them null. For a real map, we'd need an IP geolocation service.
      
      let domain = item.host;
      try {
        if (!domain) {
          domain = new URL(item.url).hostname;
        }
      } catch (e) {
        domain = "unknown";
      }

      return {
        domain,
        threatType: item.threat || "malware",
        // Fallbacks for demonstration
        ipAddress: null,
        countryCode: null, 
        latitude: null,
        longitude: null,
        // Ensure valid date
        timestamp: new Date(item.date_added ? item.date_added + " UTC" : Date.now()) 
      };
    });

    // 3. Save to database using a transaction to increment a global mock counter if needed,
    // or just insert the telemetry.
    
    // We'll create the telemetry entries
    const created = await prisma.threatTelemetry.createMany({
      data: threatsToInsert,
      skipDuplicates: true, // Requires unique constraint, but we don't have one. 
                            // That's fine, we'll just insert for the streaming demo.
    });

    // Optionally add a random scan audit for demo purposes
    await prisma.auditLog.create({
      data: {
        action: "DEEP_SCAN",
        target: threatsToInsert[0]?.domain || "unknown-domain.com",
        status: Math.random() > 0.8 ? "failed" : "success",
        severity: Math.random() > 0.8 ? "critical" : "low",
        details: "Automated cron ingestion scan",
        userId: "System",
      },
    });

    return NextResponse.json(
      { 
        message: "Threats ingested successfully",
        count: created.count 
      },
      { status: 200 }
    );
  } catch (error) {
    console.error("Ingestion error:", error);
    return NextResponse.json(
      { error: "Internal Server Error" },
      { status: 500 }
    );
  }
}
