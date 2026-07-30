import { NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import csv from "csv-parser";
import { prisma } from "@/lib/db";
// Disable strict dynamic rule so we can use local file system
export const dynamic = "force-dynamic";

let isSimulating = false;
let simulationInterval: NodeJS.Timeout | null = null;

export async function POST(req: Request) {
  if (isSimulating) {
    return NextResponse.json({ message: "Simulation is already running" });
  }

  isSimulating = true;
  const results: any[] = [];
  
  const csvPath = path.join(process.cwd(), "malicious_urls_dataset.csv");
  
  try {
    let geoip: any = null;
    try {
      geoip = require('geoip-lite');
    } catch (e) {
      console.warn("Could not load geoip-lite, skipping geolocation");
    }
    
    // Read the CSV into memory
    fs.createReadStream(csvPath)
      .pipe(csv())
      .on("data", (data) => results.push(data))
      .on("end", () => {
        let index = 0;
        
        // Loop every 4 seconds to emit a real threat from the CSV
        simulationInterval = setInterval(async () => {
          if (results.length === 0) return;
          const row = results[index % results.length];
          index++;
          
          let lat = null;
          let lon = null;
          let country = null;

          if (geoip && row.ip) {
            const geo = geoip.lookup(row.ip);
            if (geo) {
              lat = geo.ll[0];
              lon = geo.ll[1];
              country = geo.country;
            }
          }

          const threatType = row.type || "malware";
          
          try {
            await prisma.threatTelemetry.create({
              data: {
                domain: row.url || "unknown.com",
                threatType,
                ipAddress: row.ip || null,
                latitude: lat,
                longitude: lon,
                countryCode: country,
                timestamp: new Date()
              }
            });
          } catch (e) {
            console.error("Failed to insert CSV telemetry data", e);
          }

        }, 4000);
      });

    return NextResponse.json({ message: "CSV simulation started in the background" });
  } catch (err) {
    console.error("Simulation error:", err);
    isSimulating = false;
    return NextResponse.json({ error: "Failed to read CSV", details: String(err) }, { status: 500 });
  }
}

export async function DELETE(req: Request) {
  if (simulationInterval) {
    clearInterval(simulationInterval);
    simulationInterval = null;
    isSimulating = false;
  }
  return NextResponse.json({ message: "Simulation stopped" });
}
