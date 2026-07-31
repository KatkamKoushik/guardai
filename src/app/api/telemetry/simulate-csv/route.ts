/**
 * GuardAI — Synthetic Threat Telemetry Simulator
 * POST /api/telemetry/simulate-csv  → starts simulation
 * DELETE /api/telemetry/simulate-csv → stops simulation
 *
 * Previously this endpoint read from malicious_urls_dataset.csv (deleted).
 * It now generates realistic threat telemetry programmatically using a pool
 * of representative threat patterns, covering the same threat categories as
 * before (malware, phishing, botnet, ransomware, exploit) without any
 * hard-coded file dependency.
 *
 * Each simulated event picks a threat at random, resolves a plausible
 * geolocation from a curated coordinate pool, and writes directly to the
 * ThreatTelemetry table — identical behaviour to the old CSV loop.
 */

import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";

// ---------------------------------------------------------------------------
// Synthetic Threat Pool
// Represents the diversity of real-world threat types without any static file.
// ---------------------------------------------------------------------------
type ThreatType = "malware" | "phishing" | "botnet" | "ransomware" | "exploit";

interface SyntheticThreat {
  domain: string;
  threatType: ThreatType;
}

const THREAT_POOL: SyntheticThreat[] = [
  // Malware delivery
  { domain: "payload-drop.cc",          threatType: "malware"    },
  { domain: "dl.stealer-kit.ru",        threatType: "malware"    },
  { domain: "cdn.cryptominer.xyz",      threatType: "malware"    },
  { domain: "update-flash-player.tk",   threatType: "malware"    },
  { domain: "drive.evil-loader.top",    threatType: "malware"    },
  // Phishing
  { domain: "secure-paypa1-login.com",  threatType: "phishing"   },
  { domain: "apple-id-verify.tk",       threatType: "phishing"   },
  { domain: "amazon-account-update.ml", threatType: "phishing"   },
  { domain: "login.bankofamerica-auth.xyz", threatType: "phishing" },
  { domain: "netflix-billing-verify.cc", threatType: "phishing"  },
  // Botnet C2
  { domain: "c2.botmaster.ru",          threatType: "botnet"     },
  { domain: "cmd.herder-panel.cc",      threatType: "botnet"     },
  { domain: "irc.zombie-net.pw",        threatType: "botnet"     },
  // Ransomware C2
  { domain: "key-exchange.ransom-c2.onion.link", threatType: "ransomware" },
  { domain: "decrypt.lockyvariant.top", threatType: "ransomware" },
  { domain: "pay.lockbit-panel.cc",     threatType: "ransomware" },
  // Exploit kits
  { domain: "exploit.rig-ek.ru",        threatType: "exploit"    },
  { domain: "kit.magnitude-ek.cc",      threatType: "exploit"    },
  { domain: "flash.neutrino-ek.xyz",    threatType: "exploit"    },
];

// ---------------------------------------------------------------------------
// Plausible geolocation pool (lat/lon + ISO country code)
// Covers major threat actor hosting regions without relying on IP geolookup.
// ---------------------------------------------------------------------------
interface GeoEntry {
  lat: number;
  lon: number;
  country: string;
}

const GEO_POOL: GeoEntry[] = [
  { lat: 55.7558, lon:  37.6173, country: "RU" },  // Moscow
  { lat: 39.9042, lon: 116.4074, country: "CN" },  // Beijing
  { lat: 40.4093, lon:  49.8671, country: "AZ" },  // Baku
  { lat: 50.4501, lon:  30.5234, country: "UA" },  // Kyiv
  { lat: 52.2297, lon:  21.0122, country: "PL" },  // Warsaw
  { lat: 37.7749, lon:-122.4194, country: "US" },  // San Francisco
  { lat: 51.5074, lon:  -0.1278, country: "GB" },  // London
  { lat: 48.8566, lon:   2.3522, country: "FR" },  // Paris
  { lat: 35.6762, lon: 139.6503, country: "JP" },  // Tokyo
  { lat:  1.3521, lon: 103.8198, country: "SG" },  // Singapore
  { lat: 25.2048, lon:  55.2708, country: "AE" },  // Dubai
  { lat: -33.868, lon: 151.2093, country: "AU" },  // Sydney
  { lat: 19.4326, lon: -99.1332, country: "MX" },  // Mexico City
  { lat: -23.550, lon: -46.6333, country: "BR" },  // São Paulo
  { lat: 28.6139, lon:  77.2090, country: "IN" },  // New Delhi
];

// ---------------------------------------------------------------------------
// Module-level simulation state (persists for the lifetime of the process)
// ---------------------------------------------------------------------------
let isSimulating = false;
let simulationInterval: NodeJS.Timeout | null = null;

// ---------------------------------------------------------------------------
// POST — start simulation
// ---------------------------------------------------------------------------
export async function POST(_req: Request) {
  if (isSimulating) {
    return NextResponse.json({ message: "Simulation is already running." });
  }

  isSimulating = true;

  simulationInterval = setInterval(async () => {
    try {
      // Pick a random threat and geolocation
      const threat = THREAT_POOL[Math.floor(Math.random() * THREAT_POOL.length)];
      const geo    = GEO_POOL[Math.floor(Math.random() * GEO_POOL.length)];

      await prisma.threatTelemetry.create({
        data: {
          domain:      threat.domain,
          threatType:  threat.threatType,
          ipAddress:   null,               // synthetic — no real IP
          latitude:    geo.lat,
          longitude:   geo.lon,
          countryCode: geo.country,
          timestamp:   new Date(),
        },
      });
    } catch (err) {
      console.error("[simulate] Failed to insert synthetic telemetry:", err);
    }
  }, 4000);

  return NextResponse.json({
    message: "Synthetic threat simulation started.",
    note: "Emitting one threat event every 4 seconds from the in-process threat pool.",
  });
}

// ---------------------------------------------------------------------------
// DELETE — stop simulation
// ---------------------------------------------------------------------------
export async function DELETE(_req: Request) {
  if (simulationInterval) {
    clearInterval(simulationInterval);
    simulationInterval = null;
    isSimulating = false;
    return NextResponse.json({ message: "Simulation stopped." });
  }
  return NextResponse.json({ message: "No simulation was running." });
}
