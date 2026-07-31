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
// Synthetic Threat Pool (DELETED)
// ---------------------------------------------------------------------------
const THREAT_POOL: any[] = [];
const GEO_POOL: any[] = [];

// ---------------------------------------------------------------------------
// POST — start simulation
// ---------------------------------------------------------------------------
export async function POST(_req: Request) {
  return NextResponse.json({
    message: "Simulation is disabled. Using real database integrations.",
  });
}

// ---------------------------------------------------------------------------
// DELETE — stop simulation
// ---------------------------------------------------------------------------
export async function DELETE(_req: Request) {
  return NextResponse.json({ message: "Simulation is disabled." });
}
