import { NextResponse } from "next/server";

const MOCK_THREATS = [
  { id: "1", lat: 55.75, lng: 37.62, severity: "critical", type: "DDoS", source: "Moscow, RU", target: "New York, US", timestamp: "2 min ago" },
  { id: "2", lat: 39.90, lng: 116.40, severity: "high", type: "Ransomware", source: "Beijing, CN", target: "London, UK", timestamp: "5 min ago" },
  { id: "3", lat: 37.57, lng: 126.98, severity: "medium", type: "Phishing", source: "Seoul, KR", target: "Tokyo, JP", timestamp: "8 min ago" },
  { id: "4", lat: 51.51, lng: -0.13, severity: "low", type: "Scan", source: "London, UK", target: "Berlin, DE", timestamp: "12 min ago" },
  { id: "5", lat: 40.71, lng: -74.01, severity: "high", type: "Malware", source: "New York, US", target: "Sao Paulo, BR", timestamp: "15 min ago" },
];

export async function GET() {
  // In production, fetch from real threat feeds (OTX AlienVault, AbuseIPDB, etc.)
  return NextResponse.json({
    threats: MOCK_THREATS,
    lastUpdated: new Date().toISOString(),
    stats: {
      total: MOCK_THREATS.length,
      critical: MOCK_THREATS.filter((t) => t.severity === "critical").length,
      high: MOCK_THREATS.filter((t) => t.severity === "high").length,
      medium: MOCK_THREATS.filter((t) => t.severity === "medium").length,
      low: MOCK_THREATS.filter((t) => t.severity === "low").length,
    },
  });
}
