import { useState, useEffect } from 'react';

export interface ThreatTelemetry {
  id: string;
  ipAddress: string | null;
  domain: string;
  threatType: string;
  countryCode: string | null;
  latitude: number | null;
  longitude: number | null;
  timestamp: string;
}

export interface RealtimeThreatsState {
  latestThreats: ThreatTelemetry[];
  threatCount: number;
  scanCount: number;
  systemStatus: "Connected" | "Reconnecting" | "Disconnected";
  connectionLatency: number;
}

export function useRealtimeThreats(): RealtimeThreatsState {
  const [latestThreats, setLatestThreats] = useState<ThreatTelemetry[]>([]);
  const [threatCount, setThreatCount] = useState(0);
  const [scanCount, setScanCount] = useState(0);
  const [systemStatus, setSystemStatus] = useState<RealtimeThreatsState["systemStatus"]>("Disconnected");
  const [connectionLatency, setConnectionLatency] = useState(0);

  useEffect(() => {
    let lastPollTime = Date.now();
    let isMounted = true;

    async function pollTelemetry() {
      if (!isMounted) return;
      
      const startTime = Date.now();
      try {
        setSystemStatus("Reconnecting");
        const res = await fetch("/api/telemetry", {
          cache: "no-store", // Ensure we bypass Next.js cache
        });
        
        if (!res.ok) throw new Error("Failed to fetch telemetry");
        
        const data = await res.json();
        
        const latency = Date.now() - startTime;
        setConnectionLatency(latency);
        setSystemStatus("Connected");

        if (data.recentScans) {
          // Map backend's 'threatLevel' to frontend's 'threatType'
          const mappedThreats: ThreatTelemetry[] = data.recentScans.map((scan: any) => ({
            id: scan.id,
            ipAddress: scan.ipAddress,
            domain: scan.domain,
            threatType: scan.threatLevel || "Unknown",
            countryCode: scan.countryCode,
            latitude: scan.latitude,
            longitude: scan.longitude,
            timestamp: scan.timestamp,
          }));
          setLatestThreats(mappedThreats);
        }
        
        if (typeof data.totalThreats === 'number') {
          setThreatCount(data.totalThreats);
        }
        
        if (typeof data.totalScans === 'number') {
          setScanCount(data.totalScans);
        }
      } catch (err) {
        console.error("Telemetry Poll Error:", err);
        setSystemStatus("Disconnected");
      }
    }

    // Initial fetch
    pollTelemetry();

    // Poll every 2 seconds
    const interval = setInterval(pollTelemetry, 2000);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  return {
    latestThreats,
    threatCount,
    scanCount,
    systemStatus,
    connectionLatency,
  };
}
