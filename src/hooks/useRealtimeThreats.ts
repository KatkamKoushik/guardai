import { useState, useEffect, useRef } from 'react';

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

  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const lastMessageTimeRef = useRef<number>(Date.now());
  const fallbackPollRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    function fetchInitial() {
      fetch("/api/telemetry")
        .then(res => res.json())
        .then(data => {
          if (data.items && data.items.length > 0) {
            setLatestThreats(data.items);
            if (fallbackPollRef.current) clearInterval(fallbackPollRef.current);
          } else {
            if (!fallbackPollRef.current) {
              fallbackPollRef.current = setInterval(fetchInitial, 5000);
            }
          }
        })
        .catch(err => console.error("Failed to fetch initial telemetry", err));
    }
    
    fetchInitial();

    function connect() {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }

      setSystemStatus("Reconnecting");
      
      const sse = new EventSource("/api/telemetry/stream");
      eventSourceRef.current = sse;

      sse.onopen = () => {
        setSystemStatus("Connected");
        lastMessageTimeRef.current = Date.now();
      };

      sse.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          // Calculate latency: time since last message (expect ~2000ms from server)
          // To get true ping we'd need roundtrip, but for SSE we just measure consistency
          const now = Date.now();
          setConnectionLatency(now - lastMessageTimeRef.current);
          lastMessageTimeRef.current = now;

          if (data.newThreat) {
            setLatestThreats(prev => [data.newThreat, ...prev].slice(0, 50));
          }
          if (typeof data.threatCount === 'number') {
            setThreatCount(data.threatCount);
          }
          if (typeof data.scanCount === 'number') {
            setScanCount(data.scanCount);
          }
        } catch (error) {
          console.error("Failed to parse SSE data", error);
        }
      };

      sse.onerror = () => {
        setSystemStatus("Disconnected");
        sse.close();
        
        // Exponential backoff or simple fixed reconnect
        if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, 3000); // Reconnect after 3s
      };
    }

    connect();

    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (fallbackPollRef.current) {
        clearInterval(fallbackPollRef.current);
      }
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
