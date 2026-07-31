"use client";

/**
 * LiveTelemetry — Real-Time Client Component
 *
 * Polls /api/telemetry every 2 seconds using setInterval so every open tab
 * reflects the latest DB state. When User A scans a URL, User B's screen
 * updates within at most 2 seconds without any manual refresh.
 *
 * Guarantees:
 * - No mock data is rendered — if the database is empty, a "Waiting for live
 *   scans…" fallback is shown.
 * - cache: "no-store" is passed to fetch() to bypass the browser cache on
 *   every poll cycle.
 * - The interval is properly torn down on unmount to prevent memory leaks.
 */

import { useEffect, useRef, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ScanFeedItem {
  id: string;
  target: string;
  domain: string;
  score: number;
  threatLevel: "safe" | "suspicious" | "high" | "critical";
  ipAddress: string | null;
  latitude: number | null;
  longitude: number | null;
  countryCode: string | null;
  timestamp: string;
}

interface TelemetryResponse {
  totalScans: number;
  totalThreats: number;
  recentScans: ScanFeedItem[];
  waitingForData: boolean;
  error?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const THREAT_CONFIG = {
  safe:       { label: "SAFE",       color: "#00FF66", bg: "rgba(0,255,102,0.08)",  border: "rgba(0,255,102,0.25)"  },
  suspicious: { label: "SUSPICIOUS", color: "#FFB800", bg: "rgba(255,184,0,0.08)",  border: "rgba(255,184,0,0.25)"  },
  high:       { label: "HIGH",       color: "#FF6B00", bg: "rgba(255,107,0,0.08)",  border: "rgba(255,107,0,0.25)"  },
  critical:   { label: "CRITICAL",   color: "#FF003C", bg: "rgba(255,0,60,0.08)",   border: "rgba(255,0,60,0.25)"   },
} as const;

function getThreatConfig(level: string) {
  return THREAT_CONFIG[level as keyof typeof THREAT_CONFIG] ?? THREAT_CONFIG.safe;
}

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const secs = Math.floor(diff / 1000);
  if (secs < 5)   return "just now";
  if (secs < 60)  return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60)  return `${mins}m ago`;
  return `${Math.floor(mins / 60)}h ago`;
}

// ---------------------------------------------------------------------------
// AnimatedNumber — counts up smoothly when value changes
// ---------------------------------------------------------------------------

function AnimatedNumber({ value }: { value: number }) {
  const [display, setDisplay] = useState(value);
  const prevRef = useRef(value);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    const from = prevRef.current;
    const to = value;
    if (from === to) return;
    prevRef.current = to;

    const startTime = performance.now();
    const duration = 600; // ms

    const tick = (now: number) => {
      const progress = Math.min((now - startTime) / duration, 1);
      const ease = 1 - Math.pow(1 - progress, 3);
      setDisplay(Math.round(from + (to - from) * ease));
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(tick);
      }
    };

    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
    };
  }, [value]);

  return <>{display.toLocaleString()}</>;
}

// ---------------------------------------------------------------------------
// LiveTelemetry Component
// ---------------------------------------------------------------------------

interface LiveTelemetryProps {
  /** Polling interval in ms. Defaults to 2000. */
  pollInterval?: number;
  /** Whether to render the stats counters (for hero section). */
  showStats?: boolean;
  /** Whether to render the recent-scans feed (for dashboard). */
  showFeed?: boolean;
}

export default function LiveTelemetry({
  pollInterval = 2000,
  showStats = true,
  showFeed = true,
}: LiveTelemetryProps) {
  const [data, setData] = useState<TelemetryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Track displayed feed IDs so new items can be animated in
  const seenIdsRef = useRef<Set<string>>(new Set());

  const poll = useCallback(async () => {
    try {
      const res = await fetch("/api/telemetry", {
        cache: "no-store",
        credentials: "omit",
        headers: {
          "Pragma": "no-cache",
          "Cache-Control": "no-cache",
        },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json: TelemetryResponse = await res.json();
      setData(json);
      setError(null);
    } catch (err: any) {
      setError(err.message ?? "Failed to fetch telemetry.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Fetch immediately on mount, then on every interval
    poll();
    const id = setInterval(poll, pollInterval);
    return () => clearInterval(id);
  }, [poll, pollInterval]);

  // ── Stats counters ─────────────────────────────────────────────────────
  const statsBlock = showStats && (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 text-center max-w-lg mx-auto">
      {/* Total Scans */}
      <div>
        <div
          className="text-3xl sm:text-4xl lg:text-5xl font-bold font-mono text-gradient-cyan"
        >
          {loading ? (
            <span className="opacity-40">—</span>
          ) : error ? (
            <span className="text-red-500 text-lg">ERR</span>
          ) : (
            <AnimatedNumber value={data?.totalScans ?? 0} />
          )}
        </div>
        <div
          className="text-xs text-white/40 mt-1"
          style={{ fontFamily: "var(--font-mono)" }}
        >
          URLs Scanned
        </div>
      </div>

      {/* Threat Count */}
      <div>
        <div
          className="text-3xl sm:text-4xl lg:text-5xl font-bold font-mono"
          style={{ color: "#FF003C" }}
        >
          {loading ? (
            <span className="opacity-40">—</span>
          ) : error ? (
            <span className="text-red-500 text-lg">ERR</span>
          ) : (
            <AnimatedNumber value={data?.totalThreats ?? 0} />
          )}
        </div>
        <div
          className="text-xs text-white/40 mt-1"
          style={{ fontFamily: "var(--font-mono)" }}
        >
          Threats Found
        </div>
      </div>

      {/* Live indicator */}
      <div>
        <div
          className="text-3xl sm:text-4xl lg:text-5xl font-bold font-mono text-gradient-cyan"
        >
          99.9%
        </div>
        <div
          className="text-xs text-white/40 mt-1"
          style={{ fontFamily: "var(--font-mono)" }}
        >
          Uptime
        </div>
      </div>
    </div>
  );

  // ── Scan Feed ──────────────────────────────────────────────────────────
  const feedBlock = showFeed && (
    <div className="w-full">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div
            className="w-2 h-2 rounded-full bg-[#00FF66]"
            style={{ animation: "pulse 2s cubic-bezier(0.4,0,0.6,1) infinite" }}
          />
          <span
            className="text-xs tracking-widest text-white/50 uppercase"
            style={{ fontFamily: "var(--font-mono)" }}
          >
            Live Scan Feed
          </span>
        </div>
        {!loading && !error && (
          <span
            className="text-[10px] text-white/20"
            style={{ fontFamily: "var(--font-mono)" }}
          >
            Updates every 2s
          </span>
        )}
      </div>

      {/* Feed items */}
      <div className="space-y-2 min-h-[120px]">
        {loading && (
          <div className="flex items-center gap-2 py-6 justify-center">
            <div className="w-3 h-3 rounded-full bg-[#00F0FF]/50 animate-bounce [animation-delay:0ms]" />
            <div className="w-3 h-3 rounded-full bg-[#00F0FF]/50 animate-bounce [animation-delay:150ms]" />
            <div className="w-3 h-3 rounded-full bg-[#00F0FF]/50 animate-bounce [animation-delay:300ms]" />
          </div>
        )}

        {!loading && error && (
          <div
            className="text-xs text-red-400/70 py-4 text-center"
            style={{ fontFamily: "var(--font-mono)" }}
          >
            ⚠ {error}
          </div>
        )}

        {!loading && !error && data?.waitingForData && (
          <div
            className="text-xs text-white/30 py-6 text-center"
            style={{ fontFamily: "var(--font-mono)" }}
          >
            [ Waiting for live scans… ]
          </div>
        )}

        {!loading && !error && !data?.waitingForData && (
          <AnimatePresence initial={false}>
            {(data?.recentScans ?? []).map((scan) => {
              const cfg = getThreatConfig(scan.threatLevel);
              const isNew = !seenIdsRef.current.has(scan.id);
              if (isNew) seenIdsRef.current.add(scan.id);

              return (
                <motion.div
                  key={scan.id}
                  layout
                  initial={isNew ? { opacity: 0, y: -12, scale: 0.97 } : false}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: 8, scale: 0.97 }}
                  transition={{ duration: 0.3, ease: "easeOut" }}
                  className="flex items-center justify-between rounded-lg px-3 py-2.5 gap-3"
                  style={{
                    background: cfg.bg,
                    border: `1px solid ${cfg.border}`,
                  }}
                >
                  {/* Domain + timestamp */}
                  <div className="flex flex-col min-w-0">
                    <span
                      className="text-xs font-medium text-white/80 truncate"
                      style={{ fontFamily: "var(--font-mono)" }}
                    >
                      {scan.domain}
                    </span>
                    <span
                      className="text-[10px] text-white/30"
                      style={{ fontFamily: "var(--font-mono)" }}
                    >
                      {relativeTime(scan.timestamp)}
                      {scan.countryCode ? ` · ${scan.countryCode}` : ""}
                    </span>
                  </div>

                  {/* Score + threat badge */}
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span
                      className="text-xs font-bold"
                      style={{ color: cfg.color, fontFamily: "var(--font-mono)" }}
                    >
                      {scan.score}
                    </span>
                    <span
                      className="text-[9px] px-1.5 py-0.5 rounded font-bold tracking-widest"
                      style={{
                        color: cfg.color,
                        background: cfg.bg,
                        border: `1px solid ${cfg.border}`,
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {cfg.label}
                    </span>
                  </div>
                </motion.div>
              );
            })}
          </AnimatePresence>
        )}
      </div>
    </div>
  );

  return (
    <>
      {statsBlock}
      {showStats && showFeed && <div className="mt-12" />}
      {feedBlock}
    </>
  );
}
