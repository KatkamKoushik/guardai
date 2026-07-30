"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { motion, AnimatePresence, useMotionValue, useSpring, useTransform } from "framer-motion";
import GlassCard from "@/components/ui/GlassCard";

interface AuditEntry {
  id: string;
  timestamp: string;
  action: string;
  target: string;
  status: "success" | "failed" | "pending";
  severity: "low" | "medium" | "high" | "critical";
  source: string;
  details: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
function formatTimestamp(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const date = d.toLocaleDateString("en-US", { month: "short", day: "2-digit", year: "numeric" });
  const time = d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: true });
  return `${date} - ${time}`;
}

const statusColors = {
  success: { bg: "#00FF6620", text: "#00FF66", border: "#00FF6640" },
  failed:  { bg: "#FF003C20", text: "#FF003C", border: "#FF003C40" },
  pending: { bg: "#FFB80020", text: "#FFB800", border: "#FFB80040" },
};

const severityColors: Record<string, string> = {
  low:      "#00F0FF",
  medium:   "#FFB800",
  high:     "#FF6B35",
  critical: "#FF003C",
};

// ─────────────────────────────────────────────────────────────────────────────
// Detail Modal
// ─────────────────────────────────────────────────────────────────────────────
function AuditDetailModal({ log, onClose }: { log: AuditEntry; onClose: () => void }) {
  const colors = statusColors[log.status] ?? statusColors.pending;

  const handleBackdrop = (e: React.MouseEvent<HTMLDivElement>) => {
    if (e.target === e.currentTarget) onClose();
  };

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.2 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ backgroundColor: "rgba(0,0,0,0.75)" }}
      onClick={handleBackdrop}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.92, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.92, y: 20 }}
        transition={{ duration: 0.2, ease: "easeOut" }}
        className="relative w-full max-w-2xl rounded-2xl border border-cyan-500/30 bg-black/90 backdrop-blur-xl shadow-2xl shadow-cyan-500/10 overflow-hidden"
        style={{ fontFamily: "var(--font-mono)" }}
      >
        {/* Top glow line */}
        <div className="h-px w-full bg-gradient-to-r from-transparent via-cyan-400/60 to-transparent" />

        {/* Header */}
        <div className="flex items-start justify-between px-6 py-5 border-b border-white/10">
          <div>
            <h3 className="text-base font-bold text-white tracking-wider" style={{ fontFamily: "var(--font-heading)" }}>
              LOG DETAIL RECORD
            </h3>
            <p className="text-xs text-white/40 mt-0.5 break-all">{log.id}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="ml-4 shrink-0 flex items-center justify-center w-8 h-8 rounded-lg border border-white/10 bg-white/5 text-white/50 hover:text-white hover:bg-white/10 hover:border-cyan-500/40 transition-all"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="px-6 py-5 space-y-4">
          {/* Status + Severity badges */}
          <div className="flex gap-3 flex-wrap">
            <span
              className="px-3 py-1 rounded-full text-xs"
              style={{ backgroundColor: colors.bg, color: colors.text, border: `1px solid ${colors.border}` }}
            >
              {log.status.toUpperCase()}
            </span>
            <span
              className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs border border-white/10 bg-white/5"
              style={{ color: severityColors[log.severity] ?? "#fff" }}
            >
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: severityColors[log.severity] }} />
              {log.severity.toUpperCase()} SEVERITY
            </span>
          </div>

          {/* Metadata grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {[
              { label: "TIMESTAMP", value: formatTimestamp(log.timestamp) },
              { label: "ACTION",    value: log.action },
              { label: "SOURCE",    value: log.source },
            ].map(({ label, value }) => (
              <div key={label} className="rounded-lg bg-white/5 border border-white/5 px-4 py-3">
                <div className="text-[10px] text-white/30 mb-1">{label}</div>
                <div className="text-xs text-white/80 break-all">{value}</div>
              </div>
            ))}

            {/* Target — full width */}
            <div className="sm:col-span-2 rounded-lg bg-white/5 border border-white/5 px-4 py-3">
              <div className="text-[10px] text-white/30 mb-1">TARGET</div>
              <div className="text-xs text-cyan-400 break-all">{log.target}</div>
            </div>
          </div>

          {/* Details */}
          <div className="rounded-lg bg-white/5 border border-white/5 px-4 py-3">
            <div className="text-[10px] text-white/30 mb-2">DETAILS</div>
            <p className="text-xs text-white/70 leading-relaxed whitespace-pre-wrap">{log.details}</p>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-white/10 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs rounded-lg border border-white/10 bg-white/5 text-white/50 hover:text-white hover:bg-white/10 transition-all"
          >
            CLOSE
          </button>
        </div>

        {/* Bottom glow line */}
        <div className="h-px w-full bg-gradient-to-r from-transparent via-cyan-400/30 to-transparent" />
      </motion.div>
    </motion.div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Table Row
// ─────────────────────────────────────────────────────────────────────────────
function AuditRow({
  entry,
  index,
  onView,
}: {
  entry: AuditEntry;
  index: number;
  onView: (e: AuditEntry) => void;
}) {
  const ref = useRef<HTMLTableRowElement>(null);
  const x = useMotionValue(0);
  const y = useMotionValue(0);
  const rotateX = useSpring(useTransform(y, [-0.5, 0.5], [2, -2]), { stiffness: 150, damping: 20 });
  const rotateY = useSpring(useTransform(x, [-0.5, 0.5], [-2, 2]), { stiffness: 150, damping: 20 });

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!ref.current) return;
    const rect = ref.current.getBoundingClientRect();
    x.set((e.clientX - rect.left - rect.width / 2) / rect.width);
    y.set((e.clientY - rect.top - rect.height / 2) / rect.height);
  };

  const handleMouseLeave = () => { x.set(0); y.set(0); };

  const colors = statusColors[entry.status] ?? statusColors.pending;

  return (
    <motion.tr
      ref={ref}
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.05, duration: 0.3 }}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      style={{ rotateX, rotateY, transformStyle: "preserve-3d" }}
      className="border-b border-white/5 hover:bg-white/[0.02] transition-colors cursor-pointer group"
    >
      {/* Timestamp */}
      <td className="py-4 px-4">
        <span className="text-xs text-white/40 whitespace-nowrap" style={{ fontFamily: "var(--font-mono)" }}>
          {formatTimestamp(entry.timestamp)}
        </span>
      </td>

      {/* Action */}
      <td className="py-4 px-4">
        <span className="text-xs font-medium text-white/80" style={{ fontFamily: "var(--font-mono)" }}>
          {entry.action}
        </span>
      </td>

      {/* Target */}
      <td className="py-4 px-4 max-w-[180px]">
        <span className="text-xs text-white/60 truncate block" title={entry.target}>
          {entry.target}
        </span>
      </td>

      {/* Status */}
      <td className="py-4 px-4">
        <span
          className="text-xs px-2 py-1 rounded-full whitespace-nowrap"
          style={{ backgroundColor: colors.bg, color: colors.text, border: `1px solid ${colors.border}` }}
        >
          {entry.status.toUpperCase()}
        </span>
      </td>

      {/* Severity */}
      <td className="py-4 px-4">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: severityColors[entry.severity] }} />
          <span className="text-xs text-white/60 capitalize">{entry.severity}</span>
        </div>
      </td>

      {/* Source — replaces USER */}
      <td className="py-4 px-4">
        <span
          className="text-xs px-2 py-1 rounded bg-white/5 border border-white/10 text-white/50 whitespace-nowrap"
          style={{ fontFamily: "var(--font-mono)" }}
        >
          {entry.source}
        </span>
      </td>

      {/* Details */}
      <td className="py-4 px-4 max-w-[200px]">
        <span className="text-xs text-white/50 truncate block" title={entry.details}>
          {entry.details}
        </span>
      </td>

      {/* View */}
      <td className="py-4 px-4 opacity-0 group-hover:opacity-100 transition-opacity">
        <button
          type="button"
          onClick={() => onView(entry)}
          className="text-[#00F0FF] text-xs hover:underline hover:text-cyan-300 transition-colors"
        >
          VIEW
        </button>
      </td>
    </motion.tr>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────────
export default function AuditLog() {
  const router = useRouter();
  const [filter, setFilter] = useState<string>("all");
  const [data, setData] = useState<AuditEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedLog, setSelectedLog] = useState<AuditEntry | null>(null);

  useEffect(() => {
    let isMounted = true;
    const fetchAudit = async () => {
      try {
        setIsLoading(true);
        setError(null);
        const response = await fetch("/api/audit", { cache: "no-store" });

        // Redirect to login if unauthenticated
        if (response.status === 401) {
          router.push("/auth/login");
          return;
        }

        const body = await response.json();
        if (!response.ok) throw new Error(body.error || "Failed to load audit log");
        if (isMounted) setData(body.entries ?? []);
      } catch (err) {
        if (isMounted) setError(err instanceof Error ? err.message : "Failed to load audit log");
      } finally {
        if (isMounted) setIsLoading(false);
      }
    };

    fetchAudit();
    return () => { isMounted = false; };
  }, [router]);

  const filteredData = filter === "all" ? data : data.filter((e) => e.status === filter);

  const TABLE_HEADERS = ["TIMESTAMP", "ACTION", "TARGET", "STATUS", "SEVERITY", "SOURCE", "DETAILS", "VIEW"];

  return (
    <section className="relative min-h-screen px-4 py-24 z-10">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-12">
          <h2
            className="text-4xl md:text-5xl font-bold tracking-tighter mb-4"
            style={{ fontFamily: "var(--font-heading)" }}
          >
            <span className="text-gradient-cyan">AUDIT</span> LOG
          </h2>
          <p className="text-white/40 text-sm" style={{ fontFamily: "var(--font-mono)" }}>
            COMPLETE ACTIVITY HISTORY & COMPLIANCE TRACKING
          </p>
        </div>

        {/* Filter Tabs */}
        <div className="flex flex-wrap gap-3 mb-6 justify-center">
          {["all", "success", "failed", "pending"].map((f) => (
            <button
              type="button"
              key={f}
              onClick={() => setFilter(f)}
              className={`px-4 py-2 text-xs rounded-lg transition-all duration-300 ${
                filter === f
                  ? "bg-[#00F0FF]/10 border border-[#00F0FF]/30 text-[#00F0FF]"
                  : "bg-white/5 border border-white/10 text-white/50 hover:bg-white/10"
              }`}
              style={{ fontFamily: "var(--font-mono)" }}
            >
              {f.toUpperCase()}
            </button>
          ))}
        </div>

        <GlassCard hover3D={false} className="overflow-hidden">
          {error && (
            <div className="m-4 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-xs text-red-300">
              {error}
            </div>
          )}
          {isLoading && (
            <div className="m-4 rounded-lg border border-white/10 bg-white/5 px-4 py-3 text-xs text-white/60">
              Loading audit entries...
            </div>
          )}
          {!isLoading && !error && filteredData.length === 0 && (
            <div className="m-4 rounded-lg border border-white/5 bg-white/[0.02] px-4 py-8 text-center text-xs text-white/30" style={{ fontFamily: "var(--font-mono)" }}>
              NO AUDIT ENTRIES FOUND. RUN A SCAN TO START LOGGING ACTIVITY.
            </div>
          )}
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/10">
                  {TABLE_HEADERS.map((h, i) => (
                    <th
                      key={`${h}-${i}`}
                      className="py-4 px-4 text-left text-xs text-white/40 font-medium whitespace-nowrap"
                      style={{ fontFamily: "var(--font-mono)" }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                <AnimatePresence>
                  {filteredData.map((entry, index) => (
                    <AuditRow
                      key={entry.id}
                      entry={entry}
                      index={index}
                      onView={setSelectedLog}
                    />
                  ))}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        </GlassCard>

        {/* Pagination footer */}
        <div
          className="mt-6 flex items-center justify-between text-xs text-white/40"
          style={{ fontFamily: "var(--font-mono)" }}
        >
          <span>SHOWING {filteredData.length} OF {data.length} ENTRIES</span>
          <div className="flex gap-2">
            <button type="button" className="px-3 py-1 rounded bg-white/5 hover:bg-white/10 transition-colors">PREV</button>
            <button type="button" className="px-3 py-1 rounded bg-[#00F0FF]/10 text-[#00F0FF]">1</button>
            <button type="button" className="px-3 py-1 rounded bg-white/5 hover:bg-white/10 transition-colors">NEXT</button>
          </div>
        </div>
      </div>

      {/* Detail Modal */}
      <AnimatePresence>
        {selectedLog && (
          <AuditDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />
        )}
      </AnimatePresence>
    </section>
  );
}
