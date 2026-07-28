"use client";

import { useState, useRef } from "react";
import { motion, AnimatePresence, useMotionValue, useSpring, useTransform } from "framer-motion";
import GlassCard from "@/components/ui/GlassCard";

interface AuditEntry {
  id: string;
  timestamp: string;
  action: string;
  target: string;
  status: "success" | "failed" | "pending";
  severity: "low" | "medium" | "high" | "critical";
  user: string;
  details: string;
}

const MOCK_AUDIT_DATA: AuditEntry[] = [
  {
    id: "1",
    timestamp: "2026-07-28 14:32:15",
    action: "URL_SCAN",
    target: "https://suspicious-site.com",
    status: "success",
    severity: "high",
    user: "admin@guardai.com",
    details: "Phishing detected with 94% confidence",
  },
  {
    id: "2",
    timestamp: "2026-07-28 14:28:42",
    action: "IP_BLOCK",
    target: "192.168.1.105",
    status: "success",
    severity: "critical",
    user: "system",
    details: "Automated block due to DDoS attack pattern",
  },
  {
    id: "3",
    timestamp: "2026-07-28 14:15:08",
    action: "ALERT_SENT",
    target: "Discord Webhook",
    status: "success",
    severity: "low",
    user: "system",
    details: "Threat notification sent to #security-alerts",
  },
  {
    id: "4",
    timestamp: "2026-07-28 13:58:33",
    action: "SCAN_FAILED",
    target: "https://timeout-site.net",
    status: "failed",
    severity: "medium",
    user: "admin@guardai.com",
    details: "Connection timeout after 30s",
  },
  {
    id: "5",
    timestamp: "2026-07-28 13:42:19",
    action: "USER_LOGIN",
    target: "admin@guardai.com",
    status: "success",
    severity: "low",
    user: "admin@guardai.com",
    details: "Successful authentication via Google OAuth",
  },
  {
    id: "6",
    timestamp: "2026-07-28 13:25:55",
    action: "URL_SCAN",
    target: "https://malware-distribution.org",
    status: "success",
    severity: "critical",
    user: "analyst@guardai.com",
    details: "Malware distribution network identified",
  },
  {
    id: "7",
    timestamp: "2026-07-28 12:58:07",
    action: "CONFIG_CHANGE",
    target: "Notification Settings",
    status: "success",
    severity: "medium",
    user: "admin@guardai.com",
    details: "Telegram bot integration enabled",
  },
  {
    id: "8",
    timestamp: "2026-07-28 12:30:41",
    action: "API_KEY_ROTATE",
    target: "VirusTotal API",
    status: "success",
    severity: "high",
    user: "system",
    details: "API key automatically rotated per policy",
  },
];

function AuditRow({ entry, index }: { entry: AuditEntry; index: number }) {
  const ref = useRef<HTMLTableRowElement>(null);
  const x = useMotionValue(0);
  const y = useMotionValue(0);

  const rotateX = useSpring(useTransform(y, [-0.5, 0.5], [2, -2]), {
    stiffness: 150,
    damping: 20,
  });
  const rotateY = useSpring(useTransform(x, [-0.5, 0.5], [-2, 2]), {
    stiffness: 150,
    damping: 20,
  });

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!ref.current) return;
    const rect = ref.current.getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;
    x.set((e.clientX - centerX) / rect.width);
    y.set((e.clientY - centerY) / rect.height);
  };

  const handleMouseLeave = () => {
    x.set(0);
    y.set(0);
  };

  const statusColors = {
    success: { bg: "#00FF6620", text: "#00FF66", border: "#00FF6640" },
    failed: { bg: "#FF003C20", text: "#FF003C", border: "#FF003C40" },
    pending: { bg: "#FFB80020", text: "#FFB800", border: "#FFB80040" },
  };

  const severityColors = {
    low: "#00F0FF",
    medium: "#FFB800",
    high: "#FF6B35",
    critical: "#FF003C",
  };

  const colors = statusColors[entry.status];

  return (
    <motion.tr
      ref={ref}
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.05, duration: 0.3 }}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      style={{
        rotateX,
        rotateY,
        transformStyle: "preserve-3d",
      }}
      className="border-b border-white/5 hover:bg-white/[0.02] transition-colors cursor-pointer group"
    >
      <td className="py-4 px-4">
        <span className="text-xs text-white/40" style={{ fontFamily: "var(--font-mono)" }}>
          {entry.timestamp}
        </span>
      </td>
      <td className="py-4 px-4">
        <span className="text-xs font-medium text-white/80" style={{ fontFamily: "var(--font-mono)" }}>
          {entry.action}
        </span>
      </td>
      <td className="py-4 px-4">
        <span className="text-xs text-white/60 max-w-[200px] truncate block">
          {entry.target}
        </span>
      </td>
      <td className="py-4 px-4">
        <span
          className="text-xs px-2 py-1 rounded-full"
          style={{
            backgroundColor: colors.bg,
            color: colors.text,
            border: `1px solid ${colors.border}`,
          }}
        >
          {entry.status.toUpperCase()}
        </span>
      </td>
      <td className="py-4 px-4">
        <div className="flex items-center gap-2">
          <div
            className="w-2 h-2 rounded-full"
            style={{ backgroundColor: severityColors[entry.severity] }}
          />
          <span className="text-xs text-white/60 capitalize">{entry.severity}</span>
        </div>
      </td>
      <td className="py-4 px-4">
        <span className="text-xs text-white/40">{entry.user}</span>
      </td>
      <td className="py-4 px-4">
        <span className="text-xs text-white/50 max-w-[250px] truncate block">
          {entry.details}
        </span>
      </td>
      <td className="py-4 px-4 opacity-0 group-hover:opacity-100 transition-opacity">
        <button className="text-[#00F0FF] text-xs hover:underline">
          VIEW
        </button>
      </td>
    </motion.tr>
  );
}

export default function AuditLog() {
  const [filter, setFilter] = useState<string>("all");
  const [data] = useState<AuditEntry[]>(MOCK_AUDIT_DATA);

  const filteredData = filter === "all" ? data : data.filter((entry) => entry.status === filter);

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

        <div className="flex flex-wrap gap-3 mb-6 justify-center">
          {["all", "success", "failed", "pending"].map((f) => (
            <button
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
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/10">
                  <th className="py-4 px-4 text-left text-xs text-white/40 font-medium" style={{ fontFamily: "var(--font-mono)" }}>
                    TIMESTAMP
                  </th>
                  <th className="py-4 px-4 text-left text-xs text-white/40 font-medium" style={{ fontFamily: "var(--font-mono)" }}>
                    ACTION
                  </th>
                  <th className="py-4 px-4 text-left text-xs text-white/40 font-medium" style={{ fontFamily: "var(--font-mono)" }}>
                    TARGET
                  </th>
                  <th className="py-4 px-4 text-left text-xs text-white/40 font-medium" style={{ fontFamily: "var(--font-mono)" }}>
                    STATUS
                  </th>
                  <th className="py-4 px-4 text-left text-xs text-white/40 font-medium" style={{ fontFamily: "var(--font-mono)" }}>
                    SEVERITY
                  </th>
                  <th className="py-4 px-4 text-left text-xs text-white/40 font-medium" style={{ fontFamily: "var(--font-mono)" }}>
                    USER
                  </th>
                  <th className="py-4 px-4 text-left text-xs text-white/40 font-medium" style={{ fontFamily: "var(--font-mono)" }}>
                    DETAILS
                  </th>
                  <th className="py-4 px-4 text-left text-xs text-white/40 font-medium w-[80px]" style={{ fontFamily: "var(--font-mono)" }}>
                    ACTION
                  </th>
                </tr>
              </thead>
              <tbody>
                <AnimatePresence>
                  {filteredData.map((entry, index) => (
                    <AuditRow key={entry.id} entry={entry} index={index} />
                  ))}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        </GlassCard>

        <div className="mt-6 flex items-center justify-between text-xs text-white/40" style={{ fontFamily: "var(--font-mono)" }}>
          <span>SHOWING {filteredData.length} OF {data.length} ENTRIES</span>
          <div className="flex gap-2">
            <button className="px-3 py-1 rounded bg-white/5 hover:bg-white/10 transition-colors">
              PREV
            </button>
            <button className="px-3 py-1 rounded bg-[#00F0FF]/10 text-[#00F0FF]">
              1
            </button>
            <button className="px-3 py-1 rounded bg-white/5 hover:bg-white/10 transition-colors">
              NEXT
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
