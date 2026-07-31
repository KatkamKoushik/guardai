"use client";

"use client";

import { useState, useMemo } from "react";
import { Canvas } from "@react-three/fiber";
import { OrbitControls } from "@react-three/drei";
import { motion, AnimatePresence } from "framer-motion";
import GlassCard from "@/components/ui/GlassCard";
import CyberGlobe from "./CyberGlobe";
import ThreatArcs from "./ThreatArcs";
import { useRealtimeThreats, ThreatTelemetry } from "@/hooks/useRealtimeThreats";

function GlobeScene({ activeThreats }: { activeThreats: ThreatTelemetry[] }) {
  return (
    <>
      <ambientLight intensity={0.5} />
      <pointLight position={[10, 10, 10]} intensity={1} />
      <CyberGlobe />
      <ThreatArcs threats={activeThreats} />
      
      <OrbitControls
        enableZoom={true}
        enablePan={false}
        autoRotate
        autoRotateSpeed={0.5}
        enableDamping
        dampingFactor={0.05}
        minPolarAngle={Math.PI / 4}
        maxPolarAngle={(3 * Math.PI) / 4}
        minDistance={2.5}
        maxDistance={6}
      />
    </>
  );
}

export default function ThreatMap() {
  const { latestThreats, threatCount, systemStatus, connectionLatency } = useRealtimeThreats();
  
  const [filter, setFilter] = useState<"All" | "Malware" | "Phishing" | "Botnet">("All");
  const [isPaused, setIsPaused] = useState(false);
  
  // Keep a frozen copy if paused
  const [frozenThreats, setFrozenThreats] = useState<ThreatTelemetry[]>([]);

  const handlePauseToggle = () => {
    if (!isPaused) {
      setFrozenThreats(latestThreats);
    }
    setIsPaused(!isPaused);
  };

  const displayedThreats = isPaused ? frozenThreats : latestThreats;

  const filteredThreats = useMemo(() => {
    if (filter === "All") return displayedThreats;
    return displayedThreats.filter((t) => t.threatType.toLowerCase().includes(filter.toLowerCase()));
  }, [displayedThreats, filter]);

  // Derive simple pings/sec (mock calculation based on incoming frequency)
  // In reality, server sends stats, but for HUD we'll just show connection status visually
  const pingsPerSec = Math.max(0, Math.round(1000 / Math.max(connectionLatency, 1)));

  return (
    <section className="relative min-h-screen px-4 pt-20 sm:pt-24 pb-12 z-10">
      <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8 relative z-20">
          <h2
            className="text-4xl md:text-5xl font-bold tracking-tighter"
            style={{ fontFamily: "var(--font-heading)" }}
          >
            <span className="text-gradient-threat">LIVE</span> THREAT TELEMETRY
          </h2>
          <div className="flex items-center justify-center gap-4 text-sm" style={{ fontFamily: "var(--font-mono)" }}>
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${systemStatus === 'Connected' ? 'bg-[#00FF66] animate-pulse' : 'bg-red-500'}`} />
              <span className="text-white/60 uppercase">{systemStatus}</span>
            </div>
            <span className="text-white/20">|</span>
            <span className="text-white/40">LATENCY: {connectionLatency}ms</span>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Main 3D View */}
          <div className="lg:col-span-3 relative">
            
            {/* HUD Overlay Filters */}
            <div className="flex flex-wrap items-center gap-2 overflow-x-auto pb-2 scrollbar-none relative z-10 mb-4">
              {["All", "Malware", "Phishing", "Botnet"].map((f) => (
                <button
                  type="button"
                  key={f}
                  onClick={() => setFilter(f as any)}
                  className={`px-3 py-1.5 rounded-md text-xs border transition-colors whitespace-nowrap ${
                    filter === f 
                      ? "bg-[#00F0FF]/20 border-[#00F0FF]/50 text-[#00F0FF]" 
                      : "bg-black/40 border-white/10 text-white/50 hover:bg-white/5"
                  }`}
                  style={{ fontFamily: "var(--font-mono)" }}
                >
                  {f}
                </button>
              ))}
              <div className="hidden sm:block w-px h-6 bg-white/10 mx-1"></div>
              <button
                type="button"
                onClick={handlePauseToggle}
                className={`px-3 py-1.5 rounded-md text-xs border transition-colors flex items-center gap-2 whitespace-nowrap ${
                  isPaused 
                    ? "bg-red-500/20 border-red-500/50 text-red-500" 
                    : "bg-[#00F0FF]/10 border-[#00F0FF]/30 text-[#00F0FF]"
                }`}
                style={{ fontFamily: "var(--font-mono)" }}
              >
                {isPaused ? "▶ RESUME" : "⏸ PAUSE"}
              </button>
            </div>

            <GlassCard className="w-full h-[280px] sm:h-[400px] md:h-[500px] relative overflow-hidden" hover3D={false}>

              <div className="absolute bottom-4 left-4 z-10 p-3 rounded-lg bg-black/60 backdrop-blur-md border border-white/5">
                <div className="text-[10px] text-white/40 mb-1" style={{ fontFamily: "var(--font-mono)" }}>LIVE PINGS / SEC</div>
                <div className="text-2xl font-bold text-[#00F0FF]" style={{ fontFamily: "var(--font-heading)" }}>
                  {isPaused ? "0" : pingsPerSec}
                </div>
              </div>

              {/* 3D Canvas */}
              <div className="absolute inset-0">
                <Canvas camera={{ position: [0, 0, 5], fov: 45 }} gl={{ antialias: true, alpha: true }}>
                  <GlobeScene activeThreats={filteredThreats} />
                </Canvas>
              </div>

            </GlassCard>
          </div>

          {/* Sidebar */}
          <div className="space-y-4">
            <GlassCard hover3D={false}>
              <div className="text-xs text-white/40 mb-4" style={{ fontFamily: "var(--font-mono)" }}>
                GLOBAL STATISTICS
              </div>
              <div className="space-y-4">
                <div className="flex flex-col gap-1">
                  <span className="text-[10px] text-white/40 uppercase">Total Threats Blocked</span>
                  <span className="text-2xl font-mono text-[#FF003C]">{threatCount.toLocaleString()}</span>
                </div>
              </div>
            </GlassCard>

            <GlassCard hover3D={false} className="flex-1">
              <div className="text-xs text-white/40 mb-4" style={{ fontFamily: "var(--font-mono)" }}>
                LIVE FEED (RECENT)
              </div>
              <div className="space-y-2 max-h-[360px] overflow-y-auto pr-2 custom-scrollbar">
                <AnimatePresence>
                  {filteredThreats.slice(0, 15).map((threat) => (
                    <motion.div
                      key={threat.id}
                      initial={{ opacity: 0, x: 20 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, scale: 0.9 }}
                      className="p-3 rounded-lg bg-white/[0.02] border border-white/5 hover:border-[#00F0FF]/20 transition-colors"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span
                          className="text-[10px] font-medium px-2 py-0.5 rounded uppercase"
                          style={{
                            backgroundColor: threat.threatType.toLowerCase().includes("malware") ? "#FF003C20" : "#00F0FF20",
                            color: threat.threatType.toLowerCase().includes("malware") ? "#FF003C" : "#00F0FF",
                          }}
                        >
                          {threat.threatType}
                        </span>
                        <span className="text-[9px] text-white/30 font-mono">
                          {new Date(threat.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <div className="text-[11px] text-white/70 truncate" title={threat.domain}>
                        {threat.domain}
                      </div>
                    </motion.div>
                  ))}
                </AnimatePresence>
                {filteredThreats.length === 0 && (
                  <div className="text-center text-sm text-white/30 py-4">Waiting for incoming telemetry...</div>
                )}
              </div>
            </GlassCard>
          </div>
        </div>
      </div>
    </section>
  );
}
