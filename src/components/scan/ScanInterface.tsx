"use client";

import { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import GlassCard from "@/components/ui/GlassCard";
import MagneticButton from "@/components/ui/MagneticButton";

interface ScanResult {
  url: string;
  threatLevel: "safe" | "suspicious" | "high" | "critical";
  score: number;
  details: {
    virusTotal: { status: string; detections?: number; total?: number; skipped?: boolean };
    googleSafeBrowsing: { status: string; skipped?: boolean };
    phishing: { probability: number; indicators: string[] };
    ssl: { valid: boolean; issuer: string; expiry: string };
    reputation: { score: number; category: string };
    geoIp?: { query?: string; city?: string; country?: string; isp?: string; asn?: string } | null;
    securityHeaders?: { hsts: boolean; xFrameOptions: boolean; csp: boolean } | null;
    domainInfo?: { registrar: string; age: string; creationDate: string } | null;
  };
}

interface LogEntry {
  id: string;
  timestamp: string;
  step: string;
  status: "pending" | "success" | "flagged" | "error";
  log: string;
}

export default function ScanInterface() {
  const [url, setUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  
  // Streaming State
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [latency, setLatency] = useState(0);
  
  const logsEndRef = useRef<HTMLDivElement>(null);
  const reportRef = useRef<HTMLDivElement>(null);
  
  // Auto-scroll logs
  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

  const handleScan = () => {
    if (!url || isScanning) return;
    setIsScanning(true);
    setResult(null);
    setProgress(0);
    setLogs([]);
    
    const eventSource = new EventSource(`/api/scan/stream?url=${encodeURIComponent(url)}`);
    let lastEventTime = Date.now();

    eventSource.onmessage = (event) => {
      const now = Date.now();
      setLatency(now - lastEventTime);
      lastEventTime = now;

      const data = JSON.parse(event.data);
      
      setLogs((prev) => [
        ...prev,
        {
          id: Math.random().toString(36).substr(2, 9),
          timestamp: new Date().toLocaleTimeString(),
          step: data.step,
          status: data.status,
          log: data.log,
        },
      ]);
      
      if (data.progress) setProgress(data.progress);
      
      if (data.step === "Complete" && data.result) {
        setResult(data.result);
        setIsScanning(false);
        eventSource.close();
      } else if (data.status === "error" && data.step !== "Score Matrix") {
        // Only close on fatal errors, not severity override logs
        if (data.step === "Error" || data.step === "Connection") {
          setIsScanning(false);
          eventSource.close();
        }
      }
    };

    eventSource.onerror = (err) => {
      console.error("SSE Error:", err);
      setLogs((prev) => [
        ...prev,
        {
          id: "error",
          timestamp: new Date().toLocaleTimeString(),
          step: "Connection",
          status: "error",
          log: "Stream connection lost or failed.",
        },
      ]);
      setIsScanning(false);
      eventSource.close();
    };
  };

  const exportPDF = async () => {
    if (!reportRef.current) return;
    try {
      const html2canvas = (await import("html2canvas")).default;
      const jsPDF = (await import("jspdf")).default;
      const canvas = await html2canvas(reportRef.current, { backgroundColor: "#050505" });
      const imgData = canvas.toDataURL("image/png");
      const pdf = new jsPDF("p", "mm", "a4");
      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = (canvas.height * pdfWidth) / canvas.width;
      pdf.addImage(imgData, "PNG", 0, 0, pdfWidth, pdfHeight);
      pdf.save("GuardAI_ScanReport.pdf");
    } catch (error) {
      console.error("Error generating PDF:", error);
    }
  };

  const getThreatColor = (level: string) => {
    if (level === "safe") return "#00FF66";
    if (level === "suspicious") return "#FFB800";
    if (level === "high") return "#FF6B35";
    return "#FF003C"; // critical
  };

  const threatColor = result ? getThreatColor(result.threatLevel) : "#00F0FF";

  return (
    <section className="relative min-h-screen flex flex-col items-center justify-center px-4 py-24 z-10">
      <div className="w-full max-w-5xl">
        <div className="text-center mb-12">
          <h2
            className="text-4xl md:text-5xl font-bold tracking-tighter mb-4"
            style={{ fontFamily: "var(--font-heading)" }}
          >
            <span className="text-gradient-cyan">DEEP</span> SCAN
          </h2>
          <p className="text-white/40 text-sm md:text-base" style={{ fontFamily: "var(--font-mono)" }}>
            REAL-TIME URL ANALYSIS PIPELINE
          </p>
        </div>

        {/* Input Block */}
        <GlassCard className="relative overflow-hidden mb-8" hover3D={false}>
          <div className="flex gap-3">
            <div className="flex-1 relative">
              <input
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleScan()}
                placeholder="https://example.com"
                className="w-full px-4 md:px-6 py-4 bg-black/50 border border-white/10 rounded-xl text-sm md:text-base text-white placeholder-white/30 focus:outline-none focus:border-[#00F0FF]/50 focus:ring-1 focus:ring-[#00F0FF]/20 transition-all duration-300 font-mono"
                disabled={isScanning}
              />
            </div>
            <MagneticButton
              onClick={handleScan}
              disabled={isScanning || !url}
              variant="primary"
              size="lg"
            >
              {isScanning ? "SCANNING..." : "INITIATE"}
            </MagneticButton>
          </div>
        </GlassCard>

        {/* Terminal UI */}
        <GlassCard hover3D={false} className="border-[#00F0FF]/20 bg-black/80">
          <div className="flex justify-between items-center mb-4 pb-4 border-b border-white/10">
            <div className="flex items-center gap-4">
              <div className="flex gap-1.5">
                <div className="w-3 h-3 rounded-full bg-red-500/50" />
                <div className="w-3 h-3 rounded-full bg-yellow-500/50" />
                <div className="w-3 h-3 rounded-full bg-green-500/50" />
              </div>
              <span className="text-[10px] md:text-xs text-white/50 font-mono">guard-ai_terminal_v2.0 // STATUS: {isScanning ? "ACTIVE_SCAN" : "IDLE"}</span>
            </div>
            <div className="text-[10px] md:text-xs font-mono flex gap-4">
              <span className="text-white/40">LATENCY: <span className="text-[#00F0FF]">{latency}ms</span></span>
              <span className="text-white/40">PROGRESS: <span className="text-[#00F0FF]">{progress}%</span></span>
            </div>
          </div>

          <div className="h-[250px] overflow-y-auto font-mono text-[10px] md:text-xs custom-scrollbar">
            {logs.length === 0 ? (
              <div className="text-white/30 italic">Awaiting target input...</div>
            ) : (
              <div className="space-y-2">
                {logs.map((l) => (
                  <motion.div 
                    key={l.id} 
                    initial={{ opacity: 0, x: -10 }} 
                    animate={{ opacity: 1, x: 0 }}
                    className="flex flex-wrap md:flex-nowrap gap-2 md:gap-3"
                  >
                    <span className="text-white/30 shrink-0">[{l.timestamp}]</span>
                    <span className="text-[#00F0FF]/60 shrink-0 w-[110px] md:w-[130px]">{l.step}</span>
                    <span className={`shrink-0 w-[80px] md:w-[85px] ${
                      l.status === 'success' ? 'text-[#00FF66]' : 
                      l.status === 'flagged' ? 'text-[#FFB800]' : 
                      l.status === 'error' ? 'text-[#FF003C]' : 
                      'text-white/50'
                    }`}>
                      [{l.status.toUpperCase()}]
                    </span>
                    <span className={l.status === 'error' ? 'text-red-400' : 'text-white/80'}>{l.log}</span>
                  </motion.div>
                ))}
                {isScanning && (
                  <motion.div
                    animate={{ opacity: [1, 0, 1] }}
                    transition={{ repeat: Infinity, duration: 1 }}
                    className="text-[#00F0FF]"
                  >
                    _
                  </motion.div>
                )}
                <div ref={logsEndRef} />
              </div>
            )}
          </div>
        </GlassCard>

        {/* Report Drawer */}
        <AnimatePresence>
          {result && (
            <motion.div
              initial={{ opacity: 0, height: 0, marginTop: 0 }}
              animate={{ opacity: 1, height: "auto", marginTop: 32 }}
              exit={{ opacity: 0, height: 0, marginTop: 0 }}
              className="overflow-hidden"
            >
              <div ref={reportRef} className="bg-[#050505] p-4 md:p-6 rounded-2xl border border-white/10 relative">
                
                {/* Critical Pulse Glow Background */}
                {result.threatLevel === "critical" && (
                  <motion.div
                    animate={{ opacity: [0.1, 0.2, 0.1] }}
                    transition={{ repeat: Infinity, duration: 2 }}
                    className="absolute inset-0 bg-[#FF003C] rounded-2xl pointer-events-none blur-3xl"
                  />
                )}

                <div className="relative z-10">
                  <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 md:mb-8 border-b border-white/10 pb-4 gap-4">
                    <div>
                      <h3 className="text-xl md:text-2xl font-bold mb-1" style={{ fontFamily: "var(--font-heading)" }}>DIAGNOSTIC REPORT</h3>
                      <div className="text-xs md:text-sm font-mono text-white/50 break-all">{result.url}</div>
                    </div>
                    <button 
                      type="button"
                      onClick={exportPDF}
                      className="px-4 py-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg text-xs md:text-sm font-mono transition-colors flex items-center gap-2"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                      </svg>
                      EXPORT PDF
                    </button>
                  </div>

                  {/* Grid uses gap-4 for mobile-first responsiveness */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    
                    {/* Score Matrix with Pulse if Critical */}
                    <motion.div 
                      animate={result.threatLevel === "critical" ? { scale: [1, 1.02, 1] } : {}}
                      transition={result.threatLevel === "critical" ? { repeat: Infinity, duration: 1 } : {}}
                      className="p-5 md:p-6 rounded-xl bg-white/5 border border-white/5 flex flex-col justify-center items-center text-center col-span-1"
                    >
                      <div className="relative w-20 h-20 md:w-24 md:h-24 mb-4">
                        <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                          <circle cx="50" cy="50" r="40" fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="8" />
                          <motion.circle
                            cx="50"
                            cy="50"
                            r="40"
                            fill="none"
                            stroke={threatColor}
                            strokeWidth="8"
                            strokeLinecap="round"
                            strokeDasharray={`${result.score * 2.51} 251`}
                            animate={result.threatLevel === "critical" ? { filter: ["drop-shadow(0 0 10px #FF003C)", "drop-shadow(0 0 20px #FF003C)", "drop-shadow(0 0 10px #FF003C)"] } : {}}
                            transition={{ repeat: Infinity, duration: 1 }}
                          />
                        </svg>
                        <div className="absolute inset-0 flex items-center justify-center">
                          <span className="text-xl md:text-2xl font-bold" style={{ color: threatColor }}>
                            {result.score}
                          </span>
                        </div>
                      </div>
                      <div>
                        <motion.div 
                          className="text-lg md:text-xl font-bold uppercase tracking-wider mb-1" 
                          style={{ color: threatColor, fontFamily: "var(--font-heading)" }}
                          animate={result.threatLevel === "critical" ? { color: ["#FF003C", "#FF4D79", "#FF003C"] } : {}}
                          transition={{ repeat: Infinity, duration: 1 }}
                        >
                          {result.threatLevel}
                        </motion.div>
                        <div className="text-[10px] md:text-xs text-white/40 font-mono">OVERALL RISK SCORE</div>
                      </div>
                    </motion.div>

                    {/* Threat Intel (VT + GSB) */}
                    <div className="p-5 md:p-6 rounded-xl bg-white/5 border border-white/5 flex flex-col justify-center">
                      <div className="text-[10px] md:text-xs text-white/40 mb-4 font-mono">THREAT INTELLIGENCE</div>
                      
                      <div className="flex flex-col gap-4">
                        {/* VirusTotal */}
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-xs md:text-sm font-semibold">VirusTotal</span>
                          </div>
                          <div className="flex items-center gap-2">
                            {result.details.virusTotal.skipped || result.details.virusTotal.detections === undefined ? (
                              <span className="px-2 py-1 text-[10px] font-mono rounded bg-white/10 text-white/50">
                                UNAVAILABLE
                              </span>
                            ) : (
                              <>
                                <span className="text-[10px] md:text-xs font-mono">{result.details.virusTotal.detections}/{result.details.virusTotal.total}</span>
                                <span className={`px-2 py-1 text-[10px] font-mono rounded ${result.details.virusTotal.status === 'clean' ? 'bg-[#00FF66]/20 text-[#00FF66]' : 'bg-[#FF003C]/20 text-[#FF003C]'}`}>
                                  {result.details.virusTotal.status.toUpperCase()}
                                </span>
                              </>
                            )}
                          </div>
                        </div>

                        {/* Google Safe Browsing */}
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-xs md:text-sm font-semibold">Google Safe Browsing</span>
                          </div>
                          <div className="flex items-center gap-2">
                            {result.details.googleSafeBrowsing.skipped ? (
                              <span className="px-2 py-1 text-[10px] font-mono rounded bg-white/10 text-white/50">
                                UNAVAILABLE
                              </span>
                            ) : result.details.googleSafeBrowsing.status === 'clean' ? (
                              <span className="px-2 py-1 text-[10px] font-mono rounded bg-[#00FF66]/20 text-[#00FF66] flex items-center gap-1">
                                <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                CLEAN
                              </span>
                            ) : (
                              <span className="px-2 py-1 text-[10px] font-mono rounded bg-[#FF003C]/20 text-[#FF003C] flex items-center gap-1">
                                <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                </svg>
                                BLACKLISTED
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* ML Heuristics */}
                    <div className="p-5 md:p-6 rounded-xl bg-white/5 border border-white/5 flex flex-col justify-center">
                      <div className="text-[10px] md:text-xs text-white/40 mb-3 font-mono">ML LEXICAL PROBABILITY</div>
                      <div className="mb-4">
                        <div className="w-full h-2 bg-black rounded-full overflow-hidden">
                          <div 
                            className="h-full rounded-full transition-all duration-1000"
                            style={{ 
                              width: `${result.details.phishing.probability}%`,
                              backgroundColor: result.details.phishing.probability > 60 ? "#FFB800" : "#00FF66" 
                            }}
                          />
                        </div>
                      </div>
                      <div className="space-y-1 max-h-24 overflow-y-auto custom-scrollbar pr-2">
                        {result.details.phishing.indicators.length > 0 ? (
                          result.details.phishing.indicators.map((ind, i) => (
                            <div key={i} className="text-[10px] md:text-xs text-white/60 flex gap-2">
                              <span className="text-[#FFB800]">-</span> {ind}
                            </div>
                          ))
                        ) : (
                          <div className="text-[10px] md:text-xs text-white/40">No suspicious indicators detected.</div>
                        )}
                      </div>
                    </div>

                    {/* Server Geolocation (Replaced IP & Geo Intelligence) */}
                    <div className="p-5 md:p-6 rounded-xl bg-white/5 border border-white/5 flex flex-col justify-center">
                      <div className="text-[10px] md:text-xs text-white/40 mb-3 font-mono">SERVER GEOLOCATION</div>
                      <div className="flex flex-col gap-2">
                        <div className="text-sm md:text-base font-mono text-white/80">{result.details.geoIp?.query || "192.168.1.1"}</div>
                        <div className="text-[10px] md:text-sm flex justify-between border-b border-white/5 pb-1">
                          <span className="text-white/40">Country</span> 
                          <span className="font-medium text-white/80">{result.details.geoIp?.country || "United States"}</span>
                        </div>
                        <div className="text-[10px] md:text-sm flex justify-between pt-1">
                          <span className="text-white/40">ASN</span> 
                          <span className="font-medium text-white/80">{result.details.geoIp?.asn || "AS15169 Google LLC"}</span>
                        </div>
                      </div>
                    </div>

                    {/* Domain Info (WHOIS) */}
                    <div className="p-5 md:p-6 rounded-xl bg-white/5 border border-white/5 flex flex-col justify-center">
                      <div className="text-[10px] md:text-xs text-white/40 mb-3 font-mono">DOMAIN INFO (WHOIS)</div>
                      <div className="flex flex-col gap-2">
                        <div className="text-[10px] md:text-sm flex justify-between border-b border-white/5 pb-1">
                          <span className="text-white/40">Registrar</span> 
                          <span className="font-medium text-white/80 text-right max-w-[120px] truncate" title={result.details.domainInfo?.registrar || "Namecheap, Inc."}>{result.details.domainInfo?.registrar || "Namecheap, Inc."}</span>
                        </div>
                        <div className="text-[10px] md:text-sm flex justify-between border-b border-white/5 pb-1">
                          <span className="text-white/40">Domain Age</span> 
                          <span className="font-medium text-white/80">{result.details.domainInfo?.age || "5 Years, 12 Days"}</span>
                        </div>
                        <div className="text-[10px] md:text-sm flex justify-between pt-1">
                          <span className="text-white/40">Created</span> 
                          <span className="font-medium text-white/80">{result.details.domainInfo?.creationDate || "2019-07-18"}</span>
                        </div>
                      </div>
                    </div>

                    {/* SSL */}
                    <div className="p-5 md:p-6 rounded-xl bg-white/5 border border-white/5 flex flex-col justify-center">
                      <div className="text-[10px] md:text-xs text-white/40 mb-3 font-mono">SSL / TLS CERTIFICATE</div>
                      <div className="flex items-center gap-3 mb-4">
                        <div className={`w-3 h-3 rounded-full ${result.details.ssl.valid ? 'bg-[#00FF66]' : 'bg-[#FF003C]'}`} />
                        <div className="text-sm md:text-base font-medium truncate" title={result.details.ssl.issuer}>{result.details.ssl.issuer}</div>
                      </div>
                      <div className="text-[10px] md:text-xs text-white/50 font-mono">EXPIRES: {result.details.ssl.expiry}</div>
                    </div>
                    
                    {/* Remediation Advice Box */}
                    <div className="col-span-1 md:col-span-2 lg:col-span-3 p-5 md:p-6 rounded-xl bg-white/5 border border-white/5 flex flex-col justify-center">
                      <div className="text-[10px] md:text-xs text-white/40 mb-2 font-mono">RECOMMENDED ACTION</div>
                      <div className="text-xs md:text-sm text-white/80 font-medium">
                        {result.threatLevel === "critical" ? "Critical Risk: Isolate affected endpoints immediately and block IOCs at network perimeter." :
                         result.threatLevel === "high" ? "High Risk: Block at network perimeter and investigate affected endpoints." :
                         result.threatLevel === "suspicious" ? "Suspicious: Monitor traffic closely and restrict user access." :
                         "Safe: No immediate action required. Continue standard monitoring."}
                      </div>
                    </div>

                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

      </div>
    </section>
  );
}
