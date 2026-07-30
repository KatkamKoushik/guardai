"use client";

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import GlassCard from "@/components/ui/GlassCard";
import MagneticButton from "@/components/ui/MagneticButton";

type Platform = "discord" | "telegram";

interface NotificationConfig {
  platform: Platform;
  webhookUrl?: string;
  botToken?: string;
  chatId?: string;
}

interface SavedConfig {
  id: string;
  platform: Platform;
  isActive: boolean;
  alertSensitivity: "all" | "high_critical" | "critical";
  webhookUrl?: string;
  botToken?: string;
  chatId?: string;
}

export default function NotificationSetup() {
  const [selectedPlatform, setSelectedPlatform] = useState<Platform | null>(null);
  const [config, setConfig] = useState<NotificationConfig>({ platform: "discord" });
  const [step, setStep] = useState<"select" | "setup" | "test" | "complete">("select");
  const [testSent, setTestSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isConnecting, setIsConnecting] = useState(false);
  
  const [savedConfigs, setSavedConfigs] = useState<SavedConfig[]>([]);
  const [isLoadingConfigs, setIsLoadingConfigs] = useState(true);

  const fetchConfigs = async () => {
    setIsLoadingConfigs(true);
    try {
      const res = await fetch("/api/alerts/config");
      const data = await res.json();
      if (data.configs) {
        setSavedConfigs(data.configs);
      }
    } catch (e) {
      console.error("Failed to load configs", e);
    } finally {
      setIsLoadingConfigs(false);
    }
  };

  useEffect(() => {
    fetchConfigs();
  }, []);

  const getSavedConfig = (platform: Platform) => savedConfigs.find((c) => c.platform === platform);

  const handleConnect = async () => {
    if (isConnecting) return;
    setError(null);
    setTestSent(false);

    if (selectedPlatform === "discord" && !config.webhookUrl) {
      setError("Please provide a Discord webhook URL.");
      return;
    }
    if (selectedPlatform === "telegram" && (!config.botToken || !config.chatId)) {
      setError("Please provide Telegram bot token and chat ID.");
      return;
    }

    setIsConnecting(true);
    setStep("test");

    try {
      const endpoint = selectedPlatform === "discord" ? "/api/alerts/discord" : "/api/alerts/telegram";
      const payload = selectedPlatform === "discord" 
        ? { webhookUrl: config.webhookUrl }
        : { botToken: config.botToken, chatId: config.chatId };

      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.error || "Failed to connect notification provider.");
      }

      await fetchConfigs(); // Refresh configs
      setTestSent(true);
      setStep("complete");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to connect notification provider.");
      setStep("setup");
    } finally {
      setIsConnecting(false);
    }
  };

  const handleUpdateSensitivity = async (platform: Platform, val: string) => {
    try {
      const response = await fetch("/api/alerts/config", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ platform, alertSensitivity: val }),
      });
      if (response.ok) {
        setSavedConfigs((prev) => prev.map((c) => c.platform === platform ? { ...c, alertSensitivity: val as any } : c));
      }
    } catch (e) {
      console.error("Failed to update sensitivity", e);
    }
  };

  const handleSendTestAlert = async (platform: Platform) => {
    try {
      const response = await fetch("/api/alerts/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ platform }),
      });
      if (response.ok) {
        alert("Test alert sent successfully!");
      } else {
        alert("Failed to send test alert.");
      }
    } catch (e) {
      console.error(e);
      alert("Failed to send test alert.");
    }
  };

  const LivePreviewBox = () => (
    <div className="mt-8 p-4 bg-[#0a0a0a] rounded-xl border border-white/10 relative overflow-hidden">
      <div className="absolute top-0 left-0 w-1 h-full bg-[#FF003C]" />
      <div className="text-xs text-white/50 mb-2 font-mono">Live Alert Preview</div>
      <div className="text-sm text-white/90 whitespace-pre-wrap font-sans">
        🚨 <strong>[CRITICAL ALERT] GuardAI Threat Detection</strong>{"\n\n"}
        <strong>Target URL:</strong> http://wicar.org/test/eicar.com{"\n"}
        <strong>Risk Score:</strong> 95/100 (CRITICAL){"\n\n"}
        The target URL hosts an active remote code execution payload flagged by 19 malware vendors.{"\n\n"}
        <strong>Concrete Proof & Evidence Breakdown:</strong>{"\n"}
        • 🦠 <strong>VirusTotal:</strong> 19 / 92 engines flagged as Malicious{"\n"}
        • 🔒 <strong>SSL/TLS Status:</strong> UNENCRYPTED (HTTP Only){"\n"}
        • 🛡️ <strong>Missing Headers:</strong> HSTS, X-Frame-Options, CSP{"\n"}
        • ⚡ <strong>Lexical/ML Score:</strong> Shannon Entropy: 3.096{"\n\n"}
        <strong>Recommended Action:</strong> Do not navigate to this site. Block traffic at firewall.{"\n\n"}
        <span className="text-[#00F0FF] underline">View Audit Log</span>
      </div>
    </div>
  );

  return (
    <section className="relative min-h-screen flex flex-col items-center py-24 px-4 z-10">
      <div className="w-full max-w-4xl">
        <div className="text-center mb-12">
          <h2 className="text-4xl md:text-5xl font-bold tracking-tighter mb-4" style={{ fontFamily: "var(--font-heading)" }}>
            <span className="text-gradient-cyan">ALERT</span> INTEGRATION
          </h2>
          <p className="text-white/40 text-sm" style={{ fontFamily: "var(--font-mono)" }}>
            CONNECT YOUR PLATFORM FOR REAL-TIME THREAT NOTIFICATIONS
          </p>
        </div>

        <AnimatePresence mode="wait">
          {step === "select" && (
            <motion.div
              key="select"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="grid grid-cols-1 md:grid-cols-2 gap-6"
            >
              {(["discord", "telegram"] as Platform[]).map((platform) => {
                const saved = getSavedConfig(platform);
                const isDiscord = platform === "discord";
                
                return (
                  <GlassCard key={platform} className="relative py-8 flex flex-col justify-between">
                    {saved && (
                      <div className="absolute top-4 right-4 bg-[#00FF66]/20 border border-[#00FF66]/50 text-[#00FF66] px-2 py-1 rounded text-[10px] font-mono tracking-wider flex items-center gap-2">
                        <div className="w-1.5 h-1.5 rounded-full bg-[#00FF66] animate-pulse" />
                        CONNECTED
                      </div>
                    )}
                    
                    <div className="text-center">
                      <div className={`w-20 h-20 mx-auto mb-4 rounded-2xl ${isDiscord ? 'bg-[#5865F2]/10 border-[#5865F2]/30' : 'bg-[#0088CC]/10 border-[#0088CC]/30'} border flex items-center justify-center`}>
                        {isDiscord ? (
                          <svg className="w-10 h-10 text-[#5865F2]" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z" />
                          </svg>
                        ) : (
                          <svg className="w-10 h-10 text-[#0088CC]" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M11.944 0A12 12 0 000 12a12 12 0 0012 12 12 12 0 0012-12A12 12 0 0012 0a12 12 0 00-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 01.171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.479.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z" />
                          </svg>
                        )}
                      </div>
                      <h3 className="text-xl font-bold mb-2" style={{ fontFamily: "var(--font-heading)" }}>{isDiscord ? "Discord" : "Telegram"}</h3>
                      
                      {saved && (
                        <div className="text-[11px] text-white/50 font-mono mb-4 bg-black/40 py-1.5 px-3 rounded-md inline-block max-w-[90%] truncate">
                          {isDiscord ? `URL: ${saved.webhookUrl}` : `Chat ID: ${saved.chatId}`}
                        </div>
                      )}
                    </div>

                    {saved ? (
                      <div className="mt-4 space-y-4">
                        <div className="text-left bg-white/5 p-3 rounded-lg border border-white/10">
                          <label className="text-xs text-white/60 mb-2 block font-mono">Sensitivity Threshold</label>
                          <select 
                            value={saved.alertSensitivity}
                            onChange={(e) => handleUpdateSensitivity(platform, e.target.value)}
                            className="w-full bg-[#0a0a0a] text-sm text-white px-3 py-2 rounded-md border border-white/10 outline-none focus:border-[#00F0FF]/50"
                          >
                            <option value="all">All Scans (Safe, Medium, High, Critical)</option>
                            <option value="high_critical">High & Critical Only</option>
                            <option value="critical">Critical Threats Only</option>
                          </select>
                        </div>
                        <div className="flex gap-2">
                          <button 
                            className="flex-1 bg-white/10 hover:bg-white/20 transition-colors py-2 text-xs font-mono rounded border border-white/20"
                            onClick={() => {
                              setSelectedPlatform(platform);
                              setConfig({ ...config, platform });
                              setStep("setup");
                            }}
                          >
                            RECONFIGURE
                          </button>
                          <button 
                            className="flex-1 bg-[#FF003C]/20 text-[#FF003C] hover:bg-[#FF003C]/30 transition-colors py-2 text-xs font-mono rounded border border-[#FF003C]/50"
                            onClick={() => handleSendTestAlert(platform)}
                          >
                            SEND TEST ALERT
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div className="mt-4">
                        <p className="text-sm text-white/40 mb-6 text-center">Configure real-time alerts</p>
                        <MagneticButton
                          onClick={() => {
                            setError(null);
                            setSelectedPlatform(platform);
                            setConfig({ ...config, platform });
                            setStep("setup");
                          }}
                          variant="secondary"
                          className="w-full"
                        >
                          SETUP {isDiscord ? "DISCORD" : "TELEGRAM"}
                        </MagneticButton>
                      </div>
                    )}
                  </GlassCard>
                );
              })}
            </motion.div>
          )}

          {step === "setup" && selectedPlatform && (
            <motion.div
              key="setup"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
            >
              <GlassCard>
                <div className="flex items-center gap-4 mb-8">
                  <div
                    className="w-12 h-12 rounded-xl flex items-center justify-center"
                    style={{
                      backgroundColor: selectedPlatform === "discord" ? "#5865F220" : "#0088CC20",
                      border: `1px solid ${selectedPlatform === "discord" ? "#5865F240" : "#0088CC40"}`,
                    }}
                  >
                     {/* icons omitted for brevity, using simple text for generic icon if needed, but since it's just svg we can keep it */}
                     <span className="font-bold text-white/60">{selectedPlatform === "discord" ? "D" : "T"}</span>
                  </div>
                  <div>
                    <h3 className="text-lg font-bold" style={{ fontFamily: "var(--font-heading)" }}>
                      {selectedPlatform === "discord" ? "Discord" : "Telegram"} Setup
                    </h3>
                    <p className="text-sm text-white/40">
                      Follow the steps below to connect your account
                    </p>
                  </div>
                </div>

                <div className="space-y-6">
                  {selectedPlatform === "discord" ? (
                    <>
                      <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
                        <div className="flex items-start gap-3">
                          <div className="w-6 h-6 rounded-full bg-[#00F0FF]/10 flex items-center justify-center flex-shrink-0 mt-0.5"><span className="text-xs text-[#00F0FF]">1</span></div>
                          <div><h4 className="text-sm font-medium mb-1">Create a Discord Webhook</h4><p className="text-xs text-white/40">Go to your Discord server settings → Integrations → Webhooks → New Webhook</p></div>
                        </div>
                      </div>
                      <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
                        <div className="flex items-start gap-3">
                          <div className="w-6 h-6 rounded-full bg-[#00F0FF]/10 flex items-center justify-center flex-shrink-0 mt-0.5"><span className="text-xs text-[#00F0FF]">2</span></div>
                          <div className="w-full"><h4 className="text-sm font-medium mb-1">Paste Webhook URL</h4>
                            <input type="url" value={config.webhookUrl || ""} onChange={(e) => setConfig({ ...config, webhookUrl: e.target.value })} placeholder="https://discord.com/api/webhooks/..." className="w-full mt-2 px-4 py-3 bg-[#0a0a0a] border border-white/10 rounded-lg text-white text-sm placeholder-white/30 focus:outline-none focus:border-[#00F0FF]/50 transition-colors" style={{ fontFamily: "var(--font-mono)" }} />
                          </div>
                        </div>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
                        <div className="flex items-start gap-3">
                          <div className="w-6 h-6 rounded-full bg-[#00F0FF]/10 flex items-center justify-center flex-shrink-0 mt-0.5"><span className="text-xs text-[#00F0FF]">1</span></div>
                          <div><h4 className="text-sm font-medium mb-1">Create a Telegram Bot</h4><p className="text-xs text-white/40">Message @BotFather on Telegram → /newbot → Follow the prompts</p></div>
                        </div>
                      </div>
                      <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
                        <div className="flex items-start gap-3">
                          <div className="w-6 h-6 rounded-full bg-[#00F0FF]/10 flex items-center justify-center flex-shrink-0 mt-0.5"><span className="text-xs text-[#00F0FF]">2</span></div>
                          <div className="w-full"><h4 className="text-sm font-medium mb-1">Enter Bot Token & Chat ID</h4>
                            <input type="text" value={config.botToken || ""} onChange={(e) => setConfig({ ...config, botToken: e.target.value })} placeholder="Bot Token from @BotFather" className="w-full mt-2 px-4 py-3 bg-[#0a0a0a] border border-white/10 rounded-lg text-white text-sm placeholder-white/30 focus:outline-none focus:border-[#00F0FF]/50 transition-colors" style={{ fontFamily: "var(--font-mono)" }} />
                            <input type="text" value={config.chatId || ""} onChange={(e) => setConfig({ ...config, chatId: e.target.value })} placeholder="Your Chat ID" className="w-full mt-2 px-4 py-3 bg-[#0a0a0a] border border-white/10 rounded-lg text-white text-sm placeholder-white/30 focus:outline-none focus:border-[#00F0FF]/50 transition-colors" style={{ fontFamily: "var(--font-mono)" }} />
                          </div>
                        </div>
                      </div>
                    </>
                  )}

                  <div className="flex gap-3">
                    <MagneticButton onClick={() => setStep("select")} variant="ghost" disabled={isConnecting}>BACK</MagneticButton>
                    <MagneticButton onClick={handleConnect} variant="primary" className="flex-1" disabled={isConnecting}>{isConnecting ? "CONNECTING..." : "CONNECT & TEST"}</MagneticButton>
                  </div>
                  {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-xs text-red-300">{error}</div>}
                  
                  {/* Live Alert Preview inside setup to show users what they are signing up for */}
                  <LivePreviewBox />
                </div>
              </GlassCard>
            </motion.div>
          )}

          {step === "test" && (
            <motion.div key="test" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} className="text-center">
              <GlassCard className="max-w-md mx-auto py-12">
                <motion.div animate={{ rotate: 360 }} transition={{ duration: 2, repeat: Infinity, ease: "linear" }} className="w-16 h-16 mx-auto mb-6 rounded-full border-2 border-[#00F0FF]/20 border-t-[#00F0FF]" />
                <h3 className="text-xl font-bold mb-2" style={{ fontFamily: "var(--font-heading)" }}>{testSent ? "Test Alert Sent!" : "Sending Test Alert..."}</h3>
                <p className="text-sm text-white/40">{testSent ? "Check your messages for a test notification" : "Verifying connection and sending test message"}</p>
              </GlassCard>
            </motion.div>
          )}

          {step === "complete" && (
            <motion.div key="complete" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} className="text-center">
              <GlassCard className="max-w-md mx-auto py-12">
                <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", stiffness: 200, damping: 15 }} className="w-16 h-16 mx-auto mb-6 rounded-full bg-[#00FF66]/10 border border-[#00FF66]/30 flex items-center justify-center">
                  <svg className="w-8 h-8 text-[#00FF66]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14" strokeLinecap="round" /><path d="M22 4L12 14.01l-3-3" strokeLinecap="round" strokeLinejoin="round" /></svg>
                </motion.div>
                <h3 className="text-xl font-bold mb-2" style={{ fontFamily: "var(--font-heading)" }}>Successfully Connected!</h3>
                <p className="text-sm text-white/40 mb-6">You will now receive real-time threat notifications on {selectedPlatform === "discord" ? "Discord" : "Telegram"}</p>
                <MagneticButton onClick={() => { setStep("select"); setSelectedPlatform(null); }} variant="secondary">RETURN TO SETTINGS</MagneticButton>
              </GlassCard>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </section>
  );
}
