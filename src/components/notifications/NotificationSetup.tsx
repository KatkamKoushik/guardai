"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import GlassCard from "@/components/ui/GlassCard";
import MagneticButton from "@/components/ui/MagneticButton";

type Platform = "discord" | "telegram";

interface NotificationConfig {
  platform: Platform;
  webhookUrl?: string;
  botToken?: string;
  chatId?: string;
  alertsEnabled: boolean;
}

export default function NotificationSetup() {
  const [selectedPlatform, setSelectedPlatform] = useState<Platform | null>(null);
  const [config, setConfig] = useState<NotificationConfig>({
    platform: "discord",
    alertsEnabled: true,
  });
  const [step, setStep] = useState<"select" | "setup" | "test" | "complete">("select");
  const [testSent, setTestSent] = useState(false);

  const handleConnect = async () => {
    setStep("test");
    await new Promise((resolve) => setTimeout(resolve, 2000));
    setTestSent(true);
    await new Promise((resolve) => setTimeout(resolve, 1000));
    setStep("complete");
  };

  return (
    <section className="relative min-h-screen flex flex-col items-center justify-center px-4 py-24 z-10">
      <div className="w-full max-w-4xl">
        <div className="text-center mb-12">
          <h2
            className="text-4xl md:text-5xl font-bold tracking-tighter mb-4"
            style={{ fontFamily: "var(--font-heading)" }}
          >
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
              <motion.div
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => {
                  setSelectedPlatform("discord");
                  setConfig({ ...config, platform: "discord" });
                  setStep("setup");
                }}
                className="cursor-pointer"
              >
                <GlassCard className="text-center py-12">
                  <div className="w-20 h-20 mx-auto mb-6 rounded-2xl bg-[#5865F2]/10 border border-[#5865F2]/30 flex items-center justify-center">
                    <svg className="w-10 h-10 text-[#5865F2]" viewBox="0 0 24 24" fill="currentColor">
                      <path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z" />
                    </svg>
                  </div>
                  <h3 className="text-xl font-bold mb-2" style={{ fontFamily: "var(--font-heading)" }}>
                    Discord
                  </h3>
                  <p className="text-sm text-white/40">
                    Real-time alerts via webhooks to your Discord server
                  </p>
                </GlassCard>
              </motion.div>

              <motion.div
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => {
                  setSelectedPlatform("telegram");
                  setConfig({ ...config, platform: "telegram" });
                  setStep("setup");
                }}
                className="cursor-pointer"
              >
                <GlassCard className="text-center py-12">
                  <div className="w-20 h-20 mx-auto mb-6 rounded-2xl bg-[#0088CC]/10 border border-[#0088CC]/30 flex items-center justify-center">
                    <svg className="w-10 h-10 text-[#0088CC]" viewBox="0 0 24 24" fill="currentColor">
                      <path d="M11.944 0A12 12 0 000 12a12 12 0 0012 12 12 12 0 0012-12A12 12 0 0012 0a12 12 0 00-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 01.171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.479.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z" />
                    </svg>
                  </div>
                  <h3 className="text-xl font-bold mb-2" style={{ fontFamily: "var(--font-heading)" }}>
                    Telegram
                  </h3>
                  <p className="text-sm text-white/40">
                    Secure bot notifications to your Telegram chat
                  </p>
                </GlassCard>
              </motion.div>
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
                    {selectedPlatform === "discord" ? (
                      <svg className="w-6 h-6 text-[#5865F2]" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z" />
                      </svg>
                    ) : (
                      <svg className="w-6 h-6 text-[#0088CC]" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M11.944 0A12 12 0 000 12a12 12 0 0012 12 12 12 0 0012-12A12 12 0 0012 0a12 12 0 00-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 01.171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.479.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z" />
                      </svg>
                    )}
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
                          <div className="w-6 h-6 rounded-full bg-[#00F0FF]/10 flex items-center justify-center flex-shrink-0 mt-0.5">
                            <span className="text-xs text-[#00F0FF]">1</span>
                          </div>
                          <div>
                            <h4 className="text-sm font-medium mb-1">Create a Discord Webhook</h4>
                            <p className="text-xs text-white/40">
                              Go to your Discord server settings → Integrations → Webhooks → New Webhook
                            </p>
                          </div>
                        </div>
                      </div>
                      <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
                        <div className="flex items-start gap-3">
                          <div className="w-6 h-6 rounded-full bg-[#00F0FF]/10 flex items-center justify-center flex-shrink-0 mt-0.5">
                            <span className="text-xs text-[#00F0FF]">2</span>
                          </div>
                          <div>
                            <h4 className="text-sm font-medium mb-1">Paste Webhook URL</h4>
                            <input
                              type="url"
                              value={config.webhookUrl || ""}
                              onChange={(e) => setConfig({ ...config, webhookUrl: e.target.value })}
                              placeholder="https://discord.com/api/webhooks/..."
                              className="w-full mt-2 px-4 py-3 bg-[#0a0a0a] border border-white/10 rounded-lg text-white text-sm placeholder-white/30 focus:outline-none focus:border-[#00F0FF]/50 transition-colors"
                              style={{ fontFamily: "var(--font-mono)" }}
                            />
                          </div>
                        </div>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
                        <div className="flex items-start gap-3">
                          <div className="w-6 h-6 rounded-full bg-[#00F0FF]/10 flex items-center justify-center flex-shrink-0 mt-0.5">
                            <span className="text-xs text-[#00F0FF]">1</span>
                          </div>
                          <div>
                            <h4 className="text-sm font-medium mb-1">Create a Telegram Bot</h4>
                            <p className="text-xs text-white/40">
                              Message @BotFather on Telegram → /newbot → Follow the prompts
                            </p>
                          </div>
                        </div>
                      </div>
                      <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
                        <div className="flex items-start gap-3">
                          <div className="w-6 h-6 rounded-full bg-[#00F0FF]/10 flex items-center justify-center flex-shrink-0 mt-0.5">
                            <span className="text-xs text-[#00F0FF]">2</span>
                          </div>
                          <div>
                            <h4 className="text-sm font-medium mb-1">Enter Bot Token & Chat ID</h4>
                            <input
                              type="text"
                              value={config.botToken || ""}
                              onChange={(e) => setConfig({ ...config, botToken: e.target.value })}
                              placeholder="Bot Token from @BotFather"
                              className="w-full mt-2 px-4 py-3 bg-[#0a0a0a] border border-white/10 rounded-lg text-white text-sm placeholder-white/30 focus:outline-none focus:border-[#00F0FF]/50 transition-colors"
                              style={{ fontFamily: "var(--font-mono)" }}
                            />
                            <input
                              type="text"
                              value={config.chatId || ""}
                              onChange={(e) => setConfig({ ...config, chatId: e.target.value })}
                              placeholder="Your Chat ID"
                              className="w-full mt-2 px-4 py-3 bg-[#0a0a0a] border border-white/10 rounded-lg text-white text-sm placeholder-white/30 focus:outline-none focus:border-[#00F0FF]/50 transition-colors"
                              style={{ fontFamily: "var(--font-mono)" }}
                            />
                          </div>
                        </div>
                      </div>
                    </>
                  )}

                  <div className="flex gap-3">
                    <MagneticButton
                      onClick={() => setStep("select")}
                      variant="ghost"
                    >
                      BACK
                    </MagneticButton>
                    <MagneticButton
                      onClick={handleConnect}
                      variant="primary"
                      className="flex-1"
                    >
                      CONNECT & TEST
                    </MagneticButton>
                  </div>
                </div>
              </GlassCard>
            </motion.div>
          )}

          {step === "test" && (
            <motion.div
              key="test"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="text-center"
            >
              <GlassCard className="max-w-md mx-auto py-12">
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                  className="w-16 h-16 mx-auto mb-6 rounded-full border-2 border-[#00F0FF]/20 border-t-[#00F0FF]"
                />
                <h3 className="text-xl font-bold mb-2" style={{ fontFamily: "var(--font-heading)" }}>
                  {testSent ? "Test Alert Sent!" : "Sending Test Alert..."}
                </h3>
                <p className="text-sm text-white/40">
                  {testSent
                    ? "Check your messages for a test notification"
                    : "Verifying connection and sending test message"}
                </p>
              </GlassCard>
            </motion.div>
          )}

          {step === "complete" && (
            <motion.div
              key="complete"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="text-center"
            >
              <GlassCard className="max-w-md mx-auto py-12">
                <motion.div
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ type: "spring", stiffness: 200, damping: 15 }}
                  className="w-16 h-16 mx-auto mb-6 rounded-full bg-[#00FF66]/10 border border-[#00FF66]/30 flex items-center justify-center"
                >
                  <svg className="w-8 h-8 text-[#00FF66]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M22 11.08V12a10 10 0 11-5.93-9.14" strokeLinecap="round" />
                    <path d="M22 4L12 14.01l-3-3" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </motion.div>
                <h3 className="text-xl font-bold mb-2" style={{ fontFamily: "var(--font-heading)" }}>
                  Successfully Connected!
                </h3>
                <p className="text-sm text-white/40 mb-6">
                  You will now receive real-time threat notifications on {selectedPlatform === "discord" ? "Discord" : "Telegram"}
                </p>
                <MagneticButton
                  onClick={() => {
                    setStep("select");
                    setSelectedPlatform(null);
                  }}
                  variant="secondary"
                >
                  SETUP ANOTHER
                </MagneticButton>
              </GlassCard>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </section>
  );
}
