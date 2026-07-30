"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import Link from "next/link";
import { signIn } from "next-auth/react";
import GlassCard from "@/components/ui/GlassCard";
import MagneticButton from "@/components/ui/MagneticButton";

type AuthMode = "login" | "signup";

export default function AuthForm({ mode = "login" }: { mode?: AuthMode }) {
  const [authMode, setAuthMode] = useState<AuthMode>(mode);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleProviderSignIn = async (provider: "google" | "github") => {
    try {
      setError(null);
      setIsSubmitting(true);
      await signIn(provider, { redirectTo: "/" });
    } catch {
      setError("Authentication failed. Please try again.");
      setIsSubmitting(false);
    }
  };

  return (
    <section className="relative min-h-screen flex items-center justify-center px-4 z-10">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md"
      >
        <div className="text-center mb-8">
          <Link href="/" className="inline-flex items-center gap-2 mb-6">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#00F0FF] to-[#00FF66] flex items-center justify-center">
              <span className="text-[#050505] font-bold" style={{ fontFamily: "var(--font-heading)" }}>
                G
              </span>
            </div>
          </Link>
          <h2
            className="text-3xl font-bold tracking-tighter mb-2"
            style={{ fontFamily: "var(--font-heading)" }}
          >
            {authMode === "login" ? "WELCOME BACK" : "JOIN GUARDAI"}
          </h2>
          <p className="text-white/40 text-sm" style={{ fontFamily: "var(--font-mono)" }}>
            {authMode === "login"
              ? "SIGN IN TO ACCESS YOUR DASHBOARD"
              : "CREATE AN ACCOUNT TO GET STARTED"}
          </p>
        </div>

        <GlassCard>
          <div className="flex gap-2 mb-6 p-1 bg-white/[0.02] rounded-lg">
            {(["login", "signup"] as AuthMode[]).map((m) => (
              <button
                type="button"
                key={m}
                onClick={() => setAuthMode(m)}
                className={`flex-1 py-2 text-xs rounded-md transition-all duration-300 ${
                  authMode === m
                    ? "bg-[#00F0FF]/10 text-[#00F0FF]"
                    : "text-white/40 hover:text-white/60"
                }`}
                style={{ fontFamily: "var(--font-mono)" }}
              >
                {m.toUpperCase()}
              </button>
            ))}
          </div>

          <div className="space-y-3">
            <MagneticButton 
              variant="secondary" 
              className="w-full justify-center"
              onClick={() => handleProviderSignIn("google")}
              disabled={isSubmitting}
            >
              <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24" fill="currentColor">
                <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
                <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
                <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05" />
                <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
              </svg>
              CONTINUE WITH GOOGLE
            </MagneticButton>
            <MagneticButton 
              variant="secondary" 
              className="w-full justify-center"
              onClick={() => handleProviderSignIn("github")}
              disabled={isSubmitting}
            >
              <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
              </svg>
              CONTINUE WITH GITHUB
            </MagneticButton>
          </div>

          <AnimatePresence mode="wait">
            <motion.div
              key={authMode}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              className="mt-6 text-center text-xs text-white/40"
              style={{ fontFamily: "var(--font-mono)" }}
            >
              {authMode === "login"
                ? "Use your Google or GitHub account to sign in securely."
                : "Create your account securely using Google or GitHub OAuth."}
            </motion.div>
          </AnimatePresence>

          {error && (
            <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
              {error}
            </div>
          )}
        </GlassCard>
      </motion.div>
    </section>
  );
}
