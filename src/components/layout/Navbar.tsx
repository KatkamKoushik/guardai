"use client";

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import Link from "next/link";
import { useSession, signOut } from "next-auth/react";
import { cn } from "@/lib/utils";

const navLinks = [
  { href: "/", label: "HOME" },
  { href: "/scan", label: "DEEP SCAN" },
  { href: "/threats", label: "THREAT MAP" },
  { href: "/audit", label: "AUDIT LOG" },
  { href: "/notifications", label: "ALERTS" },
];

export default function Navbar() {
  const { data: session, status } = useSession();
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileOpen, setIsMobileOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 50);
    };

    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <>
      <motion.nav
        initial={{ y: -100 }}
        animate={{ y: 0 }}
        transition={{ duration: 0.8, delay: 3.5, ease: "easeOut" }}
        className={cn(
          "fixed top-0 left-0 right-0 z-40 transition-all duration-500",
          isScrolled
            ? "bg-black/95 backdrop-blur-md shadow-lg py-3"
            : "bg-black/95 backdrop-blur-md py-5"
        )}
      >
        <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-wrap items-center justify-between gap-2 md:gap-6">
          <Link href="/" className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#00F0FF] to-[#00FF66] flex items-center justify-center">
              <span className="text-[#050505] font-bold text-sm" style={{ fontFamily: "var(--font-heading)" }}>
                G
              </span>
            </div>
            <span className="font-bold text-lg tracking-tight" style={{ fontFamily: "var(--font-heading)" }}>
              GUARD<span className="text-[#00F0FF]">AI</span>
            </span>
          </Link>

          <div className="hidden md:flex items-center gap-1">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className="px-4 py-2 text-xs tracking-wider text-white/50 hover:text-[#00F0FF] transition-colors duration-300"
                style={{ fontFamily: "var(--font-mono)" }}
              >
                {link.label}
              </Link>
            ))}
          </div>

          <div className="hidden md:flex items-center gap-4">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full glass">
              <div className="w-1.5 h-1.5 rounded-full bg-[#00FF66] animate-pulse" />
              <span className="text-xs text-white/50" style={{ fontFamily: "var(--font-mono)" }}>
                ONLINE
              </span>
            </div>
            {status === "authenticated" ? (
              <div className="flex items-center gap-3">
                <span className="text-xs tracking-wider text-white/80" style={{ fontFamily: "var(--font-mono)" }}>
                  {session.user?.name || session.user?.email}
                </span>
                <button
                  onClick={() => signOut({ callbackUrl: '/' })}
                  className="px-4 py-2 text-xs tracking-wider bg-red-500/10 border border-red-500/30 text-red-500 rounded-lg hover:bg-red-500/20 transition-all duration-300"
                  style={{ fontFamily: "var(--font-mono)" }}
                >
                  DISCONNECT
                </button>
              </div>
            ) : (
              <Link
                href="/auth/login"
                className="px-4 py-2 text-xs tracking-wider bg-[#00F0FF]/10 border border-[#00F0FF]/30 text-[#00F0FF] rounded-lg hover:bg-[#00F0FF]/20 transition-all duration-300"
                style={{ fontFamily: "var(--font-mono)" }}
              >
                {status === "loading" ? "CONNECTING..." : "CONNECT"}
              </Link>
            )}
          </div>

          <div className="flex items-center gap-3 md:hidden relative z-50">
            {status === "authenticated" ? (
              <div className="flex items-center justify-center w-10 h-10 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-500 font-bold">
                 {session.user?.name?.[0]?.toUpperCase() || session.user?.email?.[0]?.toUpperCase() || "U"}
              </div>
            ) : (
              <Link
                href="/auth/login"
                className="px-4 py-3 text-xs tracking-wider bg-[#00F0FF]/10 border border-[#00F0FF]/30 text-[#00F0FF] rounded-lg font-mono"
              >
                LOGIN
              </Link>
            )}

            <button
              type="button"
              onClick={() => setIsMobileOpen(!isMobileOpen)}
              className="w-10 h-10 flex flex-col items-center justify-center gap-1.5"
              aria-label="Toggle navigation menu"
              aria-expanded={isMobileOpen}
            >
              <motion.span
                animate={isMobileOpen ? { rotate: 45, y: 6 } : { rotate: 0, y: 0 }}
                className="w-6 h-[1px] bg-white/60"
              />
              <motion.span
                animate={isMobileOpen ? { opacity: 0 } : { opacity: 1 }}
                className="w-6 h-[1px] bg-white/60"
              />
              <motion.span
                animate={isMobileOpen ? { rotate: -45, y: -6 } : { rotate: 0, y: 0 }}
                className="w-6 h-[1px] bg-white/60"
              />
            </button>
          </div>
        </div>
      </motion.nav>

      <AnimatePresence>
        {isMobileOpen && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="fixed inset-0 z-50 bg-black/95 backdrop-blur-lg pt-24 px-6 md:hidden"
          >
            <div className="flex flex-col gap-2">
              {navLinks.map((link, i) => (
                <motion.div
                  key={link.href}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.1 }}
                >
                  <Link
                    href={link.href}
                    onClick={() => setIsMobileOpen(false)}
                    className="block py-4 text-lg tracking-wider text-white/60 hover:text-[#00F0FF] transition-colors border-b border-white/5"
                    style={{ fontFamily: "var(--font-mono)" }}
                  >
                    {link.label}
                  </Link>
                </motion.div>
              ))}

              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: navLinks.length * 0.1 }}
                className="mt-6 pt-6 border-t border-white/10"
              >
                {status === "authenticated" ? (
                  <div className="flex flex-col gap-4">
                    <div className="flex items-center gap-3">
                      <div className="w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-500 font-bold text-xl">
                        {session.user?.name?.[0]?.toUpperCase() || session.user?.email?.[0]?.toUpperCase() || "U"}
                      </div>
                      <div className="flex flex-col">
                        <span className="text-sm tracking-wider text-white" style={{ fontFamily: "var(--font-mono)" }}>
                          {session.user?.name || "Verified User"}
                        </span>
                        <span className="text-xs text-white/50">{session.user?.email}</span>
                      </div>
                    </div>
                    <button
                      onClick={() => {
                        setIsMobileOpen(false);
                        signOut({ callbackUrl: '/' });
                      }}
                      className="w-full px-4 py-3 text-sm tracking-wider bg-red-500/10 border border-red-500/30 text-red-500 rounded-lg hover:bg-red-500/20 transition-all text-center z-50 relative mt-2"
                      style={{ fontFamily: "var(--font-mono)" }}
                    >
                      DISCONNECT
                    </button>
                  </div>
                ) : (
                  <Link
                    href="/auth/login"
                    onClick={() => setIsMobileOpen(false)}
                    className="block w-full px-4 py-3 text-sm tracking-wider bg-[#00F0FF]/10 border border-[#00F0FF]/30 text-[#00F0FF] rounded-lg hover:bg-[#00F0FF]/20 transition-all text-center z-50 relative"
                    style={{ fontFamily: "var(--font-mono)" }}
                  >
                    CONNECT ACCOUNT
                  </Link>
                )}
              </motion.div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
