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
          "fixed top-0 left-0 right-0 z-50 transition-all duration-500",
          isScrolled
            ? "glass-strong py-3"
            : "py-5 bg-transparent"
        )}
      >
        <div className="max-w-7xl mx-auto px-6 flex items-center justify-between">
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

          <button
            type="button"
            onClick={() => setIsMobileOpen(!isMobileOpen)}
            className="md:hidden w-10 h-10 flex flex-col items-center justify-center gap-1.5"
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
      </motion.nav>

      <AnimatePresence>
        {isMobileOpen && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="fixed inset-0 z-40 glass-strong pt-24 px-6 md:hidden"
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
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
