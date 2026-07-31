"use client";

import { useEffect, useRef } from "react";
import { motion } from "framer-motion";
import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import Link from "next/link";
import HeroSection from "@/components/hero/HeroSection";
import GlassCard from "@/components/ui/GlassCard";
import LiveTelemetry from "@/components/hero/LiveTelemetry";

if (typeof window !== "undefined") {
  gsap.registerPlugin(ScrollTrigger);
}

const features = [
  {
    icon: (
      <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
    title: "Deep Scan",
    description: "Advanced URL analysis combining VirusTotal intelligence with our custom ML model for phishing detection.",
    color: "#00F0FF",
    href: "/scan",
  },
  {
    icon: (
      <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <circle cx="12" cy="12" r="10" />
        <path d="M12 6v6l4 2" strokeLinecap="round" />
      </svg>
    ),
    title: "Real-Time Monitoring",
    description: "24/7 global threat monitoring with instant alerts via Discord, Telegram, or email.",
    color: "#00FF66",
    href: "/notifications",
  },
  {
    icon: (
      <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
    title: "Global Threat Map",
    description: "Interactive 3D visualization of cyber threats happening worldwide in real-time.",
    color: "#FF003C",
    href: "/threats",
  },
  {
    icon: (
      <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
    title: "Audit Logging",
    description: "Complete activity tracking with detailed logs for compliance and forensic analysis.",
    color: "#FFB800",
    href: "/audit",
  },
];

export default function Home() {
  const featuresRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!featuresRef.current) return;

    const cards = featuresRef.current.querySelectorAll(".feature-card");
    
    // Let GSAP control initial state instead of CSS class
    gsap.set(cards, { opacity: 0, y: 50 });

    const triggers: ScrollTrigger[] = [];
    cards.forEach((card, i) => {
      const anim = gsap.to(card, {
        opacity: 1,
        y: 0,
        duration: 0.8,
        delay: i * 0.15,
        ease: "power3.out",
        paused: true,
      });

      const st = ScrollTrigger.create({
        trigger: card,
        start: "top 90%",
        onEnter: () => anim.play(),
        onLeaveBack: () => anim.reverse(),
      });
      triggers.push(st);
    });

    return () => {
      triggers.forEach((t) => t.kill());
    };
  }, []);

  return (
    <div className="relative">
      <HeroSection />

      <section ref={featuresRef} className="relative z-10 px-4 py-32">
        <div className="max-w-6xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-100px" }}
            transition={{ duration: 0.8 }}
            className="text-center mb-16"
          >
            <h2
              className="text-4xl md:text-5xl font-bold tracking-tighter mb-4"
              style={{ fontFamily: "var(--font-heading)" }}
            >
              CAPABILITIES
            </h2>
            <p className="text-white/40 text-sm max-w-lg mx-auto" style={{ fontFamily: "var(--font-mono)" }}>
              ENTERPRISE-GRADE SECURITY TOOLS POWERED BY AI AND REAL-TIME THREAT INTELLIGENCE
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {features.map((feature, i) => (
              <Link key={i} href={feature.href} className="feature-card block">
                <GlassCard className="group cursor-pointer transition-all duration-300 hover:scale-[1.02] hover:border-[#00F0FF]/50 hover:shadow-[0_0_15px_rgba(0,240,255,0.2)] h-full">
                  <div
                    className="w-12 h-12 rounded-xl flex items-center justify-center mb-4 transition-all duration-300 group-hover:scale-110"
                    style={{
                      backgroundColor: `${feature.color}10`,
                      border: `1px solid ${feature.color}30`,
                      color: feature.color,
                    }}
                  >
                    {feature.icon}
                  </div>
                  <h3
                    className="text-xl font-bold mb-2"
                    style={{ fontFamily: "var(--font-heading)" }}
                  >
                    {feature.title}
                  </h3>
                  <p className="text-sm text-white/40 leading-relaxed">
                    {feature.description}
                  </p>
                </GlassCard>
              </Link>
            ))}
          </div>
        </div>
      </section>

      <section className="relative z-10 px-4 py-32">
        <div className="max-w-4xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-100px" }}
            transition={{ duration: 0.8 }}
          >
            <h2
              className="text-4xl md:text-5xl font-bold tracking-tighter mb-6"
              style={{ fontFamily: "var(--font-heading)" }}
            >
              READY TO <span className="text-gradient-cyan">DEFEND</span>?
            </h2>
            <p className="text-white/40 text-sm mb-8 max-w-lg mx-auto" style={{ fontFamily: "var(--font-mono)" }}>
              Join thousands of security professionals using GuardAI to protect their digital assets.
            </p>

            <LiveTelemetry showFeed={false} />

          </motion.div>
        </div>
      </section>

      <footer className="relative z-10 border-t border-white/5 py-12 px-4">
        <div className="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-md bg-gradient-to-br from-[#00F0FF] to-[#00FF66] flex items-center justify-center">
              <span className="text-[#050505] text-xs font-bold" style={{ fontFamily: "var(--font-heading)" }}>
                G
              </span>
            </div>
            <span className="text-sm text-white/40" style={{ fontFamily: "var(--font-mono)" }}>
              GUARDAI &copy; 2026
            </span>
          </div>
          <div className="flex gap-6">
            {["PRIVACY", "TERMS", "CONTACT"].map((link) => (
              <Link
                key={link}
                href={`/${link.toLowerCase()}`}
                className="text-xs text-white/30 hover:text-white/60 transition-colors"
                style={{ fontFamily: "var(--font-mono)" }}
              >
                {link}
              </Link>
            ))}
          </div>
        </div>
      </footer>
    </div>
  );
}
