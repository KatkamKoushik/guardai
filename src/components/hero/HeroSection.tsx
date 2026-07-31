"use client";

import { useEffect, useRef } from "react";
import { motion } from "framer-motion";
import { gsap } from "gsap";
import { useRouter } from "next/navigation";
import MagneticButton from "@/components/ui/MagneticButton";

const heroTexts = [
  "CYBERSECURITY",
  "THREAT INTELLIGENCE",
  "DIGITAL DEFENSE",
];

export default function HeroSection() {
  const router = useRouter();
  const titleRef = useRef<HTMLHeadingElement>(null);
  const subtitleRef = useRef<HTMLParagraphElement>(null);

  useEffect(() => {
    const chars = "!<>-_\\/[]{}—=+*^?#________";

    const scrambleText = (element: HTMLElement, target: string, delay: number) => {
      const tl = gsap.timeline({ delay });
      let iterations = 0;
      const maxIterations = target.length * 2;

      tl.to(element, {
        duration: target.length * 0.05,
        onUpdate: function () {
          iterations++;
          const progress = iterations / maxIterations;
          let result = "";
          for (let i = 0; i < target.length; i++) {
            if (i < target.length * progress) {
              result += target[i];
            } else {
              result += chars[Math.floor(Math.random() * chars.length)];
            }
          }
          element.textContent = result;
        },
      });

      return tl;
    };

    const timelines: gsap.core.Timeline[] = [];

    if (titleRef.current) {
      timelines.push(scrambleText(titleRef.current, "GUARDAI", 3));
    }

    if (subtitleRef.current) {
      timelines.push(scrambleText(subtitleRef.current, "NEXT-GEN CYBERSECURITY & THREAT INTELLIGENCE", 3.5));
    }

    return () => {
      timelines.forEach((tl) => tl.kill());
    };
  }, []);

  return (
    <section className="relative min-h-screen flex flex-col items-center justify-center px-4 z-10">
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 1, delay: 3 }}
        className="text-center"
      >
        <motion.div
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.8, delay: 3.2 }}
          className="mb-6"
        >
          <span
            className="text-xs tracking-[0.5em] uppercase text-[#00F0FF]/60 whitespace-nowrap"
            style={{ fontFamily: "var(--font-mono)" }}
          >
            [ SYSTEM STATUS: ACTIVE ]
          </span>
        </motion.div>

        <h1
          ref={titleRef}
          className="text-6xl md:text-8xl lg:text-9xl font-bold tracking-tighter mb-4"
          style={{ fontFamily: "var(--font-heading)" }}
        >
          <span className="text-gradient-cyan">GUARD</span>
          <span className="text-white">AI</span>
        </h1>

        <p
          ref={subtitleRef}
          className="text-sm md:text-base tracking-[0.3em] uppercase text-white/50 mb-8"
          style={{ fontFamily: "var(--font-mono)" }}
        >
          NEXT-GEN CYBERSECURITY & THREAT INTELLIGENCE
        </p>

        <motion.div
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.8, delay: 3.8 }}
          className="flex flex-col sm:flex-row gap-4 justify-center"
        >
          <MagneticButton variant="primary" size="lg" onClick={() => router.push("/scan")}>
            INITIATE DEEP SCAN
          </MagneticButton>
          <MagneticButton variant="secondary" size="lg" onClick={() => router.push("/threats")}>
            VIEW THREAT MAP
          </MagneticButton>
        </motion.div>

        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 1, delay: 4.5 }}
          className="mt-16 flex items-center gap-2 text-white/30"
        >
          <div className="w-1 h-1 rounded-full bg-[#00FF66] animate-pulse" />
          <span className="text-xs" style={{ fontFamily: "var(--font-mono)" }}>
            REAL-TIME MONITORING ACTIVE
          </span>
        </motion.div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 1, delay: 5 }}
        className="absolute bottom-8 left-1/2 -translate-x-1/2"
      >
        <motion.div
          animate={{ y: [0, 10, 0] }}
          transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
          className="flex flex-col items-center gap-2"
        >
          <span className="text-xs text-white/30" style={{ fontFamily: "var(--font-mono)" }}>
            SCROLL TO EXPLORE
          </span>
          <svg
            width="20"
            height="20"
            viewBox="0 0 20 20"
            fill="none"
            className="text-[#00F0FF]/50"
          >
            <path
              d="M10 4V16M10 16L5 11M10 16L15 11"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </motion.div>
      </motion.div>
    </section>
  );
}
