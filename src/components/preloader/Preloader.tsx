"use client";

import { useEffect, useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { gsap } from "gsap";

export default function Preloader() {
  const [progress, setProgress] = useState(0);
  const [isComplete, setIsComplete] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const textRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const tl = gsap.timeline({
      onComplete: () => setIsComplete(true),
    });

    tl.to(
      {},
      {
        duration: 2.5,
        onUpdate: function () {
          setProgress(Math.floor(this.progress() * 100));
        },
      }
    );

    tl.to(containerRef.current, {
      opacity: 0,
      duration: 0.5,
      ease: "power2.inOut",
    });

    return () => {
      tl.kill();
    };
  }, []);

  if (isComplete) return null;

  return (
    <AnimatePresence>
      {!isComplete && (
        <motion.div
          ref={containerRef}
          initial={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-[9999] flex flex-col items-center justify-center bg-[#050505]"
        >
          <div className="relative">
            <motion.div
              ref={textRef}
              className="text-6xl md:text-8xl font-bold tracking-tighter"
              style={{ fontFamily: "var(--font-heading)" }}
            >
              <span className="text-gradient-cyan">{progress}</span>
              <span className="text-[#00F0FF]/50">%</span>
            </motion.div>

            <motion.div
              className="mt-4 text-sm tracking-[0.3em] uppercase text-[#00F0FF]/60"
              style={{ fontFamily: "var(--font-mono)" }}
            >
              Decrypting Assets...
            </motion.div>

            <motion.div className="mt-8 w-64 h-[1px] bg-white/10">
              <motion.div
                className="h-full bg-gradient-to-r from-[#00F0FF] to-[#00FF66]"
                style={{ width: `${progress}%` }}
                transition={{ duration: 0.1 }}
              />
            </motion.div>

            <div className="mt-6 flex gap-4 text-xs text-white/30" style={{ fontFamily: "var(--font-mono)" }}>
              <span>SYS.INIT</span>
              <span>·</span>
              <span>LOADING MODULES</span>
              <span>·</span>
              <span>{progress < 30 ? "VERIFYING" : progress < 70 ? "DECRYPTING" : "FINALIZING"}</span>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
