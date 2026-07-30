"use client";

import { useRef, useState } from "react";
import { motion, useMotionValue, useSpring, useTransform } from "framer-motion";
import { cn } from "@/lib/utils";

interface GlassCardProps {
  children: React.ReactNode;
  className?: string;
  hover3D?: boolean;
  glowColor?: string;
}

export default function GlassCard({
  children,
  className,
  hover3D = true,
  glowColor = "#00F0FF",
}: GlassCardProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [isHovered, setIsHovered] = useState(false);

  const x = useMotionValue(0);
  const y = useMotionValue(0);

  const rotateX = useSpring(useTransform(y, [-0.5, 0.5], [5, -5]), {
    stiffness: 150,
    damping: 20,
  });
  const rotateY = useSpring(useTransform(x, [-0.5, 0.5], [-5, 5]), {
    stiffness: 150,
    damping: 20,
  });

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!ref.current || !hover3D) return;
    const rect = ref.current.getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;
    x.set((e.clientX - centerX) / rect.width);
    y.set((e.clientY - centerY) / rect.height);
  };

  const handleMouseLeave = () => {
    x.set(0);
    y.set(0);
    setIsHovered(false);
  };

  return (
    <motion.div
      ref={ref}
      onMouseMove={handleMouseMove}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={handleMouseLeave}
      style={{
        rotateX: hover3D ? rotateX : 0,
        rotateY: hover3D ? rotateY : 0,
        transformStyle: "preserve-3d",
      }}
      className={cn(
        "glass rounded-2xl p-6 transition-all duration-300",
        isHovered && "glass-strong",
        className
      )}
    >
      {isHovered && (
        <div
          className="absolute inset-0 rounded-2xl transition-opacity duration-300 pointer-events-none opacity-100"
          style={{
            boxShadow: `0 0 30px ${glowColor}20, inset 0 0 30px ${glowColor}05`,
          }}
        />
      )}
      {children}
    </motion.div>
  );
}
