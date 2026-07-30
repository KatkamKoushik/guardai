"use client";

import { useRef, useState } from "react";
import { motion, useMotionValue, useSpring, useTransform } from "framer-motion";
import { cn } from "@/lib/utils";

interface MagneticButtonProps {
  children: React.ReactNode;
  onClick?: () => void;
  type?: "button" | "submit" | "reset";
  disabled?: boolean;
  className?: string;
  variant?: "primary" | "secondary" | "ghost";
  size?: "sm" | "md" | "lg";
}

export default function MagneticButton({
  children,
  onClick,
  type = "button",
  disabled = false,
  className,
  variant = "primary",
  size = "md",
}: MagneticButtonProps) {
  const ref = useRef<HTMLButtonElement>(null);
  const [isHovered, setIsHovered] = useState(false);

  const x = useMotionValue(0);
  const y = useMotionValue(0);

  const springX = useSpring(x, { stiffness: 150, damping: 15 });
  const springY = useSpring(y, { stiffness: 150, damping: 15 });

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!ref.current) return;
    const rect = ref.current.getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;
    x.set((e.clientX - centerX) * 0.3);
    y.set((e.clientY - centerY) * 0.3);
  };

  const handleMouseLeave = () => {
    x.set(0);
    y.set(0);
    setIsHovered(false);
  };

  const variants = {
    primary:
      "bg-[#00F0FF]/10 border border-[#00F0FF]/30 text-[#00F0FF] hover:bg-[#00F0FF]/20 hover:border-[#00F0FF]/50",
    secondary:
      "bg-white/5 border border-white/10 text-white/80 hover:bg-white/10 hover:border-white/20",
    ghost: "bg-transparent border border-transparent text-white/60 hover:text-white hover:bg-white/5",
  };

  const sizes = {
    sm: "px-4 py-2 text-xs",
    md: "px-6 py-3 text-sm",
    lg: "px-8 py-4 text-base",
  };

  return (
    <motion.button
      ref={ref}
      type={type}
      onClick={onClick}
      onMouseMove={handleMouseMove}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={handleMouseLeave}
      disabled={disabled}
      style={{ x: springX, y: springY }}
      className={cn(
        "relative overflow-hidden rounded-lg font-medium transition-all duration-300",
        "backdrop-blur-sm",
        variants[variant],
        sizes[size],
        className
      )}
      whileTap={{ scale: 0.97 }}
    >
      <motion.span
        className="absolute inset-0 bg-gradient-to-r from-[#00F0FF]/0 via-[#00F0FF]/10 to-[#00F0FF]/0"
        initial={{ x: "-100%" }}
        animate={{ x: isHovered ? "100%" : "-100%" }}
        transition={{ duration: 0.6, ease: "easeInOut" }}
      />
      <span className="relative z-10">{children}</span>
    </motion.button>
  );
}
