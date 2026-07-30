"use client";

import { useEffect, useRef } from "react";
import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";

if (typeof window !== "undefined") {
  gsap.registerPlugin(ScrollTrigger);
}

export function useGsapContext<T extends HTMLElement = HTMLDivElement>() {
  const ref = useRef<T>(null);

  useEffect(() => {
    return () => {
      ScrollTrigger.getAll().forEach((trigger) => trigger.kill());
    };
  }, []);

  return { ref, gsap, ScrollTrigger };
}

export function animateTextScramble(
  element: HTMLElement,
  targetText: string,
  duration: number = 0.8
) {
  const chars = "!<>-_\\/[]{}—=+*^?#________";
  const length = targetText.length;

  return gsap.to(
    {},
    {
      duration,
      onUpdate: function () {
        const progress = this.progress();
        let result = "";
        for (let i = 0; i < length; i++) {
          if (i < length * progress) {
            result += targetText[i];
          } else {
            result += chars[Math.floor(Math.random() * chars.length)];
          }
        }
        element.textContent = result;
      },
    }
  );
}

export { gsap, ScrollTrigger };
