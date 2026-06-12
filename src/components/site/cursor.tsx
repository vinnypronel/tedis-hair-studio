"use client";

import { useEffect, useRef } from "react";

/**
 * Custom dot cursor. Desktop pointer devices only. An 8px ring that grows
 * to 32px over interactive elements. Disabled for touch and reduced motion.
 */
export function Cursor() {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const fine = window.matchMedia("(pointer: fine)").matches;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!fine || reduced) return;

    const el = ref.current;
    if (!el) return;
    el.style.opacity = "0";

    let raf = 0;
    let x = 0;
    let y = 0;

    const move = (e: MouseEvent) => {
      x = e.clientX;
      y = e.clientY;
      el.style.opacity = "1";
      const target = e.target as HTMLElement;
      const interactive = target.closest(
        "a, button, input, textarea, select, [role='button'], label"
      );
      el.classList.toggle("is-active", Boolean(interactive));
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        el.style.transform = `translate(${x}px, ${y}px) translate(-50%, -50%)`;
      });
    };

    const leave = () => {
      el.style.opacity = "0";
    };

    window.addEventListener("mousemove", move, { passive: true });
    document.documentElement.addEventListener("mouseleave", leave);
    return () => {
      window.removeEventListener("mousemove", move);
      document.documentElement.removeEventListener("mouseleave", leave);
      cancelAnimationFrame(raf);
    };
  }, []);

  return <div ref={ref} className="cursor-dot hidden md:block" aria-hidden />;
}
