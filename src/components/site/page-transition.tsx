"use client";

import { motion, useReducedMotion } from "motion/react";
import { BearLogo } from "@/components/site/bear-logo";
import type { ReactNode } from "react";

/**
 * Page transition: a forest slab sweeps up revealing the page, the bear
 * flashes center for a beat. Rendered from app/template.tsx so it replays
 * on every route change. Reduced motion → instant fade.
 */
export function PageTransition({ children }: { children: ReactNode }) {
  const reduced = useReducedMotion();

  if (reduced) {
    return (
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.2 }}>
        {children}
      </motion.div>
    );
  }

  return (
    <>
      <motion.div
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.55, delay: 0.35, ease: [0.22, 1, 0.36, 1] }}
      >
        {children}
      </motion.div>

      {/* forest slab sweep */}
      <motion.div
        aria-hidden
        className="pointer-events-none fixed inset-0 z-[80] flex items-center justify-center bg-forest"
        initial={{ y: 0 }}
        animate={{ y: "-100%" }}
        transition={{ duration: 0.45, delay: 0.15, ease: [0.76, 0, 0.24, 1] }}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.92 }}
          animate={{ opacity: [0, 1, 1, 0], scale: 1 }}
          transition={{ duration: 0.38, times: [0, 0.25, 0.75, 1] }}
          className="text-cream"
        >
          <BearLogo size={340} className="text-cream" label="" />
        </motion.div>
      </motion.div>
    </>
  );
}
