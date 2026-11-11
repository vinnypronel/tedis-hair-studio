"use client";

import { motion, useReducedMotion } from "motion/react";
import { BearLogo } from "@/components/site/bear-logo";
import { Footer } from "@/components/site/footer";
import type { ReactNode } from "react";

/**
 * Page transition: a forest slab sweeps up revealing the page, the bear
 * flashes center for a beat. Rendered from app/template.tsx so it replays
 * on every route change. Reduced motion: instant slab removal, short fade.
 * The element tree is identical in both modes so server and client HTML match.
 */
export function PageTransition({ children }: { children: ReactNode }) {
  const reduced = useReducedMotion();

  return (
    <>
      <motion.div
        data-stack-root
        className="intro-failsafe-show"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={
          reduced
            ? { duration: 0.2 }
            : { duration: 0.55, delay: 0.35, ease: [0.22, 1, 0.36, 1] }
        }
      >
        {children}
        <Footer />
      </motion.div>

      {/* forest slab sweep */}
      <motion.div
        aria-hidden
        className="intro-failsafe-hide pointer-events-none fixed inset-0 z-[80] flex items-center justify-center bg-forest"
        initial={{ y: 0 }}
        animate={{ y: "-100%" }}
        transition={reduced ? { duration: 0 } : { duration: 0.45, delay: 0.15, ease: [0.76, 0, 0.24, 1] }}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.92 }}
          animate={{ opacity: [0, 1, 1, 0], scale: 1 }}
          transition={reduced ? { duration: 0 } : { duration: 0.38, times: [0, 0.25, 0.75, 1] }}
          className="text-cream"
        >
          <BearLogo size={340} className="text-cream" label="" />
        </motion.div>
      </motion.div>
    </>
  );
}
