"use client";

import Image from "next/image";
import Link from "next/link";
import { motion, useReducedMotion, useScroll, useTransform } from "motion/react";
import { BookLink } from "@/components/site/book-link";
import { LiveClock } from "@/components/site/live-clock";
import { content } from "@/lib/data/content";

export function Hero() {
  const reduced = useReducedMotion();
  const { scrollY } = useScroll();
  const parallaxY = useTransform(scrollY, [0, 800], [0, -40]);

  return (
    <section className="relative flex min-h-svh flex-col justify-end overflow-hidden bg-forest-deep text-cream">
      {/* Background image + forest overlay */}
      <motion.div
        className="absolute -inset-y-16 inset-x-0 will-change-transform"
        style={reduced ? undefined : { y: parallaxY, scale: 1.04 }}
      >
        {/* Mobile: chair.jpg (portrait) */}
        <Image
          src="/professional-images/chair.jpg"
          alt="The chair at Tedi's Hair Studio, draped in the green cape with the bear mark"
          fill
          priority
          quality={90}
          sizes="100vw"
          className="object-cover lg:hidden"
        />
        {/* Desktop: backgroundmaybe.jpg (landscape) */}
        <Image
          src="/professional-images/backgroundmaybe.jpeg"
          alt="Tedi's Hair Studio, the full studio view"
          fill
          priority
          quality={90}
          sizes="100vw"
          className="hidden object-cover lg:block"
        />
        <div className="absolute inset-0 bg-forest-deep/45" />
        <div className="absolute inset-0 bg-black/25" />
        <div className="absolute inset-0 bg-gradient-to-t from-forest-deep/85 via-forest-deep/20 to-forest-deep/45" />
      </motion.div>

      {/* Eyebrow */}
      <div className="pointer-events-none absolute inset-x-0 top-20 z-10 mx-auto max-w-[1440px] px-6 md:top-24 md:px-12 lg:px-20">
        <motion.p
          initial={reduced ? false : { opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7, duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
          className="eyebrow text-cream/80"
        >
          {content.hero.eyebrow}
        </motion.p>
      </div>

      {/* Headline block */}
      <div className="relative z-10 mx-auto w-full max-w-[1440px] px-6 pb-28 md:px-12 lg:px-20 lg:pb-32">
        <motion.h1
          initial={reduced ? false : { opacity: 0, y: 28 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.85, duration: 0.9, ease: [0.22, 1, 0.36, 1] }}
          className="display-xl max-w-5xl"
        >
          Personal <br className="sm:hidden" />private <em className="italic">cuts.</em>
        </motion.h1>

        <motion.p
          initial={reduced ? false : { opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 1.05, duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
          className="mt-6 max-w-md text-sm leading-relaxed text-cream/85"
        >
          {content.hero.sub}
        </motion.p>

        <motion.div
          initial={reduced ? false : { opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 1.2, duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
          className="mt-10 flex flex-wrap items-center gap-6"
        >
          <BookLink className="group inline-flex items-center gap-3 rounded-[2px] bg-cream px-9 py-4 text-base font-medium text-forest-deep transition-colors duration-300 hover:bg-stone-300 focus-visible:bg-stone-300">
            {content.hero.ctaPrimary}
            <span aria-hidden className="transition-transform duration-300 group-hover:translate-x-1">
              →
            </span>
          </BookLink>
          <Link
            href="/gallery"
            className="text-sm text-cream/90 underline underline-offset-4 decoration-cream/50 transition-colors hover:decoration-cream"
          >
            {content.hero.ctaSecondary}
          </Link>
        </motion.div>
      </div>

      {/* Bottom rail: live clock */}
      <div className="pointer-events-none absolute inset-x-0 bottom-6 z-10 mx-auto max-w-[1440px] px-6 md:px-12 lg:px-20">
        <motion.div
          initial={reduced ? false : { opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.5, duration: 1 }}
          className="pointer-events-auto flex items-end justify-end"
        >
          <LiveClock tone="cream" />
        </motion.div>
      </div>
    </section>
  );
}

