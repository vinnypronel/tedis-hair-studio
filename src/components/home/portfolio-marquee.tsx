"use client";

import Image from "next/image";
import Link from "next/link";
import { useEffect, useRef } from "react";
import { Reveal } from "@/components/site/reveal";
import { InViewVideo } from "@/components/site/in-view-video";
import { marqueeImages } from "@/lib/data/gallery";

/**
 * Auto-advancing gallery strip that is also a real horizontal scroll area, so
 * on touch devices the user can swipe through it. Auto-scroll pauses while the
 * user is interacting and resumes a moment after they stop. Images are doubled
 * so the loop wraps seamlessly (position x and x - half show identical content).
 */
export function PortfolioMarquee() {
  const doubled = [...marqueeImages, ...marqueeImages];
  const scrollRef = useRef<HTMLDivElement>(null);
  const resumeAt = useRef(0);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    const SPEED = 60; // px per second
    let last = performance.now();
    let raf = 0;

    const tick = (now: number) => {
      const dt = now - last;
      last = now;
      const half = el.scrollWidth / 2;
      if (half > 0 && now >= resumeAt.current) {
        let next = el.scrollLeft + (SPEED * dt) / 1000;
        if (next >= half) next -= half; // seamless wrap
        el.scrollLeft = next;
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);

    // Pause auto-scroll briefly whenever the user drives it.
    const hold = () => {
      resumeAt.current = performance.now() + 2500;
    };
    el.addEventListener("pointerdown", hold);
    el.addEventListener("touchstart", hold, { passive: true });
    el.addEventListener("touchmove", hold, { passive: true });
    el.addEventListener("wheel", hold, { passive: true });

    return () => {
      cancelAnimationFrame(raf);
      el.removeEventListener("pointerdown", hold);
      el.removeEventListener("touchstart", hold);
      el.removeEventListener("touchmove", hold);
      el.removeEventListener("wheel", hold);
    };
  }, []);

  return (
    <section id="the-work" className="overflow-hidden pb-24 lg:pb-36">
      <Reveal className="px-6 md:px-12 lg:px-20">
        <div className="mx-auto flex max-w-[1440px] items-baseline justify-between">
          <p className="eyebrow text-stone-500">The work, in motion</p>
          <Link href="/gallery" className="link-draw text-sm font-medium">
            Full gallery →
          </Link>
        </div>
      </Reveal>
      <div
        ref={scrollRef}
        className="no-scrollbar mt-10 overflow-x-auto overscroll-x-contain [touch-action:pan-x]"
      >
        <div className="flex w-max gap-4">
          {doubled.map((img, i) => (
            <Link
              key={`${img.id}-${i}`}
              href="/gallery"
              className="hairline relative block h-[400px] w-[320px] shrink-0 overflow-hidden"
              tabIndex={i >= marqueeImages.length ? -1 : 0}
              aria-hidden={i >= marqueeImages.length}
              aria-label={i < marqueeImages.length ? `View gallery: ${img.alt}` : undefined}
            >
              {img.type === "video" ? (
                <InViewVideo
                  src={img.url}
                  preload={i >= marqueeImages.length ? "none" : "metadata"}
                  className="h-full w-full object-cover transition-transform duration-500 hover:scale-[1.03]"
                />
              ) : (
                <Image
                  src={img.url}
                  alt={i >= marqueeImages.length ? "" : img.alt}
                  fill
                  sizes="320px"
                  className="object-cover transition-transform duration-500 hover:scale-[1.03]"
                />
              )}
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}
