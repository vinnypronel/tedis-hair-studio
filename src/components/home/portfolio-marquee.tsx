"use client";

import Image from "next/image";
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Reveal } from "@/components/site/reveal";
import { ArrowLink } from "@/components/ui/arrow-link";
import { InViewVideo } from "@/components/site/in-view-video";
import { marqueeImages } from "@/lib/data/gallery";

/**
 * Auto-advancing gallery strip that is also a real horizontal scroll area, so
 * on touch devices the user can swipe through it. Auto-scroll pauses while the
 * user is interacting (and while the lightbox is open) and resumes a moment
 * after. Images are doubled so the loop wraps seamlessly. Tapping an item opens
 * a full-screen lightbox of that photo/video.
 */
export function PortfolioMarquee() {
  const doubled = [...marqueeImages, ...marqueeImages];
  const scrollRef = useRef<HTMLDivElement>(null);
  const resumeAt = useRef(0);
  const pausedRef = useRef(false);
  const suppressClickRef = useRef(false);
  const [active, setActive] = useState<number | null>(null);
  const [mounted, setMounted] = useState(false);

  // The lightbox renders into document.body (a portal) so it is never trapped
  // inside a sticky stacked-scroll card's stacking context on mobile.
  useEffect(() => setMounted(true), []);

  // Keep the animation loop aware of the lightbox without re-running the effect.
  useEffect(() => {
    pausedRef.current = active !== null;
  }, [active]);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    const SPEED = window.innerWidth < 640 ? 95 : 60; // px per second (faster on mobile)
    const SWIPE_SETTLE_MS = 1400; // after a swipe/fling, wait for scroll to go idle before resuming
    let last = performance.now();
    let raf = 0;
    let inView = true;
    let expectedLeft = -1; // the scrollLeft OUR loop last set, to tell our scroll from the user's

    const tick = (now: number) => {
      // Cap dt so a stall (background tab, long frame) can never produce a huge
      // jump that looks like a freeze when the loop resumes.
      const dt = Math.min(now - last, 50);
      last = now;
      const half = el.scrollWidth / 2;
      if (inView && !pausedRef.current && half > 0 && now >= resumeAt.current) {
        let next = el.scrollLeft + (SPEED * dt) / 1000;
        if (next >= half) next -= half; // seamless wrap
        el.scrollLeft = next;
        expectedLeft = el.scrollLeft; // read back (browser may round/clamp)
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);

    const io = new IntersectionObserver(
      ([entry]) => {
        inView = entry.isIntersecting;
        last = performance.now();
      },
      { threshold: 0 }
    );
    io.observe(el);

    // Any scroll the loop did NOT cause (a finger drag or its native momentum
    // fling) defers auto-scroll. While the fling is still decelerating it keeps
    // firing scroll events, so the strip keeps coasting and only eases back into
    // the normal carousel speed once it has settled, never snapping to a stop.
    const onScroll = () => {
      // Our own auto-advance lands at expectedLeft; ignore those. A finger drag
      // or its momentum moves the strip somewhere else, which defers auto-scroll.
      if (expectedLeft >= 0 && Math.abs(el.scrollLeft - expectedLeft) < 2) return;
      if (resumeAt.current !== Number.POSITIVE_INFINITY) {
        resumeAt.current = performance.now() + SWIPE_SETTLE_MS;
      }
    };
    el.addEventListener("scroll", onScroll, { passive: true });

    // Mouse and wheel input pause briefly.
    const hold = () => {
      resumeAt.current = performance.now() + 2500;
    };
    let longPressTimer: number | null = null;
    let longPressFrozen = false;
    let pressStartX = 0;
    let pressStartY = 0;

    const clearLongPressTimer = () => {
      if (longPressTimer !== null) {
        window.clearTimeout(longPressTimer);
        longPressTimer = null;
      }
    };

    const onPointerDown = (event: PointerEvent) => {
      if (event.pointerType !== "touch") {
        hold();
        return;
      }

      suppressClickRef.current = false;
      pressStartX = event.clientX;
      pressStartY = event.clientY;
      clearLongPressTimer();
      longPressTimer = window.setTimeout(() => {
        longPressFrozen = true;
        suppressClickRef.current = true;
        resumeAt.current = Number.POSITIVE_INFINITY;
      }, 1000);
    };

    const onPointerMove = (event: PointerEvent) => {
      if (
        event.pointerType === "touch" &&
        (Math.abs(event.clientX - pressStartX) > 10 ||
          Math.abs(event.clientY - pressStartY) > 10)
      ) {
        clearLongPressTimer();
        suppressClickRef.current = true; // a swipe, not a tap — don't open the lightbox
      }
    };

    const finishTouchPress = (event: PointerEvent) => {
      if (event.pointerType !== "touch") return;
      clearLongPressTimer();
      if (longPressFrozen) {
        longPressFrozen = false;
        resumeAt.current = performance.now() + 400;
      } else {
        // Let the fling's momentum run; onScroll keeps pushing this out while
        // the strip is still coasting, so we only resume once it has settled.
        resumeAt.current = performance.now() + SWIPE_SETTLE_MS;
      }
    };

    const preventLongPressMenu = (event: MouseEvent) => {
      if (suppressClickRef.current) event.preventDefault();
    };

    el.addEventListener("pointerdown", onPointerDown);
    el.addEventListener("pointermove", onPointerMove);
    el.addEventListener("pointerup", finishTouchPress);
    el.addEventListener("pointercancel", finishTouchPress);
    el.addEventListener("contextmenu", preventLongPressMenu);
    el.addEventListener("wheel", hold, { passive: true });

    return () => {
      cancelAnimationFrame(raf);
      io.disconnect();
      clearLongPressTimer();
      el.removeEventListener("scroll", onScroll);
      el.removeEventListener("pointerdown", onPointerDown);
      el.removeEventListener("pointermove", onPointerMove);
      el.removeEventListener("pointerup", finishTouchPress);
      el.removeEventListener("pointercancel", finishTouchPress);
      el.removeEventListener("contextmenu", preventLongPressMenu);
      el.removeEventListener("wheel", hold);
    };
  }, []);

  // Lightbox: lock page scroll and close on Escape while open.
  useEffect(() => {
    if (active === null) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setActive(null);
    document.addEventListener("keydown", onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [active]);

  const activeItem = active === null ? null : marqueeImages[active];

  return (
    <section id="the-work" className="bg-bone overflow-hidden pt-14 pb-8 md:pt-0 md:pb-24 lg:pb-36">
      <Reveal className="px-6 md:px-12 lg:px-20">
        <div className="mx-auto max-w-[1440px]">
          <p className="eyebrow !text-[15px] !tracking-[0.2em] text-stone-500 sm:!text-[11px] sm:!tracking-[0.18em]">02 · My Work</p>
        </div>
      </Reveal>

      <div
        ref={scrollRef}
        className="no-scrollbar mt-8 overflow-x-auto overscroll-x-contain [touch-action:pan-x_pan-y]"
      >
        <div className="flex w-max gap-4">
          {doubled.map((img, i) => {
            const realIndex = i % marqueeImages.length;
            const isClone = i >= marqueeImages.length;
            return (
              <button
                type="button"
                key={`${img.id}-${i}`}
                onClick={() => {
                  if (suppressClickRef.current) {
                    suppressClickRef.current = false;
                    return;
                  }
                  setActive(realIndex);
                }}
                tabIndex={isClone ? -1 : 0}
                aria-hidden={isClone}
                aria-label={isClone ? undefined : `View larger: ${img.alt}`}
                className="hairline group relative block h-[300px] w-[240px] shrink-0 cursor-pointer overflow-hidden select-none [-webkit-touch-callout:none] sm:h-[400px] sm:w-[320px]"
              >
                {img.type === "video" ? (
                  <InViewVideo
                    src={img.url}
                    poster={img.poster}
                    preload={isClone ? "none" : "metadata"}
                    className="h-full w-full object-cover transition-transform duration-500 group-hover:scale-[1.03]"
                  />
                ) : (
                  <Image
                    src={img.url}
                    alt={isClone ? "" : img.alt}
                    fill
                    sizes="(min-width: 640px) 320px, 240px"
                    className="object-cover transition-transform duration-500 group-hover:scale-[1.03]"
                  />
                )}
              </button>
            );
          })}
        </div>
      </div>

      <Reveal className="mt-6 px-6 md:px-12 lg:px-20">
        <div className="mx-auto flex max-w-[1440px] justify-end">
          <ArrowLink href="/gallery">Full gallery</ArrowLink>
        </div>
      </Reveal>

      {/* Full-screen lightbox — portaled to body so it sits above everything */}
      {mounted && activeItem && createPortal(
        <div
          role="dialog"
          aria-modal="true"
          aria-label={activeItem.alt}
          onClick={() => setActive(null)}
          className="fixed inset-0 z-[9990] flex items-center justify-center bg-ink/95 p-4 backdrop-blur-sm"
        >
          <button
            type="button"
            aria-label="Close"
            onClick={() => setActive(null)}
            className="absolute top-5 right-5 z-10 flex size-11 items-center justify-center rounded-full border border-cream/30 text-2xl leading-none text-cream transition-colors hover:bg-cream hover:text-ink"
          >
            &times;
          </button>
          <div className="relative flex max-h-[88vh] max-w-[92vw] items-center justify-center" onClick={(e) => e.stopPropagation()}>
            {activeItem.type === "video" ? (
              <video
                src={activeItem.url}
                poster={activeItem.poster}
                controls
                autoPlay
                loop
                playsInline
                className="max-h-[88vh] max-w-[92vw] rounded-[2px]"
              />
            ) : (
              /* eslint-disable-next-line @next/next/no-img-element */
              <img
                src={activeItem.url}
                alt={activeItem.alt}
                className="max-h-[88vh] max-w-[92vw] rounded-[2px] object-contain"
              />
            )}
          </div>
        </div>,
        document.body
      )}
    </section>
  );
}
