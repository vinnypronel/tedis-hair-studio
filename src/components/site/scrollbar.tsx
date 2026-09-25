"use client";

import { useEffect, useRef } from "react";

export function Scrollbar() {
  const thumbRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const thumb = thumbRef.current;
    if (!thumb) return;

    let hideTimer: ReturnType<typeof setTimeout>;
    let drag: { y: number; scroll: number } | null = null;
    const metrics = () => {
      const viewport = document.documentElement.clientHeight;
      const height = document.documentElement.scrollHeight;
      const track = Math.max(0, viewport - 8);
      const size = Math.min(track, Math.max(36, (viewport / height) * track));
      return { size, travel: track - size, max: Math.max(0, height - viewport) };
    };
    const update = () => {
      const { size, travel, max } = metrics();
      const progress = max ? Math.max(0, Math.min(1, window.scrollY / max)) : 0;
      thumb.style.height = `${size}px`;
      thumb.style.transform = `translateY(${4 + progress * travel}px)`;
      thumb.hidden = max === 0;
      thumb.setAttribute("aria-valuenow", String(Math.round(progress * 100)));
    };
    const reveal = () => {
      update();
      thumb.dataset.visible = "true";
      clearTimeout(hideTimer);
      hideTimer = setTimeout(() => {
        if (!drag) thumb.dataset.visible = "false";
      }, 2500);
    };
    const scrollTo = (top: number) => {
      // Instant movement also works alongside the site's smooth wheel scrolling.
      window.scrollTo({ top, behavior: "instant" });
    };
    const down = (event: PointerEvent) => {
      if (event.button !== 0) return;
      drag = { y: event.clientY, scroll: window.scrollY };
      thumb.setPointerCapture(event.pointerId);
      reveal();
      event.preventDefault();
    };
    const move = (event: PointerEvent) => {
      if (!drag) return;
      const { travel, max } = metrics();
      if (travel > 0) scrollTo(drag.scroll + ((event.clientY - drag.y) / travel) * max);
    };
    const up = () => {
      drag = null;
      reveal();
    };
    const keydown = (event: KeyboardEvent) => {
      const targets: Record<string, number> = {
        ArrowDown: window.scrollY + 40,
        ArrowUp: window.scrollY - 40,
        PageDown: window.scrollY + window.innerHeight,
        PageUp: window.scrollY - window.innerHeight,
        Home: 0,
        End: metrics().max,
      };
      if (!(event.key in targets)) return;
      event.preventDefault();
      scrollTo(targets[event.key]);
      reveal();
    };

    document.documentElement.classList.add("overlay-scrollbar");
    update();
    const observer = new ResizeObserver(update);
    observer.observe(document.body);
    window.addEventListener("scroll", reveal, { passive: true });
    window.addEventListener("resize", update);
    thumb.addEventListener("pointerdown", down);
    thumb.addEventListener("pointermove", move);
    thumb.addEventListener("lostpointercapture", up);
    thumb.addEventListener("keydown", keydown);
    return () => {
      clearTimeout(hideTimer);
      observer.disconnect();
      document.documentElement.classList.remove("overlay-scrollbar");
      window.removeEventListener("scroll", reveal);
      window.removeEventListener("resize", update);
      thumb.removeEventListener("pointerdown", down);
      thumb.removeEventListener("pointermove", move);
      thumb.removeEventListener("lostpointercapture", up);
      thumb.removeEventListener("keydown", keydown);
    };
  }, []);

  return (
    <div
      ref={thumbRef}
      className="page-scrollbar"
      role="scrollbar"
      aria-label="Page scroll"
      aria-controls="main-content"
      aria-orientation="vertical"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={0}
      tabIndex={0}
    />
  );
}
