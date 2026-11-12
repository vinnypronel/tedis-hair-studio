"use client";

import { useEffect } from "react";
import { usePathname } from "next/navigation";

/**
 * Stacked section scroll.
 * Turns the direct children of the stack root into cards that pin when their
 * bottom reaches the screen bottom while the next card slides over them. Runs
 * at every screen size (the CSS only changes corner radius and shadow per
 * breakpoint). Pages whose sections are not direct children of the root
 * (wrapped in a single div) simply have one card and stay unaffected.
 */
function isCard(el: Element): el is HTMLElement {
  if (!(el instanceof HTMLElement) || el.hasAttribute("data-stack-skip")) return false;
  const style = getComputedStyle(el);
  if (style.display === "none" || style.position === "fixed" || style.position === "absolute") return false;
  if (el.matches("header, [data-site-header]")) return false;
  return el.offsetHeight > 0;
}

export function StackSections() {
  const pathname = usePathname();

  useEffect(() => {
    // Sections live inside the page-transition wrapper ([data-stack-root]),
    // not directly in <main>, so prefer that; fall back to <main>.
    const root =
      document.querySelector<HTMLElement>("[data-stack-root]") ??
      document.querySelector("main");
    if (!root) return;
    let cards: HTMLElement[] = [];
    let observer: ResizeObserver | null = null;
    let frame = 0;

    const updateCorners = () => {
      frame = 0;
      if (!window.matchMedia("(min-width: 1024px)").matches) return;
      const header = parseFloat(getComputedStyle(root).getPropertyValue("--stack-header-h")) || 80;
      for (let index = 1; index < cards.length; index++) {
        const card = cards[index];
        const distance = card.getBoundingClientRect().top - header;
        const progress = Math.max(0, Math.min(1, distance / 96));
        card.style.setProperty("--stack-corner-progress", String(progress));
      }
    };
    const queueCorners = () => {
      if (!frame) frame = requestAnimationFrame(updateCorners);
    };

    const measure = (targets: HTMLElement[]) => {
      for (const card of targets) {
        card.style.setProperty("--stack-card-h", `${Math.ceil(card.offsetHeight)}px`);
      }
    };
    const stop = () => {
      cancelAnimationFrame(frame);
      frame = 0;
      observer?.disconnect();
      observer = null;
      for (const card of cards) {
        card.classList.remove("stack-card", "stack-card-first", "stack-card-last");
        card.style.removeProperty("--stack-card-h");
        card.style.removeProperty("--stack-corner-progress");
        card.style.removeProperty("z-index");
      }
      cards = [];
      root.classList.remove("stack-root");
    };
    const start = () => {
      stop();
      if (root.getAttribute("data-stack") === "off") return;
      cards = Array.from(root.children).filter(isCard);
      if (cards.length < 2) {
        cards = [];
        return;
      }
      root.classList.add("stack-root");
      cards.forEach((card, index) => {
        card.classList.add("stack-card");
        if (index === 0) card.classList.add("stack-card-first");
        if (index === cards.length - 1) card.classList.add("stack-card-last");
        card.style.zIndex = String(index + 1);
      });
      measure(cards);
      observer = new ResizeObserver((entries) => {
        measure(entries.map((entry) => entry.target as HTMLElement));
        queueCorners();
      });
      cards.forEach((card) => observer?.observe(card));
      queueCorners();
    };

    start();
    const sections = new MutationObserver(() => requestAnimationFrame(start));
    sections.observe(root, { childList: true });

    // Re-scan on resize/orientation change so card set and z-index stay correct
    // across breakpoints (heights are kept live by the ResizeObserver above).
    let queued = false;
    const onResize = () => {
      if (queued) return;
      queued = true;
      requestAnimationFrame(() => {
        queued = false;
        start();
      });
    };
    window.addEventListener("resize", onResize);
    window.addEventListener("scroll", queueCorners, { passive: true });
    return () => {
      window.removeEventListener("resize", onResize);
      window.removeEventListener("scroll", queueCorners);
      sections.disconnect();
      stop();
    };
  }, [pathname]);

  return null;
}
