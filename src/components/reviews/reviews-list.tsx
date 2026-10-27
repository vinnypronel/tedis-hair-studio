"use client";

import { useEffect, useMemo, useState } from "react";
import { RevealGroup, RevealItem } from "@/components/site/reveal";
import type { Review } from "@/lib/data/reviews";
import { content } from "@/lib/data/content";

const MOBILE_PAGE_SIZE = 10;
const DESKTOP_PAGE_SIZE = 30;

type ReviewsListProps = {
  reviews: Review[];
  platform: string;
};

export function ReviewsList({ reviews, platform }: ReviewsListProps) {
  const [pageSize, setPageSize] = useState(MOBILE_PAGE_SIZE);
  const [page, setPage] = useState(1);

  useEffect(() => {
    const media = window.matchMedia("(min-width: 1024px)");

    const syncPageSize = () => {
      const nextPageSize = media.matches ? DESKTOP_PAGE_SIZE : MOBILE_PAGE_SIZE;
      setPageSize((currentPageSize) => {
        if (currentPageSize !== nextPageSize) {
          setPage((currentPage) =>
            Math.floor(((currentPage - 1) * currentPageSize) / nextPageSize) + 1
          );
        }
        return nextPageSize;
      });
    };

    syncPageSize();
    media.addEventListener("change", syncPageSize);
    return () => media.removeEventListener("change", syncPageSize);
  }, []);

  const pageCount = Math.ceil(reviews.length / pageSize);
  const safePage = Math.min(page, pageCount);
  const visibleReviews = useMemo(
    () => reviews.slice((safePage - 1) * pageSize, safePage * pageSize),
    [reviews, safePage, pageSize]
  );

  const goToPage = (nextPage: number) => {
    setPage(nextPage);
    window.requestAnimationFrame(() => {
      document.getElementById("review-list")?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  };

  // Compact, windowed page list: 1 … around-current … last.
  const pageItems = useMemo<(number | "ellipsis")[]>(() => {
    if (pageCount <= 7) {
      return Array.from({ length: pageCount }, (_, i) => i + 1);
    }
    const set = new Set<number>([1, pageCount]);
    if (safePage <= 3) [2, 3].forEach((n) => set.add(n));
    else if (safePage >= pageCount - 2)
      [pageCount - 2, pageCount - 1].forEach((n) => set.add(n));
    else [safePage - 1, safePage, safePage + 1].forEach((n) => set.add(n));
    const sorted = [...set].filter((n) => n >= 1 && n <= pageCount).sort((a, b) => a - b);
    const out: (number | "ellipsis")[] = [];
    let prev = 0;
    for (const n of sorted) {
      if (prev && n - prev > 1) out.push("ellipsis");
      out.push(n);
      prev = n;
    }
    return out;
  }, [pageCount, safePage]);

  return (
    <>
      <div id="review-list" className="scroll-mt-28">
        <RevealGroup
          className="mt-14 columns-1 gap-6 sm:columns-2 lg:columns-3 [&>div]:mb-6 [&>div]:break-inside-avoid"
          stagger={0.035}
        >
          {visibleReviews.map((review) => (
          <RevealItem key={review.id}>
            <a
              href={content.booking.reviewsUrl}
              target="_blank"
              rel="noopener noreferrer"
              aria-label={`Read ${review.authorName}'s review on Booksy`}
              className="group block"
            >
              <figure className="hairline-strong bg-cream p-8 transition-all duration-300 group-hover:-translate-y-1 group-hover:bg-bone group-hover:shadow-lg">
                <p className="font-mono text-xs tracking-[0.3em] text-forest">
                  {"★".repeat(review.rating)}
                </p>
                <blockquote className="mt-5 text-[15px] leading-relaxed text-stone-700">
                  {review.text || <span className="italic text-stone-500">5-star rating</span>}
                </blockquote>
                <figcaption className="mono-micro mt-7 flex flex-wrap items-center gap-x-3 gap-y-1 text-stone-500">
                  <span className="text-ink">{review.authorName}</span>
                  <span aria-hidden>·</span>
                  <span>
                    {new Date(review.sourceDate + "T12:00:00").toLocaleDateString("en-US", {
                      month: "short",
                      day: "numeric",
                      year: "numeric",
                    })}
                  </span>
                  <span aria-hidden>·</span>
                  <span className="text-forest">via {platform} ↗</span>
                </figcaption>
              </figure>
            </a>
          </RevealItem>
          ))}
        </RevealGroup>
      </div>

      <nav className="hairline-t mt-10 flex items-center justify-center gap-1 pt-8 sm:gap-2" aria-label="Reviews pagination">
        <button
          type="button"
          onClick={() => goToPage(safePage - 1)}
          disabled={safePage === 1}
          aria-label="Previous page"
          className="flex size-9 shrink-0 items-center justify-center rounded-full border border-stone-300 text-stone-600 transition-colors hover:border-forest hover:text-forest disabled:cursor-not-allowed disabled:opacity-30 sm:size-11"
        >
          ←
        </button>
        {pageItems.map((item, i) =>
          item === "ellipsis" ? (
            <span key={`e-${i}`} className="px-1 font-mono text-xs text-stone-400 select-none">
              …
            </span>
          ) : (
            <button
              key={item}
              type="button"
              onClick={() => goToPage(item)}
              aria-current={item === safePage ? "page" : undefined}
              aria-label={`Page ${item}`}
              className={`size-9 shrink-0 rounded-[4px] border font-mono text-xs transition-colors sm:size-11 ${
                item === safePage
                  ? "border-forest bg-forest text-bone"
                  : "border-stone-300 text-stone-600 hover:border-forest hover:text-forest"
              }`}
            >
              {item}
            </button>
          )
        )}
        <button
          type="button"
          onClick={() => goToPage(safePage + 1)}
          disabled={safePage === pageCount}
          aria-label="Next page"
          className="flex size-9 shrink-0 items-center justify-center rounded-full border border-stone-300 text-stone-600 transition-colors hover:border-forest hover:text-forest disabled:cursor-not-allowed disabled:opacity-30 sm:size-11"
        >
          →
        </button>
      </nav>

      <p className="mono-micro mt-4 text-center text-stone-500" aria-live="polite">
        Showing {(safePage - 1) * pageSize + 1}–{Math.min(safePage * pageSize, reviews.length)} of {reviews.length}
      </p>
    </>
  );
}
