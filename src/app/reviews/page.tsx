import type { Metadata } from "next";
import { PageHeader } from "@/components/site/page-header";
import { Reveal, RevealGroup, RevealItem } from "@/components/site/reveal";
import { reviews, reviewStats } from "@/lib/data/reviews";

export const metadata: Metadata = {
  title: "Reviews",
  description:
    "What clients say about Tedi's Hair Studio. Five-star reviews from a private, by-appointment barber studio in Matawan NJ.",
};

export default function ReviewsPage() {
  const published = [...reviews]
    .filter((r) => r.published)
    .sort(
      (a, b) =>
        a.sortOrder - b.sortOrder ||
        new Date(b.sourceDate).getTime() - new Date(a.sourceDate).getTime()
    );

  return (
    <div className="pb-24 lg:pb-36">
      <PageHeader eyebrow="Reviews" title={<em className="italic">Five stars, on repeat.</em>} />

      <div className="px-6 md:px-12 lg:px-20">
        <div className="mx-auto max-w-[1440px]">
          {/* Aggregate */}
          <Reveal>
            <div className="hairline-t hairline-b flex flex-wrap items-baseline gap-x-12 gap-y-4 py-10">
              <span className="font-display text-7xl tracking-tight">
                {reviewStats.average.toFixed(1)}
              </span>
              <span className="font-mono text-lg tracking-[0.3em] text-forest">★★★★★</span>
              <span className="mono-micro text-stone-500">
                {reviewStats.count} reviews · via {reviewStats.platform}
              </span>
              <span className="mono-micro border-[0.5px] border-forest px-2 py-1 text-forest">
                Only 5 stars
              </span>
            </div>
          </Reveal>

          {/* Masonry-ish columns */}
          <RevealGroup
            className="mt-14 columns-1 gap-6 sm:columns-2 lg:columns-3 [&>div]:mb-6 [&>div]:break-inside-avoid"
            stagger={0.06}
          >
            {published.map((review) => (
              <RevealItem key={review.id}>
                <figure className="hairline-strong bg-cream p-8">
                  <p className="font-mono text-xs tracking-[0.3em] text-forest">
                    {"★".repeat(review.rating)}
                  </p>
                  <blockquote className="mt-5 text-[15px] leading-relaxed text-stone-700">
                    {review.text}
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
                    <span>via {review.source}</span>
                  </figcaption>
                </figure>
              </RevealItem>
            ))}
          </RevealGroup>
        </div>
      </div>
    </div>
  );
}
