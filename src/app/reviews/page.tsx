import type { Metadata } from "next";
import { PageHeader } from "@/components/site/page-header";
import { Reveal, RevealGroup, RevealItem } from "@/components/site/reveal";
import { ButtonLink } from "@/components/ui/button";
import { RatingBreakdown } from "@/components/reviews/rating-breakdown";
import { reviews, reviewStats } from "@/lib/data/reviews";
import { content } from "@/lib/data/content";

export const metadata: Metadata = {
  alternates: { canonical: "/reviews" },
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
      <PageHeader compact title={<em className="italic">Five stars, only.</em>} />

      <div className="px-6 md:px-12 lg:px-20">
        <div className="mx-auto max-w-[1440px]">
          {/* Aggregate */}
          <Reveal>
            <div className="hairline-t hairline-b grid gap-x-16 gap-y-10 py-12 lg:grid-cols-12 lg:items-center">
              <div className="lg:col-span-4">
                <div className="flex items-end gap-6">
                  <span className="font-display text-7xl leading-[0.85] tracking-tight">
                    {reviewStats.average.toFixed(1)}
                  </span>
                  <span className="pb-1 font-mono text-lg tracking-[0.3em] text-[#d4af37]">
                    ★★★★★
                  </span>
                </div>
                <p className="mono-micro mt-5 text-stone-500">
                  Based on {reviewStats.count} reviews ·{" "}
                  <a
                    href={content.booking.reviewsUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="link-draw text-stone-700"
                  >
                    via {reviewStats.platform} ↗
                  </a>
                </p>
              </div>

              <div className="lg:col-span-7 lg:col-start-6">
                <RatingBreakdown
                  distribution={reviewStats.distribution}
                  total={reviewStats.count}
                />
                <div className="mt-6 flex items-center justify-between gap-4">
                  <p className="mono-micro text-stone-500">
                    {reviewStats.distribution[5]} of {reviewStats.count} are five stars.
                    Nothing below.
                  </p>
                  <span className="font-mono text-base tracking-[0.25em] text-forest" aria-label="5 stars">
                    ★★★★★
                  </span>
                </div>
              </div>
            </div>
          </Reveal>

          {/* Masonry-ish columns */}
          <RevealGroup
            className="mt-14 columns-1 gap-6 sm:columns-2 lg:columns-3 [&>div]:mb-6 [&>div]:break-inside-avoid"
            stagger={0.06}
          >
            {published.map((review) => (
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
                      <span className="text-forest">via {reviewStats.platform} ↗</span>
                    </figcaption>
                  </figure>
                </a>
              </RevealItem>
            ))}
          </RevealGroup>

          <Reveal delay={0.1}>
            <div className="hairline-t mt-16 flex flex-wrap items-center justify-between gap-6 pt-8">
              <p className="text-sm text-stone-500">
                Showing the {published.length} most recent. Every review here was left by a
                client on {reviewStats.platform}.
              </p>
              <ButtonLink href={content.booking.reviewsUrl} arrow>
                Read all {reviewStats.count} on {reviewStats.platform}
              </ButtonLink>
            </div>
          </Reveal>
        </div>
      </div>
    </div>
  );
}
