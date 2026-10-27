import type { Metadata } from "next";
import { PageHeader } from "@/components/site/page-header";
import { Reveal } from "@/components/site/reveal";
import { ButtonLink } from "@/components/ui/button";
import { RatingBreakdown } from "@/components/reviews/rating-breakdown";
import { ReviewsList } from "@/components/reviews/reviews-list";
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
      <PageHeader
        compact
        title={<em className="italic">Five stars, only.</em>}
        sub={
          <span className="mono-micro text-stone-500">
            Last updated 10/27/26
            <span
              aria-hidden
              className="caret-blink ml-1 inline-block h-[1em] w-[2px] translate-y-[2px] bg-stone-500 align-middle"
            />
          </span>
        }
      />

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

          <ReviewsList reviews={published} platform={reviewStats.platform} />

          <Reveal delay={0.1}>
            <div className="hairline-t mt-16 flex flex-col gap-4 pt-8 sm:flex-row sm:flex-wrap sm:items-center sm:justify-between sm:gap-6">
              <p className="text-sm text-stone-500">
                Showing all {published.length} reviews. Every review here was left by a client
                on {reviewStats.platform}.
              </p>
              <div className="flex justify-end">
                <ButtonLink href={content.booking.reviewsUrl} arrow>
                  Read all {reviewStats.count} on {reviewStats.platform}
                </ButtonLink>
              </div>
            </div>
          </Reveal>
        </div>
      </div>
    </div>
  );
}
