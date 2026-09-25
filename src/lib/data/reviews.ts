export type ReviewSource = "booksy" | "google" | "direct" | "instagram";

export type Review = {
  id: string;
  authorName: string;
  rating: number;
  text: string;
  source: ReviewSource;
  sourceDate: string; // ISO date
  featured: boolean;
  published: boolean;
  sortOrder: number;
};

/**
 * Real reviews pulled from Tedi's Booksy profile on 2026-08-25. Text is verbatim,
 * including spelling and spacing. Last names are shortened to an initial, which is
 * how Booksy publishes the recent ones.
 *
 * Booksy has no per-review permalink, so every card links to the reviews section of
 * the profile: content.booking.reviewsUrl.
 *
 * To refresh: reviews live in the __NUXT_DATA__ payload on the profile page. Only
 * the first page (10) plus the photo reviews (5) are server-rendered.
 */
export const reviews: Review[] = [
  {
    id: "rev-11288049",
    authorName: "James P.",
    rating: 5,
    text: "Perfect haircut every single time, you are not rushed and he pays attention to every detail",
    source: "booksy",
    sourceDate: "2026-08-23",
    featured: true,
    published: true,
    sortOrder: 1,
  },
  {
    id: "rev-11263923",
    authorName: "Pat S.",
    rating: 5,
    text: "Fantastic. Tedi is the best.",
    source: "booksy",
    sourceDate: "2026-08-22",
    featured: false,
    published: true,
    sortOrder: 2,
  },
  {
    id: "rev-11196954",
    authorName: "Noah R.",
    rating: 5,
    text: "i LOVE it here!",
    source: "booksy",
    sourceDate: "2026-08-15",
    featured: false,
    published: true,
    sortOrder: 3,
  },
  {
    id: "rev-11170317",
    authorName: "Jovanni C.",
    rating: 5,
    text: "Come get a cut HERE!",
    source: "booksy",
    sourceDate: "2026-08-12",
    featured: false,
    published: true,
    sortOrder: 4,
  },
  {
    id: "rev-11168846",
    authorName: "Patrick H.",
    rating: 5,
    text: "Tedi is awesome. Professional and talented",
    source: "booksy",
    sourceDate: "2026-08-12",
    featured: false,
    published: true,
    sortOrder: 5,
  },
  {
    id: "rev-11125681",
    authorName: "Faris S.",
    rating: 5,
    text: "10/10 Service.",
    source: "booksy",
    sourceDate: "2026-08-05",
    featured: false,
    published: true,
    sortOrder: 6,
  },
  {
    id: "rev-11097264",
    authorName: "Jason G.",
    rating: 5,
    text: "Teddy is the best",
    source: "booksy",
    sourceDate: "2026-07-30",
    featured: false,
    published: true,
    sortOrder: 7,
  },
  {
    id: "rev-11063092",
    authorName: "Jacob R.",
    rating: 5,
    text: "He did exactly what my son asked him to do. The shop is clean and inviting. He ran on time. We continue to return for haircuts for my very picky teenage son.",
    source: "booksy",
    sourceDate: "2026-07-24",
    featured: true,
    published: true,
    sortOrder: 8,
  },
  {
    id: "rev-11058330",
    authorName: "Arti H.",
    rating: 5,
    text: "Tedi is the greatest barber ever I’ve never met another better he just be cookin and he’s valid in the hood.",
    source: "booksy",
    sourceDate: "2026-07-23",
    featured: false,
    published: true,
    sortOrder: 9,
  },
  {
    id: "rev-11056456",
    authorName: "Christine R.",
    rating: 5,
    text: "Wonderful",
    source: "booksy",
    sourceDate: "2026-07-23",
    featured: false,
    published: true,
    sortOrder: 10,
  },
  {
    id: "rev-10716324",
    authorName: "Vincenzo F.",
    rating: 5,
    text: "it was great",
    source: "booksy",
    sourceDate: "2026-05-26",
    featured: false,
    published: true,
    sortOrder: 11,
  },
  {
    id: "rev-9791294",
    authorName: "Matthew G.",
    rating: 5,
    text: "Nothing but excellence. He does exactly what you want, sharing photos of the style you’re going for goes a long way.",
    source: "booksy",
    sourceDate: "2025-11-22",
    featured: true,
    published: true,
    sortOrder: 12,
  },
  {
    id: "rev-8945841",
    authorName: "Joyce P.",
    rating: 5,
    text: "As always another perfect experience.",
    source: "booksy",
    sourceDate: "2025-06-17",
    featured: false,
    published: true,
    sortOrder: 13,
  },
  {
    id: "rev-8280179",
    authorName: "Rachael M.",
    rating: 5,
    text: "Polite courtesy service . Right on time . Clean shop . Great atmosphere. Clean smooth cut . We’ve been customers for about 4 yrs now . Highly recommended.",
    source: "booksy",
    sourceDate: "2025-01-11",
    featured: false,
    published: true,
    sortOrder: 14,
  },
  {
    id: "rev-7978950",
    authorName: "Marko A.",
    rating: 5,
    text: "Great haircut, kept it classic and simple. Nice clean shop in a cool new location.  Thank you, Tedi.",
    source: "booksy",
    sourceDate: "2024-10-19",
    featured: false,
    published: true,
    sortOrder: 15,
  },
];

/**
 * Saved Booksy totals, updated to 149 reviews on 2026-09-25.
 * Retains the existing five-star rating breakdown.
 */
export const reviewStats = {
  average: 5.0,
  count: 149,
  platform: "Booksy",
  distribution: { 5: 149, 4: 0, 3: 0, 2: 0, 1: 0 } as Record<number, number>,
};

export function getFeaturedReviews(): Review[] {
  return reviews.filter((r) => r.featured && r.published);
}
