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

export const reviews: Review[] = [
  {
    id: "rev-1",
    authorName: "Marcus T.",
    rating: 5,
    text: "Been getting cut for 15 years and nobody has ever paid this much attention to detail. Tedi checked the fade from three angles before he let me out of the chair. The studio itself is something else. Feels like a private showroom, not a shop.",
    source: "booksy",
    sourceDate: "2026-05-18",
    featured: true,
    published: true,
    sortOrder: 1,
  },
  {
    id: "rev-2",
    authorName: "Devon R.",
    rating: 5,
    text: "One chair, no waiting, no chaos. You book, you show up, it's just you. The cut is consistently the best I've had in NJ and I drive 40 minutes for it.",
    source: "booksy",
    sourceDate: "2026-04-02",
    featured: true,
    published: true,
    sortOrder: 2,
  },
  {
    id: "rev-3",
    authorName: "Chris M.",
    rating: 5,
    text: "My son won't let anyone else touch his hair now. Tedi took the time to actually listen to what he wanted instead of just doing the usual. Worth every dollar.",
    source: "booksy",
    sourceDate: "2026-03-21",
    featured: true,
    published: true,
    sortOrder: 3,
  },
  {
    id: "rev-4",
    authorName: "Anthony P.",
    rating: 5,
    text: "Cleanest shape up in Matawan, period. The attention to the hairline is surgical. Booked my next three appointments before I left.",
    source: "booksy",
    sourceDate: "2026-02-14",
    featured: false,
    published: true,
    sortOrder: 4,
  },
  {
    id: "rev-5",
    authorName: "Jordan K.",
    rating: 5,
    text: "First time somewhere new in years and I was nervous. Tedi walked me through the whole cut before he started. Beard work was unreal. Best line I've ever had.",
    source: "booksy",
    sourceDate: "2025-12-09",
    featured: false,
    published: true,
    sortOrder: 5,
  },
  {
    id: "rev-6",
    authorName: "Sam W.",
    rating: 5,
    text: "The space alone is worth seeing. Bearbricks, signed jerseys, marble counters, and then the cut backs all of it up. Got exactly what I showed him in the photo, maybe better.",
    source: "booksy",
    sourceDate: "2025-11-01",
    featured: false,
    published: true,
    sortOrder: 6,
  },
  {
    id: "rev-7",
    authorName: "Luis G.",
    rating: 5,
    text: "Appointment ran exactly on time, which never happens at a barbershop. Private studio means it's quiet, focused, and the cut shows it. Already recommended him to my whole office.",
    source: "booksy",
    sourceDate: "2025-09-15",
    featured: false,
    published: true,
    sortOrder: 7,
  },
  {
    id: "rev-8",
    authorName: "Nate B.",
    rating: 5,
    text: "Tedi fixed a cut another shop butchered two days before my wedding. Stayed late to do it. That's the kind of barber he is.",
    source: "booksy",
    sourceDate: "2025-07-28",
    featured: false,
    published: true,
    sortOrder: 8,
  },
];

export const reviewStats = {
  average: 5.0,
  count: 124,
  platform: "Booksy",
};

export function getFeaturedReviews(): Review[] {
  return reviews.filter((r) => r.featured && r.published);
}
