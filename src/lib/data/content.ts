export const content = {
  hero: {
    eyebrow: "MATAWAN, NJ · BY APPOINTMENT ONLY",
    headline: "Personal private cuts.",
    headlineItalic: "cuts.",
    ctaPrimary: "Book Now",
    ctaSecondary: "See the work",
  },
  booking: {
    // Tedi takes every appointment through Booksy. Every "Book Now" on the site
    // opens this in a new tab. The on-site booking flow is archived, see
    // archive/BOOKING-FEATURE.md.
    provider: "Booksy",
    url: "https://booksy.com/en-us/instant-experiences/widget/1231797?instant_experiences_enabled=true",
    profileUrl:
      "https://booksy.com/en-us/1231797_tedis-hair-studio_barber-shop_28674_matawan",
    reviewsUrl:
      "https://booksy.com/en-us/1231797_tedis-hair-studio_barber-shop_28674_matawan#business-reviews",
    // Universal Google "write a review" link for Tedi's Hair Studio's own
    // Google Business listing. Opens the review dialog directly.
    googleReviewUrl:
      "https://search.google.com/local/writereview?placeid=ChIJAa6pnFDNw4kRrLUgExWpZvQ",
  },
  contact: {
    phone: "(732) 947-7359",
    phoneHref: "tel:+17329477359",
    email: "tedishairstudio@gmail.com",
    addressLine1: "259-267 Broad St, Suite 128",
    addressLine2: "Matawan, NJ 07747",
    addressInside: "Inside Bellazio Collective",
    googleMapsUrl:
      "https://www.google.com/maps/search/?api=1&query=259-267+Broad+St+Suite+128+Matawan+NJ+07747",
    mapsEmbedUrl:
      "https://www.google.com/maps?q=259-267+Broad+St+Suite+128,+Matawan,+NJ+07747&output=embed",
  },
  social: {
    instagram: "https://instagram.com/tedishairstudio",
    instagramHandle: "@tedishairstudio",
  },
  brand: {
    story:
      "The studio is built for people who care how they look when they leave. No crowd, no rush, no extra noise. Just a clean room, one chair, and enough time to get the cut right. We keep the space focused and personal so every appointment gets its full attention from start to finish.",
  },
  space: {
    story:
      "Tedi's studio is inside Bellazio Collective in Matawan. It is not a walk-in shop and it is not built for waiting around. It is one room, one chair, and a clean setup made for focused appointments. You show up on time, sit down, and get the cut handled right.",
  },
  about: {
    bio: [
      "Tedi's Hair Studio is a private barber studio inside Bellazio Collective in Matawan, NJ.",
      "Tedi offers haircuts, fades, shape ups, and beard trims in a relaxed, single-chair space. Every appointment is one-on-one, with time to talk through what you want and attention to the details that make your cut feel right.",
      "Whether you're keeping your usual look or trying something new, you'll get personal attention from start to finish. Appointment only. Book through Booksy.",
    ],
    pullQuote: "Come as a client, leave as a regular.",
    objects: [
      {
        name: "The studio wall",
        note: "Personal items and framed pieces displayed in the studio.",
        image: "/professional-images/pops.jpg",
      },
      {
        name: "2026 Finals MVP Jalen Brunson",
        note: "Signed jersey displayed inside the studio.",
        image: "/professional-images/gbjerseys.jpg",
      },
      {
        name: "The whole space",
        note: "One chair, one room, and everything in its place.",
        image: "/professional-images/chair-wash.jpg",
      },
    ],
  },
  servicesNotes: [
    "Appointments are private. 1:1.",
    "Booking, rescheduling, and cancellations all run through Booksy. Give at least 24 hours notice.",
    "Running late? Text the studio. More than 15 minutes may require rebooking.",
    "Cash and Zelle accepted at the studio.",
  ],
  shop: {
    disclaimer:
      "The shirts are not for sale. Tedi occasionally gives out new designs with cuts, and each batch is different.",
  },
  meta: {
    siteName: "Tedi's Hair Studio",
    siteUrl: "https://tedishairstudio.com",
    description:
      "Private, by-appointment hair studio in Matawan, NJ. One chair, one barber, cuts done with intention. Inside Bellazio Collective.",
    established: 2024,
  },
} as const;

export type SiteContent = typeof content;
