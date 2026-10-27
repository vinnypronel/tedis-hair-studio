export const content = {
  hero: {
    eyebrow: "MATAWAN, NJ · BY APPOINTMENT ONLY",
    headline: "Personal private cuts.",
    headlineItalic: "cuts.",
    sub: "Private, by-appointment hair studio for a fade done right.",
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
    email: "book@tedishairstudio.com",
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
    tiktok: "https://tiktok.com/@tedishairstudio",
    tiktokHandle: "@tedishairstudio",
  },
  brand: {
    story:
      "The studio is built for people who care how they look when they leave. No crowd, no rush, no extra noise. Just a clean room, one chair, and enough time to get the cut right. We keep the space focused and personal so every appointment gets its full attention from start to finish.",
  },
  space: {
    story:
      "Tedi's studio is tucked inside Bellazio Collective in Matawan. It is not a walk-in shop and it is not built for waiting around. It is one room, one chair, and a clean setup made for focused appointments. You show up on time, sit down, and get the cut handled right.",
  },
  about: {
    bio: [
      "Tedi built the studio around one simple idea: take your time and get the cut right. It is one chair, appointment only, and no rushing people in and out. When you sit down, the focus is on you and the haircut you came in for.",
      "He takes pride in keeping the space clean, comfortable, and easy to be in. Come through, talk, put something on, and relax while he handles the details. It is professional without feeling too serious, and personal without all the noise of a busy shop.",
      "Whether you already know exactly what you want or need help figuring it out, Tedi will listen and make sure you leave looking fresh. Good cuts, good conversation, and a spot you will want to come back to.",
    ],
    pullQuote: "The space you get cut in is part of the cut.",
    objects: [
      {
        name: "The studio wall",
        note: "Personal details, framed pieces, and the visual language of the room.",
        image: "/professional-images/pops.jpg",
      },
      {
        name: "Signed jerseys",
        note: "A signed Brunson jersey beside one from Tedi's friend Quist.",
        image: "/professional-images/gbjerseys.jpg",
      },
      {
        name: "The neon bear",
        note: "Yellow neon, X-stitched eye, always on.",
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
      "Shirts are not sold online. Current drops are available at the studio, ask Tedi at your appointment or send a DM.",
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
