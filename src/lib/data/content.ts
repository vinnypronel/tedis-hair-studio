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
    // Universal Google "write a review" link (Bellazio Collective / Salon Suites
    // listing the studio sits in). Opens the review dialog directly.
    googleReviewUrl:
      "https://search.google.com/local/writereview?placeid=ChIJJ_J4wAzNw4kRlwrMZya2xDM",
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
      "Tedi didn't set out to own a barbershop. He set out to never compromise on a haircut again, and a one-chair private studio turned out to be the only way to do it. No double-bookings, no rushing a fade because three people are waiting, no music you didn't choose. When you're in the chair, you're the only client in the building.",
      "He came up cutting the hard way: friends' kitchens, then a chain shop, then a booth rental, each stop teaching him exactly what he didn't want his own place to feel like. The studio inside Bellazio Collective is the answer to all of it. Every part of the room is intentional: the chair, the lighting, the walls, the music, and the pace. Tedi believes the space you get cut in is part of the cut.",
      "The work is appointment-only and it stays that way. Fewer cuts a day, more attention per cut. If that sounds like your kind of arrangement, the chair is one booking away.",
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
        note: "Quist, Brunson, Arringo. Framed and earned.",
        image: "/professional-images/gbjerseys.jpg",
      },
      {
        name: "The art corner",
        note: "Color, texture, and personality without the noise of a busy shop.",
        image: "/professional-images/bwjerseys.jpg",
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
