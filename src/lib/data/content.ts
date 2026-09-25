export const content = {
  hero: {
    eyebrow: "MATAWAN, NJ · BY APPOINTMENT ONLY",
    headline: "A studio of one.",
    headlineItalic: "one.",
    sub: "Private, by-appointment hair studio for cuts done with intention.",
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
      "The studio is built on the belief that the environment you get cut in is just as important as the cut itself. Inside, you won't find the loud rush of a traditional shop. Instead, the space is a highly curated personal sanctuary, featuring Tedi's collection of Bearbrick collectibles, framed signed jerseys, and Mr. Brainwash-inspired artwork. It's a private, single-chair room designed for comfort and focus. When you're here, you choose the music, set the vibe, and get the barber's complete, uninterrupted attention.",
  },
  space: {
    story:
      "The studio sits inside Bellazio Collective, a modern, curated space in the heart of Matawan. No strip-mall storefront, no row of chairs, no walk-in churn. Tedi chose this address because the standards match his own: marble counters, black cabinetry, light wood floors, and one chair in the middle of it all. You don't pass it on the way to somewhere else. You come here on purpose.",
  },
  about: {
    bio: [
      "Tedi didn't set out to own a barbershop. He set out to never compromise on a haircut again, and a one-chair private studio turned out to be the only way to do it. No double-bookings, no rushing a fade because three people are waiting, no music you didn't choose. When you're in the chair, you're the only client in the building.",
      "He came up cutting the hard way: friends' kitchens, then a chain shop, then a booth rental, each stop teaching him exactly what he didn't want his own place to feel like. The studio inside Bellazio Collective is the answer to all of it. Every object in the room is chosen: the Bearbrick shelf, the signed jerseys, the 'High Class' print. Tedi believes the space you get cut in is part of the cut.",
      "The work is appointment-only and it stays that way. Fewer cuts a day, more attention per cut. If that sounds like your kind of arrangement, the chair is one booking away.",
    ],
    pullQuote: "The space you get cut in is part of the cut.",
    objects: [
      {
        name: "The Bearbrick shelf",
        note: "The collection that started the bear obsession.",
        image: "/professional-images/pops.jpg",
      },
      {
        name: "Signed jerseys",
        note: "Quist, Brunson, Arringo. Framed and earned.",
        image: "/professional-images/gbjerseys.jpg",
      },
      {
        name: "The 'High Class' print",
        note: "Mr. Brainwash energy, studio-approved.",
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
    established: 2023,
  },
} as const;

export type SiteContent = typeof content;
