export type ShirtStatus = "display_only" | "archived";

export type ShirtImage = {
  url: string | null;
  alt: string;
  tone?: "forest" | "ink" | "ember" | "bone";
  objectPosition?: string;
};

export type Shirt = {
  id: string;
  name: string;
  slug: string;
  description: string;
  images: ShirtImage[];
  status: ShirtStatus;
  sortOrder: number;
  releaseYear: number;
  drop: string;
};

export const shirts: Shirt[] = [
  {
    id: "shirt-red-black",
    name: "Red/Black Tee",
    slug: "red-black-tee",
    description:
      "Bold red bear mark and studio typography on a black body. Sleeve hit and full back print. Cut boxy, made to last.",
    images: [
      { url: "/professional-images/redblackshirt.jpg", alt: "Red/Black Tee, black body with red bear mark" },
    ],
    status: "display_only",
    sortOrder: 1,
    releaseYear: 2026,
    drop: "DROP 003",
  },
  {
    id: "shirt-blue-flame",
    name: "Navy Blue Tee",
    slug: "blue-tee",
    description:
      "Matched to the blue flame cape. Ink body with icy blue bear mark. Bold enough to turn heads, clean enough to wear daily.",
    images: [
      { url: "/professional-images/blueshirt.jpg", alt: "Navy Blue Tee, ink body with blue bear mark" },
    ],
    status: "display_only",
    sortOrder: 2,
    releaseYear: 2026,
    drop: "DROP 003",
  },
  {
    id: "shirt-neon-mark",
    name: "Yellow/Black Tee",
    slug: "yellow-black-tee",
    description:
      "The loud one. Yellow body, ink bear mark front and center. Matches the neon sign in the studio. You'll know it when you see it.",
    images: [
      { url: "/professional-images/yellowshirt.jpg", alt: "Yellow/Black Tee,yellow body with ink bear mark", objectPosition: "right center" },
    ],
    status: "display_only",
    sortOrder: 3,
    releaseYear: 2026,
    drop: "DROP 003",
  },
  {
    id: "shirt-mark-tee",
    name: "Green Tee",
    slug: "green-tee",
    description:
      "The studio staple. Olive green body, cream bear mark across the back, small left-chest hit on the front. Cut boxy, made to be kept.",
    images: [
      { url: "/professional-images/greenshirt.jpg", alt: "Green Tee, olive green with cream bear print" },
    ],
    status: "display_only",
    sortOrder: 4,
    releaseYear: 2026,
    drop: "DROP 003",
  },
  {
    id: "shirt-glow",
    name: "Glow in the Dark Tee",
    slug: "glow-in-the-dark-tee",
    description:
      "Black body with high-visibility glow-in-the-dark bear mark and studio typography. Lights up under blacklight. Built boxy, made to last.",
    images: [
      { url: "/professional-images/glowindarkshirt.jpg", alt: "Glow in the Dark Tee, black body with neon glow bear mark" },
    ],
    status: "display_only",
    sortOrder: 5,
    releaseYear: 2026,
    drop: "DROP 003",
  },
  {
    id: "shirt-holiday",
    name: "Christmas Tee '25",
    slug: "holiday-tee-25",
    description:
      "A December edition with a full back print. One of the rotating designs Tedi has given out with cuts.",
    images: [
      { url: "/professional-images/christmashirt.jpg", alt: "Christmas Tee 2025, full back print" },
    ],
    status: "display_only",
    sortOrder: 6,
    releaseYear: 2025,
    drop: "DROP 002",
  },
  {
    id: "shirt-halloween",
    name: "Halloween Tee '25",
    slug: "halloween-tee-25",
    description:
      "An October edition with an orange flame cape print on a black body. Made for the season and kept here in the archive.",
    images: [
      { url: "/professional-images/halloweenshirt.jpg", alt: "Halloween Tee 2025,orange flame cape print" },
    ],
    status: "display_only",
    sortOrder: 7,
    releaseYear: 2025,
    drop: "DROP 002",
  },
  {
    id: "shirt-ember",
    name: "Brown Tee",
    slug: "brown-tee",
    description:
      "Matched to the brown cape. Earth-tone body, ink bear mark, and one of the studio's rotating shirt designs.",
    images: [
      { url: "/professional-images/brownshirt.jpg", alt: "Brown Tee,earth-tone body with ink bear mark" },
    ],
    status: "display_only",
    sortOrder: 8,
    releaseYear: 2025,
    drop: "DROP 002",
  },
];

export function getShirtBySlug(slug: string): Shirt | undefined {
  return shirts.find((s) => s.slug === slug);
}

export function getVisibleShirts(): Shirt[] {
  return shirts
    .filter((s) => s.status !== "archived")
    .sort((a, b) => a.sortOrder - b.sortOrder);
}
