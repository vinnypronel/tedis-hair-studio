export type ShirtStatus = "for_sale" | "display_only" | "archived";

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
  priceCents: number;
  images: ShirtImage[];
  availableSizes: string[];
  status: ShirtStatus;
  sortOrder: number;
  releaseYear: number;
  drop: string;
};

export const shirts: Shirt[] = [
  {
    id: "shirt-mark-tee",
    name: "Green Tee",
    slug: "green-tee",
    description:
      "The studio staple. Forest green body, cream bear mark across the back, small left-chest hit on the front. Cut boxy, made to be kept.",
    priceCents: 3500,
    images: [
      { url: "/professional-images/greenshirt.jpg", alt: "The Mark Tee,forest green with cream bear print" },
    ],
    availableSizes: ["S", "M", "L", "XL", "XXL"],
    status: "for_sale",
    sortOrder: 1,
    releaseYear: 2026,
    drop: "DROP 003",
  },
  {
    id: "shirt-blue-flame",
    name: "Blue Tee",
    slug: "blue-tee",
    description:
      "Matched to the blue flame cape. Ink body with icy blue bear mark. Bold enough to turn heads, clean enough to wear daily.",
    priceCents: 3500,
    images: [
      { url: "/professional-images/blueshirt.jpg", alt: "Blue Flame Tee,ink body with blue bear mark" },
    ],
    availableSizes: ["S", "M", "L", "XL"],
    status: "for_sale",
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
    priceCents: 3500,
    images: [
      { url: "/professional-images/yellowshirt.jpg", alt: "Neon Mark Tee,yellow body with ink bear mark", objectPosition: "right center" },
    ],
    availableSizes: ["M", "L", "XL"],
    status: "for_sale",
    sortOrder: 3,
    releaseYear: 2026,
    drop: "DROP 003",
  },
  {
    id: "shirt-holiday",
    name: "Holiday Tee '25",
    slug: "holiday-tee-25",
    description:
      "The December drop. Full back print, sold out in a week. Kept here for the archive. If you have one, hold onto it.",
    priceCents: 3500,
    images: [
      { url: "/professional-images/christmashirt.jpg", alt: "Holiday Tee 2025,full back print" },
    ],
    availableSizes: [],
    status: "display_only",
    sortOrder: 4,
    releaseYear: 2025,
    drop: "DROP 002",
  },
  {
    id: "shirt-halloween",
    name: "Halloween Tee '25",
    slug: "halloween-tee-25",
    description:
      "The October drop. Orange flame cape print on a black body. Limited run for the season. Gone before November.",
    priceCents: 3500,
    images: [
      { url: "/professional-images/halloweenshirt.jpg", alt: "Halloween Tee 2025,orange flame cape print" },
    ],
    availableSizes: [],
    status: "display_only",
    sortOrder: 5,
    releaseYear: 2025,
    drop: "DROP 002",
  },
  {
    id: "shirt-ember",
    name: "Brown Tee",
    slug: "brown-tee",
    description:
      "Matched to the brown cape. Earth-tone body, ink bear mark. One run, never repeated.",
    priceCents: 3500,
    images: [
      { url: "/professional-images/brownshirt.jpg", alt: "Ember Tee,earth-tone body with ink bear mark" },
    ],
    availableSizes: [],
    status: "display_only",
    sortOrder: 6,
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
