export type GalleryCategory = "cuts" | "studio";

export type GalleryMediaType = "image" | "video";

export type GalleryImage = {
  id: string;
  type?: GalleryMediaType;
  url: string;
  alt: string;
  category: GalleryCategory;
  featured: boolean;
  sortOrder: number;
};

export const galleryImages: GalleryImage[] = [
  // ----- The Work -----
  { id: "g-cut1", url: "/images/cut1.jpeg", alt: "Skin fade with textured top", category: "cuts", featured: true, sortOrder: 1 },
  { id: "g-video-fade1", type: "video", url: "/Cut Videos/Fade1.mp4", alt: "Precision skin fade transformation in the chair", category: "cuts", featured: true, sortOrder: 2 },
  { id: "g-cut2", url: "/images/cut2.jpeg", alt: "Clean taper with sharp lineup", category: "cuts", featured: false, sortOrder: 3 },
  { id: "g-cut3", url: "/images/cut3.jpeg", alt: "Mid fade, scissor work on top", category: "cuts", featured: false, sortOrder: 4 },
  { id: "g-video-kid-fade", type: "video", url: "/Cut Videos/Kid_Fade_Design.mp4", alt: "Kid's fade with custom razor design detail", category: "cuts", featured: true, sortOrder: 5 },
  { id: "g-cut4", url: "/images/cut4.jpeg", alt: "Burst fade with detailed edges", category: "cuts", featured: true, sortOrder: 6 },
  { id: "g-cut6", url: "/images/cut6.jpeg", alt: "Crop with hard part", category: "cuts", featured: false, sortOrder: 7 },
  { id: "g-video-fade2", type: "video", url: "/Cut Videos/Fade2.mp4", alt: "Clean fade and beard detailing in the chair", category: "cuts", featured: true, sortOrder: 8 },
  { id: "g-design", url: "/images/designsidehair.jpg", alt: "Lightning bolt design fade", category: "cuts", featured: false, sortOrder: 9 },
  { id: "g-gorc", url: "/images/gorc-cut.jpg", alt: "Fresh cut, client portrait", category: "cuts", featured: false, sortOrder: 10 },
  { id: "g-video-fade3", type: "video", url: "/Cut Videos/Fade3.mp4", alt: "Taper fade and precision styling session", category: "cuts", featured: true, sortOrder: 11 },
  { id: "g-jgorc", url: "/images/jgorc.jpeg", alt: "Finished cut, studio lighting", category: "cuts", featured: false, sortOrder: 12 },

  // ----- The Studio -----
  { id: "g-chair", url: "/professional-images/chair.jpg", alt: "The chair, green cape with the bear mark", category: "studio", featured: true, sortOrder: 1 },
  { id: "g-bwj", url: "/professional-images/bwjerseys.jpg", alt: "Signed Quist and Arringo jerseys", category: "studio", featured: false, sortOrder: 2 },
  { id: "g-pops", url: "/professional-images/pops.jpg", alt: "Bape and Funko collection shelf", category: "studio", featured: false, sortOrder: 3 },
  { id: "g-xmas-decor", url: "/professional-images/christmasdecor.jpg", alt: "Holiday studio decor and custom 3D bear figures", category: "studio", featured: true, sortOrder: 4 },
  { id: "g-gbj", url: "/professional-images/gbjerseys.jpg", alt: "Signed Quist and Brunson jerseys", category: "studio", featured: false, sortOrder: 5 },
  { id: "g-wash", url: "/professional-images/chair-wash.jpg", alt: "Studio interior with shampoo chair", category: "studio", featured: false, sortOrder: 6 },
  { id: "g-door", url: "/professional-images/outsidedoor.jpg", alt: "Studio entrance at Bellazio Collective", category: "studio", featured: false, sortOrder: 7 },
  { id: "g-tedi", url: "/professional-images/tedi-door.jpg", alt: "Tedi outside the studio", category: "studio", featured: true, sortOrder: 8 },
  { id: "g-bellazio", url: "/images/bellazio.jpg", alt: "Bellazio Collective", category: "studio", featured: false, sortOrder: 9 },
];

export function getGalleryByCategory(category: GalleryCategory): GalleryImage[] {
  return galleryImages
    .filter((img) => img.category === category)
    .sort((a, b) => a.sortOrder - b.sortOrder);
}

/** Images for the home-page marquee. */
export const marqueeImages = galleryImages.filter((i) => i.category === "cuts");

export type InstagramPost = {
  image: string;
  caption: string;
  postUrl: string;
};

export const instagramPosts: InstagramPost[] = [
  {
    image: "/images/cut1.jpeg",
    caption: "Fresh out the chair 🧸 Bookings open on Booksy.",
    postUrl: "https://www.instagram.com/tedishairstudio/",
  },
  {
    image: "/professional-images/blueshirt.jpg",
    caption: "Blue Tee 🧸 Matched to the cape. In studio now.",
    postUrl: "https://www.instagram.com/tedishairstudio/",
  },
  {
    image: "/images/cut4.jpeg",
    caption: "Burst fade with precision textured finish 💈 By appointment only.",
    postUrl: "https://www.instagram.com/tedishairstudio/",
  },
  {
    image: "/professional-images/pops.jpg",
    caption: "Studio details & private studio vibes 🧸 Matawan, NJ.",
    postUrl: "https://www.instagram.com/tedishairstudio/",
  },
  {
    image: "/images/designsidehair.jpg",
    caption: "Custom razor design detail ⚡️ Bring the kids in for back to school cuts.",
    postUrl: "https://www.instagram.com/tedishairstudio/",
  },
  {
    image: "/professional-images/brownshirt.jpg",
    caption: "Brown Tee 🧸 Earth tones. Rep the studio.",
    postUrl: "https://www.instagram.com/tedishairstudio/",
  },
  {
    image: "/professional-images/yellowshirt.jpg",
    caption: "Yellow/Black Tee ⚡️ Available in the studio. Ask Tedi at your next cut.",
    postUrl: "https://www.instagram.com/tedishairstudio/",
  },
  {
    image: "/professional-images/tedi-door.jpg",
    caption: "Tedi's Hair Studio 🧸 259-267 Broad St, Suite 128, Matawan, NJ 07747 · Book Now on Booksy.",
    postUrl: "https://www.instagram.com/tedishairstudio/",
  },
];

/** @deprecated Use instagramPosts instead */
export const instagramFallback = instagramPosts.slice(0, 6).map((p) => ({
  url: p.image,
  caption: p.caption,
}));
