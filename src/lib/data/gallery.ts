export type GalleryCategory = "cuts" | "studio";

export type GalleryImage = {
  id: string;
  url: string;
  alt: string;
  category: GalleryCategory;
  featured: boolean;
  sortOrder: number;
};

export const galleryImages: GalleryImage[] = [
  // ----- The Work -----
  { id: "g-cut1", url: "/images/cut1.jpeg", alt: "Skin fade with textured top", category: "cuts", featured: true, sortOrder: 1 },
  { id: "g-cut2", url: "/images/cut2.jpeg", alt: "Clean taper with sharp lineup", category: "cuts", featured: false, sortOrder: 2 },
  { id: "g-cut3", url: "/images/cut3.jpeg", alt: "Mid fade, scissor work on top", category: "cuts", featured: false, sortOrder: 3 },
  { id: "g-cut4", url: "/images/cut4.jpeg", alt: "Burst fade with detailed edges", category: "cuts", featured: true, sortOrder: 4 },
  { id: "g-cut5", url: "/images/cut5.jpeg", alt: "Low fade with beard blend", category: "cuts", featured: false, sortOrder: 5 },
  { id: "g-cut6", url: "/images/cut6.jpeg", alt: "Crop with hard part", category: "cuts", featured: false, sortOrder: 6 },
  { id: "g-beard", url: "/images/beard-cut.jpeg", alt: "Beard sculpt and razor line", category: "cuts", featured: false, sortOrder: 7 },
  { id: "g-gorc", url: "/images/gorc-cut.jpg", alt: "Fresh cut, client portrait", category: "cuts", featured: false, sortOrder: 8 },
  { id: "g-jgorc", url: "/images/jgorc.jpeg", alt: "Finished cut, studio lighting", category: "cuts", featured: false, sortOrder: 9 },

  // ----- The Studio -----
  { id: "g-chair", url: "/professional-images/chair.jpg", alt: "The chair, green cape with the bear mark", category: "studio", featured: true, sortOrder: 1 },
  { id: "g-wash", url: "/professional-images/chair-wash.jpg", alt: "Studio interior with shampoo chair", category: "studio", featured: false, sortOrder: 2 },
  { id: "g-pops", url: "/professional-images/pops.jpg", alt: "Bape and Funko collection shelf", category: "studio", featured: false, sortOrder: 3 },
  { id: "g-gbj", url: "/professional-images/gbjerseys.jpg", alt: "Signed Quist and Brunson jerseys", category: "studio", featured: false, sortOrder: 4 },
  { id: "g-bwj", url: "/professional-images/bwjerseys.jpg", alt: "Signed Quist and Arringo jerseys", category: "studio", featured: false, sortOrder: 5 },
  { id: "g-door", url: "/professional-images/outsidedoor.jpg", alt: "Studio entrance at Bellazio Collective", category: "studio", featured: false, sortOrder: 6 },
  { id: "g-tedi", url: "/professional-images/tedi-door.jpg", alt: "Tedi outside the studio", category: "studio", featured: true, sortOrder: 7 },
  { id: "g-bellazio", url: "/images/bellazio.jpg", alt: "Bellazio Collective", category: "studio", featured: false, sortOrder: 8 },
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

/** Instagram posts. Each links to the actual post on Instagram. */
export const instagramPosts: InstagramPost[] = [
  { image: "/professional-images/outsidedoor.jpg", caption: "The entrance. Bellazio Collective.", postUrl: "https://www.instagram.com/tedishairstudio/" },
  { image: "/professional-images/greenshirt.jpg", caption: "The Mark Tee. Back print.", postUrl: "https://www.instagram.com/tedishairstudio/" },
  { image: "/professional-images/halloweenshirt.jpg", caption: "Halloween drop. Gone in a week.", postUrl: "https://www.instagram.com/tedishairstudio/" },
  { image: "/professional-images/chair.jpg", caption: "The office.", postUrl: "https://www.instagram.com/tedishairstudio/" },
  { image: "/images/cut1.jpeg", caption: "Fresh out the chair.", postUrl: "https://www.instagram.com/tedishairstudio/" },
  { image: "/professional-images/blueshirt.jpg", caption: "Blue Flame. New drop.", postUrl: "https://www.instagram.com/tedishairstudio/" },
  { image: "/images/cut4.jpeg", caption: "Burst fade, detailed.", postUrl: "https://www.instagram.com/tedishairstudio/" },
  { image: "/professional-images/pops.jpg", caption: "Studio details.", postUrl: "https://www.instagram.com/tedishairstudio/" },
  { image: "/images/cut2.jpeg", caption: "Lineup sharp enough to cut glass.", postUrl: "https://www.instagram.com/tedishairstudio/" },
  { image: "/professional-images/brownshirt.jpg", caption: "Ember Tee. Earth tones.", postUrl: "https://www.instagram.com/tedishairstudio/" },
  { image: "/images/cut5.jpeg", caption: "Low fade, beard blend.", postUrl: "https://www.instagram.com/tedishairstudio/" },
  { image: "/professional-images/yellowshirt.jpg", caption: "Neon Mark. The loud one.", postUrl: "https://www.instagram.com/tedishairstudio/" },
];

/** @deprecated Use instagramPosts instead */
export const instagramFallback = instagramPosts.slice(0, 6).map((p) => ({
  url: p.image,
  caption: p.caption,
}));
