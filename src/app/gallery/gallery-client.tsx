"use client";

import Image from "next/image";
import { useCallback, useEffect, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { getGalleryByCategory, type GalleryCategory } from "@/lib/data/gallery";
import { cn } from "@/lib/utils";

const tabs: { key: GalleryCategory; label: string }[] = [
  { key: "cuts", label: "The Work" },
  { key: "studio", label: "The Studio" },
];

export function GalleryClient() {
  const [category, setCategory] = useState<GalleryCategory>("cuts");
  const [lightbox, setLightbox] = useState<number | null>(null);
  const images = getGalleryByCategory(category);

  const close = useCallback(() => setLightbox(null), []);
  const step = useCallback(
    (dir: 1 | -1) => {
      setLightbox((cur) =>
        cur === null ? null : (cur + dir + images.length) % images.length
      );
    },
    [images.length]
  );

  useEffect(() => {
    if (lightbox === null) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
      if (e.key === "ArrowRight") step(1);
      if (e.key === "ArrowLeft") step(-1);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [lightbox, close, step]);

  return (
    <div>
      {/* Tabs */}
      <div className="flex gap-10">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => {
              setCategory(tab.key);
              setLightbox(null);
            }}
            className={cn(
              "font-display relative pb-2 text-2xl tracking-tight transition-colors md:text-3xl",
              category === tab.key ? "text-ink" : "text-stone-300 hover:text-stone-500"
            )}
            aria-pressed={category === tab.key}
          >
            {tab.label}
            {category === tab.key && (
              <motion.span
                layoutId="gallery-tab"
                className="absolute right-0 -bottom-px left-0 h-0.5 bg-forest"
              />
            )}
          </button>
        ))}
      </div>

      {/* Masonry */}
      <motion.div
        key={category}
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
        className="mt-12 columns-1 gap-4 sm:columns-2 lg:columns-3 [&>button]:mb-4"
      >
        {images.map((img, i) => (
          <button
            key={img.id}
            onClick={() => setLightbox(i)}
            className="hairline group relative block w-full overflow-hidden break-inside-avoid"
            aria-label={`View larger: ${img.alt}`}
          >
            <Image
              src={img.url}
              alt={img.alt}
              width={800}
              height={img.featured ? 1100 : 900}
              sizes="(min-width: 1024px) 33vw, (min-width: 640px) 50vw, 100vw"
              className={cn(
                "h-auto w-full object-cover transition-transform duration-500 group-hover:scale-[1.025]",
                img.featured ? "aspect-[3/4]" : "aspect-[4/5]"
              )}
            />
          </button>
        ))}
      </motion.div>

      {/* Lightbox */}
      <AnimatePresence>
        {lightbox !== null && images[lightbox] && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[70] flex items-center justify-center bg-ink/80 p-6 backdrop-blur-md"
            onClick={close}
            role="dialog"
            aria-modal="true"
            aria-label={images[lightbox].alt}
          >
            <button
              onClick={close}
              className="mono-micro absolute top-6 right-6 z-10 p-3 text-cream/80 hover:text-cream"
              aria-label="Close"
            >
              Close ✕
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                step(-1);
              }}
              className="absolute left-3 z-10 p-4 text-3xl text-cream/70 hover:text-cream md:left-8"
              aria-label="Previous image"
            >
              ←
            </button>
            <motion.div
              key={lightbox}
              initial={{ opacity: 0, scale: 0.97 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.3 }}
              className="relative max-h-[85vh] w-full max-w-4xl"
              onClick={(e) => e.stopPropagation()}
            >
              <Image
                src={images[lightbox].url}
                alt={images[lightbox].alt}
                width={1400}
                height={1600}
                sizes="(min-width: 1024px) 900px, 100vw"
                className="mx-auto max-h-[80vh] w-auto object-contain"
              />
              <p className="mono-micro mt-4 text-center text-cream/70">
                {images[lightbox].alt} · {lightbox + 1} / {images.length}
              </p>
            </motion.div>
            <button
              onClick={(e) => {
                e.stopPropagation();
                step(1);
              }}
              className="absolute right-3 z-10 p-4 text-3xl text-cream/70 hover:text-cream md:right-8"
              aria-label="Next image"
            >
              →
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
