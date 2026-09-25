"use client";

import Image from "next/image";
import { useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { getGalleryByCategory, type GalleryCategory, type GalleryImage } from "@/lib/data/gallery";
import { cn } from "@/lib/utils";

const tabs: { key: GalleryCategory; label: string }[] = [
  { key: "cuts", label: "The Work" },
  { key: "studio", label: "The Studio" },
];

function formatTime(seconds: number): string {
  if (isNaN(seconds) || seconds < 0) return "0:00";
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  return `${mins}:${secs.toString().padStart(2, "0")}`;
}

function GalleryVideoTile({
  item,
  onOpenLightbox,
}: {
  item: GalleryImage;
  onOpenLightbox: () => void;
}) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [isPlaying, setIsPlaying] = useState(true);
  const [isMuted, setIsMuted] = useState(true);

  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;

    const observer = new IntersectionObserver(
      (entries) => {
        const entry = entries[0];
        if (entry.isIntersecting && document.visibilityState === "visible") {
          video.play().then(() => setIsPlaying(true)).catch(() => {});
        } else {
          video.pause();
          setIsPlaying(false);
        }
      },
      { threshold: 0.1, rootMargin: "60px 0px 60px 0px" }
    );

    observer.observe(video);

    const onVisibilityChange = () => {
      if (!video) return;
      if (document.hidden) {
        video.pause();
        setIsPlaying(false);
      }
    };

    document.addEventListener("visibilitychange", onVisibilityChange);

    return () => {
      observer.disconnect();
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, []);

  const togglePlay = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!videoRef.current) return;
    if (videoRef.current.paused) {
      videoRef.current.play();
      setIsPlaying(true);
    } else {
      videoRef.current.pause();
      setIsPlaying(false);
    }
  };

  const toggleMute = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!videoRef.current) return;
    videoRef.current.muted = !videoRef.current.muted;
    setIsMuted(videoRef.current.muted);
  };

  return (
    <div
      onClick={onOpenLightbox}
      className="group relative block w-full cursor-pointer overflow-hidden break-inside-avoid"
    >
      <video
        ref={videoRef}
        src={item.url}
        autoPlay
        loop
        muted={isMuted}
        playsInline
        preload="metadata"
        className="aspect-[4/5] h-full w-full object-cover transition-transform duration-500 group-hover:scale-[1.025]"
      />

      {/* Hover Controls Overlay */}
      <div className="absolute inset-0 z-20 flex flex-col justify-end bg-gradient-to-t from-black/85 via-black/20 to-transparent p-3.5 opacity-0 transition-opacity duration-300 group-hover:opacity-100 group-focus-within:opacity-100 [@media(hover:none)]:opacity-100">
        <div className="flex items-center justify-between gap-2 text-cream">
          <div className="flex items-center gap-1.5">
            {/* Play/Pause */}
            <button
              type="button"
              onClick={togglePlay}
              className="flex h-8 w-8 items-center justify-center rounded bg-cream/15 text-cream transition-colors hover:bg-cream/30"
              title={isPlaying ? "Pause" : "Play"}
            >
              {isPlaying ? (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                  <rect x="6" y="4" width="4" height="16" />
                  <rect x="14" y="4" width="4" height="16" />
                </svg>
              ) : (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                  <polygon points="5 3 19 12 5 21 5 3" />
                </svg>
              )}
            </button>

            {/* Mute toggle */}
            <button
              type="button"
              onClick={toggleMute}
              className="flex h-8 w-8 items-center justify-center rounded bg-cream/15 text-cream transition-colors hover:bg-cream/30"
              title={isMuted ? "Unmute" : "Mute"}
            >
              {isMuted ? (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" />
                  <line x1="23" y1="9" x2="17" y2="15" />
                  <line x1="17" y1="9" x2="23" y2="15" />
                </svg>
              ) : (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" />
                  <path d="M19.07 4.93a10 10 0 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07" />
                </svg>
              )}
            </button>
          </div>

          {/* Fullscreen / Popout */}
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              onOpenLightbox();
            }}
            className="flex h-8 items-center gap-1.5 rounded bg-forest px-2.5 font-mono text-[10px] uppercase tracking-wider text-cream transition-colors hover:bg-forest-deep"
            title="Pop out to full screen"
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="15 3 21 3 21 9" />
              <polyline points="9 21 3 21 3 15" />
              <line x1="21" y1="3" x2="14" y2="10" />
              <line x1="3" y1="21" x2="10" y2="14" />
            </svg>
            <span>Pop Out</span>
          </button>
        </div>
      </div>
    </div>
  );
}

function GalleryVideoLightbox({
  item,
  onClose,
}: {
  item: GalleryImage;
  onClose?: () => void;
}) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [isPlaying, setIsPlaying] = useState(true);
  const [isMuted, setIsMuted] = useState(true);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const [isHovered, setIsHovered] = useState(false);

  const togglePlay = () => {
    if (!videoRef.current) return;
    if (videoRef.current.paused) {
      videoRef.current.play();
      setIsPlaying(true);
    } else {
      videoRef.current.pause();
      setIsPlaying(false);
    }
  };

  const handleScrub = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = parseFloat(e.target.value);
    setCurrentTime(val);
    if (videoRef.current) {
      videoRef.current.currentTime = val;
    }
  };

  const toggleMute = () => {
    if (!videoRef.current) return;
    videoRef.current.muted = !videoRef.current.muted;
    setIsMuted(videoRef.current.muted);
  };

  const toggleFullscreen = () => {
    if (!containerRef.current) return;
    if (!document.fullscreenElement) {
      containerRef.current.requestFullscreen?.().catch(() => {});
    } else {
      document.exitFullscreen?.().catch(() => {});
    }
  };

  useEffect(() => {
    const vid = videoRef.current;
    if (!vid) return;

    const onTime = () => setCurrentTime(vid.currentTime);
    const onLoaded = () => setDuration(vid.duration || 0);
    const onEnd = () => {
      vid.currentTime = 0;
      vid.play();
    };

    vid.addEventListener("timeupdate", onTime);
    vid.addEventListener("loadedmetadata", onLoaded);
    vid.addEventListener("ended", onEnd);

    return () => {
      vid.removeEventListener("timeupdate", onTime);
      vid.removeEventListener("loadedmetadata", onLoaded);
      vid.removeEventListener("ended", onEnd);
    };
  }, []);

  return (
    <div
      ref={containerRef}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className="group/player relative mx-auto flex w-fit max-w-full flex-col items-center justify-center overflow-hidden rounded-lg shadow-2xl"
    >
      {/* Top Left: Volume / Mute */}
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          toggleMute();
        }}
        className="absolute top-3.5 left-3.5 z-30 flex h-8 w-8 items-center justify-center rounded-full bg-black/65 text-cream backdrop-blur-md transition-colors hover:bg-black/90 hover:scale-105"
        aria-label={isMuted ? "Unmute audio" : "Mute audio"}
        title={isMuted ? "Unmute" : "Mute"}
      >
        {isMuted ? (
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" />
            <line x1="23" y1="9" x2="17" y2="15" />
            <line x1="17" y1="9" x2="23" y2="15" />
          </svg>
        ) : (
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" />
            <path d="M19.07 4.93a10 10 0 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07" />
          </svg>
        )}
      </button>

      {/* Top Right: Close */}
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          onClose?.();
        }}
        className="absolute top-3.5 right-3.5 z-30 flex h-8 w-8 items-center justify-center rounded-full bg-black/65 text-cream backdrop-blur-md transition-colors hover:bg-black/90 hover:scale-105"
        aria-label="Close video"
        title="Close"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
          <line x1="18" y1="6" x2="6" y2="18" />
          <line x1="6" y1="6" x2="18" y2="18" />
        </svg>
      </button>

      <video
        ref={videoRef}
        src={item.url}
        autoPlay
        loop
        playsInline
        muted={isMuted}
        onClick={togglePlay}
        className="max-h-[82vh] w-auto cursor-pointer rounded-lg object-contain"
      />

      {/* Center Play Button Overlay when paused */}
      {!isPlaying && (
        <button
          onClick={togglePlay}
          className="absolute inset-0 z-10 flex items-center justify-center bg-black/40 text-cream"
        >
          <div className="flex h-11 w-11 items-center justify-center rounded-full bg-forest/90 text-cream shadow-2xl transition-transform hover:scale-110">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
              <polygon points="6 4 20 12 6 20 6 4" />
            </svg>
          </div>
        </button>
      )}

      {/* Player Control Bar (Visible on hover or paused) */}
      <div
        className={cn(
          "absolute right-0 bottom-0 left-0 z-20 flex flex-col gap-1.5 bg-gradient-to-t from-black/95 via-black/70 to-transparent p-3 text-cream transition-opacity duration-300",
          isHovered || !isPlaying ? "opacity-100" : "opacity-0"
        )}
      >
        {/* Scrubber Progress Bar */}
        <input
          type="range"
          min={0}
          max={duration || 100}
          step={0.1}
          value={currentTime}
          onChange={handleScrub}
          className="h-1 w-full cursor-pointer appearance-none rounded-lg bg-cream/30 accent-forest transition-all hover:h-2"
        />

        {/* Buttons and Time */}
        <div className="flex items-center justify-between pt-1">
          <div className="flex items-center gap-3">
            {/* Play / Pause */}
            <button
              onClick={togglePlay}
              className="flex h-7 w-7 items-center justify-center rounded bg-cream/15 text-cream transition-colors hover:bg-cream/30"
              title={isPlaying ? "Pause" : "Play"}
            >
              {isPlaying ? (
                <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor">
                  <rect x="6" y="4" width="4" height="16" />
                  <rect x="14" y="4" width="4" height="16" />
                </svg>
              ) : (
                <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor">
                  <polygon points="5 3 19 12 5 21 5 3" />
                </svg>
              )}
            </button>

            {/* Time */}
            <span className="font-mono text-[10px] text-cream/70">
              {formatTime(currentTime)} / {formatTime(duration)}
            </span>
          </div>

          <div className="flex items-center gap-3">
            {/* Native Fullscreen */}
            <button
              onClick={toggleFullscreen}
              className="flex h-7 w-7 items-center justify-center rounded bg-cream/15 text-cream transition-colors hover:bg-cream/30"
              title="Fullscreen"
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3" />
              </svg>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export function GalleryClient() {
  const [category, setCategory] = useState<GalleryCategory>("cuts");
  const [lightbox, setLightbox] = useState<number | null>(null);
  const lightboxOpen = lightbox !== null;
  const dialogRef = useRef<HTMLDivElement>(null);
  const images = getGalleryByCategory(category);

  useEffect(() => {
    if (!lightboxOpen) return;
    const previousFocus = document.activeElement as HTMLElement | null;
    const previousOverflow = document.documentElement.style.overflow;
    document.documentElement.style.overflow = "hidden";
    const frame = requestAnimationFrame(() => dialogRef.current?.focus());
    const trapFocus = (event: KeyboardEvent) => {
      if (event.key !== "Tab") return;
      const dialog = dialogRef.current;
      const controls = [...(dialog?.querySelectorAll<HTMLElement>('button, input, [tabindex="0"]') ?? [])]
        .filter((element) => element.getClientRects().length > 0);
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog)) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    };
    window.addEventListener("keydown", trapFocus);
    return () => {
      cancelAnimationFrame(frame);
      document.documentElement.style.overflow = previousOverflow;
      window.removeEventListener("keydown", trapFocus);
      previousFocus?.focus({ preventScroll: true });
    };
  }, [lightboxOpen]);

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
      if (e.target instanceof HTMLInputElement) return;
      if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
        e.preventDefault();
        step(e.key === "ArrowRight" ? 1 : -1);
      }
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

      {/* Grid */}
      <motion.div
        key={category}
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
        className="mt-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3"
      >
        {images.map((item, i) =>
          item.type === "video" ? (
            <GalleryVideoTile
              key={item.id}
              item={item}
              onOpenLightbox={() => setLightbox(i)}
            />
          ) : (
            <button
              key={item.id}
              onClick={() => setLightbox(i)}
              className="hairline group relative block w-full overflow-hidden break-inside-avoid"
              aria-label={`View larger: ${item.alt}`}
            >
              <Image
                src={item.url}
                alt={item.alt}
                width={800}
                height={1000}
                sizes="(min-width: 1024px) 33vw, (min-width: 640px) 50vw, 100vw"
                className="aspect-[4/5] h-full w-full object-cover transition-transform duration-500 group-hover:scale-[1.025]"
              />
            </button>
          )
        )}
      </motion.div>

      {/* Lightbox */}
      <AnimatePresence>
        {lightbox !== null && images[lightbox] && (
          <motion.div
            ref={dialogRef}
            tabIndex={-1}
            data-lenis-prevent
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
              onClick={(e) => {
                e.stopPropagation();
                step(-1);
              }}
              className="absolute left-3 z-10 p-4 text-3xl text-cream/70 hover:text-cream md:left-8"
              aria-label="Previous item"
            >
              ←
            </button>

            <motion.div
              key={lightbox}
              initial={{ opacity: 0, scale: 0.97 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.3 }}
              className="relative flex max-h-[85vh] w-full flex-col items-center justify-center"
              onClick={(e) => e.stopPropagation()}
            >
              {images[lightbox].type === "video" ? (
                <GalleryVideoLightbox item={images[lightbox]} onClose={close} />
              ) : (
                <div className="relative w-fit max-w-full">
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      close();
                    }}
                    className="absolute top-3.5 right-3.5 z-30 flex h-8 w-8 items-center justify-center rounded-full bg-black/65 text-cream backdrop-blur-md transition-colors hover:bg-black/90 hover:scale-105"
                    aria-label="Close image"
                    title="Close"
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                      <line x1="18" y1="6" x2="6" y2="18" />
                      <line x1="6" y1="6" x2="18" y2="18" />
                    </svg>
                  </button>
                  <Image
                    src={images[lightbox].url}
                    alt={images[lightbox].alt}
                    width={1400}
                    height={1600}
                    sizes="(min-width: 1024px) 900px, 100vw"
                    className="mx-auto max-h-[82vh] w-auto rounded-lg object-contain shadow-2xl"
                  />
                </div>
              )}
            </motion.div>

            <button
              onClick={(e) => {
                e.stopPropagation();
                step(1);
              }}
              className="absolute right-3 z-10 p-4 text-3xl text-cream/70 hover:text-cream md:right-8"
              aria-label="Next item"
            >
              →
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
