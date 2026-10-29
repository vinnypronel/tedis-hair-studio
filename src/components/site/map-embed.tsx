"use client";

import { useEffect, useRef, useState } from "react";
import { BearLogo } from "@/components/site/bear-logo";
import { MapBadge } from "@/components/site/map-badge";
import { content } from "@/lib/data/content";

type MapEmbedProps = {
  title: string;
  priority?: boolean;
};

export function MapEmbed({ title, priority = false }: MapEmbedProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [shouldLoad, setShouldLoad] = useState(priority);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    if (priority || shouldLoad) return;

    const container = containerRef.current;
    if (!container || !("IntersectionObserver" in window)) {
      setShouldLoad(true);
      return;
    }

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (!entry.isIntersecting) return;
        setShouldLoad(true);
        observer.disconnect();
      },
      { rootMargin: "1000px 0px" },
    );

    observer.observe(container);
    return () => observer.disconnect();
  }, [priority, shouldLoad]);

  return (
    <div ref={containerRef} className="absolute inset-0">
      {shouldLoad && (
        <iframe
          src={content.contact.mapsEmbedUrl}
          title={title}
          className={`absolute inset-0 size-full border-0 grayscale-[35%] transition-opacity duration-500 ${
            loaded ? "opacity-100" : "opacity-0"
          }`}
          loading="eager"
          referrerPolicy="no-referrer-when-downgrade"
          onLoad={() => setLoaded(true)}
        />
      )}

      <div
        aria-hidden={loaded}
        className={`absolute inset-0 flex items-center justify-center bg-stone-100 transition-opacity duration-500 ${
          loaded ? "pointer-events-none opacity-0" : "opacity-100"
        }`}
      >
        <div className="flex flex-col items-center gap-3 text-center text-forest">
          <BearLogo size={58} label="" />
          <p className="mono-micro text-stone-500">Loading map</p>
        </div>
      </div>

      <MapBadge />
    </div>
  );
}
