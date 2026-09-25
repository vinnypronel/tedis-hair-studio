"use client";

import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";

interface InViewVideoProps extends React.VideoHTMLAttributes<HTMLVideoElement> {
  src: string;
  className?: string;
  autoPlayWhenInView?: boolean;
}

export function InViewVideo({
  src,
  className,
  autoPlayWhenInView = true,
  muted = true,
  loop = true,
  playsInline = true,
  preload = "metadata",
  ...rest
}: InViewVideoProps) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [isInView, setIsInView] = useState(false);

  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;

    // IntersectionObserver to detect when video enters/leaves viewport
    const observer = new IntersectionObserver(
      (entries) => {
        const entry = entries[0];
        const visible = entry.isIntersecting;
        setIsInView(visible);

        if (visible && autoPlayWhenInView && document.visibilityState === "visible") {
          video.play().catch(() => {
            // Autoplay policies might silently fail if not interacted, ignore
          });
        } else {
          video.pause();
        }
      },
      {
        threshold: 0.1, // Trigger when 10% visible
        rootMargin: "50px 0px 50px 0px", // Small buffer
      }
    );

    observer.observe(video);

    // Visibility change handler for browser tab switching
    const handleVisibilityChange = () => {
      if (!video) return;
      if (document.hidden) {
        video.pause();
      } else if (isInView && autoPlayWhenInView) {
        video.play().catch(() => {});
      }
    };

    document.addEventListener("visibilitychange", handleVisibilityChange);

    return () => {
      observer.disconnect();
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [autoPlayWhenInView, isInView]);

  return (
    <video
      ref={videoRef}
      src={src}
      muted={muted}
      loop={loop}
      playsInline={playsInline}
      preload={preload}
      className={cn(className)}
      {...rest}
    />
  );
}
