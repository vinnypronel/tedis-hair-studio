import Image from "next/image";
import { BearLogo } from "@/components/site/bear-logo";
import { cn } from "@/lib/utils";
import type { Shirt, ShirtImage } from "@/lib/data/shirts";

const toneStyles: Record<string, { bg: string; mark: string }> = {
  forest: { bg: "bg-forest", mark: "text-cream" },
  ink: { bg: "bg-ink", mark: "text-cream" },
  ember: { bg: "bg-ember", mark: "text-ink" },
  bone: { bg: "bg-bone", mark: "text-forest" },
};

/**
 * Shirt artwork: real photo when one exists, otherwise a colorway card.
 * The bear mark on the cape color, framed like a product flat-lay.
 * Pass `imageIndex` to show an alternate (e.g. hover swaps to back).
 */
export function ShirtVisual({
  shirt,
  imageIndex = 0,
  className,
  sizes = "(min-width: 1024px) 33vw, (min-width: 640px) 50vw, 100vw",
}: {
  shirt: Shirt;
  imageIndex?: number;
  className?: string;
  sizes?: string;
}) {
  const img: ShirtImage | undefined = shirt.images[imageIndex] ?? shirt.images[0];
  if (!img) return null;

  if (img.url) {
    return (
      <Image
        src={img.url}
        alt={img.alt}
        fill
        sizes={sizes}
        style={img.objectPosition ? { objectPosition: img.objectPosition } : undefined}
        className={cn(
          "object-cover transition-transform duration-500 group-hover:scale-[1.03]",
          className
        )}
      />
    );
  }

  const tone = toneStyles[img.tone ?? "bone"];
  return (
    <div
      role="img"
      aria-label={img.alt}
      className={cn(
        "absolute inset-0 flex flex-col items-center justify-center gap-6 transition-transform duration-500 group-hover:scale-[1.02]",
        tone.bg,
        className
      )}
    >
      <BearLogo size={120} className={tone.mark} label="" />
      <span
        className={cn("mono-micro opacity-60", tone.mark)}
      >
        {shirt.drop} · {shirt.releaseYear}
      </span>
    </div>
  );
}
