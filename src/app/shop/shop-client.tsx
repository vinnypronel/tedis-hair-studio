"use client";

import Link from "next/link";
import { useState } from "react";
import { motion } from "motion/react";
import { shirts, type ShirtStatus } from "@/lib/data/shirts";
import { formatPrice } from "@/lib/data/services";
import { ShirtVisual } from "@/components/shop/shirt-visual";
import { cn } from "@/lib/utils";

type Filter = "all" | "for_sale" | "archive";

const filters: { key: Filter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "for_sale", label: "For Sale" },
  { key: "archive", label: "Archive" },
];

function matches(filter: Filter, status: ShirtStatus): boolean {
  if (filter === "all") return status !== "archived";
  if (filter === "for_sale") return status === "for_sale";
  return status === "display_only" || status === "archived";
}

export function ShopClient() {
  const [filter, setFilter] = useState<Filter>("all");
  const visible = shirts
    .filter((s) => matches(filter, s.status))
    .sort((a, b) => a.sortOrder - b.sortOrder);

  return (
    <div>
      <div className="flex gap-3" role="group" aria-label="Filter shirts">
        {filters.map((f) => (
          <button
            key={f.key}
            onClick={() => setFilter(f.key)}
            aria-pressed={filter === f.key}
            className={cn(
              "rounded-[2px] border-[0.5px] px-4 py-2 font-mono text-[11px] tracking-[0.18em] uppercase transition-colors duration-300",
              filter === f.key
                ? "border-forest bg-forest text-cream"
                : "border-ink/30 text-stone-700 hover:border-ink hover:text-ink"
            )}
          >
            {f.label}
          </button>
        ))}
      </div>

      <motion.div
        key={filter}
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
        className="mt-12 grid gap-x-6 gap-y-14 sm:grid-cols-2 lg:grid-cols-3"
      >
        {visible.map((shirt) => (
          <Link key={shirt.id} href={`/shop/${shirt.slug}`} className="group block">
            <div className="hairline relative aspect-[4/5] overflow-hidden bg-stone-100">
              {/* front */}
              <div
                className={cn(
                  "absolute inset-0 transition-opacity duration-500",
                  shirt.images.length > 1 && "group-hover:opacity-0"
                )}
              >
                <ShirtVisual shirt={shirt} imageIndex={0} />
              </div>
              {/* back image on hover */}
              {shirt.images.length > 1 && (
                <div className="absolute inset-0 opacity-0 transition-opacity duration-500 group-hover:opacity-100">
                  <ShirtVisual shirt={shirt} imageIndex={1} />
                </div>
              )}
              {shirt.status !== "for_sale" && (
                <span className="mono-micro absolute top-4 left-4 z-10 bg-ink px-2 py-1 text-cream">
                  Archive
                </span>
              )}
            </div>
            <div className="mt-4 flex items-baseline justify-between">
              <span className="font-display text-xl tracking-tight">{shirt.name}</span>
              <span className="font-mono text-sm">
                {shirt.status === "for_sale" ? formatPrice(shirt.priceCents) : "Sold out"}
              </span>
            </div>
            <p className="mono-micro mt-1 text-stone-500">
              {shirt.drop} · {shirt.releaseYear}
            </p>
          </Link>
        ))}
      </motion.div>
    </div>
  );
}
