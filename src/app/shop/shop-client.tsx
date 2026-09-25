"use client";

import Link from "next/link";
import { useState } from "react";
import { motion } from "motion/react";
import { shirts, type ShirtStatus } from "@/lib/data/shirts";
import { ShirtVisual } from "@/components/shop/shirt-visual";
import { cn } from "@/lib/utils";

type Filter = "all" | "holiday";

const filters: { key: Filter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "holiday", label: "Holiday" },
];

function matches(filter: Filter, shirt: (typeof shirts)[number]): boolean {
  if (filter === "all") return shirt.status !== "archived";
  if (filter === "holiday") {
    return (
      shirt.slug.includes("christmas") ||
      shirt.slug.includes("holiday") ||
      shirt.slug.includes("halloween") ||
      shirt.id === "shirt-holiday" ||
      shirt.id === "shirt-halloween"
    );
  }
  return true;
}

export function ShopClient() {
  const [filter, setFilter] = useState<Filter>("all");
  const visible = shirts
    .filter((s) => matches(filter, s))
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
        className="mt-8 grid gap-x-6 gap-y-12 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4"
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
            </div>
            <p className="mt-4 font-display text-xl tracking-tight">{shirt.name}</p>
          </Link>
        ))}
      </motion.div>
    </div>
  );
}
