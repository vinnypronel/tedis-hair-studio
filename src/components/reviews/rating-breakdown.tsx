"use client";

import { motion, useReducedMotion } from "motion/react";
import { cn } from "@/lib/utils";

/**
 * Star distribution rails. Booksy's own per-rank counts, drawn in the studio's
 * language: squared hairline rails, forest fill, mono numerals. No pills, no
 * traffic-light colors.
 */
export function RatingBreakdown({
  distribution,
  total,
  className,
}: {
  distribution: Record<number, number>;
  total: number;
  className?: string;
}) {
  const reduced = useReducedMotion();
  const rows = [5, 4, 3, 2, 1];

  return (
    <div className={cn("flex flex-col gap-3.5", className)}>
      {rows.map((star, i) => {
        const count = distribution[star] ?? 0;
        const pct = total > 0 ? (count / total) * 100 : 0;
        const empty = count === 0;

        return (
          <div key={star} className="flex items-center gap-5">
            <span
              className={cn(
                "mono-micro flex w-9 shrink-0 items-center gap-1 tabular-nums",
                empty ? "text-stone-500" : "text-ink"
              )}
            >
              {star}
              <span aria-hidden className={empty ? "text-stone-300" : "text-forest"}>
                ★
              </span>
            </span>

            <span className="sr-only">{`${star} star: ${count} of ${total} reviews`}</span>

            <div aria-hidden className="relative h-[7px] flex-1 bg-ink/[0.08]">
              <motion.div
                className="absolute inset-y-0 left-0 bg-forest"
                initial={reduced ? false : { width: 0 }}
                whileInView={{ width: `${pct}%` }}
                viewport={{ once: true, margin: "-80px" }}
                transition={{
                  duration: 1,
                  delay: 0.15 + i * 0.07,
                  ease: [0.22, 1, 0.36, 1],
                }}
                style={reduced ? { width: `${pct}%` } : undefined}
              />
            </div>

            <span
              aria-hidden
              className={cn(
                "mono-micro w-10 shrink-0 text-right tabular-nums",
                empty ? "text-stone-500" : "text-ink"
              )}
            >
              {count}
            </span>
          </div>
        );
      })}
    </div>
  );
}
