"use client";

import { useEffect, useState } from "react";
import { isOpenNow } from "@/lib/data/availability";
import { cn } from "@/lib/utils";

/** Studio-time clock + OPEN/CLOSED pill, computed from weekly hours. */
export function LiveClock({ tone = "cream" }: { tone?: "cream" | "ink" }) {
  const [now, setNow] = useState<Date | null>(null);

  useEffect(() => {
    setNow(new Date());
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  if (!now) {
    return <div className="mono-micro opacity-0">00:00:00 EST</div>;
  }

  const open = isOpenNow(now);
  const time = now.toLocaleTimeString("en-US", {
    timeZone: "America/New_York",
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  return (
    <div
      className={cn(
        "flex items-center gap-3",
        tone === "cream" ? "text-cream/80" : "text-ink/70"
      )}
    >
      <span className="mono-micro tabular-nums">{time} EST</span>
      <span
        className={cn(
          "mono-micro flex items-center gap-1.5 border-[0.5px] px-2 py-1",
          open
            ? "border-current text-neon"
            : tone === "cream"
              ? "border-cream/30 text-cream/60"
              : "border-ink/30 text-ink/50"
        )}
      >
        <span
          className={cn(
            "inline-block size-1.5 rounded-full",
            open ? "bg-neon" : "bg-current opacity-50"
          )}
        />
        {open ? "Open" : "Closed"}
      </span>
    </div>
  );
}
