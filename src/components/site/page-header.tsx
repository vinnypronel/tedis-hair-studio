import { Reveal } from "@/components/site/reveal";
import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

/** Standard editorial page opener: optional mono eyebrow + display headline + optional sub. */
export function PageHeader({
  eyebrow,
  title,
  sub,
  compact,
  className,
}: {
  eyebrow?: string;
  title: ReactNode;
  sub?: ReactNode;
  /** Tighter top/bottom padding for pages that should sit higher on the screen. */
  compact?: boolean;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "px-6 md:px-12 lg:px-20",
        compact
          ? "pt-24 pb-10 lg:pt-28 lg:pb-12"
          : "pt-36 pb-16 lg:pt-44 lg:pb-20",
        className
      )}
    >
      <div className="mx-auto max-w-[1440px]">
        {eyebrow && (
          <Reveal>
            <p className="eyebrow text-stone-500">{eyebrow}</p>
          </Reveal>
        )}
        <Reveal delay={0.1}>
          <h1 className={cn("display-lg", eyebrow && "mt-6")}>{title}</h1>
        </Reveal>
        {sub && (
          <Reveal delay={0.2}>
            <p className="mt-6 max-w-lg text-base leading-relaxed text-stone-700">{sub}</p>
          </Reveal>
        )}
      </div>
    </div>
  );
}
