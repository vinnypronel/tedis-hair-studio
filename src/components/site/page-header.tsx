import { Reveal } from "@/components/site/reveal";
import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

/** Standard editorial page opener: mono eyebrow + display headline + optional sub. */
export function PageHeader({
  eyebrow,
  title,
  sub,
  className,
}: {
  eyebrow: string;
  title: ReactNode;
  sub?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("px-6 pt-36 pb-16 md:px-12 lg:px-20 lg:pt-44 lg:pb-20", className)}>
      <div className="mx-auto max-w-[1440px]">
        <Reveal>
          <p className="eyebrow text-stone-500">{eyebrow}</p>
        </Reveal>
        <Reveal delay={0.1}>
          <h1 className="display-lg mt-6">{title}</h1>
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
