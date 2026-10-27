import Link from "next/link";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * Editorial text link: underlined, no arrow by default. On hover it grows a
 * little and an arrow slides in from left to right. Use for "View all services",
 * "Full gallery", "Read all", etc. Pass `external` for off-site links.
 */
export function ArrowLink({
  href,
  children,
  external = false,
  className,
}: {
  href: string;
  children: ReactNode;
  external?: boolean;
  className?: string;
}) {
  const classes = cn(
    "group inline-flex origin-left items-center gap-1.5 text-sm font-medium underline underline-offset-4 decoration-ink/40 transition-all duration-300 hover:scale-110 hover:decoration-ink",
    className
  );
  const inner = (
    <>
      {children}
      <span
        aria-hidden
        className="inline-block -translate-x-2 opacity-0 transition-all duration-300 group-hover:translate-x-0 group-hover:opacity-100"
      >
        →
      </span>
    </>
  );

  if (external) {
    return (
      <a href={href} target="_blank" rel="noopener noreferrer" className={classes}>
        {inner}
      </a>
    );
  }
  return (
    <Link href={href} className={classes}>
      {inner}
    </Link>
  );
}
