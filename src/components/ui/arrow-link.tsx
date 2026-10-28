import Link from "next/link";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * Editorial text link: underlined, with an arrow visible on mobile. On larger
 * screens the arrow slides in on hover. Use for "View all services", "Full
 * gallery", "Read all", etc. Pass `external` for off-site links.
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
        className="inline-block translate-x-0 opacity-100 transition-all duration-300 sm:-translate-x-2 sm:opacity-0 sm:group-hover:translate-x-0 sm:group-hover:opacity-100"
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
