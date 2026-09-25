import type { ReactNode } from "react";
import { content } from "@/lib/data/content";

/**
 * Every booking action on the site opens Tedi's Booksy storefront in a new tab.
 * One component so there is a single place to change if booking ever moves back
 * on-site (see archive/BOOKING-FEATURE.md).
 */
export function BookLink({
  className,
  children,
  onClick,
}: {
  className?: string;
  children: ReactNode;
  onClick?: () => void;
}) {
  return (
    <a
      href={content.booking.url}
      target="_blank"
      rel="noopener noreferrer"
      className={className}
      onClick={onClick}
    >
      {children}
      <span className="sr-only"> (opens {content.booking.provider} in a new tab)</span>
    </a>
  );
}
