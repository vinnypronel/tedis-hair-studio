import { BearLogo } from "@/components/site/bear-logo";
import { content } from "@/lib/data/content";

export function MapBadge({ className = "" }: { className?: string }) {
  return (
    <a
      href={content.contact.googleMapsUrl}
      target="_blank"
      rel="noopener noreferrer"
      className={`group absolute right-4 bottom-4 left-4 z-10 flex max-w-[440px] items-center overflow-hidden rounded-[6px] bg-cream text-ink shadow-[0_16px_40px_rgba(11,11,11,0.18)] transition-transform duration-300 hover:-translate-y-0.5 ${className}`}
      aria-label="Open directions to Tedi's Hair Studio"
    >
      <span className="m-3 flex size-[52px] shrink-0 items-center justify-center rounded-full bg-ink text-cream">
        <BearLogo size={38} label="" />
      </span>
      <span className="min-w-0 flex-1 py-3 pr-4">
        <span className="block truncate font-display text-xl leading-tight tracking-tight">
          Tedi&rsquo;s Hair Studio
        </span>
        <span className="mt-1 block truncate text-sm leading-tight text-stone-500">
          {content.contact.addressLine1}, {content.contact.addressLine2}
        </span>
      </span>
      <span className="flex h-[68px] w-[60px] shrink-0 items-center justify-center border-l-[0.5px] border-ink/10 text-stone-500 transition-colors duration-300 group-hover:text-forest">
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="size-6"
          aria-hidden
        >
          <path d="M19 5 5 11.5l6 1.5 1.5 6L19 5Z" />
        </svg>
      </span>
    </a>
  );
}
