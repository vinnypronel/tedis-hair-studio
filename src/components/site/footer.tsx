"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { BearLogo } from "@/components/site/bear-logo";
import { BookLink } from "@/components/site/book-link";
import { content } from "@/lib/data/content";
import { weeklyHours, formatHour } from "@/lib/data/availability";

const siteMap = [
  { href: "/", label: "Home" },
  { href: "/services", label: "Services" },
  { href: "/reviews", label: "Reviews" },
  { href: "/gallery", label: "Gallery" },
  { href: "/shop", label: "Shirts" },
  { href: "/contact", label: "Contact" },
];

export function Footer() {
  const pathname = usePathname();
  if (pathname.startsWith("/admin")) return null;

  return (
    <footer className="relative overflow-hidden bg-forest-deep text-cream">
      <BearLogo
        size={320}
        className="pointer-events-none absolute -right-[3px] bottom-[96px] text-cream opacity-[0.03] md:top-1/2 md:bottom-auto md:-right-16 md:-translate-y-1/2 md:!h-[620px] md:!w-[620px] md:opacity-[0.05] lg:top-auto lg:bottom-[96px] lg:-right-[3px] lg:translate-y-0 lg:!h-[320px] lg:!w-[320px] lg:opacity-[0.03]"
        label=""
      />
      <div className="mx-auto grid max-w-[1440px] gap-14 px-6 py-20 md:px-12 lg:grid-cols-4 lg:gap-8 lg:px-20">
        {/* Explore / sitemap */}
        <div>
          <h3 className="eyebrow mb-6 text-cream/50">Explore</h3>
          <ul className="flex flex-col gap-3 text-sm text-cream/80">
            {siteMap.map((item) => (
              <li key={item.href}>
                <Link href={item.href} className="link-draw w-fit">
                  {item.label}
                </Link>
              </li>
            ))}
          </ul>
        </div>

        {/* Hours + brand */}
        <div className="flex flex-col">
          <h3 className="eyebrow mb-6 text-cream/50">Hours</h3>
          {/* self-start: the parent is a flex column, so the table would stretch */}
          <table className="self-start text-sm text-cream/70">
            <tbody>
              {weeklyHours.map((d) => (
                <tr key={d.dayOfWeek}>
                  <td className="pr-8 pb-1 align-top font-mono text-[11px] tracking-widest uppercase">
                    {d.label.slice(0, 3)}
                  </td>
                  <td className="pb-1 tabular-nums">
                    {d.open && d.close
                      ? `${formatHour(d.open)} – ${formatHour(d.close)}`
                      : "Closed"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Visit */}
        <div>
          <h3 className="eyebrow mb-6 text-cream/50">Visit</h3>
          <address className="flex flex-col gap-1 text-sm not-italic text-cream/80">
            <span className="mono-micro mb-1 text-cream/50">
              {content.contact.addressInside}
            </span>
            <span>{content.contact.addressLine1}</span>
            <span>{content.contact.addressLine2}</span>
            <a
              href={content.contact.googleMapsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="link-draw mt-2 inline-block w-fit text-cream"
            >
              Get directions
            </a>
            <a href={content.contact.phoneHref} className="link-draw mt-1 w-fit">
              {content.contact.phone}
            </a>
          </address>
        </div>

        {/* Connect */}
        <div>
          <h3 className="eyebrow mb-6 text-cream/50">Connect</h3>
          <ul className="flex flex-col gap-3 text-sm text-cream/80">
            <li>
              <a
                href={content.social.instagram}
                target="_blank"
                rel="noopener noreferrer"
                className="link-draw"
              >
                Instagram · {content.social.instagramHandle}
              </a>
            </li>
            <li>
              <a
                href={content.social.tiktok}
                target="_blank"
                rel="noopener noreferrer"
                className="link-draw"
              >
                TikTok · {content.social.tiktokHandle}
              </a>
            </li>
            <li>
              <a href={`mailto:${content.contact.email}`} className="link-draw">
                {content.contact.email}
              </a>
            </li>
            <li>
              <a href={content.contact.phoneHref} className="link-draw">
                {content.contact.phone}
              </a>
            </li>
          </ul>
        </div>
      </div>

      {/* Brand lockup + Book Now */}
      <div className="mx-auto grid max-w-[1440px] items-center gap-5 px-6 pb-16 md:px-12 lg:grid-cols-3 lg:px-20">
        <div className="flex items-center gap-5">
          <BearLogo size={82} className="text-cream" />
          <span className="font-display text-3xl tracking-tight md:text-[34px]">
            Tedi&rsquo;s Hair Studio
          </span>
        </div>
        <div className="lg:col-start-3">
          <BookLink className="group inline-flex items-center gap-3 rounded-[2px] bg-bone px-7 py-3.5 text-sm font-medium text-forest-deep transition-all duration-300 hover:-translate-y-0.5 hover:translate-x-0.5 hover:bg-forest-deep hover:text-cream">
            Book Now
            <span aria-hidden className="transition-transform duration-300 group-hover:translate-x-1.5">&rarr;</span>
          </BookLink>
        </div>
      </div>

      <div className="hairline-cream-t">
        <div className="mx-auto flex max-w-[1440px] flex-col items-start justify-between gap-3 px-6 py-6 md:flex-row md:items-center md:px-12 lg:px-20">
          <p className="mono-micro text-cream/40">
            © {new Date().getFullYear()} Tedi&rsquo;s Hair Studio
          </p>
          <div className="flex gap-6">
            <Link href="/legal" className="link-draw mono-micro text-cream/40 hover:text-cream/70">
              Privacy & Terms
            </Link>
          </div>
        </div>
      </div>
    </footer>
  );
}

