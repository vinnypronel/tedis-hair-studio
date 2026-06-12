"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { BearLogo } from "@/components/site/bear-logo";
import { content } from "@/lib/data/content";
import { weeklyHours, formatHour } from "@/lib/data/availability";

export function Footer() {
  const pathname = usePathname();
  if (pathname.startsWith("/admin")) return null;

  return (
    <footer className="bg-forest-deep text-cream">
      <div className="mx-auto grid max-w-[1440px] gap-14 px-6 py-20 md:px-12 lg:grid-cols-3 lg:gap-8 lg:px-20">
        {/* Brand */}
        <div className="flex flex-col">
          <p className="eyebrow mb-6 text-neon">Appointment only.</p>
          <p className="text-sm leading-relaxed text-cream/70">
            One chair, one barber. A private studio<br />for premium cuts.
          </p>
          <div className="mt-auto flex items-center gap-3 pt-10 lg:pb-[25px]">
            <BearLogo size={60} className="text-cream" />
            <span className="font-display text-2xl tracking-tight">
              Tedi&rsquo;s Hair Studio
            </span>
          </div>
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
          <table className="mt-6 text-sm text-cream/70">
            <tbody>
              {weeklyHours.map((d) => (
                <tr key={d.dayOfWeek}>
                  <td className="pr-6 align-top font-mono text-[11px] tracking-widest uppercase">
                    {d.label.slice(0, 3)}
                  </td>
                  <td className="tabular-nums">
                    {d.open && d.close
                      ? `${formatHour(d.open)} – ${formatHour(d.close)}`
                      : "Closed"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
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
          <Link
            href="/book"
            className="group mt-8 inline-flex items-center gap-3 rounded-[2px] bg-bone px-7 py-3.5 text-sm font-medium text-forest-deep transition-colors duration-300 hover:bg-stone-300"
          >
            Book Now
            <span aria-hidden className="transition-transform duration-300 group-hover:translate-x-1.5">→</span>
          </Link>
        </div>
      </div>

      <div className="hairline-cream-t">
        <div className="mx-auto flex max-w-[1440px] flex-col items-start justify-between gap-3 px-6 py-6 md:flex-row md:items-center md:px-12 lg:px-20">
          <p className="mono-micro text-cream/40">
            © {new Date().getFullYear()} Tedi&rsquo;s Hair Studio · Built with intention
          </p>
          <div className="flex gap-6">
            <Link href="/legal/privacy" className="mono-micro text-cream/40 hover:text-cream/70">
              Privacy
            </Link>
            <Link href="/legal/terms" className="mono-micro text-cream/40 hover:text-cream/70">
              Terms
            </Link>
            <Link href="/admin" className="mono-micro text-cream/40 hover:text-cream/70">
              Studio login
            </Link>
          </div>
        </div>
      </div>
    </footer>
  );
}
