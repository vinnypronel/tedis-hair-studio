import type { Metadata } from "next";
import { PageHeader } from "@/components/site/page-header";
import { Reveal } from "@/components/site/reveal";
import { weeklyHours, formatHour } from "@/lib/data/availability";
import { content } from "@/lib/data/content";
import { ContactForm } from "./contact-form";

export const metadata: Metadata = {
  title: "Contact & Location",
  description:
    "Find Tedi's Hair Studio inside Bellazio Collective. 259 Broad St #103, Matawan NJ 07747. Hours, directions, and contact.",
};

export default function ContactPage() {
  return (
    <div className="pb-24 lg:pb-36">
      <PageHeader eyebrow="Contact" title={<em className="italic">Stop by.</em>} />

      <div className="px-6 md:px-12 lg:px-20">
        <div className="mx-auto grid max-w-[1440px] gap-14 lg:grid-cols-2">
          {/* Left column */}
          <Reveal>
            <p className="mono-micro text-stone-500">{content.contact.addressInside}</p>
            <p className="font-display mt-3 text-3xl tracking-tight md:text-4xl">
              {content.contact.addressLine1}
              <br />
              {content.contact.addressLine2}
            </p>
            <a
              href={content.contact.googleMapsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="link-draw mt-4 inline-block text-sm font-medium"
            >
              Get directions →
            </a>

            <table className="mt-12 text-sm text-stone-700">
              <caption className="eyebrow mb-4 text-left text-stone-500">Hours</caption>
              <tbody>
                {weeklyHours.map((d) => (
                  <tr key={d.dayOfWeek}>
                    <td className="pr-10 pb-2 align-top font-mono text-[11px] tracking-widest uppercase">
                      {d.label}
                    </td>
                    <td className="pb-2 tabular-nums">
                      {d.open && d.close
                        ? `${formatHour(d.open)} – ${formatHour(d.close)}`
                        : "Closed"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div className="mt-12 flex flex-col gap-3 text-sm">
              <a href={content.contact.phoneHref} className="link-draw w-fit font-mono tracking-widest">
                {content.contact.phone}
              </a>
              <a href={`mailto:${content.contact.email}`} className="link-draw w-fit">
                {content.contact.email}
              </a>
              <a
                href={content.social.instagram}
                target="_blank"
                rel="noopener noreferrer"
                className="link-draw w-fit"
              >
                Instagram · {content.social.instagramHandle}
              </a>
              <a
                href={content.social.tiktok}
                target="_blank"
                rel="noopener noreferrer"
                className="link-draw w-fit"
              >
                TikTok · {content.social.tiktokHandle}
              </a>
            </div>
          </Reveal>

          {/* Right column */}
          <Reveal delay={0.15}>
            <div className="hairline relative aspect-video overflow-hidden lg:h-[400px]">
              <iframe
                src={content.contact.mapsEmbedUrl}
                title="Map to Tedi's Hair Studio"
                className="absolute inset-0 size-full border-0 grayscale-[35%]"
                loading="lazy"
                referrerPolicy="no-referrer-when-downgrade"
              />
            </div>
          </Reveal>
        </div>

        {/* Message form */}
        <div className="mx-auto mt-28 max-w-[1440px]">
          <Reveal>
            <p className="eyebrow text-stone-500">Send a message</p>
            <h2 className="heading-2 mt-4">Questions, requests, fix-it jobs.</h2>
          </Reveal>
          <Reveal delay={0.1} className="mt-12 max-w-2xl">
            <ContactForm />
          </Reveal>
        </div>

      </div>
    </div>
  );
}
