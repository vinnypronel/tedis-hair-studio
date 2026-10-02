import type { Metadata } from "next";
import { PageHeader } from "@/components/site/page-header";
import { Reveal } from "@/components/site/reveal";
import { MapBadge } from "@/components/site/map-badge";
import { BearLogo } from "@/components/site/bear-logo";
import { weeklyHours, formatHour } from "@/lib/data/availability";
import { content } from "@/lib/data/content";
import { ContactForm } from "./contact-form";

export const metadata: Metadata = {
  alternates: { canonical: "/contact" },
  title: "Contact & Location",
  description:
    `Find Tedi's Hair Studio inside Bellazio Collective. ${content.contact.addressLine1}, ${content.contact.addressLine2}. Hours, directions, and contact.`,
};

export default function ContactPage() {
  return (
    <div className="pb-24 lg:pb-36">
      <PageHeader title={<em className="italic">Step inside</em>} />

      <div className="px-6 md:px-12 lg:px-20">
        <div className="mx-auto max-w-[1440px]">
          <div className="grid gap-12 xl:grid-cols-12 xl:gap-10 items-start">
            {/* Left section: Address & Contact + Hours */}
            <div className="min-w-0 xl:col-span-6">
              <div className="grid gap-6 sm:grid-cols-2">
                <Reveal>
                  <p className="mono-micro text-stone-500">{content.contact.addressInside}</p>
                  <p className="font-display mt-3 text-2xl md:text-3xl tracking-tight leading-tight">
                    {content.contact.addressLine1},{" "}
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

                  <div className="mt-14 flex flex-col gap-2.5 text-sm">
                    <a href={content.contact.phoneHref} className="contact-drift-link link-draw w-fit font-mono tracking-widest">
                      {content.contact.phone}
                    </a>
                    <a href={`mailto:${content.contact.email}`} className="contact-drift-link link-draw w-fit">
                      {content.contact.email}
                    </a>
                    <a
                      href={content.social.instagram}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="contact-drift-link link-draw w-fit"
                    >
                      Instagram · {content.social.instagramHandle}
                    </a>
                    <a
                      href={content.social.tiktok}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="contact-drift-link link-draw w-fit"
                    >
                      TikTok · {content.social.tiktokHandle}
                    </a>
                  </div>
                </Reveal>

                {/* Hours directly to the right of the address */}
                <Reveal delay={0.1} className="sm:pl-6 lg:pl-8">
                  <p className="eyebrow text-stone-500">Hours</p>
                  <table className="mt-3 text-sm text-stone-700 w-full">
                    <tbody>
                      {weeklyHours.map((d) => (
                        <tr key={d.dayOfWeek}>
                          <td className="pr-3 pb-2.5 align-top font-mono text-[11px] tracking-widest uppercase text-stone-500">
                            {d.label}
                          </td>
                          <td className="pb-2.5 tabular-nums text-right sm:text-left">
                            {d.open && d.close
                              ? `${formatHour(d.open)} – ${formatHour(d.close)}`
                              : "Closed"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </Reveal>
              </div>
            </div>

            {/* Map column: shifted over to the left */}
            <Reveal delay={0.15} className="min-w-0 xl:col-span-6 xl:-mt-52">
              <div className="hairline relative aspect-video w-full overflow-hidden xl:aspect-auto xl:h-[440px]">
                <iframe
                  src={content.contact.mapsEmbedUrl}
                  title="Map to Tedi's Hair Studio"
                  className="absolute inset-0 size-full border-0 grayscale-[35%]"
                  loading="lazy"
                  referrerPolicy="no-referrer-when-downgrade"
                />
                <MapBadge />
              </div>
            </Reveal>
          </div>
        </div>

        {/* Message form */}
        <div className="mx-auto mt-28 max-w-[1440px]">
          <div className="grid gap-12 lg:grid-cols-12 lg:gap-16 items-center">
            <div className="min-w-0 lg:col-span-7">
              <Reveal>
                <h2 className="heading-2">Questions, requests, etc.</h2>
              </Reveal>
              <Reveal delay={0.1} className="mt-12">
                <ContactForm />
              </Reveal>
            </div>

            <div className="hidden min-w-0 lg:flex lg:col-span-5 items-center justify-center">
              <Reveal delay={0.2} className="w-full max-w-[540px]">
                <BearLogo
                  size={540}
                  className="aspect-square !h-auto !w-full rotate-[8deg] text-forest opacity-100 transition-transform duration-700 hover:scale-105"
                  label="Tedi's Hair Studio bear mark"
                />
              </Reveal>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
