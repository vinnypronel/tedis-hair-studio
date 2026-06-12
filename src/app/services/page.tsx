import type { Metadata } from "next";
import Link from "next/link";
import { PageHeader } from "@/components/site/page-header";
import { Reveal, RevealGroup, RevealItem } from "@/components/site/reveal";
import { BearLogo } from "@/components/site/bear-logo";
import { services, formatPrice } from "@/lib/data/services";
import { content } from "@/lib/data/content";

export const metadata: Metadata = {
  title: "Services & Pricing",
  description:
    "The full menu at Tedi's Hair Studio. Haircuts, shape ups, and beard work. Private appointments in Matawan, NJ.",
};

export default function ServicesPage() {
  return (
    <div className="pb-24 lg:pb-36">
      <PageHeader
        eyebrow="Our Services"
        title="Every cut, considered."
        sub="Five services. Each one private, each one given its full time. Pick yours and the calendar does the rest."
      />

      <div className="px-6 md:px-12 lg:px-20">
        <div className="mx-auto max-w-[1440px]">
          <RevealGroup stagger={0.08}>
            {services.map((svc) => (
              <RevealItem key={svc.id}>
                <div className="hairline-t group grid items-baseline gap-3 py-9 md:grid-cols-12 md:gap-8">
                  <div className="md:col-span-4">
                    <h2 className="font-display text-3xl tracking-tight md:text-4xl">
                      {svc.name}
                    </h2>
                    {svc.mostPopular && (
                      <span className="mono-micro mt-3 inline-block border-[0.5px] border-forest px-2 py-1 text-forest">
                        Most booked
                      </span>
                    )}
                  </div>
                  <p className="text-sm leading-relaxed text-stone-700 md:col-span-4">
                    {svc.description}
                  </p>
                  <div className="flex items-baseline gap-8 md:col-span-2 md:justify-end">
                    <span className="font-mono text-xs tracking-widest text-stone-500 uppercase">
                      {svc.durationMinutes} min
                    </span>
                    <span className="font-mono text-xl">{formatPrice(svc.priceCents)}</span>
                  </div>
                  <div className="md:col-span-2 md:text-right">
                    <Link
                      href={`/book?service=${svc.slug}`}
                      className="link-draw text-sm font-medium whitespace-nowrap"
                    >
                      Book this →
                    </Link>
                  </div>
                </div>
              </RevealItem>
            ))}
          </RevealGroup>
          <div className="hairline-t" />

          {/* Notes */}
          <Reveal delay={0.1}>
            <div className="relative mt-20 overflow-hidden bg-forest p-10 text-cream md:p-14">
              <BearLogo
                size={220}
                className="absolute -right-8 -bottom-10 text-cream opacity-[0.06]"
                label=""
              />
              <p className="eyebrow text-cream/50">House Notes</p>
              <ul className="mt-8 flex max-w-2xl flex-col gap-4">
                {content.servicesNotes.map((note, i) => (
                  <li key={i} className="flex gap-4 text-sm leading-relaxed text-cream/85">
                    <span className="font-mono text-xs text-cream/40">
                      {String(i + 1).padStart(2, "0")}
                    </span>
                    {note}
                  </li>
                ))}
              </ul>
            </div>
          </Reveal>
        </div>
      </div>
    </div>
  );
}
