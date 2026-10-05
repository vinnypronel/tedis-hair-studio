import type { Metadata } from "next";
import { PageHeader } from "@/components/site/page-header";
import { Reveal, RevealGroup, RevealItem } from "@/components/site/reveal";
import { BearLogo } from "@/components/site/bear-logo";
import { BookLink } from "@/components/site/book-link";
import { services, formatPrice } from "@/lib/data/services";
import { content } from "@/lib/data/content";

export const metadata: Metadata = {
  alternates: { canonical: "/services" },
  title: "Services & Pricing",
  description:
    "The full menu at Tedi's Hair Studio. Haircuts, shape ups, and beard work. Private appointments in Matawan, NJ.",
};

export default function ServicesPage() {
  return (
    <div className="pb-16 lg:pb-24">
      {/* Hero + services fill exactly one viewport */}
      <div className="flex min-h-screen flex-col">
        <div className="px-6 pt-28 pb-3 md:px-12 lg:px-20 lg:pt-32 lg:pb-4">
          <div className="mx-auto flex max-w-[1440px] flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
            <Reveal delay={0.1}>
              <h1 className="font-display text-4xl tracking-tight sm:text-5xl lg:text-[54px]">
                What we do:
              </h1>
            </Reveal>
            <Reveal delay={0.2}>
              <p className="text-sm leading-relaxed text-stone-600 sm:text-right sm:text-base">
                Each cut is 30 mins.
              </p>
            </Reveal>
          </div>
        </div>

        <div className="-mt-2 flex flex-1 flex-col px-6 md:px-12 lg:px-20">
          <div className="mx-auto flex w-full max-w-[1440px] flex-1 flex-col">
            <RevealGroup stagger={0.04} className="flex flex-1 flex-col">
              {services.map((svc) => (
                <RevealItem key={svc.id} className="flex flex-1">
                  <div className="hairline-t group grid w-full flex-1 items-center gap-2 py-5 md:grid-cols-12 md:gap-6 md:py-4">
                    <div className="md:col-span-4 flex flex-wrap items-center gap-3">
                      <h2 className="font-display text-[22px] tracking-tight lg:text-[26px]">
                        {svc.name}
                      </h2>
                      {svc.mostPopular && (
                        <span className="mono-micro inline-block border-[0.5px] border-forest px-2 py-0.5 text-forest text-[10px]">
                          Most booked
                        </span>
                      )}
                    </div>
                    <p className="text-[14px] leading-relaxed text-stone-700 md:col-span-5">
                      {svc.description}
                    </p>
                    <div className="flex items-baseline gap-4 md:col-span-1 md:justify-end">
                      <span className="font-mono text-xl font-medium">{formatPrice(svc.priceCents)}</span>
                    </div>
                    <div className="text-right md:col-span-2">
                      <BookLink className="text-sm font-medium whitespace-nowrap underline underline-offset-4 decoration-ink/40 transition-colors hover:decoration-ink">
                        Book this →
                      </BookLink>
                    </div>
                  </div>
                </RevealItem>
              ))}
            </RevealGroup>
            <div className="hairline-t" />
          </div>
        </div>
      </div>

      <div className="px-6 md:px-12 lg:px-20">
        <div className="mx-auto max-w-[1440px]">
          {/* Notes */}
          <Reveal delay={0.1}>
            <div className="relative mt-20 overflow-hidden bg-forest p-10 text-cream md:p-14">
              <BearLogo
                size={220}
                className="absolute right-12 md:right-24 top-1/2 -translate-y-1/2 text-cream opacity-[0.08]"
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
