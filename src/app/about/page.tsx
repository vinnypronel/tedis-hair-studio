import type { Metadata } from "next";
import Image from "next/image";
import Link from "next/link";
import { BearLogo } from "@/components/site/bear-logo";
import { Reveal, RevealGroup, RevealItem } from "@/components/site/reveal";
import { content } from "@/lib/data/content";

export const metadata: Metadata = {
  alternates: { canonical: "/about" },
  title: "Meet Tedi",
  description:
    "Meet Tedi and see his private barber studio inside Bellazio Collective in Matawan, NJ.",
};

export default function AboutPage() {
  const { about } = content;

  return (
    <div className="pb-14 md:pb-20 lg:pb-0">
      {/* Intro + portrait */}
      <div className="px-6 pt-24 md:px-12 lg:px-20 lg:pt-32">
        <div className="mx-auto grid max-w-[1440px] gap-x-16 gap-y-10 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)] lg:items-start lg:gap-y-6">
          {/* Heading — left, top */}
          <div className="order-1 lg:col-start-1 lg:row-start-1">
            <Reveal>
              <h1 className="display-xl italic lg:text-[clamp(72px,7vw,112px)]">
                Meet Tedi.
              </h1>
            </Reveal>
          </div>

          {/* Portrait — right, stretched down the full height */}
          <Reveal
            delay={0.15}
            className="order-2 lg:col-start-2 lg:row-start-1 lg:row-span-2 lg:-mt-4 lg:h-full"
          >
            <p className="mono-micro mb-3 text-stone-500">
              Tedi, outside the studio @ Bellazio Collective
            </p>
            <div className="hairline relative aspect-[3/4] overflow-hidden lg:aspect-auto lg:h-[calc(100svh-15rem)] lg:min-h-[560px] lg:max-h-[700px]">
              <Image
                src="/professional-images/tedi-door.jpg"
                alt="Tedi standing outside the studio at Bellazio Collective"
                fill
                priority
                sizes="(min-width: 1024px) 50vw, 100vw"
                className="object-cover object-[center_80%]"
              />
            </div>
          </Reveal>

          {/* Bio + quote — left, right under the heading */}
          <Reveal delay={0.2} className="order-3 lg:col-start-1 lg:row-start-2">
            <div className="flex max-w-[620px] flex-col gap-6 text-xl leading-[1.7] text-stone-700 lg:gap-5 lg:text-xl lg:leading-[1.6]">
              {about.bio.map((para, i) => (
                <p
                  key={i}
                  className={
                    i === 0
                      ? "first-letter:font-display first-letter:float-left first-letter:mr-3 first-letter:text-7xl first-letter:leading-[0.8] first-letter:text-ink"
                      : undefined
                  }
                >
                  {para}
                </p>
              ))}
            </div>
            <blockquote className="mt-10 border-l-2 border-forest pl-6 font-display text-2xl leading-snug tracking-tight italic lg:mt-6 lg:text-xl">
              &ldquo;{about.pullQuote}&rdquo;
              <footer className="eyebrow mt-4 text-stone-500 not-italic">- Tedi</footer>
            </blockquote>
          </Reveal>
        </div>
      </div>

      {/* Inside the studio */}
      <div className="mt-12 bg-forest px-6 pt-12 pb-10 text-cream md:px-12 md:pb-24 md:pt-16 lg:mt-40 lg:px-20 lg:pb-32 lg:pt-16">
        <div className="mx-auto max-w-[1440px]">
          <Reveal>
            <h2 className="heading-1">A look inside the studio.</h2>
          </Reveal>
          <RevealGroup className="mt-16 grid gap-6 sm:grid-cols-2 lg:grid-cols-3" stagger={0.08}>
            {about.objects.map((obj) => (
              <RevealItem key={obj.name}>
                <figure>
                  <div className="hairline-cream relative aspect-square overflow-hidden">
                    <Image
                      src={obj.image}
                      alt={obj.name}
                      fill
                      sizes="(min-width: 1024px) 25vw, (min-width: 640px) 50vw, 100vw"
                      className="object-cover transition-transform duration-500 hover:scale-[1.04]"
                    />
                  </div>
                  <figcaption className="mt-4">
                    <p className="font-display text-lg tracking-tight">{obj.name}</p>
                    <p className="mt-1 text-sm text-cream/60">{obj.note}</p>
                  </figcaption>
                </figure>
              </RevealItem>
            ))}
          </RevealGroup>
        </div>
      </div>

      {/* Credentials + CTA */}
      <div className="relative px-6 pt-14 md:px-12 md:pt-20 lg:px-20 lg:py-20">
        <div className="pointer-events-none absolute top-1/2 left-1/2 hidden -translate-x-1/2 -translate-y-1/2 lg:block">
          <Reveal>
            <BearLogo size={260} className="text-forest" label="" />
          </Reveal>
        </div>
        <div className="mx-auto flex max-w-[1440px] flex-col items-start gap-7 lg:flex-row lg:items-center lg:justify-between lg:gap-10">
          <Reveal>
            <p className="eyebrow text-stone-500">Licensed &amp; Certified</p>
            <p className="mt-4 max-w-md text-base leading-relaxed text-stone-700">
              NJ State Board licensed. The certificate is
              <br />
              displayed in the studio.
            </p>
          </Reveal>
          <Reveal delay={0.1} className="self-end lg:self-auto">
            <Link
              href="/services"
              className="group inline-flex items-center gap-3 rounded-[2px] border border-transparent bg-forest px-9 py-4 text-base font-medium tracking-wide text-cream transition-all duration-300 hover:-translate-y-0.5 hover:translate-x-0.5 hover:border-forest hover:bg-cream hover:text-forest"
            >
              View all services
              <span aria-hidden className="transition-transform duration-300 group-hover:translate-x-1">
                →
              </span>
            </Link>
          </Reveal>
        </div>
      </div>
    </div>
  );
}
