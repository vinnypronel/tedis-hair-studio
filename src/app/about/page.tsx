import type { Metadata } from "next";
import Image from "next/image";
import { Reveal, RevealGroup, RevealItem } from "@/components/site/reveal";
import { ButtonLink } from "@/components/ui/button";
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
    <div className="pb-14 md:pb-20 lg:pb-36">
      {/* Intro + portrait */}
      <div className="px-6 pt-24 md:px-12 lg:px-20 lg:pt-32">
        <div className="mx-auto grid max-w-[1440px] gap-x-16 gap-y-10 lg:grid-cols-2 lg:items-start">
          {/* Heading — left, top */}
          <div className="order-1 lg:col-start-1 lg:row-start-1">
            <Reveal>
              <p className="eyebrow text-stone-500">The Barber</p>
            </Reveal>
            <Reveal delay={0.1}>
              <h1 className="display-xl mt-6 italic">Meet Tedi.</h1>
            </Reveal>
          </div>

          {/* Portrait — right, stretched down the full height */}
          <Reveal
            delay={0.15}
            className="order-2 lg:col-start-2 lg:row-start-1 lg:row-span-2 lg:h-full"
          >
            <div className="hairline relative aspect-[3/4] overflow-hidden lg:aspect-auto lg:h-full lg:min-h-[560px]">
              <Image
                src="/professional-images/tedi-door.jpg"
                alt="Tedi standing outside the studio at Bellazio Collective"
                fill
                priority
                sizes="(min-width: 1024px) 50vw, 100vw"
                className="object-cover object-center"
              />
            </div>
            <p className="mono-micro mt-3 text-stone-500">
              Tedi · Outside the studio, Bellazio Collective
            </p>
          </Reveal>

          {/* Bio + quote — left, right under the heading */}
          <Reveal delay={0.2} className="order-3 lg:col-start-1 lg:row-start-2">
            <div className="flex flex-col gap-6 text-xl leading-[1.7] text-stone-700 lg:text-[22px]">
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
            <blockquote className="mt-10 border-l-2 border-forest pl-6 font-display text-2xl leading-snug tracking-tight italic">
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
      <div className="px-6 pt-14 md:px-12 md:pt-20 lg:px-20 lg:pt-36">
        <div className="mx-auto flex max-w-[1440px] flex-col items-start gap-7 lg:flex-row lg:items-center lg:justify-between lg:gap-10">
          <Reveal>
            <p className="eyebrow text-stone-500">Licensed &amp; Certified</p>
            <p className="mt-4 max-w-md text-base leading-relaxed text-stone-700">
              NJ State Board licensed. The certificate is displayed in the studio.
            </p>
          </Reveal>
          <Reveal delay={0.1} className="self-end lg:self-auto">
            <ButtonLink href={content.booking.url} size="large" arrow>
              Book with Tedi
            </ButtonLink>
          </Reveal>
        </div>
      </div>
    </div>
  );
}
