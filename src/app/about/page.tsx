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
      {/* Hero */}
      <div className="px-6 pt-24 md:px-12 lg:px-20 lg:pt-32">
        <div className="mx-auto max-w-[1440px]">
          <Reveal>
            <p className="eyebrow text-stone-500">The Barber</p>
          </Reveal>
          <Reveal delay={0.1}>
            <h1 className="display-xl mt-6 italic">Meet Tedi.</h1>
          </Reveal>
        </div>
      </div>

      <Reveal delay={0.2} className="mt-8 px-6 md:px-12 lg:px-20">
        <div className="mx-auto max-w-[1440px]">
          <div className="hairline relative aspect-[16/10] overflow-hidden md:aspect-[21/9]">
            <Image
              src="/professional-images/tedi-door.jpg"
              alt="Tedi standing outside the studio at Bellazio Collective"
              fill
              priority
              sizes="(min-width: 1440px) 1280px, 100vw"
              className="object-cover object-[center_72%]"
            />
          </div>
          <p className="mono-micro mt-3 text-stone-500">
            Tedi · Outside the studio, Bellazio Collective
          </p>
        </div>
      </Reveal>

      {/* Bio + pull quote */}
      <div className="mt-10 px-6 md:px-12 lg:mt-14 lg:px-20">
        <div className="mx-auto grid max-w-[1440px] gap-14 lg:grid-cols-12">
          <Reveal className="lg:col-span-6 lg:col-start-2">
            <div className="flex flex-col gap-7 text-[17px] leading-[1.75] text-stone-700">
              {about.bio.map((para, i) => (
                <p key={i} className={i === 0 ? "first-letter:font-display first-letter:float-left first-letter:mr-3 first-letter:text-6xl first-letter:leading-[0.85] first-letter:text-ink" : undefined}>
                  {para}
                </p>
              ))}
            </div>
          </Reveal>
          <Reveal delay={0.15} className="lg:col-span-4 lg:col-start-9">
            <blockquote className="font-display border-l-2 border-forest pl-8 text-3xl leading-snug tracking-tight italic lg:sticky lg:top-32">
              &ldquo;{about.pullQuote}&rdquo;
              <footer className="eyebrow mt-3 pl-1 text-left text-stone-500 not-italic lg:mt-6">
                - Tedi
              </footer>
            </blockquote>
          </Reveal>
        </div>
      </div>

      {/* Inside the studio */}
      <div className="mt-12 bg-forest px-6 pt-24 pb-10 text-cream md:px-12 md:pb-24 lg:mt-40 lg:px-20 lg:py-32">
        <div className="mx-auto max-w-[1440px]">
          <Reveal>
            <p className="eyebrow text-cream/50">Inside the Studio</p>
            <h2 className="heading-1 mt-5">A look inside the studio.</h2>
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
