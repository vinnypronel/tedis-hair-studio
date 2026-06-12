import Image from "next/image";
import Link from "next/link";
import { Reveal, RevealGroup, RevealItem } from "@/components/site/reveal";
import { BearLogo } from "@/components/site/bear-logo";
import { services, formatPrice } from "@/lib/data/services";
import { getFeaturedReviews, reviewStats } from "@/lib/data/reviews";
import { getVisibleShirts } from "@/lib/data/shirts";
import { marqueeImages, instagramPosts } from "@/lib/data/gallery";
import { weeklyHours, formatHour } from "@/lib/data/availability";
import { content } from "@/lib/data/content";
import { ShirtVisual } from "@/components/shop/shirt-visual";

/* ------------------------------------------------------------------ */
/* 2. INTRO STRIP                                                      */
/* ------------------------------------------------------------------ */

export function IntroStrip() {
  return (
    <section className="bg-forest px-6 py-10 text-cream md:px-12 lg:px-20 lg:py-14">
      <div className="mx-auto max-w-[1440px]">
        <Reveal>
          <p className="eyebrow text-cream/50">01 · The Studio</p>
        </Reveal>
        <Reveal delay={0.1}>
          <p className="display-lg mx-auto mt-12 max-w-4xl text-center italic">
            One cut at a time.
          </p>
        </Reveal>
        <Reveal delay={0.2}>
          <div className="mt-14 flex flex-wrap items-center justify-center gap-x-10 gap-y-3">
            <span className="eyebrow text-cream/60">Est. {content.meta.established}</span>
            <span aria-hidden className="hidden size-1 rounded-full bg-cream/30 sm:block" />
            <span className="eyebrow text-cream/60">1 Chair</span>
            <span aria-hidden className="hidden size-1 rounded-full bg-cream/30 sm:block" />
            <span className="eyebrow text-cream/60">Appointment only</span>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* 3. SERVICES TEASER                                                  */
/* ------------------------------------------------------------------ */

export function ServicesTeaser() {
  const featured = services.slice(0, 3);
  return (
    <section className="px-6 py-24 md:px-12 lg:px-20 lg:py-36">
      <div className="mx-auto max-w-[1440px]">
        <div className="grid gap-12 lg:grid-cols-12">
          <div className="lg:col-span-4">
            <Reveal>
              <p className="eyebrow text-stone-500">02 · Services</p>
              <h2 className="heading-1 mt-5">What we do</h2>
              <p className="mt-6 max-w-sm text-sm leading-relaxed text-stone-700">
                Five services, no filler. Every appointment is private and
                every cut gets the full duration it deserves.
              </p>
              <Link href="/services" className="link-draw mt-8 inline-block text-sm font-medium">
                See full menu →
              </Link>
            </Reveal>
          </div>
          <RevealGroup className="lg:col-span-8" stagger={0.08}>
            {featured.map((svc) => (
              <RevealItem key={svc.id}>
                <Link
                  href={`/book?service=${svc.slug}`}
                  className="hairline-t group flex flex-wrap items-baseline justify-between gap-3 py-7 transition-colors duration-300 hover:bg-stone-100/60 sm:flex-nowrap sm:gap-8 sm:px-4"
                >
                  <div className="min-w-0">
                    <span className="font-display text-2xl tracking-tight md:text-3xl">
                      {svc.name}
                    </span>
                    {svc.mostPopular && (
                      <span className="mono-micro ml-4 border-[0.5px] border-forest px-2 py-1 align-middle text-forest">
                        Most booked
                      </span>
                    )}
                    <p className="mt-1.5 hidden max-w-md truncate text-sm text-stone-500 md:block">
                      {svc.description}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-baseline gap-6">
                    <span className="font-mono text-xs tracking-widest text-stone-500 uppercase">
                      {svc.durationMinutes} min
                    </span>
                    <span className="font-mono text-lg">{formatPrice(svc.priceCents)}</span>
                    <span
                      aria-hidden
                      className="text-stone-500 transition-transform duration-300 group-hover:translate-x-1 group-hover:text-ink"
                    >
                      →
                    </span>
                  </div>
                </Link>
              </RevealItem>
            ))}
            <div className="hairline-t" />
          </RevealGroup>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* 4. PORTFOLIO MARQUEE                                                */
/* ------------------------------------------------------------------ */

export function PortfolioMarquee() {
  const doubled = [...marqueeImages, ...marqueeImages];
  return (
    <section id="the-work" className="overflow-hidden pb-24 lg:pb-36">
      <Reveal className="px-6 md:px-12 lg:px-20">
        <div className="mx-auto flex max-w-[1440px] items-baseline justify-between">
          <p className="eyebrow text-stone-500">The work, in motion</p>
          <Link href="/gallery" className="link-draw text-sm font-medium">
            Full gallery →
          </Link>
        </div>
      </Reveal>
      <div className="mt-10">
        <div className="marquee-track gap-4">
          {doubled.map((img, i) => (
            <Link
              key={`${img.id}-${i}`}
              href="/gallery"
              className="hairline relative block h-[400px] w-[320px] shrink-0 overflow-hidden"
              tabIndex={i >= marqueeImages.length ? -1 : 0}
              aria-hidden={i >= marqueeImages.length}
            >
              <Image
                src={img.url}
                alt={i >= marqueeImages.length ? "" : img.alt}
                fill
                sizes="320px"
                className="object-cover transition-transform duration-500 hover:scale-[1.03]"
              />
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* 5. THE BEAR                                                         */
/* ------------------------------------------------------------------ */

export function BrandStory() {
  return (
    <section className="bg-ink text-cream">
      <div className="grid lg:grid-cols-2">
        <div className="relative min-h-[420px] lg:min-h-[640px]">
          <Image
            src="/professional-images/chair-wash.jpg"
            alt="Inside the studio, the cape with the bear mark"
            fill
            sizes="(min-width: 1024px) 50vw, 100vw"
            className="object-cover"
          />
          <div className="absolute inset-0 bg-ink/20" />
        </div>
        <div className="relative flex flex-col justify-center px-6 py-24 md:px-12 lg:px-20 lg:py-32">
          <BearLogo
            size={280}
            className="absolute right-0 bottom-0 text-cream opacity-[0.05]"
            label=""
          />
          <Reveal>
            <p className="eyebrow text-cream/50">03 · The Mark</p>
          </Reveal>
          <Reveal delay={0.1}>
            <h2 className="heading-1 mt-5">Stitched with character</h2>
          </Reveal>
          <Reveal delay={0.2}>
            <p className="mt-8 max-w-xl text-base leading-relaxed text-cream/80">
              {content.brand.story}
            </p>
          </Reveal>
          <Reveal delay={0.3}>
            <div className="mt-10 flex items-center gap-4">
              <BearLogo size={56} className="text-cream" label="The bear and pole mark" />
              <span className="mono-micro text-cream/50">
                The bear · The pole · The X-stitch
              </span>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* 5b. THE SPACE                                                       */
/* ------------------------------------------------------------------ */

export function SpaceStory() {
  return (
    <section className="px-6 py-24 md:px-12 lg:px-20 lg:py-36">
      <div className="mx-auto grid max-w-[1440px] items-center gap-14 lg:grid-cols-12">
        <div className="lg:col-span-5 lg:col-start-1">
          <Reveal>
            <p className="eyebrow text-stone-500">04 · The Space</p>
          </Reveal>
          <Reveal delay={0.1}>
            <h2 className="heading-1 mt-5 italic">Inside Bellazio Collective.</h2>
          </Reveal>
          <Reveal delay={0.2}>
            <p className="mt-8 max-w-lg text-base leading-relaxed text-stone-700">
              {content.space.story}
            </p>
          </Reveal>
          <Reveal delay={0.3}>
            <p className="mono-micro mt-10 text-stone-500">
              259 Broad St #103 · Matawan, NJ
            </p>
          </Reveal>
        </div>
        <Reveal delay={0.15} className="lg:col-span-6 lg:col-start-7">
          <div className="hairline relative aspect-[4/5] overflow-hidden lg:translate-y-8">
            <Image
              src="/professional-images/outsidedoor.jpg"
              alt="The studio entrance at Bellazio Collective"
              fill
              sizes="(min-width: 1024px) 45vw, 100vw"
              className="object-cover"
            />
          </div>
        </Reveal>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* 6. REVIEWS PREVIEW                                                  */
/* ------------------------------------------------------------------ */

export function ReviewsPreview() {
  const featured = getFeaturedReviews();
  return (
    <section className="bg-stone-100 px-6 py-24 md:px-12 lg:px-20 lg:py-36">
      <div className="mx-auto max-w-[1440px]">
        <Reveal>
          <p className="eyebrow text-stone-500">05 · What They&rsquo;re Saying</p>
          <h2 className="heading-1 mt-5">Five stars, on repeat.</h2>
        </Reveal>
        <RevealGroup className="mt-14 grid gap-6 md:grid-cols-3" stagger={0.1}>
          {featured.map((review) => (
            <RevealItem key={review.id} className="flex">
              <figure className="hairline-strong flex flex-col bg-cream p-8">
                <span aria-hidden className="font-display text-6xl leading-none text-forest">
                  &ldquo;
                </span>
                <blockquote className="mt-2 flex-1 text-[15px] leading-relaxed text-stone-700">
                  {review.text}
                </blockquote>
                <figcaption className="mono-micro mt-8 text-stone-500">
                  {review.authorName} · via Booksy ·{" "}
                  {new Date(review.sourceDate + "T12:00:00").toLocaleDateString("en-US", {
                    month: "short",
                    year: "numeric",
                  })}
                </figcaption>
              </figure>
            </RevealItem>
          ))}
        </RevealGroup>
        <Reveal delay={0.2}>
          <div className="mt-14 flex flex-wrap items-center justify-between gap-6">
            <p className="font-mono text-sm tracking-widest">
              <span className="text-forest">★★★★★</span>
              <span className="ml-4 text-stone-500">
                {reviewStats.count} five-star reviews
              </span>
            </p>
            <Link href="/reviews" className="link-draw text-sm font-medium">
              Read all →
            </Link>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* 7. SHOP TEASER                                                      */
/* ------------------------------------------------------------------ */

export function ShopTeaser() {
  const featured = getVisibleShirts().slice(0, 3);
  return (
    <section className="px-6 py-24 md:px-12 lg:px-20 lg:py-36">
      <div className="mx-auto max-w-[1440px]">
        <div className="flex flex-wrap items-end justify-between gap-6">
          <Reveal>
            <p className="eyebrow text-stone-500">06 · The Shop</p>
            <h2 className="heading-1 mt-5">Rep the studio.</h2>
          </Reveal>
          <Reveal delay={0.1}>
            <Link href="/shop" className="link-draw text-sm font-medium">
              View our tees →
            </Link>
          </Reveal>
        </div>
        <RevealGroup className="mt-14 grid gap-6 sm:grid-cols-2 lg:grid-cols-3" stagger={0.1}>
          {featured.map((shirt) => (
            <RevealItem key={shirt.id}>
              <Link href={`/shop/${shirt.slug}`} className="group block">
                <div className="hairline relative aspect-[4/5] overflow-hidden bg-stone-100">
                  <ShirtVisual shirt={shirt} />
                  {shirt.status === "display_only" && (
                    <span className="mono-micro absolute top-4 left-4 bg-ink px-2 py-1 text-cream">
                      Archive
                    </span>
                  )}
                </div>
                <div className="mt-4 flex items-baseline justify-between">
                  <span className="font-display text-xl tracking-tight">{shirt.name}</span>
                  <span className="font-mono text-sm">
                    {shirt.status === "for_sale" ? formatPrice(shirt.priceCents) : "Sold out"}
                  </span>
                </div>
                <p className="mono-micro mt-1 text-stone-500">{shirt.drop}</p>
              </Link>
            </RevealItem>
          ))}
        </RevealGroup>
        <Reveal delay={0.2}>
          <p className="mt-12 text-sm text-stone-500">{content.shop.note}</p>
        </Reveal>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* 8. INSTAGRAM STRIP                                                  */
/* ------------------------------------------------------------------ */

export function InstagramStrip() {
  return (
    <section className="px-6 pb-24 md:px-12 lg:px-20 lg:pb-36">
      <div className="mx-auto max-w-[1440px]">
        <Reveal>
          <div className="flex flex-wrap items-baseline justify-between gap-4">
            <p className="eyebrow text-stone-500">07 · @tedishairstudio</p>
            <a
              href={content.social.instagram}
              target="_blank"
              rel="noopener noreferrer"
              className="link-draw text-sm font-medium"
            >
              Follow along →
            </a>
          </div>
        </Reveal>
        <RevealGroup className="mt-10 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4" stagger={0.05}>
          {instagramPosts.map((post, i) => (
            <RevealItem key={i}>
              <a
                href={post.postUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="group relative block aspect-square overflow-hidden"
              >
                <Image
                  src={post.image}
                  alt={post.caption}
                  fill
                  sizes="(min-width: 1024px) 25vw, (min-width: 640px) 33vw, 50vw"
                  className="object-cover transition-all duration-500 group-hover:scale-[1.04] group-hover:brightness-[0.45]"
                />
                <span className="absolute inset-0 flex items-end p-4 opacity-0 transition-opacity duration-300 group-hover:opacity-100">
                  <span className="text-xs leading-snug text-cream">{post.caption}</span>
                </span>
                <span className="absolute top-3 right-3 opacity-0 transition-opacity duration-300 group-hover:opacity-100">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-cream">
                    <rect x="2" y="2" width="20" height="20" rx="5" />
                    <circle cx="12" cy="12" r="5" />
                    <circle cx="17.5" cy="6.5" r="1.5" fill="currentColor" stroke="none" />
                  </svg>
                </span>
              </a>
            </RevealItem>
          ))}
        </RevealGroup>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* 9. VISIT                                                            */
/* ------------------------------------------------------------------ */

export function Visit() {
  return (
    <section className="bg-forest px-6 py-24 text-cream md:px-12 lg:px-20 lg:py-36">
      <div className="mx-auto max-w-[1440px]">
        <Reveal>
          <p className="eyebrow text-cream/50">08 · Visit</p>
        </Reveal>
        <div className="mt-12 grid gap-14 lg:grid-cols-2">
          <Reveal delay={0.1}>
            <p className="mono-micro text-cream/50">Inside Bellazio Collective</p>
            <p className="font-display mt-3 text-3xl tracking-tight md:text-4xl">
              259 Broad St #103
              <br />
              Matawan, NJ 07747
            </p>
            <table className="mt-10 text-sm text-cream/75">
              <tbody>
                {weeklyHours.map((d) => (
                  <tr key={d.dayOfWeek}>
                    <td className="pr-8 pb-1.5 align-top font-mono text-[11px] tracking-widest uppercase">
                      {d.label}
                    </td>
                    <td className="pb-1.5 tabular-nums">
                      {d.open && d.close
                        ? `${formatHour(d.open)} – ${formatHour(d.close)}`
                        : "Closed"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <a
              href={content.contact.phoneHref}
              className="link-draw mt-8 inline-block font-mono text-sm tracking-widest"
            >
              {content.contact.phone}
            </a>
          </Reveal>
          <Reveal delay={0.2}>
            <div className="hairline-cream relative h-[320px] overflow-hidden lg:h-full lg:min-h-[420px]">
              <iframe
                src={content.contact.mapsEmbedUrl}
                title="Map to Tedi's Hair Studio, 259 Broad St #103, Matawan NJ"
                className="absolute inset-0 size-full border-0 grayscale-[35%]"
                loading="lazy"
                referrerPolicy="no-referrer-when-downgrade"
              />
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
