import Image from "next/image";
import Link from "next/link";
import { Reveal, RevealGroup, RevealItem } from "@/components/site/reveal";
import { BearLogo } from "@/components/site/bear-logo";
import { BookLink } from "@/components/site/book-link";
import { MapBadge } from "@/components/site/map-badge";
import { services, formatPrice } from "@/lib/data/services";
import { getFeaturedReviews, reviewStats } from "@/lib/data/reviews";
import { getVisibleShirts } from "@/lib/data/shirts";
import { instagramPosts } from "@/lib/data/gallery";
import { weeklyHours, formatHour } from "@/lib/data/availability";
import { content } from "@/lib/data/content";
import { ShirtVisual } from "@/components/shop/shirt-visual";

/* ------------------------------------------------------------------ */
/* 2. INTRO STRIP                                                      */
/* ------------------------------------------------------------------ */

export function IntroStrip() {
  return (
    <section className="bg-forest px-6 pt-5 pb-8 text-cream md:px-12 lg:px-20 lg:pt-6 lg:pb-10">
      <div className="mx-auto max-w-[1440px]">
        <Reveal>
          <p className="eyebrow text-cream/50">01 · The Studio</p>
        </Reveal>
        <Reveal delay={0.1}>
          <p className="display-lg mx-auto mt-4 max-w-4xl text-center italic">
            Clean work, quiet setting.
          </p>
        </Reveal>
        <Reveal delay={0.2}>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-x-10 gap-y-3">
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
    <section className="px-6 py-20 md:px-12 lg:px-20 lg:py-24">
      <div className="mx-auto max-w-[1440px]">
        <div className="grid gap-12 lg:grid-cols-12">
          <div className="lg:col-span-4 pt-6 lg:pt-16">
            <Reveal>
              <p className="eyebrow text-stone-500">02 · Services</p>
              <h2 className="heading-1 mt-4">What we do</h2>
              <p className="mt-5 max-w-sm text-sm leading-relaxed text-stone-700">
                Five services, no filler. Every appointment is private and
                every cut gets the full duration it deserves.
              </p>
              <Link
                href="/services"
                className="mt-7 inline-block text-sm font-medium underline underline-offset-4 decoration-ink/40 transition-colors hover:decoration-ink"
              >
                View all services →
              </Link>
            </Reveal>
          </div>
          <RevealGroup className="lg:col-span-8" stagger={0.08}>
            {featured.map((svc) => (
              <RevealItem key={svc.id}>
                <BookLink className="hairline-t group flex flex-wrap items-baseline justify-between gap-3 py-7 transition-colors duration-300 hover:bg-stone-100/60 sm:flex-nowrap sm:gap-8 sm:px-4">
                  <div className="min-w-0">
                    <span className="font-display text-2xl tracking-tight md:text-3xl">
                      {svc.name}
                    </span>
                    {svc.mostPopular && (
                      <span className="mono-micro ml-4 border-[0.5px] border-forest px-2 py-1 align-middle text-forest">
                        Most booked
                      </span>
                    )}
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
                </BookLink>
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
/* 4. PORTFOLIO MARQUEE (client: swipeable + auto-scroll)              */
/* ------------------------------------------------------------------ */

export { PortfolioMarquee } from "./portfolio-marquee";

/* ------------------------------------------------------------------ */
/* 5. THE BEAR                                                         */
/* ------------------------------------------------------------------ */

export function BrandStory() {
  return (
    // overflow-hidden: the oversized bear mark sits at -right-1 and was adding
    // 4px of horizontal scroll to the page on desktop.
    <section className="overflow-hidden bg-ink text-cream">
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
            className="absolute -right-1 -bottom-1 text-cream opacity-[0.05]"
            label=""
          />
          <Reveal>
            <p className="eyebrow text-cream/50">03 · The Standard</p>
          </Reveal>
          <Reveal delay={0.1}>
            <h2 className="heading-1 mt-5">
              <span className="block">Clean room.</span>
              <span className="block">Serious work.</span>
            </h2>
          </Reveal>
          <Reveal delay={0.2}>
            <p className="mt-8 max-w-xl text-base leading-relaxed text-cream/80">
              {content.brand.story}
            </p>
          </Reveal>
          <Reveal delay={0.3}>
            <p className="mono-micro mt-16 text-cream/50 lg:mt-10">
              One-on-One · Clean Space · Full Attention
            </p>
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
    <section className="px-6 py-24 md:px-12 lg:px-20 lg:py-28">
      <div className="mx-auto grid max-w-[1440px] items-center gap-14 lg:grid-cols-2 lg:gap-20">
        <div className="lg:translate-x-[30px]">
          <Reveal>
            <p className="eyebrow text-stone-500">04 · The Space</p>
          </Reveal>
          <Reveal delay={0.1}>
            <h2 className="heading-1 mt-5 italic">Inside Bellazio. Kept sharp.</h2>
          </Reveal>
          <Reveal delay={0.2}>
            <p className="mt-8 max-w-xl text-lg leading-relaxed text-stone-700">
              {content.space.story}
            </p>
          </Reveal>
          <Reveal delay={0.3}>
            <p className="mono-micro mt-10 text-stone-500">
              {content.contact.addressLine1} · Matawan, NJ
            </p>
          </Reveal>
        </div>
        <Reveal delay={0.15} className="lg:-translate-x-[30px]">
          <div className="hairline relative ml-auto aspect-[4/5] w-full max-w-md overflow-hidden">
            <Image
              src="/professional-images/outsidedoor.jpg"
              alt="The studio entrance at Bellazio Collective"
              fill
              sizes="(min-width: 1024px) 40vw, 100vw"
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
          <p className="eyebrow text-stone-500">05 · Our Reviews</p>
          <h2 className="heading-1 mt-5">Five stars, only.</h2>
        </Reveal>
        <RevealGroup className="mt-14 grid gap-6 md:grid-cols-3" stagger={0.1}>
          {featured.map((review) => (
            <RevealItem key={review.id} className="flex">
              <a
                href={content.booking.reviewsUrl}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={`Read ${review.authorName}'s review on Booksy`}
                className="group flex flex-1"
              >
                <figure className="hairline-strong flex flex-1 flex-col bg-cream p-8 transition-all duration-300 group-hover:-translate-y-1 group-hover:bg-bone group-hover:shadow-lg">
                  <div className="flex items-start justify-between gap-4">
                    <span aria-hidden className="font-display text-6xl leading-none text-forest">
                      &ldquo;
                    </span>
                    <div className="flex items-center gap-2 pt-2" aria-label={`${review.rating} star review`}>
                      <div className="flex gap-1 text-neon" aria-hidden>
                        {Array.from({ length: review.rating }).map((_, i) => (
                          <svg
                            key={i}
                            viewBox="0 0 20 20"
                            fill="currentColor"
                            className="size-3.5"
                          >
                            <path d="M10 1.5 12.5 7l6 .6-4.5 4.1 1.3 5.8L10 14.5l-5.3 3 1.3-5.8-4.5-4.1 6-.6L10 1.5Z" />
                          </svg>
                        ))}
                      </div>
                      <span className="mono-micro text-stone-500">{review.rating}.0</span>
                    </div>
                  </div>
                  <blockquote className="mt-2 flex-1 text-[15px] leading-relaxed text-stone-700">
                    {review.text}
                  </blockquote>
                  <figcaption className="mono-micro mt-8 flex flex-wrap items-center gap-x-2.5 text-stone-500">
                    <span className="text-ink">{review.authorName}</span>
                    <span aria-hidden>·</span>
                    <span>
                      {new Date(review.sourceDate + "T12:00:00").toLocaleDateString("en-US", {
                        month: "short",
                        year: "numeric",
                      })}
                    </span>
                    <span aria-hidden>·</span>
                    <span className="text-forest">via Booksy ↗</span>
                  </figcaption>
                </figure>
              </a>
            </RevealItem>
          ))}
        </RevealGroup>
        <Reveal delay={0.2}>
          <div className="mt-14 flex flex-wrap items-center justify-between gap-6">
            <p className="font-mono text-sm tracking-widest">
              <span className="text-neon">★★★★★</span>
              <span className="ml-4 text-stone-500">
                {reviewStats.count} five-star reviews
              </span>
            </p>
            <div className="ml-auto flex flex-wrap items-center gap-6">
              <a
                href={content.booking.googleReviewUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2.5 rounded-[2px] border-[0.5px] border-ink/20 bg-cream px-5 py-3 text-sm font-medium transition-colors duration-300 hover:border-ink"
              >
                <svg aria-hidden viewBox="0 0 24 24" className="size-4 shrink-0">
                  <path
                    fill="#4285F4"
                    d="M23.52 12.27c0-.82-.07-1.6-.2-2.36H12v4.46h6.47a5.53 5.53 0 0 1-2.4 3.63v3.02h3.88c2.27-2.09 3.57-5.17 3.57-8.75Z"
                  />
                  <path
                    fill="#34A853"
                    d="M12 24c3.24 0 5.96-1.08 7.95-2.9l-3.88-3.02c-1.08.72-2.45 1.15-4.07 1.15-3.13 0-5.78-2.11-6.73-4.96H1.26v3.12A12 12 0 0 0 12 24Z"
                  />
                  <path
                    fill="#FBBC05"
                    d="M5.27 14.27A7.2 7.2 0 0 1 4.89 12c0-.79.14-1.56.38-2.27V6.61H1.26A12 12 0 0 0 0 12c0 1.94.46 3.77 1.26 5.39l4.01-3.12Z"
                  />
                  <path
                    fill="#EA4335"
                    d="M12 4.77c1.77 0 3.35.61 4.6 1.8l3.44-3.44A11.5 11.5 0 0 0 12 0 12 12 0 0 0 1.26 6.61l4.01 3.12C6.22 6.88 8.87 4.77 12 4.77Z"
                  />
                </svg>
                Leave a review
              </a>
              <Link
                href="/reviews"
                className="text-sm font-medium underline underline-offset-4 decoration-ink/40 transition-colors hover:decoration-ink"
              >
                Read all →
              </Link>
            </div>
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
    <section className="px-6 pt-3 pb-6 md:px-12 lg:px-20 lg:pt-4 lg:pb-8">
      <div className="mx-auto max-w-[1440px]">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <Reveal className="translate-y-1">
            <p className="eyebrow text-stone-500">06 · Our Merch</p>
            <h2 className="heading-1 mt-1 text-3xl md:text-4xl lg:text-5xl">Past drops.</h2>
          </Reveal>
          <Reveal delay={0.1}>
            <Link
              href="/shop"
              className="text-sm font-medium underline underline-offset-4 decoration-ink/40 transition-colors hover:decoration-ink"
            >
              View our tees →
            </Link>
          </Reveal>
        </div>
        <RevealGroup className="mt-4 grid gap-5 sm:grid-cols-2 lg:grid-cols-3" stagger={0.1}>
          {featured.map((shirt) => (
            <RevealItem key={shirt.id}>
              <Link href={`/shop/${shirt.slug}`} className="group block text-left">
                <div className="hairline relative h-[390px] w-full overflow-hidden bg-stone-100 sm:h-[430px] lg:h-[465px]">
                  <ShirtVisual shirt={shirt} fit="cover" />
                </div>
                <p className="mt-2.5 font-display text-lg tracking-tight md:text-xl">{shirt.name}</p>
              </Link>
            </RevealItem>
          ))}
        </RevealGroup>
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
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="eyebrow text-stone-500">07 · @tedishairstudio</p>
              <h2 className="heading-1 mt-2 text-ink">Instagram</h2>
            </div>
            <a
              href={content.social.instagram}
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm font-medium underline underline-offset-4 decoration-ink/40 transition-colors hover:decoration-ink"
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
    <section className="bg-forest px-6 py-14 text-cream md:px-12 md:py-16 lg:px-20 lg:py-20">
      <div className="mx-auto max-w-[1440px]">
        <Reveal>
          <p className="eyebrow text-cream/50">08 · Visit</p>
        </Reveal>
        <div className="mt-8 grid gap-8 lg:grid-cols-2 lg:items-center lg:gap-12">
          <Reveal delay={0.1}>
            <p className="mono-micro text-cream/50">Inside Bellazio Collective</p>
            <p className="font-display mt-3 text-3xl leading-tight tracking-tight md:text-[38px]">
              {content.contact.addressLine1}
              <br />
              {content.contact.addressLine2}
            </p>
            <table className="mt-7 text-sm text-cream/75">
              <tbody>
                {weeklyHours.map((d) => (
                  <tr key={d.dayOfWeek}>
                    <td className="pr-8 pb-1 align-top font-mono text-[11px] tracking-widest uppercase">
                      {d.label}
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
            <a
              href={content.contact.phoneHref}
              className="link-draw mt-6 inline-block font-mono text-sm tracking-widest"
            >
              {content.contact.phone}
            </a>
          </Reveal>
          <Reveal delay={0.2}>
            <div className="hairline-cream relative h-[260px] overflow-hidden md:h-[300px] lg:h-[340px]">
              <iframe
                src={content.contact.mapsEmbedUrl}
                title={`Map to Tedi's Hair Studio, ${content.contact.addressLine1}, ${content.contact.addressLine2}`}
                className="absolute inset-0 size-full border-0 grayscale-[35%]"
                loading="lazy"
                referrerPolicy="no-referrer-when-downgrade"
              />
              <MapBadge />
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}

