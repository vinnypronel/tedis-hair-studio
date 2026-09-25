import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Reveal } from "@/components/site/reveal";
import { ShirtVisual } from "@/components/shop/shirt-visual";
import { BookLink } from "@/components/site/book-link";
import { ButtonLink } from "@/components/ui/button";
import { shirts, getShirtBySlug } from "@/lib/data/shirts";
import { formatPrice } from "@/lib/data/services";
import { content } from "@/lib/data/content";

export function generateStaticParams() {
  return shirts.map((s) => ({ slug: s.slug }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}): Promise<Metadata> {
  const { slug } = await params;
  const shirt = getShirtBySlug(slug);
  if (!shirt) return {};
  return { title: shirt.name, description: shirt.description, alternates: { canonical: `/shop/${shirt.slug}` } };
}

export default async function ProductPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const shirt = getShirtBySlug(slug);
  if (!shirt) notFound();

  const forSale = shirt.status === "for_sale";

  return (
    <div className="px-6 pt-32 pb-24 md:px-12 lg:px-20 lg:pt-40 lg:pb-36">
      <div className="mx-auto max-w-[1440px]">
        <Reveal>
          <Link href="/shop" className="link-draw mono-micro text-stone-500">
            ← Back to merch
          </Link>
        </Reveal>

        <div className="mt-10 grid gap-14 lg:grid-cols-2">
          {/* Images */}
          <Reveal delay={0.05}>
            <div className="flex flex-col gap-4">
              {shirt.images.map((img, i) => (
                <div
                  key={i}
                  className="hairline group relative aspect-[4/5] overflow-hidden bg-stone-100"
                >
                  <ShirtVisual shirt={shirt} imageIndex={i} sizes="(min-width: 1024px) 50vw, 100vw" />
                </div>
              ))}
            </div>
          </Reveal>

          {/* Info */}
          <Reveal delay={0.15}>
            <div className="lg:sticky lg:top-32">
              <p className="eyebrow text-stone-500">Studio Apparel</p>
              <h1 className="heading-1 mt-4">{shirt.name}</h1>

              {forSale ? (
                <div className="mt-10">
                  <p className="eyebrow text-stone-500">Sizes at the studio</p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {shirt.availableSizes.map((s) => (
                      <span
                        key={s}
                        className="min-w-14 border-[0.5px] border-ink/30 px-4 py-3 text-center font-mono text-sm"
                      >
                        {s}
                      </span>
                    ))}
                  </div>
                  <p className="mt-8 max-w-md text-sm leading-relaxed text-stone-700">
                    Shirts are not sold online. Ask Tedi at your next appointment, or send a
                    DM and he&rsquo;ll set one aside for you.
                  </p>
                  <div className="mt-7 flex flex-wrap items-center gap-7">
                    <ButtonLink href={content.social.instagram} arrow>
                      DM to grab one
                    </ButtonLink>
                    <BookLink className="link-draw text-sm font-medium">
                      Book an appointment →
                    </BookLink>
                  </div>
                </div>
              ) : (
                <div className="mt-10">
                  <span className="mono-micro inline-block border-[0.5px] border-ink/30 px-3 py-2 text-stone-700">
                    Past drop · no longer available
                  </span>
                  <p className="mt-7 max-w-md text-sm leading-relaxed text-stone-700">
                    Kept here for the archive. New drops get announced on Instagram first.
                  </p>
                  <a
                    href={content.social.instagram}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="link-draw mt-5 inline-block text-sm font-medium"
                  >
                    Follow {content.social.instagramHandle} →
                  </a>
                </div>
              )}
            </div>
          </Reveal>
        </div>
      </div>
    </div>
  );
}
