import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Reveal } from "@/components/site/reveal";
import { ShirtVisual } from "@/components/shop/shirt-visual";
import { shirts, getShirtBySlug } from "@/lib/data/shirts";
import { formatPrice } from "@/lib/data/services";
import { ProductPurchase, NotifyForm } from "./product-client";

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
  return { title: shirt.name, description: shirt.description };
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
            ← Back to the shop
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
              <p className="eyebrow text-stone-500">
                {forSale ? `Limited · ${shirt.drop}` : `${shirt.drop} · ${shirt.releaseYear}`}
              </p>
              <h1 className="heading-1 mt-4">{shirt.name}</h1>
              <p className="mt-5 font-mono text-2xl">
                {forSale ? formatPrice(shirt.priceCents) : "Sold out"}
              </p>
              <p className="mt-7 max-w-md text-base leading-relaxed text-stone-700">
                {shirt.description}
              </p>

              {forSale ? (
                <ProductPurchase shirt={shirt} />
              ) : (
                <div className="mt-10">
                  <span className="mono-micro inline-block border-[0.5px] border-ink/30 px-3 py-2 text-stone-700">
                    Past drop · not currently available
                  </span>
                  <NotifyForm />
                </div>
              )}
            </div>
          </Reveal>
        </div>
      </div>
    </div>
  );
}
