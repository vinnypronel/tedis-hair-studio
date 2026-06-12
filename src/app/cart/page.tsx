"use client";

import Link from "next/link";
import { useCart } from "@/lib/cart";
import { formatPrice } from "@/lib/data/services";
import { BearLogo } from "@/components/site/bear-logo";
import { ButtonLink } from "@/components/ui/button";
import { Reveal } from "@/components/site/reveal";

export default function CartPage() {
  const { items, removeItem, subtotalCents } = useCart();

  return (
    <div className="px-6 pt-36 pb-24 md:px-12 lg:px-20 lg:pt-44 lg:pb-36">
      <div className="mx-auto max-w-4xl">
        <Reveal>
          <p className="eyebrow text-stone-500">The Shop</p>
          <h1 className="display-lg mt-6">Your cart</h1>
        </Reveal>

        {items.length === 0 ? (
          <Reveal delay={0.1}>
            <div className="mt-16 flex flex-col items-center gap-6 py-16 text-center">
              <BearLogo size={96} className="text-stone-300" />
              <p className="font-display text-2xl tracking-tight">
                Nothing in your cart yet.
              </p>
              <Link href="/shop" className="link-draw text-sm font-medium">
                See the shop →
              </Link>
            </div>
          </Reveal>
        ) : (
          <Reveal delay={0.1}>
            <ul className="mt-14">
              {items.map((item) => (
                <li
                  key={`${item.shirtId}-${item.size}`}
                  className="hairline-t flex flex-wrap items-baseline justify-between gap-4 py-6"
                >
                  <div>
                    <Link
                      href={`/shop/${item.slug}`}
                      className="font-display text-xl tracking-tight hover:underline"
                    >
                      {item.name}
                    </Link>
                    <p className="mono-micro mt-1 text-stone-500">
                      Size {item.size} · Qty {item.quantity}
                    </p>
                  </div>
                  <div className="flex items-baseline gap-8">
                    <span className="font-mono text-base">
                      {formatPrice(item.priceCents * item.quantity)}
                    </span>
                    <button
                      onClick={() => removeItem(item.shirtId, item.size)}
                      className="mono-micro text-stone-500 underline-offset-4 hover:text-error hover:underline"
                    >
                      Remove
                    </button>
                  </div>
                </li>
              ))}
            </ul>
            <div className="hairline-t flex items-baseline justify-between py-8">
              <span className="eyebrow text-stone-500">Subtotal</span>
              <span className="font-mono text-2xl">{formatPrice(subtotalCents)}</span>
            </div>
            <div className="mt-6 flex flex-col items-start gap-5">
              <ButtonLink href="/checkout" size="large" arrow>
                Continue to checkout
              </ButtonLink>
              <p className="text-xs text-stone-500">
                Shirts are picked up during your appointment. You&rsquo;ll
                confirm a booking at checkout.
              </p>
            </div>
          </Reveal>
        )}
      </div>
    </div>
  );
}
