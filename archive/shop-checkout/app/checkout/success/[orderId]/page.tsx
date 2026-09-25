"use client";

import Link from "next/link";
import { use, useEffect, useState } from "react";
import { BearLogo } from "@/components/site/bear-logo";
import { formatPrice } from "@/lib/data/services";
import { content } from "@/lib/data/content";
import type { CartItem } from "@/lib/cart";

type StoredOrder = {
  orderId: string;
  items: CartItem[];
  totalCents: number;
  customer: { firstName: string; paymentMethod: string };
};

export default function OrderSuccessPage({
  params,
}: {
  params: Promise<{ orderId: string }>;
}) {
  const { orderId } = use(params);
  const [order, setOrder] = useState<StoredOrder | null>(null);

  useEffect(() => {
    const raw = sessionStorage.getItem(`ths-order-${orderId}`);
    if (raw) setOrder(JSON.parse(raw));
  }, [orderId]);

  return (
    <div className="px-6 pt-36 pb-24 md:px-12 lg:px-20 lg:pt-44 lg:pb-36">
      <div className="mx-auto max-w-2xl text-center">
        <BearLogo size={72} className="mx-auto text-forest" />
        <p className="eyebrow mt-10 text-stone-500">Order confirmed</p>
        <h1 className="display-lg mt-6 italic">Packed for your cut.</h1>
        <p className="mt-8 font-mono text-4xl tracking-[0.3em]">{orderId}</p>

        {order && (
          <div className="hairline-strong mt-12 bg-cream p-8 text-left">
            <ul className="flex flex-col gap-2">
              {order.items.map((item) => (
                <li key={`${item.shirtId}-${item.size}`} className="flex justify-between text-sm">
                  <span>
                    {item.name} · {item.size} × {item.quantity}
                  </span>
                  <span className="font-mono">{formatPrice(item.priceCents * item.quantity)}</span>
                </li>
              ))}
            </ul>
            <div className="hairline-t mt-4 flex justify-between pt-4">
              <span className="eyebrow text-stone-500">Total · {order.customer.paymentMethod} at the studio</span>
              <span className="font-mono text-lg">{formatPrice(order.totalCents)}</span>
            </div>
          </div>
        )}

        <p className="mt-10 text-sm leading-relaxed text-stone-700">
          Your shirts will be waiting at your appointment. Questions? Text the
          studio at{" "}
          <a href={content.contact.phoneHref} className="underline underline-offset-4">
            {content.contact.phone}
          </a>
          .
        </p>
        <Link href="/" className="link-draw mt-10 inline-block text-sm font-medium">
          Back home →
        </Link>
      </div>
    </div>
  );
}
