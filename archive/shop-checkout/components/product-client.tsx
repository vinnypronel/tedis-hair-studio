"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { useCart } from "@/lib/cart";
import { formatPrice } from "@/lib/data/services";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { Shirt } from "@/lib/data/shirts";

export function ProductPurchase({ shirt }: { shirt: Shirt }) {
  const router = useRouter();
  const { addItem } = useCart();
  const [size, setSize] = useState<string | null>(null);
  const [qty, setQty] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const [added, setAdded] = useState(false);

  function handleAdd() {
    if (!size) {
      setError("Pick a size first");
      return;
    }
    setError(null);
    addItem({
      shirtId: shirt.id,
      slug: shirt.slug,
      name: shirt.name,
      size,
      quantity: qty,
      priceCents: shirt.priceCents,
    });
    setAdded(true);
    setTimeout(() => router.push("/cart"), 600);
  }

  return (
    <div>
      <p className="eyebrow mt-10 text-stone-500">Size</p>
      <div className="mt-3 flex flex-wrap gap-2" role="group" aria-label="Select size">
        {shirt.availableSizes.map((s) => (
          <button
            key={s}
            onClick={() => {
              setSize(s);
              setError(null);
            }}
            aria-pressed={size === s}
            className={cn(
              "min-w-14 rounded-[2px] border-[0.5px] px-4 py-3 font-mono text-sm transition-colors duration-200",
              size === s
                ? "border-forest bg-forest text-cream"
                : "border-ink/30 hover:border-ink"
            )}
          >
            {s}
          </button>
        ))}
      </div>
      {error && (
        <p role="alert" aria-live="polite" className="mt-2 text-xs text-error">
          {error}
        </p>
      )}

      <p className="eyebrow mt-8 text-stone-500">Quantity</p>
      <div className="mt-3 inline-flex items-center border-[0.5px] border-ink/30">
        <button
          onClick={() => setQty((q) => Math.max(1, q - 1))}
          className="px-4 py-3 font-mono text-sm hover:bg-stone-100"
          aria-label="Decrease quantity"
        >
          −
        </button>
        <span className="min-w-12 text-center font-mono text-sm tabular-nums" aria-live="polite">
          {qty}
        </span>
        <button
          onClick={() => setQty((q) => Math.min(5, q + 1))}
          className="px-4 py-3 font-mono text-sm hover:bg-stone-100"
          aria-label="Increase quantity"
        >
          +
        </button>
      </div>

      <div className="mt-10">
        <Button size="large" arrow onClick={handleAdd} disabled={added}>
          {added ? "Added! Heading to cart" : `Add to cart · ${formatPrice(shirt.priceCents * qty)}`}
        </Button>
      </div>
      <p className="mt-4 text-xs text-stone-500">
        Shirts ship with your next cut. You&rsquo;ll book at checkout.
      </p>
    </div>
  );
}

export function NotifyForm() {
  const [email, setEmail] = useState("");
  const [done, setDone] = useState(false);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!/^\S+@\S+\.\S+$/.test(email)) return;
    console.log("[notify_list] signup:", { email });
    setDone(true);
  }

  if (done) {
    return (
      <p className="mt-6 text-sm text-forest">
        You&rsquo;re on the list. First to know about the next drop.
      </p>
    );
  }

  return (
    <form onSubmit={submit} className="mt-6 flex max-w-sm items-end gap-4">
      <div className="flex-1">
        <label htmlFor="notify-email" className="eyebrow text-stone-500">
          Notify me about the next drop
        </label>
        <input
          id="notify-email"
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@email.com"
          className="input-line mt-2"
        />
      </div>
      <Button type="submit" variant="secondary">
        Notify
      </Button>
    </form>
  );
}
