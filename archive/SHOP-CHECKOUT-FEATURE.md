# Archived: Shirt Shop Cart + Checkout (Tedi's Hair Studio)

**Archived:** 2026-08-24
**Reason:** No online selling at launch. `/shop` stays live as a browse-only merch gallery, so
people can see the tees but cannot add them to a cart or attach them to an appointment.
**Status:** Cart, checkout, and the order confirmation screen are fully removed. Source is
preserved under `archive/shop-checkout/`. Nothing in `src/` imports any of it, and `archive/`
is excluded from `tsconfig.json`.

---

## 1. What it was

A three-surface commerce flow on top of the mock shirt data:

1. **Product purchase block** (`/shop/[slug]`) - size picker, quantity stepper (capped at 5),
   "Add to cart · $35" button, then a 600ms delay and a push to `/cart`. Past drops instead
   showed a "Notify me about the next drop" email capture that only console-logged.
2. **Cart** (`/cart`) - line items with size and quantity, remove per line, subtotal, and a
   "Continue to checkout" button. Empty state showed the bear mark and a link back to the shop.
3. **Checkout** (`/checkout`) - an appointment gate ("Do you have an upcoming booking?"). Saying
   no showed a forest panel pushing you to `/book`. Saying yes revealed a Zod-validated form
   (name, email, phone, 6-char booking confirmation code, cash or Zelle), which console-logged
   the order, stashed it in `sessionStorage`, cleared the cart, and routed to
   `/checkout/success/[orderId]`.

Nothing was ever charged online. Shirts were picked up at the appointment, paid cash or Zelle.

Cart state lived in a React context (`CartProvider` in `src/lib/cart.tsx`) wrapped around the
whole app in `src/app/layout.tsx`, persisted to `localStorage` under `ths-cart-v1`. The header
showed a `Cart (n)` link whenever `count > 0`.

---

## 2. Files in this archive

| Archived path | Original path |
| --- | --- |
| `archive/shop-checkout/lib/cart.tsx` | `src/lib/cart.tsx` |
| `archive/shop-checkout/components/product-client.tsx` | `src/app/shop/[slug]/product-client.tsx` |
| `archive/shop-checkout/app/cart/page.tsx` | `src/app/cart/page.tsx` |
| `archive/shop-checkout/app/checkout/page.tsx` | `src/app/checkout/page.tsx` |
| `archive/shop-checkout/app/checkout/success/[orderId]/page.tsx` | `src/app/checkout/success/[orderId]/page.tsx` |

`product-client.tsx` exports two components: `ProductPurchase` (the buy block) and `NotifyForm`
(the next-drop email capture).

---

## 3. What changed in files that are still live

### `src/app/layout.tsx`

```tsx
import { CartProvider } from "@/lib/cart";
...
        <CartProvider>
          <Header />
          <main>{children}</main>
          <Footer />
        </CartProvider>
```

The provider was removed; `<Header /> <main> <Footer />` now sit directly in `<body>`.

### `src/components/site/header.tsx`

```tsx
import { useCart } from "@/lib/cart";
...
  const { count } = useCart();
...
            {count > 0 && (
              <Link href="/cart" className="link-draw font-mono text-xs tracking-widest uppercase">
                Cart ({count})
              </Link>
            )}
```

Also: the desktop nav label for `/shop` was `"Shop"`, now `"Merch"`.

### `src/app/shop/[slug]/page.tsx`

The info column ended with a conditional on `shirt.status === "for_sale"`:

```tsx
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
```

That is now a static "at the studio" block with no interactive commerce.

### `src/app/shop/shop-client.tsx`

Filter labels were `All / For Sale / Archive`. They are now `All / Current / Past drops`. The
`matches()` logic and the `ShirtStatus` values are unchanged.

### `src/app/robots.ts`

```ts
disallow: ["/admin", "/checkout", "/cart"],
```

is now just `disallow: ["/admin"]`.

### `src/lib/data/content.ts`

```ts
  shop: {
    note: "Shirts given at your next cut. Booking required for purchase.",
    disclaimer:
      "All shirts are picked up during your appointment. Booking is required to purchase.",
  },
```

Both strings were rewritten so they no longer promise an online purchase path.

### `src/lib/utils.ts`

`generateConfirmationCode()` was used by checkout as well as booking. It is preserved in
`archive/BOOKING-FEATURE.md` section 3b.

---

## 4. Data contract

The shirt data itself (`src/lib/data/shirts.ts`) is untouched and still drives the gallery:
`status` is `"for_sale" | "display_only" | "archived"`, prices are `priceCents: 3500` across the
board, and `availableSizes` is still populated on the three current tees. Nothing needs to
change there to turn selling back on.

Cart item shape:

```ts
export type CartItem = {
  shirtId: string;
  slug: string;
  name: string;
  size: string;
  quantity: number;
  priceCents: number;
};
```

Checkout Zod schema:

```ts
const checkoutSchema = z.object({
  firstName: z.string().min(1, "First name required"),
  lastName: z.string().min(1, "Last name required"),
  email: z.string().email("That email doesn't look right"),
  phone: z.string().min(10, "A real phone number, please"),
  appointmentCode: z.string().regex(/^[A-Z0-9]{6}$/i, "Codes are 6 letters/numbers"),
  paymentMethod: z.enum(["cash", "zelle"]),
});
```

Storage keys: `ths-cart-v1` (localStorage, cart contents), `ths-order-<ORDERID>` (sessionStorage,
order for the success screen).

---

## 5. Copy worth keeping

- Shop header: "Wear the mark." / "Limited drops. Pick-up at your next cut."
- Product: "Add to cart · $35", "Added! Heading to cart", "Pick a size first"
- Product footnote: "Shirts ship with your next cut. You'll book at checkout."
- Cart empty: "Nothing in your cart yet." / "See the shop"
- Cart footnote: "Shirts are picked up during your appointment. You'll confirm a booking at checkout."
- Checkout: "Almost yours." / "One thing first" / "Yes, I'm booked" / "Not yet" / "Let's book one."
- Checkout footnote: "We'll pack these for your appointment. Nothing is charged online."
- Success: "Packed for your cut." / "Your shirts will be waiting at your appointment."
- Notify form: "Notify me about the next drop" / "You're on the list. First to know about the next drop."

Shirt names and the $35 price are client-approved and final: Green Tee, Blue Tee, Yellow/Black
Tee, Brown Tee.

---

## 6. How to reinstate

1. Copy the five files in `archive/shop-checkout/` back to their original paths (section 2).
2. Re-wrap the app in `<CartProvider>` in `src/app/layout.tsx`.
3. Restore the `useCart()` count badge in the header and set the nav label back to "Shop".
4. Restore the `forSale ? <ProductPurchase /> : <NotifyForm />` branch in `src/app/shop/[slug]/page.tsx`.
5. Restore `generateConfirmationCode()` in `src/lib/utils.ts` (see the booking archive doc).
6. Put `/checkout` and `/cart` back in the `robots.ts` disallow list.
7. Revert the two `content.shop` strings.

### Before selling for real

The archived checkout never took money. Real commerce needs a payment processor (Stripe was the
plan, deferred with the rest of the backend), inventory that actually decrements, and an order
record that survives a browser wipe. The appointment-code gate also assumed the on-site booking
flow existed; with Booksy running the calendar there is no code to validate against, so that
gate has to be redesigned or dropped.
