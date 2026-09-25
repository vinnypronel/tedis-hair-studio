"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { z } from "zod";
import { useCart } from "@/lib/cart";
import { formatPrice } from "@/lib/data/services";
import { Button, ButtonLink } from "@/components/ui/button";
import { Reveal } from "@/components/site/reveal";
import { generateConfirmationCode } from "@/lib/utils";
import { cn } from "@/lib/utils";

const checkoutSchema = z.object({
  firstName: z.string().min(1, "First name required"),
  lastName: z.string().min(1, "Last name required"),
  email: z.string().email("That email doesn't look right"),
  phone: z.string().min(10, "A real phone number, please"),
  appointmentCode: z
    .string()
    .regex(/^[A-Z0-9]{6}$/i, "Codes are 6 letters/numbers"),
  paymentMethod: z.enum(["cash", "zelle"]),
});

export default function CheckoutPage() {
  const router = useRouter();
  const { items, subtotalCents, clear } = useCart();
  const [hasAppointment, setHasAppointment] = useState<boolean | null>(null);
  const [payment, setPayment] = useState<"cash" | "zelle">("cash");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);

  if (items.length === 0) {
    return (
      <div className="px-6 pt-44 pb-36 text-center">
        <p className="font-display text-3xl tracking-tight italic">Your cart is empty.</p>
        <Link href="/shop" className="link-draw mt-6 inline-block text-sm font-medium">
          Back to the shop →
        </Link>
      </div>
    );
  }

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const payload = {
      firstName: String(form.get("firstName") ?? ""),
      lastName: String(form.get("lastName") ?? ""),
      email: String(form.get("email") ?? ""),
      phone: String(form.get("phone") ?? ""),
      appointmentCode: String(form.get("appointmentCode") ?? "").toUpperCase(),
      paymentMethod: payment,
    };
    const result = checkoutSchema.safeParse(payload);
    if (!result.success) {
      const errs: Record<string, string> = {};
      for (const issue of result.error.issues) {
        errs[String(issue.path[0])] = issue.message;
      }
      setErrors(errs);
      return;
    }
    setErrors({});
    setSubmitting(true);
    const orderId = generateConfirmationCode();
    const order = {
      orderId,
      customer: result.data,
      items,
      subtotalCents,
      totalCents: subtotalCents,
      status: "pending",
      paymentStatus: "unpaid",
    };
    console.log("[checkout] order payload:", order);
    sessionStorage.setItem(`ths-order-${orderId}`, JSON.stringify(order));
    clear();
    router.push(`/checkout/success/${orderId}`);
  }

  return (
    <div className="px-6 pt-36 pb-24 md:px-12 lg:px-20 lg:pt-44 lg:pb-36">
      <div className="mx-auto max-w-3xl">
        <Reveal>
          <p className="eyebrow text-stone-500">Checkout</p>
          <h1 className="display-lg mt-6">Almost yours.</h1>
        </Reveal>

        {/* Order summary */}
        <Reveal delay={0.1}>
          <div className="hairline-strong mt-12 bg-cream p-8">
            <p className="eyebrow text-stone-500">Order</p>
            <ul className="mt-4 flex flex-col gap-2">
              {items.map((item) => (
                <li
                  key={`${item.shirtId}-${item.size}`}
                  className="flex justify-between text-sm"
                >
                  <span>
                    {item.name} · {item.size} × {item.quantity}
                  </span>
                  <span className="font-mono">
                    {formatPrice(item.priceCents * item.quantity)}
                  </span>
                </li>
              ))}
            </ul>
            <div className="hairline-t mt-4 flex justify-between pt-4">
              <span className="eyebrow text-stone-500">Total</span>
              <span className="font-mono text-lg">{formatPrice(subtotalCents)}</span>
            </div>
          </div>
        </Reveal>

        {/* Appointment gate */}
        <Reveal delay={0.15}>
          <div className="mt-12">
            <p className="eyebrow text-stone-500">One thing first</p>
            <p className="mt-4 text-base leading-relaxed text-stone-700">
              Shirts are picked up during your appointment. There&rsquo;s no
              shipping. Do you have an upcoming booking?
            </p>
            <div className="mt-6 flex gap-3">
              <button
                onClick={() => setHasAppointment(true)}
                aria-pressed={hasAppointment === true}
                className={cn(
                  "rounded-[2px] border-[0.5px] px-5 py-3 text-sm transition-colors",
                  hasAppointment === true
                    ? "border-forest bg-forest text-cream"
                    : "border-ink/30 hover:border-ink"
                )}
              >
                Yes, I&rsquo;m booked
              </button>
              <button
                onClick={() => setHasAppointment(false)}
                aria-pressed={hasAppointment === false}
                className={cn(
                  "rounded-[2px] border-[0.5px] px-5 py-3 text-sm transition-colors",
                  hasAppointment === false
                    ? "border-forest bg-forest text-cream"
                    : "border-ink/30 hover:border-ink"
                )}
              >
                Not yet
              </button>
            </div>
          </div>
        </Reveal>

        {hasAppointment === false && (
          <div className="hairline-strong mt-10 flex flex-col items-start gap-5 bg-forest p-8 text-cream">
            <p className="font-display text-2xl tracking-tight italic">
              Let&rsquo;s book one.
            </p>
            <p className="text-sm leading-relaxed text-cream/80">
              Your cart stays saved. Book your chair, then come back and we&rsquo;ll
              attach the shirts to your visit.
            </p>
            <ButtonLink href="/book" variant="cream" arrow>
              Book first
            </ButtonLink>
          </div>
        )}

        {hasAppointment === true && (
          <form onSubmit={handleSubmit} noValidate className="mt-12 grid gap-10 sm:grid-cols-2">
            {(
              [
                { name: "firstName", label: "First name", type: "text", auto: "given-name" },
                { name: "lastName", label: "Last name", type: "text", auto: "family-name" },
                { name: "email", label: "Email", type: "email", auto: "email" },
                { name: "phone", label: "Phone", type: "tel", auto: "tel" },
              ] as const
            ).map((field) => (
              <div key={field.name}>
                <label htmlFor={`co-${field.name}`} className="eyebrow text-stone-500">
                  {field.label}
                </label>
                <input
                  id={`co-${field.name}`}
                  name={field.name}
                  type={field.type}
                  autoComplete={field.auto}
                  className="input-line mt-2"
                />
                {errors[field.name] && (
                  <p role="alert" aria-live="polite" className="mt-2 text-xs text-error">
                    {errors[field.name]}
                  </p>
                )}
              </div>
            ))}

            <div className="sm:col-span-2">
              <label htmlFor="co-code" className="eyebrow text-stone-500">
                Booking confirmation code
              </label>
              <input
                id="co-code"
                name="appointmentCode"
                placeholder="e.g. 7K4M9X"
                maxLength={6}
                className="input-line mt-2 font-mono uppercase tracking-[0.3em]"
              />
              {errors.appointmentCode && (
                <p role="alert" aria-live="polite" className="mt-2 text-xs text-error">
                  {errors.appointmentCode}
                </p>
              )}
            </div>

            <fieldset className="sm:col-span-2">
              <legend className="eyebrow text-stone-500">How you&rsquo;ll pay</legend>
              <div className="mt-4 flex flex-col gap-3">
                {(
                  [
                    { key: "cash", label: "Cash · at the studio" },
                    { key: "zelle", label: "Zelle · at the studio (handle in confirmation)" },
                  ] as const
                ).map((opt) => (
                  <label
                    key={opt.key}
                    className={cn(
                      "flex cursor-pointer items-center gap-4 border-[0.5px] px-5 py-4 text-sm transition-colors",
                      payment === opt.key ? "border-forest bg-forest/5" : "border-ink/20"
                    )}
                  >
                    <input
                      type="radio"
                      name="payment"
                      checked={payment === opt.key}
                      onChange={() => setPayment(opt.key)}
                      className="accent-[#1A2F23]"
                    />
                    {opt.label}
                  </label>
                ))}
              </div>
            </fieldset>

            <div className="sm:col-span-2">
              <Button type="submit" size="large" arrow disabled={submitting} className="w-full">
                {submitting ? "Confirming…" : "Confirm order"}
              </Button>
              <p className="mt-4 text-xs text-stone-500">
                We&rsquo;ll pack these for your appointment. Nothing is charged online.
              </p>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
