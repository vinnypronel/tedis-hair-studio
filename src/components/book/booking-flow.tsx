"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { z } from "zod";
import { services, formatPrice, type Service } from "@/lib/data/services";
import {
  getAvailableSlots,
  isDateBookable,
  weeklyHours,
} from "@/lib/data/availability";
import { shirts } from "@/lib/data/shirts";
import { Button } from "@/components/ui/button";
import { BearLogo } from "@/components/site/bear-logo";
import { cn, formatDateLong, formatTime12, generateConfirmationCode } from "@/lib/utils";

/* ------------------------------------------------------------------ */
/* Schema                                                              */
/* ------------------------------------------------------------------ */

const infoSchema = z.object({
  firstName: z.string().min(1, "First name required"),
  lastName: z.string().min(1, "Last name required"),
  email: z.string().email("That email doesn't look right"),
  phone: z.string().min(10, "A real phone number, please"),
  notes: z.string().optional(),
});

type Info = z.infer<typeof infoSchema>;

const steps = [
  "Choose your service",
  "Pick a time",
  "Your details",
  "How you'll pay",
] as const;

/* ------------------------------------------------------------------ */
/* Calendar                                                            */
/* ------------------------------------------------------------------ */

function Calendar({
  selected,
  onSelect,
}: {
  selected: Date | null;
  onSelect: (d: Date) => void;
}) {
  const today = new Date();
  const [viewYear, setViewYear] = useState(today.getFullYear());
  const [viewMonth, setViewMonth] = useState(today.getMonth());

  const first = new Date(viewYear, viewMonth, 1);
  const startPad = first.getDay();
  const daysInMonth = new Date(viewYear, viewMonth + 1, 0).getDate();
  const monthLabel = first.toLocaleDateString("en-US", { month: "long", year: "numeric" });

  const isCurrentMonth =
    viewYear === today.getFullYear() && viewMonth === today.getMonth();

  function shift(delta: number) {
    const d = new Date(viewYear, viewMonth + delta, 1);
    setViewYear(d.getFullYear());
    setViewMonth(d.getMonth());
  }

  return (
    <div>
      <div className="flex items-center justify-between">
        <p className="font-display text-2xl tracking-tight">{monthLabel}</p>
        <div className="flex gap-1">
          <button
            type="button"
            onClick={() => shift(-1)}
            disabled={isCurrentMonth}
            className="border-[0.5px] border-ink/20 px-3 py-1.5 text-sm transition-colors hover:border-ink disabled:opacity-30"
            aria-label="Previous month"
          >
            ←
          </button>
          <button
            type="button"
            onClick={() => shift(1)}
            className="border-[0.5px] border-ink/20 px-3 py-1.5 text-sm transition-colors hover:border-ink"
            aria-label="Next month"
          >
            →
          </button>
        </div>
      </div>

      <div className="mt-6 grid grid-cols-7 gap-1 text-center">
        {["S", "M", "T", "W", "T", "F", "S"].map((d, i) => (
          <span key={i} className="mono-micro pb-2 text-stone-500">
            {d}
          </span>
        ))}
        {Array.from({ length: startPad }).map((_, i) => (
          <span key={`pad-${i}`} />
        ))}
        {Array.from({ length: daysInMonth }).map((_, i) => {
          const date = new Date(viewYear, viewMonth, i + 1);
          const bookable = isDateBookable(date);
          const isSelected =
            selected !== null && date.toDateString() === selected.toDateString();
          const isToday = date.toDateString() === today.toDateString();
          return (
            <button
              key={i}
              type="button"
              disabled={!bookable}
              onClick={() => onSelect(date)}
              aria-pressed={isSelected}
              className={cn(
                "relative aspect-square text-sm tabular-nums transition-colors duration-200",
                bookable ? "hover:bg-stone-100" : "text-stone-300",
                isSelected && "bg-forest text-cream hover:bg-forest"
              )}
            >
              {i + 1}
              {isToday && (
                <span
                  aria-hidden
                  className="absolute bottom-1.5 left-1/2 h-0.5 w-4 -translate-x-1/2 bg-neon"
                />
              )}
            </button>
          );
        })}
      </div>
      <p className="mono-micro mt-4 text-stone-500">
        Closed Sundays · Sat 9–5 · Mon–Fri 10–8
      </p>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Flow                                                                */
/* ------------------------------------------------------------------ */

export function BookingFlow() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const preselect = searchParams.get("service");

  const [step, setStep] = useState(0);
  const [service, setService] = useState<Service | null>(
    () => services.find((s) => s.slug === preselect) ?? null
  );
  const [date, setDate] = useState<Date | null>(null);
  const [slot, setSlot] = useState<string | null>(null);
  const [info, setInfo] = useState<Info>({
    firstName: "",
    lastName: "",
    email: "",
    phone: "",
    notes: "",
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [shirtOpen, setShirtOpen] = useState(false);
  const [addedShirts, setAddedShirts] = useState<Record<string, string>>({}); // shirtId -> size
  const [payment, setPayment] = useState<"cash" | "zelle">("cash");
  const [agreed, setAgreed] = useState(false);
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const slots = useMemo(
    () => (date && service ? getAvailableSlots(date, service.durationMinutes) : []),
    [date, service]
  );

  const forSaleShirts = shirts.filter((s) => s.status === "for_sale");
  const shirtTotal = Object.keys(addedShirts).reduce((sum, id) => {
    const shirt = shirts.find((s) => s.id === id);
    return sum + (shirt?.priceCents ?? 0);
  }, 0);
  const totalCents = (service?.priceCents ?? 0) + shirtTotal;

  function validateInfo(): boolean {
    const result = infoSchema.safeParse(info);
    if (!result.success) {
      const errs: Record<string, string> = {};
      for (const issue of result.error.issues) {
        errs[String(issue.path[0])] = issue.message;
      }
      setErrors(errs);
      return false;
    }
    setErrors({});
    return true;
  }

  function confirmBooking() {
    if (!agreed) {
      setConfirmError("Please accept the studio terms first.");
      return;
    }
    if (!service || !date || !slot) return;
    setConfirmError(null);
    setSubmitting(true);

    const code = generateConfirmationCode();
    const booking = {
      confirmationCode: code,
      service: { id: service.id, name: service.name, priceCents: service.priceCents },
      scheduledFor: `${date.toDateString()} ${slot}`,
      durationMinutes: service.durationMinutes,
      customer: info,
      shirts: Object.entries(addedShirts).map(([shirtId, size]) => {
        const s = shirts.find((x) => x.id === shirtId)!;
        return { shirtId, name: s.name, size, priceCents: s.priceCents };
      }),
      paymentMethod: payment,
      paymentStatus: "unpaid",
      status: "confirmed",
      totalCents,
    };
    console.log("[booking] appointment payload:", booking);
    sessionStorage.setItem(
      `ths-booking-${code}`,
      JSON.stringify({
        ...booking,
        dateISO: date.toISOString(),
        slot,
      })
    );
    router.push(`/book/confirmed/${code}`);
  }

  const stepMotion = {
    initial: { opacity: 0, x: 24 },
    animate: { opacity: 1, x: 0 },
    exit: { opacity: 0, x: -24 },
    transition: { duration: 0.4, ease: [0.22, 1, 0.36, 1] as const },
  };

  return (
    <div className="mx-auto max-w-3xl">
      {/* Progress */}
      <div className="flex items-center gap-2" aria-hidden>
        {steps.map((_, i) => (
          <span
            key={i}
            className={cn(
              "h-0.5 flex-1 transition-colors duration-500",
              i <= step ? "bg-forest" : "bg-stone-300"
            )}
          />
        ))}
      </div>
      <p className="eyebrow mt-6 text-stone-500">
        Step {step + 1} of 4 · {steps[step]}
      </p>

      <AnimatePresence mode="wait">
        {/* -------- STEP 1: SERVICE -------- */}
        {step === 0 && (
          <motion.div key="step-0" {...stepMotion} className="mt-10">
            <div className="flex flex-col gap-3" role="radiogroup" aria-label="Service">
              {services.map((svc) => (
                <button
                  key={svc.id}
                  role="radio"
                  aria-checked={service?.id === svc.id}
                  onClick={() => {
                    setService(svc);
                    setSlot(null);
                  }}
                  className={cn(
                    "flex flex-wrap items-baseline justify-between gap-3 border-[0.5px] px-6 py-5 text-left transition-all duration-300",
                    service?.id === svc.id
                      ? "border-forest bg-forest text-cream"
                      : "border-ink/20 hover:border-ink"
                  )}
                >
                  <span>
                    <span className="font-display text-xl tracking-tight">{svc.name}</span>
                    {svc.mostPopular && (
                      <span
                        className={cn(
                          "mono-micro ml-3 border-[0.5px] px-1.5 py-0.5",
                          service?.id === svc.id
                            ? "border-cream/40 text-cream/80"
                            : "border-forest text-forest"
                        )}
                      >
                        Most booked
                      </span>
                    )}
                  </span>
                  <span className="flex items-baseline gap-6">
                    <span
                      className={cn(
                        "font-mono text-xs tracking-widest uppercase",
                        service?.id === svc.id ? "text-cream/70" : "text-stone-500"
                      )}
                    >
                      {svc.durationMinutes} min
                    </span>
                    <span className="font-mono text-lg">{formatPrice(svc.priceCents)}</span>
                  </span>
                </button>
              ))}
            </div>
            {service && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mt-8">
                <Button size="large" arrow onClick={() => setStep(1)}>
                  Continue
                </Button>
              </motion.div>
            )}
          </motion.div>
        )}

        {/* -------- STEP 2: DATE & TIME -------- */}
        {step === 1 && (
          <motion.div key="step-1" {...stepMotion} className="mt-10">
            <div className="grid gap-12 md:grid-cols-2">
              <Calendar
                selected={date}
                onSelect={(d) => {
                  setDate(d);
                  setSlot(null);
                }}
              />
              <div>
                <p className="font-display text-2xl tracking-tight">
                  {date ? formatDateLong(date) : "Pick a date"}
                </p>
                {date && slots.length === 0 && (
                  <p className="mt-6 text-sm text-stone-500">
                    {weeklyHours[date.getDay()].open
                      ? "Fully booked that day. Try another."
                      : "The studio is closed that day."}
                  </p>
                )}
                <div className="mt-6 grid grid-cols-3 gap-2">
                  {slots.map((s) => (
                    <button
                      key={s}
                      type="button"
                      onClick={() => setSlot(s)}
                      aria-pressed={slot === s}
                      className={cn(
                        "border-[0.5px] px-2 py-3 font-mono text-sm tabular-nums transition-colors duration-200",
                        slot === s
                          ? "border-forest bg-forest text-cream"
                          : "border-ink/20 hover:border-ink"
                      )}
                    >
                      {formatTime12(s)}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <div className="mt-10 flex items-center gap-6">
              <Button variant="secondary" onClick={() => setStep(0)}>
                ← Back
              </Button>
              {slot && (
                <Button size="large" arrow onClick={() => setStep(2)}>
                  Continue
                </Button>
              )}
            </div>
          </motion.div>
        )}

        {/* -------- STEP 3: INFO -------- */}
        {step === 2 && (
          <motion.div key="step-2" {...stepMotion} className="mt-10">
            <div className="grid gap-8 sm:grid-cols-2">
              {(
                [
                  { key: "firstName", label: "First name", type: "text", auto: "given-name" },
                  { key: "lastName", label: "Last name", type: "text", auto: "family-name" },
                  { key: "email", label: "Email", type: "email", auto: "email" },
                  { key: "phone", label: "Phone", type: "tel", auto: "tel" },
                ] as const
              ).map((field) => (
                <div key={field.key}>
                  <label htmlFor={`bk-${field.key}`} className="eyebrow text-stone-500">
                    {field.label}
                  </label>
                  <input
                    id={`bk-${field.key}`}
                    type={field.type}
                    autoComplete={field.auto}
                    value={info[field.key]}
                    onChange={(e) => setInfo({ ...info, [field.key]: e.target.value })}
                    className="input-line mt-2"
                  />
                  {errors[field.key] && (
                    <p role="alert" aria-live="polite" className="mt-2 text-xs text-error">
                      {errors[field.key]}
                    </p>
                  )}
                </div>
              ))}
              <div className="sm:col-span-2">
                <label htmlFor="bk-notes" className="eyebrow text-stone-500">
                  Notes <span className="normal-case">(optional)</span>
                </label>
                <textarea
                  id="bk-notes"
                  rows={3}
                  value={info.notes}
                  onChange={(e) => setInfo({ ...info, notes: e.target.value })}
                  className="input-line mt-2 resize-none"
                  placeholder="Reference photos? Mention them here or DM @tedishairstudio."
                />
              </div>
            </div>

            {/* Shirt add-on */}
            <div className="hairline-strong mt-12 bg-cream">
              <button
                type="button"
                onClick={() => setShirtOpen((v) => !v)}
                aria-expanded={shirtOpen}
                className="flex w-full items-center justify-between px-6 py-5 text-left"
              >
                <span className="font-display text-lg tracking-tight">
                  Add a shirt to this appointment?
                </span>
                <span aria-hidden className="font-mono text-sm">
                  {shirtOpen ? "−" : "+"}
                </span>
              </button>
              <AnimatePresence>
                {shirtOpen && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
                    className="overflow-hidden"
                  >
                    <div className="flex flex-col gap-5 px-6 pb-6">
                      {forSaleShirts.map((shirt) => {
                        const added = addedShirts[shirt.id];
                        return (
                          <div
                            key={shirt.id}
                            className="hairline-t flex flex-wrap items-center justify-between gap-4 pt-5"
                          >
                            <div className="flex items-center gap-4">
                              <BearLogo size={32} className="text-forest" label="" />
                              <div>
                                <p className="text-sm font-medium">{shirt.name}</p>
                                <p className="font-mono text-xs text-stone-500">
                                  {formatPrice(shirt.priceCents)}
                                </p>
                              </div>
                            </div>
                            <div className="flex items-center gap-1.5">
                              {shirt.availableSizes.map((size) => (
                                <button
                                  key={size}
                                  type="button"
                                  onClick={() =>
                                    setAddedShirts((prev) => {
                                      const next = { ...prev };
                                      if (next[shirt.id] === size) delete next[shirt.id];
                                      else next[shirt.id] = size;
                                      return next;
                                    })
                                  }
                                  aria-pressed={added === size}
                                  className={cn(
                                    "min-w-10 border-[0.5px] px-2 py-1.5 font-mono text-xs transition-colors",
                                    added === size
                                      ? "border-forest bg-forest text-cream"
                                      : "border-ink/20 hover:border-ink"
                                  )}
                                >
                                  {size}
                                </button>
                              ))}
                            </div>
                          </div>
                        );
                      })}
                      <p className="text-xs text-stone-500">
                        Tap a size to add, tap again to remove. Shirts are handed over at the cut.
                      </p>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            <div className="mt-10 flex items-center gap-6">
              <Button variant="secondary" onClick={() => setStep(1)}>
                ← Back
              </Button>
              <Button
                size="large"
                arrow
                onClick={() => {
                  if (validateInfo()) setStep(3);
                }}
              >
                Continue
              </Button>
            </div>
          </motion.div>
        )}

        {/* -------- STEP 4: PAYMENT & CONFIRM -------- */}
        {step === 3 && service && date && slot && (
          <motion.div key="step-3" {...stepMotion} className="mt-10">
            {/* Summary */}
            <div className="hairline-strong bg-forest p-8 text-cream">
              <p className="eyebrow text-cream/50">Your appointment</p>
              <div className="mt-5 flex flex-col gap-2.5 text-sm">
                <div className="flex justify-between">
                  <span className="font-display text-xl tracking-tight">{service.name}</span>
                  <span className="font-mono">{formatPrice(service.priceCents)}</span>
                </div>
                <p className="text-cream/80">
                  {formatDateLong(date)} · {formatTime12(slot)} · {service.durationMinutes} min
                </p>
                {Object.entries(addedShirts).map(([shirtId, size]) => {
                  const s = shirts.find((x) => x.id === shirtId)!;
                  return (
                    <div key={shirtId} className="flex justify-between text-cream/80">
                      <span>
                        + {s.name} ({size})
                      </span>
                      <span className="font-mono">{formatPrice(s.priceCents)}</span>
                    </div>
                  );
                })}
                <div className="hairline-cream-t mt-3 flex justify-between pt-3">
                  <span className="eyebrow text-cream/50">Total</span>
                  <span className="font-mono text-lg">{formatPrice(totalCents)}</span>
                </div>
              </div>
            </div>

            {/* Payment */}
            <fieldset className="mt-10">
              <legend className="eyebrow text-stone-500">Payment</legend>
              <div className="mt-4 flex flex-col gap-3">
                {(
                  [
                    { key: "cash", label: "Cash · at the studio" },
                    {
                      key: "zelle",
                      label: "Zelle · at the studio (you'll get the Zelle handle in confirmation)",
                    },
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
                      name="bk-payment"
                      checked={payment === opt.key}
                      onChange={() => setPayment(opt.key)}
                      className="accent-[#1A2F23]"
                    />
                    {opt.label}
                  </label>
                ))}
              </div>
            </fieldset>

            <label className="mt-8 flex cursor-pointer items-start gap-3 text-sm leading-relaxed text-stone-700">
              <input
                type="checkbox"
                checked={agreed}
                onChange={(e) => setAgreed(e.target.checked)}
                className="mt-1 accent-[#1A2F23]"
              />
              I understand this is a private studio, by appointment only.
              Cancellations within 24h forfeit any deposit.
            </label>
            {confirmError && (
              <p role="alert" aria-live="polite" className="mt-3 text-xs text-error">
                {confirmError}
              </p>
            )}

            <div className="mt-10 flex flex-col gap-4">
              <Button
                size="large"
                arrow
                onClick={confirmBooking}
                disabled={submitting}
                className="w-full"
              >
                {submitting ? "Locking it in…" : "Confirm booking"}
              </Button>
              <Button variant="ghost" onClick={() => setStep(2)} className="self-start text-stone-500">
                ← Back to details
              </Button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
