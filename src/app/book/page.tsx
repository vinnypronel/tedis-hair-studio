import type { Metadata } from "next";
import { Suspense } from "react";
import { Reveal } from "@/components/site/reveal";
import { BookingFlow } from "@/components/book/booking-flow";

export const metadata: Metadata = {
  title: "Book Your Chair",
  description:
    "Book a private appointment at Tedi's Hair Studio in Matawan, NJ. Pick a service, pick a time, the chair is yours.",
};

export default function BookPage() {
  return (
    <div className="px-6 pt-36 pb-24 md:px-12 lg:px-20 lg:pt-44 lg:pb-36">
      <div className="mx-auto max-w-3xl">
        <Reveal>
          <p className="eyebrow text-stone-500">Booking</p>
          <h1 className="display-lg mt-6">
            The chair is <em className="italic">yours.</em>
          </h1>
          <p className="mt-6 max-w-md text-base leading-relaxed text-stone-700">
            Four steps, no account, no waiting room. Private appointments only.
          </p>
        </Reveal>
      </div>
      <div className="mt-16">
        <Suspense fallback={null}>
          <BookingFlow />
        </Suspense>
      </div>
    </div>
  );
}
