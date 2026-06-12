"use client";

import Link from "next/link";
import { use, useEffect, useState } from "react";
import { BearLogo } from "@/components/site/bear-logo";
import { formatPrice } from "@/lib/data/services";
import { content } from "@/lib/data/content";
import { formatDateLong, formatTime12 } from "@/lib/utils";

type StoredBooking = {
  confirmationCode: string;
  service: { name: string; priceCents: number };
  dateISO: string;
  slot: string;
  durationMinutes: number;
  customer: { firstName: string; email: string };
  shirts: { name: string; size: string; priceCents: number }[];
  paymentMethod: "cash" | "zelle";
  totalCents: number;
};

function googleCalUrl(b: StoredBooking): string {
  const start = new Date(b.dateISO);
  const [h, m] = b.slot.split(":").map(Number);
  start.setHours(h, m, 0, 0);
  const end = new Date(start.getTime() + b.durationMinutes * 60000);
  const fmt = (d: Date) =>
    d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const params = new URLSearchParams({
    action: "TEMPLATE",
    text: `${b.service.name} at Tedi's Hair Studio`,
    dates: `${fmt(start)}/${fmt(end)}`,
    location: "259 Broad St #103, Matawan, NJ 07747",
    details: `Confirmation code: ${b.confirmationCode}`,
  });
  return `https://calendar.google.com/calendar/render?${params}`;
}

function downloadIcs(b: StoredBooking) {
  const start = new Date(b.dateISO);
  const [h, m] = b.slot.split(":").map(Number);
  start.setHours(h, m, 0, 0);
  const end = new Date(start.getTime() + b.durationMinutes * 60000);
  const fmt = (d: Date) =>
    d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const ics = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//Tedis Hair Studio//Booking//EN",
    "BEGIN:VEVENT",
    `UID:${b.confirmationCode}@tedishairstudio.com`,
    `DTSTAMP:${fmt(new Date())}`,
    `DTSTART:${fmt(start)}`,
    `DTEND:${fmt(end)}`,
    `SUMMARY:${b.service.name} at Tedi's Hair Studio`,
    "LOCATION:259 Broad St #103\\, Matawan\\, NJ 07747",
    `DESCRIPTION:Confirmation code: ${b.confirmationCode}`,
    "END:VEVENT",
    "END:VCALENDAR",
  ].join("\r\n");
  const blob = new Blob([ics], { type: "text/calendar" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `tedis-hair-studio-${b.confirmationCode}.ics`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ConfirmedPage({
  params,
}: {
  params: Promise<{ code: string }>;
}) {
  const { code } = use(params);
  const [booking, setBooking] = useState<StoredBooking | null>(null);

  useEffect(() => {
    const raw = sessionStorage.getItem(`ths-booking-${code}`);
    if (raw) setBooking(JSON.parse(raw));
  }, [code]);

  return (
    <div className="px-6 pt-36 pb-24 md:px-12 lg:px-20 lg:pt-44 lg:pb-36">
      <div className="mx-auto max-w-2xl">
        <div className="text-center">
          <BearLogo size={72} className="mx-auto text-forest" />
          <p className="eyebrow mt-10 text-stone-500">Confirmed</p>
          <h1 className="display-lg mt-6 italic">You&rsquo;re in.</h1>
          <p
            className="mt-10 font-mono text-5xl tracking-[0.25em] md:text-6xl"
            aria-label={`Confirmation code ${code}`}
          >
            {code}
          </p>
          <p className="mono-micro mt-3 text-stone-500">Your confirmation code</p>
        </div>

        {booking ? (
          <div className="hairline-strong mt-14 bg-cream p-8">
            <div className="flex flex-col gap-3 text-sm">
              <div className="flex justify-between">
                <span className="font-display text-xl tracking-tight">
                  {booking.service.name}
                </span>
                <span className="font-mono">{formatPrice(booking.service.priceCents)}</span>
              </div>
              <p className="text-stone-700">
                {formatDateLong(new Date(booking.dateISO))} · {formatTime12(booking.slot)} ·{" "}
                {booking.durationMinutes} min
              </p>
              {booking.shirts.map((s, i) => (
                <div key={i} className="flex justify-between text-stone-700">
                  <span>
                    + {s.name} ({s.size}) · packed for pickup
                  </span>
                  <span className="font-mono">{formatPrice(s.priceCents)}</span>
                </div>
              ))}
              <div className="hairline-t mt-3 flex justify-between pt-3">
                <span className="eyebrow text-stone-500">
                  Total · {booking.paymentMethod} at the studio
                </span>
                <span className="font-mono text-lg">{formatPrice(booking.totalCents)}</span>
              </div>
            </div>

            {booking.paymentMethod === "zelle" && (
              <div className="mt-6 border-[0.5px] border-forest bg-forest/5 p-5 text-sm leading-relaxed">
                <p className="eyebrow text-forest">Zelle instructions</p>
                <p className="mt-2 text-stone-700">
                  Send {formatPrice(booking.totalCents)} to{" "}
                  <span className="font-mono">{content.contact.phone}</span> (Tedi&rsquo;s
                  Hair Studio) any time before your appointment, or pay at the chair.
                </p>
              </div>
            )}

            <div className="mt-8 flex flex-wrap gap-4">
              <button
                onClick={() => downloadIcs(booking)}
                className="rounded-[2px] border-[0.5px] border-ink/40 px-5 py-3 text-sm transition-colors hover:bg-ink hover:text-cream"
              >
                Add to calendar (.ics)
              </button>
              <a
                href={googleCalUrl(booking)}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-[2px] border-[0.5px] border-ink/40 px-5 py-3 text-sm transition-colors hover:bg-ink hover:text-cream"
              >
                Google Calendar
              </a>
            </div>
          </div>
        ) : (
          <p className="mt-14 text-center text-sm text-stone-500">
            Booking details saved. Bring your confirmation code to the studio.
          </p>
        )}

        <div className="mt-12 flex flex-col gap-3 text-center text-sm text-stone-700">
          <p>
            <span className="mono-micro text-stone-500">Where ·</span>{" "}
            {content.contact.addressInside} · {content.contact.addressLine1},{" "}
            {content.contact.addressLine2}{" "}
            <a
              href={content.contact.googleMapsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="underline underline-offset-4"
            >
              (map)
            </a>
          </p>
          <p>
            Need to change?{" "}
            <a href={content.contact.phoneHref} className="underline underline-offset-4">
              Text {content.contact.phone}
            </a>{" "}
            or email{" "}
            <a href={`mailto:${content.contact.email}`} className="underline underline-offset-4">
              {content.contact.email}
            </a>
          </p>
          <a
            href={content.social.instagram}
            target="_blank"
            rel="noopener noreferrer"
            className="link-draw mx-auto mt-4 w-fit text-sm font-medium"
          >
            Follow {content.social.instagramHandle} →
          </a>
          <Link href="/" className="link-draw mx-auto mt-2 w-fit text-sm text-stone-500">
            Back home
          </Link>
        </div>
      </div>
    </div>
  );
}
