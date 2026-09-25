"use client";

import { useEffect, useState } from "react";
import { formatPrice } from "@/lib/data/services";
import { formatDateLong, formatTime12 } from "@/lib/utils";
import {
  clearBookings,
  getBookings,
  type StoredBooking,
} from "@/lib/data/bookings";

/**
 * Live booking log pulled from localStorage (demo persistence). Shows every
 * appointment confirmed in this browser with the full captured payload, so
 * Tedi can see bookings land in the dashboard before the backend exists.
 */
export function LiveBookings() {
  const [bookings, setBookings] = useState<StoredBooking[] | null>(null);

  useEffect(() => {
    setBookings(getBookings());
  }, []);

  // Not yet hydrated: render nothing to avoid a server/client mismatch.
  if (bookings === null) return null;

  const unpaid = bookings.filter((b) => b.paymentStatus === "unpaid").length;
  const shirtOrders = bookings.filter((b) => b.shirts.length > 0).length;

  return (
    <section className="mt-10">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <div>
          <p className="eyebrow text-stone-500">Live bookings</p>
          <h2 className="heading-1 mt-2 text-2xl">
            {bookings.length === 0
              ? "No bookings yet"
              : `${bookings.length} booking${bookings.length === 1 ? "" : "s"} logged`}
          </h2>
        </div>
        {bookings.length > 0 && (
          <div className="flex items-center gap-6">
            <span className="mono-micro text-stone-500">
              {unpaid} unpaid · {shirtOrders} with shirts
            </span>
            <button
              type="button"
              onClick={() => {
                clearBookings();
                setBookings([]);
              }}
              className="mono-micro border-[0.5px] border-stone-300 px-3 py-1.5 text-stone-500 transition-colors hover:border-ink hover:text-ink"
            >
              Clear demo log
            </button>
          </div>
        )}
      </div>

      <p className="mono-micro mt-2 text-stone-400">
        Stored in this browser only (demo). Real bookings sync server-side once
        the backend phase begins.
      </p>

      {bookings.length === 0 ? (
        <div className="hairline-strong mt-5 bg-cream p-8 text-sm text-stone-500">
          Confirm a booking on{" "}
          <span className="font-mono">/book</span> and it will appear here with
          the full client and appointment details.
        </div>
      ) : (
        <div className="hairline-strong mt-5 overflow-x-auto bg-cream">
          <table className="w-full min-w-[880px] text-sm">
            <thead>
              <tr className="hairline-b text-left">
                {[
                  "Code",
                  "Booked",
                  "Client",
                  "Contact",
                  "Service",
                  "When",
                  "Add-ons",
                  "Payment",
                  "Total",
                ].map((h) => (
                  <th
                    key={h}
                    className="eyebrow px-4 py-3 font-medium whitespace-nowrap text-stone-500"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {bookings.map((b) => (
                <tr key={b.confirmationCode} className="hairline-b align-top">
                  <td className="px-4 py-4 font-mono text-xs tracking-widest whitespace-nowrap">
                    {b.confirmationCode}
                  </td>
                  <td className="px-4 py-4 text-xs whitespace-nowrap text-stone-500">
                    {new Date(b.createdAtISO).toLocaleString("en-US", {
                      month: "short",
                      day: "numeric",
                      hour: "numeric",
                      minute: "2-digit",
                    })}
                  </td>
                  <td className="px-4 py-4 whitespace-nowrap">
                    <span className="font-medium">
                      {b.customer.firstName} {b.customer.lastName}
                    </span>
                    {b.customer.notes ? (
                      <span className="mt-1 block max-w-[220px] text-xs whitespace-normal text-stone-500">
                        “{b.customer.notes}”
                      </span>
                    ) : null}
                  </td>
                  <td className="px-4 py-4 text-xs whitespace-nowrap text-stone-700">
                    <a
                      href={`mailto:${b.customer.email}`}
                      className="underline underline-offset-2"
                    >
                      {b.customer.email}
                    </a>
                    <span className="mt-1 block font-mono text-stone-500">
                      {b.customer.phone}
                    </span>
                  </td>
                  <td className="px-4 py-4 whitespace-nowrap">
                    {b.service.name}
                    <span className="mt-1 block text-xs text-stone-500">
                      {b.durationMinutes} min · {formatPrice(b.service.priceCents)}
                    </span>
                  </td>
                  <td className="px-4 py-4 whitespace-nowrap">
                    {formatDateLong(new Date(b.dateISO))}
                    <span className="mt-1 block font-mono text-xs text-stone-500">
                      {formatTime12(b.slot)}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-xs text-stone-700">
                    {b.shirts.length === 0 ? (
                      <span className="text-stone-400">—</span>
                    ) : (
                      b.shirts.map((s) => (
                        <span key={s.shirtId + s.size} className="block whitespace-nowrap">
                          {s.name} ({s.size}) · {formatPrice(s.priceCents)}
                        </span>
                      ))
                    )}
                  </td>
                  <td className="px-4 py-4 whitespace-nowrap">
                    <span className="text-xs text-stone-700 capitalize">
                      {b.paymentMethod}
                    </span>
                    <span
                      className={
                        b.paymentStatus === "paid"
                          ? "mono-micro mt-1 block w-fit border-[0.5px] border-success px-2 py-0.5 text-success"
                          : "mono-micro mt-1 block w-fit border-[0.5px] border-stone-300 px-2 py-0.5 text-stone-500"
                      }
                    >
                      {b.paymentStatus === "paid" ? "Paid" : "Unpaid"}
                    </span>
                  </td>
                  <td className="px-4 py-4 font-mono whitespace-nowrap">
                    {formatPrice(b.totalCents)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
