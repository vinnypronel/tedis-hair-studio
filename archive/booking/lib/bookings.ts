/**
 * Booking log (demo persistence layer).
 *
 * Frontend-only build: every confirmed appointment is appended here and stored
 * in localStorage so it survives navigation and shows up in the admin dashboard.
 * Shape mirrors the future DB row so the backend swap-in stays one file per
 * domain. Replace the localStorage reads/writes with API calls when the backend
 * phase begins; the types and function signatures stay the same.
 */

export type BookingShirt = {
  shirtId: string;
  name: string;
  size: string;
  priceCents: number;
};

export type StoredBooking = {
  confirmationCode: string;
  createdAtISO: string;
  service: { id: string; name: string; priceCents: number };
  dateISO: string;
  slot: string;
  scheduledFor: string;
  durationMinutes: number;
  customer: {
    firstName: string;
    lastName: string;
    email: string;
    phone: string;
    notes?: string;
  };
  shirts: BookingShirt[];
  paymentMethod: "cash" | "zelle";
  paymentStatus: "unpaid" | "paid";
  status: "confirmed" | "cancelled";
  totalCents: number;
};

const KEY = "ths-bookings";

/** All bookings logged in this browser, newest first. Empty on the server. */
export function getBookings(): StoredBooking[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as StoredBooking[]) : [];
  } catch {
    return [];
  }
}

/** Append a booking (dedupes by confirmation code, keeps newest first). */
export function saveBooking(booking: StoredBooking): void {
  if (typeof window === "undefined") return;
  const existing = getBookings().filter(
    (b) => b.confirmationCode !== booking.confirmationCode
  );
  const next = [booking, ...existing];
  window.localStorage.setItem(KEY, JSON.stringify(next));
}

export function getBookingByCode(code: string): StoredBooking | null {
  return getBookings().find((b) => b.confirmationCode === code) ?? null;
}

/** Demo helper: wipe the local booking log. */
export function clearBookings(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(KEY);
}
