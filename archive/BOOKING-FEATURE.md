# Archived: On-Site Booking Feature (Tedi's Hair Studio)

**Archived:** 2026-08-24
**Reason:** Tedi books through Booksy. The site now sends every "Book Now" action to his Booksy
storefront instead of running its own booking flow.
**Status:** Fully removed from the live site. All source preserved under `archive/booking/`.
Nothing in `src/` imports any of it, and `archive/` is excluded from `tsconfig.json`, so these
files are not compiled or type-checked.

---

## 1. What it was

A four-step, no-account booking flow at `/book`, plus a confirmation screen at
`/book/confirmed/[code]`. Frontend-only: it validated with Zod, logged the payload to the
console, wrote the booking to `localStorage` (so it showed up in the admin dashboard) and to
`sessionStorage` (so the confirmation screen could render it).

The four steps:

1. **Choose your service** - radio list of the five services from `src/lib/data/services.ts`,
   with the "Most booked" marker on Basic Haircut. Supported deep-linking via
   `/book?service=<slug>`, which preselected the service.
2. **Pick a time** - custom month calendar (no date library) plus a time-slot grid. Sundays and
   past dates disabled, slots generated from `weeklyHours` and the service duration.
3. **Your details** - first name, last name, email, phone, optional notes. Zod-validated.
   Included a collapsible "Add a shirt to this appointment?" panel that let a client attach a
   for-sale tee (size selectable) to the appointment.
4. **How you'll pay** - appointment summary, cash or Zelle radio, terms checkbox, confirm.

On confirm it generated a 6-char code (e.g. `7K4M9X`), saved the booking, and routed to the
confirmation page, which showed the code, the summary, Zelle instructions when relevant, an
`.ics` download, and a Google Calendar link.

---

## 2. Files in this archive

| Archived path | Original path |
| --- | --- |
| `archive/booking/app/book/page.tsx` | `src/app/book/page.tsx` |
| `archive/booking/app/book/confirmed/[code]/page.tsx` | `src/app/book/confirmed/[code]/page.tsx` |
| `archive/booking/components/booking-flow.tsx` | `src/components/book/booking-flow.tsx` |
| `archive/booking/lib/bookings.ts` | `src/lib/data/bookings.ts` |
| `archive/booking/admin/live-bookings.tsx` | `src/components/admin/live-bookings.tsx` |

Restoring is a straight copy back to the original paths.

---

## 3. Code that was deleted from files that still exist

These are the pieces that lived inside files still in use. They were removed rather than moved,
so they are reproduced here verbatim.

### 3a. `src/lib/data/availability.ts` - slot generation

`weeklyHours`, `formatHour`, and `isOpenNow` are still in the live file (the footer, contact
page, home Visit section, and the live clock use them). These two functions were booking-only
and were removed:

```ts
/**
 * Mock slot generation. Mirrors what the server will eventually compute from
 * availability_blocks - appointments - overrides. Deterministically "books out"
 * a few slots per day so the calendar looks real.
 */
export function getAvailableSlots(date: Date, durationMinutes: number): string[] {
  const day = weeklyHours[date.getDay()];
  if (!day.open || !day.close) return [];

  const [openH, openM] = day.open.split(":").map(Number);
  const [closeH, closeM] = day.close.split(":").map(Number);
  const openMins = openH * 60 + openM;
  const closeMins = closeH * 60 + closeM;

  const slots: string[] = [];
  // pseudo-random but stable per date: pretend some slots are taken
  const seed = date.getFullYear() * 372 + (date.getMonth() + 1) * 31 + date.getDate();

  for (let t = openMins; t + durationMinutes <= closeMins; t += durationMinutes) {
    const taken = (seed * 2654435761 + t * 97) % 100 < 30; // ~30% booked
    if (taken) continue;
    const h = Math.floor(t / 60);
    const m = t % 60;
    slots.push(`${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`);
  }
  return slots;
}

export function isDateBookable(date: Date): boolean {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  if (date < today) return false;
  const day = weeklyHours[date.getDay()];
  return day.open !== null;
}
```

### 3b. `src/lib/utils.ts` - confirmation codes

`cn`, `formatDateLong`, and `formatTime12` are still live. This one was booking/checkout only:

```ts
/** 6-char uppercase alphanumeric confirmation code, e.g. 7K4M9X */
export function generateConfirmationCode(): string {
  const chars = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // no 0/O, 1/I/L
  let code = "";
  for (let i = 0; i < 6; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}
```

### 3c. `src/app/admin/dashboard/page.tsx` - live booking log

The dashboard rendered `<LiveBookings />` between the page heading and the sample snapshot:

```tsx
import { LiveBookings } from "@/components/admin/live-bookings";
...
        {/* Real bookings confirmed in this browser */}
        <LiveBookings />

        {/* Demo snapshot below (static placeholder data until the backend phase) */}
        <p className="eyebrow mt-14 text-stone-400">Sample snapshot · placeholder data</p>
```

The `modules` array also carried an `Appointments` entry
(`{ name: "Appointments", note: "Calendar + list view", href: null }`), and the stat cards
included `{ label: "Today", value: "5", note: "appointments" }` and
`{ label: "This week", value: "23", note: "booked · next free slot Thu 2 PM" }`.

---

## 4. Call sites: what pointed at `/book`

Every one of these now points at `content.booking.url` (Booksy). To reinstate on-site booking,
swap each back to an internal `next/link` to `/book`.

| File | What it was |
| --- | --- |
| `src/components/site/header.tsx` | Desktop "Book Now" button: `<Link href="/book">`; mobile overlay nav item `{ href: "/book", label: "Book" }` |
| `src/components/site/footer.tsx` | "Book Now" bone button in the Connect column: `<Link href="/book">` |
| `src/components/home/hero.tsx` | Hero primary CTA: `<Link href="/book">` wrapping `content.hero.ctaPrimary` |
| `src/components/home/sections.tsx` | `ServicesTeaser` rows linked to `/book?service=<slug>` |
| `src/app/services/page.tsx` | "Book this" per service, linked to `/book?service=<slug>` |
| `src/app/about/page.tsx` | "Book with Tedi": `<ButtonLink href="/book" size="large" arrow>` |
| `src/app/sitemap.ts` | `/book` was in `staticRoutes` |

The `?service=<slug>` deep link mattered: `BookingFlow` read it with `useSearchParams()` and
preselected that service, which is why `/book` was wrapped in `<Suspense>`. Booksy has no
equivalent per-service deep link on the widget URL, so every CTA now lands on the same page.

---

## 5. Data contract (mirrors the future DB row)

From `archive/booking/lib/bookings.ts`:

```ts
export type StoredBooking = {
  confirmationCode: string;
  createdAtISO: string;
  service: { id: string; name: string; priceCents: number };
  dateISO: string;
  slot: string;              // "HH:mm" 24h
  scheduledFor: string;      // human string, e.g. "Tue Aug 25 2026 14:30"
  durationMinutes: number;
  customer: { firstName: string; lastName: string; email: string; phone: string; notes?: string };
  shirts: { shirtId: string; name: string; size: string; priceCents: number }[];
  paymentMethod: "cash" | "zelle";
  paymentStatus: "unpaid" | "paid";
  status: "confirmed" | "cancelled";
  totalCents: number;
};
```

Storage keys used:

- `ths-bookings` (localStorage) - the full booking log, newest first, read by the admin dashboard.
- `ths-booking-<CODE>` (sessionStorage) - per-code copy for the confirmation screen.

Zod schema for step 3:

```ts
const infoSchema = z.object({
  firstName: z.string().min(1, "First name required"),
  lastName: z.string().min(1, "Last name required"),
  email: z.string().email("That email doesn't look right"),
  phone: z.string().min(10, "A real phone number, please"),
  notes: z.string().optional(),
});
```

---

## 6. Copy that lived in the flow (reuse it verbatim)

- Page title: "The chair is *yours.*" / sub: "Four steps, no account, no waiting room. Private appointments only."
- Step labels: "Choose your service", "Pick a time", "Your details", "How you'll pay"
- Progress line: "Step {n} of 4 · {step label}"
- Calendar footnote: "Closed Sundays · Sat 9-5 · Mon-Fri 10-8"
- Empty day: "Fully booked that day. Try another." / "The studio is closed that day."
- Shirt panel: "Add a shirt to this appointment?" / "Tap a size to add, tap again to remove. Shirts are handed over at the cut."
- Terms checkbox: "I understand this is a private studio, by appointment only. Cancellations within 24h forfeit any deposit."
- Confirm button: "Confirm booking" / pending state: "Locking it in…"
- Confirmation page: "You're in." / "Your confirmation code" / "Booking details saved. Bring your confirmation code to the studio."
- Zelle block: "Send {total} to {phone} (Tedi's Hair Studio) any time before your appointment, or pay at the chair."

No em dashes anywhere in it. Keep it that way.

---

## 7. How to reinstate

1. Copy the five files in `archive/booking/` back to their original paths (table in section 2).
2. Paste `getAvailableSlots` and `isDateBookable` back into `src/lib/data/availability.ts`, and
   `generateConfirmationCode` back into `src/lib/utils.ts`.
3. Point the call sites in section 4 back at `/book`. The single switch to flip is
   `content.booking.url` in `src/lib/data/content.ts`, plus the `external` handling in
   `src/components/ui/button.tsx` and `src/components/site/book-link.tsx`.
4. Add `"/book"` back to `staticRoutes` in `src/app/sitemap.ts`.
5. Re-add `<LiveBookings />` to the admin dashboard (section 3c) if the demo log is still wanted.
6. If the shirt add-on step is wanted, `archive/SHOP-CHECKOUT-FEATURE.md` covers what
   `status: "for_sale"` shirts need.

### If a real backend comes online instead of the mock

The mock layer was deliberately shaped like the eventual schema, so the swap stays one file per
domain:

- `src/lib/data/bookings.ts` - replace the localStorage reads/writes with API calls. Keep the
  `getBookings()`, `saveBooking()`, `getBookingByCode()`, `clearBookings()` signatures.
- `src/lib/data/availability.ts` - `getAvailableSlots()` becomes a server query over
  `availability_blocks - appointments - overrides`.
- The `console.log("[booking] appointment payload:", booking)` line in `confirmBooking()` is the
  exact point where a POST goes.
- Confirmation email/SMS was never built. That is new work.

### Conflict warning

If on-site booking ever comes back while the Booksy storefront is still live, two systems will
be writing to the same single chair with no shared availability. Pick one, or the calendar will
double-book Tedi.
