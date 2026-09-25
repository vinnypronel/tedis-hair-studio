export type DayHours = {
  dayOfWeek: number; // 0 = Sunday
  label: string;
  open: string | null; // "HH:mm" 24h, null = closed
  close: string | null;
};

export const weeklyHours: DayHours[] = [
  { dayOfWeek: 0, label: "Sunday", open: null, close: null },
  { dayOfWeek: 1, label: "Monday", open: "10:00", close: "20:00" },
  { dayOfWeek: 2, label: "Tuesday", open: "10:00", close: "20:00" },
  { dayOfWeek: 3, label: "Wednesday", open: "10:00", close: "20:00" },
  { dayOfWeek: 4, label: "Thursday", open: "10:00", close: "20:00" },
  { dayOfWeek: 5, label: "Friday", open: "10:00", close: "20:00" },
  { dayOfWeek: 6, label: "Saturday", open: "09:00", close: "17:00" },
];

export function formatHour(time: string): string {
  const [h, m] = time.split(":").map(Number);
  const period = h >= 12 ? "PM" : "AM";
  const hour12 = h % 12 === 0 ? 12 : h % 12;
  return m === 0 ? `${hour12} ${period}` : `${hour12}:${String(m).padStart(2, "0")} ${period}`;
}

/* Slot generation (getAvailableSlots, isDateBookable) lived here for the on-site
   booking flow. Booking now runs on Booksy, so both were archived. See
   archive/BOOKING-FEATURE.md section 3a to bring them back. */

/** Returns true if the studio is open right now (America/New_York). */
export function isOpenNow(now: Date = new Date()): boolean {
  const est = new Date(now.toLocaleString("en-US", { timeZone: "America/New_York" }));
  const day = weeklyHours[est.getDay()];
  if (!day.open || !day.close) return false;
  const mins = est.getHours() * 60 + est.getMinutes();
  const [oH, oM] = day.open.split(":").map(Number);
  const [cH, cM] = day.close.split(":").map(Number);
  return mins >= oH * 60 + oM && mins < cH * 60 + cM;
}
