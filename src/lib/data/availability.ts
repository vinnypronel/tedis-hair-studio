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

/**
 * Mock slot generation. Mirrors what the server will eventually compute from
 * availability_blocks − appointments − overrides. Deterministically "books out"
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
