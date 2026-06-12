import type { Metadata } from "next";
import Link from "next/link";
import { BearLogo } from "@/components/site/bear-logo";

export const metadata: Metadata = {
  title: "Dashboard",
  robots: { index: false },
};

/* Static visual mockup with placeholder data. Real CRUD arrives with the
   backend phase. Shows Tedi the surface area of the admin. */

const todayAppointments = [
  { time: "10:00 AM", name: "Marcus T.", service: "Haircut w/ Beard", status: "Confirmed", paid: false },
  { time: "11:30 AM", name: "Devon R.", service: "Basic Haircut", status: "Confirmed", paid: true },
  { time: "1:00 PM", name: "Jordan K.", service: "Shape Up", status: "Confirmed", paid: false },
  { time: "3:30 PM", name: "Chris M.", service: "Basic Haircut", status: "Confirmed", paid: false },
  { time: "5:00 PM", name: "Sam W.", service: "Beard Trim", status: "Confirmed", paid: true },
];

const recentActivity = [
  { action: "appointment.create", detail: "Sam W. booked Beard Trim · 5:00 PM", time: "12 min ago" },
  { action: "order.create", detail: "The Mark Tee (L) attached to 7K4M9X", time: "1 hr ago" },
  { action: "appointment.paid", detail: "Devon R. marked paid · Zelle", time: "2 hrs ago" },
  { action: "review.publish", detail: "New 5-star review from Booksy import", time: "Yesterday" },
];

const modules = [
  { name: "Appointments", note: "Calendar + list view", href: null },
  { name: "Orders", note: "Shirt fulfillment", href: null },
  { name: "Shirts", note: "Product CRUD", href: null },
  { name: "Reviews", note: "Booksy import", href: null },
  { name: "Availability", note: "Weekly hours + overrides", href: null },
  { name: "Gallery", note: "Upload + manage photos", href: "/admin/gallery" },
  { name: "Content", note: "Site copy editor", href: null },
  { name: "Settings", note: "Password + notifications", href: null },
];

export default function AdminDashboardPage() {
  return (
    <div className="min-h-svh bg-stone-100">
      {/* Admin header */}
      <header className="bg-forest-deep text-cream">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <BearLogo size={32} className="text-cream" />
            <span className="font-display tracking-tight">Studio Admin</span>
            <span className="mono-micro ml-3 border-[0.5px] border-neon/60 px-2 py-0.5 text-neon">
              Demo preview
            </span>
          </div>
          <div className="flex items-center gap-6">
            <Link href="/" target="_blank" className="mono-micro text-cream/60 hover:text-cream">
              View as customer ↗
            </Link>
            <Link href="/admin" className="mono-micro text-cream/60 hover:text-cream">
              Log out
            </Link>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-6 py-10">
        <p className="eyebrow text-stone-500">Dashboard</p>
        <h1 className="heading-1 mt-3">Tuesday at the studio.</h1>

        {/* Stat cards */}
        <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { label: "Today", value: "5", note: "appointments" },
            { label: "This week", value: "23", note: "booked · next free slot Thu 2 PM" },
            { label: "Unpaid", value: "3", note: "past appointments to mark paid" },
            { label: "Orders pending", value: "2", note: "shirts to hand over" },
          ].map((stat) => (
            <div key={stat.label} className="hairline-strong bg-cream p-6">
              <p className="eyebrow text-stone-500">{stat.label}</p>
              <p className="font-display mt-3 text-5xl tracking-tight">{stat.value}</p>
              <p className="mt-2 text-xs text-stone-500">{stat.note}</p>
            </div>
          ))}
        </div>

        <div className="mt-8 grid gap-6 lg:grid-cols-3">
          {/* Today list */}
          <div className="hairline-strong bg-cream p-6 lg:col-span-2">
            <div className="flex items-baseline justify-between">
              <h2 className="font-display text-xl tracking-tight">Today</h2>
              <span className="mono-micro text-stone-500">5 appointments</span>
            </div>
            <table className="mt-5 w-full text-sm">
              <thead>
                <tr className="hairline-b text-left">
                  <th className="eyebrow pb-3 font-medium text-stone-500">Time</th>
                  <th className="eyebrow pb-3 font-medium text-stone-500">Client</th>
                  <th className="eyebrow hidden pb-3 font-medium text-stone-500 sm:table-cell">
                    Service
                  </th>
                  <th className="eyebrow pb-3 font-medium text-stone-500">Payment</th>
                </tr>
              </thead>
              <tbody>
                {todayAppointments.map((apt) => (
                  <tr key={apt.time} className="hairline-b">
                    <td className="py-3.5 font-mono text-xs">{apt.time}</td>
                    <td className="py-3.5 font-medium">{apt.name}</td>
                    <td className="hidden py-3.5 text-stone-700 sm:table-cell">{apt.service}</td>
                    <td className="py-3.5">
                      <span
                        className={
                          apt.paid
                            ? "mono-micro border-[0.5px] border-success px-2 py-1 text-success"
                            : "mono-micro border-[0.5px] border-stone-300 px-2 py-1 text-stone-500"
                        }
                      >
                        {apt.paid ? "Paid" : "Unpaid"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Activity */}
          <div className="hairline-strong bg-cream p-6">
            <h2 className="font-display text-xl tracking-tight">Recent activity</h2>
            <ul className="mt-5 flex flex-col gap-4">
              {recentActivity.map((item, i) => (
                <li key={i} className="hairline-b pb-4 last:border-0">
                  <p className="font-mono text-[10px] tracking-widest text-forest uppercase">
                    {item.action}
                  </p>
                  <p className="mt-1 text-sm">{item.detail}</p>
                  <p className="mt-1 text-xs text-stone-500">{item.time}</p>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Modules */}
        <h2 className="eyebrow mt-12 text-stone-500">Modules</h2>
        <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {modules.map((mod) =>
            mod.href ? (
              <Link
                key={mod.name}
                href={mod.href}
                className="hairline-strong bg-cream p-6 transition-colors hover:bg-stone-50"
              >
                <p className="font-display text-lg tracking-tight">{mod.name}</p>
                <p className="mt-1 text-xs text-stone-500">{mod.note}</p>
                <p className="mono-micro mt-4 text-forest">Open →</p>
              </Link>
            ) : (
              <div key={mod.name} className="hairline-strong bg-cream p-6 opacity-80">
                <p className="font-display text-lg tracking-tight">{mod.name}</p>
                <p className="mt-1 text-xs text-stone-500">{mod.note}</p>
                <p className="mono-micro mt-4 text-forest">Activates on launch</p>
              </div>
            )
          )}
        </div>
      </div>
    </div>
  );
}
