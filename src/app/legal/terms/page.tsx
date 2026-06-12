import type { Metadata } from "next";
import { PageHeader } from "@/components/site/page-header";
import { content } from "@/lib/data/content";

export const metadata: Metadata = {
  title: "Terms of Service",
  robots: { index: false },
};

const sections = [
  {
    heading: "Appointments",
    body: "Tedi's Hair Studio is private and appointment-only. Your booking reserves the entire studio for your time slot. Please arrive on time. Arrivals more than 15 minutes late may need to be rebooked so the next client isn't affected.",
  },
  {
    heading: "Cancellations",
    body: "Life happens. Cancel or reschedule any time up to 24 hours before your appointment at no cost. Cancellations within 24 hours, or no-shows, forfeit any deposit paid. Repeated no-shows may require prepayment for future bookings.",
  },
  {
    heading: "Payment",
    body: "Cash and Zelle are accepted at the studio. Card and Apple Pay are coming soon. Prices shown at booking are the prices charged. No surprises in the chair.",
  },
  {
    heading: "Shop orders",
    body: "Shirts are picked up in person during your appointment; there is no shipping. An order without a connected appointment isn't an order yet. You'll be asked to book first. Unclaimed orders are released after 30 days.",
  },
  {
    heading: "The studio",
    body: "The studio is a curated space. Treat it the way you'd want your own things treated. Tedi reserves the right to refuse service, though in three years, he hasn't had to.",
  },
  {
    heading: "Contact",
    body: `Questions about these terms go to ${content.contact.phone} or ${content.contact.email}.`,
  },
];

export default function TermsPage() {
  return (
    <div className="pb-24 lg:pb-36">
      <PageHeader
        eyebrow="Legal"
        title="Terms of service"
        sub="House rules, written plainly."
      />
      <div className="px-6 md:px-12 lg:px-20">
        <div className="mx-auto max-w-2xl">
          <p className="mono-micro text-stone-500">Last updated June 2026</p>
          {sections.map((s) => (
            <section key={s.heading} className="mt-12">
              <h2 className="heading-2">{s.heading}</h2>
              <p className="mt-4 text-base leading-relaxed text-stone-700">{s.body}</p>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}
