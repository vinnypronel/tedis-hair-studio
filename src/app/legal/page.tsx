import type { Metadata } from "next";
import { PageHeader } from "@/components/site/page-header";
import { content } from "@/lib/data/content";

export const metadata: Metadata = {
  title: "Privacy & Terms",
  robots: { index: false },
};

const privacySections = [
  {
    heading: "What we collect",
    body: "When you book an appointment or place a shop order, we collect your name, email address, and phone number. That's it. No accounts, no passwords, no tracking profiles. Optional notes you add to a booking are stored with the appointment.",
  },
  {
    heading: "How it's used",
    body: "Your contact details are used for exactly two things: confirming and managing your appointments, and reaching you about an order you placed. We don't sell, rent, or share your information with anyone, ever.",
  },
  {
    heading: "Emails and messages",
    body: "You'll receive a confirmation when you book and, if needed, a message about changes to your appointment. We don't send marketing email unless you explicitly join the drop list, and you can leave it any time.",
  },
  {
    heading: "Retention",
    body: "Appointment history is kept so Tedi can give you a better cut next time: what was done, what you liked. If you'd like your information removed, text or email the studio and it's gone.",
  },
  {
    heading: "Questions",
    body: `This is a one-person studio, so privacy questions go straight to the person responsible: ${content.contact.phone} or ${content.contact.email}.`,
  },
];

const termsSections = [
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

export default function LegalPage() {
  return (
    <div className="pb-24 lg:pb-36">
      <PageHeader
        eyebrow="Legal"
        title="Privacy & Terms"
        sub="Our guidelines and rules, written plainly."
      />
      <div className="px-6 md:px-12 lg:px-20">
        <div className="mx-auto max-w-6xl">
          <p className="mono-micro mb-8 text-stone-500">Last updated June 2026</p>
          
          <div className="grid grid-cols-1 gap-12 md:grid-cols-2 md:divide-x md:divide-stone-200">
            {/* Privacy Policy */}
            <div className="space-y-12">
              <div className="border-b border-stone-200 pb-4">
                <h2 className="font-display text-2xl font-semibold tracking-tight text-forest-deep">
                  Privacy Policy
                </h2>
                <p className="mt-1 text-sm text-stone-500">
                  How we protect your data.
                </p>
              </div>
              <div className="space-y-10">
                {privacySections.map((s) => (
                  <section key={s.heading}>
                    <h3 className="font-display text-lg font-medium tracking-tight text-stone-900">
                      {s.heading}
                    </h3>
                    <p className="mt-3 text-sm leading-relaxed text-stone-600">
                      {s.body}
                    </p>
                  </section>
                ))}
              </div>
            </div>

            {/* Terms of Service */}
            <div className="space-y-12 md:pl-12 lg:pl-16">
              <div className="border-b border-stone-200 pb-4">
                <h2 className="font-display text-2xl font-semibold tracking-tight text-forest-deep">
                  Terms of Service
                </h2>
                <p className="mt-1 text-sm text-stone-500">
                  Our studio rules.
                </p>
              </div>
              <div className="space-y-10">
                {termsSections.map((s) => (
                  <section key={s.heading}>
                    <h3 className="font-display text-lg font-medium tracking-tight text-stone-900">
                      {s.heading}
                    </h3>
                    <p className="mt-3 text-sm leading-relaxed text-stone-600">
                      {s.body}
                    </p>
                  </section>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
