import type { Metadata } from "next";
import { PageHeader } from "@/components/site/page-header";
import { content } from "@/lib/data/content";

export const metadata: Metadata = {
  alternates: { canonical: "/legal" },
  title: "Privacy & Terms",
  robots: { index: false },
};

const privacySections = [
  {
    heading: "What we collect",
    body: "Appointments are booked through Booksy. Information you provide during booking is handled through that service. This website does not accept online orders or contact form submissions. If you call, text, or email the studio, you share the contact information and message you choose to send.",
  },
  {
    heading: "How it's used",
    body: "The studio uses information you share to respond to your inquiry and manage your appointment. For information about how Booksy handles booking data, review its privacy policy when booking.",
  },
  {
    heading: "Third-party services",
    body: "The contact page embeds Google Maps. Loading that map sends connection information to Google. Links to Booksy, Instagram, and TikTok open services with their own privacy policies. Website hosting providers may process technical request information to deliver and secure this website.",
  },
  {
    heading: "Privacy requests",
    body: "Contact the studio with questions about information you have shared directly. Requests about information held by Booksy or another service may also need to be made to that provider.",
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
    body: "Booking, rescheduling, and cancellations run through Booksy. Please give at least 24 hours notice. Review the cancellation and payment conditions displayed in Booksy before confirming your appointment.",
  },
  {
    heading: "Payment",
    body: "Cash and Zelle are accepted at the studio. Confirm current prices and any booking conditions in Booksy before booking.",
  },
  {
    heading: "Studio merchandise",
    body: "Shirts are not sold online. Ask Tedi about current availability, sizes, and purchases at the studio, or contact the studio on Instagram.",
  },
  {
    heading: "The studio",
    body: "Please treat the studio and its collection with care. Contact Tedi before your appointment if you have questions about access or your visit.",
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
        title="Privacy & Terms"
      />
      <div className="px-6 md:px-12 lg:px-20">
        <div className="mx-auto max-w-6xl">
          <p className="mono-micro mb-8 text-stone-500">Last updated September 2026</p>
          
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
