import type { Metadata } from "next";
import { PageHeader } from "@/components/site/page-header";
import { content } from "@/lib/data/content";

export const metadata: Metadata = {
  title: "Privacy Policy",
  robots: { index: false },
};

const sections = [
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

export default function PrivacyPage() {
  return (
    <div className="pb-24 lg:pb-36">
      <PageHeader
        eyebrow="Legal"
        title="Privacy policy"
        sub="The short version: we collect the minimum needed to cut your hair, and we never share it."
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
