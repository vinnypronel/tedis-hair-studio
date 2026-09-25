import { content } from "@/lib/data/content";
import styles from "./contact-form.module.css";

export function ContactForm() {
  return (
    <div className="hairline-strong bg-cream p-8 md:p-10">
      <p className="font-display text-3xl tracking-tight italic">Talk to Tedi.</p>
      <p className="mt-4 max-w-lg text-sm leading-relaxed text-stone-700">
        For questions about the studio or your visit, call or text directly.
        Book, reschedule, or cancel your appointment through Booksy.
      </p>
      <div className="mt-7 flex flex-wrap items-center gap-6">
        <a href={content.contact.phoneHref.replace("tel:", "sms:")} className={`${styles.textButton} inline-flex items-center px-6 py-3 text-sm font-medium text-cream focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-forest`}>
          <span className={styles.icon} aria-hidden="true">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 11.5a8.5 8.5 0 0 1-8.5 8.5H4l-3 3V11.5a8.5 8.5 0 0 1 8.5-8.5h3a8.5 8.5 0 0 1 8.5 8.5Z" />
              <path d="M7 10h8M7 14h5" />
            </svg>
          </span>
          <span className={styles.label}>Text the studio</span>
        </a>
        <a href={content.contact.phoneHref} className={`${styles.callButton} inline-flex items-center px-6 py-3 text-sm font-medium text-cream focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-forest`}>
          <span className={styles.phoneIcon} aria-hidden="true">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
              <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z" />
            </svg>
          </span>
          <span className={styles.label}>Call {content.contact.phone}</span>
        </a>
      </div>
    </div>
  );
}
