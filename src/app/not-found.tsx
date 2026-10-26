import type { Metadata } from "next";
import Link from "next/link";
import { BearLogo } from "@/components/site/bear-logo";

export const metadata: Metadata = {
  title: "Page not found",
  robots: { index: false },
};

export default function NotFound() {
  return (
    <section className="flex min-h-svh flex-col items-center justify-center bg-forest-deep px-6 text-center text-cream">
      <BearLogo size={72} className="text-cream/80" />
      <p className="eyebrow mt-10 text-cream/50">Error 404</p>
      <h1 className="display-lg mt-4 italic">Lost the part.</h1>
      <p className="mt-6 max-w-md text-sm leading-relaxed text-cream/80">
        That page does not exist, or it moved. Head back and book your next cut.
      </p>
      <div className="mt-10 flex flex-wrap items-center justify-center gap-6">
        <Link
          href="/"
          className="group inline-flex items-center gap-3 rounded-[2px] border border-transparent bg-cream px-7 py-3.5 text-sm font-medium text-forest-deep transition-all duration-300 hover:-translate-y-0.5 hover:translate-x-0.5 hover:border-cream hover:bg-forest-deep hover:text-cream"
        >
          Back home
          <span aria-hidden className="transition-transform duration-300 group-hover:translate-x-1">
            &rarr;
          </span>
        </Link>
        <Link
          href="/services"
          className="text-sm text-cream/90 underline underline-offset-4 decoration-cream/50 transition-colors hover:decoration-cream"
        >
          See services
        </Link>
      </div>
    </section>
  );
}
