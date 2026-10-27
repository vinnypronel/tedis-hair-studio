import type { Metadata } from "next";
import { PageHeader } from "@/components/site/page-header";
import { ShopClient } from "./shop-client";

export const metadata: Metadata = {
  alternates: { canonical: "/shop" },
  title: "Shirt Archive",
  description:
    "An archive of custom Tedi's Hair Studio shirts occasionally given out with cuts. These shirts are not for sale.",
};

export default function ShopPage() {
  return (
    <div className="pb-12 lg:pb-16">
      <PageHeader compact title={<em className="italic">The shirt archive.</em>} />
      <div className="px-6 md:px-12 lg:px-20">
        <div className="mx-auto max-w-[1440px]">
          <p className="mb-10 max-w-2xl text-base leading-relaxed text-stone-700">
            A look at recent shirts from the studio. They are not for sale. Tedi occasionally
            gives out a shirt with a cut, and the designs change each time.
          </p>
          <ShopClient />
        </div>
      </div>
    </div>
  );
}
