import type { Metadata } from "next";
import { PageHeader } from "@/components/site/page-header";
import { Reveal } from "@/components/site/reveal";
import { content } from "@/lib/data/content";
import { ShopClient } from "./shop-client";

export const metadata: Metadata = {
  alternates: { canonical: "/shop" },
  title: "Merch",
  description:
    "Studio tees from Tedi's Hair Studio. Exclusive merch. Ask about a shirt at your next cut.",
};

export default function ShopPage() {
  return (
    <div className="pb-12 lg:pb-16">
      <PageHeader compact title={<em className="italic">Exclusive Merch</em>} />
      <div className="px-6 md:px-12 lg:px-20">
        <div className="mx-auto max-w-[1440px]">
          <ShopClient />
        </div>
      </div>
    </div>
  );
}
