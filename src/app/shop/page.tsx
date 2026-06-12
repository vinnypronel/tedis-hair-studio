import type { Metadata } from "next";
import { PageHeader } from "@/components/site/page-header";
import { Reveal } from "@/components/site/reveal";
import { content } from "@/lib/data/content";
import { ShopClient } from "./shop-client";

export const metadata: Metadata = {
  title: "The Shop",
  description:
    "Limited shirt drops from Tedi's Hair Studio. Wear the mark. Pick-up at your next cut.",
};

export default function ShopPage() {
  return (
    <div className="pb-24 lg:pb-36">
      <PageHeader
        eyebrow="The Shop"
        title={<em className="italic">Wear the mark.</em>}
        sub="Limited drops. Pick-up at your next cut."
      />
      <div className="px-6 md:px-12 lg:px-20">
        <div className="mx-auto max-w-[1440px]">
          <ShopClient />
          <Reveal delay={0.1}>
            <p className="hairline-t mt-20 pt-8 text-sm text-stone-500">
              {content.shop.disclaimer}
            </p>
          </Reveal>
        </div>
      </div>
    </div>
  );
}
