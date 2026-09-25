import type { Metadata } from "next";
import { PageHeader } from "@/components/site/page-header";
import { GalleryClient } from "./gallery-client";

export const metadata: Metadata = {
  alternates: { canonical: "/gallery" },
  title: "Gallery",
  description:
    "The work and the space. Cuts, fades, beard work, and the studio inside Bellazio Collective.",
};

export default function GalleryPage() {
  return (
    <div className="pb-24 lg:pb-36">
      <PageHeader
        compact
        title={"Tedi’s Gallery"}
        sub="Cuts out of the chair and the studio they happen in."
      />
      <div className="px-6 md:px-12 lg:px-20">
        <div className="mx-auto max-w-[1440px]">
          <GalleryClient />
        </div>
      </div>
    </div>
  );
}
