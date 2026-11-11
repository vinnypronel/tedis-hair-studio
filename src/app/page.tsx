import type { Metadata } from "next";
export const metadata: Metadata = { alternates: { canonical: "/" } };
import { Hero } from "@/components/home/hero";
import {
  ServicesTeaser,
  PortfolioMarquee,
  BrandStory,
  SpaceStory,
  ReviewsPreview,
  ShopTeaser,
  InstagramStrip,
  Visit,
} from "@/components/home/sections";

export default function HomePage() {
  return (
    <>
      <Hero />
      <ServicesTeaser />
      <PortfolioMarquee />
      <BrandStory />
      <SpaceStory />
      <ReviewsPreview />
      <ShopTeaser />
      <InstagramStrip />
      <Visit />
    </>
  );
}
