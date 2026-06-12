import { Hero } from "@/components/home/hero";
import {
  IntroStrip,
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
      <IntroStrip />
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
