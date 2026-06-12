import type { MetadataRoute } from "next";
import { content } from "@/lib/data/content";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      allow: "/",
      disallow: ["/admin", "/checkout", "/cart"],
    },
    sitemap: `${content.meta.siteUrl}/sitemap.xml`,
  };
}
