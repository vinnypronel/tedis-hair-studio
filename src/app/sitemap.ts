import type { MetadataRoute } from "next";
import { shirts } from "@/lib/data/shirts";
import { content } from "@/lib/data/content";

export default function sitemap(): MetadataRoute.Sitemap {
  const base = content.meta.siteUrl;
  const staticRoutes = [
    "",
    "/about",
    "/services",
    "/book",
    "/shop",
    "/reviews",
    "/gallery",
    "/contact",
  ].map((path) => ({
    url: `${base}${path}`,
    lastModified: new Date(),
    changeFrequency: "weekly" as const,
    priority: path === "" ? 1 : 0.8,
  }));

  const products = shirts
    .filter((s) => s.status !== "archived")
    .map((s) => ({
      url: `${base}/shop/${s.slug}`,
      lastModified: new Date(),
      changeFrequency: "monthly" as const,
      priority: 0.6,
    }));

  return [...staticRoutes, ...products];
}
