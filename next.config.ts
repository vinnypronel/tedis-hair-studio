import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: process.env.CLOUDFLARE_BUILD === "1" ? "standalone" : undefined,
  // Allow production checks to run without overwriting the live dev build.
  distDir: process.env.NEXT_BUILD_DIR || ".next",
  images: {
    // Cloudflare serves the supplied files directly, without a paid image service.
    unoptimized: process.env.CLOUDFLARE_BUILD === "1",
    // The hero images request quality 90. Next 16 requires allowed values to be
    // declared, so declare them now rather than at upgrade time.
    qualities: [75, 90],
  },
};

export default nextConfig;
