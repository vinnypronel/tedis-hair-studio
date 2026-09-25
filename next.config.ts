import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Allow production checks to run without overwriting the live dev build.
  distDir: process.env.NEXT_BUILD_DIR || ".next",
  images: {
    // The hero images request quality 90. Next 16 requires allowed values to be
    // declared, so declare them now rather than at upgrade time.
    qualities: [75, 90],
  },
};

export default nextConfig;
