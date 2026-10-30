import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Both the apex (tedishairstudio.com) and www.tedishairstudio.com are served as
// Cloudflare custom domains. Without a redirect, search engines see the same
// pages on two hosts and split indexing between them ("duplicate, Google chose a
// different canonical"). Permanently redirect www to the apex so there is one
// canonical origin, matching metadataBase, the sitemap, and the JSON-LD.
export function middleware(request: NextRequest) {
  const host = request.headers.get("host");
  if (host && host.toLowerCase().startsWith("www.")) {
    const url = request.nextUrl.clone();
    url.host = host.slice(4);
    url.port = "";
    return NextResponse.redirect(url, 301);
  }
  return NextResponse.next();
}

export const config = {
  // Run on real pages only; skip Next internals and static assets.
  matcher: ["/((?!_next/|.*\\.[\\w]+$).*)"],
};
