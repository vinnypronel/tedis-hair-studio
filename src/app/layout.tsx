import type { Metadata } from "next";
import { Fraunces, Inter, JetBrains_Mono } from "next/font/google";
import { Header } from "@/components/site/header";
import { Footer } from "@/components/site/footer";
import { Grain } from "@/components/site/grain";
import { Cursor } from "@/components/site/cursor";
import { content } from "@/lib/data/content";
import { SmoothScrollProvider } from "@/components/site/smooth-scroll-provider";
import { Scrollbar } from "@/components/site/scrollbar";
import "./globals.css";

const fraunces = Fraunces({
  subsets: ["latin"],
  variable: "--font-fraunces",
  axes: ["opsz"],
  style: ["normal", "italic"],
});

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

const jetbrains = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains",
  weight: ["400", "500"],
});

export const metadata: Metadata = {
  metadataBase: new URL(content.meta.siteUrl),
  title: {
    default: "Tedi's Hair Studio | Private Barber Studio in Matawan, NJ",
    template: "%s | Tedi's Hair Studio",
  },
  description: content.meta.description,
  openGraph: {
    title: "Tedi's Hair Studio | Private Barber Studio in Matawan, NJ",
    description: content.meta.description,
    siteName: content.meta.siteName,
    type: "website",
    locale: "en_US",
    images: [{ url: "/professional-images/chair-wash.jpg", alt: "Inside Tedi's Hair Studio" }],
  },
  twitter: { card: "summary_large_image" },
};

const localBusinessJsonLd = {
  "@context": "https://schema.org",
  "@type": "HairSalon",
  "@id": `${content.meta.siteUrl}/#studio`,
  name: "Tedi's Hair Studio",
  description: content.meta.description,
  url: content.meta.siteUrl,
  telephone: content.contact.phoneHref.replace("tel:", ""),
  image: `${content.meta.siteUrl}/professional-images/chair-wash.jpg`,
  priceRange: "$$",
  sameAs: [
    content.social.instagram,
    content.social.tiktok,
    content.booking.profileUrl,
  ],
  hasMap: content.contact.googleMapsUrl,
  potentialAction: {
    "@type": "ReserveAction",
    target: {
      "@type": "EntryPoint",
      urlTemplate: content.booking.url,
      inLanguage: "en-US",
      actionPlatform: [
        "http://schema.org/DesktopWebPlatform",
        "http://schema.org/IOSPlatform",
        "http://schema.org/AndroidPlatform",
      ],
    },
    result: { "@type": "Reservation", name: "Book an appointment" },
  },
  address: {
    "@type": "PostalAddress",
    streetAddress: content.contact.addressLine1,
    addressLocality: "Matawan",
    addressRegion: "NJ",
    postalCode: "07747",
    addressCountry: "US",
  },
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      data-scroll-behavior="smooth"
      className={`${fraunces.variable} ${inter.variable} ${jetbrains.variable}`}
    >
      <body>
        <a href="#main-content" className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-[9999] focus:bg-bone focus:p-4 focus:text-forest">
          Skip to content
        </a>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(localBusinessJsonLd) }}
        />
        <SmoothScrollProvider>
          <Header />
          <main id="main-content" tabIndex={-1}>{children}</main>
          <Footer />
        </SmoothScrollProvider>
        <Grain />
        <Cursor />
        <Scrollbar />
      </body>
    </html>
  );
}
