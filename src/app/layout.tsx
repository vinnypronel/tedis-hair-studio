import type { Metadata } from "next";
import { Fraunces, Inter, JetBrains_Mono } from "next/font/google";
import { Header } from "@/components/site/header";
import { Footer } from "@/components/site/footer";
import { Grain } from "@/components/site/grain";
import { Cursor } from "@/components/site/cursor";
import { CartProvider } from "@/lib/cart";
import { content } from "@/lib/data/content";
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
    default: "Tedi's Hair Studio |Private Barber Studio in Matawan, NJ",
    template: "%s |Tedi's Hair Studio",
  },
  description: content.meta.description,
  openGraph: {
    siteName: content.meta.siteName,
    type: "website",
    locale: "en_US",
  },
};

const localBusinessJsonLd = {
  "@context": "https://schema.org",
  "@type": "HairSalon",
  name: "Tedi's Hair Studio",
  description: content.meta.description,
  telephone: "+17329477359",
  priceRange: "$$",
  address: {
    "@type": "PostalAddress",
    streetAddress: "259 Broad St #103",
    addressLocality: "Matawan",
    addressRegion: "NJ",
    postalCode: "07747",
    addressCountry: "US",
  },
  geo: { "@type": "GeoCoordinates", latitude: 40.4131, longitude: -74.2293 },
  openingHoursSpecification: [
    {
      "@type": "OpeningHoursSpecification",
      dayOfWeek: ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
      opens: "10:00",
      closes: "20:00",
    },
    {
      "@type": "OpeningHoursSpecification",
      dayOfWeek: "Saturday",
      opens: "09:00",
      closes: "17:00",
    },
  ],
  aggregateRating: {
    "@type": "AggregateRating",
    ratingValue: "5.0",
    reviewCount: "127",
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
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(localBusinessJsonLd) }}
        />
        <CartProvider>
          <Header />
          <main>{children}</main>
          <Footer />
        </CartProvider>
        <Grain />
        <Cursor />
      </body>
    </html>
  );
}
