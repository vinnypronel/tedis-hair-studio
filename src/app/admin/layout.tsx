import type { Metadata } from "next";
import { notFound } from "next/navigation";

export const metadata: Metadata = {
  robots: { index: false, follow: false },
};

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  // The mock login is only available in local development, never on a deployment.
  if (process.env.NODE_ENV === "production") notFound();
  return children;
}
