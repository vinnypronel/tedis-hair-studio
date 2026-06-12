import { PageTransition } from "@/components/site/page-transition";
import type { ReactNode } from "react";

export default function Template({ children }: { children: ReactNode }) {
  return <PageTransition>{children}</PageTransition>;
}
