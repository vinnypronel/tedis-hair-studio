import type { Metadata } from "next";
import { BearLogo } from "@/components/site/bear-logo";
import { LoginForm } from "./login-form";

export const metadata: Metadata = {
  title: "Studio Login",
  robots: { index: false },
};

export default function AdminLoginPage() {
  return (
    <div className="flex min-h-svh items-center justify-center bg-forest-deep px-6 py-24 text-cream">
      <div className="w-full max-w-sm">
        <BearLogo size={64} className="mx-auto text-cream" />
        <p className="eyebrow mt-8 text-center text-cream/50">Studio Access</p>
        <h1 className="font-display mt-3 text-center text-3xl tracking-tight">
          Welcome back, Tedi.
        </h1>
        <LoginForm />
        <p className="mono-micro mt-10 text-center text-cream/30">
          Authorized access only · All activity is logged
        </p>
      </div>
    </div>
  );
}
