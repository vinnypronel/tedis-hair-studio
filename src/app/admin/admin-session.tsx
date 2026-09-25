"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

const SESSION_KEY = "tedis-admin-session";

export function setAdminSession() {
  sessionStorage.setItem(SESSION_KEY, "true");
}

export function AdminAuthGate({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [allowed, setAllowed] = useState(false);

  useEffect(() => {
    if (sessionStorage.getItem(SESSION_KEY) === "true") {
      setAllowed(true);
      return;
    }

    router.replace(`/admin?next=${encodeURIComponent(pathname)}`);
  }, [pathname, router]);

  if (!allowed) {
    return (
      <div className="flex min-h-svh items-center justify-center bg-forest-deep text-cream">
        <p className="eyebrow text-cream/50">Checking studio access</p>
      </div>
    );
  }

  return children;
}

export function AdminLogoutLink({ className }: { className?: string }) {
  return (
    <Link
      href="/admin"
      className={className}
      onClick={() => sessionStorage.removeItem(SESSION_KEY)}
    >
      Log out
    </Link>
  );
}
