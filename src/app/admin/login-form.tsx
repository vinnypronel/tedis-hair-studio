"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

/**
 * Static login UI. Authentication comes online with the backend phase.
 * Any input currently routes to the dashboard mockup.
 */
export function LoginForm() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setTimeout(() => router.push("/admin/dashboard"), 500);
  }

  return (
    <form onSubmit={handleSubmit} className="mt-12 flex flex-col gap-8">
      <div>
        <label htmlFor="admin-email" className="eyebrow text-cream/50">
          Email
        </label>
        <input
          id="admin-email"
          type="email"
          autoComplete="username"
          className="input-line input-line-cream mt-2"
        />
      </div>
      <div>
        <label htmlFor="admin-password" className="eyebrow text-cream/50">
          Password
        </label>
        <input
          id="admin-password"
          type="password"
          autoComplete="current-password"
          className="input-line input-line-cream mt-2"
        />
      </div>
      <button
        type="submit"
        disabled={loading}
        className="mt-2 rounded-[2px] bg-cream py-4 text-sm font-medium text-forest-deep transition-colors hover:bg-bone disabled:opacity-50"
      >
        {loading ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}
