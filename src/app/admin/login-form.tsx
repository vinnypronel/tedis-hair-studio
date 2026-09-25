"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { setAdminSession } from "./admin-session";

/**
 * Static login UI. Real authentication comes online with the backend phase.
 * This only gates the frontend demo.
 */

export function LoginForm() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");


    setLoading(true);
    setAdminSession();
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
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="input-line input-line-cream mt-2"
          required
        />
      </div>
      <div>
        <label htmlFor="admin-password" className="eyebrow text-cream/50">
          Password
        </label>
        <div className="relative mt-2">
          <input
            id="admin-password"
            type={showPassword ? "text" : "password"}
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="input-line input-line-cream w-full pr-10"
            required
          />
          <button
            type="button"
            onClick={() => setShowPassword((v) => !v)}
            className="cursor-pointer absolute right-1 top-1/2 -translate-y-1/2 p-1 text-cream/50 transition-colors hover:text-cream"
            aria-label={showPassword ? "Hide password" : "Show password"}
            title={showPassword ? "Hide password" : "Show password"}
          >
            {showPassword ? (
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24" />
                <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" />
                <path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61" />
                <line x1="2" y1="2" x2="22" y2="22" />
              </svg>
            ) : (
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" />
                <circle cx="12" cy="12" r="3" />
              </svg>
            )}
          </button>
        </div>
      </div>
      {error && (
        <p className="hairline-cream bg-error/20 px-4 py-3 text-sm text-cream" role="alert">
          {error}
        </p>
      )}
      <button
        type="submit"
        disabled={loading}
        className="mt-2 rounded-[2px] bg-cream py-4 text-sm font-medium text-forest-deep transition-all duration-300 hover:bg-success hover:text-cream disabled:opacity-50"
      >
        {loading ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}
