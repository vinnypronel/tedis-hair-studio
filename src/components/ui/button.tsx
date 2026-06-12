import Link from "next/link";
import { cn } from "@/lib/utils";
import type { ButtonHTMLAttributes, ReactNode } from "react";

type Variant = "primary" | "secondary" | "ghost" | "cream";
type Size = "default" | "large";

const base =
  "group inline-flex items-center justify-center gap-3 rounded-[2px] font-medium tracking-wide transition-all duration-300 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-forest disabled:opacity-40 disabled:pointer-events-none";

const variants: Record<Variant, string> = {
  primary:
    "bg-forest text-cream hover:bg-forest-deep",
  secondary:
    "bg-transparent text-ink border-[0.5px] border-ink/60 hover:bg-ink hover:text-cream",
  cream:
    "bg-cream text-forest-deep hover:bg-bone",
  ghost:
    "bg-transparent text-current underline-offset-4 hover:underline px-0",
};

const sizes: Record<Size, string> = {
  default: "px-6 py-3 text-sm",
  large: "px-9 py-4 text-base",
};

function Arrow() {
  return (
    <span
      aria-hidden
      className="inline-block transition-transform duration-300 group-hover:translate-x-1 group-hover:scale-110"
    >
      →
    </span>
  );
}

type CommonProps = {
  variant?: Variant;
  size?: Size;
  arrow?: boolean;
  className?: string;
  children: ReactNode;
};

export function Button({
  variant = "primary",
  size = "default",
  arrow = false,
  className,
  children,
  ...props
}: CommonProps & ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={cn(base, variants[variant], variant !== "ghost" && sizes[size], className)}
      {...props}
    >
      {children}
      {arrow && <Arrow />}
    </button>
  );
}

export function ButtonLink({
  href,
  variant = "primary",
  size = "default",
  arrow = false,
  className,
  children,
}: CommonProps & { href: string }) {
  return (
    <Link
      href={href}
      className={cn(base, variants[variant], variant !== "ghost" && sizes[size], className)}
    >
      {children}
      {arrow && <Arrow />}
    </Link>
  );
}
