"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { BearLogo } from "@/components/site/bear-logo";
import { content } from "@/lib/data/content";
import { useCart } from "@/lib/cart";
import { cn } from "@/lib/utils";

const navLinks = [
  { href: "/services", label: "Services" },
  { href: "/shop", label: "Shop" },
  { href: "/reviews", label: "Reviews" },
  { href: "/gallery", label: "Gallery" },
  { href: "/contact", label: "Contact" },
];

export function Header() {
  const pathname = usePathname();
  const [scrolled, setScrolled] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const { count } = useCart();

  // transparent-over-hero only on home; everywhere else always solid
  const overHero = pathname === "/" && !scrolled;

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 80);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    setMenuOpen(false);
  }, [pathname]);

  useEffect(() => {
    document.body.style.overflow = menuOpen ? "hidden" : "";
    return () => {
      document.body.style.overflow = "";
    };
  }, [menuOpen]);

  if (pathname.startsWith("/admin")) return null;

  return (
    <>
      <header
        className={cn(
          "fixed inset-x-0 top-0 z-50 transition-colors duration-500",
          overHero
            ? "bg-transparent text-cream"
            : "bg-bone/95 text-ink backdrop-blur-sm hairline-b"
        )}
      >
        <div className="mx-auto flex max-w-[1440px] items-center justify-between px-6 py-4 md:px-12 lg:px-20">
          <Link href="/" className="flex items-center gap-3" aria-label="Tedi's Hair Studio, home">
            <BearLogo size={48} idle />
            <span className="font-display text-xl tracking-tight whitespace-nowrap">
              Tedi&rsquo;s Hair Studio
            </span>
          </Link>

          <nav className="hidden items-center gap-8 lg:flex" aria-label="Main">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className={cn(
                  "link-draw text-sm",
                  pathname === link.href && "font-semibold link-active"
                )}
              >
                {link.label}
              </Link>
            ))}
            {count > 0 && (
              <Link href="/cart" className="link-draw font-mono text-xs tracking-widest uppercase">
                Cart ({count})
              </Link>
            )}
            <Link
              href="/book"
              className={cn(
                "group inline-flex items-center gap-2.5 rounded-[2px] px-5 py-2.5 text-sm font-medium transition-colors duration-300",
                overHero
                  ? "bg-cream text-forest-deep hover:bg-bone"
                  : "bg-forest text-cream hover:bg-forest-deep"
              )}
            >
              Book Now
              <span aria-hidden className="transition-transform duration-300 group-hover:translate-x-1">→</span>
            </Link>
          </nav>

          <button
            className="flex flex-col gap-1.5 p-2 lg:hidden"
            onClick={() => setMenuOpen((v) => !v)}
            aria-expanded={menuOpen}
            aria-label={menuOpen ? "Close menu" : "Open menu"}
          >
            <span
              className={cn(
                "block h-px w-6 bg-current transition-transform duration-300",
                menuOpen && "translate-y-[3.5px] rotate-45"
              )}
            />
            <span
              className={cn(
                "block h-px w-6 bg-current transition-transform duration-300",
                menuOpen && "-translate-y-[3.5px] -rotate-45"
              )}
            />
          </button>
        </div>
      </header>

      <AnimatePresence>
        {menuOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.35 }}
            className="fixed inset-0 z-40 flex flex-col bg-forest-deep px-6 pt-28 pb-10 text-cream lg:hidden"
          >
            <BearLogo size={72} className="mx-auto mb-10 text-cream/90" />
            <nav className="flex flex-col items-center gap-2" aria-label="Mobile">
              {[{ href: "/", label: "Home" }, ...navLinks, { href: "/book", label: "Book" }].map(
                (link, i) => (
                  <motion.div
                    key={link.href}
                    initial={{ opacity: 0, y: 16 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.08 + i * 0.05, duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
                  >
                    <Link
                      href={link.href}
                      className="font-display block py-2 text-4xl tracking-tight"
                    >
                      {link.label}
                    </Link>
                  </motion.div>
                )
              )}
            </nav>
            <div className="mt-auto flex items-center justify-center gap-8">
              <a
                href={content.social.instagram}
                target="_blank"
                rel="noopener noreferrer"
                className="mono-micro text-cream/70"
              >
                Instagram
              </a>
              <a
                href={content.social.tiktok}
                target="_blank"
                rel="noopener noreferrer"
                className="mono-micro text-cream/70"
              >
                TikTok
              </a>
              <a href={content.contact.phoneHref} className="mono-micro text-cream/70">
                {content.contact.phone}
              </a>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
