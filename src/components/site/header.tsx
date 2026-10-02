"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { BearLogo } from "@/components/site/bear-logo";
import { BookLink } from "@/components/site/book-link";
import { content } from "@/lib/data/content";
import { cn } from "@/lib/utils";

const navLinks = [
  { href: "/", label: "Home" },
  { href: "/services", label: "Services" },
  { href: "/reviews", label: "Reviews" },
  { href: "/gallery", label: "Gallery" },
  { href: "/contact", label: "Contact" },
  { href: "/shop", label: "Shirts" },
];

export function Header() {
  const pathname = usePathname();
  const [scrolled, setScrolled] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  // transparent-over-hero only on home when not scrolled and menu is closed
  const overHero = pathname === "/" && !scrolled && !menuOpen;

  // Scroll detection for sticky header backdrop
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 40);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  // 1. Auto-close on route change
  useEffect(() => {
    setMenuOpen(false);
  }, [pathname]);

  useEffect(() => {
    const desktop = window.matchMedia("(min-width: 1024px)");
    const onResize = () => { if (desktop.matches) setMenuOpen(false); };
    desktop.addEventListener("change", onResize);
    return () => desktop.removeEventListener("change", onResize);
  }, []);

  // 2. Lock body and html scroll + Escape key listener
  useEffect(() => {
    if (!menuOpen) return;

    const prevBodyOverflow = document.body.style.overflow;
    const prevHtmlOverflow = document.documentElement.style.overflow;

    document.body.style.overflow = "hidden";
    document.documentElement.style.overflow = "hidden";

    const toggle = document.querySelector<HTMLButtonElement>('[aria-controls="mobile-nav-takeover"]');
    const background = [...document.querySelectorAll<HTMLElement>('main, footer, .page-scrollbar')];
    const previousInert = background.map((element) => element.inert);
    background.forEach((element) => { element.inert = true; });
    toggle?.focus();

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMenuOpen(false);
      if (e.key !== "Tab") return;
      const links = [...document.querySelectorAll<HTMLElement>('header a, header button, #mobile-nav-takeover a')]
        .filter((element) => element.getClientRects().length > 0 && element.tabIndex >= 0);
      const first = links[0];
      const last = links[links.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last?.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first?.focus();
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = prevBodyOverflow;
      document.documentElement.style.overflow = prevHtmlOverflow;
      background.forEach((element, index) => { element.inert = previousInert[index]; });
      if (document.activeElement?.closest('#mobile-nav-takeover')) toggle?.focus();
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [menuOpen]);

  if (pathname.startsWith("/admin")) return null;

  return (
    <>
      <style>{`
        /* ── Mobile Full-Screen Takeover Container ── */
        .nav-takeover-panel {
          position: fixed;
          inset: 0;
          z-index: 40;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: space-between;
          padding: 110px 24px 32px;
          background:
            radial-gradient(ellipse 80% 50% at 50% 25%, rgba(245, 197, 24, 0.06) 0%, transparent 70%),
            radial-gradient(ellipse 70% 50% at 50% 85%, rgba(26, 47, 35, 0.4) 0%, transparent 70%),
            #0f1f17;
          opacity: 0;
          visibility: hidden;
          pointer-events: none;
          transform: translateY(-8px);
          transition: opacity 0.4s ease, transform 0.45s cubic-bezier(0.22, 1, 0.36, 1), visibility 0.45s;
          overflow-y: auto;
        }

        .nav-takeover-panel.open {
          opacity: 1;
          visibility: visible;
          pointer-events: auto;
          transform: none;
        }

        /* ── Staggered Nav Links ── */
        .nav-takeover-link {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 12px;
          padding: 8px 16px;
          font-family: var(--font-display);
          font-size: clamp(2rem, 7vw, 3.2rem);
          font-weight: 400;
          line-height: 1.15;
          letter-spacing: -0.02em;
          color: #faf6ee;
          text-decoration: none;
          opacity: 0;
          transform: translateY(18px);
          transition: color 0.25s ease, opacity 0.45s ease, transform 0.45s cubic-bezier(0.22, 1, 0.36, 1);
        }

        .nav-takeover-panel.open .nav-takeover-link {
          opacity: 1;
          transform: none;
        }

        /* Staggered Delay */
        .nav-takeover-panel.open li:nth-child(1) .nav-takeover-link { transition-delay: 0.08s; }
        .nav-takeover-panel.open li:nth-child(2) .nav-takeover-link { transition-delay: 0.13s; }
        .nav-takeover-panel.open li:nth-child(3) .nav-takeover-link { transition-delay: 0.18s; }
        .nav-takeover-panel.open li:nth-child(4) .nav-takeover-link { transition-delay: 0.23s; }
        .nav-takeover-panel.open li:nth-child(5) .nav-takeover-link { transition-delay: 0.28s; }
        .nav-takeover-panel.open li:nth-child(6) .nav-takeover-link { transition-delay: 0.33s; }

        .nav-takeover-link:hover,
        .nav-takeover-link.active {
          color: #f5c518;
        }

        .nav-takeover-link.active {
          text-decoration: underline;
          text-decoration-thickness: 2px;
          text-underline-offset: 8px;
        }

        /* CTA Reveal */
        .nav-takeover-cta {
          opacity: 0;
          transform: translateY(18px);
          transition: opacity 0.45s ease, transform 0.45s cubic-bezier(0.22, 1, 0.36, 1);
        }
        .nav-takeover-panel.open .nav-takeover-cta {
          opacity: 1;
          transform: none;
          transition-delay: 0.38s;
        }

        /* Footer Socials */
        .nav-takeover-footer {
          opacity: 0;
          transition: opacity 0.4s ease 0.42s;
        }
        .nav-takeover-panel.open .nav-takeover-footer {
          opacity: 1;
        }

        /* ── Landscape / Short-Screen Optimizations ── */
        @media (max-height: 620px) {
          .nav-takeover-panel {
            padding: 80px 16px 16px !important;
            gap: 12px !important;
          }
          .nav-takeover-links {
            gap: 4px !important;
          }
          .nav-takeover-link {
            font-size: clamp(1.3rem, 5vh, 1.8rem) !important;
            padding: 4px 8px !important;
          }
        }

        /* ── Reduced Motion ── */
        @media (prefers-reduced-motion: reduce) {
          .nav-takeover-panel,
          .nav-takeover-link,
          .nav-takeover-cta,
          .nav-takeover-footer {
            transition-duration: 0.001s !important;
            transition-delay: 0s !important;
          }
        }
      `}</style>

      {/* Main Header Bar (z-index: 50) */}
      <header
        role="banner"
        className={cn(
          "fixed inset-x-0 top-0 z-50 transition-colors duration-500",
          menuOpen
            ? "bg-transparent text-cream"
            : overHero
            ? "bg-transparent text-cream"
            : "bg-bone/95 text-ink backdrop-blur-sm hairline-b"
        )}
      >
        <div className="mx-auto flex max-w-[1440px] items-center justify-between px-6 py-4 md:px-12 lg:px-20">
          {/* Logo */}
          <Link
            href="/"
            onClick={() => setMenuOpen(false)}
            className="flex items-center gap-3"
            aria-label="Tedi's Hair Studio, home"
          >
            <BearLogo size={48} idle />
            <span className="font-display text-xl tracking-tight whitespace-nowrap">
              Tedi&rsquo;s Hair Studio
            </span>
          </Link>

          {/* Desktop Navigation */}
          <nav className="hidden items-center gap-5 lg:flex xl:gap-8" aria-label="Main Navigation">
            {navLinks.map((link) => {
              const isActive = pathname === link.href || (link.href !== "/" && pathname.startsWith(`${link.href}/`));
              return (
                <Link
                  key={link.href}
                  href={link.href}
                  prefetch={true}
                  aria-current={isActive ? "page" : undefined}
                  className={cn(
                    "link-draw text-sm transition-colors",
                    isActive && "font-semibold link-active",
                    isActive && !overHero && "text-forest-deep"
                  )}
                >
                  {link.label}
                </Link>
              );
            })}
            <BookLink
              className={cn(
                "group inline-flex items-center gap-2.5 rounded-[2px] px-5 py-2.5 text-sm font-medium transition-all duration-300 hover:-translate-y-0.5 hover:translate-x-0.5",
                overHero
                  ? "bg-cream text-forest-deep hover:bg-forest-deep hover:text-cream"
                  : "bg-forest text-cream hover:bg-cream hover:text-forest"
              )}
            >
              Book Now
              <span aria-hidden className="transition-transform duration-300 group-hover:translate-x-1">
                →
              </span>
            </BookLink>
          </nav>

          {/* Morphing 3-Bar Hamburger Button */}
          <button
            type="button"
            onClick={() => setMenuOpen((prev) => !prev)}
            aria-label={menuOpen ? "Close navigation menu" : "Open navigation menu"}
            aria-expanded={menuOpen}
            aria-controls="mobile-nav-takeover"
            className="cursor-pointer flex h-10 w-10 items-center justify-center rounded p-2 text-current lg:hidden"
          >
            <span
              aria-hidden="true"
              className="flex w-6 flex-col items-center justify-center gap-[5px]"
            >
              {/* Top Bar */}
              <span
                className={cn(
                  "block h-[2px] w-6 rounded-full bg-current transition-all duration-300",
                  menuOpen && "translate-y-[7px] rotate-45 bg-cream"
                )}
              />
              {/* Middle Bar */}
              <span
                className={cn(
                  "block h-[2px] w-6 rounded-full bg-current transition-all duration-300",
                  menuOpen && "scale-x-0 opacity-0"
                )}
              />
              {/* Bottom Bar */}
              <span
                className={cn(
                  "block h-[2px] w-6 rounded-full bg-current transition-all duration-300",
                  menuOpen && "-translate-y-[7px] -rotate-45 bg-cream"
                )}
              />
            </span>
          </button>
        </div>
      </header>

      {/* Full-Screen Takeover Panel (z-index: 40) */}
      <div
        id="mobile-nav-takeover"
        className={cn("nav-takeover-panel", menuOpen && "open")}
        aria-hidden={!menuOpen}
        inert={!menuOpen}
        data-lenis-prevent
      >
        <BearLogo size={64} className="mx-auto text-cream/90" />

        {/* Center: Navigation Links */}
        <nav aria-label="Mobile Navigation" className="w-full max-w-sm">
          <ul className="nav-takeover-links flex flex-col items-center gap-2 list-none p-0 m-0">
            {navLinks.map((item) => {
              const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(`${item.href}/`));
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    prefetch={true}
                    onClick={() => setMenuOpen(false)}
                    tabIndex={menuOpen ? 0 : -1}
                    aria-current={isActive ? "page" : undefined}
                    className={cn("nav-takeover-link", isActive && "active")}
                  >
                    {item.label}
                  </Link>
                </li>
              );
            })}
          </ul>

          {/* Book Now Button in Takeover */}
          <div className="nav-takeover-cta mt-6 flex justify-center">
            <BookLink
              onClick={() => setMenuOpen(false)}
              className="font-display inline-flex items-center gap-3 rounded-[2px] bg-cream px-8 py-3 text-xl tracking-tight text-forest-deep transition-transform duration-300 hover:scale-105"
            >
              Book Now
              <span aria-hidden>→</span>
            </BookLink>
          </div>
        </nav>

        {/* Bottom Socials & Phone Strip */}
        <div className="nav-takeover-footer flex flex-wrap items-center justify-center gap-6 pt-4 text-cream/70">
          <a
            href={content.social.instagram}
            target="_blank"
            rel="noopener noreferrer"
            tabIndex={menuOpen ? 0 : -1}
            className="mono-micro transition-colors hover:text-neon"
          >
            Instagram ↗
          </a>
          <span className="text-cream/30">·</span>
          <a
            href={content.social.tiktok}
            target="_blank"
            rel="noopener noreferrer"
            tabIndex={menuOpen ? 0 : -1}
            className="mono-micro transition-colors hover:text-neon"
          >
            TikTok ↗
          </a>
          <span className="text-cream/30">·</span>
          <a
            href={content.contact.phoneHref}
            tabIndex={menuOpen ? 0 : -1}
            className="mono-micro transition-colors hover:text-neon"
          >
            {content.contact.phone}
          </a>
        </div>
      </div>
    </>
  );
}
