# Tedi's Hair Studio

## What this is
Premium single-chair barber studio site (editorial, hypebeast-luxury). Currently a FRONTEND-ONLY
demo build (June 2026 rebuild); full spec at
C:\Users\vinny\OneDrive\Desktop\tedis-hair-studio-spec.md. Backend is DEFERRED.

## Stack (locked - do not re-decide)
Next.js 15 App Router (src/ layout), Tailwind v4, motion (framer-motion), Zod, TypeScript strict.
npm, NOT pnpm (pnpm install hits EPERM on this machine). No Supabase, Stripe, Resend, or auth
until the backend phase is explicitly started.

## Mock data layer (core architecture - preserve)
ALL data comes from typed mock modules in src/lib/data/ (services, reviews, shirts, availability,
content, gallery), shaped to mirror the future DB schema. Backend swap-in must stay one file per
domain. Booking/checkout: validate with Zod, console.log the payload, store fake confirmation in
sessionStorage. /admin login is a static mockup (any input routes to /admin/dashboard).

## Run it
`npm run dev` (port 3000, autoPort on).

## Design system (locked)
Bone background, forest green primary, neon yellow at most ONCE per screen. Fonts: Fraunces /
Inter / JetBrains Mono. No dark mode toggle. The bear mark is tinted via CSS mask-image on
/brand/greylogo.png (the only transparent-background logo asset); see .bear-mask in globals.css
and the BearLogo component. No em dashes anywhere on the site.

## Preserve list - never modify without asking
/public (all images, logos, fonts), .env.local, .gitignore, .git/. Never add images I did not
provide.

## Copy that is final (client-approved)
"Book Now" (not "book your chair"), "Appointment only", "Rep the studio", shirt names Green Tee /
Blue Tee / Yellow/Black Tee / Brown Tee at $35, all haircut services 30 minutes.
