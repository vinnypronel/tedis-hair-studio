# Tedi's Hair Studio: presentation audit

September 25, 2026

## Outcome

Ready for Tedi's design and content review after the fixes below. This is a frontend review, not a backend or production-launch certification. No deployment, booking, message, or purchase was submitted.

## Coverage and results

- Checked Home, Services, Merch, Reviews, Gallery, and Contact at phone, tablet, laptop, and desktop widths: 320, 375, 390, 768, 1024, 1280, 1440, and 1920 CSS pixels across the audit. Also inspected About, Privacy & Terms, and product detail layouts. Not every route was tested at every width.
- Tested the mobile menu on a 320px-wide screen and in 812 x 375 landscape. Its links and footer remain reachable by scrolling.
- Production route checks: all 16 public content routes returned HTTP 200, including all eight products. Robots and sitemap returned 200; an invalid product returned 404.
- Checked 28 unique image/video requests using GET: all succeeded. No old Suite 103 address remained in the website's rendered public pages.
- Merch filtering: All shows eight items; Holiday shows two; switching back restores all eight.
- Gallery: both categories load; all four haircut videos loaded; image lightbox opens, advances, closes with Escape, locks background scrolling, and restores keyboard focus.
- Mobile menu: active-page underline, keyboard focus containment, Escape dismissal, background interaction lock, and hidden-menu exclusion verified.
- Scrollbar appears during movement and reaches opacity zero after the 2.5-second idle delay and fade.
- Booksy's actual booking widget opens and lists five services. Prices ($35, $25, $40, $30, $20) and all 30-minute durations match the site. Stopped before making a booking.
- TypeScript, ESLint, and the optimized Next.js build pass.

## Fixes made during the audit

- Contact: removed horizontal overflow caused by the map's aspect ratio and the fixed-width bear; use a stacked layout until there is enough room for the address, hours, and map.
- Home: allow the environment tagline to wrap instead of widening/clipping the mobile section.
- Navigation: tightened laptop link spacing; kept the selected Home link readable over the hero; mark Merch active on product pages; trap mobile-menu keyboard focus and close the menu when switching to desktop.
- Services: added vertical padding so mobile service rows do not run together.
- Gallery: expose controls on touch and keyboard focus; contain lightbox focus, restore it on close, and let the video seek slider retain its arrow-key behavior.
- Smooth scrolling: cancel the latest animation frame correctly during cleanup.
- Homepage carousel: defer duplicate video loading until needed, avoiding competing cached media requests; add accessible names to video gallery links.
- Clock: use ET instead of a year-round EST label, since New York observes daylight saving time.
- Build tooling: support NEXT_BUILD_DIR so production audit builds can use build/responsive-audit without overwriting the live development output.

## Items for Tedi to confirm

1. **Booksy address:** the live profile and booking widget still display **259 Broad St, 103, Matawan, 07747**. The website uses the supplied **259-267 Broad St, Suite 128, Matawan, NJ 07747**. Update the address in Booksy before customers use the new site.
2. **Review snapshot updated:** the website's saved count was updated to 149 at the user's request after the audit. The site's review data is static, not a live feed.
3. **Business content:** confirm opening hours, phone/email, shirt availability/sizes, and the remaining descriptive copy. A working mailto/tel/sms link does not verify that the inbox or number receives messages.

Booksy reference: https://booksy.com/en-us/1231797_tedis-hair-studio_barber-shop_28674_matawan

## Test limits

- Browser testing used desktop Chromium with responsive and touch emulation. Physical iPhone Safari, Android Chrome, and Firefox were not tested.
- No real appointment, call, SMS, email, checkout, or admin data mutation was performed. Backend work remains deferred.
- This audit covers layout, public navigation, media loading, selected keyboard interactions, and build health. It is not a formal WCAG, legal, security, or performance certification.
- The existing admin area is a local demo and is excluded from production by its layout guard.

## Clean presentation preview

The audit production preview uses http://localhost:3002 (no Next.js development badge). The usual live development preview remains on http://localhost:3000.

To recreate the audit preview in PowerShell:

```powershell
$env:NEXT_BUILD_DIR = "build/responsive-audit"
npm run build
npm run start -- --port 3002
```
