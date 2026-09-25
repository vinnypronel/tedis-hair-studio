# Archive

Features built for Tedi's Hair Studio that are not on the live site. Kept whole so they can be
put back without rebuilding them.

Nothing in here is compiled: `archive` is in the `exclude` list in `tsconfig.json`, and no file
under `src/` imports from it.

| Doc | Feature | Archived |
| --- | --- | --- |
| [BOOKING-FEATURE.md](BOOKING-FEATURE.md) | On-site 4-step booking flow, `/book` and `/book/confirmed/[code]`, plus the admin live-booking log | 2026-08-24 |
| [SHOP-CHECKOUT-FEATURE.md](SHOP-CHECKOUT-FEATURE.md) | Cart, checkout, order confirmation, and the shirt purchase block | 2026-08-24 |

Each doc lists the archived files, the exact code removed from files that are still live, every
call site that changed, the data contracts, the copy, and the steps to reinstate.

**Current state of the live site:** all booking CTAs go to Booksy
(`content.booking.url` in `src/lib/data/content.ts`), and `/shop` is a browse-only merch gallery.
