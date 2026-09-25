# Tedi's Hair Studio: website and Google launch

Prepared September 23, 2026. Status: launch preparation, not published. Google profile not created or verified.

## Owner update received September 24

- Business name confirmed as Tedis Hair Studio. Match the exact spelling and punctuation on permanent signage when entering Google's name field.
- Domain access confirmed; supplied screenshot shows `tedishairstudio.com` active in Cloudflare. This confirms zone access, not a completed website deployment or mailbox setup.
- Booksy is the source of truth for service pricing, available appointment slots, and booking management. No custom booking or checkout backend is needed.
- The owner has not created a Google Business Profile. Still search Maps before creation because an unclaimed listing may already exist.
- Business name and logo are displayed outside on the glass, per the user. Prepare to show this signage during verification.
- Domain email setup is unknown. Do not treat `book@tedishairstudio.com` as a working mailbox until tested; remove the public email references before launch if it remains unconfirmed.
- Website approval is pending. Do not publish until the owner has reviewed it.

Immediate Google handoff: have Tedi sign into the Google account he intends to keep, visit https://business.google.com/add, check for an existing matching business, and create or claim the studio. Suggested primary category: Barber shop. Use the real suite address and owner-confirmed business phone. Add the Booksy profile as the appointment link when that field is available. Leave the new website URL unset until it is live. Use Business Profile settings > People and access to invite the website manager as a Manager, keeping Tedi as primary owner. Complete whichever verification Google offers; if video is requested, use the on-site recording checklist below.

## Decisions needed from the owner

- Confirm the hosting account and Google account that Tedi will retain as primary owner. Domain zone access is confirmed; registrar and renewal responsibility still need recording. Use collaborator access instead of sharing passwords.
- Confirm the address, suite, phone, SMS capability, Instagram and TikTok handles.
- Confirm whether `book@tedishairstudio.com` is a working mailbox. If it is not, provision it or remove the email links before launch.
- Confirm appointment availability currently shown on the website: Monday-Friday 10 AM-8 PM, Saturday 9 AM-5 PM, Sunday closed. These are not independently verified.
- Confirm the bio, studio story, establishment year, service descriptions, payment methods, cancellation wording, merchandise availability, and permission to publish customer photos and reviews.
- Signage is confirmed by the user. Identify the actual customer entrance and map pin, and prepare real photos showing the name on the glass.

The referenced desktop specification was not present at the path in AGENTS.md. This audit used the current project and its instructions.

## Work prepared in the code

- Replaced the browser-only contact form with direct call/text links. Previously it falsely reported delivery to Tedi; no server delivered the messages.
- Disabled the mock admin routes in production through a server layout. Local development keeps the mock screens. This is not an authenticated administration system.
- Added page-specific canonical URLs, social preview metadata using an existing supplied image, and a keyboard skip link.
- Removed unverified coordinates, duplicated opening hours, and self-serving review rating markup from the business structured data. Booksy review cards remain on the site.
- Removed fabricated sitemap modification timestamps.
- Updated Privacy & Terms to describe Booksy booking and in-studio merchandise, removing obsolete checkout, deposit, and deletion promises. Owner review is still required, including the eventual host's data practices.
- Applied compatible dependency security updates. See final verification record below.
- Restored approved Green Tee, Blue Tee, Yellow/Black Tee, and Brown Tee names and the Book Now wording. Added explicit typecheck and non-interactive lint commands.

## Website publication sequence

1. Resolve the owner details above, then update the typed modules in `src/lib/data/`. Keep all booking on Booksy and merchandise sales in person. A custom backend is not required for this launch.
2. Choose a host with Next.js 15 support. Deploy a preview using `npm ci` and `npm run build`. Keep preview URLs protected from indexing using the host's preview protection or `X-Robots-Tag: noindex`. Never apply that header to the final public site.
3. Review desktop and mobile on the actual preview: every public page, mobile navigation, gallery videos/lightbox, keyboard navigation, reduced motion, merchandise details, contact links, and Book Now. Complete a real booking only with the owner's intended appointment; simply opening Booksy is enough for the routing check.
4. In the host dashboard, add the apex domain and `www` and use its exact DNS instructions. Preserve existing mail and verification records. Redirect HTTP and the secondary hostname to `https://tedishairstudio.com`. The code currently assumes this as the final canonical domain.
5. Confirm HTTPS, all routes and image/video delivery, the chosen canonical hostname, and a genuine 404 on unknown paths. `/admin`, `/admin/dashboard`, and `/admin/gallery` must remain unavailable in production.
6. Confirm the public site permits indexing and `/robots.txt` and `/sitemap.xml` return successfully. Verify social previews use an accessible supplied image.
7. Verify mailbox sending/receiving if the email address remains visible. Check that phone/text links reach Tedi.
8. Save the deploy ID and a known good release for rollback. Record who owns hosting, domain renewal, and content updates. The mock admin does not publish changes.

DNS lookup during preparation returned Cloudflare authoritative SOA data but no apex A or MX answers. This is not proof of domain ownership. Hosting and mail configuration still need confirmation.

## Google Business Profile preparation

Search Google Maps first for the exact name, phone, and address. A web search found Tedi's Booksy profile but did not establish whether an existing Google profile exists. Claim an existing matching profile or request access if another person owns it. Create a new profile only after checking for duplicates. [Google add/claim instructions](https://support.google.com/business/answer/2911778?hl=en).

Suggested fields, pending owner confirmation:

| Field | Prepared value |
| --- | --- |
| Business name | Tedi's Hair Studio, matching real signage |
| Primary category | Barber shop, if offered in the setup category picker |
| Address line 1 | 259 Broad St |
| Address line 2 | Suite 103 |
| City / state / ZIP | Matawan, NJ 07747 |
| Phone | (732) 947-7359 |
| Website | https://tedishairstudio.com, once live |
| Appointment destination | https://booksy.com/en-us/1231797_tedis-hair-studio_barber-shop_28674_matawan |
| Location context | Inside Bellazio Collective, in the description rather than added to the business name |
| Hours | Appointment only; follow Google's appointment-only guidance |

Suggested description:

> Tedi's Hair Studio is a private, single-chair barber studio inside Bellazio Collective in Matawan, New Jersey. Services include haircuts, shape ups, beard trims, and haircut and beard appointments. Each visit is one-on-one with Tedi in a space designed for personal attention. Appointment only. Book through Booksy.

Do not add location keywords to the business name. Google requires permanent business signage for an address shown publicly. Its guidelines say appointment-only businesses should not list regular hours. Confirm eligibility for this specific suite before submitting; do not describe the studio as a mobile service unless Tedi actually travels to customers. [Business representation rules](https://support.google.com/business/answer/3038177?hl=en).

Services to enter after owner confirmation, all 30 minutes:

| Service | Price |
| --- | --- |
| Haircut | $35 |
| Haircut with beard | $40 |
| Shape up | $25 |
| Shape up with beard | $30 |
| Beard trim | $20 |

These prices and durations match the [public Booksy profile](https://booksy.com/en-us/1231797_tedis-hair-studio_barber-shop_28674_matawan) checked during preparation. Review totals change; Booksy reviews do not become Google reviews.

## Verification kit

Google chooses the available verification methods. Tedi should complete account sign-in, verification codes, and any on-site recording directly. [Verification options](https://support.google.com/business/answer/7107242?hl=en).

If video verification is requested, prepare one continuous recording of at least 30 seconds, captured through the Business Profile flow on a phone. Start outside with the street/building number, follow the entrance to suite 103, show Tedi's permanent business sign and barber equipment, and demonstrate authorized access such as unlocking the studio. Avoid customer faces and private records. Do not pre-record or edit the verification video. [Google video requirements](https://support.google.com/business/answer/14271705?hl=en).

Prepare owner-supplied profile photos: recognizable logo, exterior/entrance, suite signage, interior and chair, Tedi at work, and a small selection of cuts with permission. Existing site photos may be suitable for interior/work examples. New real entrance/signage photos may still be needed. No generated or unprovided images were added to the website.

After verification, check the map pin and directions from a customer's phone. Add the public profile URL to the site's business data, replace generic map-search links where appropriate, and add the booking link if supported. [Business link requirements](https://support.google.com/business/answer/13769188?hl=en).

## Get the website into Google Search

Business Profile and website indexing are separate tasks.

1. Add a Domain property for `tedishairstudio.com` in [Google Search Console](https://search.google.com/search-console).
2. Add Google's exact DNS verification record at the authoritative DNS provider and retain it. [Ownership verification](https://support.google.com/webmasters/answer/9008080?hl=en).
3. Submit `https://tedishairstudio.com/sitemap.xml`.
4. Inspect the homepage and services/contact pages and request indexing after the live URL tests succeed.
5. Validate the live business markup with [Rich Results Test](https://search.google.com/test/rich-results). Ratings on a business's own site should not be used to seek self-serving review stars. [Local business structured data](https://developers.google.com/search/docs/appearance/structured-data/local-business).
6. Review indexing and search performance after Google has crawled the site. Submission does not guarantee ranking or immediate indexing.

## After launch

- Put the website link in the existing Booksy and social profiles, and keep the business name/address/phone consistent.
- Once the Google profile is verified, get its review link and ask customers neutrally for honest feedback. No incentives or filtering requests to only satisfied customers. [Google review guidance](https://support.google.com/business/answer/3474122?hl=en).
- Draft review request, for the owner to send: "Thanks for visiting Tedi's Hair Studio. If you'd like to share your experience, you can leave an honest Google review here: [insert verified review link]. Thank you!" Nothing was sent to customers.
- Update real photos, reply to reviews, and keep booking/service details current. Consider Apple Business Connect and Bing Places after Google and the website are correct; avoid duplicate listings.
- Review Search Console, profile performance, broken links, domain renewal, and dependency security regularly. Analytics can be added later after choosing what to measure and updating the privacy notice.

## Verification record

- Production build and TypeScript checks passed during preparation.
- `npm run lint` passed after adding ESLint configuration.
- `npm audit` reported zero known vulnerabilities, including development dependencies. Next.js remains on version 15 (15.5.26); its PostCSS dependency is overridden to patched 8.5.28.
- HTTP checks passed for the homepage, all seven other public main pages, a product detail page, robots, and sitemap. Canonicals point to the expected production URLs.
- All three admin routes and an unknown route returned HTTP 404 in production.
- Browser spot checks covered mobile contact actions, mobile navigation to Services, and desktop contact/map layout. These are not a comprehensive accessibility or performance audit. Complete the full preview/device checklist above before publishing.
- Existing unrelated whitespace in `src/app/globals.css` was reported by `git diff --check`; it was left untouched.

Domain deployment, mobile-device contact delivery, account ownership, Google verification, and live indexing remain external launch steps. No Google account/profile or hosting/DNS changes were made.
