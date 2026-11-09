# Cresswell Court: 3 Cresswell Court, Tenby

Direct-booking website and admin for Lloyd & Paula Jones t/a Fairwood Properties. Hosted on Cloudflare.

| Folder | What it is | Cloudflare name |
|---|---|---|
| `site/` | Public website (static assets) | `morning-sun-e4f8` → cresswellcourt.co.uk |
| `workers/admin/` | Admin dashboard + API (`page.html` is the UI source, `worker.js` is generated from it) | `cresswell-admin` → admin.cresswellcourt.co.uk (behind Cloudflare Access) |
| `workers/mailer/` | Guest emails, payment links, messages out | `cresswell-mailer` |
| `workers/inbox/` | Email Worker: files guest replies to booking@ into the thread. Single file, no dependencies | `cresswell-inbox` |
| `workers/enquiries/` | Booking/enquiry form API | `cresswell-enquiries` |
| `workers/availability/` | Public availability feed | `cresswell-availability` |
| `schema/schema.sql` | D1 database tables (`cresswell-bookings`) | |

## Editing the admin
Edit `workers/admin/page.html`, then run `python3 tools/build-admin.py` to regenerate `workers/admin/worker.js` (the page is embedded in the worker as a template literal).

## Secrets and bindings (never commit these)
Held in Cloudflare only: `STRIPE_SECRET_KEY` (mailer), `ACCESS_AUD` / `ACCESS_TEAM` (admin). Bindings: D1 `DB` on admin, mailer, inbox; `EMAIL` send_email on mailer; service binding `MAILER` on admin. Mailer has a cron trigger every minute.
Email Routing: booking@cresswellcourt.co.uk → worker `cresswell-inbox` (which also forwards a copy to the host mailbox unless switched off in Settings).

## Business rules (in the code)
Full payment at booking; cancellation 14+ days full refund, 7–13 days 50%, under 7 none; min 3 nights; check-in Mon/Fri, check-out Mon/Thu/Fri; no cleaning fee; promo WELCOMEBACK = 10%.
