# Steepd

Email a newsletter or an EPUB to your private Steepd address and it appears on your
e-reader, ready to read.

Every email you send in is turned into a clean EPUB and added to a personal OPDS
catalogue. Point your e-reader at that catalogue once and new items just show up. It is
built for small e-ink readers that have no store, no Send-to-Kindle and no sync, where a
catalogue feed is the only way in, and it works with anything that speaks OPDS: KOReader
on Kindle, Kobo, PocketBook and Boox, the Xteink X3/X4 under CrossPoint, PocketBook and
Onyx firmware, and phone apps such as Cantook, KyBook and Moon+ Reader.

The hosted service runs at [steepd.app](https://steepd.app). This repository is the
source for it, under the AGPL, so you can also run your own.

## How it works

- You sign up with an email address; there is no password. Sign-in is a link by email.
- On first sign-in you choose your inbox address, which is also the username your reader
  signs in with. It cannot be changed afterwards.
- Email an EPUB to your address and it is filed as a book. Email anything else, a
  newsletter, an article, a forwarded message, and it is cleaned up and filed as an
  article. Images are fetched once and stored inside the EPUB; tracking pixels and
  tracking parameters are dropped.
- Both show up on your reader through the same feed. Your reader signs in with the
  username and a device passphrase generated from the account page.
- Anyone who has your address can send to it by default. The account page can restrict
  that to listed senders.
- If something you sent could not be filed, you get one email saying why.

## The hosted service

steepd.app is in open beta and free while it is: 100 MB of storage, items kept seven
days. There is no paid plan yet. It is a one-person project; there is no support desk,
and no promise about uptime or data retention beyond what the terms page says.

## Running your own

Steepd is one Python process with one SQLite file and one data directory. It is small
enough to run on the smallest instance of any container host, and it has no external
services beyond a mail provider.

What you need:

- **Python 3.13.**
- **A domain for inbox addresses** (for example `read.example.com`) with its MX record
  pointed at [Resend](https://resend.com), which is the only mail provider the code
  speaks. Resend receives the mail and calls the webhook; Steepd fetches the message and
  attachments through Resend's API.
- **A verified sending address** on Resend, for sign-in links and rejection replies.
- **A public HTTPS address** for the service, since e-readers fetch the catalogue from it
  and Resend posts webhooks to it.

### Local development

```bash
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/
ruff check src tests
PUBLIC_BASE_URL=http://localhost:8000 DATA_DIR=./.localdata python -m steepd
```

The editable install is required: the project uses a `src/` layout, so `python -m steepd`
fails with `ModuleNotFoundError` from a bare checkout. With only the two variables above
set, the service starts and `/healthz` answers, but inbound email is disabled and the
sign-in form says so.

### Deploying

The `Dockerfile` builds a self-contained image; `railway.toml` is the configuration the
hosted service uses on Railway. Mount a persistent volume at `DATA_DIR` (the image
defaults it to `/data`). `ops/uptime-worker` is an optional Cloudflare Worker that polls
`/healthz` every five minutes and emails you when the service goes down, comes back, or
runs low on disk.

There is a command for onboarding an account by hand, which skips the sign-in flow and
prints the one-time device passphrase:

```bash
python -m steepd create-tenant someone@example.com theirname
```

### Configuration

Everything is an environment variable. Required:

| Variable | Meaning |
|---|---|
| `PUBLIC_BASE_URL` | The address readers reach the service at. Every catalogue URL is built from it. Must be `https://` when `APP_ENVIRONMENT=production`. |
| `DATA_DIR` | Where the database, EPUBs and temporary files live. Defaults to `./data`; set it explicitly. |

Inbound email needs all three of these, or the webhook answers 503:

| Variable | Meaning |
|---|---|
| `INBOX_DOMAIN` | The domain every inbox lives under, e.g. `read.example.com`. Mail to any other domain is ignored. |
| `RESEND_API_KEY` | Used to fetch received mail and attachments, and to send replies. |
| `RESEND_WEBHOOK_SECRET` | The signing secret for Resend's `email.received` webhook. Unsigned requests are rejected. |

Optional, each feature off until set:

| Variable | Meaning |
|---|---|
| `MAIL_FROM_ADDRESS` | The From for all outbound mail, e.g. `Steepd <hello@example.com>`. Without it there is no sign-in by email and no rejection replies. |
| `APP_ENVIRONMENT` | `production` turns on the hourly retention sweep and requires HTTPS. Anything else is development. |
| `PORT` | Listening port. Defaults to 8000. |
| `STATS_TOKEN` | Bearer token for `GET /admin/stats`, which prints accounts, items, thirty days of inbound results and disk usage. Unset, the route answers 404 to everyone. `ops/stats.sh` wraps the request. |
| `SOURCE_REPOSITORY_URL` | HTTPS link rendered in the site footer as the AGPL source offer. |
| `SUPPORT_CONTACT` | An address rendered on the privacy and terms pages. |
| `SUPPORT_INBOUND_ADDRESS`, `SUPPORT_FORWARD_ADDRESS` | Set together, with `MAIL_FROM_ADDRESS`, to relay mail sent to an address on a Resend-receiving domain to your own mailbox. Only useful if Resend receives your apex domain. |
| `MAX_UPLOAD_BYTES`, `MAX_ARCHIVE_UNCOMPRESSED_BYTES`, `MAX_ARCHIVE_MEMBERS`, `MAX_COMPRESSION_RATIO`, `WEBHOOK_MAX_BYTES`, `NEWSLETTER_MAX_BODY_BYTES`, `NEWSLETTER_MAX_IMAGE_BYTES`, `NEWSLETTER_MAX_TOTAL_IMAGE_BYTES`, `SERVICE_CHECK_TIMEOUT_SECONDS` | Size and time limits. The defaults in `src/steepd/config.py` are the ones the hosted service runs with. |

Plan limits (storage per account, retention) live in `src/steepd/plans.py` and are not
environment variables.

## What is deliberately not here

- No JavaScript, no template engine, no ORM, no queue, no cache server. The pages are
  strings, the database is SQLite, background work is one thread.
- No web upload. Email is the only way in, on purpose.
- No RSS or URL saving yet.

## Contributing

Issues and pull requests are closed. The code is published so you can read it, audit it
and run it yourself, which the AGPL requires of a hosted service. If you fork it, the
licence asks that your users can get your source too.

If you find a security problem in the hosted service, email hello@steepd.app rather than
posting it anywhere public.

## Licence

GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE). Third-party
material is listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
