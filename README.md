# Steepd

Email a newsletter, a webpage link or an EPUB to your private Steepd address and it
appears on your e-reader, ready to read.
You can also upload EPUBs and save article links from your account page on the website.

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
- Attach an EPUB and it is filed as a book. With no EPUB attached, put one webpage URL
  alone in the subject to file its readable article in Saved. Anything else is treated as
  a newsletter or forwarded article. Images are fetched once and stored inside the EPUB;
  tracking pixels and tracking parameters are dropped.
- Prefer the website? The account page has an **Add to library** section to upload one
  EPUB or save one public article URL. Books go to Books; articles go to Saved. Import
  errors appear beside the form. Browser imports share a limit of 30 attempts per account
  per hour.
- Everything shows up on your reader through the same feed. Your reader signs in with the
  username and a device passphrase generated from the account page.
- The account page shows the same shelves your reader does: Recent, Newsletters, Saved
  and Books. Saved webpages are grouped by the site they came from. Newsletters can be
  grouped by publication; that is an opt-in which sends newsletter text to a model
  provider, described under "Automatic newsletter organization" below.
- Deleting an item moves it to Trash, where it can be restored for seven days. After that
  the hourly sweep deletes it and its file; **Delete permanently** in Trash does so
  straight away. Trashed items still count toward storage. Sending the same file again
  restores it rather than storing a second copy.
- **Star and delete from your reader** is an opt-in on the account page. With it on,
  choosing an item in the catalogue opens a menu with the real download, Star or Unstar,
  and Delete from Steepd, and the catalogue has a Starred shelf. Readers can only follow
  links, so these are GET requests. Each one sets a value rather than toggling it and
  carries the item revision its menu showed, so a request a reader replays with Back after
  a later change does nothing. Delete only moves the item to Trash. It is tested on
  CrossPoint; a client that loads links in advance could star or delete items, which is
  why it is off by default.
- Anyone who has your address can send to it by default. The account page can restrict
  that to listed senders.
- The account page's **Email Verification** checkbox can relay exactly the next inbound
  message to the account email, for services such as Gmail that verify an auto-forwarding
  address. That message bypasses the sender list, is not filed, and the relay switches off
  after the message or five minutes. It cannot forward anywhere else.
- If something you emailed could not be filed, you get one email saying why and up to three
  practical things to try.

## The hosted service

steepd.app is in open beta and free for now: 100 MB of storage, with items kept
90 days. There is no paid plan yet. It is a one-person
project; there is no support desk, and no promise about uptime or data retention beyond
what the terms page says.

## Running your own

Steepd is one Python process with one SQLite file and one data directory. It is small
enough to run on the smallest instance of any container host, and it needs no supporting
infrastructure service beyond a mail provider.

What you need:

- **Python 3.13.**
- **A domain for inbox addresses** (for example `read.example.com`) with its MX record
  pointed at [Resend](https://resend.com), which is the only mail provider the code
  speaks. Resend receives the mail and calls the webhook; Steepd fetches the message and
  attachments through Resend's API.
- **A verified sending address** on Resend, for sign-in links, rejection replies and
  temporary email-verification relays.
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
| `MAIL_FROM_ADDRESS` | The From for all outbound mail, e.g. `Steepd <hello@example.com>`. Without it there is no sign-in by email, rejection replies or temporary email-verification relay. |
| `APP_ENVIRONMENT` | `production` turns on the hourly retention sweep and requires HTTPS. Anything else is development. |
| `READER_ACTIONS_ENABLED` | Defaults to `true`. Set `false` to switch off Star and Delete in the catalogue for every account at once; their links then answer 404, including ones already open on a reader. Each account still has to opt in while it is `true`. |
| `PORT` | Listening port. Defaults to 8000. |
| `STATS_TOKEN` | Bearer token for `GET /admin/stats`, which prints accounts, items, thirty days of inbound results and disk usage. Unset, the route answers 404 to everyone. `ops/stats.sh` wraps the request. |
| `SOURCE_REPOSITORY_URL` | HTTPS link rendered in the site footer as the AGPL source offer. |
| `SUPPORT_CONTACT` | An address rendered on the privacy and terms pages. |
| `SUPPORT_INBOUND_ADDRESS`, `SUPPORT_FORWARD_ADDRESS` | Set together, with `MAIL_FROM_ADDRESS`, to relay mail sent to an address on a Resend-receiving domain to your own mailbox. Only useful if Resend receives your apex domain. |
| `MAX_UPLOAD_BYTES`, `MAX_ARCHIVE_UNCOMPRESSED_BYTES`, `MAX_ARCHIVE_MEMBERS`, `MAX_COMPRESSION_RATIO`, `WEBHOOK_MAX_BYTES`, `NEWSLETTER_MAX_BODY_BYTES`, `NEWSLETTER_MAX_IMAGE_BYTES`, `NEWSLETTER_MAX_TOTAL_IMAGE_BYTES`, `SERVICE_CHECK_TIMEOUT_SECONDS` | Size and time limits. The defaults in `src/steepd/config.py` are the ones the hosted service runs with. |

### Automatic newsletter organization

Off everywhere by default: the server switch below, and then each account's own opt-in.
With it off, nothing leaves the machine and the publication pages still work for anyone
who already has publications.

| Variable | Default | Meaning |
|---|---|---|
| `NEWSLETTER_AI_ENABLED` | `false` | The service switch. With `LLMKEY` and `LLMMODEL`, starts the organizer thread in production. |
| `LLMKEY` | — | One operator-owned OpenRouter inference key. Set its **monthly spending limit on OpenRouter**: that limit is the only dollar bound this service has. Never deploy a management key. |
| `LLMMODEL` | — | Model slug, e.g. `z-ai/glm-5.3-flash`. |
| `NEWSLETTER_AI_PLANS` | `free,paid` | Which plans are offered the feature. `paid` restricts it to paying accounts. An unknown plan name refuses to start rather than silently disabling the feature. |
| `NEWSLETTER_AI_DAILY_LIMIT` | `200` | Dispatches per account per UTC day, retries included. A workload and abuse bound, **not** a budget: see below. |
| `NEWSLETTER_AI_REASONING` | `exclude` | How much reasoning to pay for: `off`, `exclude`, `minimal`, `low`, `medium`, `high`. Reasoning is billed output. Some endpoints refuse `off` outright. |
| `NEWSLETTER_AI_PROVIDERS` | — | Comma-separated provider order. Set it and fallbacks are disabled. |
| `NEWSLETTER_AI_MAX_INPUT_PRICE`, `NEWSLETTER_AI_MAX_OUTPUT_PRICE` | `0.10`, `0.40` | USD per million tokens the router may pay. |

Before switching it on, run the compatibility check, which costs a fraction of a cent
and sends no real mail:

```bash
LLMKEY=... LLMMODEL=... .venv/bin/python ops/evaluate_publications.py smoke
```

It reports the provider actually used, the output contract, and the real token counts and
cost — including reasoning, which a short visible answer does not predict. If you set
`NEWSLETTER_AI_PROVIDERS` or the price ceilings, pass the same values as `--providers`,
`--max-input-price` and `--max-output-price` so the check uses the routing production will. `evaluate`
replays a private fixture directory in delivery order for a held-out accuracy trial.

**On the daily limit.** It stops one account generating unbounded work; it does not
reserve anyone a share of the key's balance. An account running at 200 dispatches a day
for a month costs roughly \$1.20 at 5,000 input tokens an issue and roughly \$12 at
65,000 — so the number to set it from is your monthly budget, your expected account
count, and how long a large backlog may take, not the cost per issue alone. When the key
hits its provider-side limit, or is rejected, the worker pauses and the account page says
so; reading is unaffected. The pause lasts until the process restarts: fix the key or the
balance on OpenRouter, then redeploy or restart the service to resume.

Changing `LLMMODEL` never re-sends history: completed and unrecognized issues are left
alone, and only an explicit Retry starts a new cycle.

Plan limits are optional environment variables, read once at startup:

| Variable | Default | Meaning |
|---|---|---|
| `FREE_QUOTA_BYTES` | `104857600` (100 MiB) | Storage per free account. |
| `PAID_QUOTA_BYTES` | `5368709120` (5 GiB) | Storage per paid account. |
| `FREE_RETENTION_DAYS` | `7` | Whole days a free item is kept, measured from its original arrival. |

The hosted service sets `FREE_QUOTA_BYTES=104857600` and `FREE_RETENTION_DAYS=90`.
The table above lists the defaults for an installation with these variables unset.

Unset variables use these defaults. Values must be positive integers; surrounding
whitespace is allowed, but blank values, fractions, and unit suffixes such as `100MB`
or `7d` are rejected. Quotas cannot exceed `9223372036854775807` bytes; retention cannot
exceed `36500` days. Invalid values prevent startup. Paid items are kept until deleted.
Upload limits and service disk-headroom checks still apply independently of plan quotas.

Restart or redeploy after changing these variables. The new limits apply to existing
accounts and items. Lowering a quota below current usage refuses new distinct items;
it does not remove existing files or prevent downloads, deletion, or duplicate delivery.
Shortening free retention can delete older items on the first production cleanup pass
after restart, which runs immediately and then hourly. Increasing retention keeps
remaining eligible items longer but cannot recover deleted files. Rolling back the
variables likewise cannot restore deleted files. Development runs have no automatic
cleanup thread. Changing an account's plan still takes effect without a restart.

## What is deliberately not here

- No JavaScript, no template engine, no ORM, no queue, no cache server. The pages are
  strings, the database is SQLite, background work is two threads: the retention sweep,
  and the newsletter organizer when it is switched on. Neither is a job system. The
  organizer has nothing to enqueue — a newsletter with no row in
  `newsletter_organization` *is* the work still to do, which is why importing mail is
  untouched by the feature and why turning it on needs no catch-up pass.
- No RSS, browser extension, paywall bypass, or site-specific extraction rules.

## Contributing

Issues and pull requests are closed. The code is published so you can read it, audit it
and run it yourself, which the AGPL requires of a hosted service. If you fork it, the
licence asks that your users can get your source too.

If you find a security problem in the hosted service, email hello@steepd.app rather than
posting it anywhere public.

## Licence

GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE). Third-party
material is listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
