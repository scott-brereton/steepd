"""The browser-facing layer: passwordless sign-up, sign-in, and the account page.

There is no password to choose and none to store. Both sign-up and sign-in end in an
emailed single-use link; redeeming it sets a session cookie. The device password the
e-reader uses for OPDS Basic auth is a separate credential, generated on demand from
the account page and shown exactly once.

Pages are server-rendered strings. No template engine and no JavaScript: every page is
a form and a few links, and the security headers middleware already sends a
`default-src 'none'` CSP that would have to be loosened for either.

The visual tokens below are shared with the public marketing page so the two read as
one product; they are inlined once per response rather than served as a stylesheet,
which keeps the CSP's `style-src 'unsafe-inline'` the only concession it makes.
"""

# No `from __future__ import annotations` here, for the reason app.py records at the top
# of that file: the dependency aliases below are locals of build_web_router, so under
# PEP 563 their annotations would arrive as strings that never resolve and every route
# taking a session would silently degrade into one expecting a query parameter.
import html
import logging
import math
import secrets
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated
from urllib.parse import parse_qsl, urlencode, urljoin

from bs4 import BeautifulSoup, NavigableString, Tag
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from steepd.auth import (
    MAGIC_TOKEN_TTL,
    SESSION_TTL,
    consume_magic_token,
    hash_password,
    issue_magic_token,
    issue_session,
    resolve_session,
    revoke_session,
    same_origin_guard,
)
from steepd.config import Settings
from steepd.db import AllowedSenderCapReached, Database
from steepd.inboxnames import (
    email_stem,
    is_reserved_inbox_local,
    normalize_inbox_local,
    validate_inbox_local_format,
)
from steepd.models import Item, RefusedSender, Tenant
from steepd.outbound import OutboundEmailDisabled, OutboundEmailError, send_email
from steepd.plans import FREE_PLAN, FREE_RETENTION, PAID_PLAN, quota_bytes, retention_for
from steepd.storage import ItemStorage
from steepd.tenancy import TenantScope

LOGGER = logging.getLogger("steepd.web")

SESSION_COOKIE = "steepd_session"
SESSION_MAX_AGE_SECONDS = int(SESSION_TTL.total_seconds())
MAGIC_TOKEN_TTL_MINUTES = int(MAGIC_TOKEN_TTL.total_seconds() // 60)
MAGIC_EMAIL_SUBJECT = "Sign in to Steepd"

# Long enough for any real address (RFC 5321's limit), short enough that the form field
# cannot be used to push a large value through the mail provider.
MAX_EMAIL_LENGTH = 320

# A page of cards rather than a feed of entries, so smaller than opds.PAGE_SIZE.
ACCOUNT_PAGE_SIZE = 25
ACCOUNT_SORTS = ("newest", "oldest", "title")
ACCOUNT_DEFAULT_SORT = ACCOUNT_SORTS[0]
ACCOUNT_SORT_LABELS = {"newest": "Newest", "oldest": "Oldest", "title": "Title"}
# The same cap the OPDS search route puts on its own q, because it is the same field.
ACCOUNT_QUERY_MAX_LENGTH = 160
USAGE_WARNING_PERCENT = 85
DELETE_CONFIRMATION_FIELD = "confirm"

# Every form on these pages is one short field. Registered with the body-size middleware
# in app.py so an unauthenticated POST cannot make the server buffer an arbitrary body;
# the item-delete route is absent only because its path carries an id and the middleware
# matches exact paths.
FORM_MAX_BYTES = 8 * 1024
FORM_ROUTE_LIMITS = {
    path: FORM_MAX_BYTES
    for path in (
        "/signup",
        "/signin",
        "/signout",
        "/account/address",
        "/account/rotate",
        "/account/delete",
        "/account/senders/policy",
        "/account/senders/add",
        "/account/senders/remove",
    )
}


@dataclass(frozen=True, slots=True)
class BrowserSession:
    """A resolved session cookie. The raw token travels with the tenant because sign-out
    and account deletion need to revoke the row it points at."""

    tenant: Tenant
    token: str


@dataclass(frozen=True, slots=True)
class LibraryView:
    """One rendered page of the library, and everything the links around it need.

    `matching` counts what the search found and `library` counts the whole library, which
    are the same number when there is no search. They are kept apart because they answer
    different questions: `matching` drives "3 items match" and the page count, while
    `library` decides whether to offer a search box at all -- a brand-new account with no
    items should see the get-started sentence, not a form with nothing to search.
    """

    items: list[Item]
    matching: int
    library: int
    query: str
    sort: str
    page: int
    pages: int


# -- query parameters --------------------------------------------------------
# The account page takes q, sort and page from the query string, and every one of them
# falls back to a default instead of erroring. A 422 belongs to an API; here the value
# arrives from a bookmark, a hand-edited URL or a stale link, and the useful answer to
# all three is the library.


def _clean_query(raw: str) -> str:
    value = raw.strip()
    return value if len(value) <= ACCOUNT_QUERY_MAX_LENGTH else ""


def _clean_sort(raw: str) -> str:
    return raw if raw in ACCOUNT_SORTS else ACCOUNT_DEFAULT_SORT


def _clean_page(raw: str) -> int:
    try:
        page = int(raw)
    except ValueError:
        return 1
    return max(1, page)


def _account_href(*, query: str = "", sort: str = ACCOUNT_DEFAULT_SORT, page: int = 1) -> str:
    """An attribute-ready /account URL carrying only the parameters that are not defaults.

    Escaped here rather than at each call site: the ampersands urlencode writes between
    parameters have to reach the browser as `&amp;`, and a link that skipped that would
    only misbehave once a page had two parameters on it, which is every paginated search.
    """
    params: list[tuple[str, str]] = []
    if query:
        params.append(("q", query))
    if sort != ACCOUNT_DEFAULT_SORT:
        params.append(("sort", sort))
    if page > 1:
        params.append(("page", str(page)))
    return html.escape(f"/account?{urlencode(params)}" if params else "/account", quote=True)


# -- rendering ---------------------------------------------------------------

_CSS = """
:root{--umber:#6B4226;--almond:#8B5E3C;--charcoal:#1A1A2E;--parchment:#F5F2ED;
--chamomile:#D4A96A;--muted:#8A857E;--rule:#E2DCD2;--card:#FFFDFA}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--parchment);color:var(--charcoal);
font:17px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:660px;margin:0 auto;padding:0 24px 64px}
h1,h2{font-family:ui-rounded,-apple-system,"SF Pro Rounded",system-ui,sans-serif;letter-spacing:-0.02em}
h1{font-size:32px;line-height:1.15;font-weight:700;margin:0 0 14px}
h2{font-size:20px;font-weight:700;margin:0 0 10px}
p{margin:0 0 14px}
a{color:var(--almond)}
.lede{font-size:19px;color:#4A453E;margin-bottom:26px}
.mark{display:flex;align-items:center;gap:10px;padding:48px 0 36px;text-decoration:none;color:var(--charcoal)}
.mark span{font:600 18px/1 ui-rounded,-apple-system,system-ui,sans-serif;letter-spacing:.06em}
form{margin:0 0 14px}
.field{display:flex;gap:10px;flex-wrap:wrap}
input[type=email],input[type=search]{flex:1 1 250px;font:16px/1 inherit;padding:14px 16px;
border:1px solid var(--rule);border-radius:8px;background:var(--card);color:var(--charcoal)}
input[type=email]:focus,input[type=search]:focus{outline:2px solid var(--almond);outline-offset:-1px;
border-color:transparent}
button{font:600 16px/1 ui-rounded,-apple-system,system-ui,sans-serif;padding:14px 26px;border:0;
border-radius:8px;background:var(--umber);color:#fff;cursor:pointer}
button:hover{background:#5A3720}
.fineprint{font-size:14px;color:var(--muted);margin:10px 0 0}
.notice{background:var(--card);border:1px solid var(--umber);border-radius:8px;padding:12px 16px;
font-size:15px;margin:0 0 18px}
section{padding:32px 0 0;border-top:1px solid var(--rule);margin-top:32px}
.card{background:var(--card);border:1px solid var(--rule);border-radius:12px;padding:16px 20px;margin:0 0 10px}
.label{display:block;font:600 13px/1 ui-rounded,-apple-system,system-ui,sans-serif;color:var(--umber);
letter-spacing:.02em;margin-bottom:6px}
.usage-meter{height:6px;background:var(--rule);border-radius:999px;overflow:hidden;margin:10px 0 0}
.usage-meter-fill{height:100%;background:var(--umber)}
code{font:15px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.secret{display:block;font:16px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--card);
border:1px solid var(--umber);border-radius:8px;padding:14px 16px;word-break:break-all;margin:0 0 14px}
.items{list-style:none;padding:0;margin:0 0 14px}
.items li{display:flex;gap:12px;align-items:center;justify-content:space-between;background:var(--card);
border:1px solid var(--rule);border-radius:10px;padding:12px 16px;margin-bottom:8px}
.items form{margin:0}
.title{display:block;font-size:16px}
.meta{display:block;font-size:14px;color:var(--muted)}
.quiet{background:none;color:var(--almond);border:1px solid var(--rule);padding:8px 14px;font-size:14px}
.quiet:hover{background:var(--parchment);color:var(--umber)}
.pager{display:flex;gap:14px;align-items:center;font-size:14px;margin:0 0 14px}
.confirm{display:flex;gap:8px;align-items:center;font-size:15px;margin:0 0 14px}
.danger button{background:#8A2F2F}
.danger button:hover{background:#6E2525}
.chip{font:600 11px/1 ui-rounded,-apple-system,system-ui,sans-serif;font-style:normal;
letter-spacing:.06em;background:var(--chamomile);color:#4A3418;border-radius:999px;padding:5px 9px}
.hero h1{font-size:42px;line-height:1.1}
.small{font-size:15.5px;color:#544F48}
.muted{color:var(--muted)}
.diagram{margin:52px 0 0}
.diagram svg{width:100%;height:auto;display:block}
.tiers{display:flex;gap:12px;flex-wrap:wrap}
.tier{flex:1 1 170px;background:var(--card);border:1px solid var(--rule);border-radius:12px;padding:20px}
.tier.live{border-color:var(--umber);border-width:1.5px}
.tier.soon{opacity:.55}
.amt{font:700 28px/1.1 ui-rounded,-apple-system,system-ui,sans-serif;color:var(--umber);display:block}
.per{font-size:14px;color:var(--muted);display:block;margin:3px 0 10px}
.tier ul{list-style:none;padding:0;margin:0;font-size:15px;color:#544F48}
.tier li{padding:2px 0}
.check{margin:20px 0 16px}
.check p{margin:0 0 8px;padding:12px 16px;background:var(--card);border:1px solid var(--rule);
border-radius:10px;font-size:15px;color:#544F48}
.check strong{font-family:ui-rounded,-apple-system,system-ui,sans-serif;font-size:13px;
color:var(--umber);letter-spacing:.02em}
.check span{display:inline-block;margin-top:2px}
ol{margin:0 0 14px;padding-left:22px;font-size:15.5px;color:#544F48}
ol li{margin:0 0 7px}
footer{margin-top:32px;padding:36px 0 0;border-top:1px solid var(--rule);font-size:14px;color:var(--muted)}
/* The walkthrough runs on radios, because this site ships no script and the CSP would
block one anyway. Four radios in one group sit in front of the four panels, and
`#walk-n:checked ~ .walk-sn` is the whole state machine -- which is why every control in
it is a <label for=...> aimed at the next radio rather than a button. The four panels are
stacked in one grid cell and hidden with visibility, not display, so the stage keeps the
height of the tallest step and the box never grows or shrinks between steps. Visibility
does not rewind keyframes the way display:none did, so every animation is declared under
the step's :checked selector instead -- applying the animation fresh when a step opens is
what restarts it, including on "Start over". */
.walk{margin:30px 0 0;padding:0}
.walk-caption{font-size:14px;color:var(--muted);margin:0 0 12px}
.walk details{background:var(--card);border:1px solid var(--rule);border-radius:12px}
.walk summary{display:flex;align-items:center;gap:8px;cursor:pointer;list-style:none;padding:15px 20px;
font:600 16px/1.2 ui-rounded,-apple-system,system-ui,sans-serif;color:var(--umber)}
.walk summary::-webkit-details-marker{display:none}
.walk summary::after{content:"";width:7px;height:7px;margin-left:auto;transform:rotate(45deg);
border-right:2px solid var(--almond);border-bottom:2px solid var(--almond)}
.walk details[open] summary::after{transform:rotate(-135deg)}
.walk-hide{display:none}
.walk details[open] .walk-say{display:none}
.walk details[open] .walk-hide{display:inline}
.walk-stage{position:relative;display:grid;border-top:1px solid var(--rule);padding:18px 20px 20px}
.walk-stage input{position:absolute;width:1px;height:1px;opacity:0;margin:0}
.walk-step{grid-area:1/1;visibility:hidden}
#walk-1:checked~.walk-s1,#walk-2:checked~.walk-s2,#walk-3:checked~.walk-s3,#walk-4:checked~.walk-s4{visibility:visible}
.walk-count{font:600 12px/1 ui-rounded,-apple-system,system-ui,sans-serif;color:var(--muted);
letter-spacing:.04em;margin:0 0 12px}
.walk-mail{background:var(--parchment);border:1px solid var(--rule);border-radius:10px;overflow:hidden}
.walk-bar{display:flex;align-items:center;gap:7px;padding:9px 14px;background:#EDE8E0;
border-bottom:1px solid var(--rule);color:var(--muted);letter-spacing:.05em;
font:600 12px/1 ui-rounded,-apple-system,system-ui,sans-serif}
.walk-body{padding:14px 16px}
.walk-body p{font-size:14.5px;color:#544F48;margin:0 0 8px}
.walk-body p:last-child{margin:0}
.walk-from{display:block;font:600 15.5px/1.3 ui-rounded,-apple-system,system-ui,sans-serif}
.walk-subject{display:block;font-size:14px;color:var(--umber);margin:1px 0 10px}
.walk-row{display:flex;gap:12px;align-items:baseline;padding:11px 16px;border-bottom:1px solid var(--rule)}
.walk-key{flex:none;width:52px;color:var(--muted);
font:600 12px/1.5 ui-rounded,-apple-system,system-ui,sans-serif}
.walk-val{overflow:hidden;font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
.walk-note{padding:10px 16px 0}
.walk-hint{font-size:13.5px;color:var(--muted);margin:0}
.walk-act{display:flex;align-items:center;gap:14px;flex-wrap:wrap;padding:14px 16px}
.walk-mail .walk-act{border-top:1px solid var(--rule)}
.walk-go{display:inline-block;cursor:pointer;padding:12px 24px;border-radius:8px;background:var(--umber);
color:#fff;font:600 15px/1 ui-rounded,-apple-system,system-ui,sans-serif}
.walk-go:hover{background:#5A3720}
.walk-type{display:inline-block;width:0;overflow:hidden;white-space:nowrap;vertical-align:bottom;
border-right:2px solid var(--umber)}
.walk-brew{display:block;width:100%;height:auto;margin:2px 0 6px}
.walk-swirl,.walk-file,.walk-next,.walk-entry{opacity:0}
.walk-cap{font-size:15px;color:#544F48;margin:0}
.walk-side{display:flex;gap:20px;align-items:center}
.walk-side>div{flex:1}
.walk-reader{display:block;flex:none;width:132px;height:auto;margin:2px 0}
#walk-1:checked~.walk-s1 .walk-go,#walk-2:checked~.walk-s2 .walk-go,#walk-3:checked~.walk-s3 .walk-go,
#walk-4:checked~.walk-s4 .walk-go{animation:walk-pulse 1.9s ease-out .5s infinite}
#walk-2:checked~.walk-s2 .walk-late{animation-delay:2.1s}
#walk-2:checked~.walk-s2 .walk-type{
animation:walk-type 1.6s steps(24,end) .4s forwards,walk-caret .8s step-end infinite}
#walk-3:checked~.walk-s3 .walk-fly{animation:walk-fly 1.6s ease-in-out .25s forwards}
#walk-3:checked~.walk-s3 .walk-swirl{animation:walk-swirl 1.5s ease-in-out 1.5s forwards}
#walk-3:checked~.walk-s3 .walk-file{animation:walk-file .8s ease-out 2.5s forwards}
#walk-3:checked~.walk-s3 .walk-next{animation:walk-in .5s ease-out 3.2s forwards}
#walk-4:checked~.walk-s4 .walk-entry{animation:walk-in .7s ease-out .4s forwards}
.walk-done{font:700 22px/1.2 ui-rounded,-apple-system,system-ui,sans-serif;color:var(--umber);margin:16px 0 6px}
.walk-restart{display:inline-block;cursor:pointer;padding:9px 15px;border:1px solid var(--rule);
border-radius:8px;background:none;color:var(--almond);
font:600 14px/1 ui-rounded,-apple-system,system-ui,sans-serif}
.walk-restart:hover{color:var(--umber);background:var(--parchment)}
@keyframes walk-pulse{0%{box-shadow:0 0 0 0 rgba(107,66,38,.38)}70%{box-shadow:0 0 0 13px rgba(107,66,38,0)}
100%{box-shadow:0 0 0 0 rgba(107,66,38,0)}}
@keyframes walk-type{to{width:var(--tw)}}
@keyframes walk-caret{50%{border-right-color:transparent}}
@keyframes walk-fly{0%{transform:translateX(0);opacity:1}62%{transform:translateX(158px);opacity:1}
100%{transform:translateX(178px);opacity:0}}
@keyframes walk-swirl{0%{opacity:0;transform:translateY(8px)}40%{opacity:.9}
100%{opacity:0;transform:translateY(-12px)}}
@keyframes walk-file{from{opacity:0;transform:translateX(-18px)}to{opacity:1;transform:translateX(0)}}
@keyframes walk-in{to{opacity:1}}
@media (max-width:520px){h1{font-size:28px}.hero h1{font-size:32px}.mark{padding-top:32px}
.diagram{margin-top:38px}.walk-stage{padding:16px 14px}
.walk-side{display:block}.walk-reader{width:94px;margin:2px auto 8px}
.walk-done{font-size:19px;margin:10px 0 4px}}
/* Same story, told as still pictures: every step keeps its end state and stays clickable. */
@media (prefers-reduced-motion:reduce){
/* !important so these outrank the #walk-n:checked animation triggers above; an
   accessibility override losing a specificity fight would be silent. */
.walk-type{width:var(--tw);animation:none!important;border-right-color:transparent}
.walk-go{animation:none!important;box-shadow:0 0 0 3px var(--chamomile)}
.walk-fly,.walk-swirl,.walk-file,.walk-next,.walk-entry{animation:none!important}
.walk-file,.walk-swirl,.walk-next,.walk-entry{opacity:1}}
"""

_MARK = (
    '<a class="mark" href="/">'
    '<svg width="28" height="28" viewBox="0 0 46 46" aria-hidden="true">'
    '<path d="M33 8.5 A18 18 0 1 0 39.5 20.5" fill="none" stroke="#6B4226" '
    'stroke-width="3.4" stroke-linecap="round"/></svg>'
    "<span>steepd</span><em class=\"chip\">beta</em></a>"
)


def _page(title: str, body: str, *, status_code: int = status.HTTP_200_OK) -> HTMLResponse:
    document = (
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{html.escape(title)}</title>\n<style>{_CSS}</style>\n</head>\n"
        f"<body>\n<main>\n{_MARK}\n{body}\n</main>\n</body>\n</html>\n"
    )
    # no-store, not just private: one of these pages carries a device password, and the
    # rest carry an inbox address that is effectively a credential of its own.
    return HTMLResponse(document, status_code=status_code, headers={"Cache-Control": "private, no-store"})


def _notice(message: str) -> str:
    return f'<p class="notice">{html.escape(message)}</p>' if message else ""


def _email_form(action: str, submit_label: str, email: str) -> str:
    return (
        f'<form method="post" action="{action}"><div class="field">'
        '<input type="email" name="email" placeholder="you@example.com" required '
        f'autocomplete="email" aria-label="Email address" value="{html.escape(email)}">'
        f"<button type=\"submit\">{submit_label}</button></div></form>"
    )


def _signup_page(*, email: str = "", error: str = "", status_code: int = status.HTTP_200_OK) -> HTMLResponse:
    return _page(
        "Steepd — sign up",
        f"{_notice(error)}"
        "<h1>Read it on your e-reader</h1>"
        '<p class="lede">You get a private email address to send newsletters and books to, and a '
        "catalogue feed your reader subscribes to once.</p>"
        f"{_email_form('/signup', 'Create an account', email)}"
        '<p class="fineprint">We send a sign-in link to that address. There is no password to choose.</p>'
        '<p class="fineprint">Already have an account? <a href="/signin">Sign in</a>.</p>',
        status_code=status_code,
    )


def _signin_page(*, email: str = "", error: str = "", status_code: int = status.HTTP_200_OK) -> HTMLResponse:
    return _page(
        "Steepd — sign in",
        f"{_notice(error)}"
        "<h1>Sign in</h1>"
        '<p class="lede">Enter your email address and we will send you a link.</p>'
        f"{_email_form('/signin', 'Send me a link', email)}"
        '<p class="fineprint">New here? <a href="/signup">Create an account</a>.</p>',
        status_code=status_code,
    )


def _check_email_page(email: str) -> HTMLResponse:
    """The single response for every outcome of a sign-in or sign-up request.

    Sign-up for an address that already has an account renders this, sign-in for an
    address with no account renders this, and so does an account that has hit the
    issuance cap. Any wording that varied between them would turn either form into a
    way to ask whether a given person uses this service.
    """
    return _page(
        "Steepd — check your email",
        "<h1>Check your email</h1>"
        f'<p class="lede">If there is an account for <strong>{html.escape(email)}</strong>, a sign-in '
        f"link is on its way. It works once and expires in {MAGIC_TOKEN_TTL_MINUTES} minutes.</p>"
        '<p class="fineprint">Nothing after a minute or two? Look in the spam folder, or '
        '<a href="/signin">ask for another link</a>.</p>',
    )


def _redeem_page(token: str) -> HTMLResponse:
    """What the link in the email opens: one button, and the token goes nowhere until it
    is pressed.

    Redeeming on the GET was the natural shape and the wrong one. Anything that follows
    links in a mailbox -- a security scanner, a preview fetcher -- spent the token before
    the person could, and the request line, token included, was written to the access log.
    A POST is made by nothing but the button, and its path is never logged.
    """
    return _page(
        "Steepd — sign in",
        "<h1>Sign in to Steepd</h1>"
        '<p class="lede">Press the button to finish signing in. The link works once.</p>'
        f'<form method="post" action="/auth/{html.escape(token, quote=True)}">'
        '<button type="submit">Sign in</button></form>',
    )


def _expired_link_page() -> HTMLResponse:
    return _page(
        "Steepd — link expired",
        "<h1>That link has expired</h1>"
        f'<p class="lede">Sign-in links work once and last {MAGIC_TOKEN_TTL_MINUTES} minutes, so this '
        "one has already done its job or timed out. Ask for another and it will arrive in a moment.</p>"
        '<p><a href="/signin">Get a new link</a></p>',
    )


def _unavailable_page() -> HTMLResponse:
    return _page(
        "Steepd — sign-in unavailable",
        "<h1>Sign-in is not available yet</h1>"
        '<p class="lede">This deployment cannot send email, so there is no way to deliver your link. '
        "Nothing is wrong with your address.</p>",
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
    )


def _send_failed_page() -> HTMLResponse:
    return _page(
        "Steepd — link not sent",
        "<h1>The link did not send</h1>"
        '<p class="lede">Our mail provider did not accept the message. Try again shortly and it will '
        "usually go through.</p>"
        '<p><a href="/signin">Try again</a></p>',
        status_code=status.HTTP_502_BAD_GATEWAY,
    )


def _no_inbox_page() -> HTMLResponse:
    return _page(
        "Steepd — account not created",
        "<h1>We could not set up your inbox address</h1>"
        '<p class="lede">Every account needs its own address and we could not settle on one. Try again '
        "and it will almost certainly work.</p>"
        '<p><a href="/signup">Try again</a></p>',
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
    )


class StemStatus(StrEnum):
    """What became of the name taken from the email address the account signed up with."""

    FREE = "free"
    TAKEN = "taken"
    RESERVED = "reserved"
    MALFORMED = "malformed"


# How the choose-your-address page says each of those out loud. FREE is absent because a
# stem that was offered needs no explaining.
_STEM_VERDICTS = {
    StemStatus.TAKEN: "is taken",
    StemStatus.RESERVED: "is reserved",
    StemStatus.MALFORMED: "cannot be an address",
}


def _address_page(*, name: str, stem: str, stem_status: StemStatus, inbox_domain: str, error: str = "",
                  status_code: int = status.HTTP_200_OK) -> HTMLResponse:
    domain = html.escape(inbox_domain) if inbox_domain else "your Steepd domain"
    verdict = _STEM_VERDICTS.get(stem_status, "")
    notice = (
        f'<p class="notice"><code>{html.escape(stem)}</code> {verdict}, so here is the nearest free one. '
        "Keep it or choose another.</p>"
        if verdict and not error
        else _notice(error)
    )
    return _page(
        "Steepd — choose your address",
        f"{notice}"
        "<h1>Choose your address</h1>"
        '<p class="lede">This is where you will send things, and the username your reader signs in with. '
        "It cannot be changed later.</p>"
        '<form method="post" action="/account/address"><div class="field">'
        f'<input type="text" name="name" value="{html.escape(name, quote=True)}" required '
        'autocomplete="off" autocapitalize="none" spellcheck="false" maxlength="24" '
        'aria-label="Your address" pattern="[a-z0-9.\\-]{2,24}">'
        f'<span class="meta">@{domain}</span>'
        '<button type="submit">Use this address</button></div></form>'
        '<p class="fineprint">Lowercase letters, digits, dots and hyphens; 2 to 24 characters.</p>',
        status_code=status_code,
    )


def _address_already_chosen_page() -> HTMLResponse:
    """The stale-tab answer. A 403 the browser can read, rather than the JSON body a raised
    HTTPException would render, because the person holding that tab is not an API client."""
    return _page(
        "Steepd — address already chosen",
        "<h1>Your address is already chosen</h1>"
        '<p class="lede">It was set the first time you signed in and it cannot be changed, so this '
        "form has nothing left to do.</p>"
        '<p><a href="/account">Back to your library</a></p>',
        status_code=status.HTTP_403_FORBIDDEN,
    )


def _goodbye_page() -> HTMLResponse:
    return _page(
        "Steepd — account deleted",
        "<h1>Your account is gone</h1>"
        '<p class="lede">Your library and your files have been deleted, and your inbox address is '
        "held back so nobody else can ever be sent your mail. Your reader will stop finding the "
        "catalogue on its next refresh.</p>"
        '<p><a href="/signup">Start again</a></p>',
    )


def _password_page(password: str) -> HTMLResponse:
    return _page(
        "Steepd — new device password",
        "<h1>Your new device password</h1>"
        f'<code class="secret">{html.escape(password)}</code>'
        "<p>Copy it into your reader now. We store only a hash of it, so this is the one time it can "
        "be shown.</p>"
        '<p class="fineprint">Your previous password may keep working for up to a minute while cached '
        "credentials expire.</p>"
        '<p><a href="/account">Back to your account</a></p>',
    )


def _human_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    kilobytes = size_bytes / 1024
    if kilobytes < 1024:
        return f"{kilobytes:.0f} KB"
    megabytes = kilobytes / 1024
    if megabytes < 1024:
        return f"{megabytes:.1f}".removesuffix(".0") + " MB"
    return f"{megabytes / 1024:.1f}".removesuffix(".0") + " GB"


def _remaining_retention_days(item: Item, retention: timedelta, *, now: datetime) -> int:
    created_at = datetime.fromisoformat(item.created_at)
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    seconds_remaining = ((created_at + retention) - now).total_seconds()
    return max(0, math.ceil(seconds_remaining / timedelta(days=1).total_seconds()))


def _item_row(item: Item, *, retention: timedelta | None, now: datetime) -> str:
    meta = f"{item.kind.capitalize()} · {_human_size(item.size_bytes)} · {item.created_at[:10]}"
    removal_note = ""
    if retention is not None:
        days = _remaining_retention_days(item, retention, now=now)
        unit = "day" if days == 1 else "days"
        removal_note = f'<span class="meta">removed in {days} {unit}</span>'
    return (
        "<li><div>"
        f'<span class="title">{html.escape(item.title)}</span>'
        f'<span class="meta">{html.escape(meta)}</span>'
        f"{removal_note}"
        "</div>"
        f'<form method="post" action="/account/items/{html.escape(item.id)}/delete">'
        '<button class="quiet" type="submit">Delete</button></form></li>'
    )


def _plan_card(tenant: Tenant, storage_bytes: int, retention: timedelta | None) -> str:
    allowance = quota_bytes(tenant.plan)
    percentage = max(0.0, storage_bytes / allowance * 100) if allowance else 0.0
    fill_width = min(percentage, 100.0)
    width = f"{fill_width:.4f}".rstrip("0").rstrip(".")
    plan_name = "Paid" if tenant.plan == PAID_PLAN else "Free"
    retention_note = (
        f'<p class="fineprint">Items are kept for {retention.days} days.</p>' if retention is not None else ""
    )
    warning = (
        '<p class="fineprint">New deliveries are refused once the storage limit is reached.</p>'
        if percentage >= USAGE_WARNING_PERCENT
        else ""
    )
    return (
        '<div class="card"><span class="label">Plan</span>'
        f'<span class="title">{plan_name}</span>'
        f'<span class="meta">{_human_size(storage_bytes)} of {_human_size(allowance)} used</span>'
        '<div class="usage-meter" role="meter" aria-label="Storage used" aria-valuemin="0" '
        f'aria-valuemax="{allowance}" aria-valuenow="{min(storage_bytes, allowance)}">'
        f'<div class="usage-meter-fill" style="width: {width}%"></div></div>'
        f"{retention_note}{warning}</div>"
    )


def _search_form(view: LibraryView) -> str:
    # The sort rides along as a hidden field so searching does not silently reorder the
    # library under someone who had just chosen an order.
    carried_sort = (
        f'<input type="hidden" name="sort" value="{html.escape(view.sort, quote=True)}">'
        if view.sort != ACCOUNT_DEFAULT_SORT
        else ""
    )
    return (
        '<form method="get" action="/account"><div class="field">'
        '<input type="search" name="q" placeholder="Search titles and authors" '
        f'aria-label="Search your library" maxlength="{ACCOUNT_QUERY_MAX_LENGTH}" '
        f'value="{html.escape(view.query, quote=True)}">'
        f'{carried_sort}<button type="submit">Search</button></div></form>'
    )


def _sort_links(view: LibraryView) -> str:
    choices = []
    for sort in ACCOUNT_SORTS:
        label = ACCOUNT_SORT_LABELS[sort]
        if sort == view.sort:
            choices.append(f"<strong>{label}</strong>")
        else:
            # No page: a reorder puts different items on page 3, so staying there would
            # land on a page of things the reader has never seen the start of.
            choices.append(f'<a href="{_account_href(query=view.query, sort=sort)}">{label}</a>')
    return f'<p class="fineprint">Sort: {" · ".join(choices)}</p>'


def _search_summary(view: LibraryView) -> str:
    if not view.query:
        return ""
    matches = "1 item matches" if view.matching == 1 else f"{view.matching} items match"
    return (
        f'<p class="fineprint">{matches} “{html.escape(view.query)}”. '
        f'<a href="{_account_href(sort=view.sort)}">Clear</a></p>'
    )


def _pager(view: LibraryView) -> str:
    if view.pages <= 1:
        return ""
    parts = []
    if view.page > 1:
        href = _account_href(query=view.query, sort=view.sort, page=view.page - 1)
        parts.append(f'<a href="{href}">Previous</a>')
    parts.append(f'<span class="meta">Page {view.page} of {view.pages}</span>')
    if view.page < view.pages:
        href = _account_href(query=view.query, sort=view.sort, page=view.page + 1)
        parts.append(f'<a href="{href}">Next</a>')
    return f'<p class="pager">{" ".join(parts)}</p>'


def _library_section(view: LibraryView, *, retention: timedelta | None, now: datetime) -> str:
    if not view.library:
        return (
            '<p class="lede">Nothing here yet. Send something to the address above and it will appear '
            "in a minute or so.</p>"
        )
    controls = f"{_search_form(view)}{_sort_links(view)}{_search_summary(view)}"
    if not view.items:
        return f'{controls}<p class="lede">Nothing in your library matches that search.</p>'
    rows = "".join(_item_row(item, retention=retention, now=now) for item in view.items)
    return f'{controls}<ul class="items">{rows}</ul>{_pager(view)}'


def _short_date(stamp: str) -> str:
    """'2 Sep' from an ISO timestamp; the year is noise on a page about the last month."""
    try:
        moment = datetime.fromisoformat(stamp)
    except ValueError:
        return stamp[:10]
    return f"{moment.day} {moment.strftime('%b')}"


def _senders_section(tenant: Tenant, senders: list[str], refused: list[RefusedSender]) -> str:
    """The list is an addition to the account's own address, never a replacement for it:
    the row at the top is always allowed and cannot be removed, which is why the add route
    refuses to store it."""
    anyone = " checked" if tenant.sender_policy != "listed" else ""
    listed = " checked" if tenant.sender_policy == "listed" else ""
    rows = "".join(
        "<li><div>"
        f'<span class="title"><code>{html.escape(address)}</code></span></div>'
        '<form method="post" action="/account/senders/remove">'
        f'<input type="hidden" name="address" value="{html.escape(address, quote=True)}">'
        '<button class="quiet" type="submit">Remove</button></form></li>'
        for address in senders
    )
    offers = "".join(
        "<li><div>"
        f'<span class="title">Mail from <code>{html.escape(item.address)}</code> was not accepted</span>'
        f'<span class="meta">{item.count} time{"s" if item.count != 1 else ""}, last on '
        f"{html.escape(_short_date(item.last_seen_at))}</span></div>"
        '<form method="post" action="/account/senders/add">'
        f'<input type="hidden" name="address" value="{html.escape(item.address, quote=True)}">'
        '<button class="quiet" type="submit">Allow</button></form></li>'
        for item in refused
    )
    return (
        "<section><h2>Who can send to this address</h2>"
        '<form method="post" action="/account/senders/policy">'
        f'<label class="confirm"><input type="radio" name="policy" value="anyone"{anyone}> '
        "Anyone who has the address</label>"
        f'<label class="confirm"><input type="radio" name="policy" value="listed"{listed}> '
        "Only the senders listed here</label>"
        '<button class="quiet" type="submit">Save</button></form>'
        '<ul class="items">'
        f'<li><div><span class="title"><code>{html.escape(tenant.email)}</code></span>'
        '<span class="meta">always allowed</span></div></li>'
        f"{rows}</ul>"
        '<form method="post" action="/account/senders/add"><div class="field">'
        '<input type="email" name="address" placeholder="newsletter@example.com" required '
        'aria-label="Sender to allow"><button type="submit">Allow this sender</button></div></form>'
        + (f'<ul class="items">{offers}</ul>' if offers else "")
        + "</section>"
    )


def _account_page(
    tenant: Tenant,
    view: LibraryView,
    *,
    senders: list[str],
    refused: list[RefusedSender],
    storage_bytes: int,
    inbox_address: str,
    catalogue_url: str,
    error: str = "",
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    retention = retention_for(tenant.plan)
    listing = _library_section(view, retention=retention, now=datetime.now(UTC))
    return _page(
        "Steepd — your account",
        f"{_notice(error)}"
        "<h1>Your account</h1>"
        f"{_plan_card(tenant, storage_bytes, retention)}"
        f'<div class="card"><span class="label">Send books and newsletters here</span>'
        f"<code>{html.escape(inbox_address)}</code></div>"
        f'<div class="card"><span class="label">Catalogue address for your reader</span>'
        f"<code>{html.escape(catalogue_url)}</code></div>"
        f'<div class="card"><span class="label">Device username</span>'
        f"<code>{html.escape(tenant.opds_username)}</code></div>"
        '<p class="fineprint"><a href="/devices">How to set this up on your reader</a></p>'
        f"<section><h2>Your library</h2>{listing}</section>"
        f"{_senders_section(tenant, senders, refused)}"
        "<section><h2>Device password</h2>"
        "<p>Your reader signs in with the username above and a device password. Generate one here "
        "whether it is your first or a replacement — it is shown once and never stored.</p>"
        '<form method="post" action="/account/rotate">'
        '<button type="submit">Generate a new device password</button></form>'
        '<p class="fineprint">A new password replaces the old one, so any reader already set up will '
        "need updating.</p></section>"
        '<section><h2>Sign out</h2><form method="post" action="/signout">'
        '<button class="quiet" type="submit">Sign out of this browser</button></form></section>'
        '<section class="danger"><h2>Delete your account</h2>'
        "<p>This removes your library and your stored files, and holds your inbox address back so nobody "
        "else can ever be sent your mail. It cannot be undone.</p>"
        '<form method="post" action="/account/delete">'
        f'<label class="confirm"><input type="checkbox" name="{DELETE_CONFIRMATION_FIELD}" value="yes" '
        'required> Yes, delete everything</label>'
        '<button type="submit">Delete my account</button></form></section>',
        status_code=status_code,
    )


# -- the public pages --------------------------------------------------------
#
# The landing page and the two legal pages are the only pages a signed-out visitor sees
# with anything on them, and they are rendered by the same _page as the account: one
# stylesheet, one header, one beta chip, so the marketing side and the product side
# cannot drift into looking like two services.
#
# Every number quoted below is derived from steepd.plans rather than written out, because
# a page that says "100 MB" while the quota says something else is worse than no page.

# Hand-tuned geometry: two source shapes on the left, the service in the middle, a reader
# on the right. Inline rather than an <img> because the CSP serves no images and an
# external one would be the single request that made this page phone anywhere.
_DIAGRAM = """
<div class="diagram">
<svg viewBox="0 0 660 250" role="img"
aria-label="A forwarded newsletter or an emailed EPUB goes to Steepd, which delivers it to your e-reader's catalogue.">
<defs>
<marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7"
orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="#B6AFA5"/></marker>
</defs>
<g transform="translate(0,52)">
<rect x="0" y="0" width="176" height="60" rx="10" fill="#FFFDFA" stroke="#E2DCD2"/>
<rect x="18" y="19" width="30" height="22" rx="3" fill="none" stroke="#8B5E3C" stroke-width="1.8"/>
<path d="M18 21 L33 32 L48 21" fill="none" stroke="#8B5E3C" stroke-width="1.8" stroke-linecap="round"/>
<text x="62" y="26" font-family="ui-rounded,-apple-system,system-ui,sans-serif"
font-size="14" font-weight="600" fill="#1A1A2E">Newsletter</text>
<text x="62" y="44" font-family="-apple-system,system-ui,sans-serif"
font-size="12.5" fill="#8A857E">you forward it</text>
</g>
<g transform="translate(0,138)">
<rect x="0" y="0" width="176" height="60" rx="10" fill="#FFFDFA" stroke="#E2DCD2"/>
<rect x="20" y="17" width="26" height="26" rx="3" fill="none" stroke="#8B5E3C" stroke-width="1.8"/>
<path d="M26 25 h14 M26 30 h14 M26 35 h9" stroke="#8B5E3C" stroke-width="1.6" stroke-linecap="round"/>
<text x="62" y="26" font-family="ui-rounded,-apple-system,system-ui,sans-serif"
font-size="14" font-weight="600" fill="#1A1A2E">EPUB</text>
<text x="62" y="44" font-family="-apple-system,system-ui,sans-serif"
font-size="12.5" fill="#8A857E">you attach it</text>
</g>
<path d="M184 82 C 214 82, 214 118, 244 122" fill="none" stroke="#B6AFA5" stroke-width="1.8" marker-end="url(#a)"/>
<path d="M184 168 C 214 168, 214 132, 244 128" fill="none" stroke="#B6AFA5" stroke-width="1.8" marker-end="url(#a)"/>
<g transform="translate(258,88)">
<rect x="0" y="0" width="124" height="74" rx="12" fill="#FBF7F2" stroke="#6B4226" stroke-width="1.5"/>
<path d="M69 19 A12 12 0 1 0 73.5 27" fill="none" stroke="#6B4226" stroke-width="2.6" stroke-linecap="round"/>
<text x="62" y="58" text-anchor="middle" font-family="ui-rounded,-apple-system,system-ui,sans-serif"
font-size="13.5" font-weight="600" fill="#6B4226" letter-spacing="0.5">steepd</text>
</g>
<text x="320" y="182" text-anchor="middle" font-family="-apple-system,system-ui,sans-serif"
font-size="12.5" fill="#8A857E">cleans it up</text>
<text x="320" y="199" text-anchor="middle" font-family="-apple-system,system-ui,sans-serif"
font-size="12.5" fill="#8A857E">about a minute</text>
<path d="M390 125 H 448" fill="none" stroke="#B6AFA5" stroke-width="1.8" marker-end="url(#a)"/>
<g transform="translate(462,34)">
<rect x="0" y="0" width="128" height="182" rx="14" fill="#1A1A2E"/>
<rect x="9" y="9" width="110" height="150" rx="6" fill="#F5F2ED"/>
<circle cx="64" cy="171" r="5" fill="none" stroke="#4A4560" stroke-width="1.6"/>
<text x="20" y="32" font-family="ui-rounded,-apple-system,system-ui,sans-serif"
font-size="11.5" font-weight="700" fill="#1A1A2E">Steepd</text>
<line x1="20" y1="40" x2="108" y2="40" stroke="#E2DCD2" stroke-width="1"/>
<text x="20" y="60" font-family="-apple-system,system-ui,sans-serif" font-size="11" fill="#4A453E">Recent</text>
<text x="20" y="84" font-family="-apple-system,system-ui,sans-serif" font-size="11" fill="#4A453E">Newsletters</text>
<text x="20" y="108" font-family="-apple-system,system-ui,sans-serif" font-size="11" fill="#4A453E">Books</text>
<path d="M99 56 l4 4 -4 4 M99 80 l4 4 -4 4 M99 104 l4 4 -4 4" fill="none" stroke="#B6AFA5"
stroke-width="1.4" stroke-linecap="round"/>
<rect x="20" y="126" width="88" height="6" rx="3" fill="#D4A96A" opacity="0.55"/>
<rect x="20" y="138" width="60" height="6" rx="3" fill="#D4A96A" opacity="0.35"/>
</g>
<text x="526" y="238" text-anchor="middle" font-family="-apple-system,system-ui,sans-serif"
font-size="12.5" fill="#8A857E">your catalogue</text>
</svg>
</div>
"""

# The storyboard's own artwork, in the diagram's vocabulary: the envelope from the
# newsletter card, the steepd cup, and the reader frame. Two SVGs rather than one because
# they play in different steps, and both are decorative -- every word they show is also in
# the prose beside them, which is what a screen reader gets.
_WALK_BREW = """
<svg class="walk-brew" viewBox="0 0 540 150" aria-hidden="true">
<g transform="translate(14,52)"><g class="walk-fly">
<rect x="0" y="0" width="56" height="42" rx="4" fill="#FFFDFA" stroke="#8B5E3C" stroke-width="2"/>
<path d="M3 4 L28 24 L53 4" fill="none" stroke="#8B5E3C" stroke-width="2" stroke-linecap="round"/>
</g></g>
<g transform="translate(196,38)">
<g class="walk-swirl">
<path d="M44 -8 c -7 -8 4 -14 -3 -22" fill="none" stroke="#D4A96A" stroke-width="2.4" stroke-linecap="round"/>
<path d="M72 -6 c -7 -8 4 -14 -3 -22" fill="none" stroke="#D4A96A" stroke-width="2.4" stroke-linecap="round"/>
</g>
<rect x="0" y="0" width="124" height="74" rx="12" fill="#FBF7F2" stroke="#6B4226" stroke-width="1.5"/>
<path d="M69 19 A12 12 0 1 0 73.5 27" fill="none" stroke="#6B4226" stroke-width="2.6" stroke-linecap="round"/>
<text x="62" y="58" text-anchor="middle" font-family="ui-rounded,-apple-system,system-ui,sans-serif"
font-size="13.5" font-weight="600" fill="#6B4226" letter-spacing="0.5">steepd</text>
</g>
<g transform="translate(410,36)"><g class="walk-file">
<rect x="0" y="0" width="96" height="78" rx="8" fill="#FFFDFA" stroke="#E2DCD2"/>
<path d="M18 24 h60 M18 36 h60 M18 48 h40" stroke="#8B5E3C" stroke-width="2" stroke-linecap="round"/>
<text x="48" y="68" text-anchor="middle" font-family="ui-rounded,-apple-system,system-ui,sans-serif"
font-size="11.5" font-weight="600" fill="#6B4226">EPUB</text>
</g></g>
</svg>
"""

_WALK_READER = """
<svg class="walk-reader" viewBox="0 0 240 250" aria-hidden="true">
<rect x="20" y="0" width="200" height="238" rx="18" fill="#1A1A2E"/>
<rect x="33" y="13" width="174" height="196" rx="8" fill="#F5F2ED"/>
<circle cx="120" cy="223" r="7" fill="none" stroke="#4A4560" stroke-width="2"/>
<text x="47" y="38" font-family="ui-rounded,-apple-system,system-ui,sans-serif"
font-size="12.5" font-weight="700" fill="#1A1A2E">Steepd</text>
<line x1="47" y1="47" x2="193" y2="47" stroke="#E2DCD2" stroke-width="1"/>
<g class="walk-entry">
<rect x="43" y="57" width="154" height="38" rx="7" fill="#FFFDFA" stroke="#D4A96A" stroke-width="1.4"/>
<text x="53" y="75" font-family="ui-rounded,-apple-system,system-ui,sans-serif"
font-size="10.5" font-weight="600" fill="#1A1A2E">The Weekly Dispatch</text>
<text x="53" y="88" font-family="-apple-system,system-ui,sans-serif" font-size="10" fill="#8A857E">Issue #42</text>
</g>
<path d="M53 116 h118 M53 138 h118 M53 160 h92" stroke="#E2DCD2" stroke-width="7" stroke-linecap="round"/>
</svg>
"""

_WALK_ENVELOPE_GLYPH = (
    '<svg width="15" height="12" viewBox="0 0 30 22" aria-hidden="true">'
    '<rect x="1" y="1" width="28" height="20" rx="3" fill="none" stroke="#8A857E" stroke-width="2"/>'
    '<path d="M3 4 L15 13 L27 4" fill="none" stroke="#8A857E" stroke-width="2" stroke-linecap="round"/></svg>'
)


def _walkthrough(inbox_domain: str) -> str:
    """The storyboard under the diagram: four steps, one radio group, no script.

    The address it types is this deployment's own. A walkthrough that showed a domain this
    instance does not answer on would be teaching the one detail a new reader has to get
    right, wrongly -- so a deployment with no inbox domain configured says "your Steepd
    address" instead of inventing one.
    """
    address = f"you@{inbox_domain}" if inbox_domain else "your Steepd address"
    named = f"@{html.escape(inbox_domain)} address" if inbox_domain else "Steepd address"
    return (
        '<figure class="walk">'
        f'<figcaption class="walk-caption">See how it works: forward any email to your {named} '
        "and it appears on your e&#8209;reader; EPUB attachments are filed as books.</figcaption>"
        "<details><summary>"
        '<span class="walk-say">Show me how it works</span>'
        '<span class="walk-hide">Hide the walkthrough</span>'
        "</summary>"
        '<div class="walk-stage">'
        '<input type="radio" name="walkthrough" id="walk-1" checked '
        'aria-label="Step 1: a newsletter in your inbox">'
        '<input type="radio" name="walkthrough" id="walk-2" '
        'aria-label="Step 2: forward it to your Steepd address">'
        '<input type="radio" name="walkthrough" id="walk-3" aria-label="Step 3: Steepd converts it">'
        '<input type="radio" name="walkthrough" id="walk-4" aria-label="Step 4: it arrives on your reader">'
        '<div class="walk-step walk-s1">'
        '<p class="walk-count">Step 1 of 4 — your inbox</p>'
        f'<div class="walk-mail"><div class="walk-bar">{_WALK_ENVELOPE_GLYPH}<span>Inbox</span></div>'
        '<div class="walk-body"><span class="walk-from">The Weekly Dispatch</span>'
        '<span class="walk-subject">Issue #42</span>'
        "<p>Ten things worth your Sunday, and the one chart that changed our minds about batteries.</p>"
        "<p>Plus: what we got wrong last week, and a short note on the new format.</p></div>"
        '<div class="walk-act"><label class="walk-go" for="walk-2">Forward</label>'
        '<span class="walk-hint">Tap forward</span></div></div></div>'
        '<div class="walk-step walk-s2">'
        '<p class="walk-count">Step 2 of 4 — the forward</p>'
        f'<div class="walk-mail"><div class="walk-bar">{_WALK_ENVELOPE_GLYPH}<span>New message</span></div>'
        '<div class="walk-row"><span class="walk-key">To</span><span class="walk-val">'
        f'<span class="walk-type" style="--tw:{len(address)}ch">{html.escape(address)}</span>'
        "</span></div>"
        '<div class="walk-note"><p class="walk-hint">Your Steepd address</p></div>'
        '<div class="walk-row"><span class="walk-key">Subject</span>'
        '<span class="walk-val">Fwd: Issue #42</span></div>'
        '<div class="walk-act"><label class="walk-go walk-late" for="walk-3">Send</label></div>'
        "</div></div>"
        '<div class="walk-step walk-s3">'
        '<p class="walk-count">Step 3 of 4 — steeping</p>'
        f"{_WALK_BREW}"
        '<p class="walk-cap">Steepd cleans it up — about a minute.</p>'
        '<div class="walk-act"><label class="walk-go walk-next" for="walk-4">See it on the reader</label>'
        "</div></div>"
        '<div class="walk-step walk-s4">'
        '<p class="walk-count">Step 4 of 4 — your reader</p>'
        '<div class="walk-side">'
        f"{_WALK_READER}"
        "<div>"
        '<p class="walk-hint">The Weekly Dispatch — Issue #42, now the top entry in your catalogue.</p>'
        '<p class="walk-done">Simple, right?</p>'
        f"<p>Books work the same way — attach the EPUB to an email to your {named}.</p>"
        "</div></div>"
        '<div class="walk-act"><label class="walk-restart" for="walk-1">Start over</label></div>'
        "</div>"
        "</div></details></figure>"
    )


# The same call to action twice, once above the diagram and once at the foot of the page.
LANDING_SUBMIT_LABEL = "Create your reader address"
LANDING_FINEPRINT = (
    '<p class="fineprint">Free while Steepd is in beta — we email you a sign-in link '
    "instead of asking for a password.</p>"
)

# The two places the setup page sends someone whose own reader cannot do this. Both are
# other people's projects rather than ours, which is exactly why they are named here as
# constants: if either moves, one line changes and the page follows.
KOREADER_KOBO_URL = "https://www.mobileread.com/forums/showthread.php?t=314220"
KINDLE_MODDING_URL = "https://kindlemodding.org/"


def _free_quota() -> str:
    return _human_size(quota_bytes(FREE_PLAN))


def _footer(source_url: str) -> str:
    source = f' · <a href="{html.escape(source_url, quote=True)}">source</a>' if source_url else ""
    return (
        '<footer>Steepd · <a href="/privacy">privacy</a> · <a href="/terms">terms</a>'
        f"{source} · AGPL&#8209;3.0</footer>"
    )


def _tiers() -> str:
    """Three cards, only one of which is buyable.

    The paid two are shown muted and without a button on purpose: the beta is a demand
    test, and a price with no way to pay it is only honest if the page says so.
    """
    return (
        '<div class="tiers">'
        '<div class="tier live"><span class="amt">Free</span>'
        '<span class="per">what you get today</span>'
        f"<ul><li>{_free_quota()}</li><li>Kept {FREE_RETENTION.days} days</li></ul></div>"
        '<div class="tier soon"><span class="amt">$5</span><span class="per">per month</span>'
        f"<ul><li>{_human_size(quota_bytes(PAID_PLAN))}</li><li>Kept until deleted</li>"
        '<li class="muted">coming soon</li></ul></div>'
        "</div>"
    )


def _landing_page(*, source_url: str = "", inbox_domain: str = "") -> HTMLResponse:
    signup = _email_form("/signup", LANDING_SUBMIT_LABEL, "")
    return _page(
        "Steepd — reading for small e-ink readers",
        '<div class="hero">'
        "<h1>Email it. Read it on your e&#8209;reader.</h1>"
        '<p class="lede">For small e&#8209;ink readers with no store, no '
        "Send&#8209;to&#8209;Kindle and no sync — where a catalogue feed is the only way in.</p>"
        f"{signup}{LANDING_FINEPRINT}{_DIAGRAM}{_walkthrough(inbox_domain)}</div>"
        "<section><h2>Setup</h2>"
        '<p class="small">You get an address to email things to, and a feed address. Type the '
        "feed into your reader once. No app, no plugin, no cable.</p>"
        '<p class="small"><strong>Attachment means book. No attachment means article.</strong></p>'
        "</section>"
        "<section><h2>Newsletters that read like articles</h2>"
        '<p class="small">Most converters hand your reader a narrow column of nested email tables. '
        "Steepd flattens them, keeps the tables holding real data, drops the tracking pixels, and "
        "stores images in the file so it works offline.</p></section>"
        f"<section><h2>Pricing</h2>{_tiers()}"
        '<p class="small muted">Paid plans arrive after the beta. Libraries built during the beta '
        "carry over.</p></section>"
        "<section><h2>Will it work on mine?</h2>"
        '<p class="small">Steepd is an <strong>OPDS catalogue</strong> — a standard most '
        "e&#8209;readers already speak. Think of it as an RSS feed for books: your reader browses "
        "it over wifi and downloads what you pick. Nothing to install.</p>"
        '<p class="small"><strong>The test:</strong> open your reader\'s menu and look for '
        "<em>OPDS</em>, <em>Catalog</em>, <em>Library</em>, or anywhere you can add a catalogue by "
        "URL. If that exists, Steepd works.</p>"
        '<div class="check">'
        "<p><strong>Tested</strong><br><span>Xteink X4 Pro on stock CrossPoint firmware — no "
        "sideloading, and a strict parser that rejects malformed feeds. The hardest case.</span></p>"
        "<p><strong>Has OPDS built in</strong><br><span>KOReader, which runs on Kindle, Kobo, "
        "PocketBook, Boox and Android. Also PocketBook and Onyx firmware directly.</span></p>"
        "<p><strong>Tell us</strong><br><span>Own something else with a catalogue option? Sign up "
        "and point it at your feed. If your reader will not read it, we want to hear about it.</span></p>"
        "</div>"
        '<p class="small"><a href="/devices">Full setup steps for your device</a> — the exact menus on '
        "the readers we have tested, and the honest answer for the ones that cannot do it.</p>"
        '<p class="small muted">Think of it as Send&#8209;to&#8209;Kindle for every reader that never got one.</p>'
        "</section>"
        "<section><h2>Open source</h2>"
        '<p class="small">Steepd is AGPL&#8209;3.0 and you are free to run your own copy. This one '
        "is the copy you do not have to maintain."
        + (
            f' The source is at <a href="{html.escape(source_url, quote=True)}">'
            f"{html.escape(source_url.removeprefix('https://'))}</a>."
            if source_url
            else ""
        )
        + "</p></section>"
        "<section><h2>Start reading</h2>"
        '<p class="small">Sign up with an email address; there is no password to choose.</p>'
        f"{signup}{LANDING_FINEPRINT}</section>"
        f"{_footer(source_url)}",
    )


def _privacy_page(*, contact: str = "", source_url: str = "") -> HTMLResponse:
    questions = ""
    if contact:
        safe = html.escape(contact)
        questions = (
            "<section><h2>Questions</h2>"
            f'<p>Write to <a href="mailto:{html.escape(contact, quote=True)}">{safe}</a> and a '
            "person will answer.</p></section>"
        )
    return _page(
        "Steepd — privacy",
        "<h1>Privacy</h1>"
        '<p class="lede">Steepd holds your reading, so it holds as little else as it can and shows '
        "none of it to anyone.</p>"
        "<section><h2>What we hold</h2>"
        "<p>You sign up with an email address. It is used to send you sign-in links and for nothing "
        "else: no newsletter, no product mail, and it is not passed on.</p>"
        "<p>When you forward an email to your Steepd address we convert it and store the result as "
        "an EPUB in your library. That file belongs to your account and is reachable only with your "
        "session or your device password.</p></section>"
        "<section><h2>What publishers can see</h2>"
        "<p>Images in a newsletter are fetched once, at the moment we convert it, and stored inside "
        "the EPUB. A publisher can therefore learn that a message was converted, but not when or "
        "whether you read it. Tracking pixels are dropped and tracking parameters are stripped out "
        "of links before the file is built.</p></section>"
        "<section><h2>What we do not do</h2>"
        "<p>There is no analytics, no advertising, no third-party script and no tracking cookie. "
        "One cookie is set, and it exists only to keep you signed in.</p></section>"
        "<section><h2>How long we keep it</h2>"
        f"<p>On the free plan an item is deleted automatically {FREE_RETENTION.days} days after it "
        "arrives, and the stored file goes with the record of it. Deleting an item yourself deletes "
        "it straight away. Deleting your account deletes your library and your stored files, and "
        "your inbox address is held back so nobody else can ever be sent your mail.</p></section>"
        "<section><h2>Who else is involved</h2>"
        "<p>Steepd runs on Railway, in the United States, and the email it sends you is delivered by "
        "Resend. Each sees only what its job needs: Railway holds the machine and its disk, Resend "
        "handles the messages we send. Our logs record that a request happened, never what was in it "
        "— no message content and no sign-in links.</p></section>"
        f"{questions}"
        f"{_footer(source_url)}",
    )


def _terms_page(*, source_url: str = "") -> HTMLResponse:
    licence = (
        f'Steepd is licensed under AGPL&#8209;3.0 and the <a href="{html.escape(source_url, quote=True)}">'
        "source is published</a>."
        if source_url
        else "Steepd is licensed under AGPL&#8209;3.0."
    )
    return _page(
        "Steepd — terms",
        "<h1>Terms</h1>"
        '<p class="lede">Steepd is a free public beta. Read this as a description of what to expect '
        "rather than as a promise.</p>"
        "<section><h2>The beta</h2>"
        "<p>The service can change, break or lose data without notice. Your reader can download "
        "every item in your library, so take a copy of anything you cannot afford to lose rather "
        "than trusting us to still have it.</p></section>"
        "<section><h2>What the free plan gives you</h2>"
        f"<p>{_free_quota()} of storage, with each item deleted automatically "
        f"{FREE_RETENTION.days} days after it arrives. Once you are at the limit new deliveries are "
        "refused, rather than something older being quietly thrown away.</p></section>"
        "<section><h2>Using it</h2>"
        "<p>One account per person. Do not use Steepd to store unlawful content, or content you have "
        "no right to copy. We may suspend an account being used to abuse the service or the mail "
        "providers it depends on.</p></section>"
        f"<section><h2>The software</h2><p>{licence} You are free to run your own copy.</p></section>"
        "<section><h2>No warranty</h2>"
        "<p>The service is provided as is, with no warranty of any kind, and we are not liable for "
        "data that is lost or unavailable. That is the honest position for a beta.</p></section>"
        "<section><h2>Ending it</h2>"
        "<p>You can delete your account from the account page whenever you like, which deletes your "
        "library and the files behind it. If we close an account, the same thing happens to its "
        "data.</p></section>"
        f"{_footer(source_url)}",
    )


def _devices_page(*, catalogue_url: str, source_url: str = "") -> HTMLResponse:
    """The setup walkthrough, one section per device.

    Two rules hold this page together. Steps are only numbered where the flow has actually
    been carried out on the device, so a numbered list is a promise that those menu names
    are the real ones; everywhere else the wording stays general on purpose. And where a
    reader's own software simply cannot do this -- Kobo, Kindle, PocketBook -- the page
    says so and names the alternative, rather than inventing a menu path that would send
    someone hunting through settings that do not exist.
    """
    address = html.escape(catalogue_url)
    return _page(
        "Steepd — set up your reader",
        "<h1>Set up your reader</h1>"
        '<p class="lede">You need three things, all on your account page: the catalogue address below, '
        "your device username, and a device password.</p>"
        f'<div class="card"><span class="label">Catalogue address</span><code>{address}</code></div>'
        '<p class="small">Any reader or app that can add a catalogue, an OPDS server or a network '
        "library by URL should work. Enter the address with your username and device password, and if a "
        "list of your books appears you are done. A reader that never asks for a password and shows an "
        "access error instead cannot read a private catalogue — use one of the apps below.</p>"
        "<section><h2>Xteink X4 (CrossPoint)</h2>"
        '<p class="small">Use the browser settings page: the address and the password are long to type '
        "on the device itself.</p>"
        "<ol>"
        "<li>On the home screen, open <strong>File Transfer → Join Network</strong> and join a 2.4 GHz "
        "network.</li>"
        "<li>On a phone or computer on that network, scan the QR code shown, or open "
        "<code>http://crosspoint.local/settings</code>.</li>"
        "<li>Open <strong>Settings</strong>, scroll to <strong>OPDS Servers</strong>, and choose "
        "<strong>+ Add Server</strong>.</li>"
        "<li>Enter a name, the catalogue address, your username and your device password, then use the "
        "<strong>Save</strong> button inside the server card.</li>"
        "<li>Leave File Transfer. <strong>OPDS Browser</strong> now appears on the home screen: open it, "
        "pick the server, and download a book.</li>"
        "</ol>"
        '<p class="small">The same entry can be made on the device under <strong>Settings → System → '
        "OPDS Servers → Add Server</strong>. Your password goes with every download as well as every "
        "browse, so if the catalogue opens but downloads fail, re-enter it.</p></section>"
        "<section><h2>KOReader</h2>"
        '<p class="small">KOReader runs on Kindle, Kobo, PocketBook, Boox, Android and desktop, and '
        "three sections below send you here.</p>"
        "<ol>"
        "<li>In the file browser, tap the <strong>magnifying-glass icon</strong> in the toolbar, then "
        "choose <strong>OPDS catalog</strong>.</li>"
        "<li>Tap the <strong>+</strong> icon in the top left.</li>"
        "<li>Enter a name, the catalogue address, your username and your device password.</li>"
        "<li>Save, then tap the catalogue to browse.</li>"
        "</ol>"
        '<p class="small">Downloading asks where to keep the book. Choose a folder of your own: on '
        "Kindle, do not accept the suggested <code>koreader/help</code> location, which a KOReader "
        "update can overwrite.</p></section>"
        "<section><h2>Onyx Boox</h2>"
        '<p class="small">Boox runs Android with the Play Store: install KOReader and follow the steps '
        "above, or use Moon+ Reader: <strong>Net Library → ⋮ → Add new catalog</strong>. The stock "
        "PushRead app is not documented to work with catalogue passwords.</p></section>"
        "<section><h2>PocketBook</h2>"
        '<p class="small">There is no way to add a catalogue that needs a password on PocketBook stock '
        "firmware. KOReader installs on PocketBook without jailbreaking; follow the steps above. Books "
        "another app downloads may not show in the native library until it rescans.</p></section>"
        "<section><h2>Kobo</h2>"
        '<p class="small">Kobo\'s built-in software cannot add catalogues; it only talks to the Kobo '
        f'store. The community <a href="{KOREADER_KOBO_URL}">one-click KOReader install</a> adds a '
        "reader that can, alongside everything you already have, and then the steps above "
        "apply.</p></section>"
        "<section><h2>Kindle</h2>"
        '<p class="small">Stock Kindle firmware has no OPDS support and no way to add a catalogue: '
        "books arrive by Send-to-Kindle or cable. A jailbroken Kindle runs KOReader and connects like "
        "any other reader; jailbreaking depends on your model and firmware — "
        f'<a href="{KINDLE_MODDING_URL}">kindlemodding.org</a> is where to start.</p></section>'
        "<section><h2>Phones and tablets</h2>"
        '<p class="small">On iPhone and iPad, Cantook by Aldiko and KyBook 3 can both add your own '
        "catalogues; Apple Books cannot. On Android, Moon+ Reader (<strong>Net Library → ⋮ → "
        "Add new catalog</strong>), KOReader and Librera Reader all work. In each, add a catalogue "
        "with the address above and enter your username and device password when the app asks.</p>"
        '<p class="fineprint">Moon+ Reader sometimes asks again for a password it already has; '
        "entering it again works.</p></section>"
        f"{_footer(source_url)}",
    )


# -- reading the public pages without a browser ------------------------------
#
# The pages above are also read by crawlers and by agents fetching on someone's
# behalf, and both want the text rather than the markup. Nothing here writes a second
# copy of that text: a hand-written markdown version of each page would be correct on
# the day it was written and wrong on the first edit, so the already-rendered HTML is
# converted at request time instead.
#
# The converter is deliberately partial. It handles the tags these pages actually
# use and nothing else, and MARKDOWN_HANDLED_TAGS is checked against the real pages in
# the test suite, so a page edit that introduces a new tag fails a test rather than
# quietly dropping a paragraph on the way out.

# The pages a signed-out visitor can read, which is also exactly what the sitemap lists
# and exactly what negotiates markdown. Everything else is private.
PUBLIC_PAGE_PATHS = ("/", "/devices", "/signup", "/signin", "/privacy", "/terms")

MARKDOWN_MEDIA_TYPE = "text/markdown; charset=utf-8"

# Dropped with everything inside them, and saying nothing in their place. The diagram says
# in pictures what the prose beside it already says in words, and its 60 lines of path data
# are noise to a reader that cannot see it; the walkthrough inside the <details> is that
# same diagram in motion, and its figure caption -- which is on the page for everyone --
# is the sentence it spends four steps acting out.
MARKDOWN_SILENT_TAGS = frozenset({"svg", "details"})

# A form is an input nothing on the other end of this can fill in, so it becomes a one-line
# pointer to the address it posts to instead of disappearing.
MARKDOWN_DROPPED_TAGS = MARKDOWN_SILENT_TAGS | frozenset({"form"})

# Containers are recursed into; everything else here becomes a line or part of one.
MARKDOWN_CONTAINER_TAGS = frozenset({"main", "div", "section"})
MARKDOWN_HANDLED_TAGS = MARKDOWN_CONTAINER_TAGS | frozenset(
    {"h1", "h2", "p", "ul", "ol", "li", "code", "footer", "span", "a", "strong", "em", "br", "figure", "figcaption"}
)


def _squeeze(text: str) -> str:
    return " ".join(text.split())


def _inline_edges(text: str) -> str:
    """Collapse a text node's whitespace but keep the single spaces at its edges.

    Those edge spaces are load-bearing: in `Steepd · <a>privacy</a>` they are the only
    thing separating the text from the link, and a plain strip would run the two together.
    """
    collapsed = _squeeze(text)
    if not collapsed:
        return " " if text else ""
    lead = " " if text[:1].isspace() else ""
    trail = " " if text[-1:].isspace() else ""
    return f"{lead}{collapsed}{trail}"


def _absolute(href: str, base_url: str) -> str:
    """Resolve a page-relative href against the deployment's own base URL.

    Relative links are right in a browser that arrived here and meaningless in a file an
    agent has saved, so markdown gets absolute ones. mailto: and already-absolute hrefs
    pass through untouched.
    """
    return urljoin(f"{base_url}/", href)


def _markdown_inline(node: Tag | NavigableString, base_url: str) -> str:
    if isinstance(node, NavigableString):
        return _inline_edges(str(node))
    if node.name in MARKDOWN_DROPPED_TAGS:
        return ""
    if node.name == "br":
        return "\n"
    inner = "".join(_markdown_inline(child, base_url) for child in node.children).strip()
    if not inner:
        return ""
    if node.name == "a":
        return f"[{inner}]({_absolute(str(node.get('href', '')), base_url)})"
    if node.name == "strong":
        return f"**{inner}**"
    if node.name == "em":
        return f"*{inner}*"
    if node.name == "code":
        # An address or a folder name. Backticks keep it out of the prose and stop a
        # reader -- human or otherwise -- from guessing where it ends.
        return f"`{inner}`"
    return inner


def _inline_text(node: Tag, base_url: str) -> str:
    joined = "".join(_markdown_inline(child, base_url) for child in node.children)
    # Split on the newlines <br> left behind, collapse each line, drop the empty ones.
    return "\n".join(line for line in (_squeeze(part) for part in joined.split("\n")) if line)


def _form_note(form: Tag, base_url: str) -> str:
    """A form, as the one thing about it an agent can act on: where it goes."""
    button = form.find("button")
    label = _squeeze(button.get_text()) if isinstance(button, Tag) else "Submit"
    return f"{label} — send an email address to {_absolute(str(form.get('action', '/')), base_url)}"


def _markdown_masthead(mark: Tag) -> str:
    """The wordmark, its logo and the beta chip as a single title line.

    Read out of the header rather than written down, so the chip disappearing from the
    page takes it out of the markdown too instead of leaving the two disagreeing about
    whether this is still a beta.
    """
    wordmark = mark.find("span")
    chip = mark.find("em")
    title = _squeeze(wordmark.get_text()) if isinstance(wordmark, Tag) else ""
    return f"{title} ({_squeeze(chip.get_text())})" if isinstance(chip, Tag) else title


def _markdown_blocks(node: Tag, base_url: str) -> Iterator[str]:
    for child in node.children:
        if isinstance(child, NavigableString) or child.name in MARKDOWN_SILENT_TAGS:
            # Whitespace between blocks, and the diagram. Text that belongs to a block is
            # reached through that block, never here.
            continue
        if child.name == "form":
            yield _form_note(child, base_url)
            continue
        if child.name == "figure":
            # A figure is a picture and the line that explains it. Only the line survives,
            # so the walkthrough arrives as one sentence rather than a stage direction.
            caption = child.find("figcaption")
            if isinstance(caption, Tag) and (line := _inline_text(caption, base_url)):
                yield line
            continue
        if child.name == "a" and "mark" in (child.get("class") or []):
            yield _markdown_masthead(child)
            continue
        if child.name in MARKDOWN_CONTAINER_TAGS:
            yield from _markdown_blocks(child, base_url)
            continue
        if child.name in ("ul", "ol"):
            # The whole list is one block. Yielding each item separately would put a blank
            # line between them, which is a different list in markdown, not a tidier one.
            items = [line for item in child.find_all("li", recursive=False) if (line := _inline_text(item, base_url))]
            if items:
                # Numbered on the page means numbered in the markdown: on the setup page
                # the order of the steps is the instruction, and bullets would lose it.
                marks = [f"{n}." for n in range(1, len(items) + 1)] if child.name == "ol" else ["-"] * len(items)
                yield "\n".join(f"{mark} {item}" for mark, item in zip(marks, items, strict=True))
            continue
        text = _inline_text(child, base_url)
        if not text:
            continue
        if child.name in ("h1", "h2"):
            yield f"{'#' if child.name == 'h1' else '##'} {text}"
        else:
            yield text


def page_as_markdown(document: str, base_url: str) -> str:
    """Convert one rendered page to markdown. The HTML is the source of truth."""
    soup = BeautifulSoup(document, "html.parser")
    root = soup.body or soup
    return "\n\n".join(_markdown_blocks(root, base_url)) + "\n"


def _prefers_markdown(request: Request) -> bool:
    # A substring test rather than a parsed Accept header with q-values. No browser sends
    # text/markdown at all, so the only caller this can match is one that named it on
    # purpose, and ranking it against the other media types could not change the answer.
    return "text/markdown" in request.headers.get("accept", "").casefold()


# -- crawlers ----------------------------------------------------------------

# One rule set, used by both groups below so the two policies cannot drift into saying
# different things about the same paths.
#
# /auth/ is the security-relevant line: those URLs carry single-use sign-in tokens. They
# only ever travel by email, so no crawler should ever hold one -- but a crawler that
# somehow met one must not fetch it, because fetching it consumes it and the person
# waiting on that link would find it already spent. Defence in depth, not decoration.
# The rest is privacy hygiene: a private library and a webhook endpoint have no business
# in anyone's index.
_CRAWLER_RULES = (
    "Allow: /",
    "Disallow: /account",
    "Disallow: /admin/",
    "Disallow: /auth/",
    "Disallow: /opds",
    "Disallow: /webhooks/",
)

# Named individually because several of these ignore the wildcard group, not because they
# get a different answer: the public pages exist to be understood, so AI crawlers are told
# the same thing everyone else is told.
_AI_CRAWLERS = ("GPTBot", "OAI-SearchBot", "Claude-Web", "ClaudeBot", "Google-Extended", "PerplexityBot")

ROBOTS_MEDIA_TYPE = "text/plain; charset=utf-8"
SITEMAP_MEDIA_TYPE = "application/xml"


def _robots_txt(base_url: str) -> str:
    rules = "\n".join(_CRAWLER_RULES)
    named = "\n".join(f"User-agent: {crawler}" for crawler in _AI_CRAWLERS)
    return (
        f"User-agent: *\n{rules}\n\n"
        f"{named}\n{rules}\n\n"
        "Content-Signal: search=yes, ai-input=yes\n\n"
        f"Sitemap: {base_url}/sitemap.xml\n"
    )


def _sitemap_xml(base_url: str) -> str:
    # No lastmod. Page-level modification dates are not tracked anywhere in this codebase,
    # so any date here would be invented, and a wrong lastmod is worse than none: it
    # teaches a crawler to stop coming back to a page that did change.
    entries = "".join(
        f"  <url><loc>{html.escape(base_url + path, quote=False)}</loc></url>\n" for path in PUBLIC_PAGE_PATHS
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{entries}"
        "</urlset>\n"
    )


# -- email -------------------------------------------------------------------


def _magic_email_text(link: str) -> str:
    return (
        "Use this link to sign in to Steepd:\n\n"
        f"{link}\n\n"
        f"It works once and expires in {MAGIC_TOKEN_TTL_MINUTES} minutes. "
        "If you did not ask to sign in, you can ignore this email.\n"
    )


def _magic_email_html(link: str) -> str:
    safe = html.escape(link)
    return (
        '<!DOCTYPE html><html lang="en"><body>'
        f'<p>Use this link to sign in to Steepd: <a href="{safe}">{safe}</a></p>'
        f"<p>It works once and expires in {MAGIC_TOKEN_TTL_MINUTES} minutes. "
        "If you did not ask to sign in, you can ignore this email.</p>"
        "</body></html>"
    )


# -- request helpers ---------------------------------------------------------


FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"


async def _form_fields(request: Request) -> dict[str, str]:
    """Decode a submitted form without Starlette's parser.

    `request.form()` needs python-multipart even for a urlencoded body, and nothing here
    accepts a file, so pulling in a parser for uploads to read one short text field would
    add a dependency for a capability these forms deliberately do not have. Bodies are
    bounded before they reach here by the limits app.py registers from FORM_ROUTE_LIMITS.
    """
    if request.headers.get("content-type", "").split(";")[0].strip().casefold() != FORM_CONTENT_TYPE:
        return {}
    body = await request.body()
    # Pages declare UTF-8, so that is what a browser submits; a body that is not valid
    # UTF-8 did not come from one of our forms and fails validation below either way.
    return dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))


def _submitted_email(fields: dict[str, str]) -> str:
    return fields.get("email", "").strip().casefold()


def _looks_like_email(value: str) -> bool:
    """A deliberately loose check: it exists to reject an empty or obviously malformed
    field, not to decide deliverability, which only the mail provider can."""
    if not 3 <= len(value) <= MAX_EMAIL_LENGTH or any(character.isspace() for character in value):
        return False
    local, separator, domain = value.partition("@")
    return bool(local and separator and domain and "@" not in domain)


def _is_on_inbox_domain(email: str, inbox_domain: str) -> bool:
    """An account whose own address is a Steepd inbox would have its sign-in links converted
    into articles for whoever owns that inbox, token and all."""
    return bool(inbox_domain) and email.rpartition("@")[2] == inbox_domain


def _stem_status(stem: str, database: Database) -> StemStatus:
    """Why the email's own stem is not being offered, if it is not.

    Told apart rather than lumped together because the page says it out loud, and
    "info is taken" is a different, wronger thing to tell someone than "info is
    reserved": the first implies a stranger holds it and a variant would do.
    """
    if validate_inbox_local_format(stem) is not None:
        return StemStatus.RESERVED if is_reserved_inbox_local(stem) else StemStatus.MALFORMED
    return StemStatus.FREE if database.inbox_local_available(stem) else StemStatus.TAKEN


def suggest_inbox_local(email: str, database: Database) -> tuple[str, StemStatus]:
    """The name to prefill, and what became of the plain stem of the email.

    The stem first. If someone already has it, the stem with the first letter of the
    domain after a dot, which is what a person would try next; then the stem with a
    two-digit number. Every candidate is checked against the format rules as well as
    availability, so a stem that happens to be a reserved word is skipped rather
    than offered.
    """
    stem = email_stem(email)
    status = _stem_status(stem, database)
    if status is StemStatus.FREE:
        return stem, status
    domain_initial = email.partition("@")[2][:1].casefold()
    candidates = []
    if domain_initial.isalnum():
        candidates.append(f"{stem}.{domain_initial}")
    candidates.extend(f"{stem}{n:02d}" for n in range(1, 100))
    for candidate in candidates:
        if validate_inbox_local_format(candidate) is None and database.inbox_local_available(candidate):
            return candidate, status
    # Ninety-nine numbered variants taken is not a real case; the page still needs a
    # value, and the person can type anything.
    return "", status


def build_web_router(settings: Settings, database: Database, storage: ItemStorage) -> APIRouter:
    router = APIRouter()
    verify_same_origin = same_origin_guard(settings.public_base_url)
    # Secure would make the cookie undeliverable over plain HTTP, which is what a local
    # development run uses, so it follows the deployment's own scheme rather than a flag
    # someone has to remember to set.
    cookie_is_secure = settings.public_base_url.lower().startswith("https://")
    catalogue_url = f"{settings.public_base_url}/opds"

    def _set_session_cookie(response: Response, token: str) -> None:
        response.set_cookie(
            SESSION_COOKIE,
            token,
            max_age=SESSION_MAX_AGE_SECONDS,
            path="/",
            httponly=True,
            samesite="lax",
            secure=cookie_is_secure,
        )

    def _clear_session_cookie(response: Response) -> None:
        response.delete_cookie(SESSION_COOKIE, path="/")

    def _redirect(location: str) -> RedirectResponse:
        # 303 rather than the default 307: every caller here is redirecting after a POST
        # or from a bare GET, and a 307 would replay the POST against the new location.
        return RedirectResponse(location, status_code=status.HTTP_303_SEE_OTHER)

    def optional_session(request: Request) -> BrowserSession | None:
        token = request.cookies.get(SESSION_COOKIE, "")
        if not token:
            return None
        tenant = resolve_session(database, token)
        return None if tenant is None else BrowserSession(tenant=tenant, token=token)

    def require_any_session(request: Request) -> BrowserSession:
        session = optional_session(request)
        if session is None:
            # A redirect rather than a 401: an expired or missing cookie is the ordinary
            # case for a browser, and the sign-in form is the only useful next step. The
            # JSON body FastAPI attaches to this is never seen -- a browser follows it.
            raise HTTPException(
                status_code=status.HTTP_303_SEE_OTHER,
                detail="Sign in required",
                headers={"Location": "/signin"},
            )
        return session

    def require_confirmed_session(request: Request) -> BrowserSession:
        session = require_any_session(request)
        if session.tenant.inbox_confirmed_at is None:
            # Nothing on the account is usable until the address exists: there is no inbox
            # to show and no username a reader could use. One page, then everything.
            raise HTTPException(
                status_code=status.HTTP_303_SEE_OTHER,
                detail="Choose an address first",
                headers={"Location": "/account/address"},
            )
        return session

    # Declared as route dependencies rather than parameters so they run before anything
    # the endpoint itself asks for: a cross-site POST from a signed-out browser must
    # answer 403, not redirect to the sign-in form.
    SameOrigin = Depends(verify_same_origin)
    SignedIn = Annotated[BrowserSession, Depends(require_confirmed_session)]
    # The address page itself, and sign-out, are the only things reachable before a name
    # has been chosen; everything else takes SignedIn and bounces there.
    SignedInUnconfirmedOk = Annotated[BrowserSession, Depends(require_any_session)]

    def _inbox_address(tenant: Tenant) -> str:
        return f"{tenant.inbox_local}@{settings.inbox_domain}" if settings.inbox_domain else tenant.inbox_local

    def _library_view(scope: TenantScope, *, query: str, sort: str, page: int) -> LibraryView:
        """One page of items, in the requested order, plus the counts the page links need.

        A page number past the end is clamped to the last page rather than answered with an
        empty list: it arrives from a bookmark taken when the library was larger, or from a
        deletion that shortened it, and both read better as "you are on the last page".
        """
        matching = database.count_items(scope, query=query or None)
        library = database.count_items(scope) if query else matching
        pages = max(1, math.ceil(matching / ACCOUNT_PAGE_SIZE))
        page = min(page, pages)

        # The sort names on this page are exactly db.list_items' ordering names, so the
        # database does the ordering at any library size and this function only pages.
        items = database.list_items(
            scope,
            query=query or None,
            limit=ACCOUNT_PAGE_SIZE,
            offset=(page - 1) * ACCOUNT_PAGE_SIZE,
            order=sort,
        )

        return LibraryView(
            items=items,
            matching=matching,
            library=library,
            query=query,
            sort=sort,
            page=page,
            pages=pages,
        )

    def _render_account(
        tenant: Tenant,
        *,
        query: str = "",
        sort: str = ACCOUNT_DEFAULT_SORT,
        page: int = 1,
        error: str = "",
        status_code: int = status.HTTP_200_OK,
    ) -> HTMLResponse:
        scope = TenantScope(tenant.id)
        return _account_page(
            tenant,
            _library_view(scope, query=query, sort=sort, page=page),
            senders=database.list_allowed_senders(tenant.id),
            refused=database.list_refused_senders(tenant.id),
            storage_bytes=database.tenant_storage_bytes(scope),
            inbox_address=_inbox_address(tenant),
            catalogue_url=catalogue_url,
            error=error,
            status_code=status_code,
        )

    def _create_tenant(email: str) -> Tenant | None:
        try:
            return database.create_pending_tenant(email=email)
        except sqlite3.IntegrityError:
            # A concurrent sign-up for the same address won. Nothing to retry: the caller
            # issues a token for the tenant that now exists.
            return None

    def _begin_sign_in(email: str, *, create: bool) -> Response:
        """The whole of sign-in, and all of sign-up after the account exists.

        Both entry points end here so they cannot drift apart. Every outcome except a
        mail-transport failure renders the same page.
        """
        tenant = database.tenant_by_email(email)
        if create and tenant is None:
            if _create_tenant(email) is None and database.tenant_by_email(email) is None:
                LOGGER.error("Could not create an account for a new sign-up")
                return _no_inbox_page()
        elif create:
            # Sign-up for an address that already has an account must not be faster than
            # sign-up for a new one. create_tenant pays a scrypt to hash the device
            # password it generates; without a matching cost here the response time alone
            # would answer "does this person have an account", which is the enumeration
            # the identical page above exists to prevent. The hash is discarded.
            hash_password(secrets.token_urlsafe(18))

        token = issue_magic_token(database, email)
        if token:
            link = f"{settings.public_base_url}/auth/{token}"
            try:
                send_email(
                    settings,
                    to=email,
                    subject=MAGIC_EMAIL_SUBJECT,
                    html=_magic_email_html(link),
                    text=_magic_email_text(link),
                )
            except OutboundEmailDisabled:
                return _unavailable_page()
            except OutboundEmailError as exc:
                # The class only. The address is personal data and the link is a bearer
                # credential; neither belongs in a log line.
                LOGGER.error("Magic-link send failed: %s", type(exc).__name__)
                return _send_failed_page()
        return _check_email_page(email)

    def _public(request: Request, page: HTMLResponse) -> Response:
        """Serve one of the public pages, as HTML or as markdown.

        Vary goes on both variants, not just the markdown one: without it a cache in front
        of this would happily hand a browser the markdown it had stored for an agent.
        """
        if not _prefers_markdown(request):
            page.headers["Vary"] = "Accept"
            return page
        return Response(
            page_as_markdown(page.body.decode("utf-8"), settings.public_base_url),
            media_type=MARKDOWN_MEDIA_TYPE,
            headers={"Cache-Control": page.headers["cache-control"], "Vary": "Accept"},
        )

    # -- routes --------------------------------------------------------------

    @router.get("/", include_in_schema=False)
    def index(request: Request) -> Response:
        # Signed in, / is a shortcut to the library; signed out, it is the only page that
        # explains what this is, so it renders rather than bouncing to a bare sign-in form.
        session = optional_session(request)
        if session is not None:
            # Straight to the address page while there is no address, rather than to
            # /account only to be sent back here by the session dependency.
            return _redirect("/account" if session.tenant.inbox_confirmed_at else "/account/address")
        return _public(
            request,
            _landing_page(
                source_url=settings.source_repository_url,
                inbox_domain=settings.inbox_domain,
            ),
        )

    @router.get("/privacy", include_in_schema=False)
    def privacy(request: Request) -> Response:
        return _public(
            request,
            _privacy_page(
                contact=settings.support_contact,
                source_url=settings.source_repository_url,
            ),
        )

    @router.get("/terms", include_in_schema=False)
    def terms(request: Request) -> Response:
        return _public(request, _terms_page(source_url=settings.source_repository_url))

    @router.get("/devices", include_in_schema=False)
    def devices(request: Request) -> Response:
        # Public on purpose, and the same page whether you have an account or not: the
        # address it shows is this deployment's, not anybody's, and someone deciding
        # whether their reader can do this needs to read it before they sign up.
        return _public(
            request,
            _devices_page(catalogue_url=catalogue_url, source_url=settings.source_repository_url),
        )

    @router.get("/signup")
    def signup_form(request: Request) -> Response:
        return _public(request, _signup_page())

    @router.get("/signin")
    def signin_form(request: Request) -> Response:
        return _public(request, _signin_page())

    @router.get("/robots.txt", include_in_schema=False)
    def robots() -> Response:
        return Response(_robots_txt(settings.public_base_url), media_type=ROBOTS_MEDIA_TYPE)

    @router.get("/sitemap.xml", include_in_schema=False)
    def sitemap() -> Response:
        return Response(_sitemap_xml(settings.public_base_url), media_type=SITEMAP_MEDIA_TYPE)

    @router.post("/signup", dependencies=[SameOrigin])
    async def signup(request: Request) -> Response:
        email = _submitted_email(await _form_fields(request))
        if not _looks_like_email(email):
            return _signup_page(
                email=email,
                error="Enter an email address in the form you@example.com.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        if _is_on_inbox_domain(email, settings.inbox_domain):
            return _signup_page(
                email=email,
                error="Sign up with your own email address. Steepd inbox addresses are for sending things in.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        return await run_in_threadpool(_begin_sign_in, email, create=True)

    @router.post("/signin", dependencies=[SameOrigin])
    async def signin(request: Request) -> Response:
        email = _submitted_email(await _form_fields(request))
        if not _looks_like_email(email):
            return _signin_page(
                email=email,
                error="Enter an email address in the form you@example.com.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        return await run_in_threadpool(_begin_sign_in, email, create=False)

    @router.get("/auth/{token}")
    def sign_in_page(token: str) -> Response:
        # Deliberately touches nothing: not the database, not the token. A prefetcher or
        # a scanner following the link from the email gets a page, and the token is still
        # there for the person when they arrive.
        return _redeem_page(token)

    @router.post("/auth/{token}", dependencies=[SameOrigin])
    def redeem_magic_link(token: str) -> Response:
        tenant = consume_magic_token(database, token)
        if tenant is None:
            return _expired_link_page()
        response = _redirect("/account")
        _set_session_cookie(response, issue_session(database, tenant.id))
        return response

    @router.get("/account/address")
    def address_form(session: SignedInUnconfirmedOk) -> Response:
        if session.tenant.inbox_confirmed_at is not None:
            return _redirect("/account")
        suggestion, stem_status = suggest_inbox_local(session.tenant.email, database)
        return _address_page(
            name=suggestion,
            stem=email_stem(session.tenant.email),
            stem_status=stem_status,
            inbox_domain=settings.inbox_domain,
        )

    @router.post("/account/address", dependencies=[SameOrigin])
    async def choose_address(request: Request, session: SignedInUnconfirmedOk) -> Response:
        if session.tenant.inbox_confirmed_at is not None:
            return _address_already_chosen_page()
        name = normalize_inbox_local((await _form_fields(request)).get("name", ""))
        stem = email_stem(session.tenant.email)

        def attempt() -> str:
            reason = validate_inbox_local_format(name)
            if reason is not None:
                return reason
            if not database.inbox_local_available(name):
                return f"{name} is taken. Try another."
            try:
                confirmed = database.confirm_inbox_local(session.tenant.id, name)
            except sqlite3.IntegrityError:
                return f"{name} is taken. Try another."
            return "" if confirmed else "already"

        outcome = await run_in_threadpool(attempt)
        if outcome == "already":
            return _redirect("/account")
        if outcome:
            return _address_page(
                name=name,
                stem=stem,
                stem_status=StemStatus.FREE,
                inbox_domain=settings.inbox_domain,
                error=outcome,
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        return _redirect("/account")

    @router.get("/account")
    def account(session: SignedIn, q: str = "", sort: str = "", page: str = "") -> Response:
        # Taken as strings and validated by hand rather than declared as typed query
        # parameters: FastAPI would answer `page=nonsense` with a 422 JSON body, and a
        # browser following a stale link deserves the library instead.
        return _render_account(
            session.tenant,
            query=_clean_query(q),
            sort=_clean_sort(sort),
            page=_clean_page(page),
        )

    @router.post("/account/rotate", dependencies=[SameOrigin])
    async def rotate_password(session: SignedIn) -> Response:
        password = await run_in_threadpool(database.rotate_device_password, session.tenant.id)
        if password is None:
            # The tenant went away between resolving the session and the update.
            return _redirect("/signin")
        return _password_page(password)

    @router.post("/account/senders/policy", dependencies=[SameOrigin])
    async def set_policy(request: Request, session: SignedIn) -> Response:
        policy = (await _form_fields(request)).get("policy", "")
        if policy not in ("anyone", "listed"):
            return await run_in_threadpool(
                _render_account,
                session.tenant,
                error="Choose one of the two options.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        await run_in_threadpool(database.set_sender_policy, session.tenant.id, policy)
        return _redirect("/account")

    @router.post("/account/senders/add", dependencies=[SameOrigin])
    async def add_sender(request: Request, session: SignedIn) -> Response:
        address = (await _form_fields(request)).get("address", "").strip().casefold()
        if not _looks_like_email(address):
            return await run_in_threadpool(
                _render_account,
                session.tenant,
                error="Enter an email address in the form you@example.com.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        if address == session.tenant.email.casefold():
            # The account's own address is already allowed by the row at the top of the
            # list. Storing it as well would put a Remove button under a rule that removing
            # it cannot lift.
            return await run_in_threadpool(
                _render_account,
                session.tenant,
                error="Your own address is always allowed.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        def add() -> str:
            try:
                database.add_allowed_sender(session.tenant.id, address)
            except AllowedSenderCapReached:
                return "You can list up to 50 senders. Remove one to add another."
            database.clear_refused_sender(session.tenant.id, address)
            return ""

        error = await run_in_threadpool(add)
        if error:
            return await run_in_threadpool(
                _render_account, session.tenant, error=error, status_code=status.HTTP_400_BAD_REQUEST
            )
        return _redirect("/account")

    @router.post("/account/senders/remove", dependencies=[SameOrigin])
    async def remove_sender(request: Request, session: SignedIn) -> Response:
        # An address that was never listed is the same outcome from where the user is
        # standing, so the return value is ignored just as it is for a deleted item.
        address = (await _form_fields(request)).get("address", "").strip().casefold()
        await run_in_threadpool(database.remove_allowed_sender, session.tenant.id, address)
        return _redirect("/account")

    @router.post("/account/items/{item_id}/delete", dependencies=[SameOrigin])
    async def delete_item(item_id: str, session: SignedIn) -> Response:
        # The return value is deliberately ignored: an unknown or already-deleted id is
        # the same outcome from where the user is standing, and reporting it would make
        # this route say whether an id exists.
        await run_in_threadpool(storage.delete, TenantScope(session.tenant.id), item_id)
        return _redirect("/account")

    @router.post("/signout", dependencies=[SameOrigin])
    async def signout(session: SignedInUnconfirmedOk) -> Response:
        await run_in_threadpool(revoke_session, database, session.token)
        response = _redirect("/signin")
        _clear_session_cookie(response)
        return response

    @router.post("/account/delete", dependencies=[SameOrigin])
    async def delete_account(request: Request, session: SignedIn) -> Response:
        fields = await _form_fields(request)
        if not fields.get(DELETE_CONFIRMATION_FIELD):
            return await run_in_threadpool(
                _render_account,
                session.tenant,
                error="Tick the confirmation box to delete your account.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        def purge() -> None:
            # Files first, then the row: delete_tenant cascades the items away, and rows
            # deleted before their files leave a file nothing points at. It also cascades
            # every session, which is stronger than revoking this one -- deleting an
            # account has to sign out the other browsers too.
            scope = TenantScope(session.tenant.id)
            storage.delete_all_for_tenant(scope)
            database.delete_tenant(session.tenant.id)

        await run_in_threadpool(purge)
        response = _goodbye_page()
        _clear_session_cookie(response)
        return response

    return router
