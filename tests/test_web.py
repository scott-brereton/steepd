"""Tests for the browser layer: sign-up, sign-in, and the account page.

Outbound email is captured rather than sent, so the sign-in link these tests follow is
the one a real recipient would receive. Several tests deliberately extract the link from
the captured message instead of building the URL, because a link that does not match the
route it is meant to reach is exactly the failure a constructed URL would hide.
"""

from __future__ import annotations

import base64
import html
import re
import xml.etree.ElementTree as ElementTree
from datetime import UTC, datetime, timedelta

import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from steepd.app import create_app
from steepd.auth import issue_magic_token
from steepd.config import Settings
from steepd.epubgen import build_epub
from steepd.models import Item
from steepd.plans import FREE_QUOTA_BYTES, FREE_RETENTION, PAID_PLAN, PAID_QUOTA_BYTES
from steepd.tenancy import TenantScope
from steepd.web import (
    MARKDOWN_DROPPED_TAGS,
    MARKDOWN_HANDLED_TAGS,
    PUBLIC_PAGE_PATHS,
    SESSION_COOKIE,
    _human_size,
)

BASE_URL = "http://localhost:8000"
INBOX_DOMAIN = "read.example.test"
EMAIL = "reader@example.test"


def _build_client(tmp_path, monkeypatch, *, base_url=BASE_URL, capture=True, **overrides):
    settings = Settings(
        data_dir=tmp_path, public_base_url=base_url, inbox_domain=INBOX_DOMAIN, **overrides
    )
    app = create_app(settings)
    sent: list[dict] = []
    if capture:
        monkeypatch.setattr("steepd.web.send_email", lambda settings, **message: sent.append(message))
    return TestClient(app, base_url=base_url), sent


@pytest.fixture
def web(tmp_path, monkeypatch):
    """A client whose outbound mail lands in a list, and the app's database beside it."""
    client, sent = _build_client(tmp_path, monkeypatch)
    return client, sent


def _magic_link(message: dict) -> str:
    match = re.search(r"http\S*/auth/\S+", message["text"])
    assert match, f"no sign-in link in the sent message: {message['text']!r}"
    return match.group(0)


def _device_password(body: str) -> str:
    match = re.search(r'class="secret">([^<]+)<', body)
    assert match, "the rotate page did not show a password"
    return match.group(1)


def _redeem(client, link: str, **kwargs):
    """Press the button on the page the emailed link opens."""
    return client.post(link, **kwargs)


def _sign_up(client, sent, email=EMAIL, name: str | None = None) -> str:
    """Complete a full sign-up, including the first-sign-in address page, and return the
    address the client is now signed in as."""
    assert client.post("/signup", data={"email": email}).status_code == 200
    assert _redeem(client, _magic_link(sent[-1]), follow_redirects=False).status_code == 303
    page = client.get("/account/address")
    assert page.status_code == 200
    chosen = name if name is not None else _prefilled_name(page.text)
    done = client.post("/account/address", data={"name": chosen}, follow_redirects=False)
    assert done.status_code == 303 and done.headers["location"] == "/account", done.text
    return email


def _prefilled_name(body: str) -> str:
    match = re.search(r'name="name"[^>]*value="([^"]*)"', body)
    assert match, "the address page did not prefill a name"
    return match.group(1)


# -- the journey -------------------------------------------------------------


def test_signing_up_ends_at_a_library_the_reader_can_reach(web):
    """The one test that proves the web layer and the device layer share an account.

    Sign-up mails a link, the link opens a session, and the password generated from the
    account page authenticates against OPDS. If the two layers ever drift onto separate
    credentials this is where it shows, before a user discovers it with an e-reader.
    """
    client, sent = web
    database = client.app.state.database

    response = client.post("/signup", data={"email": "Reader@Example.test"})
    assert response.status_code == 200
    assert "Check your email" in response.text

    tenant = database.tenant_by_email(EMAIL)
    assert tenant is not None, "sign-up did not create an account"
    assert sent[-1]["to"] == EMAIL
    assert sent[-1]["subject"] == "Sign in to Steepd"

    redeemed = _redeem(client, _magic_link(sent[-1]), follow_redirects=False)
    assert redeemed.status_code == 303
    assert redeemed.headers["location"] == "/account"
    assert SESSION_COOKIE in redeemed.headers["set-cookie"]

    address = client.get("/account/address")
    assert address.status_code == 200
    chosen = client.post(
        "/account/address", data={"name": _prefilled_name(address.text)}, follow_redirects=False
    )
    assert chosen.status_code == 303 and chosen.headers["location"] == "/account"
    # Re-read: the placeholder the sign-up created is only now the real address.
    tenant = database.tenant_by_email(EMAIL)

    account = client.get("/account")
    assert account.status_code == 200
    assert f"{tenant.inbox_local}@{INBOX_DOMAIN}" in account.text
    assert f"{BASE_URL}/opds" in account.text

    rotated = client.post("/account/rotate")
    assert rotated.status_code == 200
    password = _device_password(rotated.text)

    credentials = base64.b64encode(f"{tenant.opds_username}:{password}".encode()).decode()
    assert client.get("/opds", headers={"Authorization": f"Basic {credentials}"}).status_code == 200

    signed_out = client.post("/signout", follow_redirects=False)
    assert signed_out.status_code == 303
    assert signed_out.headers["location"] == "/signin"
    assert client.get("/account", follow_redirects=False).headers["location"] == "/signin"


def test_the_root_path_sends_you_where_your_session_says(web):
    """Signed out, / is the page that explains the product; signed in, it is the library.

    The signed-in redirect is the load-bearing half: someone with a session who opens the
    bookmark wants their items, not the pitch for a service they already use.
    """
    client, sent = web
    signed_out = client.get("/", follow_redirects=False)
    assert signed_out.status_code == 200
    assert "Email it. Read it on your e" in signed_out.text

    _sign_up(client, sent)
    assert client.get("/", follow_redirects=False).headers["location"] == "/account"


# -- account existence must not leak -----------------------------------------


def test_signing_up_with_a_known_address_is_indistinguishable_from_signing_in(web):
    """Sign-up must not answer "does this person have an account".

    A distinct "that email is taken" response turns the public sign-up form into an
    account-existence oracle, and an inbox address is enough on its own to put content
    into someone's library. The two bodies are compared byte for byte because any
    difference at all -- a word, a heading, a hidden field -- is the leak.
    """
    client, sent = web
    _sign_up(client, sent)

    from_signup = client.post("/signup", data={"email": EMAIL})
    from_signin = client.post("/signin", data={"email": EMAIL})

    assert from_signup.status_code == from_signin.status_code == 200
    assert from_signup.content == from_signin.content


def test_signing_in_with_an_unknown_address_says_the_same_thing_and_sends_nothing(web):
    """The unknown-address branch must reach the same page without mailing a stranger."""
    client, sent = web
    known = client.post("/signin", data={"email": "stranger@example.test"})
    assert known.status_code == 200
    assert "Check your email" in known.text
    assert sent == []


def test_a_malformed_address_is_answered_by_the_form_again(web):
    """An empty or malformed field should re-open the form, not create anything."""
    client, sent = web
    response = client.post("/signup", data={"email": "not-an-address"})
    assert response.status_code == 400
    assert "you@example.com" in response.text
    assert sent == []
    assert client.app.state.database.tenant_by_email("not-an-address") is None


# -- magic links -------------------------------------------------------------


def test_a_sign_in_link_works_only_once(web):
    """A link that stays valid is a reusable credential sitting in an inbox forever."""
    client, sent = web
    client.post("/signup", data={"email": EMAIL})
    link = _magic_link(sent[-1])

    assert _redeem(client, link).status_code == 200
    client.cookies.clear()

    second = _redeem(client, link)
    assert second.status_code == 200
    assert "expired" in second.text
    assert client.get("/account", follow_redirects=False).headers["location"] == "/signin"


def test_opening_the_link_spends_nothing_until_the_button_is_pressed(web):
    """Mail scanners and preview fetchers follow links. A GET that redeemed the token left
    the person who then clicked it looking at an expired-link page; the GET is now a page
    with a button, and only the button consumes the token. The GET also reads nothing, so
    a junk token gets the same page as a real one."""
    client, sent = web
    client.post("/signup", data={"email": EMAIL})
    link = _magic_link(sent[-1])

    for _ in range(3):
        opened = client.get(link)
        assert opened.status_code == 200
        assert "Sign in to Steepd" in opened.text
        assert SESSION_COOKIE not in opened.headers.get("set-cookie", "")
    assert "Sign in to Steepd" in client.get("/auth/junk").text

    assert _redeem(client, link, follow_redirects=False).headers["location"] == "/account"


def test_a_cross_site_press_of_the_sign_in_button_is_refused(web):
    client, sent = web
    client.post("/signup", data={"email": EMAIL})
    link = _magic_link(sent[-1])

    refused = client.post(link, headers={"Origin": "https://evil.example"})

    assert refused.status_code == 403
    # Refused, not spent: the person can still press the real button afterwards.
    assert _redeem(client, link, follow_redirects=False).status_code == 303


def test_an_inbox_address_is_the_wrong_kind_of_address_to_sign_up_with(web):
    """A sign-in link sent to a Steepd inbox is converted into an article for whoever owns
    that inbox, token included."""
    client, sent = web
    response = client.post("/signup", data={"email": f"ada.1@{INBOX_DOMAIN}"})
    assert response.status_code == 400
    assert "your own email address" in response.text
    assert sent == []
    assert client.app.state.database.tenant_by_email(f"ada.1@{INBOX_DOMAIN}") is None


def test_the_inbox_address_is_exactly_the_chosen_name_with_nothing_appended(web):
    """The address used to carry random hex after the stem. It is now whatever was
    confirmed on the address page and nothing else, because that is what a person is
    told to type into their reader."""
    client, sent = web
    _sign_up(client, sent)
    tenant = client.app.state.database.tenant_by_email(EMAIL)
    assert tenant.inbox_local == "reader", tenant.inbox_local


def test_an_expired_sign_in_link_is_refused(web):
    """Issued far enough in the past that it is already past its expiry when redeemed."""
    client, sent = web
    _sign_up(client, sent)
    client.cookies.clear()

    stale = issue_magic_token(
        client.app.state.database, EMAIL, now=datetime.now(UTC) - timedelta(minutes=90)
    )
    response = _redeem(client, f"/auth/{stale}")
    assert response.status_code == 200
    assert "expired" in response.text
    assert client.get("/account", follow_redirects=False).headers["location"] == "/signin"


def test_a_junk_token_is_refused_rather_than_erroring(web):
    """A hand-typed or truncated link should reach the same page as an expired one."""
    client, _ = web
    response = _redeem(client, "/auth/not-a-real-token")
    assert response.status_code == 200
    assert "expired" in response.text


# -- sessions ----------------------------------------------------------------


def test_the_account_page_refuses_a_missing_or_forged_cookie(web):
    """A cookie that does not resolve must be treated as no cookie at all."""
    client, _ = web
    assert client.get("/account", follow_redirects=False).headers["location"] == "/signin"

    client.cookies.set(SESSION_COOKIE, "forged-value", domain="localhost")
    assert client.get("/account", follow_redirects=False).headers["location"] == "/signin"


def test_the_session_cookie_is_not_reachable_from_script(web):
    """Without HttpOnly and SameSite the session token is one XSS or one cross-site form
    away from being usable by someone else."""
    client, sent = web
    client.post("/signup", data={"email": EMAIL})
    cookie = _redeem(client, _magic_link(sent[-1]), follow_redirects=False).headers["set-cookie"]

    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie.replace("samesite", "SameSite")
    assert "Path=/" in cookie
    # Plain HTTP here, so Secure would make the cookie undeliverable to a local run.
    assert "Secure" not in cookie


def test_the_session_cookie_is_secure_when_the_deployment_is_https(tmp_path, monkeypatch):
    """A session cookie without Secure on an HTTPS deployment can still be stripped onto a
    plain-HTTP request and read off the wire."""
    client, sent = _build_client(tmp_path, monkeypatch, base_url="https://steepd.example.test")
    client.post("/signup", data={"email": EMAIL})
    cookie = _redeem(client, _magic_link(sent[-1]), follow_redirects=False).headers["set-cookie"]
    assert "Secure" in cookie


# -- cross-site requests -----------------------------------------------------


def test_a_cross_site_sign_in_post_is_rejected(web):
    """Another site must not be able to make a visitor's browser request sign-in links."""
    client, sent = web
    response = client.post(
        "/signin", data={"email": EMAIL}, headers={"Origin": "https://evil.example"}
    )
    assert response.status_code == 403
    assert sent == []


def test_a_cross_site_rotate_post_is_rejected(web):
    """The real CSRF shape: the victim is signed in, so the cookie rides along. Without the
    guard, another site could silently replace the device password and break their reader."""
    client, sent = web
    _sign_up(client, sent)
    response = client.post("/account/rotate", headers={"Origin": "https://evil.example"})
    assert response.status_code == 403


@pytest.mark.parametrize(
    "path",
    [
        "/signup",
        "/signin",
        "/signout",
        "/account/address",
        "/account/rotate",
        "/account/delete",
        "/account/items/x/delete",
        "/account/senders/policy",
        "/account/senders/add",
        "/account/senders/remove",
    ],
)
def test_every_post_route_rejects_a_cross_site_origin(web, path):
    """Each POST carries the same-origin guard as its own route dependency, so any one of
    them can lose it independently in a refactor. Mutation testing found exactly that: the
    guard dropped from /signout alone left the suite green, because only two routes were
    pinned. A forced sign-out is the mildest outcome on this list, but the property being
    tested is uniform, so the test is too."""
    client, _ = web
    response = client.post(path, headers={"Origin": "https://evil.example"}, follow_redirects=False)
    assert response.status_code == 403


def test_a_cross_site_post_is_rejected_before_the_session_is_considered(web):
    """Ordering matters: if the session check ran first, a signed-out victim would be
    redirected to sign in and the cross-site attempt would look like an ordinary visit."""
    client, _ = web
    response = client.post(
        "/account/delete",
        data={"confirm": "yes"},
        headers={"Origin": "https://evil.example"},
        follow_redirects=False,
    )
    assert response.status_code == 403


# -- account plan and storage -------------------------------------------------


def _store_item(client, tenant, title="A stored book"):
    return client.app.state.storage.store_bytes(
        TenantScope(tenant.id),
        build_epub(
            title=title, author="An author", language="en", identifier=f"urn:uuid:{title}", body_html=f"<p>{title}</p>"
        ),
        filename=f"{title}.epub",
        kind="book",
        source="email",
        title=title,
    ).item


def _insert_sized_item(client, tenant, *, size_bytes):
    item = Item(
        id=f"sized-item-{size_bytes}",
        tenant_id=tenant.id,
        kind="book",
        sha256=f"sized-item-{size_bytes}",
        storage_name=f"sized-item-{size_bytes}.epub",
        download_filename="sized-item.epub",
        title="A sized book",
        author="An author",
        language="en",
        identifier=f"urn:uuid:sized-item-{size_bytes}",
        source_url="",
        size_bytes=size_bytes,
        created_at=datetime.now(UTC).isoformat(),
        expires_at=None,
        source="test",
    )
    client.app.state.database.insert_item(TenantScope(tenant.id), item)
    return item


def test_a_free_account_shows_its_plan_usage_retention_and_item_removal(web):
    client, sent = web
    _sign_up(client, sent)
    database = client.app.state.database
    tenant = database.tenant_by_email(EMAIL)
    item = _store_item(client, tenant)

    body = client.get("/account").text

    assert '<span class="title">Free</span>' in body
    assert "100 MB" in body
    assert f"{_human_size(item.size_bytes)} of 100 MB used" in body
    assert f"Items are kept for {FREE_RETENTION.days} days." in body
    assert f"removed in {FREE_RETENTION.days} days" in body


def test_a_paid_account_shows_its_larger_quota_without_retention_notes(web):
    client, sent = web
    _sign_up(client, sent)
    database = client.app.state.database
    tenant = database.tenant_by_email(EMAIL)
    _store_item(client, tenant)
    assert database.set_tenant_plan(tenant.id, PAID_PLAN)

    body = client.get("/account").text

    assert '<span class="title">Paid</span>' in body
    assert "5 GB" in body
    assert "Items are kept for" not in body
    assert "removed in" not in body


def test_the_usage_meter_width_reflects_actual_storage(web):
    client, sent = web
    _sign_up(client, sent)
    tenant = client.app.state.database.tenant_by_email(EMAIL)
    _insert_sized_item(client, tenant, size_bytes=FREE_QUOTA_BYTES // 4)

    body = client.get("/account").text
    fill = re.search(r'class="usage-meter-fill"[^>]*style="[^"]*width:\s*([\d.]+)%', body)

    assert fill, "the account page did not render a usage-meter fill width"
    assert float(fill.group(1)) == pytest.approx(25.0)


def test_the_account_warns_near_the_storage_limit_but_not_at_low_usage(web):
    client, sent = web
    _sign_up(client, sent)
    tenant = client.app.state.database.tenant_by_email(EMAIL)
    warning = "New deliveries are refused once the storage limit is reached."

    assert warning not in client.get("/account").text

    _insert_sized_item(client, tenant, size_bytes=FREE_QUOTA_BYTES * 86 // 100)

    assert warning in client.get("/account").text


# -- deletion ----------------------------------------------------------------


def test_deleting_an_item_removes_the_row_and_the_file(web):
    """A delete that drops the row but leaves the file keeps paid-for storage occupied by
    something the owner believes is gone."""
    client, sent = web
    _sign_up(client, sent)
    database = client.app.state.database
    tenant = database.tenant_by_email(EMAIL)
    item = _store_item(client, tenant)
    path = client.app.state.storage.path_for(item)
    assert path.is_file()

    account = client.get("/account")
    assert "A stored book" in account.text

    response = client.post(f"/account/items/{item.id}/delete", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/account"
    assert database.get_item(TenantScope(tenant.id), item.id) is None
    assert not path.exists()
    assert "A stored book" not in client.get("/account").text


def test_an_item_title_cannot_carry_markup_onto_the_account_page(web):
    """Titles arrive from the metadata of an emailed EPUB, so they are attacker-influenced,
    and the account page is the first place one is rendered as HTML. Unescaped, a forwarded
    book would run script against the session that lists it."""
    client, sent = web
    _sign_up(client, sent)
    tenant = client.app.state.database.tenant_by_email(EMAIL)
    _store_item(client, tenant, title="<script>alert(1)</script>")

    body = client.get("/account").text
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body


def test_deleting_an_unknown_item_still_returns_to_the_account_page(web):
    """Deleting is idempotent from where the user is standing, and an error here would
    also report whether an id exists."""
    client, sent = web
    _sign_up(client, sent)
    response = client.post("/account/items/does-not-exist/delete", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/account"


def test_deleting_the_account_removes_the_tenant_its_files_and_its_sessions(web):
    """Everything must go together. A surviving session row would keep a deleted account
    signed in, and a surviving file is data the owner asked us to destroy."""
    client, sent = web
    _sign_up(client, sent)
    database = client.app.state.database
    tenant = database.tenant_by_email(EMAIL)
    item = _store_item(client, tenant)
    path = client.app.state.storage.path_for(item)

    response = client.post("/account/delete", data={"confirm": "yes"})
    assert response.status_code == 200
    assert "Your account is gone" in response.text
    # The address outlives the account by design; saying it was deleted would be a lie.
    assert "your inbox address is held back so nobody else can ever be sent your mail" in response.text
    assert "inbox address have been deleted" not in response.text

    assert database.tenant_by_email(EMAIL) is None
    assert database.get_item(TenantScope(tenant.id), item.id) is None
    assert not path.exists()
    assert client.get("/account", follow_redirects=False).headers["location"] == "/signin"


def test_deleting_the_account_needs_the_confirmation_ticked(web):
    """The one irreversible action on the page must not happen on a stray submit."""
    client, sent = web
    _sign_up(client, sent)
    response = client.post("/account/delete", data={})
    assert response.status_code == 400
    assert client.app.state.database.tenant_by_email(EMAIL) is not None


# -- searching, sorting and paging the library --------------------------------
#
# Every test below follows the hrefs the page actually emitted rather than building a URL
# by hand, for the reason the module docstring gives: a constructed URL would keep passing
# after the page started emitting a link that goes somewhere else.


def _insert_items(client, tenant, titles):
    """Insert one item per title, oldest first, a minute apart.

    Timestamps are explicit rather than "whatever now() returned inside the loop", because
    every ordering assertion here depends on knowing which item is the oldest, and thirty
    inserts can land inside the same tick.
    """
    database = client.app.state.database
    base = datetime(2026, 1, 1, tzinfo=UTC)
    items = []
    for index, title in enumerate(titles):
        item = Item(
            id=f"library-item-{index:03d}",
            tenant_id=tenant.id,
            kind="book",
            sha256=f"library-sha-{index:03d}",
            storage_name=f"library-item-{index:03d}.epub",
            download_filename="library-item.epub",
            title=title,
            author="An author",
            language="en",
            identifier=f"urn:uuid:library-item-{index:03d}",
            source_url="",
            size_bytes=1024,
            created_at=(base + timedelta(minutes=index)).isoformat(),
            expires_at=None,
            source="test",
        )
        database.insert_item(TenantScope(tenant.id), item)
        items.append(item)
    return items


def _listed_titles(body):
    """The item titles on the page, in the order they were rendered.

    Scoped to the items list on purpose: the plan card renders a `title` span too, and a
    match against the whole document would fold "Free" into every ordering assertion.
    """
    listing = re.search(r'<ul class="items">(.*?)</ul>', body, re.S)
    if listing is None:
        return []
    return [html.unescape(found) for found in re.findall(r'<span class="title">([^<]*)</span>', listing.group(1))]


def _followable(body, label):
    match = re.search(rf'<a href="([^"]+)">{label}</a>', body)
    assert match, f"the page emitted no {label!r} link: {body}"
    return html.unescape(match.group(1))


def _signed_in_tenant(client, sent):
    _sign_up(client, sent)
    return client.app.state.database.tenant_by_email(EMAIL)


def test_a_long_library_pages_and_the_next_link_reaches_the_remainder(web):
    """Thirty items must arrive as 25 then 5, not as 24 then 6 or as one page of 30.

    The counts are asserted exactly and written as literals rather than as the page-size
    constant, so a page size that drifts by one is a failure here rather than a value the
    test quietly agrees with.
    """
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _insert_items(client, tenant, [f"Book {index:02d}" for index in range(30)])

    first = client.get("/account")
    assert first.status_code == 200
    first_titles = _listed_titles(first.text)
    assert len(first_titles) == 25
    assert "Page 1 of 2" in first.text

    second = client.get(_followable(first.text, "Next"))
    assert second.status_code == 200
    second_titles = _listed_titles(second.text)
    assert len(second_titles) == 5
    assert "Page 2 of 2" in second.text

    assert not set(first_titles) & set(second_titles)
    assert set(first_titles) | set(second_titles) == {f"Book {index:02d}" for index in range(30)}
    # The retention notes are derived per item, so they have to survive onto page 2 too.
    assert "removed in" in second.text

    back = client.get(_followable(second.text, "Previous"))
    assert _listed_titles(back.text) == first_titles


def test_the_newest_items_come_first_and_the_last_page_holds_the_oldest(web):
    """Default order is newest first, and it spans the library rather than the page."""
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _insert_items(client, tenant, [f"Book {index:02d}" for index in range(30)])

    first = client.get("/account")
    assert _listed_titles(first.text)[0] == "Book 29"
    second = client.get(_followable(first.text, "Next"))
    assert _listed_titles(second.text)[-1] == "Book 00"


def test_searching_narrows_the_library_and_reports_the_count(web):
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _insert_items(client, tenant, ["Tea one", "Coffee one", "Tea two", "Coffee two", "Tea three"])

    response = client.get("/account", params={"q": "Tea"})
    assert response.status_code == 200
    assert _listed_titles(response.text) == ["Tea three", "Tea two", "Tea one"]
    assert "3 items match" in response.text

    cleared = client.get(_followable(response.text, "Clear"))
    assert len(_listed_titles(cleared.text)) == 5


def test_a_search_of_one_item_is_worded_as_one(web):
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _insert_items(client, tenant, ["Tea one", "Coffee one"])

    body = client.get("/account", params={"q": "Coffee"}).text
    assert "1 item matches" in body
    assert "1 items match" not in body


def test_a_search_paginates_and_its_next_link_carries_the_query(web):
    """The parameters have to compose: page 2 of a search is still that search.

    A next link that dropped q would hand back page 2 of the whole library, which looks
    plausible and is wrong -- hence following the emitted link and re-checking the titles.
    """
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _insert_items(
        client,
        tenant,
        [f"Steeping {index:02d}" for index in range(30)] + ["Coffee one", "Coffee two"],
    )

    first = client.get("/account", params={"q": "Steeping"})
    assert "30 items match" in first.text
    first_titles = _listed_titles(first.text)
    assert len(first_titles) == 25

    next_href = _followable(first.text, "Next")
    assert "q=Steeping" in next_href

    second = client.get(next_href)
    second_titles = _listed_titles(second.text)
    assert len(second_titles) == 5
    assert all(title.startswith("Steeping") for title in first_titles + second_titles)
    assert set(first_titles) | set(second_titles) == {f"Steeping {index:02d}" for index in range(30)}


def test_sorting_by_title_orders_the_whole_library_not_one_page(web):
    """The assertion that catches a page-local sort.

    "Aardvark" is the oldest item, so by date it sits at the bottom of page 2. Sorting only
    the items already fetched for a page would leave it there and merely reorder its
    neighbours; sorting the library puts it first on page 1.
    """
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _insert_items(client, tenant, ["Aardvark"] + [f"Book {index:02d}" for index in range(1, 30)])

    by_date = client.get("/account")
    assert "Aardvark" not in _listed_titles(by_date.text)

    first = client.get(_followable(by_date.text, "Title"))
    assert first.status_code == 200
    first_titles = _listed_titles(first.text)
    assert first_titles[0] == "Aardvark"
    assert len(first_titles) == 25
    assert first_titles == sorted(first_titles, key=str.casefold)

    next_href = _followable(first.text, "Next")
    assert "sort=title" in next_href
    second_titles = _listed_titles(client.get(next_href).text)
    assert second_titles == [f"Book {index:02d}" for index in range(25, 30)]


def test_sorting_by_oldest_reverses_the_default_order_across_every_page(web):
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _insert_items(client, tenant, [f"Book {index:02d}" for index in range(30)])

    newest = client.get("/account")
    newest_titles = _listed_titles(newest.text) + _listed_titles(client.get(_followable(newest.text, "Next")).text)

    oldest = client.get(_followable(newest.text, "Oldest"))
    assert oldest.status_code == 200
    oldest_titles = _listed_titles(oldest.text) + _listed_titles(client.get(_followable(oldest.text, "Next")).text)

    assert oldest_titles == list(reversed(newest_titles))
    assert len(_listed_titles(oldest.text)) == 25


def test_a_search_that_matches_nothing_says_so_without_erroring(web):
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _insert_items(client, tenant, ["Tea one", "Tea two"])

    response = client.get("/account", params={"q": "cocoa"})
    assert response.status_code == 200
    assert "0 items match" in response.text
    assert "Nothing in your library matches that search." in response.text
    assert _listed_titles(response.text) == []


def test_an_empty_library_still_says_how_to_start(web):
    """No items means nothing to search, so the form stays away and the invitation stays."""
    client, sent = web
    _signed_in_tenant(client, sent)

    body = client.get("/account").text
    assert "Nothing here yet." in body
    assert 'name="q"' not in body


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"q": "x" * 161}, "Page 1 of 2"),
        ({"sort": "garbage"}, "Page 1 of 2"),
        ({"page": "0"}, "Page 1 of 2"),
        ({"page": "not-a-number"}, "Page 1 of 2"),
        ({"page": "-3"}, "Page 1 of 2"),
        ({"page": "9999"}, "Page 2 of 2"),
    ],
)
def test_nonsense_parameters_fall_back_rather_than_erroring(web, params, expected):
    """This is a page, not an API: a hand-edited or stale URL should render the library.

    A page number past the end clamps to the last page, and an over-long q is treated as no
    search at all -- so the over-long case still shows the whole 30-item library.
    """
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _insert_items(client, tenant, [f"Book {index:02d}" for index in range(30)])

    response = client.get("/account", params=params)
    assert response.status_code == 200
    assert expected in response.text
    assert len(_listed_titles(response.text)) in (25, 5)


def test_an_over_long_search_is_ignored_rather_than_applied(web):
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _insert_items(client, tenant, ["Tea one", "Tea two"])

    body = client.get("/account", params={"q": "x" * 161}).text
    assert "items match" not in body
    assert len(_listed_titles(body)) == 2


def test_markup_cannot_ride_a_title_or_a_search_term_into_the_search_view(web):
    """The escaping test's twin for the views search added.

    Two attacker-influenced strings meet here: the item title, which arrives from an
    emailed EPUB, and q, which is echoed into both the summary sentence and the search
    box's value attribute.
    """
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _insert_items(client, tenant, ["<script>alert(1)</script>", "Tea one"])

    body = client.get("/account", params={"q": "<script>alert(1)</script>"}).text
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "1 item matches" in body


# -- outbound email failure --------------------------------------------------


def test_sign_in_says_so_when_the_deployment_cannot_send_email(tmp_path, monkeypatch):
    """No monkeypatch here: this drives the real send_email, which refuses before any
    network call when MAIL_FROM_ADDRESS is unset. Reporting success would leave someone
    waiting for a link that was never going to arrive."""
    client, _ = _build_client(tmp_path, monkeypatch, capture=False)
    response = client.post("/signup", data={"email": EMAIL})
    assert response.status_code == 503
    assert "not available yet" in response.text


# -- headers -----------------------------------------------------------------


def test_the_security_headers_reach_web_pages_too(web):
    """The middleware was added for the OPDS and webhook routes; the browser pages are the
    ones that actually need a frame and content-security policy."""
    client, _ = web
    response = client.get("/signin")
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "private, no-store"


# -- the landing page ---------------------------------------------------------


SOURCE_URL = "https://code.example.test/steepd"
SUPPORT_ADDRESS = "hello@example.test"


def _first_form(body):
    """The action and field name of the first form on the page, as the browser sees them.

    Read out of the emitted HTML rather than written down here, so a form that starts
    pointing somewhere else takes the round-trip test with it instead of leaving a test
    that posts to /signup no matter what the page says.
    """
    form = re.search(r'<form method="post" action="([^"]+)">(.*?)</form>', body, re.S)
    assert form, f"the page emitted no form: {body}"
    field = re.search(r'<input type="email" name="(\w+)"', form.group(2))
    assert field, f"the form has no email field: {form.group(2)}"
    return html.unescape(form.group(1)), field.group(1)


def test_the_landing_page_makes_its_case_and_offers_the_real_sign_up(web):
    """Everything a signed-out visitor has to be able to see before they type an address."""
    client, _ = web
    body = client.get("/").text

    assert "Email it. Read it on your e" in body
    assert '<em class="chip">beta</em>' in body
    assert 'action="/signup"' in body
    assert "Create your reader address" in body
    assert "Free while Steepd is in beta" in body
    assert 'href="/privacy"' in body
    assert 'href="/terms"' in body


def test_the_landing_pricing_quotes_the_plans_module_rather_than_a_number(web):
    """The free card describes the live product, so its numbers have to be the ones the
    quota and the retention sweep actually enforce. Both expectations are computed from
    steepd.plans here: a page that hardcoded "100 MB" or "7 days" would keep saying so
    after the plan changed, and the first person to notice would be a user at their limit.
    """
    client, _ = web
    body = client.get("/").text

    assert _human_size(FREE_QUOTA_BYTES) in body
    assert f"Kept {FREE_RETENTION.days} days" in body
    assert _human_size(PAID_QUOTA_BYTES) in body
    assert body.count("coming soon") == 1
    assert "Paid plans arrive after the beta" in body


def test_the_beta_chip_is_on_the_signed_in_pages_too(web):
    """One header for the whole product: an account page without the chip would tell a
    paying-attention user that the beta label is marketing rather than a status."""
    client, sent = web
    _sign_up(client, sent)
    assert '<em class="chip">beta</em>' in client.get("/account").text


def test_the_landing_form_reaches_the_real_sign_up_flow(web):
    """The landing's own form, submitted exactly as the page emits it, must create an
    account and mail a link -- not merely look like a sign-up box."""
    client, sent = web
    action, field = _first_form(client.get("/").text)

    response = client.post(action, data={field: EMAIL})

    assert response.status_code == 200
    assert "Check your email" in response.text
    assert client.app.state.database.tenant_by_email(EMAIL) is not None
    assert _redeem(client, _magic_link(sent[-1]), follow_redirects=False).headers["location"] == "/account"


def test_the_landing_page_loads_nothing_from_anywhere_else(web):
    """The CSP is `default-src 'none'`, so any external reference on this page would be a
    blocked request in the console and, for a marketing page, a silent hole in the layout.
    The diagram is inline SVG for this reason; there is no webfont and no image file."""
    client, _ = web
    response = client.get("/")

    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert "http" not in response.text, "the landing page must not reference an external origin"
    assert "<svg" in response.text


# -- the walkthrough -----------------------------------------------------------

WALKTHROUGH_STEPS = ("walk-s1", "walk-s2", "walk-s3", "walk-s4")


def _walk_stage(body):
    stage = BeautifulSoup(body, "html.parser").find("div", class_="walk-stage")
    assert stage is not None, "the landing page has no walkthrough"
    return stage


def test_the_walkthrough_is_four_steps_wired_to_controls_that_exist(web):
    """The whole thing runs on `label for` pointing at a radio, and a `for` that names an
    id nothing answers to is a button that silently does nothing. There is no script on
    this page and so no console to notice it in -- this test is the only thing watching.
    """
    client, _ = web
    body = client.get("/").text
    stage = _walk_stage(body)

    assert "Show me how it works" in body
    assert "<script" not in body, "the walkthrough must stay script-free; the CSP would block one"

    radios = stage.find_all("input", attrs={"type": "radio"})
    assert len(radios) == 4
    assert {radio["name"] for radio in radios} == {"walkthrough"}, "the steps must be one radio group"
    assert [radio["id"] for radio in radios if radio.has_attr("checked")] == ["walk-1"]
    assert all(radio.get("aria-label") for radio in radios), "every step control needs a spoken name"

    steps = stage.find_all("div", class_="walk-step")
    assert len(steps) == 4
    assert [step["class"][1] for step in steps] == list(WALKTHROUGH_STEPS)

    ids = {radio["id"] for radio in radios}
    targets = {label["for"] for label in stage.find_all("label")}
    assert targets, "the walkthrough has no controls to advance it"
    assert targets <= ids, f"a control points at a control that does not exist: {sorted(targets - ids)}"
    assert targets == ids, "every step, including the way back to the first, must be reachable"


def test_the_walkthrough_types_the_address_this_deployment_answers_on(web):
    """The one detail a new reader has to copy correctly. Hardcoding read.steepd.app would
    make the walkthrough right on production and wrong on every other deployment -- and
    wrong in the most expensive place, because a wrong address just silently never arrives.
    """
    client, _ = web
    body = client.get("/").text

    assert f"you@{INBOX_DOMAIN}" in body
    assert f"your @{INBOX_DOMAIN} address" in body
    assert "steepd.app" not in body, "the walkthrough quoted a domain the settings did not give it"


def test_the_walkthrough_names_no_address_when_no_inbox_domain_is_configured(tmp_path):
    """A deployment with no inbox domain has no address to show, so it says so in words
    rather than printing a plausible-looking one."""
    settings = Settings(data_dir=tmp_path, public_base_url=BASE_URL, inbox_domain="")
    client = TestClient(create_app(settings), base_url=BASE_URL)

    body = client.get("/").text

    assert "Your Steepd address" in body
    assert "to your Steepd address." in body
    assert "@read." not in body


def test_the_walkthrough_is_one_line_of_markdown_not_a_transcript(web):
    """Four steps of stage direction would tell an agent nothing the sentence does not,
    and would bury the page's actual prose. The line it collapses to is the figure caption
    a sighted visitor reads, so the two cannot drift apart."""
    client, _ = web
    body = client.get("/", headers=MARKDOWN).text

    assert f"See how it works: forward any email to your @{INBOX_DOMAIN} address" in body
    assert "EPUB attachments are filed as books" in body
    for staging in ("The Weekly Dispatch", "Issue #42", "Show me how it works", "Start over", "Simple, right?"):
        assert staging not in body, f"the walkthrough's internals leaked into the markdown: {staging}"


def test_the_walkthrough_holds_still_for_a_reader_who_asked_for_less_motion(web):
    """Typing carets and pulsing rings are the two that would be worst to leave running.
    Reduced motion keeps every step visible and clickable and drops the keyframes."""
    client, _ = web
    body = client.get("/").text

    start = body.find("@media (prefers-reduced-motion:reduce){")
    assert start != -1, "the page never asks whether the reader wants less motion"
    reduced = body[start : body.index("</style>", start)]

    assert ".walk-type" in reduced, "the typing animation keeps running"
    assert ".walk-go" in reduced, "the pulsing control keeps running"
    for selector in (".walk-fly", ".walk-swirl", ".walk-file", ".walk-entry"):
        assert selector in reduced, f"{selector} keeps animating"
    assert reduced.count("animation:none") >= 3
    assert "display:none" not in reduced, "reduced motion must not hide a step, only still it"


def test_the_source_link_appears_only_once_a_repository_is_configured(tmp_path, monkeypatch):
    """The repository is not public yet. A "source" link to a 404 on an AGPL product is
    worse than no link, so the footer omits it until SOURCE_REPOSITORY_URL is set."""
    unconfigured, _ = _build_client(tmp_path, monkeypatch)
    for path in ("/", "/privacy", "/terms"):
        assert ">source</a>" not in unconfigured.get(path).text

    configured, _ = _build_client(tmp_path / "configured", monkeypatch, source_repository_url=SOURCE_URL)
    for path in ("/", "/privacy", "/terms"):
        body = configured.get(path).text
        assert f'<a href="{SOURCE_URL}">source</a>' in body


def test_the_support_address_appears_only_once_it_is_configured(tmp_path, monkeypatch):
    """A mailto nobody reads is a worse answer than not offering one."""
    unconfigured, _ = _build_client(tmp_path, monkeypatch)
    assert "mailto:" not in unconfigured.get("/privacy").text

    configured, _ = _build_client(tmp_path / "configured", monkeypatch, support_contact=SUPPORT_ADDRESS)
    body = configured.get("/privacy").text
    assert f'href="mailto:{SUPPORT_ADDRESS}"' in body
    assert SUPPORT_ADDRESS in body


# -- privacy and terms --------------------------------------------------------


def test_the_privacy_page_states_what_the_service_actually_does(web):
    """Each sentence here is a claim the code has to keep true. They are pinned so a
    change in behaviour -- analytics added, images fetched at read time, logs widened --
    breaks a test rather than turning this page into a lie."""
    client, _ = web
    response = client.get("/privacy")

    assert response.status_code == 200
    assert "sign-in links" in response.text
    assert "fetched once" in response.text
    assert "Tracking pixels are dropped" in response.text
    assert "no analytics" in response.text.lower()
    assert "keep you signed in" in response.text
    assert "Railway" in response.text
    assert "Resend" in response.text
    assert "never what was in it" in response.text
    # delete_tenant writes the local part to retired_inbox_locals forever, so the page may
    # not say the address is deleted: it is held back, and the difference is the promise
    # that nobody else is ever sent mail meant for you.
    assert "your inbox address is held back so nobody else can ever be sent your mail" in response.text
    assert "your stored files and your inbox address" not in response.text


def test_the_privacy_retention_number_comes_from_the_plans_module(web):
    """The page promises automatic deletion on a schedule the retention sweep owns. The
    expectation is computed from FREE_RETENTION so the promise and the sweep cannot drift."""
    client, _ = web
    body = client.get("/privacy").text
    assert f"deleted automatically {FREE_RETENTION.days} days after it" in body


def test_the_terms_page_is_honest_about_the_beta(web):
    client, _ = web
    response = client.get("/terms")

    assert response.status_code == 200
    assert "free public beta" in response.text
    assert "change, break or lose data without notice" in response.text
    assert "One account per person" in response.text
    assert "no warranty of any kind" in response.text
    assert "AGPL" in response.text


def test_the_terms_free_plan_limits_come_from_the_plans_module(web):
    client, _ = web
    body = client.get("/terms").text
    assert f"{_human_size(FREE_QUOTA_BYTES)} of storage" in body
    assert f"deleted automatically {FREE_RETENTION.days} days after it" in body


# -- the setup page -----------------------------------------------------------


def _hrefs(body: str) -> list[str]:
    return [str(link.get("href")) for link in BeautifulSoup(body, "html.parser").find_all("a")]


def test_the_setup_page_gives_a_signed_out_visitor_the_steps_for_their_reader(web):
    """The page has to be readable before anyone has an account -- deciding whether your
    reader can do this is the reason to sign up, not something you learn afterwards."""
    client, _ = web
    assert SESSION_COOKIE not in client.cookies
    response = client.get("/devices")

    assert response.status_code == 200
    # The two devices whose menus have actually been walked, quoted exactly. A test that
    # accepted "look under Settings" would let a wrong menu path through.
    assert "Settings → System → OPDS Servers → Add Server" in response.text
    assert "OPDS Browser" in response.text
    assert "choose <strong>OPDS catalog</strong>" in response.text
    assert "<ol>" in response.text, "the verified flows are numbered steps"


def test_the_setup_page_says_plainly_where_the_stock_software_cannot_do_it(web):
    """Three readers cannot add a private catalogue with their own software. Inventing a
    menu path for them would send someone hunting through settings that do not exist, so
    each of these sections has to keep saying no and naming what to use instead."""
    client, _ = web
    body = client.get("/devices").text

    assert "no way to add a catalogue that needs a password on PocketBook stock firmware" in body
    assert "Kobo's built-in software cannot add catalogues" in body
    assert "Stock Kindle firmware has no OPDS support" in body
    assert body.count("KOReader") >= 4, "each honest no has to point at the reader that works"


def test_the_setup_page_shows_the_address_this_deployment_answers_on(tmp_path, monkeypatch):
    """The address is the one thing on the page a visitor copies, so it is built from
    public_base_url rather than written down. A page carrying the canonical domain would
    be wrong on every other deployment and wrong in every self-hosted copy."""
    client, _ = _build_client(tmp_path, monkeypatch)
    assert f"{BASE_URL}/opds" in client.get("/devices").text

    elsewhere = "https://books.example.test"
    other, _ = _build_client(tmp_path, monkeypatch, base_url=elsewhere)
    body = other.get("/devices").text
    assert f"{elsewhere}/opds" in body
    assert BASE_URL not in body


def test_the_landing_and_the_account_both_point_at_the_setup_page(web):
    """Both places someone meets their catalogue address. The landing page raises the
    question of whether their reader can do this; the account page is where they are
    holding the credentials and wondering what to type them into."""
    client, sent = web
    assert "/devices" in _hrefs(client.get("/").text)

    _sign_up(client, sent)
    assert "/devices" in _hrefs(client.get("/account").text)


# -- crawlers -----------------------------------------------------------------


MARKDOWN = {"Accept": "text/markdown"}


def test_robots_names_the_public_paths_and_keeps_crawlers_off_the_private_ones(web):
    """The /auth/ line is the one with teeth. Sign-in tokens are single-use and travel
    only by email, but a crawler that somehow met one and fetched it would consume it,
    leaving the person waiting on that link with one that had already been spent."""
    client, _ = web
    response = client.get("/robots.txt")

    assert response.status_code == 200
    assert response.headers["content-type"] == "text/plain; charset=utf-8"
    assert "User-agent: *" in response.text
    assert "Disallow: /auth/" in response.text
    assert "Disallow: /account" in response.text
    assert "Disallow: /opds" in response.text
    assert "Disallow: /webhooks/" in response.text
    assert "Content-Signal: search=yes, ai-input=yes" in response.text
    assert f"Sitemap: {BASE_URL}/sitemap.xml" in response.text


def test_the_ai_crawlers_are_named_and_told_exactly_what_everyone_else_is(web):
    """These pages exist to be understood, so the AI group gets the same answer as the
    wildcard group. It is spelled out separately only because several of these crawlers
    look for their own name rather than reading the wildcard rules."""
    client, _ = web
    body = client.get("/robots.txt").text

    for crawler in ("GPTBot", "OAI-SearchBot", "Claude-Web", "ClaudeBot", "Google-Extended", "PerplexityBot"):
        assert f"User-agent: {crawler}" in body

    wildcard, named = body.split("User-agent: GPTBot", 1)
    rules = ("Allow: /", "Disallow: /account", "Disallow: /admin/", "Disallow: /auth/", "Disallow: /opds")
    for rule in (*rules, "Disallow: /webhooks/"):
        assert rule in wildcard, f"the wildcard group is missing {rule!r}"
        assert rule in named, f"the AI group is missing {rule!r}"


def test_the_sitemap_lists_exactly_the_public_pages_as_absolute_urls(web):
    """Parsed rather than string-matched: a sitemap a crawler cannot parse is not a
    sitemap, and the failure would be invisible in a substring assertion."""
    client, _ = web
    response = client.get("/sitemap.xml")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/xml")

    root = ElementTree.fromstring(response.text)
    namespace = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
    assert root.tag == f"{namespace}urlset"
    locations = [element.text for element in root.iter(f"{namespace}loc")]
    assert locations == [f"{BASE_URL}{path}" for path in PUBLIC_PAGE_PATHS]
    assert all(location.startswith(BASE_URL) for location in locations)
    # Spelled out as well as derived: comparing the sitemap to the list it is built from
    # proves they agree, not that either is right. A page dropped from the list would be
    # dropped from the sitemap too, and the two would go on agreeing about six pages
    # having become five.
    assert set(locations) == {
        f"{BASE_URL}{path}" for path in ("/", "/devices", "/signup", "/signin", "/privacy", "/terms")
    }


def test_the_crawler_files_need_no_session_and_are_never_rate_limited(web):
    """A crawler comes back repeatedly and from one address. Both files are public,
    cheap, and absent from the rate-limit policy table; this fails if either changes."""
    client, _ = web
    assert SESSION_COOKIE not in client.cookies

    for _ in range(25):
        assert client.get("/robots.txt").status_code == 200
        assert client.get("/sitemap.xml").status_code == 200


# -- markdown for readers that are not browsers -------------------------------


def test_asking_for_markdown_gets_markdown_and_the_browser_still_gets_html(web):
    """The default is unchanged: only a caller that names text/markdown sees it."""
    client, _ = web

    markdown = client.get("/", headers=MARKDOWN)
    assert markdown.status_code == 200
    assert markdown.headers["content-type"] == "text/markdown; charset=utf-8"
    assert "# Email it. Read it on your e" in markdown.text
    # The form becomes the one thing an agent can act on -- where to send an address.
    assert f"{BASE_URL}/signup" in markdown.text
    assert "[privacy](" in markdown.text

    html_page = client.get("/")
    assert html_page.headers["content-type"].startswith("text/html")
    assert html_page.text == client.get("/", headers={"Accept": "text/html"}).text
    assert "<h1>" in html_page.text


def test_the_markdown_carries_no_markup_and_no_diagram(web):
    """A converter that let tags through would hand an agent worse input than the HTML,
    and the diagram is 60 lines of path data saying what the prose beside it already says."""
    client, _ = web
    body = client.get("/", headers=MARKDOWN).text

    assert "<h1" not in body
    assert "<form" not in body
    assert "<svg" not in body
    assert "<" not in body, f"markup survived the conversion: {body}"
    assert "stroke-linecap" not in body


def test_the_privacy_page_in_markdown_says_what_the_html_says(web):
    """One source of truth: the retention sentence is not written twice, so it cannot be
    right on the page and stale in the markdown."""
    client, _ = web
    body = client.get("/privacy", headers=MARKDOWN).text

    assert "# Privacy" in body
    assert f"deleted automatically {FREE_RETENTION.days} days after it" in body
    assert "## What we do not do" in body


def test_the_setup_page_in_markdown_keeps_the_steps_in_order(web):
    """An agent reading this on someone's behalf gets the numbers, not bullets: on the
    setup page the order of the steps is the instruction, and a list of five things to do
    in no particular order is a different and wrong page."""
    client, _ = web
    response = client.get("/devices", headers=MARKDOWN)

    assert response.headers["content-type"] == "text/markdown; charset=utf-8"
    body = response.text
    assert "## Xteink X4 (CrossPoint)" in body
    assert "## KOReader" in body
    assert "1. In the file browser" in body
    assert "2. Tap the **+** icon" in body
    assert "<" not in body, f"markup survived the conversion: {body}"


def test_both_variants_of_every_public_page_vary_on_accept(web):
    """Without this a cache in front of the service would serve one visitor's markdown to
    the next visitor's browser. It goes on the HTML too, which is the half that matters:
    the browser response is the one that would be stored and replayed."""
    client, _ = web
    for path in PUBLIC_PAGE_PATHS:
        assert client.get(path).headers["vary"] == "Accept", path
        assert client.get(path, headers=MARKDOWN).headers["vary"] == "Accept", path


def test_a_private_page_never_negotiates_markdown(web):
    """Negotiation is a property of the five public pages, not of the app. The account
    page holds an inbox address and a catalogue URL, and it answers the same way to
    everyone regardless of what they claim to accept."""
    client, sent = web
    signed_out = client.get("/account", headers=MARKDOWN, follow_redirects=False)
    assert signed_out.status_code == 303
    assert signed_out.headers["location"] == "/signin"

    _sign_up(client, sent)
    signed_in = client.get("/account", headers=MARKDOWN)
    assert signed_in.headers["content-type"].startswith("text/html")
    assert "vary" not in signed_in.headers


def test_the_converter_handles_every_tag_the_public_pages_actually_use(tmp_path, monkeypatch):
    """The converter is partial on purpose, so this is the guard that keeps it honest.

    A page edit that introduces a tag nobody taught it about would otherwise drop that
    content silently from the markdown -- the HTML would look fine and only an agent
    would ever notice. Rendered with the support address and the source link configured,
    because both add links the default fixture omits.
    """
    client, _ = _build_client(
        tmp_path, monkeypatch, support_contact=SUPPORT_ADDRESS, source_repository_url=SOURCE_URL
    )
    for path in PUBLIC_PAGE_PATHS:
        body = BeautifulSoup(client.get(path).text, "html.parser").body
        assert body is not None, f"{path} rendered no body"
        # Tags inside a dropped subtree are irrelevant: the whole subtree never reaches
        # the converter. Everything else has to be a tag it knows what to do with.
        used = {tag.name for tag in body.find_all(True) if not tag.find_parent(list(MARKDOWN_DROPPED_TAGS))}
        unknown = used - MARKDOWN_HANDLED_TAGS - MARKDOWN_DROPPED_TAGS
        assert not unknown, f"{path} uses tags the markdown converter would drop: {sorted(unknown)}"


def test_the_walkthrough_stage_holds_one_height_across_steps(web):
    """The panels are stacked in a single grid cell and hidden with visibility, so the
    box is always as tall as the tallest step and does not grow and shrink as the steps
    change. display:none would resize the stage on every click -- the jump this exists
    to prevent -- so its absence from the step css is the property under test."""
    client, _ = web
    body = client.get("/").text
    css = body[body.index("<style>"):body.index("</style>")]
    walk_step_rule = next(part for part in css.split("}") if part.strip().startswith(".walk-step{"))
    assert "grid-area:1/1" in walk_step_rule
    assert "visibility:hidden" in walk_step_rule
    assert "display:none" not in walk_step_rule
    assert "display:grid" in next(p for p in css.split("}") if p.strip().startswith(".walk-stage{"))
    # The animations moved under the :checked selectors when visibility took over hiding;
    # if one drifts back to the bare class it will run while its panel is invisible.
    for animated in (".walk-type{", ".walk-go{"):
        bare_rule = next(p for p in css.split("}") if p.strip().startswith(animated))
        assert "animation:" not in bare_rule.split("@media")[0]


def test_the_signup_form_is_not_inside_the_open_source_section(web):
    """The bottom form used to sit in the open-source section, where its button read as
    the way to get the repository. The form now lives in its own headed section, and the
    repository link -- when configured -- is an actual link in the open-source prose."""
    client, _ = web
    soup = BeautifulSoup(client.get("/").text, "html.parser")
    open_source = next(s for s in soup.find_all("section") if s.h2 and s.h2.get_text() == "Open source")
    assert open_source.find("form") is None
    start = next(s for s in soup.find_all("section") if s.h2 and s.h2.get_text() == "Start reading")
    assert start.find("form") is not None


def test_the_open_source_section_links_to_the_repository_when_configured(tmp_path, monkeypatch):
    client, _ = _build_client(tmp_path, monkeypatch, source_repository_url="https://repo.example.test/steepd")
    soup = BeautifulSoup(client.get("/").text, "html.parser")
    open_source = next(s for s in soup.find_all("section") if s.h2 and s.h2.get_text() == "Open source")
    links = [a["href"] for a in open_source.find_all("a")]
    assert "https://repo.example.test/steepd" in links


# -- choosing an address -----------------------------------------------------


def test_the_first_sign_in_lands_on_the_address_page_and_nothing_else_until_it_is_done(web):
    client, sent = web
    client.post("/signup", data={"email": EMAIL})
    _redeem(client, _magic_link(sent[-1]))
    for path in ("/account", "/", "/account?q=x"):
        assert client.get(path, follow_redirects=False).headers["location"] == "/account/address"
    assert client.post("/account/rotate", follow_redirects=False).headers["location"] == "/account/address"
    page = client.get("/account/address")
    assert page.status_code == 200
    assert _prefilled_name(page.text) == "reader"
    assert "is taken" not in page.text
    # The placeholder must never be shown.
    tenant = client.app.state.database.tenant_by_email(EMAIL)
    assert tenant.inbox_local not in page.text
    assert tenant.inbox_local not in sent[-1]["text"]


def test_confirming_the_prefilled_name_sets_the_address_and_username(web):
    client, sent = web
    _sign_up(client, sent)
    tenant = client.app.state.database.tenant_by_email(EMAIL)
    assert tenant.inbox_local == tenant.opds_username == "reader"
    assert tenant.inbox_confirmed_at is not None
    account = client.get("/account")
    assert f"reader@{INBOX_DOMAIN}" in account.text


def test_a_taken_stem_is_said_so_and_an_alternative_is_offered(web):
    client, sent = web
    client.app.state.database.create_tenant(email="other@example.test", inbox_local="reader")
    client.post("/signup", data={"email": EMAIL})
    _redeem(client, _magic_link(sent[-1]))
    page = client.get("/account/address")
    assert "reader" in page.text and "is taken" in page.text
    assert _prefilled_name(page.text) == "reader.e"


def test_a_reserved_stem_is_called_reserved_rather_than_taken(web):
    """Nobody holds `info` and nobody ever will, so calling it taken would be a lie that
    sends the person hunting for a variant."""
    client, sent = web
    client.post("/signup", data={"email": "info@example.test"})
    _redeem(client, _magic_link(sent[-1]))

    page = client.get("/account/address")

    assert "is reserved" in page.text
    assert "is taken" not in page.text
    assert _prefilled_name(page.text) == "info.e"


def test_two_accounts_racing_for_one_name_get_a_page_not_a_crash(web):
    """Availability is checked and then the name is written, and nothing holds the gap
    open. The loser of that race must be told the name went, the same as anyone who asks
    for a name that was already gone."""
    client, sent = web
    second = TestClient(client.app, base_url=BASE_URL)
    client.post("/signup", data={"email": EMAIL})
    _redeem(client, _magic_link(sent[-1]))
    second.post("/signup", data={"email": "other@example.test"})
    _redeem(second, _magic_link(sent[-1]))

    assert client.post("/account/address", data={"name": "ines"}, follow_redirects=False).status_code == 303
    response = second.post("/account/address", data={"name": "ines"})

    assert response.status_code == 400
    assert "is taken" in response.text
    assert client.app.state.database.tenant_by_email("other@example.test").inbox_confirmed_at is None


def test_the_unique_constraint_answers_the_race_the_availability_check_cannot(web, monkeypatch):
    """The check and the insert are two statements. This drives the branch that catches
    the UNIQUE violation between them by making the check lie, which is what a genuinely
    concurrent pair of requests does to it."""
    client, sent = web
    client.app.state.database.create_tenant(email="other@example.test", inbox_local="ines")
    client.post("/signup", data={"email": EMAIL})
    _redeem(client, _magic_link(sent[-1]))
    monkeypatch.setattr(client.app.state.database, "inbox_local_available", lambda name: True)
    # Without this the 400 below would prove nothing: the ordinary check would produce the
    # same page, and a patch that failed to take would look like a pass.
    assert client.app.state.database.inbox_local_available("ines") is True

    response = client.post("/account/address", data={"name": "ines"})

    assert response.status_code == 400
    assert "is taken" in response.text
    assert client.app.state.database.tenant_by_email(EMAIL).inbox_confirmed_at is None


@pytest.mark.parametrize(
    ("name", "fragment"),
    [("R", "at least 2"), ("hello", "reserved"), ("bad name", "lowercase"), ("reader", "is taken")],
)
def test_a_bad_name_is_refused_with_a_reason_and_the_page_stays(web, name, fragment):
    client, sent = web
    client.app.state.database.create_tenant(email="other@example.test", inbox_local="reader")
    client.post("/signup", data={"email": EMAIL})
    _redeem(client, _magic_link(sent[-1]))
    response = client.post("/account/address", data={"name": name})
    assert response.status_code == 400
    assert fragment in response.text
    assert client.app.state.database.tenant_by_email(EMAIL).inbox_confirmed_at is None


def test_a_retired_name_cannot_be_chosen(web):
    client, sent = web
    database = client.app.state.database
    gone = database.create_tenant(email="gone@example.test", inbox_local="ines")
    database.delete_tenant(gone.id)
    client.post("/signup", data={"email": EMAIL})
    _redeem(client, _magic_link(sent[-1]))
    assert "is taken" in client.post("/account/address", data={"name": "ines"}).text


def test_the_address_is_chosen_exactly_once(web):
    client, sent = web
    _sign_up(client, sent, name="ines")
    assert client.get("/account/address", follow_redirects=False).headers["location"] == "/account"
    again = client.post("/account/address", data={"name": "other"})
    assert again.status_code == 403
    # A rendered page, not the raw JSON body FastAPI attaches to a raised HTTPException:
    # a stale tab is a person, and every other outcome on this surface is a page.
    assert "already chosen" in again.text
    assert '<a href="/account">' in again.text, again.text
    assert client.app.state.database.tenant_by_email(EMAIL).inbox_local == "ines"


def test_sign_out_works_before_the_address_is_chosen(web):
    client, sent = web
    client.post("/signup", data={"email": EMAIL})
    _redeem(client, _magic_link(sent[-1]))
    assert client.post("/signout", follow_redirects=False).status_code == 303
    assert client.get("/account", follow_redirects=False).headers["location"] == "/signin"


def test_suggest_inbox_local_walks_the_fallbacks(web):
    from steepd.web import StemStatus, suggest_inbox_local

    database = client_db = web[0].app.state.database
    assert suggest_inbox_local("ines@example.com", database) == ("ines", StemStatus.FREE)
    client_db.create_tenant(email="a@example.test", inbox_local="ines")
    assert suggest_inbox_local("ines@example.com", database) == ("ines.e", StemStatus.TAKEN)
    client_db.create_tenant(email="b@example.test", inbox_local="ines.e")
    assert suggest_inbox_local("ines@example.com", database) == ("ines01", StemStatus.TAKEN)


def test_suggest_inbox_local_tells_a_reserved_stem_from_a_taken_one(web):
    """A reserved stem was never anybody's to hold, so saying it is taken would send the
    person looking for a variant of a name no variant will free up."""
    from steepd.web import StemStatus, suggest_inbox_local

    database = web[0].app.state.database
    assert suggest_inbox_local("info@example.test", database) == ("info.e", StemStatus.RESERVED)
    # Two characters is the floor, so a one-letter stem is not reserved, just unusable.
    assert suggest_inbox_local("a@example.test", database) == ("a.e", StemStatus.MALFORMED)


# -- who can send ------------------------------------------------------------


def test_the_senders_section_defaults_to_anyone_and_names_the_account_email(web):
    client, sent = web
    _sign_up(client, sent)
    page = client.get("/account").text
    assert "Who can send to this address" in page
    assert 'name="policy" value="anyone" checked' in page
    assert EMAIL in page and "always allowed" in page


def test_switching_to_listed_and_adding_and_removing_a_sender(web):
    client, sent = web
    _sign_up(client, sent)
    database = client.app.state.database
    policy = client.post("/account/senders/policy", data={"policy": "listed"}, follow_redirects=False)
    assert policy.status_code == 303
    assert database.tenant_by_email(EMAIL).sender_policy == "listed"

    added = client.post(
        "/account/senders/add", data={"address": " News@Dispatch.example "}, follow_redirects=False
    )
    assert added.status_code == 303
    tenant = database.tenant_by_email(EMAIL)
    assert database.list_allowed_senders(tenant.id) == ["news@dispatch.example"]
    assert "news@dispatch.example" in client.get("/account").text

    removed = client.post(
        "/account/senders/remove", data={"address": "news@dispatch.example"}, follow_redirects=False
    )
    assert removed.status_code == 303
    assert database.list_allowed_senders(tenant.id) == []


def test_a_bad_address_or_bad_policy_is_refused_and_the_page_says_so(web):
    client, sent = web
    _sign_up(client, sent)
    response = client.post("/account/senders/add", data={"address": "not-an-address"})
    assert response.status_code == 400 and "you@example.com" in response.text
    assert client.post("/account/senders/policy", data={"policy": "everyone"}).status_code == 400


def test_your_own_address_is_never_listed_as_a_sender(web):
    client, sent = web
    _sign_up(client, sent)
    response = client.post("/account/senders/add", data={"address": EMAIL.upper()})
    assert response.status_code == 400
    assert "Your own address is always allowed." in response.text
    tenant = client.app.state.database.tenant_by_email(EMAIL)
    assert client.app.state.database.list_allowed_senders(tenant.id) == []


def test_the_cap_is_explained(web):
    client, sent = web
    _sign_up(client, sent)
    tenant = client.app.state.database.tenant_by_email(EMAIL)
    for n in range(50):
        client.app.state.database.add_allowed_sender(tenant.id, f"s{n}@example.com")
    response = client.post("/account/senders/add", data={"address": "one@more.example"})
    assert response.status_code == 400 and "50" in response.text


def test_refused_senders_are_offered_with_an_allow_button(web):
    client, sent = web
    _sign_up(client, sent)
    database = client.app.state.database
    tenant = database.tenant_by_email(EMAIL)
    database.set_sender_policy(tenant.id, "listed")
    database.record_refused_sender(tenant.id, "news@dispatch.example", now="2026-09-02T10:00:00+00:00")
    database.record_refused_sender(tenant.id, "news@dispatch.example", now="2026-09-02T11:00:00+00:00")
    page = client.get("/account").text
    assert "news@dispatch.example" in page and "2 times" in page and "2 Sep" in page
    # Allowing it is the same add route, and clears the refusal.
    client.post("/account/senders/add", data={"address": "news@dispatch.example"})
    assert database.list_allowed_senders(tenant.id) == ["news@dispatch.example"]
    assert database.list_refused_senders(tenant.id) == []
    assert "was not accepted" not in client.get("/account").text


def test_sender_routes_need_a_session_and_same_origin(web):
    client, _ = web
    signed_out = client.post("/account/senders/add", data={"address": "a@b.c"}, follow_redirects=False)
    assert signed_out.headers["location"] == "/signin"
    cross_site = client.post(
        "/account/senders/policy", data={"policy": "listed"}, headers={"Origin": "https://evil.example"}
    )
    assert cross_site.status_code == 403
