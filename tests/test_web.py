"""Tests for the browser layer: sign-up, sign-in, and the account page.

Outbound email is captured rather than sent, so the sign-in link these tests follow is
the one a real recipient would receive. Several tests deliberately extract the link from
the captured message instead of building the URL, because a link that does not match the
route it is meant to reach is exactly the failure a constructed URL would hide.
"""

from __future__ import annotations

import base64
import hashlib
import html
import re
import xml.etree.ElementTree as ElementTree
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from steepd.app import create_app
from steepd.auth import issue_magic_token
from steepd.config import Settings
from steepd.epubgen import build_epub
from steepd.models import Item
from steepd.plans import PAID_PLAN
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
    assert client.get("/account/library", follow_redirects=False).headers["location"] == "/signin"


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
        "/account/email-verification",
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
    library = client.get("/account/library").text

    assert '<span class="title">Free</span>' in body
    assert "100 MB" in body
    assert f"{_human_size(item.size_bytes)} of 100 MB used" in body
    assert f"Items are kept for {client.app.state.settings.free_retention.days} days." in body
    assert f"removed in {client.app.state.settings.free_retention.days} days" in library


def test_a_paid_account_shows_its_larger_quota_without_retention_notes(web):
    client, sent = web
    _sign_up(client, sent)
    database = client.app.state.database
    tenant = database.tenant_by_email(EMAIL)
    _store_item(client, tenant)
    assert database.set_tenant_plan(tenant.id, PAID_PLAN)

    body = client.get("/account").text
    library = client.get("/account/library").text

    assert '<span class="title">Paid</span>' in body
    assert "5 GB" in body
    assert "Items are kept for" not in body
    assert "removed in" not in library


def test_the_usage_meter_width_reflects_actual_storage(web):
    client, sent = web
    _sign_up(client, sent)
    tenant = client.app.state.database.tenant_by_email(EMAIL)
    _insert_sized_item(client, tenant, size_bytes=client.app.state.settings.free_quota_bytes // 4)

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

    _insert_sized_item(client, tenant, size_bytes=client.app.state.settings.free_quota_bytes * 86 // 100)

    assert warning in client.get("/account").text


@pytest.mark.parametrize("accept", ["text/html", "text/markdown"])
def test_configured_plan_limits_stay_consistent_and_isolated_between_apps(tmp_path, monkeypatch, accept):
    apps = []
    for free_mb, paid_gb, days, period in [(200, 2, 1, "1 day"), (100, 5, 60, "60 days")]:
        client, sent = _build_client(
            tmp_path / str(days), monkeypatch,
            free_quota_bytes=free_mb * 1024**2,
            paid_quota_bytes=paid_gb * 1024**3,
            free_retention=timedelta(days=days),
        )
        _sign_up(client, sent)
        tenant = client.app.state.database.tenant_by_email(EMAIL)
        item = _store_item(client, tenant)
        apps.append((client, tenant, item, free_mb, paid_gb, period))

    # Read both apps after constructing both: a global changed by the second app would
    # advertise or enforce its limits for the first app as well.
    for client, tenant, item, free_mb, paid_gb, period in apps:
        with TestClient(client.app, base_url=BASE_URL) as public:
            landing = public.get("/", headers={"Accept": accept})
            assert landing.status_code == 200
            assert landing.headers["content-type"].startswith(accept)
            assert f"{free_mb} MB" in landing.text
            assert f"{paid_gb} GB" in landing.text
            assert f"Kept {period}" in landing.text
            assert "Kept until deleted" in landing.text
            for path in ("/privacy", "/terms"):
                page = public.get(path, headers={"Accept": accept})
                assert page.status_code == 200
                assert page.headers["content-type"].startswith(accept)
                assert f"deleted automatically {period} after it" in page.text
                if path == "/terms":
                    assert f"{free_mb} MB of storage" in page.text

        body = client.get("/account").text
        assert f"of {free_mb} MB used" in body
        assert f"Items are kept for {period}." in body
        assert f"removed in {period}" in client.get("/account/library").text

        allowance = free_mb * 1024**2
        _insert_sized_item(client, tenant, size_bytes=allowance * 84 // 100 - item.size_bytes)
        warning = "New deliveries are refused once the storage limit is reached."
        assert warning not in client.get("/account").text
        _insert_sized_item(client, tenant, size_bytes=allowance // 100)
        body = client.get("/account").text
        assert warning in body
        meter = BeautifulSoup(body, "html.parser").find(attrs={"role": "meter"})
        assert meter["aria-valuemax"] == str(allowance)
        assert meter["aria-valuenow"] == str(allowance * 85 // 100)
        assert meter.find(class_="usage-meter-fill")["style"] == "width: 85%"

        client.app.state.database.set_tenant_plan(tenant.id, PAID_PLAN)
        body = client.get("/account").text
        assert f"of {paid_gb} GB used" in body
        assert "Items are kept for" not in body
        assert "removed in" not in body


# -- deletion ----------------------------------------------------------------


def test_delete_moves_an_item_to_trash_where_it_can_be_restored(web):
    """Delete is one click with no confirmation, so it has to be undoable."""
    client, sent = web
    _sign_up(client, sent)
    database = client.app.state.database
    tenant = database.tenant_by_email(EMAIL)
    scope = TenantScope(tenant.id)
    item = _store_item(client, tenant)
    path = client.app.state.storage.path_for(item)

    response = client.post(f"/account/items/{item.id}/delete", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/account/library?notice=trashed"
    assert "Moved to Trash" in client.get(response.headers["location"]).text
    assert database.get_item(scope, item.id) is None
    assert "A stored book" not in client.get("/account/library").text
    # Still on disk and still counted until it is purged.
    assert path.is_file()
    assert database.tenant_storage_bytes(scope) == item.size_bytes
    assert 'href="/account/trash"' in client.get("/account").text
    assert "A stored book" in client.get("/account/trash").text

    response = client.post(f"/account/trash/{item.id}/restore", follow_redirects=False)
    assert response.headers["location"] == "/account/trash?notice=restored"
    assert database.get_item(scope, item.id) == replace(item, revision=2)
    assert "A stored book" in client.get("/account/library").text
    assert 'href="/account/trash"' not in client.get("/account").text


def test_delete_returns_to_the_same_place_in_the_library(web):
    """Deleting several items in a row should not throw the reader back to the first page."""
    client, sent = web
    _sign_up(client, sent)
    tenant = client.app.state.database.tenant_by_email(EMAIL)
    first = _store_item(client, tenant, title="Alpha book")
    second = _store_item(client, tenant, title="Beta book")

    page = client.get("/account/library?shelf=books&q=book&sort=title").text
    action = re.search(rf'action="(/account/items/{first.id}/delete[^"]*)"', page).group(1).replace("&amp;", "&")
    assert f"anchor={second.id}" in action

    response = client.post(action, follow_redirects=False)
    assert response.headers["location"] == (
        f"/account/library?shelf=books&q=book&sort=title&notice=trashed#item-{second.id}"
    )
    assert f'id="item-{second.id}"' in client.get(response.headers["location"].split("#")[0]).text


def test_delete_ignores_a_redirect_it_did_not_build(web):
    client, sent = web
    _sign_up(client, sent)
    response = client.post(
        "/account/items/x/delete?shelf=https://evil.example&anchor=%22%3E%3Cscript%3E", follow_redirects=False
    )
    assert response.headers["location"] == "/account/library?notice=trashed"


def test_deleting_permanently_from_trash_removes_the_row_and_the_file(web):
    """A delete that drops the row but leaves the file keeps paid-for storage occupied by
    something the owner believes is gone."""
    client, sent = web
    _sign_up(client, sent)
    database = client.app.state.database
    tenant = database.tenant_by_email(EMAIL)
    scope = TenantScope(tenant.id)
    item = _store_item(client, tenant)
    path = client.app.state.storage.path_for(item)
    client.post(f"/account/items/{item.id}/delete")

    response = client.post(f"/account/trash/{item.id}/delete", follow_redirects=False)
    assert response.headers["location"] == "/account/trash?notice=deleted"
    assert database.get_trashed_item(scope, item.id) is None
    assert not path.exists()
    assert database.tenant_storage_bytes(scope) == 0
    assert "Nothing in Trash." in client.get("/account/trash").text


def test_trash_routes_do_not_reach_another_tenants_items(web):
    client, sent = web
    _sign_up(client, sent)
    database = client.app.state.database
    other = database.create_tenant(email="other@example.com", inbox_local="other")
    storage = client.app.state.storage
    item = _store_item(client, other)
    storage.trash(TenantScope(other.id), item.id)

    assert "A stored book" not in client.get("/account/trash").text
    client.post(f"/account/trash/{item.id}/restore")
    client.post(f"/account/trash/{item.id}/delete")
    assert database.get_trashed_item(TenantScope(other.id), item.id) is not None
    assert storage.path_for(item).is_file()


def test_an_item_title_cannot_carry_markup_onto_the_account_page(web):
    """Titles arrive from the metadata of an emailed EPUB, so they are attacker-influenced,
    and the account page is the first place one is rendered as HTML. Unescaped, a forwarded
    book would run script against the session that lists it."""
    client, sent = web
    _sign_up(client, sent)
    tenant = client.app.state.database.tenant_by_email(EMAIL)
    _store_item(client, tenant, title="<script>alert(1)</script>")

    body = client.get("/account/library").text
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body


def test_deleting_an_unknown_item_still_returns_to_the_library(web):
    """Deleting is idempotent from where the user is standing, and an error here would
    also report whether an id exists."""
    client, sent = web
    _sign_up(client, sent)
    response = client.post("/account/items/does-not-exist/delete", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/account/library?notice=trashed"


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

    first = client.get("/account/library")
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

    first = client.get("/account/library")
    assert _listed_titles(first.text)[0] == "Book 29"
    second = client.get(_followable(first.text, "Next"))
    assert _listed_titles(second.text)[-1] == "Book 00"


def test_searching_narrows_the_library_and_reports_the_count(web):
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _insert_items(client, tenant, ["Tea one", "Coffee one", "Tea two", "Coffee two", "Tea three"])

    response = client.get("/account/library", params={"q": "Tea"})
    assert response.status_code == 200
    assert _listed_titles(response.text) == ["Tea three", "Tea two", "Tea one"]
    assert "3 items match" in response.text

    cleared = client.get(_followable(response.text, "Clear"))
    assert len(_listed_titles(cleared.text)) == 5


def test_a_search_of_one_item_is_worded_as_one(web):
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _insert_items(client, tenant, ["Tea one", "Coffee one"])

    body = client.get("/account/library", params={"q": "Coffee"}).text
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

    first = client.get("/account/library", params={"q": "Steeping"})
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

    by_date = client.get("/account/library")
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

    newest = client.get("/account/library")
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

    response = client.get("/account/library", params={"q": "cocoa"})
    assert response.status_code == 200
    assert "0 items match" in response.text
    assert "Nothing in your library matches that search." in response.text
    assert _listed_titles(response.text) == []


def test_an_empty_library_still_says_how_to_start(web):
    """No items means nothing to search, so the form stays away and the invitation stays."""
    client, sent = web
    _signed_in_tenant(client, sent)

    body = client.get("/account/library").text
    assert "Nothing here yet." in body
    assert "address above" not in body, "the address is on the account page, not this one"
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

    response = client.get("/account/library", params=params)
    assert response.status_code == 200
    assert expected in response.text
    assert len(_listed_titles(response.text)) in (25, 5)


def test_an_over_long_search_is_ignored_rather_than_applied(web):
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _insert_items(client, tenant, ["Tea one", "Tea two"])

    body = client.get("/account/library", params={"q": "x" * 161}).text
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

    body = client.get("/account/library", params={"q": "<script>alert(1)</script>"}).text
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
    assert "one webpage URL alone in the email subject" in body
    assert 'href="/privacy"' in body
    assert 'href="/terms"' in body


def test_the_landing_diagram_shows_all_three_email_inputs_and_saved(web):
    client, _ = web
    soup = BeautifulSoup(client.get("/").text, "html.parser")
    diagram = soup.find("div", class_="diagram")
    assert diagram is not None
    svg = diagram.find("svg")
    assert svg is not None

    spoken = svg.get("aria-label", "")
    assert "forwarded newsletter" in spoken
    assert "webpage URL in the email subject" in spoken
    assert "attached EPUB" in spoken
    visible = " ".join(svg.stripped_strings)
    assert "Newsletter" in visible
    assert "Webpage" in visible
    assert "link in subject" in visible
    assert "EPUB" in visible
    assert "Saved" in visible


def test_the_landing_pricing_quotes_the_app_settings(web):
    """The free card describes the live product, so its numbers have to be the ones the
    quota and the retention sweep actually enforce. Both expectations are computed from
    the app settings here: a page that hardcoded "100 MB" or "7 days" would keep saying so
    after the plan changed, and the first person to notice would be a user at their limit.
    """
    client, _ = web
    body = client.get("/").text

    assert _human_size(client.app.state.settings.free_quota_bytes) in body
    assert f"Kept {client.app.state.settings.free_retention.days} days" in body
    assert _human_size(client.app.state.settings.paid_quota_bytes) in body
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
    assert "start a blank email and put only its URL in Subject" in body
    assert (
        "For a link, start a blank email, put one webpage URL alone in the subject, "
        f"and send it to your @{INBOX_DOMAIN} address. It appears in Saved."
    ) in body


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

    assert f"See how it works: forward a newsletter to your @{INBOX_DOMAIN} address" in body
    assert "put one webpage URL alone in Subject" in body
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
    assert "verification email" in response.text
    assert "fetched once" in response.text
    assert "public webpage html" in response.text.lower()
    assert "webpage images" in response.text.lower()
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


def test_the_account_names_links_as_an_inbox_option(web):
    client, sent = web
    _sign_up(client, sent)

    assert "Send books, newsletters, and links here" in client.get("/account").text


def test_the_privacy_retention_number_comes_from_the_app_settings(web):
    """The page promises automatic deletion on a schedule the retention sweep owns. The
    expectation is computed from app settings so the promise and the sweep cannot drift."""
    client, _ = web
    body = client.get("/privacy").text
    assert f"deleted automatically {client.app.state.settings.free_retention.days} days after it" in body


def test_the_terms_page_is_honest_about_the_beta(web):
    client, _ = web
    response = client.get("/terms")

    assert response.status_code == 200
    assert "free public beta" in response.text
    assert "change, break or lose data without notice" in response.text
    assert "One account per person" in response.text
    assert "no warranty of any kind" in response.text
    assert "AGPL" in response.text


def test_the_terms_free_plan_limits_come_from_the_app_settings(web):
    client, _ = web
    body = client.get("/terms").text
    assert f"{_human_size(client.app.state.settings.free_quota_bytes)} of storage" in body
    assert f"deleted automatically {client.app.state.settings.free_retention.days} days after it" in body


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
    assert f"deleted automatically {client.app.state.settings.free_retention.days} days after it" in body
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
    for path in ("/account", "/", "/account?q=x", "/account/library", "/account/library?shelf=books"):
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


# -- temporary email verification relay -------------------------------------


def test_email_verification_section_arms_and_disarms_a_five_minute_relay(tmp_path, monkeypatch):
    from steepd.web import EMAIL_VERIFICATION_RELAY_DURATION

    client, sent = _build_client(
        tmp_path,
        monkeypatch,
        resend_api_key="key",
        resend_webhook_secret="secret",
        mail_from_address="Steepd <noreply@example.test>",
    )
    _sign_up(client, sent)
    database = client.app.state.database
    tenant = database.tenant_by_email(EMAIL)

    page = BeautifulSoup(client.get("/account").text, "html.parser")
    heading = page.find("h2", string="Email Verification")
    assert heading is not None
    section = heading.find_parent("section")
    checkbox = section.find("input", {"name": "enabled"})
    assert checkbox is not None and not checkbox.has_attr("checked") and not checkbox.has_attr("disabled")
    assert "Gmail" in section.get_text(" ")
    assert EMAIL in section.get_text(" ")
    assert "first email" in section.get_text(" ").lower()
    assert "five minutes" in section.get_text(" ").lower()

    before = datetime.now(UTC)
    armed = client.post(
        "/account/email-verification", data={"enabled": "yes"}, follow_redirects=False
    )
    after = datetime.now(UTC)

    assert armed.status_code == 303 and armed.headers["location"] == "/account"
    expires_at = database.email_verification_relay_expires_at(tenant.id, now=before.isoformat())
    assert expires_at is not None
    expiry = datetime.fromisoformat(expires_at)
    assert before + EMAIL_VERIFICATION_RELAY_DURATION <= expiry <= after + EMAIL_VERIFICATION_RELAY_DURATION
    checkbox = BeautifulSoup(client.get("/account").text, "html.parser").find(
        "input", {"name": "enabled"}
    )
    assert checkbox is not None and checkbox.has_attr("checked")

    disarmed = client.post("/account/email-verification", data={}, follow_redirects=False)
    assert disarmed.status_code == 303
    assert database.email_verification_relay_expires_at(tenant.id, now=datetime.now(UTC).isoformat()) is None


def test_email_verification_checkbox_is_disabled_when_outbound_mail_is_unavailable(web):
    client, sent = web
    _sign_up(client, sent)
    database = client.app.state.database
    tenant = database.tenant_by_email(EMAIL)

    page = BeautifulSoup(client.get("/account").text, "html.parser")
    heading = page.find("h2", string="Email Verification")
    assert heading is not None
    checkbox = heading.find_parent("section").find("input", {"name": "enabled"})
    assert checkbox is not None and checkbox.has_attr("disabled")

    response = client.post("/account/email-verification", data={"enabled": "yes"})
    assert response.status_code == 503
    assert "not available" in response.text.lower()
    assert database.email_verification_relay_expires_at(tenant.id, now=datetime.now(UTC).isoformat()) is None


def test_sender_routes_need_a_session_and_same_origin(web):
    client, _ = web
    signed_out = client.post("/account/senders/add", data={"address": "a@b.c"}, follow_redirects=False)
    assert signed_out.headers["location"] == "/signin"
    cross_site = client.post(
        "/account/senders/policy", data={"policy": "listed"}, headers={"Origin": "https://evil.example"}
    )
    assert cross_site.status_code == 403


# -- newsletters and publications -------------------------------------------
# Every POST here has a fixed path with the ids in the body, which is what lets the
# exact-path body-size middleware in app.py cover them all without learning patterns.


def _newsletter_client(tmp_path, monkeypatch, **overrides):
    client, sent = _build_client(
        tmp_path, monkeypatch,
        newsletter_ai_enabled=True, newsletter_ai_key="sk-or-test", newsletter_ai_model="test/model",
        **overrides,
    )
    _sign_up(client, sent)
    database = client.app.state.database
    tenant = database.tenant_by_email(EMAIL)
    return client, database, TenantScope(tenant.id)


def _newsletter_item(database, scope, item_id, *, title, created=None):
    database.insert_item(
        scope,
        Item(
            id=item_id, tenant_id=scope.tenant_id, kind="article", sha256=hashlib.sha256(item_id.encode()).hexdigest(),
            storage_name=f"{item_id}.epub", download_filename=f"{title}.epub", title=title, author="",
            language="en", identifier=f"urn:{item_id}", source_url="", size_bytes=100,
            created_at=(created or datetime.now(UTC)).isoformat(), expires_at=None, source="newsletter",
        ),
    )



def _publication(database, scope, publication_id, name, *, now):
    """A publication row without an issue, the way an owner's earlier correction left one.

    Inserted directly: production creates publications only alongside an assignment, and
    these tests want the bare record to exercise everything downstream of that.
    """
    with database._connect() as connection:
        connection.execute(
            """
            INSERT INTO publications (
                tenant_id, id, name, original_name, identification_note, merged_into_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, '', NULL, ?, ?)
            """,
            (scope.tenant_id, publication_id, name, name, now, now),
        )

def _submitted_revision(client) -> str:
    """The settings revision the page actually rendered.

    Read from the form rather than assumed, because assuming it is what let a bug through
    where the first enable on a new account always conflicted: the empty form rendered one
    number and the save expected another, so the feature could never be switched on.
    """
    match = re.search(r'name="settings_revision" value="(\d+)"', client.get("/account").text)
    assert match, "the newsletters page did not render a settings revision"
    return match.group(1)


def _enable_organization(client) -> None:
    response = client.post(
        "/account/newsletters/settings",
        data={"enabled": "yes", "consent_version": "1", "settings_revision": _submitted_revision(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text


def test_the_enable_form_states_how_much_it_will_organize(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    for index in range(3):
        _newsletter_item(database, scope, f"i{index}", title=f"Issue {index}")

    page = client.get("/account")

    assert "3 unprocessed newsletters" in page.text
    assert "OpenRouter" in page.text, "what leaves the server is stated before it leaves"
    assert "Your reader password and account credentials are never sent" in page.text


def test_a_large_backlog_says_it_will_take_more_than_a_day(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch, newsletter_ai_daily_limit=2)
    for index in range(5):
        _newsletter_item(database, scope, f"i{index}", title=f"Issue {index}")

    page = client.get("/account")

    assert "Up to 2 are processed a day" in page.text


def test_turning_it_on_and_off_is_recorded_with_its_consent(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)

    on = client.post(
        "/account/newsletters/settings",
        data={"enabled": "yes", "consent_version": "1", "settings_revision": _submitted_revision(client)},
        follow_redirects=False,
    )

    assert on.status_code == 303, "a brand-new account must be able to turn this on at all"
    preferences = database.newsletter_preferences(scope)
    assert (preferences.enabled, preferences.consent_version) == (True, 1)
    assert preferences.consented_at is not None

    client.post(
        "/account/newsletters/settings",
        data={"enabled": "no", "settings_revision": str(preferences.settings_revision)},
    )
    assert database.newsletter_preferences(scope).enabled is False


def test_a_stale_settings_form_cannot_undo_a_later_choice(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    _enable_organization(client)
    current = database.newsletter_preferences(scope).settings_revision
    client.post("/account/newsletters/settings", data={"enabled": "no", "settings_revision": str(current)})

    replayed = client.post(
        "/account/newsletters/settings",
        # The consent field is present and current, so the only thing left to refuse
        # this is the revision check itself.
        data={"enabled": "yes", "consent_version": "1", "settings_revision": str(current)},
    )

    assert replayed.status_code == 409
    assert database.newsletter_preferences(scope).enabled is False


def test_a_plan_outside_the_deployment_is_told_rather_than_silently_ignored(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch, newsletter_ai_plans=("paid",))

    page = client.get("/account")
    refused = client.post("/account/newsletters/settings", data={"enabled": "yes", "settings_revision": "0"})

    assert "not available on this server" in page.text
    assert refused.status_code == 400
    assert database.newsletter_preferences(scope) is None


def test_an_owner_can_name_a_publication_and_then_correct_themselves(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    _newsletter_item(database, scope, "i1", title="Issue one")

    client.post("/account/newsletters/assign", data={"item_id": "i1", "new_name": "Stratechery"})
    first = database.organization_row(scope, "i1")["publication_id"]

    client.post("/account/newsletters/assign", data={"item_id": "i1", "new_name": "Dense Discovery"})
    second = database.organization_row(scope, "i1")["publication_id"]

    assert first != second, "a second correction must not be refused by the first"
    assert database.publication(scope, second).name == "Dense Discovery"

    client.post("/account/newsletters/assign", data={"item_id": "i1", "publication_id": ""})
    row = database.organization_row(scope, "i1")
    assert (row["manual"], row["publication_id"]) == (1, None), "Keep ungrouped is a decision"


def test_submitting_the_same_new_publication_twice_makes_only_one(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    _newsletter_item(database, scope, "i1", title="Issue one")

    for _ in range(2):
        client.post("/account/newsletters/assign", data={"item_id": "i1", "new_name": "Stratechery"})

    assert len(database.canonical_publications(scope)) == 1


def test_another_tenants_item_and_publication_are_both_refused(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    intruder = database.create_tenant(email="other@example.test", inbox_local="other")
    other_scope = TenantScope(intruder.id)
    _newsletter_item(database, other_scope, "theirs", title="Not yours")
    _publication(database, other_scope, "theirpub", "Theirs", now=datetime.now(UTC).isoformat()
    )
    _newsletter_item(database, scope, "mine", title="Mine")

    assert client.post("/account/newsletters/assign", data={"item_id": "theirs", "new_name": "X"}).status_code == 400
    assert (
        client.post("/account/newsletters/assign", data={"item_id": "mine", "publication_id": "theirpub"})
    ).status_code == 400
    assert client.get("/account/publications/theirpub").status_code == 404
    assert database.organization_row(other_scope, "theirs") is None


def test_renaming_keeps_the_url_and_combining_keeps_the_old_one_working(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    for index, name in enumerate(("Alpha", "Beta")):
        _newsletter_item(database, scope, f"i{index}", title=f"Issue {index}")
        client.post("/account/newsletters/assign", data={"item_id": f"i{index}", "new_name": name})
    alpha, beta = sorted(database.canonical_publications(scope), key=lambda p: p.name)

    client.post(
        "/account/newsletters/publication",
        data={"publication_id": alpha.id, "name": "Alpha Weekly", "identification_note": "The one by Ada"},
    )
    renamed = client.get(f"/account/publications/{alpha.id}")

    assert renamed.status_code == 200 and "Alpha Weekly" in renamed.text
    assert database.publication(scope, alpha.id).original_name == "Alpha"

    client.post("/account/newsletters/merge", data={"source_id": alpha.id, "target_id": beta.id})
    old_url = client.get(f"/account/publications/{alpha.id}")

    assert old_url.status_code == 200 and "Beta" in old_url.text
    assert database.organization_row(scope, "i0")["publication_id"] == beta.id


def test_a_stale_merge_form_asks_for_a_fresh_choice_rather_than_guessing(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    for index, name in enumerate(("Alpha", "Beta", "Gamma")):
        _newsletter_item(database, scope, f"i{index}", title=f"Issue {index}")
        client.post("/account/newsletters/assign", data={"item_id": f"i{index}", "new_name": name})
    alpha, beta, gamma = sorted(database.canonical_publications(scope), key=lambda p: p.name)
    client.post("/account/newsletters/merge", data={"source_id": alpha.id, "target_id": beta.id})

    replayed = client.post("/account/newsletters/merge", data={"source_id": alpha.id, "target_id": gamma.id})

    assert replayed.status_code == 409
    assert database.publication(scope, alpha.id).merged_into_id == beta.id


def test_retry_selects_by_item_and_ignores_a_stale_result_token(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    for index in range(3):
        _newsletter_item(database, scope, f"i{index}", title=f"Issue {index}")
    _enable_organization(client)
    failed = []
    for index in range(2):
        # The claim decides which item it takes, so the test follows it rather than
        # assuming an order.
        claimed = database.claim_organization_item(
            scope, now=datetime.now(UTC).isoformat(), lease_token=f"tok{index}",
            lease_until=(datetime.now(UTC) + timedelta(minutes=2)).isoformat(),
            retention_cutoff=None, max_attempts=2,
        )
        database.record_organization_outcome(
            scope, claimed.item_id, guard=_guard_for(database, scope, f"tok{index}"),
            state="failed", error_code="provider_unavailable",
        )
        failed.append((claimed.item_id, f"tok{index}"))

    (retried, token), (untouched, _) = failed
    page = client.get("/account/newsletters")
    assert f'name="item_{retried}"' in page.text and f'value="{token}"' in page.text

    # Sparse selection: only one box is ticked, and the other carries a token that has
    # since been replaced, so it matches nothing.
    client.post("/account/newsletters/retry", data={f"item_{retried}": token, f"item_{untouched}": "stale"})

    assert database.organization_row(scope, retried)["state"] == "retry"
    assert database.organization_row(scope, untouched)["state"] == "failed", "a stale token matches nothing"


def _guard_for(database, scope, token):
    from steepd.models import OrganizationGuard

    preferences = database.newsletter_preferences(scope)
    return OrganizationGuard(
        lease_token=token,
        settings_revision=preferences.settings_revision,
        catalogue_revision=preferences.catalogue_revision,
        plan="free",
        retention_cutoff=None,
        now=datetime.now(UTC).isoformat(),
    )


def test_a_long_unicode_form_is_bounded_by_bytes_not_characters(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    _newsletter_item(database, scope, "i1", title="Issue one")
    client.post("/account/newsletters/assign", data={"item_id": "i1", "new_name": "Alpha"})
    publication = database.canonical_publications(scope)[0]

    # 620 astral-plane characters is 7.4 KiB once percent-encoded: inside the 16 KiB the
    # middleware allows for these paths, and comfortably over the old 8 KiB.
    accepted = client.post(
        "/account/newsletters/publication",
        data={"publication_id": publication.id, "name": "😀" * 120, "identification_note": "😀" * 500},
    )
    assert accepted.status_code in (303, 200)
    assert database.publication(scope, publication.id).name == "😀" * 120

    refused = client.post(
        "/account/newsletters/publication",
        data={"publication_id": publication.id, "name": "x" * 200, "identification_note": ""},
    )
    assert refused.status_code == 400, "character limits are still validated separately"

    oversized = client.post(
        "/account/newsletters/publication",
        data={"publication_id": publication.id, "name": "A", "identification_note": "😀" * 20_000},
    )
    assert oversized.status_code == 413


def test_a_publication_name_is_escaped_everywhere_it_is_shown(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    _newsletter_item(database, scope, "i1", title="Issue one")
    client.post("/account/newsletters/assign", data={"item_id": "i1", "new_name": '<script>alert(1)</script>'})

    index = client.get("/account/newsletters")
    detail = client.get(f"/account/publications/{database.canonical_publications(scope)[0].id}")

    for page in (index.text, detail.text):
        assert "<script>alert(1)</script>" not in page
        assert "&lt;script&gt;" in page


def test_a_publication_page_pages_beyond_fifty_issues(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    _newsletter_item(database, scope, "i00", title="Issue 00")
    client.post("/account/newsletters/assign", data={"item_id": "i00", "new_name": "Alpha"})
    publication = database.canonical_publications(scope)[0]
    # The rest join it by id, the way the chooser offers it. Typing the same name again
    # would deliberately make a second publication: names are labels, not identities.
    for index in range(1, 55):
        _newsletter_item(database, scope, f"i{index:02d}", title=f"Issue {index:02d}")
        client.post(
            "/account/newsletters/assign", data={"item_id": f"i{index:02d}", "publication_id": publication.id}
        )

    first = client.get(f"/account/publications/{publication.id}")
    second = client.get(f"/account/publications/{publication.id}?page=2")

    assert "55 issues" in first.text
    assert first.text.count('class="item"') == 50
    assert second.text.count('class="item"') == 5


def test_every_newsletter_post_refuses_a_cross_site_submission(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    paths = (
        "/account/newsletters/settings",
        "/account/newsletters/assign",
        "/account/newsletters/publication",
        "/account/newsletters/merge",
        "/account/newsletters/retry",
    )

    for path in paths:
        response = client.post(path, data={}, headers={"Origin": "https://evil.example"})
        assert response.status_code == 403, path


def test_the_newsletters_page_needs_a_confirmed_session(tmp_path, monkeypatch):
    client, _ = _build_client(tmp_path, monkeypatch)

    assert client.get("/account/newsletters", follow_redirects=False).status_code in (303, 307)
    assert client.get("/account/publications/anything", follow_redirects=False).status_code in (303, 307)


def test_the_privacy_page_stops_claiming_nobody_sees_your_reading(tmp_path, monkeypatch):
    """The old lede was true only while nothing could leave the machine."""
    off, _ = _build_client(tmp_path / "off", monkeypatch)
    on, _ = _build_client(tmp_path / "on", monkeypatch, newsletter_ai_enabled=True)

    quiet = off.get("/privacy").text
    loud = on.get("/privacy").text

    assert "shows none of it to anyone" in quiet.replace("It shows", "shows")
    assert "OpenRouter" not in quiet, "a server that cannot send anywhere should not say it does"

    assert "unless you turn on newsletter organization" in loud
    assert "OpenRouter" in loud
    assert "does not make it anonymous" in loud, "no anonymity claim over newsletter text"
    assert "Deleting your account deletes all of it" in loud


def test_a_brand_new_account_can_turn_organization_on_from_the_page_it_was_offered(tmp_path, monkeypatch):
    """The whole browser round trip, with nothing about the form assumed.

    The regression this pins: the empty form rendered revision 0 while saving created the
    row at revision 1 and then demanded a match, so every first enable was a conflict and
    nobody could ever switch the feature on.
    """
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    assert database.newsletter_preferences(scope) is None

    form = client.get("/account").text
    revision = re.search(r'name="settings_revision" value="(\d+)"', form).group(1)
    saved = client.post(
        "/account/newsletters/settings",
        data={"enabled": "yes", "consent_version": "1", "settings_revision": revision},
        follow_redirects=False,
    )

    assert saved.status_code == 303
    assert database.newsletter_preferences(scope).enabled is True
    assert "Turn off" in client.get("/account").text


def test_an_issue_already_in_a_publication_can_still_be_moved(tmp_path, monkeypatch):
    """Correcting a wrong-but-confident answer is the common case, so the control has to
    be on the issue wherever it is shown -- not only where the classifier gave up."""
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    _newsletter_item(database, scope, "i1", title="Issue one")
    client.post("/account/newsletters/assign", data={"item_id": "i1", "new_name": "Alpha"})
    _newsletter_item(database, scope, "i2", title="Issue two")
    client.post("/account/newsletters/assign", data={"item_id": "i2", "new_name": "Beta"})
    alpha, beta = sorted(database.canonical_publications(scope), key=lambda p: p.name)

    page = client.get(f"/account/publications/{alpha.id}")
    assert 'action="/account/newsletters/assign"' in page.text, "no way to correct an organized issue"
    assert beta.id in page.text, "and no other publication offered to move it to"

    client.post("/account/newsletters/assign", data={"item_id": "i1", "publication_id": beta.id})
    assert database.organization_row(scope, "i1")["publication_id"] == beta.id


def test_older_unorganized_issues_stay_reachable_beyond_the_first_page(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    for index in range(55):
        _newsletter_item(
            database, scope, f"i{index:02d}", title=f"Issue {index:02d}",
            created=datetime.now(UTC) - timedelta(minutes=index),
        )

    first = client.get("/account/newsletters")
    second = client.get("/account/newsletters?page=2")

    assert "55 issues" in first.text
    assert "Issue 00" in first.text and "Issue 54" not in first.text
    assert "Issue 54" in second.text, "the oldest issue must still be correctable"


def test_a_form_showing_the_old_wording_cannot_record_agreement_to_the_new(tmp_path, monkeypatch):
    """Recording the server's current version regardless meant a policy change silently
    inherited consent nobody had been shown."""
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)

    stale = client.post(
        "/account/newsletters/settings",
        data={"enabled": "yes", "consent_version": "0", "settings_revision": _submitted_revision(client)},
    )

    assert stale.status_code == 409
    assert database.newsletter_preferences(scope) is None or not database.newsletter_preferences(scope).enabled


def test_superseded_consent_says_paused_and_offers_the_new_description(tmp_path, monkeypatch):
    """The worker stops sending for this account, so the page must not keep saying On with
    nothing but a Turn off button."""
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    _enable_organization(client)
    assert "On. This organizes the newsletters already in your library" in client.get("/account").text
    monkeypatch.setattr("steepd.web.CONSENT_VERSION", 2)

    page = client.get("/account").text

    assert "Paused" in page and "changed since you turned it on" in page
    assert 'value="2"' in page, "the current version is what the new form submits"
    assert "Turn on again" in page
    assert "Automatic organization is paused" in client.get("/account/newsletters").text, "not on: nothing is sent"


def test_a_server_that_cannot_classify_does_not_offer_the_setting(tmp_path, monkeypatch):
    """Default settings: no service flag, no key. Offering Turn on here collects consent
    for something that will never run, while the privacy page says nothing leaves."""
    client, sent = _build_client(tmp_path, monkeypatch)
    _sign_up(client, sent)
    database = client.app.state.database
    scope = TenantScope(database.tenant_by_email(EMAIL).id)

    page = client.get("/account").text
    refused = client.post(
        "/account/newsletters/settings",
        data={"enabled": "yes", "consent_version": "1", "settings_revision": "0"},
    )

    assert "not available on this server" in page
    # The organize form's own field, a hidden input; the verification checkbox shares the name.
    assert '<input type="hidden" name="enabled" value="yes">' not in page
    assert refused.status_code == 400
    assert database.newsletter_preferences(scope) is None


def test_the_enable_form_counts_only_what_the_worker_will_process(tmp_path, monkeypatch):
    """Keep-ungrouped, unrecognized and failed issues are never re-analyzed, so a count
    that includes them promises work that will not happen."""
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    _newsletter_item(database, scope, "waiting", title="Waiting")
    _newsletter_item(database, scope, "kept", title="Kept ungrouped")
    database.assign_publication_manually(scope, "kept", publication_id=None, now=datetime.now(UTC).isoformat())

    page = client.get("/account").text

    assert "<strong>1 unprocessed newsletter</strong>" in page


def test_the_privacy_page_names_everything_the_request_carries(tmp_path, monkeypatch):
    on, _ = _build_client(tmp_path, monkeypatch, newsletter_ai_enabled=True)

    page = on.get("/privacy").text

    for phrase in ("identification note", "issues you assigned by hand", "earlier names"):
        assert phrase in page, phrase
    assert "and nothing else" not in page, "publication names and notes go too"


def test_an_emptied_publication_stays_reachable_for_renaming_or_combining(tmp_path, monkeypatch):
    """A typo publication corrected away has no issues, so it leaves the shelf -- but it is
    still offered to the model and in every chooser, so it needs a page to fix it from."""
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    _newsletter_item(database, scope, "i1", title="Issue one")
    client.post("/account/newsletters/assign", data={"item_id": "i1", "new_name": "Stratechry"})
    typo = database.canonical_publications(scope)[0]
    client.post("/account/newsletters/assign", data={"item_id": "i1", "new_name": "Stratechery"})

    page = client.get("/account/newsletters").text

    assert f'href="/account/publications/{typo.id}"' in page
    assert "Stratechry" in page


def test_an_account_moved_off_an_offered_plan_can_still_turn_it_off(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch, newsletter_ai_plans=("paid",))
    database.set_newsletter_organization(
        scope, enabled=True, consent_version=1, settings_revision=None, now=datetime.now(UTC).isoformat()
    )

    page = client.get("/account").text
    assert "Turn off" in page, "consent must be withdrawable even where nothing is being sent"

    revision = re.search(r'name="settings_revision" value="(\d+)"', page).group(1)
    off = client.post(
        "/account/newsletters/settings", data={"enabled": "no", "settings_revision": revision}, follow_redirects=False
    )
    assert off.status_code == 303
    assert database.newsletter_preferences(scope).enabled is False


def test_a_populated_publication_past_the_first_fifty_is_not_called_empty(tmp_path, monkeypatch):
    """Emptiness must come from membership, not from absence in a page-sized list."""
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    now = datetime.now(UTC).isoformat()
    for index in range(51):
        _newsletter_item(database, scope, f"i{index:02d}", title=f"Issue {index:02d}")
        client.post("/account/newsletters/assign", data={"item_id": f"i{index:02d}", "new_name": f"Pub {index:02d}"})
    _publication(database, scope, "hollow", "Zed Hollow", now=now)

    page = client.get("/account/newsletters").text
    empty_section = page.split("<h2>Empty publications</h2>", 1)[1]

    assert "Zed Hollow" in empty_section
    assert "Pub " not in empty_section, "every populated publication is populated, whatever page it is on"
    assert page.count("Pub ") == 51, "and every populated one is on the shelf"


def test_the_enable_form_counts_work_that_resumes_on_re_enabling(tmp_path, monkeypatch):
    """A claim released before dispatch -- the setting went off in between -- is a retry
    row with no attempts spent. Enabling again picks it up, so the count must say so."""
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    _newsletter_item(database, scope, "i1", title="Issue one")
    now = datetime.now(UTC)
    database.claim_organization_item(
        scope, now=now.isoformat(), lease_token="t", lease_until=(now + timedelta(minutes=2)).isoformat(),
        retention_cutoff=None, max_attempts=2,
    )
    database.release_organization_claim(scope, "i1", lease_token="t", now=now.isoformat())

    page = client.get("/account").text

    assert "<strong>1 unprocessed newsletter</strong>" in page


# -- shelves ------------------------------------------------------------------
# The account page mirrors what a reader shows: one shelf per kind, with a count. The
# lists themselves live on /account/library and are filtered by the shelf parameter.


def _insert_kind(client, tenant, item_id, *, title, kind, source, created=None, source_url=""):
    client.app.state.database.insert_item(
        TenantScope(tenant.id),
        Item(
            id=item_id, tenant_id=tenant.id, kind=kind, sha256=hashlib.sha256(item_id.encode()).hexdigest(),
            storage_name=f"{item_id}.epub", download_filename=f"{item_id}.epub", title=title, author="",
            language="en", identifier=f"urn:{item_id}", source_url=source_url, size_bytes=100,
            created_at=(created or datetime.now(UTC)).isoformat(), expires_at=None, source=source,
        ),
    )


def _mixed_library(client, tenant):
    """Two newsletters, one saved page, one book. Newsletters and saved pages are both
    articles, so a shelf that filtered on kind alone could not tell them apart."""
    _insert_kind(client, tenant, "n1", title="Issue one", kind="article", source="newsletter")
    _insert_kind(client, tenant, "n2", title="Issue two", kind="article", source="newsletter")
    _insert_kind(client, tenant, "s1", title="A saved page", kind="article", source="url")
    _insert_kind(client, tenant, "b1", title="A book", kind="book", source="email")


def test_the_account_page_lists_the_reader_shelves_with_counts(web):
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _mixed_library(client, tenant)
    other = client.app.state.database.create_tenant(email="other@example.test", inbox_local="other")
    _insert_kind(client, other, "theirs", title="Not yours", kind="book", source="email")

    body = client.get("/account").text
    shelves = re.search(r"<h2>Your library</h2>(.*?)</section>", body, re.S).group(1)

    assert '<a href="/account/library">Recent</a>' in shelves and "4 items" in shelves
    assert '<a href="/account/newsletters">Newsletters</a>' in shelves and "2 items" in shelves
    assert '<a href="/account/library?shelf=saved">Saved</a>' in shelves and "1 item<" in shelves
    assert '<a href="/account/library?shelf=books">Books</a>' in shelves
    assert "Not yours" not in body and "Issue one" not in body, "the account page is an index, not a list"


def test_each_shelf_lists_only_its_own_kind(web):
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _mixed_library(client, tenant)

    newsletters = client.get("/account/library", params={"shelf": "newsletters"}).text
    assert _listed_titles(newsletters) == ["Issue two", "Issue one"]
    assert _listed_titles(client.get("/account/library", params={"shelf": "saved"}).text) == ["A saved page"]
    assert _listed_titles(client.get("/account/library", params={"shelf": "books"}).text) == ["A book"]
    assert len(_listed_titles(client.get("/account/library").text)) == 4
    assert len(_listed_titles(client.get("/account/library", params={"shelf": "nonsense"}).text)) == 4


def test_search_sort_and_paging_stay_on_the_shelf(web):
    """Every control the shelf page emits has to carry the shelf, or one click drops the
    reader back into the whole library."""
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    base = datetime(2026, 1, 1, tzinfo=UTC)
    for index in range(30):
        _insert_kind(client, tenant, f"n{index:02d}", title=f"Issue {index:02d}", kind="article",
                     source="newsletter", created=base + timedelta(minutes=index))
    _insert_kind(client, tenant, "b1", title="Issue book", kind="book", source="email")

    first = client.get("/account/library", params={"shelf": "newsletters"})
    assert len(_listed_titles(first.text)) == 25
    assert "Issue book" not in first.text
    assert 'name="shelf" value="newsletters"' in first.text, "the search form carries the shelf"

    second = client.get(_followable(first.text, "Next"))
    assert "Issue book" not in second.text and len(_listed_titles(second.text)) == 5

    by_title = client.get(_followable(first.text, "Title"))
    assert "Issue book" not in by_title.text and _listed_titles(by_title.text)[0] == "Issue 00"

    searched = client.get("/account/library", params={"shelf": "newsletters", "q": "Issue"})
    assert "30 items match" in searched.text, "the book called Issue is not on this shelf"
    cleared = client.get(_followable(searched.text, "Clear"))
    assert "Issue book" not in cleared.text and len(_listed_titles(cleared.text)) == 25


def test_an_empty_shelf_in_a_populated_library_says_so_plainly(web):
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _insert_kind(client, tenant, "b1", title="A book", kind="book", source="email")

    body = client.get("/account/library", params={"shelf": "saved"}).text

    assert "Nothing here yet." in body
    assert "matches that search" not in body, "no search was made"
    assert 'href="/account"' in body, "a way back to the account page"


def test_old_account_links_are_redirected_to_the_library(web):
    """Bookmarks and emailed links carry q, sort and page on /account. They keep working by
    redirect, with the query passed through untouched for the library route to clean."""
    client, sent = web
    _signed_in_tenant(client, sent)

    for query in ("page=2", "q=tea&sort=title", "q="):
        response = client.get(f"/account?{query}", follow_redirects=False)
        assert response.status_code == 303, query
        assert response.headers["location"] == f"/account/library?{query}", query
    assert client.get("/account", follow_redirects=False).status_code == 200


def test_the_newsletters_page_says_existing_newsletters_are_organized_too(tmp_path, monkeypatch):
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    _newsletter_item(database, scope, "i1", title="Issue one")
    _enable_organization(client)

    account = client.get("/account").text
    page = client.get("/account/newsletters").text

    assert "On. This organizes the newsletters already in your library" in account
    assert "1 waiting" in account
    assert "Automatic organization is on" in page and 'href="/account"' in page, "the page says where the setting is"
    assert 'href="/account/library?shelf=newsletters"' in page, "a link to every issue, organized or not"


def test_the_landing_page_explains_newsletter_organization(web):
    client, _ = web
    for accept in ("text/html", "text/markdown"):
        body = client.get("/", headers={"Accept": accept}).text
        assert "by publication" in body, accept
        assert "off until you turn it on" in body, accept


# -- saved pages by site ------------------------------------------------------


def test_the_saved_shelf_lists_sites_and_a_site_narrows_the_list(web):
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    base = datetime(2026, 1, 1, tzinfo=UTC)
    for index in range(26):
        _insert_kind(client, tenant, f"s{index:02d}", title=f"Essay {index:02d}", kind="article", source="url",
                     source_url=f"https://www.paulgraham.com/{index}.html", created=base + timedelta(minutes=index))
    _insert_kind(client, tenant, "t1", title="A news story", kind="article", source="url",
                 source_url="https://nytimes.com/story")

    shelf = client.get("/account/library", params={"shelf": "saved"})
    assert len(_listed_titles(shelf.text)) == 25, "the page list is untouched by the site list"
    sites = re.search(r'<p class="fineprint sites">(.*?)</p>', shelf.text, re.S).group(1)
    assert 'href="/account/library?shelf=saved&amp;site=paulgraham.com">paulgraham.com</a> (26)' in sites
    assert 'href="/account/library?shelf=saved&amp;site=nytimes.com">nytimes.com</a> (1)' in sites

    site = client.get(_followable(shelf.text, "paulgraham.com"))
    assert "<h1>paulgraham.com</h1>" in site.text
    assert "A news story" not in site.text and len(_listed_titles(site.text)) == 25
    assert 'name="site" value="paulgraham.com"' in site.text, "the search form carries the site"

    second = client.get(_followable(site.text, "Next"))
    assert "A news story" not in second.text and _listed_titles(second.text) == ["Essay 00"]
    by_title = client.get(_followable(site.text, "Title"))
    assert "A news story" not in by_title.text and _listed_titles(by_title.text)[0] == "Essay 00"
    searched = client.get("/account/library", params={"shelf": "saved", "site": "paulgraham.com", "q": "Essay 1"})
    assert "10 items match" in searched.text
    cleared = client.get(_followable(searched.text, "Clear"))
    assert "A news story" not in cleared.text and len(_listed_titles(cleared.text)) == 25

    back = client.get(_followable(site.text, "Saved"))
    assert "A news story" in back.text, "the shelf link drops the site"


def test_a_site_is_ignored_off_the_saved_shelf_and_when_malformed(web):
    client, sent = web
    tenant = _signed_in_tenant(client, sent)
    _insert_kind(client, tenant, "s1", title="Essay", kind="article", source="url", source_url="https://a.example/1")
    _insert_kind(client, tenant, "s2", title="Story", kind="article", source="url", source_url="https://b.example/2")
    _insert_kind(client, tenant, "b1", title="A book", kind="book", source="email")

    books = client.get("/account/library", params={"shelf": "books", "site": "a.example"}).text
    assert _listed_titles(books) == ["A book"]
    malformed = client.get("/account/library", params={"shelf": "saved", "site": "bad host"}).text
    assert sorted(_listed_titles(malformed)) == ["Essay", "Story"]
    assert "<h1>Saved</h1>" in malformed


def test_the_landing_page_says_saved_pages_are_grouped_by_site(web):
    client, _ = web
    for accept in ("text/html", "text/markdown"):
        assert "grouped by the site they came from" in client.get("/", headers={"Accept": accept}).text, accept


def test_the_organize_setting_is_on_the_account_page_above_the_library(tmp_path, monkeypatch):
    """Two clicks down, behind a shelf link that only shows a count, nobody finds it. The
    long part of the consent text folds away so the account page stays short."""
    client, database, scope = _newsletter_client(tmp_path, monkeypatch)
    _newsletter_item(database, scope, "i1", title="Issue one")

    page = client.get("/account").text

    assert page.index("Organize my newsletters") < page.index("<h2>Your library</h2>")
    # A plain section like Senders and Device password, not a boxed card, and the
    # progress line lives inside it rather than floating below.
    section = page[page.index("<section><h2>Organize my newsletters</h2>"):]
    section = section[: section.index("</section>")]
    assert "1 waiting" in section and "Refresh" in section
    assert "—" not in section
    folded = re.search(r"<details>(.*?)</details>", page, re.S)
    assert folded, "the sending paragraph is collapsible"
    assert "<summary>" in folded.group(1) and "Steepd sends newsletter text" in folded.group(1)
    assert "1 unprocessed newsletter" in page and "Turn on" in page, "the short part stays visible"
    assert "Organize my newsletters" not in client.get("/account/newsletters").text, "one place for the setting"


def test_a_server_pause_is_reported_even_when_the_daily_allowance_is_also_spent(tmp_path, monkeypatch):
    """A rejected key needs the operator; "continues tomorrow" would be a false promise."""
    from steepd.publications import WorkerStatus

    client, database, scope = _newsletter_client(tmp_path, monkeypatch, newsletter_ai_daily_limit=1)
    _newsletter_item(database, scope, "i1", title="Issue one")
    _enable_organization(client)
    with database._connect() as connection:
        connection.execute(
            "UPDATE newsletter_preferences SET attempt_day = ?, attempts_today = 1 WHERE tenant_id = ?",
            (datetime.now(UTC).date().isoformat(), scope.tenant_id),
        )
    client.app.state.organizer.status = WorkerStatus(paused_code="auth_rejected", paused_at="now")

    page = client.get("/account").text

    assert "needs attention from its operator" in page
    assert "continues tomorrow" not in page
