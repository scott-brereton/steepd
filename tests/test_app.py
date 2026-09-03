"""End-to-end tests for the wired application.

Several tests here deliberately follow generated hrefs rather than constructing URLs.
The feed builders in steepd.opds derive their own self/previous/next links from a
feed_id, so a route registered at a path the feed does not emit produces a catalogue
that renders perfectly and navigates nowhere. Constructing the URL in the test would
hide exactly that.
"""

from __future__ import annotations

import base64
import gc
import xml.etree.ElementTree as ElementTree
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from steepd.app import create_app
from steepd.auth import consume_magic_token, issue_magic_token
from steepd.config import Settings
from steepd.epubgen import build_epub
from steepd.inbound import InboundEmailDisabled, InvalidWebhookSignature
from steepd.models import Item
from steepd.opds import ATOM, PAGE_SIZE, author_token
from steepd.tenancy import TenantScope

BASE_URL = "http://localhost:8000"


@pytest.fixture
def client_and_tenants(tmp_path):
    settings = Settings(data_dir=tmp_path, public_base_url=BASE_URL)
    app = create_app(settings)  # constructs AND initializes eagerly - see the design note
    client = TestClient(app)
    database = app.state.database
    alice, alice_pw = database.create_tenant_with_password(email="a@example.com", inbox_local="a.1")
    bob, bob_pw = database.create_tenant_with_password(email="b@example.com", inbox_local="b.2")
    return client, (alice, alice_pw), (bob, bob_pw)


def _auth(tenant, password):
    raw = f"{tenant.opds_username}:{password}".encode()
    return {"Authorization": f"Basic {base64.b64encode(raw).decode()}"}


def _store(client, tenant, *, title, author="", kind="book", source="email", identifier="urn:uuid:x"):
    return client.app.state.storage.store_bytes(
        TenantScope(tenant.id),
        build_epub(
            title=title, author=author, language="en", identifier=identifier, body_html=f"<p>{title}</p>"
        ),
        filename=f"{title}.epub",
        kind=kind,
        source=source,
        title=title,
        author=author,
    ).item


def _local_path(href: str) -> str:
    """Strip the configured public base URL, leaving the path the app must serve."""
    assert href.startswith(BASE_URL), href
    return href[len(BASE_URL) :]


def _hrefs(content: bytes, rel: str | None = None) -> list[str]:
    root = ElementTree.fromstring(content)
    return [
        link.get("href")
        for link in root.iter(f"{{{ATOM}}}link")
        if rel is None or link.get("rel") == rel
    ]


def _entry_hrefs(content: bytes) -> list[str]:
    root = ElementTree.fromstring(content)
    return [
        link.get("href")
        for entry in root.iter(f"{{{ATOM}}}entry")
        for link in entry.iter(f"{{{ATOM}}}link")
    ]


# -- health and auth ---------------------------------------------------------


def test_health_is_public(client_and_tenants):
    client, _, _ = client_and_tenants
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_opds_requires_auth(client_and_tenants):
    client, _, _ = client_and_tenants
    assert client.get("/opds").status_code == 401


def test_opds_root_returns_a_catalogue(client_and_tenants):
    client, (alice, pw), _ = client_and_tenants
    response = client.get("/opds", headers=_auth(alice, pw))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/atom+xml")
    assert b"<feed" in response.content


def test_wrong_password_is_rejected(client_and_tenants):
    client, (alice, _), (_, bob_pw) = client_and_tenants
    assert client.get("/opds", headers=_auth(alice, bob_pw)).status_code == 401


def test_unauthenticated_opds_asks_the_device_to_authenticate(client_and_tenants):
    # Without this header an e-reader shows an empty library instead of a login prompt.
    client, _, _ = client_and_tenants
    response = client.get("/opds")
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Basic")


def test_unknown_username_is_rejected(client_and_tenants):
    client, (alice, alice_pw), _ = client_and_tenants
    raw = base64.b64encode(b"nobody:" + alice_pw.encode()).decode()
    assert client.get("/opds", headers={"Authorization": f"Basic {raw}"}).status_code == 401


def test_security_headers_are_present(client_and_tenants):
    client, (alice, pw), _ = client_and_tenants
    response = client.get("/opds", headers=_auth(alice, pw))
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


# -- the routes the feed actually points at ----------------------------------


def test_every_href_in_the_root_feed_resolves(client_and_tenants):
    """The root feed's navigation entries name paths this app must serve. A mismatch
    yields a catalogue that looks correct and navigates nowhere."""
    client, (alice, pw), _ = client_and_tenants
    headers = _auth(alice, pw)
    _store(client, alice, title="Alpha", author="One Writer")

    root = client.get("/opds", headers=headers)
    assert root.status_code == 200

    hrefs = _hrefs(root.content) + _entry_hrefs(root.content)
    # The search link is an OpenSearch template, not a fetchable URL.
    targets = [href for href in hrefs if "{searchTerms}" not in href]
    assert len(targets) >= 5
    for href in targets:
        assert client.get(_local_path(href), headers=headers).status_code == 200, href


@pytest.mark.parametrize(
    ("path", "feed_id"),
    [
        ("/opds/recent", "recent"),
        ("/opds/newsletters", "newsletters"),
        ("/opds/saved", "saved"),
        ("/opds/books", "books"),
    ],
)
def test_each_section_feed_reports_its_own_path_as_self(client_and_tenants, path, feed_id):
    """build_items_catalog derives self/previous/next as /opds/{feed_id}. If a route is
    registered under one path but passes a different feed_id, page 1 still renders --
    only page 2 onwards breaks. Comparing the self link to the requested path catches
    the wrong feed_id on page 1."""
    client, (alice, pw), _ = client_and_tenants
    response = client.get(path, headers=_auth(alice, pw))
    assert response.status_code == 200
    assert _hrefs(response.content, rel="self") == [f"{BASE_URL}/opds/{feed_id}"]
    assert _local_path(_hrefs(response.content, rel="self")[0]) == path


def test_pagination_links_resolve(client_and_tenants):
    """Rows are inserted directly: this test is about link targets, not stored files."""
    client, (alice, pw), _ = client_and_tenants
    headers = _auth(alice, pw)
    database = client.app.state.database
    scope = TenantScope(alice.id)
    for index in range(PAGE_SIZE + 1):
        database.insert_item(
            scope,
            Item(
                id=f"{index:032x}",
                tenant_id=alice.id,
                kind="book",
                sha256=f"{index:064x}",
                storage_name=f"{index:032x}.epub",
                download_filename=f"book-{index}.epub",
                title=f"Book {index}",
                author="One Writer",
                language="en",
                identifier=f"urn:uuid:{index}",
                source_url="",
                size_bytes=100,
                created_at=f"2026-08-28T00:{index:02d}:00+00:00",
                expires_at=None,
                source="email",
            ),
        )

    page_one = client.get("/opds/recent", headers=headers)
    next_links = _hrefs(page_one.content, rel="next")
    assert next_links == [f"{BASE_URL}/opds/recent?page=2"]

    page_two = client.get(_local_path(next_links[0]), headers=headers)
    assert page_two.status_code == 200
    assert _hrefs(page_two.content, rel="previous") == [f"{BASE_URL}/opds/recent?page=1"]
    assert client.get(_local_path(_hrefs(page_two.content, rel="previous")[0]), headers=headers).status_code == 200

    # The pages themselves, not just their links. next/previous derive from count_items, so
    # they look right even when the query returns a short page: mutating list_items' limit to
    # PAGE_SIZE - 1 silently drops one row per page and every link assertion above still
    # holds. Counting entries and checking the two pages do not overlap is what catches it.
    def titles(content):
        root = ElementTree.fromstring(content)
        return [entry.findtext(f"{{{ATOM}}}title") for entry in root.iter(f"{{{ATOM}}}entry")]

    first, second = titles(page_one.content), titles(page_two.content)
    assert len(first) == PAGE_SIZE
    assert len(second) == 1
    assert not set(first) & set(second)
    assert sorted(first + second) == sorted(f"Book {index}" for index in range(PAGE_SIZE + 1))


def test_section_feeds_filter_by_kind_and_source(client_and_tenants):
    client, (alice, pw), _ = client_and_tenants
    headers = _auth(alice, pw)
    _store(client, alice, title="Book", kind="book", source="email", identifier="urn:uuid:1")
    _store(client, alice, title="Letter", kind="article", source="newsletter", identifier="urn:uuid:2")
    _store(client, alice, title="Link", kind="article", source="url", identifier="urn:uuid:3")

    def titles(path):
        root = ElementTree.fromstring(client.get(path, headers=headers).content)
        return sorted(entry.findtext(f"{{{ATOM}}}title") for entry in root.iter(f"{{{ATOM}}}entry"))

    assert titles("/opds/books") == ["Book"]
    assert titles("/opds/newsletters") == ["Letter"]
    assert titles("/opds/saved") == ["Link"]
    assert titles("/opds/recent") == ["Book", "Letter", "Link"]


def test_search_finds_an_item_by_title(client_and_tenants):
    client, (alice, pw), _ = client_and_tenants
    headers = _auth(alice, pw)
    _store(client, alice, title="Findable", identifier="urn:uuid:1")
    _store(client, alice, title="Other", identifier="urn:uuid:2")

    response = client.get("/opds/search", params={"q": "Finda"}, headers=headers)
    assert response.status_code == 200
    root = ElementTree.fromstring(response.content)
    assert [entry.findtext(f"{{{ATOM}}}title") for entry in root.iter(f"{{{ATOM}}}entry")] == ["Findable"]
    assert _hrefs(response.content, rel="self") == [f"{BASE_URL}/opds/search"]


def test_search_without_a_query_is_rejected(client_and_tenants):
    client, (alice, pw), _ = client_and_tenants
    assert client.get("/opds/search", headers=_auth(alice, pw)).status_code == 422


# -- author browsing ---------------------------------------------------------


def test_author_browse_follows_the_generated_href(client_and_tenants):
    """Follows the href the feed emits rather than building one, so this exercises
    author_token and author_from_token end to end. Building the URL here would leave
    the codec unverified, which is how it went untested in the first place."""
    client, (alice, pw), _ = client_and_tenants
    headers = _auth(alice, pw)
    _store(client, alice, title="Alpha", author="Ursula K. Le Guin", identifier="urn:uuid:1")
    _store(client, alice, title="Beta", author="村上 春樹", identifier="urn:uuid:2")

    authors = client.get("/opds/authors", headers=headers)
    assert authors.status_code == 200
    root = ElementTree.fromstring(authors.content)
    entries = list(root.iter(f"{{{ATOM}}}entry"))
    names = [entry.findtext(f"{{{ATOM}}}title") for entry in entries]
    assert names == ["Ursula K. Le Guin", "村上 春樹"]

    first_href = next(iter(_entry_hrefs(authors.content)))
    response = client.get(_local_path(first_href), headers=headers)
    assert response.status_code == 200
    author_feed = ElementTree.fromstring(response.content)
    assert [entry.findtext(f"{{{ATOM}}}title") for entry in author_feed.iter(f"{{{ATOM}}}entry")] == ["Alpha"]
    # The author feed's own self link must be the URL we followed, or its pages point nowhere.
    assert _local_path(_hrefs(response.content, rel="self")[0]) == _local_path(first_href)


def test_author_browse_survives_a_non_latin_name(client_and_tenants):
    client, (alice, pw), _ = client_and_tenants
    headers = _auth(alice, pw)
    _store(client, alice, title="Beta", author="村上 春樹", identifier="urn:uuid:2")

    href = next(iter(_entry_hrefs(client.get("/opds/authors", headers=headers).content)))
    root = ElementTree.fromstring(client.get(_local_path(href), headers=headers).content)
    assert [entry.findtext(f"{{{ATOM}}}title") for entry in root.iter(f"{{{ATOM}}}entry")] == ["Beta"]


def test_the_unknown_author_shelf_delivers_the_items_it_advertises(client_and_tenants):
    """Newsletters are stored with author="", and list_authors folds every blank author into
    the display name 'Unknown'. The href that entry carries therefore asks for author
    'Unknown', which no row literally holds -- so the shelf counted items it then served
    none of. The filter has to normalise exactly as the grouping does.
    """
    client, (alice, pw), _ = client_and_tenants
    headers = _auth(alice, pw)
    _store(client, alice, title="A Newsletter", author="", kind="article", source="newsletter",
           identifier="urn:uuid:1")
    _store(client, alice, title="Alpha", author="One Writer", identifier="urn:uuid:2")

    authors = client.get("/opds/authors", headers=headers)
    assert authors.status_code == 200
    root = ElementTree.fromstring(authors.content)
    unknown = next(
        entry for entry in root.iter(f"{{{ATOM}}}entry")
        if entry.findtext(f"{{{ATOM}}}title") == "Unknown"
    )
    assert unknown.findtext(f"{{{ATOM}}}content") == "1 item"

    href = next(iter(link.get("href") for link in unknown.iter(f"{{{ATOM}}}link")))
    response = client.get(_local_path(href), headers=headers)
    assert response.status_code == 200
    shelf = ElementTree.fromstring(response.content)
    assert [entry.findtext(f"{{{ATOM}}}title") for entry in shelf.iter(f"{{{ATOM}}}entry")] == ["A Newsletter"]


def test_a_malformed_author_token_is_404(client_and_tenants):
    client, (alice, pw), _ = client_and_tenants
    assert client.get("/opds/authors/not!a!token", headers=_auth(alice, pw)).status_code == 404


def test_authors_are_scoped_to_the_requesting_tenant(client_and_tenants):
    client, (alice, alice_pw), (bob, bob_pw) = client_and_tenants
    _store(client, alice, title="Alpha", author="One Writer", identifier="urn:uuid:1")
    # Bob holds a book by the same author name, under his own tenant. If author scoping
    # ever became a union across tenants instead of a filter, this would leak into
    # Alice's response below. Note this asserts scoping, not pagination arithmetic:
    # both libraries are far under PAGE_SIZE, so a limit off-by-one stays invisible here.
    _store(client, bob, title="Beta", author="One Writer", identifier="urn:uuid:2")
    token = author_token("One Writer")

    alice_response = client.get(f"/opds/authors/{token}", headers=_auth(alice, alice_pw))
    bob_response = client.get(f"/opds/authors/{token}", headers=_auth(bob, bob_pw))
    assert alice_response.status_code == bob_response.status_code == 200

    alice_root = ElementTree.fromstring(alice_response.content)
    bob_root = ElementTree.fromstring(bob_response.content)
    assert [e.findtext(f"{{{ATOM}}}title") for e in alice_root.iter(f"{{{ATOM}}}entry")] == ["Alpha"]
    assert [e.findtext(f"{{{ATOM}}}title") for e in bob_root.iter(f"{{{ATOM}}}entry")] == ["Beta"]


# -- downloads and tenant isolation -----------------------------------------


def test_download_of_another_tenants_item_is_404(client_and_tenants):
    client, (alice, alice_pw), (bob, bob_pw) = client_and_tenants
    storage = client.app.state.storage

    item = storage.store_bytes(
        TenantScope(alice.id),
        build_epub(title="Private", author="", language="en", identifier="urn:uuid:p",
                   body_html="<p>secret</p>"),
        filename="p.epub", kind="book", source="email", title="Private",
    ).item

    assert client.get(f"/opds/download/{item.id}.epub", headers=_auth(bob, bob_pw)).status_code == 404
    assert client.get(f"/opds/download/{item.id}.epub", headers=_auth(alice, alice_pw)).status_code == 200


def test_an_unknown_and_a_foreign_item_are_indistinguishable(client_and_tenants):
    """Same status and same body either way. A 403 on a foreign id, or a different
    message, would turn this route into a cross-tenant existence oracle."""
    client, (alice, alice_pw), (bob, bob_pw) = client_and_tenants
    item = _store(client, alice, title="Private")

    foreign = client.get(f"/opds/download/{item.id}.epub", headers=_auth(bob, bob_pw))
    unknown = client.get(f"/opds/download/{'0' * 32}.epub", headers=_auth(bob, bob_pw))
    assert foreign.status_code == unknown.status_code == 404
    assert foreign.json() == unknown.json()


def test_download_requires_auth(client_and_tenants):
    client, (alice, _), _ = client_and_tenants
    item = _store(client, alice, title="Private")
    assert client.get(f"/opds/download/{item.id}.epub").status_code == 401


def test_download_serves_the_acquisition_href_the_feed_emits(client_and_tenants):
    """The acquisition link, including its .epub suffix, must be exactly what this app
    serves -- otherwise every download 404s while the catalogue still looks correct."""
    client, (alice, pw), _ = client_and_tenants
    headers = _auth(alice, pw)
    _store(client, alice, title="Alpha", author="One Writer")

    feed = client.get("/opds/recent", headers=headers)
    acquisition = [href for href in _entry_hrefs(feed.content) if href.endswith(".epub")]
    assert len(acquisition) == 1

    response = client.get(_local_path(acquisition[0]), headers=headers)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/epub+zip"
    assert response.content.startswith(b"PK")


def test_the_authors_navigation_feed_is_scoped_to_the_requesting_tenant(client_and_tenants):
    """Covers list_authors, which no other test reaches with two populated tenants.

    test_authors_are_scoped_to_the_requesting_tenant exercises /opds/authors/{token},
    which routes through list_items. The /opds/authors navigation feed is the only
    caller of list_authors, and mutating its WHERE tenant_id = ? to a tautology
    previously left the entire suite green.
    """
    client, (alice, alice_pw), (bob, bob_pw) = client_and_tenants
    _store(client, alice, title="Alpha", author="Alice Author", identifier="urn:uuid:a1")
    _store(client, bob, title="Beta", author="Bob Author", identifier="urn:uuid:b1")
    _store(client, bob, title="Gamma", author="Another Bob Author", identifier="urn:uuid:b2")

    alice_root = ElementTree.fromstring(client.get("/opds/authors", headers=_auth(alice, alice_pw)).content)
    bob_root = ElementTree.fromstring(client.get("/opds/authors", headers=_auth(bob, bob_pw)).content)

    alice_authors = [e.findtext(f"{{{ATOM}}}title") for e in alice_root.iter(f"{{{ATOM}}}entry")]
    bob_authors = sorted(e.findtext(f"{{{ATOM}}}title") for e in bob_root.iter(f"{{{ATOM}}}entry"))

    assert alice_authors == ["Alice Author"]
    assert bob_authors == ["Another Bob Author", "Bob Author"]


def test_a_feed_only_shows_the_requesting_tenants_items(client_and_tenants):
    client, (alice, alice_pw), (bob, bob_pw) = client_and_tenants
    # Both tenants hold items, not just Alice: a filter that returned the union of both
    # tenants' items would still pass an empty-Bob-library test, but fails this one.
    # An earlier version of this comment also claimed to catch a limit off-by-one. It
    # does not: every feed here holds far fewer rows than PAGE_SIZE, so a truncated page
    # is indistinguishable from a full one. test_pagination_links_resolve builds the
    # larger-than-one-page feed that does catch it.
    _store(client, alice, title="Alices Book", identifier="urn:uuid:alice-1")
    _store(client, alice, title="Alices Other Book", identifier="urn:uuid:alice-2")
    _store(client, bob, title="Bobs Book", identifier="urn:uuid:bob-1")

    alice_root = ElementTree.fromstring(client.get("/opds/recent", headers=_auth(alice, alice_pw)).content)
    bob_root = ElementTree.fromstring(client.get("/opds/recent", headers=_auth(bob, bob_pw)).content)

    alice_titles = [e.findtext(f"{{{ATOM}}}title") for e in alice_root.iter(f"{{{ATOM}}}entry")]
    bob_titles = [e.findtext(f"{{{ATOM}}}title") for e in bob_root.iter(f"{{{ATOM}}}entry")]
    assert sorted(alice_titles) == ["Alices Book", "Alices Other Book"]
    assert bob_titles == ["Bobs Book"]


# -- inbound email -----------------------------------------------------------


def test_inbound_webhook_is_503_when_not_configured(client_and_tenants):
    """An unconfigured deployment refuses mail loudly. A 500 reads as a transient fault
    the provider should retry; a 200 would look healthy while discarding mail."""
    client, _, _ = client_and_tenants
    response = client.post("/webhooks/inbound-email", json={"type": "email.received"})
    assert response.status_code == 503
    assert response.json()["status"] == "disabled"


def test_inbound_webhook_body_is_size_limited(tmp_path):
    settings = Settings(data_dir=tmp_path, public_base_url=BASE_URL, webhook_max_bytes=1024)
    client = TestClient(create_app(settings))
    response = client.post("/webhooks/inbound-email", content=b"x" * 2048)
    assert response.status_code == 413


def test_a_configured_service_reaches_the_provider(tmp_path):
    """With configuration present the route no longer short-circuits to 503 -- it calls
    into the service, so this covers the wiring rather than the disabled branch."""

    class RejectingProvider:
        def verify_event(self, raw_body, headers):
            raise InvalidWebhookSignature("bad signature")

        def list_attachments(self, email_id):  # pragma: no cover - not reached
            return []

        def get_email(self, email_id):  # pragma: no cover - not reached
            raise AssertionError

        def download_chunks(self, attachment):  # pragma: no cover - not reached
            raise AssertionError

    settings = Settings(
        data_dir=tmp_path,
        public_base_url=BASE_URL,
        inbox_domain="read.steepd.app",
        resend_api_key="key",
        resend_webhook_secret="secret",
    )
    client = TestClient(create_app(settings, inbound_provider=RejectingProvider()))
    response = client.post("/webhooks/inbound-email", json={"type": "email.received"})
    assert response.status_code == 400
    assert response.json()["status"] == "rejected"


def test_inbound_service_is_disabled_without_configuration(tmp_path):
    settings = Settings(data_dir=tmp_path, public_base_url=BASE_URL)
    app = create_app(settings)
    with pytest.raises(InboundEmailDisabled):
        app.state.inbound_service.handle(b"{}", {})


# -- construction ------------------------------------------------------------


def test_create_app_initializes_before_returning(tmp_path):
    """State and schema must exist on the returned app, not only after startup: the
    service should fail here if it cannot open its database, not on first request."""
    settings = Settings(data_dir=tmp_path, public_base_url=BASE_URL)
    app = create_app(settings)
    assert app.state.settings is settings
    assert (tmp_path / "steepd.sqlite3").is_file()
    assert (tmp_path / "items").is_dir()
    # Works without ever having entered the lifespan.
    tenant, _ = app.state.database.create_tenant_with_password(email="c@example.com", inbox_local="c.3")
    assert app.state.database.tenant_by_opds_username(tenant.opds_username) == tenant


def test_health_reports_an_unusable_database(client_and_tenants):
    client, _, _ = client_and_tenants
    path = client.app.state.database.path
    # Database never closes its connections (the sqlite3 context manager only commits), so several
    # are still open on this file, reachable only through reference cycles. Whichever the
    # cyclic collector reaps next closes, checkpoints its WAL back through a descriptor on
    # the inode write_bytes() below truncates, and a valid database reappears at this path
    # -- health() then honestly reports ok and this test fails. Which side of the write the
    # collector runs on depends on unrelated allocation, so the failure moves with any
    # change to the rest of the suite; collecting first pins it. The -wal and -shm sidecars
    # go for the same reason: a populated WAL beside a garbage main file also recovers.
    gc.collect()
    for sidecar in (f"{path}-wal", f"{path}-shm"):
        Path(sidecar).unlink(missing_ok=True)
    path.write_bytes(b"not a database")

    response = client.get("/healthz")
    assert response.status_code == 503
    assert response.json()["status"] == "error"


def test_health_warns_when_the_volume_is_low_but_stays_up(client_and_tenants, monkeypatch):
    """Low is a warning the uptime worker relays, not an outage: 200 with a fixed token."""
    from collections import namedtuple

    client, _, _ = client_and_tenants
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr("steepd.storage.shutil.disk_usage", lambda path: usage(5 * 1024**3, 0, 100 * 1024**2))
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "storage": "low"}


def test_admin_stats_is_invisible_without_the_exact_token(tmp_path):
    from dataclasses import replace

    from steepd.app import create_app
    from steepd.config import Settings

    settings = Settings(data_dir=tmp_path, public_base_url="http://localhost:8000", stats_token="s3cret-token")
    client = TestClient(create_app(settings))
    assert client.get("/admin/stats").status_code == 404
    assert client.get("/admin/stats", headers={"Authorization": "Bearer wrong"}).status_code == 404
    assert client.get("/admin/stats", headers={"Authorization": "Bearer s3cret-toke"}).status_code == 404

    good = client.get("/admin/stats", headers={"Authorization": "Bearer s3cret-token"})
    assert good.status_code == 200
    assert good.headers["content-type"].startswith("text/plain")
    assert good.text.startswith("Accounts:       0 (0 confirmed, 0 pending); 0 free, 0 paid\n")
    assert "Volume:" in good.text

    # Unset means the route does not exist for anyone, including a correct-looking header.
    unset = TestClient(create_app(replace(settings, stats_token="", data_dir=tmp_path / "other")))
    assert unset.get("/admin/stats", headers={"Authorization": "Bearer s3cret-token"}).status_code == 404


def test_health_reports_unusable_storage(client_and_tenants):
    client, _, _ = client_and_tenants
    storage = client.app.state.storage
    storage.items_dir.rename(storage.items_dir.parent / "items-moved")
    response = client.get("/healthz")
    assert response.status_code == 503
    assert response.json()["status"] == "error"


# -- magic-link timezone guard -----------------------------------------------


def test_magic_token_rejects_a_naive_datetime(tmp_path):
    """astimezone() would read a naive datetime as system local time. West of UTC that
    fails closed; east of UTC it fails open and an expired token stays redeemable."""
    app = create_app(Settings(data_dir=tmp_path, public_base_url=BASE_URL))
    database = app.state.database
    database.create_tenant_with_password(email="d@example.com", inbox_local="d.4")

    with pytest.raises(ValueError):
        issue_magic_token(database, "d@example.com", now=datetime(2026, 8, 28, 12, 0, 0))

    token = issue_magic_token(database, "d@example.com", now=datetime(2026, 8, 28, 12, 0, tzinfo=UTC))
    with pytest.raises(ValueError):
        consume_magic_token(database, token, now=datetime(2026, 8, 28, 12, 1, 0))
    assert consume_magic_token(database, token, now=datetime(2026, 8, 28, 12, 1, tzinfo=UTC)) is not None


def test_an_expired_magic_token_is_not_redeemable(tmp_path):
    app = create_app(Settings(data_dir=tmp_path, public_base_url=BASE_URL))
    database = app.state.database
    database.create_tenant_with_password(email="e@example.com", inbox_local="e.5")
    issued_at = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
    token = issue_magic_token(database, "e@example.com", now=issued_at)
    assert consume_magic_token(database, token, now=issued_at + timedelta(hours=1)) is None
