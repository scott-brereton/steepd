"""Ported from the OPDS CrossPoint conformance test of the originating project.

The original drove its OPDS conformance assertions over HTTP, through a
FastAPI TestClient (routes such as GET /opds/all and GET /opds/books/{id}.epub
with basic auth). steepd's OPDS routes don't exist yet -- they land in
Task 10 -- so this port calls the catalogue builders in steepd.opds directly
and scopes every call to a tenant. The CrossPoint conformance parser
(crosspoint_parse) is kept verbatim: it is what a real e-ink firmware parser
accepts, and is the reason this system works on a device at all.

The acquisition path changed from /opds/books/{id}.epub to
/opds/download/{id}.epub -- this service serves articles as well as books --
so the pinned hrefs below reflect the new path, not the original.
"""

from __future__ import annotations

import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass

import pytest

from steepd.config import Settings
from steepd.db import Database
from steepd.epubgen import build_epub
from steepd.opds import (
    ACQUISITION_REL,
    EPUB_TYPE,
    author_from_token,
    author_token,
    build_authors_catalog,
    build_items_catalog,
    build_root_catalog,
)
from steepd.storage import ItemStorage
from steepd.tenancy import TenantScope

BASE_URL = "https://read.steepd.app"


@dataclass
class ParsedEntry:
    kind: str
    title: str
    author: str
    href: str


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def crosspoint_parse(xml: bytes) -> list[ParsedEntry]:
    """Mirror the entry/link decisions in stock CrossPoint v1.5.0 OpdsParser.cpp."""
    root = ElementTree.fromstring(xml)
    parsed: list[ParsedEntry] = []
    for entry in [item for item in root if local_name(item.tag) == "entry"][:62]:
        title = ""
        author = ""
        href = ""
        kind = "navigation"
        for child in entry:
            name = local_name(child.tag)
            if name == "title":
                title = "".join(child.itertext())[:160]
            elif name == "author":
                author_name = next((item for item in child if local_name(item.tag) == "name"), None)
                author = "".join(author_name.itertext())[:120] if author_name is not None else ""
            elif name == "link":
                rel = child.attrib.get("rel", "")
                media_type = child.attrib.get("type", "")
                candidate = child.attrib.get("href", "")[:768]
                if ACQUISITION_REL in rel and media_type == EPUB_TYPE:
                    kind, href = "book", candidate
                elif "application/atom+xml" in media_type and kind != "book":
                    kind, href = "navigation", candidate
        if title and href:
            parsed.append(ParsedEntry(kind, title, author, href))
    return parsed


@pytest.fixture
def database_with_items(tmp_path):
    settings = Settings(data_dir=tmp_path, public_base_url=BASE_URL)
    database = Database(tmp_path / "steepd.sqlite3")
    database.initialize()
    storage = ItemStorage(settings, database)
    storage.initialize()
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)
    storage.store_bytes(
        scope,
        build_epub(
            title="A book", author="An author", language="en", identifier="urn:uuid:b1", body_html="<p>book</p>"
        ),
        filename="book.epub", kind="book", source="email", title="A book", author="An author",
    )
    storage.store_bytes(
        scope,
        build_epub(
            title="A newsletter", author="", language="en", identifier="urn:uuid:n1", body_html="<p>news</p>"
        ),
        filename="news.epub", kind="article", source="newsletter",
        source_url="https://example.com/post", title="A newsletter",
    )
    return database, scope


@pytest.fixture
def two_tenants_with_items(tmp_path):
    settings = Settings(data_dir=tmp_path, public_base_url=BASE_URL)
    database = Database(tmp_path / "steepd.sqlite3")
    database.initialize()
    storage = ItemStorage(settings, database)
    storage.initialize()
    scopes = []
    for local, email, title in (("a.1", "a@example.com", "Alice's book"), ("b.2", "b@example.com", "Bob's book")):
        tenant = database.create_tenant(email=email, inbox_local=local)
        scope = TenantScope(tenant.id)
        storage.store_bytes(
            scope,
            build_epub(
                title=title, author="Someone", language="en", identifier=f"urn:uuid:{local}", body_html="<p>x</p>"
            ),
            filename="b.epub", kind="book", source="email", title=title, author="Someone",
        )
        scopes.append(scope)
    return database, scopes[0], scopes[1]


def test_root_catalog_lists_the_shipping_sections(database_with_items):
    """Saved is deliberately absent: /opds/saved filters source="url", which nothing writes
    until Plan 2, so advertising it would put a permanently empty shelf on a device."""
    database, scope = database_with_items
    xml = build_root_catalog(database, scope, BASE_URL).decode()
    for title in ("Recent", "Newsletters", "Books"):
        assert f"<title>{title}</title>" in xml
    assert "<title>Saved</title>" not in xml


def test_catalog_only_contains_the_scoped_tenants_items(two_tenants_with_items):
    database, alice_scope, bob_scope = two_tenants_with_items
    alice_xml = build_items_catalog(
        database, alice_scope, BASE_URL, title="Recent", feed_id="recent"
    ).decode()
    assert "Alice&#39;s book" in alice_xml or "Alice's book" in alice_xml
    assert "Bob" not in alice_xml


def test_article_entry_links_its_source_url(database_with_items):
    database, scope = database_with_items
    xml = build_items_catalog(
        database, scope, BASE_URL, title="Newsletters", feed_id="newsletters", kind="article"
    ).decode()
    assert "https://example.com/post" in xml


def test_root_catalog_matches_crosspoint_navigation_rules(database_with_items):
    database, scope = database_with_items
    xml = build_root_catalog(database, scope, BASE_URL)
    entries = crosspoint_parse(xml)
    assert [(item.kind, item.title) for item in entries] == [
        ("navigation", "Recent"),
        ("navigation", "Newsletters"),
        ("navigation", "Books"),
    ]
    assert all(item.href.startswith(f"{BASE_URL}/opds/") for item in entries)


def test_acquisition_feed_and_download_match_crosspoint(database_with_items):
    database, scope = database_with_items
    feed = build_items_catalog(database, scope, BASE_URL, title="Books", feed_id="books", kind="book")
    ElementTree.fromstring(feed)
    entries = crosspoint_parse(feed)
    [item] = database.list_items(scope, kind="book")
    assert entries == [
        ParsedEntry(
            "book",
            "A book",
            "An author",
            f"{BASE_URL}/opds/download/{item.id}.epub",
        )
    ]


def test_recent_authors_and_search_are_crosspoint_browsable(tmp_path):
    settings = Settings(data_dir=tmp_path, public_base_url=BASE_URL)
    database = Database(tmp_path / "steepd.sqlite3")
    database.initialize()
    storage = ItemStorage(settings, database)
    storage.initialize()
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)
    storage.store_bytes(
        scope,
        build_epub(title="Alpha", author="One Writer", language="en", identifier="urn:uuid:one", body_html="<p/>"),
        filename="alpha.epub", kind="book", source="email", title="Alpha", author="One Writer",
    )
    storage.store_bytes(
        scope,
        build_epub(title="Beta", author="Two Writer", language="en", identifier="urn:uuid:two", body_html="<p/>"),
        filename="beta.epub", kind="book", source="email", title="Beta", author="Two Writer",
    )

    recent = crosspoint_parse(build_items_catalog(database, scope, BASE_URL, title="Recent", feed_id="recent"))
    assert [entry.title for entry in recent] == ["Beta", "Alpha"]

    authors = crosspoint_parse(build_authors_catalog(database, scope, BASE_URL))
    assert [entry.title for entry in authors] == ["One Writer", "Two Writer"]

    author_books = crosspoint_parse(
        build_items_catalog(
            database, scope, BASE_URL, title="One Writer", feed_id="authors-one", author="One Writer"
        )
    )
    assert [entry.title for entry in author_books] == ["Alpha"]

    search = crosspoint_parse(
        build_items_catalog(database, scope, BASE_URL, title="Search", feed_id="search", query="Beta")
    )
    assert [entry.title for entry in search] == ["Beta"]


# -- author tokens ----------------------------------------------------------
# The codec that turns an author name into a URL segment and back. Nothing else in
# the suite exercises it: the CrossPoint port above calls build_items_catalog with a
# plain author name, so a decode bug would first surface on a physical device.


@pytest.mark.parametrize(
    "author",
    [
        "One Writer",
        "Ursula K. Le Guin",
        "Jorge Luis Borges",       # accented characters
        "村上 春樹",                # non-latin
        "O'Brien & Sons",          # punctuation that must survive a URL
        "A" * 240,                 # the documented upper bound, exactly
    ],
)
def test_author_token_round_trips(author):
    assert author_from_token(author_token(author)) == author


def test_author_token_rejects_a_name_past_the_stored_bound():
    # inspect_epub bounds a stored author to 240 characters (epub.py:245) and
    # author_from_token rejects anything longer. Those two limits must stay equal:
    # raise one without the other and author browsing breaks for long names.
    assert author_from_token(author_token("A" * 240)) == "A" * 240
    with pytest.raises(ValueError):
        author_from_token(author_token("A" * 241))
