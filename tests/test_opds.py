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
    PAGE_SIZE,
    author_from_token,
    author_token,
    build_authors_catalog,
    build_items_catalog,
    build_publication_catalog,
    build_publications_catalog,
    build_root_catalog,
    build_site_catalog,
    build_sites_catalog,
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
    database, scope = database_with_items
    xml = build_root_catalog(database, scope, BASE_URL).decode()
    for title in ("Recent", "Saved", "Newsletters", "Books"):
        assert f"<title>{title}</title>" in xml


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
        ("navigation", "Saved"),
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


# -- publications -----------------------------------------------------------
# The navigation feed carries All newsletters plus a page of publications: 51 entries,
# inside the 62 a CrossPoint retains, which is why PAGE_SIZE is reused unchanged.


@pytest.fixture
def publication_catalogue(tmp_path):
    settings = Settings(data_dir=tmp_path, public_base_url=BASE_URL)
    database = Database(tmp_path / "steepd.sqlite3")
    database.initialize()
    storage = ItemStorage(settings, database)
    storage.initialize()
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)
    return database, storage, scope


def _publish(database, storage, scope, *, publication_name, title, publication_id=None):
    item = storage.store_bytes(
        scope,
        build_epub(title=title, author="", language="en", identifier=f"urn:{title}", body_html=f"<p>{title}</p>"),
        filename=f"{title}.epub", kind="article", source="newsletter", title=title,
    ).item
    now = "2026-09-11T12:00:00+00:00"
    if publication_id is None:
        publication_id = f"pub-{publication_name.lower().replace(' ', '-')}"
        database.create_and_assign_for_owner(
            scope, item.id, publication_id=publication_id, name=publication_name, now=now
        )
    else:
        database.assign_publication_manually(scope, item.id, publication_id=publication_id, now=now)
    return item, publication_id


def _entries(feed: bytes):
    root = ElementTree.fromstring(feed)
    return root.findall("{http://www.w3.org/2005/Atom}entry")


def test_the_root_points_newsletters_at_the_flat_feed_until_there_is_anything_to_group(publication_catalogue):
    database, storage, scope = publication_catalogue

    before = crosspoint_parse(build_root_catalog(database, scope, BASE_URL))
    newsletters = next(entry for entry in before if entry.title == "Newsletters")

    assert newsletters.href == f"{BASE_URL}/opds/newsletters"
    assert newsletters.kind == "navigation", "an entry leading to a shelf, as it always was"


def test_the_root_points_newsletters_at_the_navigation_feed_once_it_is_on(publication_catalogue):
    database, storage, scope = publication_catalogue
    database.set_newsletter_organization(
        scope, enabled=True, consent_version=1, settings_revision=None, now="2026-09-11T12:00:00+00:00"
    )

    root = ElementTree.fromstring(build_root_catalog(database, scope, BASE_URL))
    entry = next(
        e for e in _entries(build_root_catalog(database, scope, BASE_URL))
        if e.find("{http://www.w3.org/2005/Atom}title").text == "Newsletters"
    )
    link = entry.find("{http://www.w3.org/2005/Atom}link")

    assert link.get("href") == f"{BASE_URL}/opds/publications"
    # A reader must know it is opening another shelf, not a list of files.
    assert link.get("type").endswith("kind=navigation")
    updated = root.find("{http://www.w3.org/2005/Atom}updated").text
    assert updated >= "2026-09-11T12:00:00+00:00", "the catalogue clock makes the change visible"


def test_the_flat_newsletters_feed_keeps_working_for_old_bookmarks(publication_catalogue):
    database, storage, scope = publication_catalogue
    _publish(database, storage, scope, publication_name="Alpha", title="Issue one")

    flat = crosspoint_parse(
        build_items_catalog(
            database, scope, BASE_URL, title="Newsletters", feed_id="newsletters",
            kind="article", source="newsletter",
        )
    )

    assert [entry.title for entry in flat] == ["Issue one"]


@pytest.mark.parametrize("count", [49, 50, 51, 100, 101])
def test_a_navigation_page_never_exceeds_fifty_one_entries(publication_catalogue, count):
    database, storage, scope = publication_catalogue
    for index in range(count):
        _publish(database, storage, scope, publication_name=f"Pub {index:03d}", title=f"Issue {index:03d}")

    first = _entries(build_publications_catalog(database, scope, BASE_URL))
    second = _entries(build_publications_catalog(database, scope, BASE_URL, page=2))

    assert len(first) == min(count, PAGE_SIZE) + 1, "All newsletters plus a page of publications"
    assert len(first) <= 51
    assert first[0].find("{http://www.w3.org/2005/Atom}title").text == "All newsletters"
    assert len(second) == max(0, min(count - PAGE_SIZE, PAGE_SIZE)) + 1


def test_the_next_link_appears_exactly_when_there_is_another_page(publication_catalogue):
    database, storage, scope = publication_catalogue
    for index in range(PAGE_SIZE):
        _publish(database, storage, scope, publication_name=f"Pub {index:03d}", title=f"Issue {index:03d}")

    def next_link(feed):
        root = ElementTree.fromstring(feed)
        return [
            link.get("href")
            for link in root.findall("{http://www.w3.org/2005/Atom}link")
            if link.get("rel") == "next"
        ]

    assert next_link(build_publications_catalog(database, scope, BASE_URL)) == []

    _publish(database, storage, scope, publication_name="Pub 050", title="Issue 050")
    assert next_link(build_publications_catalog(database, scope, BASE_URL)) == [
        f"{BASE_URL}/opds/publications?page=2"
    ]


def test_a_publication_feed_lists_only_its_own_issues(publication_catalogue):
    database, storage, scope = publication_catalogue
    _, alpha = _publish(database, storage, scope, publication_name="Alpha", title="Alpha one")
    _publish(database, storage, scope, publication_name="Alpha", title="Alpha two", publication_id=alpha)
    _publish(database, storage, scope, publication_name="Beta", title="Beta one")

    feed = crosspoint_parse(build_publication_catalog(database, scope, BASE_URL, publication_id=alpha))

    assert sorted(entry.title for entry in feed) == ["Alpha one", "Alpha two"]


def test_a_rename_keeps_the_url_and_a_merge_answers_at_the_old_one(publication_catalogue):
    database, storage, scope = publication_catalogue
    _, alpha = _publish(database, storage, scope, publication_name="Alpha", title="Alpha one")
    _, beta = _publish(database, storage, scope, publication_name="Beta", title="Beta one")
    now = "2026-09-12T12:00:00+00:00"

    database.edit_publication(scope, alpha, name="Alpha Weekly", identification_note="", now=now)
    renamed = ElementTree.fromstring(build_publication_catalog(database, scope, BASE_URL, publication_id=alpha))
    assert renamed.find("{http://www.w3.org/2005/Atom}title").text == "Alpha Weekly"
    self_link = next(
        link.get("href")
        for link in renamed.findall("{http://www.w3.org/2005/Atom}link")
        if link.get("rel") == "self"
    )
    assert self_link == f"{BASE_URL}/opds/publications/{alpha}"

    database.merge_publications(scope, source_id=alpha, target_id=beta, now=now)
    old_url = crosspoint_parse(build_publication_catalog(database, scope, BASE_URL, publication_id=alpha))

    assert sorted(entry.title for entry in old_url) == ["Alpha one", "Beta one"]


def test_an_unknown_or_other_tenants_publication_has_no_feed(publication_catalogue, tmp_path):
    database, storage, scope = publication_catalogue
    other = database.create_tenant(email="b@example.com", inbox_local="b.2")
    other_scope = TenantScope(other.id)
    _, theirs = _publish(database, storage, other_scope, publication_name="Theirs", title="Theirs one")

    assert build_publication_catalog(database, scope, BASE_URL, publication_id=theirs) is None
    assert build_publication_catalog(database, scope, BASE_URL, publication_id="nonexistent") is None


# -- saved pages by site ------------------------------------------------------


def _save(database, storage, scope, *, title, url):
    return storage.store_bytes(
        scope,
        build_epub(title=title, author="", language="en", identifier=f"urn:{title}", body_html=f"<p>{title}</p>"),
        filename=f"{title}.epub", kind="article", source="url", title=title, source_url=url,
    ).item


def _feed_links(feed: bytes, *, rel: str):
    root = ElementTree.fromstring(feed)
    return [link for link in root.findall("{http://www.w3.org/2005/Atom}link") if link.get("rel") == rel]


def _link_type(feed: bytes, *, rel: str) -> str:
    return _feed_links(feed, rel=rel)[0].get("type")


def _entry_link(entry):
    return entry.find("{http://www.w3.org/2005/Atom}link")


def test_the_root_points_saved_at_the_flat_feed_until_a_page_is_saved(publication_catalogue):
    database, storage, scope = publication_catalogue

    def saved_entry():
        entries = _entries(build_root_catalog(database, scope, BASE_URL))
        entry = next(e for e in entries if e.find("{http://www.w3.org/2005/Atom}title").text == "Saved")
        return _entry_link(entry)

    before = saved_entry()
    assert before.get("href") == f"{BASE_URL}/opds/saved"
    assert before.get("type").endswith("kind=acquisition")

    _save(database, storage, scope, title="A page", url="https://example.com/a")

    after = saved_entry()
    assert after.get("href") == f"{BASE_URL}/opds/sites"
    assert after.get("type").endswith("kind=navigation")


def test_the_sites_feed_lists_all_saved_then_one_entry_per_site(publication_catalogue):
    database, storage, scope = publication_catalogue
    _save(database, storage, scope, title="One", url="https://www.example.com/1")
    _save(database, storage, scope, title="Two", url="https://example.com/2")
    _save(database, storage, scope, title="Three", url="https://other.example/3")

    feed = build_sites_catalog(database, scope, BASE_URL)
    entries = _entries(feed)

    assert _link_type(feed, rel="self").endswith("kind=navigation")
    titles = [e.find("{http://www.w3.org/2005/Atom}title").text for e in entries]
    assert titles == ["All saved", "example.com", "other.example"]
    assert [_entry_link(e).get("href") for e in entries] == [
        f"{BASE_URL}/opds/saved", f"{BASE_URL}/opds/sites/example.com", f"{BASE_URL}/opds/sites/other.example"
    ]
    assert all(_entry_link(e).get("type").endswith("kind=acquisition") for e in entries), "each opens a list of pages"
    assert entries[1].find("{http://www.w3.org/2005/Atom}content").text == "2 pages"


@pytest.mark.parametrize("count", [50, 51])
def test_a_sites_page_never_exceeds_fifty_one_entries(publication_catalogue, count):
    database, storage, scope = publication_catalogue
    for index in range(count):
        _save(database, storage, scope, title=f"Page {index:02d}", url=f"https://site{index:02d}.example/p")

    first = build_sites_catalog(database, scope, BASE_URL)
    second = build_sites_catalog(database, scope, BASE_URL, page=2)
    next_links = _feed_links(first, rel="next")

    assert len(_entries(first)) == min(count, PAGE_SIZE) + 1
    assert len(_entries(second)) == max(0, count - PAGE_SIZE) + 1
    assert [link.get("href") for link in next_links] == ([f"{BASE_URL}/opds/sites?page=2"] if count > PAGE_SIZE else [])
    assert all(link.get("type").endswith("kind=navigation") for link in next_links)


def test_a_site_feed_lists_only_that_sites_pages_and_reports_its_own_path(publication_catalogue):
    database, storage, scope = publication_catalogue
    _save(database, storage, scope, title="Mine one", url="https://example.com/1")
    _save(database, storage, scope, title="Mine two", url="https://www.example.com/2")
    _save(database, storage, scope, title="Elsewhere", url="https://other.example/3")

    feed = build_site_catalog(database, scope, BASE_URL, host="example.com")

    assert sorted(entry.title for entry in crosspoint_parse(feed)) == ["Mine one", "Mine two"]
    assert _feed_links(feed, rel="self")[0].get("href") == f"{BASE_URL}/opds/sites/example.com"
    assert _link_type(feed, rel="self").endswith("kind=acquisition")


def test_a_site_with_no_pages_is_an_empty_feed_not_an_error(publication_catalogue):
    """A bookmark to a site outlives its last page, as an author feed does. Unknown hosts
    and another account's hosts answer the same way, so the feed says nothing about
    what anyone else has."""
    database, storage, scope = publication_catalogue
    item = _save(database, storage, scope, title="Only one", url="https://example.com/1")

    storage.delete(scope, item.id)

    assert database.list_saved_sites(scope) == []
    assert _entries(build_site_catalog(database, scope, BASE_URL, host="example.com")) == []
    assert _entries(build_site_catalog(database, scope, BASE_URL, host="nobody.example")) == []


def test_a_host_with_a_port_is_encoded_in_its_link(publication_catalogue):
    database, storage, scope = publication_catalogue
    _save(database, storage, scope, title="Local", url="http://example.com:8080/x")

    entries = _entries(build_sites_catalog(database, scope, BASE_URL))

    assert _entry_link(entries[1]).get("href") == f"{BASE_URL}/opds/sites/example.com%3A8080"
