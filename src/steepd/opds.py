from __future__ import annotations

import base64
import hashlib
import xml.etree.ElementTree as ElementTree
from urllib.parse import quote, urlencode

from steepd.db import Database
from steepd.models import AuthorSummary, Item
from steepd.tenancy import TenantScope

ATOM = "http://www.w3.org/2005/Atom"
OPDS = "http://opds-spec.org/2010/catalog"
ACQUISITION_REL = "http://opds-spec.org/acquisition"
NAVIGATION_TYPE = "application/atom+xml;profile=opds-catalog;kind=navigation"
ACQUISITION_TYPE = "application/atom+xml;profile=opds-catalog;kind=acquisition"
EPUB_TYPE = "application/epub+zip"
PAGE_SIZE = 50  # CrossPoint v1.5.0 retains at most 62 feed entries.

ElementTree.register_namespace("", ATOM)
ElementTree.register_namespace("opds", OPDS)


def _atom(parent: ElementTree.Element, name: str, text: str | None = None, **attributes: str) -> ElementTree.Element:
    element = ElementTree.SubElement(parent, f"{{{ATOM}}}{name}", attributes)
    if text is not None:
        element.text = text
    return element


def _absolute(base_url: str, path: str, query: dict[str, object] | None = None) -> str:
    url = f"{base_url}{path}"
    if query:
        url = f"{url}?{urlencode(query)}"
    return url


def _feed(feed_id: str, title: str, updated: str) -> ElementTree.Element:
    root = ElementTree.Element(f"{{{ATOM}}}feed")
    _atom(root, "id", feed_id)
    _atom(root, "title", title)
    _atom(root, "updated", updated)
    author = _atom(root, "author")
    _atom(author, "name", "Steepd")
    return root


def _link(parent: ElementTree.Element, *, rel: str, href: str, media_type: str) -> None:
    _atom(parent, "link", rel=rel, href=href, type=media_type)


def _navigation_entry(
    root: ElementTree.Element,
    *,
    entry_id: str,
    title: str,
    updated: str,
    href: str,
    description: str,
) -> None:
    entry = _atom(root, "entry")
    _atom(entry, "id", entry_id)
    _atom(entry, "title", title)
    _atom(entry, "updated", updated)
    _atom(entry, "content", description, type="text")
    _link(entry, rel="subsection", href=href, media_type=ACQUISITION_TYPE)


def _publication_entry(root: ElementTree.Element, item: Item, base_url: str) -> None:
    entry = _atom(root, "entry")
    _atom(entry, "id", f"urn:sha256:{item.sha256}")
    _atom(entry, "title", item.title)
    _atom(entry, "updated", item.created_at)
    _atom(entry, "published", item.created_at)
    if item.author:
        author = _atom(entry, "author")
        _atom(author, "name", item.author)
    _atom(entry, "content", f"EPUB · {item.size_bytes} bytes", type="text")
    _link(
        entry,
        rel=ACQUISITION_REL,
        href=_absolute(base_url, f"/opds/download/{item.id}.epub"),
        media_type=EPUB_TYPE,
    )
    if item.source_url:
        # Lets a reader jump to the original article. item.source_url is already an
        # absolute external URL, so it is used as-is rather than through _absolute().
        _link(entry, rel="alternate", href=item.source_url, media_type="text/html")


def _serialize(root: ElementTree.Element) -> bytes:
    return ElementTree.tostring(root, encoding="utf-8", xml_declaration=True, short_empty_elements=True)


def _add_common_links(
    root: ElementTree.Element,
    *,
    base_url: str,
    self_path: str,
    self_type: str,
    search: bool = True,
) -> None:
    _link(root, rel="self", href=_absolute(base_url, self_path), media_type=self_type)
    _link(root, rel="start", href=_absolute(base_url, "/opds"), media_type=NAVIGATION_TYPE)
    if search:
        _link(
            root,
            rel="search",
            href=f"{_absolute(base_url, '/opds/search')}?q={{searchTerms}}",
            media_type=ACQUISITION_TYPE,
        )


def _add_page_links(
    root: ElementTree.Element,
    *,
    base_url: str,
    path: str,
    page: int,
    total: int,
    extra_query: dict[str, object] | None = None,
    media_type: str = ACQUISITION_TYPE,
) -> None:
    query = dict(extra_query or {})
    if page > 1:
        query["page"] = page - 1
        _link(root, rel="previous", href=_absolute(base_url, path, query), media_type=media_type)
    if page * PAGE_SIZE < total:
        query["page"] = page + 1
        _link(root, rel="next", href=_absolute(base_url, path, query), media_type=media_type)


def build_root_catalog(database: Database, scope: TenantScope, base_url: str) -> bytes:
    updated = database.latest_created_at(scope)
    root = _feed("urn:steepd:root", "Steepd", updated)
    _add_common_links(root, base_url=base_url, self_path="/opds", self_type=NAVIGATION_TYPE)
    _navigation_entry(
        root,
        entry_id="urn:steepd:recent",
        title="Recent",
        updated=updated,
        href=_absolute(base_url, "/opds/recent"),
        description="Everything recently added, newest first",
    )
    _navigation_entry(
        root,
        entry_id="urn:steepd:newsletters",
        title="Newsletters",
        updated=updated,
        href=_absolute(base_url, "/opds/newsletters"),
        description="Newsletters delivered to your inbox",
    )
    # No "Saved" entry: it filters source="url", and URL saving is Plan 2, so the shelf
    # would be permanently empty on a device. /opds/saved still exists and works -- the
    # entry comes back here when Plan 2 lands.
    _navigation_entry(
        root,
        entry_id="urn:steepd:books",
        title="Books",
        updated=updated,
        href=_absolute(base_url, "/opds/books"),
        description="Every book in your library",
    )
    return _serialize(root)


def build_items_catalog(
    database: Database,
    scope: TenantScope,
    base_url: str,
    *,
    title: str,
    feed_id: str,
    kind: str | None = None,
    author: str | None = None,
    query: str | None = None,
    source: str | None = None,
    page: int = 1,
) -> bytes:
    self_path = f"/opds/{feed_id}"
    offset = (page - 1) * PAGE_SIZE
    total = database.count_items(scope, kind=kind, author=author, query=query, source=source)
    items = database.list_items(
        scope,
        kind=kind,
        author=author,
        query=query,
        source=source,
        limit=PAGE_SIZE,
        offset=offset,
    )
    updated = items[0].created_at if items else database.latest_created_at(scope)
    root = _feed(f"urn:steepd:catalog:{feed_id}", title, updated)
    _add_common_links(root, base_url=base_url, self_path=self_path, self_type=ACQUISITION_TYPE)
    page_query: dict[str, object] = {}
    if query:
        page_query["q"] = query
    _add_page_links(
        root,
        base_url=base_url,
        path=self_path,
        page=page,
        total=total,
        extra_query=page_query,
    )
    for item in items:
        _publication_entry(root, item, base_url)
    return _serialize(root)


def author_token(author: str) -> str:
    return base64.urlsafe_b64encode(author.encode("utf-8")).decode("ascii").rstrip("=")


def author_from_token(token: str) -> str:
    if not token or not re_fullmatch_urlsafe(token):
        raise ValueError("Invalid author token")
    padding = "=" * (-len(token) % 4)
    try:
        decoded = base64.urlsafe_b64decode(f"{token}{padding}").decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Invalid author token") from exc
    if not decoded or len(decoded) > 240:
        raise ValueError("Invalid author token")
    return decoded


def re_fullmatch_urlsafe(value: str) -> bool:
    return all(character.isalnum() or character in "-_" for character in value)


def _author_entry(root: ElementTree.Element, author: AuthorSummary, base_url: str) -> None:
    token = author_token(author.name)
    _navigation_entry(
        root,
        entry_id=f"urn:steepd:author:{hashlib.sha256(author.name.encode()).hexdigest()}",
        title=author.name,
        updated=author.updated_at,
        href=_absolute(base_url, f"/opds/authors/{quote(token, safe='-_')}"),
        description=f"{author.item_count} item{'s' if author.item_count != 1 else ''}",
    )


def build_authors_catalog(database: Database, scope: TenantScope, base_url: str, *, page: int = 1) -> bytes:
    offset = (page - 1) * PAGE_SIZE
    authors = database.list_authors(scope, limit=PAGE_SIZE, offset=offset)
    total = database.count_authors(scope)
    updated = max((author.updated_at for author in authors), default=database.latest_created_at(scope))
    root = _feed("urn:steepd:authors", "Authors", updated)
    _add_common_links(root, base_url=base_url, self_path="/opds/authors", self_type=NAVIGATION_TYPE)
    _add_page_links(
        root,
        base_url=base_url,
        path="/opds/authors",
        page=page,
        total=total,
        media_type=NAVIGATION_TYPE,
    )
    for author in authors:
        _author_entry(root, author, base_url)
    return _serialize(root)
