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
    media_type: str = ACQUISITION_TYPE,
) -> None:
    # media_type defaults to acquisition because every existing caller points at a list of
    # books. An entry leading to another navigation feed -- Newsletters, once publications
    # exist -- has to say so, or a reader treats the shelf it opens as a list of files.
    entry = _atom(root, "entry")
    _atom(entry, "id", entry_id)
    _atom(entry, "title", title)
    _atom(entry, "updated", updated)
    _atom(entry, "content", description, type="text")
    _link(entry, rel="subsection", href=href, media_type=media_type)


def _acquisition_entry(root: ElementTree.Element, item: Item, base_url: str) -> None:
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


def build_root_catalog(
    database: Database, scope: TenantScope, base_url: str, *, interactive: bool = False
) -> bytes:
    show_publications, catalogue_updated_at = database.newsletter_catalogue_state(scope)
    # The newest arrival alone cannot express a rename, a merge, an expiry, or this feed's
    # own Newsletters link changing target, so the catalogue clock is folded in. Both are
    # ISO-8601 UTC strings written by this codebase, which order lexicographically.
    updated = max(database.latest_created_at(scope), catalogue_updated_at or "")
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
    # Once anything is saved, Saved opens a list of sites with All saved at the top; the
    # flat feed keeps its address so an older bookmark still works. This switches back if
    # every saved page goes, which is the honest shape of "nothing to group".
    by_site = database.count_items(scope, kind="article", source="url") > 0
    _navigation_entry(
        root,
        entry_id="urn:steepd:saved",
        title="Saved",
        updated=updated,
        href=_absolute(base_url, "/opds/sites" if by_site else "/opds/saved"),
        description="Webpages saved from a link in an email subject, by site" if by_site else
        "Webpages saved from a link in an email subject",
        media_type=NAVIGATION_TYPE if by_site else ACQUISITION_TYPE,
    )
    _navigation_entry(
        root,
        entry_id="urn:steepd:newsletters",
        title="Newsletters",
        updated=updated,
        # /opds/newsletters stays exactly where it was, so a bookmark made before this
        # feature keeps working; the root simply stops being the only way to reach it.
        href=_absolute(base_url, "/opds/publications" if show_publications else "/opds/newsletters"),
        description=(
            "Your newsletters, by publication" if show_publications else "Newsletters delivered to your inbox"
        ),
        media_type=NAVIGATION_TYPE if show_publications else ACQUISITION_TYPE,
    )
    _navigation_entry(
        root,
        entry_id="urn:steepd:books",
        title="Books",
        updated=updated,
        href=_absolute(base_url, "/opds/books"),
        description="Every book in your library",
    )
    if interactive:
        _navigation_entry(
            root,
            entry_id="urn:steepd:starred",
            title="Starred",
            updated=updated,
            href=_absolute(base_url, "/opds/starred"),
            description="Items you starred, most recent first",
            media_type=NAVIGATION_TYPE,
        )
    return _serialize(root)


# -- item menus ----------------------------------------------------------
# With reader actions on, a shelf lists each item as a navigation entry that opens its
# menu: the real download plus Star or Unstar and Delete from Steepd. Those two are
# navigation entries too, so a reader fetches them as feeds and never writes a file for
# them. Result feeds put their status in entry titles, because CrossPoint keeps no entry
# content, and always carry a row, because it treats an empty feed as an error.

ACTION_VERBS = ("star", "unstar", "trash")


def _item_menu_entry(root: ElementTree.Element, item: Item, base_url: str) -> None:
    entry = _atom(root, "entry")
    _atom(entry, "id", f"urn:sha256:{item.sha256}")
    _atom(entry, "title", item.title)
    _atom(entry, "updated", item.created_at)
    if item.author:
        author = _atom(entry, "author")
        _atom(author, "name", item.author)
    _link(entry, rel="subsection", href=_absolute(base_url, f"/opds/items/{item.id}"), media_type=NAVIGATION_TYPE)


def _action_url(base_url: str, item: Item, verb: str) -> str:
    return _absolute(base_url, f"/opds/items/{item.id}/{verb}", {"rev": item.revision})


def build_item_menu(item: Item, base_url: str) -> bytes:
    root = _feed(f"urn:steepd:item:{item.id}", item.title, item.created_at)
    _add_common_links(
        root, base_url=base_url, self_path=f"/opds/items/{item.id}", self_type=NAVIGATION_TYPE, search=False
    )
    # The download row keeps the item's own title and author: CrossPoint names the local
    # file after them, so a row titled "Download" would save Download.epub.
    _acquisition_entry(root, item, base_url)
    star_verb, star_label = ("unstar", "Unstar") if item.starred_at else ("star", "Star")
    for verb, label in ((star_verb, star_label), ("trash", "Delete from Steepd")):
        _navigation_entry(
            root,
            entry_id=f"urn:steepd:item:{item.id}:{verb}",
            title=label,
            updated=item.created_at,
            href=_action_url(base_url, item, verb),
            description="",
            media_type=NAVIGATION_TYPE,
        )
    return _serialize(root)


def build_result_feed(
    base_url: str, *, feed_id: str, title: str, updated: str, rows: list[tuple[str, str]]
) -> bytes:
    """A feed of navigation rows, each a (title, path) pair. The first row carries the
    outcome; Back to library is appended to every result."""
    root = _feed(f"urn:steepd:result:{feed_id}", title, updated)
    _add_common_links(root, base_url=base_url, self_path="/opds", self_type=NAVIGATION_TYPE, search=False)
    for index, (row_title, path) in enumerate([*rows, ("Back to library", "/opds")]):
        _navigation_entry(
            root,
            entry_id=f"urn:steepd:result:{feed_id}:{index}",
            title=row_title,
            updated=updated,
            href=_absolute(base_url, path),
            description="",
            media_type=NAVIGATION_TYPE,
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
    publication: str | None = None,
    site: str | None = None,
    starred: bool = False,
    page: int = 1,
    self_path: str | None = None,
    updated_floor: str | None = None,
    interactive: bool = False,
) -> bytes:
    # self_path is overridable so a feed reached through a merged publication's old URL
    # advertises the URL that was actually requested. Answering there directly is what
    # lets an old bookmark keep working without relying on the reader to follow a redirect.
    self_path = self_path or f"/opds/{feed_id}"
    offset = (page - 1) * PAGE_SIZE
    filters = dict(
        kind=kind, author=author, query=query, source=source, publication=publication, site=site, starred=starred
    )
    total = database.count_items(scope, **filters)
    items = database.list_items(
        scope, **filters, limit=PAGE_SIZE, offset=offset, order="starred" if starred else "newest"
    )
    updated = items[0].created_at if items else database.latest_created_at(scope)
    # A rename moves a publication's feed without changing any issue's arrival date.
    updated = max(updated, updated_floor or "")
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
        if interactive:
            _item_menu_entry(root, item, base_url)
        else:
            _acquisition_entry(root, item, base_url)
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


def build_publications_catalog(database: Database, scope: TenantScope, base_url: str, *, page: int = 1) -> bytes:
    """The navigation feed listing All newsletters and each publication.

    PAGE_SIZE is reused unchanged. All newsletters is an extra entry rather than one of
    the fifty, so a page carries 51 -- inside the 62 a CrossPoint retains -- and the page
    arithmetic in _add_page_links keeps counting the thing it was written to count. It
    appears on every page so the shortcut is never more than one tap away.
    """
    _, catalogue_updated_at = database.newsletter_catalogue_state(scope)
    updated = max(database.latest_created_at(scope), catalogue_updated_at or "")
    total = database.count_publications(scope)
    summaries = database.list_publication_summaries(scope, limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE)

    root = _feed("urn:steepd:publications", "Newsletters", updated)
    _add_common_links(root, base_url=base_url, self_path="/opds/publications", self_type=NAVIGATION_TYPE)
    _add_page_links(
        root,
        base_url=base_url,
        path="/opds/publications",
        page=page,
        total=total,
        media_type=NAVIGATION_TYPE,
    )
    _navigation_entry(
        root,
        entry_id="urn:steepd:newsletters",
        title="All newsletters",
        updated=updated,
        href=_absolute(base_url, "/opds/newsletters"),
        description="Every newsletter, newest first",
    )
    for summary in summaries:
        publication = summary.publication
        _navigation_entry(
            root,
            entry_id=f"urn:steepd:publication:{publication.id}",
            title=publication.name,
            updated=publication.updated_at,
            href=_absolute(base_url, f"/opds/publications/{publication.id}"),
            description=f"{summary.issue_count} issue{'s' if summary.issue_count != 1 else ''}",
        )
    return _serialize(root)


def build_publication_catalog(
    database: Database,
    scope: TenantScope,
    base_url: str,
    *,
    publication_id: str,
    page: int = 1,
    interactive: bool = False,
) -> bytes | None:
    """One publication's issues, or None when this tenant has no such publication.

    A merged id resolves to its survivor and the survivor's issues are returned at the
    requested URL. Renames never move this URL: it carries the publication's id, and a
    rename leaves that alone.
    """
    publication = database.resolve_publication(scope, publication_id)
    if publication is None:
        return None
    return build_items_catalog(
        database,
        scope,
        base_url,
        title=publication.name,
        feed_id=f"publication:{publication.id}",
        kind="article",
        source="newsletter",
        publication=publication.id,
        page=page,
        self_path=f"/opds/publications/{publication_id}",
        updated_floor=publication.updated_at,
        interactive=interactive,
    )


def build_sites_catalog(database: Database, scope: TenantScope, base_url: str, *, page: int = 1) -> bytes:
    """The navigation feed listing All saved and then one entry per site.

    Shaped like the publications feed: PAGE_SIZE sites plus the All saved entry on every
    page. `updated` is the newest saved page, which is the same clock the flat feed uses;
    deleting an older page changes a count without moving it. A reader opens the feed on
    demand rather than polling it, so that is accepted rather than tracked in a new column.
    """
    updated = database.latest_created_at(scope)
    total = database.count_saved_sites(scope)
    sites = database.list_saved_sites(scope, limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE)

    root = _feed("urn:steepd:sites", "Saved", updated)
    _add_common_links(root, base_url=base_url, self_path="/opds/sites", self_type=NAVIGATION_TYPE)
    _add_page_links(root, base_url=base_url, path="/opds/sites", page=page, total=total, media_type=NAVIGATION_TYPE)
    _navigation_entry(
        root,
        entry_id="urn:steepd:saved",
        title="All saved",
        updated=updated,
        href=_absolute(base_url, "/opds/saved"),
        description="Every saved page, newest first",
    )
    for site in sites:
        _navigation_entry(
            root,
            entry_id=f"urn:steepd:site:{site.host}",
            title=site.host,
            updated=site.updated_at,
            href=_absolute(base_url, f"/opds/sites/{quote(site.host, safe='')}"),
            description=f"{site.page_count} page{'s' if site.page_count != 1 else ''}",
        )
    return _serialize(root)


def build_site_catalog(
    database: Database, scope: TenantScope, base_url: str, *, host: str, page: int = 1, interactive: bool = False
) -> bytes:
    """One site's saved pages. A host with none gives an empty feed, as an author does.

    An empty feed rather than a 404 keeps a bookmark usable after the last page from that
    site expires, and answers the same for a host nobody here ever saved from.
    """
    return build_items_catalog(
        database,
        scope,
        base_url,
        title=host,
        feed_id=f"sites/{quote(host, safe='')}",
        kind="article",
        source="url",
        site=host,
        page=page,
        interactive=interactive,
    )
