"""Star, Unstar and Delete from Steepd in the reader catalogue.

These follow the hrefs the feeds emit rather than building URLs, for the reason test_app.py
gives. The replay tests reproduce what a CrossPoint reader did on a real device: Back
fetches the previous page's URL again, action links included.
"""

from __future__ import annotations

import base64
import xml.etree.ElementTree as ElementTree

import pytest
from fastapi.testclient import TestClient

from steepd.app import create_app
from steepd.auth import issue_magic_token
from steepd.config import Settings
from steepd.epubgen import build_epub
from steepd.opds import ACQUISITION_REL, ATOM, NAVIGATION_TYPE, author_token
from steepd.tenancy import TenantScope

BASE_URL = "http://localhost:8000"


@pytest.fixture
def reader(tmp_path):
    settings = Settings(data_dir=tmp_path, public_base_url=BASE_URL)
    app = create_app(settings)
    database = app.state.database
    alice, alice_pw = database.create_tenant_with_password(email="a@example.com", inbox_local="a.1")
    bob, bob_pw = database.create_tenant_with_password(email="b@example.com", inbox_local="b.2")
    database.set_reader_actions(alice.id, True)
    return TestClient(app), (alice, alice_pw), (bob, bob_pw)


def _auth(tenant, password):
    raw = f"{tenant.opds_username}:{password}".encode()
    return {"Authorization": f"Basic {base64.b64encode(raw).decode()}"}


def _store(client, tenant, title, *, kind="book", source="email", source_url=""):
    return client.app.state.storage.store_bytes(
        TenantScope(tenant.id),
        build_epub(title=title, author="Ann Author", language="en", identifier=f"urn:uuid:{title}", body_html="<p/>"),
        filename=f"{title}.epub",
        kind=kind,
        source=source,
        title=title,
        author="Ann Author",
        source_url=source_url,
    ).item


def _path(href: str) -> str:
    assert href.startswith(BASE_URL), href
    return href[len(BASE_URL) :]


def _rows(content: bytes) -> list[tuple[str, str, str, str]]:
    """(title, rel, type, path) for each entry's first link."""
    rows = []
    for entry in ElementTree.fromstring(content).iter(f"{{{ATOM}}}entry"):
        link = entry.find(f"{{{ATOM}}}link")
        rows.append((entry.findtext(f"{{{ATOM}}}title"), link.get("rel"), link.get("type"), _path(link.get("href"))))
    return rows


def _row(content: bytes, title: str) -> str:
    return next(path for row_title, _, _, path in _rows(content) if row_title == title)


def _menu(client, headers, item) -> bytes:
    shelf = client.get("/opds/recent", headers=headers)
    return client.get(_row(shelf.content, item.title), headers=headers).content


def _stored(client, tenant, item_id):
    return client.app.state.database.get_item(TenantScope(tenant.id), item_id)


# -- off unless turned on ----------------------------------------------------------


def test_an_account_that_has_not_opted_in_keeps_direct_downloads(reader):
    client, _, (bob, pw) = reader
    headers = _auth(bob, pw)
    item = _store(client, bob, "Plain")

    rows = _rows(client.get("/opds/recent", headers=headers).content)
    assert [(title, rel) for title, rel, _, _ in rows] == [("Plain", ACQUISITION_REL)]
    assert "Starred" not in [row[0] for row in _rows(client.get("/opds", headers=headers).content)]
    assert client.get(f"/opds/items/{item.id}", headers=headers).status_code == 404
    assert client.get(f"/opds/items/{item.id}/star", params={"rev": 0}, headers=headers).status_code == 404
    assert _stored(client, bob, item.id).starred_at is None


def test_the_operator_switch_turns_everything_off_including_old_links(reader):
    client, (alice, pw), _ = reader
    headers = _auth(alice, pw)
    item = _store(client, alice, "Switched")
    star = _row(_menu(client, headers, item), "Star")

    object.__setattr__(client.app.state.settings, "reader_actions_enabled", False)

    assert client.get(star, headers=headers).status_code == 404
    assert _stored(client, alice, item.id).starred_at is None
    rows = _rows(client.get("/opds/recent", headers=headers).content)
    assert [rel for _, rel, _, _ in rows] == [ACQUISITION_REL]


# -- shelves and menus -------------------------------------------------------------


def test_every_shelf_opens_item_menus(reader):
    client, (alice, pw), _ = reader
    headers = _auth(alice, pw)
    book = _store(client, alice, "Book")
    page = _store(client, alice, "Page", kind="article", source="url", source_url="https://example.com/a")
    shelves = {
        "/opds/recent": {"Book", "Page"},
        "/opds/books": {"Book"},
        "/opds/saved": {"Page"},
        "/opds/sites/example.com": {"Page"},
        f"/opds/authors/{author_token('Ann Author')}": {"Book", "Page"},
        "/opds/search?q=Boo": {"Book"},
    }
    for shelf, titles in shelves.items():
        rows = _rows(client.get(shelf, headers=headers).content)
        assert {title for title, _, _, _ in rows} == titles, shelf
        for title, rel, media_type, path in rows:
            assert (rel, media_type) == ("subsection", NAVIGATION_TYPE)
            item = book if title == "Book" else page
            assert path == f"/opds/items/{item.id}"


def test_the_menu_offers_the_real_download_star_and_delete(reader):
    client, (alice, pw), _ = reader
    headers = _auth(alice, pw)
    item = _store(client, alice, "Menu Book")

    response = client.get(f"/opds/items/{item.id}", headers=headers)
    assert response.headers["cache-control"] == "private, no-store"
    download, star, trash = _rows(response.content)
    # The download keeps the item's own title: CrossPoint names the file after it.
    assert download[:3] == ("Menu Book", ACQUISITION_REL, "application/epub+zip")
    assert client.get(download[3], headers=headers).content == client.app.state.storage.path_for(item).read_bytes()
    assert (star[0], star[2], star[3]) == ("Star", NAVIGATION_TYPE, f"/opds/items/{item.id}/star?rev=0")
    assert (trash[0], trash[3]) == ("Delete from Steepd", f"/opds/items/{item.id}/trash?rev=0")


# -- star --------------------------------------------------------------------------


def test_star_shows_on_the_starred_shelf_and_the_menu_offers_unstar(reader):
    client, (alice, pw), _ = reader
    headers = _auth(alice, pw)
    item = _store(client, alice, "Keeper")
    _store(client, alice, "Other")

    result = client.get(_row(_menu(client, headers, item), "Star"), headers=headers)
    assert [row[0] for row in _rows(result.content)] == ["Starred. Back to this item", "Back to library"]
    assert _stored(client, alice, item.id).starred_at is not None

    starred_href = _row(client.get("/opds", headers=headers).content, "Starred")
    assert [row[0] for row in _rows(client.get(starred_href, headers=headers).content)] == ["Keeper"]
    menu = client.get(_row(result.content, "Starred. Back to this item"), headers=headers)
    unstar = _row(menu.content, "Unstar")
    assert unstar == f"/opds/items/{item.id}/unstar?rev=1"

    result = client.get(unstar, headers=headers)
    assert _rows(result.content)[0][0] == "Unstarred. Back to this item"
    assert _stored(client, alice, item.id).starred_at is None
    assert _rows(client.get(starred_href, headers=headers).content) == []


def test_back_refetching_a_star_link_changes_nothing(reader):
    """Star, then Back: the reader requests the same Star URL again."""
    client, (alice, pw), _ = reader
    headers = _auth(alice, pw)
    item = _store(client, alice, "Twice")
    star = _row(_menu(client, headers, item), "Star")

    client.get(star, headers=headers)
    again = client.get(star, headers=headers)

    assert _rows(again.content)[0][0] == "Starred. Back to this item"
    assert _stored(client, alice, item.id).revision == 1


def test_an_old_star_link_cannot_undo_a_later_unstar(reader):
    """Star, Back to this item, Unstar, then Back twice: the old Star URL comes back."""
    client, (alice, pw), _ = reader
    headers = _auth(alice, pw)
    item = _store(client, alice, "Replayed")
    star = _row(_menu(client, headers, item), "Star")
    client.get(star, headers=headers)
    client.get(_row(_menu(client, headers, item), "Unstar"), headers=headers)

    replay = client.get(star, headers=headers)

    assert _rows(replay.content)[0] == (
        "Nothing changed. This item changed since you opened it. Reopen it",
        "subsection",
        NAVIGATION_TYPE,
        f"/opds/items/{item.id}",
    )
    assert _stored(client, alice, item.id).starred_at is None


# -- delete ------------------------------------------------------------------------


def test_delete_moves_the_item_to_trash_and_back_stays_harmless(reader):
    client, (alice, pw), _ = reader
    headers = _auth(alice, pw)
    item = _store(client, alice, "Doomed")
    menu = _menu(client, headers, item)
    trash, download = _row(menu, "Delete from Steepd"), _row(menu, "Doomed")
    deleted = "Deleted from Steepd. You can restore it on the website for 7 days"

    result = client.get(trash, headers=headers)
    assert [row[0] for row in _rows(result.content)] == [deleted, "Back to library"]
    database = client.app.state.database
    assert database.get_trashed_item(TenantScope(alice.id), item.id) is not None
    assert client.app.state.storage.path_for(item).is_file()
    assert _rows(client.get("/opds/recent", headers=headers).content) == []
    assert client.get(download, headers=headers).status_code == 404

    # Back from the result reaches the menu, then the same Delete link again.
    assert _rows(client.get(f"/opds/items/{item.id}", headers=headers).content)[0][0] == deleted
    assert _rows(client.get(trash, headers=headers).content)[0][0] == deleted
    star = f"/opds/items/{item.id}/star?rev=0"
    assert _rows(client.get(star, headers=headers).content)[0][0] == (
        "Nothing changed. This item was deleted from Steepd"
    )


def test_an_old_delete_link_cannot_delete_an_item_restored_since(reader):
    client, (alice, pw), _ = reader
    headers = _auth(alice, pw)
    item = _store(client, alice, "Rescued")
    trash = _row(_menu(client, headers, item), "Delete from Steepd")
    client.get(trash, headers=headers)
    client.app.state.storage.restore(TenantScope(alice.id), item.id)

    replay = client.get(trash, headers=headers)

    assert _rows(replay.content)[0][0].startswith("Nothing changed. This item changed")
    assert _stored(client, alice, item.id) is not None


def test_a_delete_from_a_menu_shown_before_a_star_does_nothing(reader):
    client, (alice, pw), _ = reader
    headers = _auth(alice, pw)
    item = _store(client, alice, "Menu")
    menu = _menu(client, headers, item)
    client.get(_row(menu, "Star"), headers=headers)

    client.get(_row(menu, "Delete from Steepd"), headers=headers)

    assert _stored(client, alice, item.id) is not None


# -- requests that must not act ----------------------------------------------------


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
def test_a_cross_site_browser_request_is_refused(reader, site):
    client, (alice, pw), _ = reader
    headers = _auth(alice, pw)
    item = _store(client, alice, "Target")
    star = _row(_menu(client, headers, item), "Star")

    assert client.get(star, headers={**headers, "Sec-Fetch-Site": site}).status_code == 403
    assert _stored(client, alice, item.id).starred_at is None
    assert client.get(star, headers={**headers, "Sec-Fetch-Site": "none"}).status_code == 200


def test_head_and_a_missing_revision_change_nothing(reader):
    client, (alice, pw), _ = reader
    headers = _auth(alice, pw)
    item = _store(client, alice, "Probed")
    trash = _row(_menu(client, headers, item), "Delete from Steepd")

    assert client.head(trash, headers=headers).status_code == 405
    assert client.get(f"/opds/items/{item.id}/trash", headers=headers).status_code == 422
    assert client.get(f"/opds/items/{item.id}/toggle", params={"rev": 0}, headers=headers).status_code == 404
    assert _stored(client, alice, item.id) is not None


def test_another_tenants_item_is_404(reader):
    client, (alice, pw), (bob, _) = reader
    headers = _auth(alice, pw)
    item = _store(client, bob, "Not yours")
    for path in (f"/opds/items/{item.id}", f"/opds/items/{item.id}/trash?rev=0"):
        assert client.get(path, headers=headers).status_code == 404
    assert _stored(client, bob, item.id) is not None


def test_the_account_page_turns_reader_actions_on_and_off(reader):
    client, _, (bob, _) = reader
    database = client.app.state.database
    token = issue_magic_token(database, bob.email)
    client.post(f"/auth/{token}")

    assert 'name="reader_actions"' in client.get("/account").text
    client.post("/account/reader-actions", data={"reader_actions": "yes"})
    assert database.tenant_by_id(bob.id).reader_actions is True
    client.post("/account/reader-actions", data={})
    assert database.tenant_by_id(bob.id).reader_actions is False
