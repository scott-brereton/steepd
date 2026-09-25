"""The reader action probe: a hidden catalogue whose action rows only log.

These follow generated hrefs rather than building URLs, for the reason test_app.py gives.
"""

from __future__ import annotations

import base64
import xml.etree.ElementTree as ElementTree

import pytest
from fastapi.testclient import TestClient

from steepd.app import create_app
from steepd.config import Settings
from steepd.epubgen import build_epub
from steepd.opds import ACQUISITION_REL, ATOM, NAVIGATION_TYPE
from steepd.tenancy import TenantScope

BASE_URL = "http://localhost:8000"


def _client(tmp_path, *, probe_for_alice: bool):
    settings = Settings(data_dir=tmp_path, public_base_url=BASE_URL)
    app = create_app(settings)
    database = app.state.database
    alice, alice_pw = database.create_tenant_with_password(email="a@example.com", inbox_local="a.1")
    bob, bob_pw = database.create_tenant_with_password(email="b@example.com", inbox_local="b.2")
    if probe_for_alice:
        # Settings is frozen, and create_app closes over the instance it was given.
        object.__setattr__(settings, "opds_probe_usernames", (alice.opds_username,))
    return TestClient(app), (alice, alice_pw), (bob, bob_pw)


def _auth(tenant, password):
    raw = f"{tenant.opds_username}:{password}".encode()
    return {"Authorization": f"Basic {base64.b64encode(raw).decode()}"}


def _store(client, tenant, title):
    return client.app.state.storage.store_bytes(
        TenantScope(tenant.id),
        build_epub(title=title, author="Ann Author", language="en", identifier=f"urn:uuid:{title}", body_html="<p/>"),
        filename=f"{title}.epub",
        kind="book",
        source="email",
        title=title,
        author="Ann Author",
    ).item


def _path(href: str) -> str:
    assert href.startswith(BASE_URL), href
    return href[len(BASE_URL) :]


def _entries(content: bytes) -> list[tuple[str, str, str, str]]:
    """(title, rel, type, href) for each entry's first link."""
    root = ElementTree.fromstring(content)
    rows = []
    for entry in root.iter(f"{{{ATOM}}}entry"):
        link = entry.find(f"{{{ATOM}}}link")
        rows.append((entry.findtext(f"{{{ATOM}}}title"), link.get("rel"), link.get("type"), link.get("href")))
    return rows


def test_the_probe_is_hidden_unless_the_username_is_listed(tmp_path):
    client, (alice, pw), _ = _client(tmp_path, probe_for_alice=False)
    headers = _auth(alice, pw)
    assert "Action probe" not in [row[0] for row in _entries(client.get("/opds", headers=headers).content)]
    assert client.get("/opds/probe", headers=headers).status_code == 404


def test_the_probe_needs_credentials(tmp_path):
    client, *_ = _client(tmp_path, probe_for_alice=True)
    assert client.get("/opds/probe").status_code == 401


def test_menu_rows_and_action_results(tmp_path):
    client, (alice, pw), _ = _client(tmp_path, probe_for_alice=True)
    headers = _auth(alice, pw)
    item = _store(client, alice, "Probe Book")

    root = _entries(client.get("/opds", headers=headers).content)
    probe_href = next(href for title, _, _, href in root if title == "Action probe")
    listing = _entries(client.get(_path(probe_href), headers=headers).content)
    assert [(title, media_type) for title, _, media_type, _ in listing] == [("Probe Book", NAVIGATION_TYPE)]

    menu = client.get(_path(listing[0][3]), headers=headers)
    assert menu.headers["cache-control"] == "private, no-store"
    download, star, trash = _entries(menu.content)
    # The download row keeps the item's own title: CrossPoint names the file after it.
    assert download[:3] == ("Probe Book", ACQUISITION_REL, "application/epub+zip")
    assert client.get(_path(download[3]), headers=headers).content == client.app.state.storage.path_for(
        item
    ).read_bytes()
    assert (star[0], star[2]) == ("Star", NAVIGATION_TYPE)
    assert (trash[0], trash[2]) == ("Delete from Steepd", NAVIGATION_TYPE)

    first = _entries(client.get(_path(star[3]), headers=headers).content)
    assert first[0][0] == "Star request #1 logged. Nothing changed. Return to item"
    assert _path(first[0][3]) == _path(listing[0][3])
    assert first[1][0] == "Back to library"
    again = _entries(client.get(_path(star[3]), headers=headers).content)
    assert again[0][0].startswith("Star request #2 logged")

    client.get(_path(trash[3]), headers=headers)
    # Nothing changed: the item is still listed and still downloads.
    assert client.app.state.database.get_item(TenantScope(alice.id), item.id) == item
    assert client.get(_path(download[3]), headers=headers).status_code == 200


def test_an_empty_library_still_gives_a_row(tmp_path):
    client, (alice, pw), _ = _client(tmp_path, probe_for_alice=True)
    rows = _entries(client.get("/opds/probe", headers=_auth(alice, pw)).content)
    assert [(title, _path(href)) for title, _, _, href in rows] == [("Nothing to test yet. Back to library", "/opds")]


@pytest.mark.parametrize("suffix", ["", "/star", "/trash"])
def test_another_tenants_item_is_404(tmp_path, suffix):
    client, (alice, alice_pw), (bob, bob_pw) = _client(tmp_path, probe_for_alice=True)
    item = _store(client, bob, "Bob Book")
    path = f"/opds/probe/items/{item.id}" if not suffix else f"/opds/probe/actions/{item.id}{suffix}"
    assert client.get(path, headers=_auth(alice, alice_pw)).status_code == 404
    # Bob is not listed, so even his own item's probe routes do not exist for him.
    assert client.get(path, headers=_auth(bob, bob_pw)).status_code == 404


def test_an_unknown_verb_is_404(tmp_path):
    client, (alice, pw), _ = _client(tmp_path, probe_for_alice=True)
    item = _store(client, alice, "Probe Book")
    assert client.get(f"/opds/probe/actions/{item.id}/unstar", headers=_auth(alice, pw)).status_code == 404
