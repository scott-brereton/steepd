import io
import posixpath
import zipfile
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from bs4 import BeautifulSoup

from steepd.config import Settings
from steepd.db import Database
from steepd.newsletter import (
    NewsletterConversionError,
    NewsletterConversionStats,
    NewsletterDocument,
    NewsletterEmail,
    NewsletterResource,
    convert_newsletter,
)
from steepd.publisher import LocalNewsletterPublisher
from steepd.storage import ItemStorage
from steepd.tenancy import TenantScope


@pytest.fixture
def publisher(tmp_path):
    settings = Settings(data_dir=tmp_path, public_base_url="http://localhost:8000")
    database = Database(tmp_path / "steepd.sqlite3")
    database.initialize()
    store = ItemStorage(settings, database)
    store.initialize()
    tenant = database.create_tenant(email="a@example.com", inbox_local="a.1")
    scope = TenantScope(tenant.id)
    return database, store, scope, LocalNewsletterPublisher(store, scope)


def _document(title: str = "Weekly digest") -> NewsletterDocument:
    return NewsletterDocument(
        title=title,
        html="<h1>Weekly digest</h1><p>Something worth reading.</p>",
        source_url="https://example.com/weekly",
        author="Weekly Writer",
        created_at=datetime.now(UTC).isoformat(),
        content_sha256="a" * 64,
        inline_images=(),
        stats=NewsletterConversionStats(0, 0, 1.0, 0, 0, 0, 0, 0),
    )


def test_publishing_files_an_article_item(publisher):
    database, _, scope, pub = publisher

    item_id = pub.publish(_document(), [], ("newsletter",))

    item = database.get_item(scope, item_id)
    assert item is not None
    assert item.kind == "article"
    assert item.title == "Weekly digest"
    assert item.author == "Weekly Writer"
    assert item.source_url == "https://example.com/weekly"


def test_published_article_is_a_readable_epub(publisher):
    _, store, scope, pub = publisher
    item_id = pub.publish(_document(), [], ("newsletter",))
    payload = store.path_for(store.database.get_item(scope, item_id)).read_bytes()
    assert payload.startswith(b"PK")
    # The body is DEFLATE-compressed inside the archive, so it never appears in the raw
    # bytes. Open the archive and read the document to assert on the content itself.
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        name = next(n for n in archive.namelist() if n.endswith("index.xhtml"))
        assert b"Something worth reading" in archive.read(name)


def test_real_newsletter_email_converts_and_publishes(publisher):
    database, _, scope, pub = publisher
    # convert_newsletter enforces a quality gate at newsletter.py:604 - a body with under 80
    # visible characters and no images is rejected as not enough readable content. Real
    # newsletters clear this easily; a toy fixture does not, so use a realistic body.
    body = (
        "<table><tr><td><p>The Monday note covers three things this week: what shipped, "
        "what broke, and what we learned from the outage on Thursday afternoon.</p>"
        "<p>Full write-up below, with the timeline and the follow-up actions.</p>"
        "</td></tr></table>"
    )
    email = NewsletterEmail(
        id="email-1", sender="news@example.com", recipients=("a.1@read.steepd.app",),
        subject="Fwd: The Monday note", html=body,
        text="", created_at=datetime.now(UTC).isoformat(), message_id="<m1@example.com>",
    )
    document = convert_newsletter(email, public_base_url="http://localhost:8000")

    item_id = pub.publish(document, [], ("newsletter",))

    assert database.get_item(scope, item_id).kind == "article"


def test_a_newsletter_with_no_real_content_is_rejected_before_publishing(publisher):
    """The quality gate is product behaviour, not an obstacle - assert it stays live."""
    database, _, scope, pub = publisher
    email = NewsletterEmail(
        id="email-2", sender="news@example.com", recipients=("a.1@read.steepd.app",),
        subject="Fwd: Empty", html="<p>Hi.</p>", text="",
        created_at=datetime.now(UTC).isoformat(), message_id="<m2@example.com>",
    )

    with pytest.raises(NewsletterConversionError):
        convert_newsletter(email, public_base_url="http://localhost:8000")

    assert database.count_items(scope) == 0


def test_inline_image_is_packaged_at_a_relative_path(publisher):
    """convert_newsletter points inline <img> at an absolute URL. Used verbatim as an
    archive member name that is an unsafe path, so the article would never store."""
    _, store, scope, pub = publisher
    image = b"\x89PNG\r\n\x1a\nhero"
    location = "http://localhost:8000/newsletters/email-1/inline/1"
    document = replace(
        _document(),
        html=f"<h1>Weekly digest</h1><p>Something worth reading.</p><img src='{location}' alt='Hero'>",
    )

    item_id = pub.publish(document, [NewsletterResource(location, "image/png", image)], ("newsletter",))

    payload = store.path_for(store.database.get_item(scope, item_id)).read_bytes()
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        assert any(name.endswith("images/1.png") and archive.read(name) == image for name in archive.namelist())
        chapter = next(name for name in archive.namelist() if name.endswith("index.xhtml"))
        assert b"images/1.png" in archive.read(chapter)
        assert location.encode() not in archive.read(chapter)


def test_every_inline_image_reference_resolves_to_a_real_archive_member(publisher):
    """The inline URLs end in a bare counter, so one ending in /1 is a prefix of one ending
    in /10.
    Eleven images is enough to catch a substitution that is not anchored to the attribute.
    Asserts the src-to-member relationship, not a list of names: a test that only checked
    images/11.png existed would still pass while nothing referenced it."""
    _, store, scope, pub = publisher
    count = 11
    body = (
        "<p>The Monday note covers three things this week: what shipped, what broke, and "
        "what we learned from the outage on Thursday afternoon.</p>"
        + "".join(f"<img src='cid:img-{n}' alt='Figure {n}'>" for n in range(1, count + 1))
    )
    email = NewsletterEmail(
        id="email-many-images", sender="news@example.com", recipients=("a.1@read.steepd.app",),
        subject="Fwd: The Monday note", html=body, text="",
        created_at=datetime.now(UTC).isoformat(), message_id="<many@example.com>",
    )
    document = convert_newsletter(
        email,
        public_base_url="http://localhost:8000",
        inline_image_types={f"img-{n}": "image/png" for n in range(1, count + 1)},
    )
    assert len(document.inline_images) == count
    resources = [
        NewsletterResource(reference.location, "image/png", f"image-bytes-{index}".encode())
        for index, reference in enumerate(document.inline_images, start=1)
    ]

    item_id = pub.publish(document, resources, ("newsletter",))

    payload = store.path_for(store.database.get_item(scope, item_id)).read_bytes()
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = set(archive.namelist())
        chapter = next(name for name in names if name.endswith("index.xhtml"))
        directory = posixpath.dirname(chapter)
        sources = [
            str(tag["src"])
            for tag in BeautifulSoup(archive.read(chapter), "html.parser").find_all("img")
        ]
        assert len(sources) == count
        referenced = {posixpath.normpath(posixpath.join(directory, src)) for src in sources}
        # Every src resolves to a member that is really there, and carries the right bytes.
        assert referenced <= names
        assert {archive.read(name) for name in referenced} == {resource.content for resource in resources}
        # And no packaged image is left in the archive with nothing pointing at it.
        assert {name for name in names if "/images/" in name} == referenced
