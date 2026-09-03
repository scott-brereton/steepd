from __future__ import annotations

import tempfile
from collections.abc import Sequence
from pathlib import Path
from xml.sax.saxutils import escape

from ebooklib import epub

from steepd.newsletter import NewsletterResource

_IMAGE_TYPES = {"image/gif", "image/jpeg", "image/png", "image/webp"}


def _media_type(location: str, declared: str) -> str:
    normalized = declared.casefold().split(";", 1)[0].strip()
    if normalized in _IMAGE_TYPES:
        return normalized
    suffix = location.rsplit(".", 1)[-1].casefold() if "." in location else ""
    return {"gif": "image/gif", "jpg": "image/jpeg", "jpeg": "image/jpeg",
             "png": "image/png", "webp": "image/webp"}.get(suffix, "application/octet-stream")


def build_epub(
    *,
    title: str,
    author: str,
    language: str,
    identifier: str,
    body_html: str,
    resources: Sequence[NewsletterResource] = (),
) -> bytes:
    """Build an EPUB from cleaned article HTML.

    Thin wrapper over EbookLib so callers depend on this signature, not the library API.
    """
    book = epub.EpubBook()
    book.set_identifier(identifier.strip() or "urn:uuid:steepd-item")
    book.set_title(title)
    book.set_language(language.strip() or "en")
    if author:
        book.add_author(author)

    # EbookLib 0.20 has no `epub.escape`; use the stdlib XML escaper instead. EbookLib's own
    # metadata handling (title/author/etc.) already escapes safely, so this only covers the
    # heading we inject manually below.
    chapter = epub.EpubHtml(title=title, file_name="index.xhtml", lang=language.strip() or "en")
    chapter.content = f"<h1>{escape(title)}</h1>{body_html}"
    book.add_item(chapter)

    for resource in resources:
        book.add_item(
            epub.EpubItem(
                uid=resource.location,
                file_name=resource.location,
                media_type=_media_type(resource.location, resource.content_type),
                content=resource.content,
            )
        )

    book.toc = (chapter,)
    book.spine = ["nav", chapter]
    book.add_item(epub.EpubNcx())
    book.add_item(epub.EpubNav())

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "out.epub"
        epub.write_epub(path, book)
        return path.read_bytes()
