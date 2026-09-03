from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from steepd.epub import sanitize_filename
from steepd.epubgen import build_epub
from steepd.newsletter import NewsletterDocument, NewsletterResource
from steepd.storage import ItemStorage
from steepd.tenancy import TenantScope

_SUFFIXES = {"image/gif": ".gif", "image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}


class LocalNewsletterPublisher:
    """Implements the NewsletterPublisher Protocol by filing articles into our own library."""

    def __init__(self, storage: ItemStorage, scope: TenantScope) -> None:
        self.storage = storage
        self.scope = scope

    @staticmethod
    def _package_resources(
        document: NewsletterDocument,
        resources: Sequence[NewsletterResource],
    ) -> tuple[str, list[NewsletterResource]]:
        """Move each inline image to a relative path inside the archive.

        convert_newsletter points every inline <img> at an absolute public URL so the
        converted HTML also renders on the web. Inside an EPUB that same string becomes the
        archive member name, and a name containing "//" is rejected as an ambiguous archive
        path (epub.py:95) -- so an article with an inline image would never store. Rewriting
        the src alongside the member name keeps the book self-contained and offline-readable.

        The substitution is anchored on the whole src attribute, closing quote included. Those
        URLs end in a bare counter, so one ending in /1 is a prefix of one ending in /10:
        replacing the bare URL would corrupt every image from the tenth on into a name that
        nothing points at, and neither build_epub nor inspect_epub would object -- silent
        output corruption, not a crash. Anchoring also keeps the rewrite out
        of any body text that happens to quote the URL. Both quote styles are matched so this
        does not depend on how the caller's HTML was serialised.
        """
        body_html = document.html
        packaged: list[NewsletterResource] = []
        for index, resource in enumerate(resources, start=1):
            normalized = resource.content_type.casefold().split(";", 1)[0].strip()
            location = f"images/{index}{_SUFFIXES.get(normalized, '.bin')}"
            for mark in ('"', "'"):
                body_html = body_html.replace(
                    f"src={mark}{resource.location}{mark}", f"src={mark}{location}{mark}"
                )
            packaged.append(replace(resource, location=location))
        return body_html, packaged

    def publish(
        self,
        document: NewsletterDocument,
        resources: Sequence[NewsletterResource],
        labels: tuple[str, ...],
    ) -> str:
        body_html, packaged = self._package_resources(document, resources)
        payload = build_epub(
            title=document.title,
            author=document.author,
            language="en",
            identifier=f"urn:sha256:{document.content_sha256}",
            body_html=body_html,
            resources=packaged,
        )
        result = self.storage.store_bytes(
            self.scope,
            payload,
            filename=sanitize_filename(f"{document.title}.epub", fallback_title="article"),
            kind="article",
            source="newsletter",
            source_url=document.source_url,
            title=document.title,
            author=document.author,
        )
        return result.item.id
