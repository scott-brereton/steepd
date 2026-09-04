"""Turn one exact email-subject URL into Steepd's cleaned article document."""

from __future__ import annotations

import hashlib
import html as html_module
import unicodedata
from collections.abc import Callable
from urllib.parse import urlsplit

from trafilatura import extract, extract_metadata

from steepd.newsletter import (
    NewsletterConversionError,
    NewsletterDocument,
    NewsletterSizeError,
    RemoteImageFetcher,
    clean_article_html,
)
from steepd.remotefetch import (
    FetchedRemote,
    RemoteAccessDenied,
    RemoteBodyTooLarge,
    RemoteFetchError,
    fetch_remote,
)

HTML_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})

PageFetcher = Callable[..., FetchedRemote]


class UrlArticleError(RuntimeError):
    """An expected fetch or extraction rejection for a URL article."""


class UrlArticleTooLarge(UrlArticleError):
    """The fetched or cleaned webpage exceeded a configured size limit."""


def exact_subject_url(subject: object) -> str | None:
    """Return an exact absolute HTTP(S) subject URL without doing network work."""
    if not isinstance(subject, str):
        return None
    value = subject.strip()
    if not value or any(character.isspace() for character in value):
        return None
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
    except ValueError:
        return None
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.netloc or not host:
        return None
    return value


def _metadata_value(raw: object, maximum: int) -> str:
    if not isinstance(raw, str):
        return ""
    value = html_module.unescape(raw)
    value = "".join(character for character in value if character.isprintable())
    return unicodedata.normalize("NFC", " ".join(value.split()))[:maximum].strip()


def _display_hostname(hostname: str) -> str:
    return hostname.removeprefix("www.")[:253] or "This website"


def convert_url_article(
    url: str,
    *,
    public_base_url: str,
    max_body_bytes: int,
    created_at: str,
    fetch_remote_image: RemoteImageFetcher,
    fetch_page: PageFetcher = fetch_remote,
) -> NewsletterDocument:
    """Fetch, extract, and clean a public webpage without downloading through Trafilatura."""
    try:
        fetched = fetch_page(url, max_bytes=max_body_bytes)
    except RemoteAccessDenied as exc:
        hostname = _display_hostname(exc.hostname)
        raise UrlArticleError(f"{hostname} does not allow article capture.") from exc
    except RemoteBodyTooLarge as exc:
        raise UrlArticleTooLarge("The webpage exceeds the configured size limit.") from exc
    except RemoteFetchError as exc:
        raise UrlArticleError("The webpage could not be fetched safely.") from exc

    if fetched.content_type not in HTML_CONTENT_TYPES:
        raise UrlArticleError("The URL did not return an HTML webpage.")

    try:
        # Trafilatura's HTML serializer cannot represent list-valued metadata such as
        # article tags. Keep metadata out of that serializer and read it through the
        # library's dedicated metadata API instead.
        extracted = extract(
            fetched.content,
            url=fetched.final_url,
            output_format="html",
            with_metadata=False,
            include_comments=False,
            include_tables=True,
            include_images=True,
            include_links=True,
        )
    except (TypeError, ValueError) as exc:
        raise UrlArticleError("The webpage could not be read as an article.") from exc
    if not extracted or not extracted.strip():
        raise UrlArticleError("The webpage did not contain a readable article.")

    try:
        metadata = extract_metadata(fetched.content, default_url=fetched.final_url)
    except (TypeError, ValueError):
        metadata = None
    title = _metadata_value(getattr(metadata, "title", None), 1024)
    if not title:
        title = (urlsplit(fetched.final_url).hostname or "Saved webpage")[:1024]
    author = _metadata_value(getattr(metadata, "author", None), 200)
    document_key = hashlib.sha256(fetched.final_url.encode("utf-8")).hexdigest()[:32]

    try:
        return clean_article_html(
            extracted,
            title=title,
            author=author,
            source_url=fetched.final_url,
            created_at=created_at,
            document_key=document_key,
            public_base_url=public_base_url,
            max_output_bytes=max_body_bytes,
            fetch_remote_image=fetch_remote_image,
        )
    except NewsletterSizeError as exc:
        raise UrlArticleTooLarge("The cleaned webpage exceeds the configured size limit.") from exc
    except NewsletterConversionError as exc:
        raise UrlArticleError("The webpage did not contain a readable article.") from exc
