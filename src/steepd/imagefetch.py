"""Fetch a remote newsletter image through Steepd's shared SSRF boundary."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

import httpx

from steepd.newsletter import SAFE_INLINE_IMAGE_TYPES
from steepd.remotefetch import RemoteFetchError, fetch_remote


class ImageFetchError(RuntimeError):
    """The image could not be fetched safely or was not a supported image payload."""


@dataclass(frozen=True, slots=True)
class FetchedImage:
    content_type: str
    content: bytes


def _sniff_image_type(content: bytes) -> str:
    """Identify the payload from magic bytes rather than attacker-controlled headers."""
    if content.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if content.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        return "image/webp"
    return ""


def fetch_remote_image(
    url: str,
    *,
    max_bytes: int,
    transport: httpx.BaseTransport | None = None,
    resolve_host: Callable[[str], Sequence[str]] | None = None,
) -> FetchedImage:
    """Fetch one remote image, or raise ``ImageFetchError``. Never returns partial data."""
    try:
        fetched = fetch_remote(
            url,
            max_bytes=max_bytes,
            transport=transport,
            resolve_host=resolve_host,
        )
    except RemoteFetchError as exc:
        raise ImageFetchError(str(exc)) from exc

    content_type = _sniff_image_type(fetched.content)
    if content_type not in SAFE_INLINE_IMAGE_TYPES:
        raise ImageFetchError("Image payload is not a supported image format")
    return FetchedImage(content_type=content_type, content=fetched.content)
