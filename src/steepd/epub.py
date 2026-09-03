from __future__ import annotations

import posixpath
import re
import stat
import unicodedata
import xml.etree.ElementTree as StandardElementTree
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

from defusedxml import ElementTree as SafeElementTree
from defusedxml.common import DefusedXmlException

from .config import Settings

EPUB_MIME_TYPE = "application/epub+zip"
ALLOWED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


class EpubImportError(ValueError):
    status_code = 422


class UploadTooLarge(EpubImportError):
    status_code = 413


class StorageQuotaExceeded(EpubImportError):
    """Raised by ItemStorage, not by anything here -- like UploadTooLarge. The hierarchy
    lives in one module because callers dispatch on EpubImportError.status_code alone, and
    413 is as true of a full account as it is of an oversized file."""

    status_code = 413


class ServiceStorageFull(EpubImportError):
    """The volume itself is out of room, as opposed to one account being at its allowance.
    507 rather than 413 so the two are distinguishable in the webhook result and the log,
    and because the message a reader gets must say this is our problem, not theirs."""

    status_code = 507


class UnsafeEpub(EpubImportError):
    pass


@dataclass(frozen=True, slots=True)
class EpubMetadata:
    title: str
    author: str
    language: str
    identifier: str


def _bounded_text(value: str, maximum: int) -> str:
    normalized = unicodedata.normalize("NFC", " ".join(value.split()))
    return normalized[:maximum]


def sanitize_filename(filename: str, *, fallback_title: str = "book", maximum_bytes: int = 180) -> str:
    candidate = unicodedata.normalize("NFC", filename or "")
    candidate = candidate.replace("\\", "/").rsplit("/", 1)[-1]
    candidate = "".join(character for character in candidate if unicodedata.category(character) != "Cc")
    candidate = re.sub(r"[<>:\"/\\|?*]", "_", candidate)
    candidate = re.sub(r"\s+", " ", candidate).strip().rstrip(" .")

    if candidate.lower().endswith(".epub"):
        stem = candidate[:-5].strip(" .")
    else:
        stem = candidate.strip(" .")
    if not stem:
        stem = _bounded_text(fallback_title, 120).strip(" .") or "book"
    if stem.upper() in WINDOWS_RESERVED_NAMES:
        stem = f"_{stem}"

    suffix = ".epub"
    byte_budget = max(16, maximum_bytes - len(suffix.encode("utf-8")))
    while len(stem.encode("utf-8")) > byte_budget:
        stem = stem[:-1]
    stem = stem.rstrip(" .") or "book"
    return f"{stem}{suffix}"


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def _element_text(element: object | None) -> str:
    if element is None:
        return ""
    return "".join(element.itertext()).strip()


def _safe_member_name(name: str) -> str:
    if not name or "\x00" in name or "\\" in name or len(name.encode("utf-8")) > 1_024:
        raise UnsafeEpub("EPUB contains an unsafe archive path")
    if name.startswith(("/", "//")) or re.match(r"^[A-Za-z]:", name):
        raise UnsafeEpub("EPUB contains an absolute archive path")
    if "//" in name:
        raise UnsafeEpub("EPUB contains an ambiguous archive path")
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise UnsafeEpub("EPUB contains a path-traversal archive member")
    return path.as_posix()


def _safe_manifest_path(package_path: str, href: str) -> str:
    parsed = urlsplit(href)
    if parsed.scheme or parsed.netloc:
        raise UnsafeEpub("EPUB spine references a remote resource")
    decoded = unquote(parsed.path)
    _safe_member_name(decoded)
    combined = posixpath.normpath(posixpath.join(posixpath.dirname(package_path), decoded))
    return _safe_member_name(combined)


def _read_bounded(archive: zipfile.ZipFile, info: zipfile.ZipInfo, maximum: int, label: str) -> bytes:
    if info.file_size > maximum:
        raise UnsafeEpub(f"{label} is unreasonably large")
    try:
        return archive.read(info)
    except (RuntimeError, NotImplementedError, OSError, zipfile.BadZipFile) as exc:
        raise UnsafeEpub(f"Unable to read {label}") from exc


def inspect_epub(path: Path, settings: Settings, *, fallback_title: str) -> EpubMetadata:
    if not zipfile.is_zipfile(path):
        raise UnsafeEpub("The upload is not a valid ZIP/EPUB archive")

    try:
        with zipfile.ZipFile(path, "r") as archive:
            members = archive.infolist()
            if not members:
                raise UnsafeEpub("EPUB archive is empty")
            if len(members) > settings.max_archive_members:
                raise UnsafeEpub("EPUB contains too many archive members")

            names: dict[str, zipfile.ZipInfo] = {}
            total_uncompressed = 0
            total_compressed = 0
            for info in members:
                safe_name = _safe_member_name(info.filename.rstrip("/") or info.filename)
                if safe_name in names:
                    raise UnsafeEpub("EPUB contains duplicate archive member names")
                names[safe_name] = info
                if info.flag_bits & 0x1:
                    raise UnsafeEpub("Password-encrypted EPUB archives are not supported")
                file_type = (info.external_attr >> 16) & 0o170000
                if file_type == stat.S_IFLNK:
                    raise UnsafeEpub("EPUB contains a symbolic link")
                if not info.is_dir() and info.compress_type not in ALLOWED_COMPRESSION:
                    raise UnsafeEpub("EPUB uses an unsupported compression method")
                total_uncompressed += info.file_size
                total_compressed += max(info.compress_size, 1)

            if total_uncompressed > settings.max_archive_bytes:
                raise UnsafeEpub("EPUB expands beyond the configured safety limit")
            if (
                total_uncompressed > 1024 * 1024
                and total_uncompressed / total_compressed > settings.max_compression_ratio
            ):
                raise UnsafeEpub("EPUB has a suspicious compression ratio")

            # The specification wants `mimetype` first and stored, and files built by hand
            # or by older tools get one or both wrong while every reader still opens them.
            # Its position and compression are a packaging nicety, not a safety property,
            # so only its presence and content are required: a wrong value here is what
            # says this ZIP is not an EPUB at all.
            mimetype_info = names.get("mimetype")
            if mimetype_info is None:
                raise UnsafeEpub("EPUB is missing its mimetype declaration")
            mimetype = _read_bounded(archive, mimetype_info, 128, "EPUB mimetype").decode("ascii", errors="strict")
            if mimetype.strip() != EPUB_MIME_TYPE:
                raise UnsafeEpub("EPUB has an invalid mimetype declaration")

            if "META-INF/encryption.xml" in names:
                raise UnsafeEpub("EPUB content encryption is not supported")
            container_info = names.get("META-INF/container.xml")
            if container_info is None:
                raise UnsafeEpub("EPUB is missing META-INF/container.xml")
            try:
                container_root = SafeElementTree.fromstring(
                    _read_bounded(archive, container_info, 1024 * 1024, "EPUB container document")
                )
            except (DefusedXmlException, StandardElementTree.ParseError) as exc:
                raise UnsafeEpub("EPUB container document is malformed") from exc

            package_path = ""
            for element in container_root.iter():
                if _local_name(element.tag) != "rootfile":
                    continue
                candidate = element.attrib.get("full-path", "")
                media_type = element.attrib.get("media-type", "")
                if candidate and (not package_path or media_type == "application/oebps-package+xml"):
                    package_path = _safe_member_name(candidate)
                    if media_type == "application/oebps-package+xml":
                        break
            if not package_path or package_path not in names:
                raise UnsafeEpub("EPUB package document cannot be resolved")

            try:
                package_root = SafeElementTree.fromstring(
                    _read_bounded(archive, names[package_path], 5 * 1024 * 1024, "EPUB package document")
                )
            except (DefusedXmlException, StandardElementTree.ParseError) as exc:
                raise UnsafeEpub("EPUB package document is malformed") from exc
            if _local_name(package_root.tag) != "package":
                raise UnsafeEpub("EPUB package document has an invalid root element")

            metadata_node = next((item for item in package_root.iter() if _local_name(item.tag) == "metadata"), None)
            if metadata_node is None:
                raise UnsafeEpub("EPUB package document has no metadata section")

            titles = [_element_text(item) for item in metadata_node.iter() if _local_name(item.tag) == "title"]
            creators = [_element_text(item) for item in metadata_node.iter() if _local_name(item.tag) == "creator"]
            languages = [_element_text(item) for item in metadata_node.iter() if _local_name(item.tag) == "language"]
            identifiers = [item for item in metadata_node.iter() if _local_name(item.tag) == "identifier"]

            unique_identifier = package_root.attrib.get("unique-identifier", "")
            selected_identifier = ""
            if unique_identifier:
                for item in identifiers:
                    if item.attrib.get("id") == unique_identifier:
                        selected_identifier = _element_text(item)
                        break
            if not selected_identifier and identifiers:
                selected_identifier = _element_text(identifiers[0])

            manifest: dict[str, str] = {}
            for item in package_root.iter():
                if _local_name(item.tag) == "item" and item.attrib.get("id") and item.attrib.get("href"):
                    manifest[item.attrib["id"]] = item.attrib["href"]
            spine_refs = [
                item.attrib.get("idref", "") for item in package_root.iter() if _local_name(item.tag) == "itemref"
            ]
            if not manifest or not any(spine_refs):
                raise UnsafeEpub("EPUB package has no readable spine")
            for item_ref in spine_refs:
                href = manifest.get(item_ref)
                if not href:
                    raise UnsafeEpub("EPUB spine references an unknown manifest item")
                content_path = _safe_manifest_path(package_path, href)
                if content_path not in names:
                    raise UnsafeEpub("EPUB spine references a missing content file")

            corrupt_member = archive.testzip()
            if corrupt_member is not None:
                raise UnsafeEpub("EPUB contains corrupt archive data")

            title = next((item for item in titles if item), fallback_title)
            author = "; ".join(dict.fromkeys(item for item in creators if item))
            language = next((item for item in languages if item), "")
            return EpubMetadata(
                title=_bounded_text(title, 300) or "Untitled",
                author=_bounded_text(author, 240),
                language=_bounded_text(language, 64),
                identifier=_bounded_text(selected_identifier, 300),
            )
    except UnicodeDecodeError as exc:
        raise UnsafeEpub("EPUB mimetype is not valid ASCII") from exc
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, RuntimeError, NotImplementedError) as exc:
        raise UnsafeEpub("EPUB archive is malformed or unreadable") from exc
