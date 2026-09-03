from __future__ import annotations

import hashlib
import html as html_module
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from email.utils import parseaddr
from typing import Protocol
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup, Comment, NavigableString, Tag


class NewsletterError(RuntimeError):
    pass


class NewsletterConversionError(NewsletterError):
    pass


class NewsletterForwardingError(NewsletterError):
    pass


@dataclass(frozen=True, slots=True)
class NewsletterEmail:
    id: str
    sender: str
    recipients: tuple[str, ...]
    subject: str
    html: str
    text: str
    created_at: str
    message_id: str


@dataclass(frozen=True, slots=True)
class InlineImageReference:
    content_id: str
    location: str
    content_type: str


@dataclass(frozen=True, slots=True)
class NewsletterResource:
    location: str
    content_type: str
    content: bytes


@dataclass(frozen=True, slots=True)
class NewsletterConversionStats:
    input_text_chars: int
    output_text_chars: int
    retained_text_ratio: float
    links_kept: int
    images_kept: int
    tracking_images_removed: int
    layout_tables_flattened: int
    data_tables_preserved: int
    remote_images_inlined: int = 0
    remote_images_failed: int = 0


@dataclass(frozen=True, slots=True)
class NewsletterDocument:
    title: str
    html: str
    source_url: str
    # The byline the article is filed under: the original sender of a forwarded message
    # where the forwarding client left it recoverable, otherwise the display name of
    # whoever sent the email to us, otherwise "". See _article_author.
    author: str
    created_at: str
    content_sha256: str
    inline_images: tuple[InlineImageReference, ...]
    stats: NewsletterConversionStats
    remote_resources: tuple[NewsletterResource, ...] = ()


class NewsletterPublisher(Protocol):
    def publish(
        self,
        document: NewsletterDocument,
        resources: Sequence[NewsletterResource],
        labels: tuple[str, ...],
    ) -> str: ...


SAFE_INLINE_IMAGE_TYPES = frozenset({"image/gif", "image/jpeg", "image/png", "image/webp"})

# A callable that fetches one remote image. Returns (content_type, content) where
# content_type is one of SAFE_INLINE_IMAGE_TYPES, or None on ANY failure. Must not raise.
RemoteImageFetcher = Callable[[str], tuple[str, bytes] | None]

_DANGEROUS_TAGS = frozenset(
    {
        "applet",
        "audio",
        "base",
        "button",
        "canvas",
        "embed",
        "form",
        "frame",
        "frameset",
        "iframe",
        "input",
        "link",
        "math",
        "meta",
        "object",
        "option",
        "script",
        "select",
        "source",
        "style",
        "svg",
        "textarea",
        "video",
    }
)

_ALLOWED_TAGS = frozenset(
    {
        "a",
        "abbr",
        "article",
        "b",
        "blockquote",
        "body",
        "br",
        "caption",
        "code",
        "col",
        "colgroup",
        "dd",
        "del",
        "details",
        "div",
        "dl",
        "dt",
        "em",
        "figcaption",
        "figure",
        "footer",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "hr",
        "i",
        "img",
        "ins",
        "li",
        "main",
        "mark",
        "ol",
        "p",
        "pre",
        "s",
        "section",
        "small",
        "span",
        "strong",
        "sub",
        "summary",
        "sup",
        "table",
        "tbody",
        "td",
        "tfoot",
        "th",
        "thead",
        "time",
        "tr",
        "u",
        "ul",
    }
)

_GLOBAL_ATTRIBUTES = frozenset({"dir", "lang"})
_TAG_ATTRIBUTES: dict[str, frozenset[str]] = {
    "a": frozenset({"href", "title"}),
    "abbr": frozenset({"title"}),
    "blockquote": frozenset({"cite"}),
    "col": frozenset({"span"}),
    "ol": frozenset({"reversed", "start"}),
    "li": frozenset({"value"}),
    "img": frozenset({"alt", "src", "title"}),
    "td": frozenset({"colspan", "rowspan"}),
    "th": frozenset({"colspan", "rowspan", "scope"}),
    "time": frozenset({"datetime"}),
}

_FORWARD_PREFIX = re.compile(r"^\s*(?:(?:fwd?|fw|wg|tr)\s*:\s*)+", re.IGNORECASE)
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_VIEW_ONLINE = re.compile(
    r"(?:view.{0,30}(?:browser|online|web)|read.{0,30}(?:online|web|substack)|open.{0,30}(?:browser|web))",
    re.IGNORECASE,
)
_FORWARDED_MARKER = re.compile(r"(?:forwarded|original)\s+message|begin\s+forwarded\s+message", re.IGNORECASE)
_TRACKING_QUERY_KEYS = frozenset(
    {
        "access_token",
        "fbclid",
        "gclid",
        "mc_cid",
        "mc_eid",
        "mkt_tok",
        "token",
    }
)
_TRACKING_HOST_SUFFIXES = (
    ".list-manage.com",
    ".substack.com",
    "open.substack.com",
    "substack.com",
    "spyglass.org",
)
_TRACKING_HOST_QUERY_KEYS = frozenset(
    {
        "action",
        "c2id",
        "e",
        "inbox",
        "isfreemail",
        "j",
        "m",
        "r",
        "redirect",
        "submitlike",
        "triggershare",
    }
)
_SOURCE_STOP_WORDS = frozenset(
    {"about", "after", "again", "from", "have", "into", "newsletter", "that", "this", "with", "your"}
)


def normalize_content_id(value: str) -> str:
    return value.strip().strip("<>").casefold()


def clean_newsletter_title(subject: str) -> str:
    title = html_module.unescape(_CONTROL_CHARS.sub("", subject or ""))
    title = _FORWARD_PREFIX.sub("", title).strip()
    return " ".join(title.split())[:1024] or "Forwarded newsletter"


def _visible_text(node: Tag | BeautifulSoup) -> str:
    return " ".join(node.get_text(" ", strip=True).split())


def _safe_http_url(value: str, *, remove_tracking: bool = True) -> str:
    value = html_module.unescape(value or "").strip()
    if value.startswith("//"):
        value = "https:" + value
    if not value or len(value) > 4096:
        return ""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return ""
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return ""

    host = parsed.hostname.casefold()
    if host in {"google.com", "www.google.com"} and parsed.path == "/url":
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        redirected = query.get("q") or query.get("url")
        if redirected:
            return _safe_http_url(redirected, remove_tracking=remove_tracking)

    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    if remove_tracking:
        filtered: list[tuple[str, str]] = []
        tracking_host = host == "substack.com" or any(host.endswith(suffix) for suffix in _TRACKING_HOST_SUFFIXES)
        for key, item in query_items:
            normalized_key = key.casefold()
            if normalized_key.startswith("utm_") or normalized_key in _TRACKING_QUERY_KEYS:
                continue
            if tracking_host and normalized_key in _TRACKING_HOST_QUERY_KEYS:
                continue
            filtered.append((key, item))
        query_items = filtered

    cleaned = urlunsplit(
        (
            parsed.scheme.casefold(),
            parsed.netloc,
            parsed.path or "/",
            urlencode(query_items, doseq=True),
            "",
        )
    )
    return cleaned if len(cleaned) <= 1024 else ""


def _safe_href(value: str, *, base_url: str) -> str:
    value = html_module.unescape(value or "").strip()
    if not value:
        return ""
    if value.casefold().startswith("mailto:"):
        return value[:2048] if "\r" not in value and "\n" not in value else ""
    if not urlsplit(value).scheme and base_url:
        value = urljoin(base_url, value)
    return _safe_http_url(value)


def _source_tokens(title: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]{4,}", title.casefold()) if token not in _SOURCE_STOP_WORDS}


def _find_source_url(soup: BeautifulSoup, title: str) -> str:
    candidates: list[tuple[int, str]] = []
    for link in soup.find_all("link", href=True):
        rel = {str(item).casefold() for item in link.get("rel", [])}
        if "canonical" in rel:
            candidates.append((120, str(link["href"])))
    for meta in soup.find_all("meta"):
        key = str(meta.get("property") or meta.get("name") or "").casefold()
        if key in {"og:url", "twitter:url"} and meta.get("content"):
            candidates.append((115, str(meta["content"])))

    title_tokens = _source_tokens(title)
    for anchor in soup.find_all("a", href=True):
        href = str(anchor.get("href") or "")
        try:
            parsed = urlsplit(href)
        except ValueError:
            continue
        host = (parsed.hostname or "").casefold()
        path = parsed.path.casefold()
        label = _visible_text(anchor)
        score = 0
        if host == "open.substack.com" and "/pub/" in path and "/p/" in path:
            score = 110
        elif _VIEW_ONLINE.search(label):
            score = 100
        elif "/p/" in path:
            score = 70
        elif title_tokens:
            label_tokens = _source_tokens(label)
            overlap = len(title_tokens & label_tokens)
            if overlap >= min(3, len(title_tokens)):
                score = 65
        if score:
            candidates.append((score, href))

    for _, candidate in sorted(candidates, key=lambda item: item[0], reverse=True):
        cleaned = _safe_http_url(candidate)
        if cleaned:
            return cleaned
    return ""


def _extract_forwarded_author(soup: BeautifulSoup) -> str:
    for node in soup.select(".gmail_attr"):
        text = _visible_text(node)
        match = re.search(r"\bFrom:\s*(.+?)(?=\s+(?:Date|Sent|Subject|To):)", text, re.IGNORECASE)
        if not match:
            continue
        author = re.sub(r"<[^>]*@[^>]*>", "", match.group(1))
        author = re.sub(r"\([^)]*@[^)]*\)", "", author)
        author = " ".join(author.strip(" \"'").split())
        if 1 <= len(author) <= 200 and "@" not in author:
            return author
    return ""


def _sender_display_name(sender: str) -> str:
    """The human part of a From header, or "" when there is only an address."""
    name, address = parseaddr(sender or "", strict=True)
    name = " ".join(name.strip(" \"'").split())
    if not name or "@" in name or len(name) > 200 or name.casefold() == address.casefold():
        return ""
    return name


def _article_author(soup: BeautifulSoup, email: NewsletterEmail) -> str:
    """Who the article is by.

    A forward is the hard case: the sender is the reader themselves, and the writer is
    only recoverable from the attribution block the forwarding client wrote. Gmail's is
    parsed; where no attribution is found and the subject carries a forward prefix, the
    byline is left empty rather than crediting the reader with their own newsletter. Mail
    that arrives directly -- a subscription pointed at the inbox address -- is by whoever
    sent it.
    """
    forwarded = _extract_forwarded_author(soup)
    if forwarded:
        return forwarded
    if _FORWARD_PREFIX.match(email.subject or "") or soup.select_one(".gmail_attr") is not None:
        return ""
    return _sender_display_name(email.sender)


def _forwarded_fragment(soup: BeautifulSoup) -> BeautifulSoup:
    candidates = list(soup.select(".gmail_quote")) + list(soup.select('blockquote[type="cite"]'))
    root: Tag | BeautifulSoup = (
        max(candidates, key=lambda node: len(_visible_text(node))) if candidates else soup.body or soup
    )
    fragment = BeautifulSoup(str(root), "html.parser")
    for node in fragment.select(".gmail_attr"):
        node.decompose()
    for node in list(fragment.find_all(["div", "p"])):
        text = _visible_text(node)
        has_body_children = node.find(
            ["article", "blockquote", "div", "h1", "h2", "h3", "ol", "p", "section", "table", "ul"],
            recursive=False,
        )
        if (
            len(text) <= 500
            and _FORWARDED_MARKER.search(text)
            and not node.find(["img", "table"])
            and not has_body_children
        ):
            node.decompose()
    return fragment


def _is_hidden(tag: Tag) -> bool:
    if tag.has_attr("hidden") or str(tag.get("aria-hidden", "")).casefold() == "true":
        return True
    classes = {str(item).casefold() for item in tag.get("class", [])}
    if classes & {"preheader", "preview-text"}:
        return True
    style = re.sub(r"\s+", "", str(tag.get("style", "")).casefold())
    return any(
        marker in style
        for marker in (
            "display:none",
            "visibility:hidden",
            "max-height:0",
            "opacity:0",
            "mso-hide:all",
        )
    )


def _dimension(value: object) -> int | None:
    match = re.search(r"\d+", str(value or ""))
    return int(match.group()) if match else None


def _is_tracking_image(tag: Tag) -> bool:
    width = _dimension(tag.get("width"))
    height = _dimension(tag.get("height"))
    style = re.sub(r"\s+", "", str(tag.get("style", "")).casefold())
    src = str(tag.get("src", "")).casefold()
    alt = str(tag.get("alt", "")).strip()
    explicit_small = (width is not None and width <= 2) or (height is not None and height <= 2)
    css_small = any(marker in style for marker in ("width:1px", "height:1px", "width:0", "height:0"))
    path_hint = any(marker in src for marker in ("/open.gif", "/pixel", "/track/open", "tracking_pixel"))
    return not alt and (explicit_small or css_small or path_hint)


def _replace_with_alt(tag: Tag) -> None:
    alt = " ".join(str(tag.get("alt", "")).split())
    if alt:
        tag.replace_with(NavigableString(f"[{alt}]"))
    else:
        tag.decompose()


def _direct_table_rows(table: Tag) -> list[Tag]:
    rows = list(table.find_all("tr", recursive=False))
    for section in table.find_all(["thead", "tbody", "tfoot"], recursive=False):
        rows.extend(section.find_all("tr", recursive=False))
    return rows


def _is_data_table(table: Tag) -> bool:
    if str(table.get("role", "")).casefold() == "presentation":
        return False
    if table.find("caption", recursive=False):
        return True

    rows = _direct_table_rows(table)
    if len(rows) < 2:
        return False
    cells = [row.find_all(["th", "td"], recursive=False) for row in rows]
    return max((len(row) for row in cells), default=0) >= 2 and any(cell.name == "th" for row in cells for cell in row)


def _flatten_layout_tables(root: Tag | BeautifulSoup) -> tuple[int, int]:
    flattened = 0
    preserved = 0
    for table in reversed(list(root.find_all("table"))):
        if _is_data_table(table):
            preserved += 1
            continue
        flattened += 1
        for descendant in table.find_all(["thead", "tbody", "tfoot", "tr", "td", "th"]):
            if descendant.find_parent("table") is not table:
                continue
            descendant.name = "div"
            descendant.attrs = {}
        table.name = "section"
        table.attrs = {}
    return flattened, preserved


def _plain_text_fragment(value: str) -> BeautifulSoup:
    soup = BeautifulSoup("<article></article>", "html.parser")
    article = soup.article
    assert article is not None
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    for block in re.split(r"\n{2,}", normalized):
        lines = [line.rstrip() for line in block.split("\n")]
        if not any(line.strip() for line in lines):
            continue
        paragraph = soup.new_tag("p")
        for index, line in enumerate(lines):
            if index:
                paragraph.append(soup.new_tag("br"))
            paragraph.append(NavigableString(line))
        article.append(paragraph)
    return soup


def _sanitize_attributes(root: Tag | BeautifulSoup) -> None:
    for tag in root.find_all(True):
        allowed = _GLOBAL_ATTRIBUTES | _TAG_ATTRIBUTES.get(tag.name or "", frozenset())
        tag.attrs = {key: value for key, value in tag.attrs.items() if key.casefold() in allowed}


def convert_newsletter(
    email: NewsletterEmail,
    *,
    public_base_url: str,
    inline_image_types: Mapping[str, str] | None = None,
    max_output_bytes: int = 5 * 1024 * 1024,
    fetch_remote_image: RemoteImageFetcher | None = None,
) -> NewsletterDocument:
    title = clean_newsletter_title(email.subject)
    raw_html = email.html.strip()
    if raw_html:
        original = BeautifulSoup(raw_html, "html.parser")
    elif email.text.strip():
        original = _plain_text_fragment(email.text)
    else:
        raise NewsletterConversionError("Inbound newsletter has no HTML or text body")

    source_url = _find_source_url(original, title)
    author = _article_author(original, email)
    fragment = _forwarded_fragment(original)
    body: Tag | BeautifulSoup = fragment.body or fragment

    for comment in list(body.find_all(string=lambda value: isinstance(value, Comment))):
        comment.extract()
    for tag in list(body.find_all(True)):
        if tag.name is None or tag.attrs is None:
            continue
        if tag.name in _DANGEROUS_TAGS or _is_hidden(tag):
            tag.decompose()
    # Measured here, after hidden and dangerous nodes are gone, and not before: the
    # retention check below exists to catch the converter losing text a reader would have
    # seen, and a preheader is text nobody was ever meant to see. Nearly every marketing
    # newsletter carries one, padded with hundreds of zero-width characters, and counting
    # that as input made short issues fail the check for having dropped it.
    input_text = _visible_text(body)

    flattened, preserved = _flatten_layout_tables(body)
    inline_types = {
        normalize_content_id(key): value.casefold().split(";", 1)[0].strip()
        for key, value in (inline_image_types or {}).items()
    }
    inline_images: list[InlineImageReference] = []
    inline_by_content_id: dict[str, InlineImageReference] = {}
    remote_resources: list[NewsletterResource] = []
    # Outcome cache keyed by cleaned src, holding successes and failures alike: one email may
    # repeat the same image, and the fetcher must see each distinct URL exactly once.
    remote_by_url: dict[str, NewsletterResource | None] = {}
    remote_failed = 0
    tracking_removed = 0
    images_kept = 0
    for image in list(body.find_all("img")):
        if _is_tracking_image(image):
            tracking_removed += 1
            image.decompose()
            continue
        src = str(image.get("src") or "").strip()
        if not src and image.get("srcset"):
            choices = [part.strip().split()[0] for part in str(image["srcset"]).split(",") if part.strip()]
            src = choices[-1] if choices else ""
        if src.casefold().startswith("cid:"):
            content_id = normalize_content_id(src[4:])
            content_type = inline_types.get(content_id, "")
            if not content_id or content_type not in SAFE_INLINE_IMAGE_TYPES:
                _replace_with_alt(image)
                continue
            reference = inline_by_content_id.get(content_id)
            if reference is None:
                location = f"{public_base_url}/newsletters/{quote(email.id, safe='')}/inline/{len(inline_images) + 1}"
                reference = InlineImageReference(content_id, location, content_type)
                inline_images.append(reference)
                inline_by_content_id[content_id] = reference
            image["src"] = reference.location
        else:
            if not urlsplit(src).scheme and source_url:
                src = urljoin(source_url, src)
            cleaned_src = _safe_http_url(src, remove_tracking=False)
            if not cleaned_src:
                _replace_with_alt(image)
                continue
            if fetch_remote_image is None:
                image["src"] = cleaned_src
            else:
                if cleaned_src not in remote_by_url:
                    fetched = fetch_remote_image(cleaned_src)
                    if fetched is None:
                        remote_by_url[cleaned_src] = None
                        remote_failed += 1
                    else:
                        content_type, content = fetched
                        # Same placeholder shape as the cid: branch above, and for the same
                        # reason: _package_resources rewrites these out of the HTML with a
                        # substitution anchored on the whole src attribute, because a location
                        # ending in /1 is a prefix of one ending in /10 (publisher.py).
                        location = (
                            f"{public_base_url}/newsletters/{quote(email.id, safe='')}"
                            f"/remote/{len(remote_resources) + 1}"
                        )
                        fetched_resource = NewsletterResource(location, content_type, content)
                        remote_by_url[cleaned_src] = fetched_resource
                        remote_resources.append(fetched_resource)
                resource = remote_by_url[cleaned_src]
                if resource is None:
                    # Fail closed on privacy: a fetch that did not succeed degrades to alt text
                    # and never leaves a live remote URL in the EPUB. Falling back to the original
                    # src would hand a malicious sender an easy win -- fail the fetch on purpose
                    # (refuse our user agent, time out) and the beacon survives into the reader.
                    _replace_with_alt(image)
                    continue
                image["src"] = resource.location
        images_kept += 1

    links_kept = 0
    for anchor in list(body.find_all("a")):
        href = _safe_href(str(anchor.get("href") or ""), base_url=source_url)
        if not href:
            anchor.unwrap()
            continue
        anchor["href"] = href
        links_kept += 1

    for tag in list(body.find_all(True)):
        if tag.name not in _ALLOWED_TAGS:
            tag.unwrap()
    _sanitize_attributes(body)

    output = BeautifulSoup("<!doctype html><html><head></head><body><article></article></body></html>", "html.parser")
    head = output.head
    article = output.article
    assert head is not None and article is not None
    charset = output.new_tag("meta")
    charset["charset"] = "utf-8"
    head.append(charset)
    title_tag = output.new_tag("title")
    title_tag.string = title
    head.append(title_tag)
    if author:
        author_tag = output.new_tag("meta")
        author_tag["name"] = "author"
        author_tag["content"] = author
        head.append(author_tag)
    for child in list(body.contents):
        article.append(child.extract())

    output_text = _visible_text(article)
    if len(output_text) < 80 and images_kept == 0:
        raise NewsletterConversionError("Inbound newsletter does not contain enough readable content")
    retained_ratio = min(1.0, len(output_text) / len(input_text)) if input_text else 1.0
    if len(input_text) >= 500 and retained_ratio < 0.85:
        raise NewsletterConversionError("Newsletter conversion failed the text-retention quality check")

    output_html = str(output)
    output_bytes = output_html.encode("utf-8")
    if len(output_bytes) > max_output_bytes:
        raise NewsletterConversionError("Converted newsletter exceeds the configured body-size limit")

    # Both placeholder families collapse to one token so the hash does not depend on how the
    # images happened to be numbered. Remote images make this dedupe looser than it looks: two
    # deliveries of the same newsletter can disagree on whether a fetch succeeded, so one stores
    # a placeholder where the other stores alt text and the hashes differ. content_sha256 is
    # therefore best-effort; email_id and message_id remain the exact dedupe keys.
    canonical_for_hash = re.sub(
        rf"{re.escape(public_base_url)}/newsletters/{re.escape(quote(email.id, safe=''))}/(?:inline|remote)/\d+",
        "cid:inline-image",
        output_html,
    )
    content_sha256 = hashlib.sha256(f"{title}\0{canonical_for_hash}".encode()).hexdigest()

    return NewsletterDocument(
        title=title,
        html=output_html,
        source_url=source_url,
        author=author,
        created_at=email.created_at[:64],
        content_sha256=content_sha256,
        inline_images=tuple(inline_images),
        stats=NewsletterConversionStats(
            input_text_chars=len(input_text),
            output_text_chars=len(output_text),
            retained_text_ratio=retained_ratio,
            links_kept=links_kept,
            images_kept=images_kept,
            tracking_images_removed=tracking_removed,
            layout_tables_flattened=flattened,
            data_tables_preserved=preserved,
            remote_images_inlined=len(remote_resources),
            remote_images_failed=remote_failed,
        ),
        remote_resources=tuple(remote_resources),
    )
