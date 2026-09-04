from __future__ import annotations

from email import policy
from email.parser import BytesParser

import httpx
import pytest
from bs4 import BeautifulSoup

from steepd.newsletter import (
    NewsletterConversionError,
    NewsletterEmail,
    clean_article_html,
    convert_newsletter,
)


def email_with(
    *,
    html: str = "",
    text: str = "",
    subject: str = "Fwd: A useful newsletter",
    email_id: str = "email-newsletter-1",
) -> NewsletterEmail:
    return NewsletterEmail(
        id=email_id,
        sender="reader@example.com",
        recipients=("read@example.com",),
        subject=subject,
        html=html,
        text=text,
        created_at="2026-08-25T20:00:00Z",
        message_id="<newsletter-1@example.com>",
    )


def test_direct_article_cleaning_applies_the_newsletter_safety_and_link_rules() -> None:
    """A URL extractor returns untrusted HTML. Skipping the shared cleaner would leave
    executable markup or publisher tracking in the EPUB."""
    document = clean_article_html(
        '<article><script>bad()</script><p>This useful article paragraph contains enough '
        'readable prose to pass the existing quality gate and remain in the saved file.</p>'
        '<a href="/read?utm_source=mail&amp;keep=yes">Read</a></article>',
        title="A story",
        author="Ada Writer",
        source_url="https://publisher.example/story",
        created_at="2026-09-04T12:00:00Z",
        document_key="url-fixture",
        public_base_url="https://steepd.app",
    )

    assert "<script" not in document.html
    assert "bad()" not in document.html
    assert 'href="https://publisher.example/read?keep=yes"' in document.html
    assert document.title == "A story"
    assert document.author == "Ada Writer"
    assert document.source_url == "https://publisher.example/story"


def test_html_conversion_removes_forwarding_chrome_and_normalizes_email_layout() -> None:
    source = """
    <html><body><p>Forwarding note outside the original message.</p>
      <div class="gmail_quote">
        <div class="gmail_attr">---------- Forwarded message ---------<br>
          From: Useful Writer &lt;writer@example.com&gt; Date: Monday Subject: A useful newsletter
        </div>
        <table role="presentation" width="600"><tr><td style="font-size: 18px">
          <h1>A useful newsletter</h1>
          <p>The meaningful article text remains readable.</p>
          <a href="https://publication.example/post?utm_source=email&amp;access_token=private">View in browser</a>
          <img src="https://images.example/hero.jpg?signature=content" width="600" alt="A useful chart">
          <img src="https://track.example/open.gif" width="1" height="1">
          <script>alert('no')</script><a href="javascript:alert(1)">unsafe</a>
        </td></tr></table>
        <table><caption>Actual data</caption><tr><th>Year</th><th>Total</th></tr>
          <tr><td>2025</td><td>42</td></tr></table>
      </div>
    </body></html>
    """
    document = convert_newsletter(
        email_with(html=source),
        public_base_url="https://books.example.test",
    )
    parsed = BeautifulSoup(document.html, "html.parser")

    assert document.title == "A useful newsletter"
    assert document.source_url == "https://publication.example/post"
    assert "Forwarding note outside" not in document.html
    assert "Forwarded message" not in document.html
    assert "Useful Writer" in str(parsed.find("meta", attrs={"name": "author"}))
    assert "The meaningful article text remains readable." in document.html
    assert "alert('no')" not in document.html
    assert "javascript:" not in document.html
    assert "style=" not in document.html
    assert len(parsed.find_all("table")) == 1
    assert parsed.find("caption").get_text(strip=True) == "Actual data"
    assert document.stats.layout_tables_flattened == 1
    assert document.stats.data_tables_preserved == 1
    assert document.stats.tracking_images_removed == 1
    assert document.stats.images_kept == 1
    assert document.stats.retained_text_ratio > 0.9


def test_inline_cid_images_are_bounded_resources_and_missing_cids_become_alt_text() -> None:
    source = """
    <div class="gmail_quote"><div class="gmail_attr">Forwarded message From: Writer Date: now</div>
      <p>Article text long enough to be accepted and remain useful on the reader.</p>
      <img src="cid:hero-image" alt="Hero">
      <img src="cid:hero-image" alt="Hero repeated">
      <img src="cid:missing-image" alt="Missing illustration">
    </div>
    """
    document = convert_newsletter(
        email_with(html=source),
        public_base_url="https://books.example.test",
        inline_image_types={"hero-image": "image/png", "missing-image": "image/svg+xml"},
    )

    assert len(document.inline_images) == 1
    assert document.inline_images[0].content_id == "hero-image"
    assert document.inline_images[0].content_type == "image/png"
    assert document.inline_images[0].location in document.html
    assert document.html.count(document.inline_images[0].location) == 2
    assert "cid:" not in document.html
    assert "[Missing illustration]" in document.html


def test_forwarded_marker_wrapper_does_not_remove_nested_article_body() -> None:
    source = """
    <div class="gmail_quote">
      <div><span>Begin forwarded message:</span>
        <p>This nested article body is long enough to remain readable and must never be removed with its header.</p>
      </div>
    </div>
    """

    document = convert_newsletter(email_with(html=source), public_base_url="https://books.example.test")

    assert "This nested article body" in document.html


def test_layout_table_around_a_real_data_table_is_flattened_without_flattening_the_data() -> None:
    source = """
    <div class="gmail_quote"><div class="gmail_attr">Forwarded message</div>
      <table><tr><td>
        <p>Readable newsletter introduction with enough text to pass the content-quality threshold.</p>
        <table><tr><th>Year</th><th>Total</th></tr><tr><td>2025</td><td>42</td></tr></table>
      </td></tr></table>
    </div>
    """

    document = convert_newsletter(email_with(html=source), public_base_url="https://books.example.test")
    parsed = BeautifulSoup(document.html, "html.parser")

    assert len(parsed.find_all("table")) == 1
    assert parsed.find("th").get_text(strip=True) == "Year"
    assert document.stats.layout_tables_flattened == 1
    assert document.stats.data_tables_preserved == 1


def test_plain_text_newsletter_has_reflowable_paragraphs() -> None:
    document = convert_newsletter(
        email_with(
            html="",
            text="First paragraph with enough readable newsletter content.\n\nSecond paragraph.\nWith another line.",
            subject="FW: Plain edition",
        ),
        public_base_url="https://books.example.test",
    )
    parsed = BeautifulSoup(document.html, "html.parser")

    assert document.title == "Plain edition"
    assert len(parsed.find_all("p")) == 2
    assert parsed.find("br") is not None
    # No external canonical URL was found in this plain-text email, so source_url must
    # stay empty rather than synthesizing a same-origin URL that no route serves - the
    # OPDS builder only emits an alternate link when source_url is truthy (opds.py).
    assert document.source_url == ""


def test_hostile_attributes_are_stripped_from_tags_that_are_otherwise_kept() -> None:
    """Surviving a tag allow-list is not enough; each tag keeps only its allow-listed attributes.

    Event handlers ride in on ordinary content tags, and an inline style can hide or reposition
    content in any reading system that honours CSS. Both must be gone while the attributes the
    article actually needs -- href, src, alt -- are left intact.
    """
    source = """
    <div class="gmail_quote">
      <p onclick="alert(1)" style="color:red" data-x="y">Readable newsletter body with enough
      characters to clear the conversion's content-quality floor.</p>
      <a href="https://example.com/x" onmouseover="alert(1)" target="_blank">a link</a>
      <img src="https://example.com/a.png" alt="ok" onerror="alert(1)">
    </div>
    """

    document = convert_newsletter(email_with(html=source), public_base_url="https://books.example.test")
    parsed = BeautifulSoup(document.html, "html.parser")

    for attribute in ("onclick", "onmouseover", "onerror", "style=", "target=", "data-x"):
        assert attribute not in document.html
    assert parsed.find("a")["href"] == "https://example.com/x"
    assert parsed.find("img")["src"] == "https://example.com/a.png"
    assert parsed.find("img")["alt"] == "ok"


def test_links_using_a_non_http_scheme_are_unwrapped_even_when_they_have_a_hostname() -> None:
    """The href allow-list is on the scheme, not just on whether a hostname parses.

    javascript: and data: URLs happen to be caught by the empty-hostname rule, so they do not
    exercise the scheme check at all. file:// and ftp:// do have a hostname, and would reach
    the e-reader as a live link to the reader's own filesystem or to the sender's server.
    """
    source = """
    <div class="gmail_quote">
      <p>Readable newsletter body with plenty of characters so the conversion clears the
      content-quality floor before the links are examined.</p>
      <a href="file://attacker.example/etc/passwd">local file</a>
      <a href="ftp://attacker.example/secret.txt">remote fetch</a>
    </div>
    """

    document = convert_newsletter(email_with(html=source), public_base_url="https://books.example.test")
    parsed = BeautifulSoup(document.html, "html.parser")

    assert "file:" not in document.html
    assert "ftp:" not in document.html
    assert parsed.find("a") is None
    assert document.stats.links_kept == 0
    # Unwrapping keeps the label, so the reader still sees the text the sender wrote.
    assert "local file" in document.html


def test_a_padded_hidden_preheader_does_not_fail_the_retention_check() -> None:
    """Marketing newsletters open with a hidden preview line padded out with hundreds of
    zero-width characters. That text is removed on purpose, so it must not count as input
    the converter then "lost": a short issue with a long preheader used to be rejected."""
    body = "<p>" + "A real sentence a reader would actually see on the page. " * 25 + "</p>"
    preheader = '<div class="preheader" style="display:none;max-height:0">' + "Preview \u200c" * 120 + "</div>"
    document = convert_newsletter(
        email_with(html=f"<html><body>{preheader}{body}</body></html>"),
        public_base_url="https://books.example.test",
    )
    assert "Preview" not in document.html
    assert document.stats.retained_text_ratio == 1.0


def test_author_is_the_forwarded_writer_or_the_direct_sender_never_the_forwarder() -> None:
    """Three shapes of arrival, three bylines. A Gmail forward names the original writer in
    its attribution block. A newsletter delivered straight to the inbox address is by its
    sender. A forward whose client left no attribution is by nobody, because the only name
    available is the reader's own."""
    body = "<p>" + "Enough readable prose to clear the content floor comfortably. " * 5 + "</p>"
    gmail = (
        '<div class="gmail_attr">---------- Forwarded message ---------<br>'
        "From: Useful Writer &lt;writer@example.com&gt; Date: Monday Subject: Issue 4</div>" + body
    )
    forwarded = convert_newsletter(email_with(html=gmail), public_base_url="https://books.example.test")
    assert forwarded.author == "Useful Writer"

    direct = NewsletterEmail(
        id="email-direct",
        sender="The Weekly Dispatch <hello@dispatch.example>",
        recipients=("read@example.com",),
        subject="Issue 42",
        html=body,
        text="",
        created_at="2026-08-25T20:00:00Z",
        message_id="<direct-1@dispatch.example>",
    )
    assert convert_newsletter(direct, public_base_url="https://books.example.test").author == "The Weekly Dispatch"

    bare_forward = NewsletterEmail(
        id="email-fwd",
        sender="Reader Person <reader@example.com>",
        recipients=("read@example.com",),
        subject="Fwd: Issue 42",
        html=body,
        text="",
        created_at="2026-08-25T20:00:00Z",
        message_id="<fwd-1@example.com>",
    )
    assert convert_newsletter(bare_forward, public_base_url="https://books.example.test").author == ""


def test_empty_or_tiny_newsletter_is_rejected() -> None:
    with pytest.raises(NewsletterConversionError):
        convert_newsletter(email_with(html="<p>Hi</p>"), public_base_url="https://books.example.test")


_BODY_TEXT = "The meaningful article text remains readable and is long enough to clear the content-quality floor."


class _StubFetcher:
    """A RemoteImageFetcher answering from a fixed table while recording what it was asked for.

    A URL missing from the table answers None, which is the fetcher contract's signal for any
    failure at all -- blocked host, timeout, oversized body, disallowed content type.
    """

    def __init__(self, responses: dict[str, tuple[str, bytes]] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[str] = []

    def __call__(self, url: str) -> tuple[str, bytes] | None:
        self.calls.append(url)
        return self.responses.get(url)


def test_remote_image_keeps_its_absolute_url_when_no_fetcher_is_supplied() -> None:
    """With no fetcher injected the conversion must behave exactly as it did before inlining existed.

    The wiring layer decides whether fetching is available, and every other newsletter test runs
    through this branch. If the hook changed the default it would point src attributes at
    placeholder URLs that no resource backs, and the reader would render nothing at all.
    """
    source = f"""
    <div class="gmail_quote"><p>{_BODY_TEXT}</p>
      <img src="https://cdn.example/hero.png?sig=abc" alt="Hero chart"></div>
    """

    document = convert_newsletter(email_with(html=source), public_base_url="https://books.example.test")
    parsed = BeautifulSoup(document.html, "html.parser")

    assert parsed.find("img")["src"] == "https://cdn.example/hero.png?sig=abc"
    assert document.remote_resources == ()
    assert document.stats.images_kept == 1
    assert document.stats.remote_images_inlined == 0
    assert document.stats.remote_images_failed == 0


def test_fetched_remote_image_is_carried_as_a_resource_and_its_cdn_url_leaves_the_document() -> None:
    """A successful fetch must remove the CDN URL, not merely add a resource beside it.

    The whole point of inlining is that the stored EPUB stops phoning home. A document that
    kept the original src would still beacon the reader's IP and read time on open, and the
    extra resource would just be dead weight in the archive.
    """
    source = f"""
    <div class="gmail_quote"><p>{_BODY_TEXT}</p>
      <img src="https://cdn.example/hero.png" alt="Hero chart"></div>
    """
    fetcher = _StubFetcher({"https://cdn.example/hero.png": ("image/png", b"PNG-BYTES")})

    document = convert_newsletter(
        email_with(html=source),
        public_base_url="https://books.example.test",
        fetch_remote_image=fetcher,
    )
    parsed = BeautifulSoup(document.html, "html.parser")
    placeholder = "https://books.example.test/newsletters/email-newsletter-1/remote/1"

    assert parsed.find("img")["src"] == placeholder
    assert "cdn.example" not in document.html
    assert len(document.remote_resources) == 1
    resource = document.remote_resources[0]
    assert resource.location == placeholder
    assert resource.content_type == "image/png"
    assert resource.content == b"PNG-BYTES"
    assert document.stats.remote_images_inlined == 1
    assert document.stats.images_kept == 1


def test_failed_remote_fetch_degrades_to_alt_text_rather_than_leaving_a_live_url() -> None:
    """Fetch failure must fail closed on privacy, because the sender controls whether it fails.

    Falling back to the original src would make the beacon trivially recoverable: refuse our
    user agent or stall the connection and the untouched tracking URL ships inside the EPUB.
    Degrading to alt text is the same treatment an unresolvable cid: reference already gets.
    """
    source = f"""
    <div class="gmail_quote"><p>{_BODY_TEXT}</p>
      <img src="https://cdn.example/beacon.png" alt="Chart of adoption"></div>
    """
    fetcher = _StubFetcher()

    document = convert_newsletter(
        email_with(html=source),
        public_base_url="https://books.example.test",
        fetch_remote_image=fetcher,
    )

    assert fetcher.calls == ["https://cdn.example/beacon.png"]
    assert "[Chart of adoption]" in document.html
    assert "cdn.example" not in document.html
    assert BeautifulSoup(document.html, "html.parser").find("img") is None
    assert document.remote_resources == ()
    assert document.stats.remote_images_failed == 1
    assert document.stats.remote_images_inlined == 0


def test_repeated_remote_url_is_fetched_once_and_shares_one_resource() -> None:
    """Newsletters reuse a logo or divider on every row; each distinct URL is fetched only once.

    Without the per-URL cache a masthead repeated ten times would mean ten HTTP requests to the
    sender's CDN -- ten confirmations that the message was processed -- and ten copies of the
    same bytes packaged into the archive.
    """
    source = f"""
    <div class="gmail_quote"><p>{_BODY_TEXT}</p>
      <img src="https://cdn.example/logo.png" alt="Masthead">
      <p>A second section of the newsletter follows the masthead.</p>
      <img src="https://cdn.example/logo.png" alt="Masthead again"></div>
    """
    fetcher = _StubFetcher({"https://cdn.example/logo.png": ("image/gif", b"GIF-BYTES")})

    document = convert_newsletter(
        email_with(html=source),
        public_base_url="https://books.example.test",
        fetch_remote_image=fetcher,
    )
    parsed = BeautifulSoup(document.html, "html.parser")
    placeholder = "https://books.example.test/newsletters/email-newsletter-1/remote/1"

    assert fetcher.calls == ["https://cdn.example/logo.png"]
    assert [image["src"] for image in parsed.find_all("img")] == [placeholder, placeholder]
    assert len(document.remote_resources) == 1
    assert document.stats.remote_images_inlined == 1
    assert document.stats.images_kept == 2


def test_attached_fetched_and_unreachable_images_coexist_in_one_newsletter() -> None:
    """The three image outcomes are independent, and a real newsletter mixes all of them.

    Each family keeps its own counter and its own resource list, so a failure in one must not
    renumber or drop the others; the wiring layer concatenates both lists for the publisher.
    """
    source = f"""
    <div class="gmail_quote"><p>{_BODY_TEXT}</p>
      <img src="cid:hero-image" alt="Attached hero">
      <img src="https://cdn.example/chart.png" alt="Fetched chart">
      <img src="https://cdn.example/missing.png" alt="Unreachable chart"></div>
    """
    fetcher = _StubFetcher({"https://cdn.example/chart.png": ("image/jpeg", b"JPEG-BYTES")})

    document = convert_newsletter(
        email_with(html=source),
        public_base_url="https://books.example.test",
        inline_image_types={"hero-image": "image/png"},
        fetch_remote_image=fetcher,
    )
    parsed = BeautifulSoup(document.html, "html.parser")

    assert fetcher.calls == ["https://cdn.example/chart.png", "https://cdn.example/missing.png"]
    assert [image.content_id for image in document.inline_images] == ["hero-image"]
    assert document.inline_images[0].location.endswith("/inline/1")
    assert [resource.content for resource in document.remote_resources] == [b"JPEG-BYTES"]
    assert document.remote_resources[0].location.endswith("/remote/1")
    assert [image["src"] for image in parsed.find_all("img")] == [
        document.inline_images[0].location,
        document.remote_resources[0].location,
    ]
    assert "[Unreachable chart]" in document.html
    assert "cdn.example" not in document.html
    assert document.stats.images_kept == 2
    assert document.stats.remote_images_inlined == 1
    assert document.stats.remote_images_failed == 1


def test_image_placeholders_are_canonicalized_out_of_the_content_hash() -> None:
    """content_sha256 must describe the article, not the placeholder URLs standing in for images.

    Placeholders embed the email id and a per-conversion counter, so hashing them raw would make
    every delivery of the same newsletter unique and defeat the hash. The same article delivered
    once as a cid: attachment and once as a fetched remote image differs only in placeholder
    family and email id, so the two must hash identically.

    A pure /remote/1-versus-/remote/2 pair is not constructible here: the counter only advances
    on a successful fetch, and every success leaves an <img> behind, so two such documents would
    differ by more than the number. The cross-family pair exercises the same substitution.
    """
    template = f'<div class="gmail_quote"><p>{_BODY_TEXT}</p><img src="{{src}}" alt="Hero chart"></div>'
    responses = {"https://cdn.example/hero.png": ("image/png", b"PNG-BYTES")}

    attached = convert_newsletter(
        email_with(html=template.format(src="cid:hero-image"), email_id="delivery-a"),
        public_base_url="https://books.example.test",
        inline_image_types={"hero-image": "image/png"},
    )
    fetched = convert_newsletter(
        email_with(html=template.format(src="https://cdn.example/hero.png"), email_id="delivery-b"),
        public_base_url="https://books.example.test",
        fetch_remote_image=_StubFetcher(responses),
    )
    refetched = convert_newsletter(
        email_with(html=template.format(src="https://cdn.example/hero.png"), email_id="delivery-b"),
        public_base_url="https://books.example.test",
        fetch_remote_image=_StubFetcher(responses),
    )

    assert attached.content_sha256 == fetched.content_sha256
    assert fetched.content_sha256 == refetched.content_sha256


def test_realistic_newsletter_with_a_fetched_image_still_clears_the_quality_gates() -> None:
    """The length and retention gates run after image processing, on the rewritten document.

    Both gates are measured on visible text, so replacing a src must not move them -- but they
    are the failure mode that would take the whole feature down silently, converting a perfectly
    good newsletter into a rejected one purely because its images were inlined.
    """
    source = f"""
    <div class="gmail_quote">
      <table role="presentation" width="600"><tr><td>
        <h1>Weekly roundup</h1>
        <p>{_BODY_TEXT}</p>
        <img src="https://cdn.example/hero.png" alt="Adoption over time">
        <p>The second section discusses the same material at greater length, because a realistic
        newsletter carries well over five hundred characters of prose and therefore trips the
        retention check that shorter fixtures never reach.</p>
        <p>{_BODY_TEXT}</p>
        <p>A closing note repeats the publication details and the unsubscribe language that every
        newsletter carries at the foot of the message.</p>
        <img src="https://track.example/open.gif" width="1" height="1">
      </td></tr></table>
    </div>
    """
    fetcher = _StubFetcher({"https://cdn.example/hero.png": ("image/webp", b"WEBP-BYTES")})

    document = convert_newsletter(
        email_with(html=source),
        public_base_url="https://books.example.test",
        fetch_remote_image=fetcher,
    )

    assert document.stats.input_text_chars >= 500
    assert document.stats.retained_text_ratio >= 0.85
    assert document.stats.tracking_images_removed == 1
    assert document.stats.remote_images_inlined == 1
    assert "cdn.example" not in document.html
    assert BeautifulSoup(document.html, "html.parser").find("img")["src"].endswith("/remote/1")


def _multipart_parts(request: httpx.Request):
    content_type = request.headers["content-type"]
    message = BytesParser(policy=policy.default).parsebytes(
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + request.content
    )
    return list(message.iter_parts())
