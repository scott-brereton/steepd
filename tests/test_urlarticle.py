from __future__ import annotations

from collections.abc import Callable

import pytest

from steepd.remotefetch import FetchedRemote, RemoteAccessDenied, RemoteBodyTooLarge
from steepd.urlarticle import (
    UrlArticleError,
    UrlArticleTooLarge,
    convert_url_article,
    exact_subject_url,
)

FIXTURE_HTML = b"""<!doctype html>
<html>
  <head>
    <title>A useful story</title>
    <meta name="author" content="Ada Writer">
    <meta property="article:tag" content="Policy">
  </head>
  <body>
    <nav>Site navigation and account links that are not part of the article.</nav>
    <main>
      <h1>A useful story</h1>
      <p>This article paragraph explains the central idea in enough detail for the extractor
      to distinguish it from navigation, advertising, and other surrounding page furniture.
      It is written as ordinary prose that a person would reasonably want to read offline.</p>
      <h2>The practical detail</h2>
      <p>A second substantial paragraph develops the point with concrete context, useful
      examples, and a clear conclusion. It provides enough meaningful text for extraction
      and for Steepd's existing quality gate without relying on hidden or repeated content.</p>
      <img src="/images/chart.png" alt="A useful chart">
      <p>Continue with <a href="/related?utm_source=email&amp;edition=1">the related analysis</a>
      when more background is useful.</p>
    </main>
    <aside>Advertisement and unrelated promotion.</aside>
  </body>
</html>"""


@pytest.mark.parametrize(
    "subject, expected",
    [
        ("https://example.com/story", "https://example.com/story"),
        ("  http://example.com/story?x=1#part  ", "http://example.com/story?x=1#part"),
        ("HTTPS://Example.com/Story", "HTTPS://Example.com/Story"),
    ],
)
def test_exact_subject_url_is_recognized(subject: object, expected: str):
    assert exact_subject_url(subject) == expected


@pytest.mark.parametrize(
    "subject",
    [
        "Read: https://example.com/story",
        "https://example.com/story notes",
        "https://one.example https://two.example",
        "https://example.com/story\nplease save",
        "mailto:reader@example.com",
        "example.com/story",
        "",
        None,
        42,
    ],
)
def test_non_exact_subject_stays_out_of_url_mode(subject: object):
    assert exact_subject_url(subject) is None


def _page_fetch(
    content: bytes = FIXTURE_HTML,
    *,
    content_type: str = "text/html",
    final_url: str = "https://publisher.example/final/story",
) -> Callable[..., FetchedRemote]:
    def fetch(url: str, *, max_bytes: int) -> FetchedRemote:
        assert url == "https://short.example/story"
        assert max_bytes == 5 * 1024 * 1024
        return FetchedRemote(content_type=content_type, content=content, final_url=final_url)

    return fetch


def test_url_article_extracts_main_content_metadata_and_uses_final_url():
    image_urls: list[str] = []

    def refuse_image(url: str) -> None:
        image_urls.append(url)
        return None

    document = convert_url_article(
        "https://short.example/story",
        public_base_url="https://steepd.app",
        max_body_bytes=5 * 1024 * 1024,
        created_at="2026-09-04T12:00:00Z",
        fetch_page=_page_fetch(),
        fetch_remote_image=refuse_image,
    )

    assert document.title == "A useful story"
    assert document.author == "Ada Writer"
    assert document.source_url == "https://publisher.example/final/story"
    assert document.created_at == "2026-09-04T12:00:00Z"
    assert "Site navigation" not in document.html
    assert "Advertisement" not in document.html
    assert "central idea" in document.html
    assert 'href="https://publisher.example/related?edition=1"' in document.html
    assert "publisher.example/images/chart.png" not in document.html
    assert image_urls == ["https://publisher.example/images/chart.png"]


def test_url_article_uses_the_final_hostname_when_extraction_has_no_title():
    untitled = b"""<html><body><main><p>This is a long untitled article with enough readable
    prose to be extracted successfully. It explains one idea carefully and continues with
    enough supporting detail to be useful to a reader who saved it for later.</p><p>The second
    paragraph supplies more context, examples, and a conclusion without introducing a heading
    that Trafilatura could use as an inferred title for the page.</p></main></body></html>"""

    document = convert_url_article(
        "https://short.example/story",
        public_base_url="https://steepd.app",
        max_body_bytes=5 * 1024 * 1024,
        created_at="2026-09-04T12:00:00Z",
        fetch_page=_page_fetch(content=untitled, final_url="https://www.publisher.example/final"),
        fetch_remote_image=lambda url: None,
    )

    assert document.title == "www.publisher.example"


def test_url_article_rejects_a_non_html_response_before_extraction():
    with pytest.raises(UrlArticleError, match="did not return an HTML webpage"):
        convert_url_article(
            "https://short.example/story",
            public_base_url="https://steepd.app",
            max_body_bytes=5 * 1024 * 1024,
            created_at="2026-09-04T12:00:00Z",
            fetch_page=_page_fetch(content_type="application/pdf"),
            fetch_remote_image=lambda url: None,
        )


def test_url_article_names_a_site_that_denies_capture():
    def denied(url: str, *, max_bytes: int) -> FetchedRemote:
        raise RemoteAccessDenied("www.publisher.example", 403)

    with pytest.raises(UrlArticleError, match=r"^publisher\.example does not allow article capture\.$"):
        convert_url_article(
            "https://short.example/story",
            public_base_url="https://steepd.app",
            max_body_bytes=5 * 1024 * 1024,
            created_at="2026-09-04T12:00:00Z",
            fetch_page=denied,
            fetch_remote_image=lambda url: None,
        )


def test_url_article_rejects_a_page_without_extractable_content():
    with pytest.raises(UrlArticleError, match="readable article"):
        convert_url_article(
            "https://short.example/story",
            public_base_url="https://steepd.app",
            max_body_bytes=5 * 1024 * 1024,
            created_at="2026-09-04T12:00:00Z",
            fetch_page=_page_fetch(content=b"<html><body><nav>Home</nav></body></html>"),
            fetch_remote_image=lambda url: None,
        )


def test_url_article_preserves_a_typed_page_size_rejection():
    def too_large(url: str, *, max_bytes: int) -> FetchedRemote:
        raise RemoteBodyTooLarge("remote detail that must not become user-facing copy")

    with pytest.raises(UrlArticleTooLarge, match="exceeds the configured size limit"):
        convert_url_article(
            "https://short.example/story",
            public_base_url="https://steepd.app",
            max_body_bytes=5 * 1024 * 1024,
            created_at="2026-09-04T12:00:00Z",
            fetch_page=too_large,
            fetch_remote_image=lambda url: None,
        )
