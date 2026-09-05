"""The shared remote fetch boundary is a read-oracle boundary, not an HTTP helper.

These tests exercise the generic result URL and media type needed by webpage imports while
the exhaustive address, redirect, and pinning matrix remains covered through imagefetch.
"""

from __future__ import annotations

from collections.abc import Sequence

import httpx
import pytest

from steepd.remotefetch import RemoteAccessDenied, RemoteBodyTooLarge, RemoteFetchError, fetch_remote

GLOBAL_V4 = "93.184.216.34"


def resolver(host: str) -> Sequence[str]:
    return [GLOBAL_V4]


def test_remote_fetch_returns_normalized_type_bytes_and_fragment_free_final_url():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            headers={"content-type": "Text/HTML; charset=utf-8"},
            content=b"<html>article</html>",
        )

    fetched = fetch_remote(
        "https://publisher.example/story#section",
        max_bytes=1024,
        transport=httpx.MockTransport(handler),
        resolve_host=resolver,
    )

    assert fetched.content_type == "text/html"
    assert fetched.content == b"<html>article</html>"
    assert fetched.final_url == "https://publisher.example/story"
    assert requests[0].url.host == GLOBAL_V4
    assert requests[0].headers["host"] == "publisher.example"


def test_remote_fetch_returns_the_public_final_url_after_a_relative_redirect():
    queue = [
        httpx.Response(302, headers={"location": "/final/story?edition=1#reading"}),
        httpx.Response(200, headers={"content-type": "application/xhtml+xml"}, content=b"<html/>")
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return queue.pop(0)

    fetched = fetch_remote(
        "https://publisher.example/start",
        max_bytes=1024,
        transport=httpx.MockTransport(handler),
        resolve_host=resolver,
    )

    assert fetched.final_url == "https://publisher.example/final/story?edition=1"
    assert fetched.content_type == "application/xhtml+xml"


def test_remote_fetch_revalidates_a_redirect_before_contacting_it():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(302, headers={"location": "http://127.0.0.1/private"})

    with pytest.raises(RemoteFetchError, match="non-routable"):
        fetch_remote(
            "https://publisher.example/story",
            max_bytes=1024,
            transport=httpx.MockTransport(handler),
            resolve_host=resolver,
        )

    assert len(requests) == 1


def test_remote_fetch_preserves_the_hostname_when_a_site_denies_access():
    transport = httpx.MockTransport(lambda request: httpx.Response(403, content=b"Forbidden"))

    with pytest.raises(RemoteAccessDenied) as captured:
        fetch_remote(
            "https://www.publisher.example/story",
            max_bytes=1024,
            transport=transport,
            resolve_host=resolver,
        )

    assert captured.value.hostname == "www.publisher.example"
    assert captured.value.status_code == 403


def test_remote_fetch_raises_a_typed_size_error_for_declared_overflow():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, headers={"content-length": "5"}, content=b"12345")
    )

    with pytest.raises(RemoteBodyTooLarge, match="size limit"):
        fetch_remote(
            "https://publisher.example/story",
            max_bytes=4,
            transport=transport,
            resolve_host=resolver,
        )


def test_remote_fetch_raises_a_typed_size_error_for_streamed_overflow():
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b"12345"))

    with pytest.raises(RemoteBodyTooLarge, match="size limit"):
        fetch_remote(
            "https://publisher.example/story",
            max_bytes=4,
            transport=transport,
            resolve_host=resolver,
        )


def test_remote_fetch_sends_an_internationalized_hostname_in_idna_form():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, headers={"content-type": "text/html"}, content=b"<html/>")

    fetched = fetch_remote(
        "https://bücher.example/story",
        max_bytes=1024,
        transport=httpx.MockTransport(handler),
        resolve_host=resolver,
    )

    assert requests[0].headers["host"] == "xn--bcher-kva.example"
    assert requests[0].extensions["sni_hostname"] == "xn--bcher-kva.example"
    assert fetched.final_url == "https://xn--bcher-kva.example/story"


def test_remote_fetch_rejects_a_hostname_that_cannot_be_idna_encoded():
    with pytest.raises(RemoteFetchError, match="hostname"):
        fetch_remote(
            "https://a..example/story",
            max_bytes=1024,
            transport=httpx.MockTransport(lambda request: httpx.Response(200)),
            resolve_host=resolver,
        )
