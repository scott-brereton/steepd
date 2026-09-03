"""Remote images come from URLs an attacker put in an email, and the bytes we fetch are
handed back to that same attacker inside their own EPUB. Every test here names the read
an unguarded fetcher would have granted."""

from __future__ import annotations

from collections.abc import Sequence

import httpx
import pytest

from steepd.imagefetch import ImageFetchError, fetch_remote_image

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 28
GIF = b"GIF89a" + b"\x00" * 26
WEBP = b"RIFF\x20\x00\x00\x00WEBP" + b"\x00" * 20
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>fetch("/steal")</script></svg>'

GLOBAL_V4 = "93.184.216.34"
GLOBAL_V6 = "2606:2800:220:1:248:1893:25c8:1946"


def transport_for(*responses: httpx.Response) -> tuple[httpx.MockTransport, list[httpx.Request]]:
    """MockTransport that records every request and replays the responses in order,
    repeating the last one once the queue runs down."""
    requests: list[httpx.Request] = []
    queue = list(responses) or [httpx.Response(200, content=PNG)]

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return queue.pop(0) if len(queue) > 1 else queue[0]

    return httpx.MockTransport(handler), requests


def resolver_for(
    mapping: dict[str, Sequence[str]] | None = None,
    *,
    default: Sequence[str] = (GLOBAL_V4,),
) -> tuple[object, list[str]]:
    """An injected resolver plus the log of hostnames it was asked about. No test in this
    module is allowed to touch real DNS."""
    seen: list[str] = []
    table = mapping or {}

    def resolve(host: str) -> Sequence[str]:
        seen.append(host)
        return list(table.get(host, default))

    return resolve, seen


def fetch(url: str, *, max_bytes: int = 1024, transport=None, resolve=None):
    if transport is None:
        transport, _ = transport_for()
    if resolve is None:
        resolve, _ = resolver_for()
    return fetch_remote_image(url, max_bytes=max_bytes, transport=transport, resolve_host=resolve)


def test_https_fetch_connects_to_the_validated_address_not_the_hostname():
    """The connection is pinned to an address that already passed validation. Connecting
    by name would let a second DNS answer point at 127.0.0.1 after the check passed."""
    transport, requests = transport_for(httpx.Response(200, headers={"content-type": "image/png"}, content=PNG))
    resolve, seen = resolver_for({"cdn.example.com": [GLOBAL_V4]})

    image = fetch("https://cdn.example.com/photo.png?w=800#frag", transport=transport, resolve=resolve)

    assert image.content_type == "image/png"
    assert image.content == PNG
    assert seen == ["cdn.example.com"]
    request = requests[0]
    assert request.url.host == GLOBAL_V4
    assert request.url.path == "/photo.png"
    assert request.url.query == b"w=800"
    assert request.headers["host"] == "cdn.example.com"
    assert request.headers["user-agent"] == "Steepd/0.1"
    # SNI and certificate verification still use the real name, so pinning the address
    # does not quietly downgrade TLS.
    assert request.extensions["sni_hostname"] == "cdn.example.com"


def test_http_fetch_pins_the_address_and_preserves_the_host_header():
    """Plain HTTP gets the same pinning; the Host header is what makes the CDN serve the
    right virtual host once we are talking to an IP."""
    transport, requests = transport_for(httpx.Response(200, content=JPEG))
    resolve, _ = resolver_for({"images.example.org": [GLOBAL_V4]})

    image = fetch("http://images.example.org/a.jpg", transport=transport, resolve=resolve)

    assert image.content_type == "image/jpeg"
    assert requests[0].url.host == GLOBAL_V4
    assert requests[0].url.scheme == "http"
    assert requests[0].headers["host"] == "images.example.org"
    assert "sni_hostname" not in requests[0].extensions


def test_an_ipv6_literal_target_is_bracketed_in_the_request_url():
    """A global IPv6 host is legitimate; the request URL must bracket it or the port
    parse turns into garbage."""
    transport, requests = transport_for(httpx.Response(200, content=GIF))

    image = fetch(f"http://[{GLOBAL_V6}]/a.gif", transport=transport)

    assert image.content_type == "image/gif"
    assert requests[0].url.host == GLOBAL_V6
    assert requests[0].headers["host"] == f"[{GLOBAL_V6}]"


BLOCKED_ADDRESSES = [
    ("127.0.0.1", "IPv4 loopback reaches services bound to localhost"),
    ("::1", "IPv6 loopback is the same read by another name"),
    ("10.1.2.3", "RFC1918 private range"),
    ("172.16.0.5", "RFC1918 private range"),
    ("192.168.1.1", "RFC1918 private range, typically the router admin page"),
    ("169.254.169.254", "cloud instance metadata, the credential jackpot"),
    ("fe80::1", "IPv6 link-local"),
    ("fc00::1", "IPv6 unique-local"),
    ("100.64.0.1", "carrier-grade NAT shared address space"),
    ("::ffff:127.0.0.1", "IPv4-mapped loopback smuggled through an IPv6 literal"),
    ("0.0.0.0", "unspecified address routes to this host on most stacks"),
    ("255.255.255.255", "IPv4 broadcast"),
    ("224.0.0.1", "multicast"),
]


@pytest.mark.parametrize("address,threat", BLOCKED_ADDRESSES, ids=[item[0] for item in BLOCKED_ADDRESSES])
def test_a_non_routable_address_literal_is_rejected(address, threat):
    """A literal address in the URL skips DNS entirely, so it must be judged directly."""
    literal = f"[{address}]" if ":" in address else address
    with pytest.raises(ImageFetchError, match="non-routable"):
        fetch(f"http://{literal}/probe.png")
    assert threat


@pytest.mark.parametrize("address,threat", BLOCKED_ADDRESSES, ids=[item[0] for item in BLOCKED_ADDRESSES])
def test_a_hostname_resolving_to_a_non_routable_address_is_rejected(address, threat):
    """A name the attacker controls is the easy way to reach the same targets, so the
    check has to sit on the resolved address rather than on the URL text."""
    resolve, _ = resolver_for({"evil.example.com": [address]})
    with pytest.raises(ImageFetchError, match="non-routable"):
        fetch("http://evil.example.com/probe.png", resolve=resolve)
    assert threat


def test_every_resolved_address_must_pass_not_only_the_first():
    """A name with one global and several private answers is a rebinding attack: checking
    only the address we happen to connect to lets the private one through on a retry."""
    resolve, _ = resolver_for({"mixed.example.com": [GLOBAL_V4, GLOBAL_V6, "10.0.0.7"]})
    with pytest.raises(ImageFetchError, match="non-routable"):
        fetch("http://mixed.example.com/probe.png", resolve=resolve)


def test_a_host_that_resolves_to_nothing_is_rejected():
    """An empty answer means nothing was validated; fetching anyway would fall back to
    connecting by name."""
    resolve, _ = resolver_for({"void.example.com": []})
    with pytest.raises(ImageFetchError, match="no addresses"):
        fetch("http://void.example.com/probe.png", resolve=resolve)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://ftp.example.com/a.png",
        "data:image/png;base64,iVBORw0KGgo=",
        "gopher://example.com/a.png",
        "//example.com/a.png",
    ],
)
def test_a_non_http_scheme_is_rejected(url):
    """file: reads the local disk and data: smuggles bytes past the network layer
    entirely; neither is something a publisher CDN ever serves."""
    with pytest.raises(ImageFetchError, match="scheme"):
        fetch(url)


def test_credentials_in_the_url_are_rejected():
    """Userinfo is how an attacker gets us to authenticate to an internal service on
    their behalf."""
    with pytest.raises(ImageFetchError, match="credentials"):
        fetch("http://admin:secret@cdn.example.com/a.png")


@pytest.mark.parametrize("url", ["http://cdn.example.com:8080/a.png", "https://cdn.example.com:22/a.png"])
def test_a_non_default_port_is_rejected(url):
    """Free choice of port turns the fetcher into a port scanner for everything the
    service can reach, since the response comes back to the sender."""
    with pytest.raises(ImageFetchError, match="port"):
        fetch(url)


@pytest.mark.parametrize("url", ["http://cdn.example.com:80/a.png", "https://cdn.example.com:443/a.png"])
def test_an_explicit_default_port_is_accepted_without_leaking_into_the_host_header(url):
    """Spelling out the scheme's own port is legitimate, and the Host header must still
    be the bare name the CDN expects."""
    transport, requests = transport_for(httpx.Response(200, content=PNG))

    assert fetch(url, transport=transport).content == PNG
    assert requests[0].url.host == GLOBAL_V4
    assert requests[0].headers["host"] == "cdn.example.com"


def test_a_url_without_a_host_is_rejected():
    with pytest.raises(ImageFetchError, match="no host"):
        fetch("http:///a.png")


def test_an_overlong_url_is_rejected():
    with pytest.raises(ImageFetchError, match="too long"):
        fetch("http://cdn.example.com/" + "a" * 2100 + ".png")


def test_a_redirect_to_a_private_address_is_rejected():
    """The first hop being global proves nothing about the second. A public CDN that
    301s to 169.254.169.254 is the whole attack."""
    transport, requests = transport_for(
        httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"}),
        httpx.Response(200, content=PNG),
    )
    resolve, _ = resolver_for({"cdn.example.com": [GLOBAL_V4]})

    with pytest.raises(ImageFetchError, match="non-routable"):
        fetch("http://cdn.example.com/a.png", transport=transport, resolve=resolve)
    # The metadata endpoint was never contacted: validation happens before the request.
    assert len(requests) == 1


def test_a_redirect_to_a_hostname_that_resolves_privately_is_rejected():
    """Redirecting to a name rather than a literal has to be caught by the same
    per-hop resolution, not by inspecting the Location text."""
    transport, _ = transport_for(
        httpx.Response(301, headers={"location": "http://internal.example.com/secret"}),
        httpx.Response(200, content=PNG),
    )
    resolve, seen = resolver_for({"cdn.example.com": [GLOBAL_V4], "internal.example.com": ["10.0.0.5"]})

    with pytest.raises(ImageFetchError, match="non-routable"):
        fetch("http://cdn.example.com/a.png", transport=transport, resolve=resolve)
    assert seen == ["cdn.example.com", "internal.example.com"]


def test_a_redirect_to_another_global_host_is_resolved_again():
    """Each hop gets its own resolution; reusing the first hop's verdict would let a
    redirect inherit approval it never earned."""
    transport, requests = transport_for(
        httpx.Response(307, headers={"location": "https://other.example.net/real.png"}),
        httpx.Response(200, content=PNG),
    )
    resolve, seen = resolver_for({"cdn.example.com": [GLOBAL_V4], "other.example.net": ["151.101.1.1"]})

    image = fetch("https://cdn.example.com/a.png", transport=transport, resolve=resolve)

    assert image.content_type == "image/png"
    assert seen == ["cdn.example.com", "other.example.net"]
    assert requests[1].url.host == "151.101.1.1"
    assert requests[1].headers["host"] == "other.example.net"
    assert requests[1].extensions["sni_hostname"] == "other.example.net"


def test_a_relative_redirect_resolves_against_the_hostname_not_the_pinned_ip():
    """The request URL carries an IP, so joining a relative Location against it would
    silently rewrite the origin and lose the host we validated."""
    transport, requests = transport_for(
        httpx.Response(302, headers={"location": "/moved/real.png"}),
        httpx.Response(200, content=PNG),
    )
    resolve, seen = resolver_for({"cdn.example.com": [GLOBAL_V4]})

    fetch("http://cdn.example.com/a/b.png", transport=transport, resolve=resolve)

    assert seen == ["cdn.example.com", "cdn.example.com"]
    assert requests[1].url.path == "/moved/real.png"
    assert requests[1].headers["host"] == "cdn.example.com"


def test_a_redirect_chain_longer_than_three_hops_is_rejected():
    """An unbounded chain is a cheap way to tie up a worker, and each extra hop is
    another chance to slip an address past a check."""
    transport, requests = transport_for(httpx.Response(302, headers={"location": "http://cdn.example.com/next"}))

    with pytest.raises(ImageFetchError, match="redirect limit"):
        fetch("http://cdn.example.com/a.png", transport=transport)
    assert len(requests) == 4


def test_a_chain_of_exactly_three_redirects_still_succeeds():
    """The limit is three redirects, not two: the boundary is asserted so tightening it
    by accident shows up here."""
    transport, requests = transport_for(
        httpx.Response(302, headers={"location": "http://cdn.example.com/1"}),
        httpx.Response(302, headers={"location": "http://cdn.example.com/2"}),
        httpx.Response(302, headers={"location": "http://cdn.example.com/3"}),
        httpx.Response(200, content=PNG),
    )

    assert fetch("http://cdn.example.com/a.png", transport=transport).content == PNG
    assert len(requests) == 4


def test_a_redirect_without_a_location_is_rejected():
    transport, _ = transport_for(httpx.Response(302))
    with pytest.raises(ImageFetchError, match="no location"):
        fetch("http://cdn.example.com/a.png", transport=transport)


@pytest.mark.parametrize("status", [201, 204, 304, 401, 403, 404, 418, 500, 503])
def test_a_non_success_status_is_rejected(status):
    """Only 200 carries an image. Error pages are HTML, and treating one as a payload
    would inline whatever an internal service said in its error body."""
    transport, _ = transport_for(httpx.Response(status, content=b"<html>nope</html>"))
    with pytest.raises(ImageFetchError, match="HTTP"):
        fetch("http://cdn.example.com/a.png", transport=transport)


def test_a_body_larger_than_the_limit_is_rejected_while_streaming():
    """Content-Length is attacker-influenced and may simply lie. The count of bytes
    actually taken off the socket is the limit that matters."""
    transport, _ = transport_for(httpx.Response(200, headers={"content-length": "10"}, content=PNG + b"\x00" * 5000))
    with pytest.raises(ImageFetchError, match="size limit"):
        fetch("http://cdn.example.com/a.png", max_bytes=64, transport=transport)


def test_an_honest_oversize_content_length_is_rejected_before_the_body_is_read():
    """When the header is truthful it is a free early exit, so it is checked first."""
    transport, _ = transport_for(httpx.Response(200, headers={"content-length": "999999"}, content=PNG))
    with pytest.raises(ImageFetchError, match="size limit"):
        fetch("http://cdn.example.com/a.png", max_bytes=64, transport=transport)


def test_a_body_exactly_at_the_limit_is_accepted():
    """The cap is inclusive; an off-by-one here would reject legitimate images at the
    configured boundary."""
    transport, _ = transport_for(httpx.Response(200, content=PNG))
    assert fetch("http://cdn.example.com/a.png", max_bytes=len(PNG), transport=transport).content == PNG


def test_one_byte_over_the_limit_is_rejected():
    transport, _ = transport_for(httpx.Response(200, content=PNG))
    with pytest.raises(ImageFetchError, match="size limit"):
        fetch("http://cdn.example.com/a.png", max_bytes=len(PNG) - 1, transport=transport)


def test_an_empty_body_is_rejected():
    transport, _ = transport_for(httpx.Response(200, content=b""))
    with pytest.raises(ImageFetchError, match="empty"):
        fetch("http://cdn.example.com/a.png", transport=transport)


def test_html_labelled_as_a_png_is_rejected():
    """The exfiltration payoff: an internal endpoint returns JSON or HTML, a lying
    Content-Type calls it an image, and the bytes land in the attacker's EPUB. Magic
    bytes are the only thing that decides."""
    transport, _ = transport_for(
        httpx.Response(200, headers={"content-type": "image/png"}, content=b"<html><body>secret</body></html>")
    )
    with pytest.raises(ImageFetchError, match="supported image format"):
        fetch("http://cdn.example.com/a.png", transport=transport)


def test_an_svg_is_rejected_even_when_labelled_as_an_image():
    """SVG is a script container, not a picture, and it has no magic number to match."""
    transport, _ = transport_for(httpx.Response(200, headers={"content-type": "image/svg+xml"}, content=SVG))
    with pytest.raises(ImageFetchError, match="supported image format"):
        fetch("http://cdn.example.com/a.svg", transport=transport)


@pytest.mark.parametrize(
    "payload,expected",
    [(PNG, "image/png"), (JPEG, "image/jpeg"), (GIF, "image/gif"), (WEBP, "image/webp")],
    ids=["png", "jpeg", "gif", "webp"],
)
def test_the_sniffed_type_wins_over_a_wrong_content_type_header(payload, expected):
    """CDNs mislabel images constantly, so a wrong header is not a reason to drop a real
    image - but the returned type is the sniffed one, never the claimed one."""
    transport, _ = transport_for(
        httpx.Response(200, headers={"content-type": "application/octet-stream"}, content=payload)
    )
    assert fetch("http://cdn.example.com/a.bin", transport=transport).content_type == expected


def test_a_riff_container_that_is_not_webp_is_rejected():
    """RIFF alone is a WAV or AVI; the WEBP tag at offset 8 is what makes it an image."""
    transport, _ = transport_for(httpx.Response(200, content=b"RIFF\x20\x00\x00\x00WAVEfmt " + b"\x00" * 16))
    with pytest.raises(ImageFetchError, match="supported image format"):
        fetch("http://cdn.example.com/a.webp", transport=transport)


def test_a_transport_failure_becomes_an_image_fetch_error():
    """Callers get exactly one exception type, so a connect timeout to an internal host
    cannot be told apart from any other failure by whoever reads the response."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out", request=request)

    with pytest.raises(ImageFetchError, match="request failed"):
        fetch("http://cdn.example.com/a.png", transport=httpx.MockTransport(handler))


def test_a_non_positive_size_limit_is_rejected():
    """A caller passing 0 must not silently mean "no limit"."""
    with pytest.raises(ImageFetchError, match="size limit"):
        fetch("http://cdn.example.com/a.png", max_bytes=0)


def test_a_resolver_failure_becomes_an_image_fetch_error():
    def resolve(host: str) -> Sequence[str]:
        raise OSError("no such host")

    with pytest.raises(ImageFetchError, match="could not be resolved"):
        fetch("http://cdn.example.com/a.png", resolve=resolve)
