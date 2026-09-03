"""Fetch a remote newsletter image without turning the service into an SSRF oracle.

Every URL reaching this module came out of an attacker-controlled email, and the bytes
we return are handed straight back to that sender inside their own EPUB. A fetch of
http://169.254.169.254/latest/meta-data/ that succeeded would deliver cloud credentials
into the attacker's library, so the guard here is a full read oracle's worth of risk,
not a nice-to-have. Nothing about a host is trusted: the URL shape, every address the
name resolves to, and every redirect target are validated on their own terms, and the
connection is pinned to an address we already approved.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from steepd.newsletter import SAFE_INLINE_IMAGE_TYPES

USER_AGENT = "Steepd/0.1"
MAX_URL_LENGTH = 2048
MAX_REDIRECTS = 3
REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})

# One port per scheme, and only the default one. A caller-chosen port would make this a
# port scanner for everything the service can reach, since the response comes back to
# the sender; publisher CDNs never need anything but 80 and 443.
_DEFAULT_PORTS = {"http": 80, "https": 443}

# Named explicitly so the deny list can be audited against the threat list rather than
# read off a single property. `is_global` already excludes both, but a reader checking
# "is carrier-grade NAT covered?" should find the answer here.
_SHARED_ADDRESS_SPACE_V4 = ipaddress.ip_network("100.64.0.0/10")
_UNIQUE_LOCAL_V6 = ipaddress.ip_network("fc00::/7")
_BROADCAST_V4 = ipaddress.ip_address("255.255.255.255")

_CHUNK_BYTES = 64 * 1024


class ImageFetchError(RuntimeError):
    """Any reason the image cannot be fetched safely: unsafe URL, blocked address,
    redirect trouble, oversize, timeout, non-image payload."""


@dataclass(frozen=True, slots=True)
class FetchedImage:
    content_type: str
    content: bytes


@dataclass(frozen=True, slots=True)
class _Target:
    """One validated hop: where to connect, and who to claim to be talking to."""

    scheme: str
    host: str
    port: int
    address: str
    # scheme://<validated ip>:<port>/<path> - the connection never sees the hostname,
    # so a second DNS answer cannot redirect it after the address passed validation.
    request_url: str
    # The hostname form of the same hop, used only as the base for resolving a relative
    # Location header. Resolving a redirect against the pinned IP URL would silently
    # rewrite the origin.
    origin_url: str
    host_header: str


def _resolve_host(host: str) -> Sequence[str]:
    """Every A and AAAA answer for the host, because every one of them is reachable."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ImageFetchError("Image host could not be resolved") from exc
    return [str(info[4][0]) for info in infos]


def _validate_address(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Reject anything that is not a globally routable unicast address."""
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ImageFetchError("Image host resolved to something that is not an IP address") from exc

    # ::ffff:127.0.0.1 is loopback wearing an IPv6 costume, and the v6 properties do not
    # see through the mapping. Judge the address that packets will actually reach.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    blocked = (
        ip.is_unspecified  # 0.0.0.0 and :: route to "this host" on most stacks
        or ip.is_loopback  # 127/8, ::1
        or ip.is_private  # RFC1918 and friends
        or ip.is_link_local  # 169.254/16 carries the cloud metadata endpoint; fe80::/10
        or ip.is_multicast
        or ip.is_reserved
        or ip == _BROADCAST_V4
        or (isinstance(ip, ipaddress.IPv4Address) and ip in _SHARED_ADDRESS_SPACE_V4)
        or (isinstance(ip, ipaddress.IPv6Address) and ip in _UNIQUE_LOCAL_V6)
        or not ip.is_global
    )
    if blocked:
        raise ImageFetchError(f"Image host resolves to a non-routable address: {ip}")
    return ip


def _prepare_target(url: str, resolver: Callable[[str], Sequence[str]]) -> _Target:
    """Validate one hop end to end and pin it to an approved address."""
    if len(url) > MAX_URL_LENGTH:
        raise ImageFetchError("Image URL is too long")
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise ImageFetchError("Image URL could not be parsed") from exc

    scheme = parsed.scheme.casefold()
    if scheme not in _DEFAULT_PORTS:
        raise ImageFetchError(f"Image URL scheme is not fetchable: {scheme or 'none'}")
    # Credentials in the URL are how an attacker gets us to authenticate to an internal
    # service on their behalf; a publisher CDN never needs them.
    if parsed.username is not None or parsed.password is not None:
        raise ImageFetchError("Image URL carries credentials")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ImageFetchError("Image URL has an invalid port") from exc
    default_port = _DEFAULT_PORTS[scheme]
    if port not in {None, default_port}:
        raise ImageFetchError("Image URL uses a non-default port")
    host = (parsed.hostname or "").casefold()
    if not host:
        raise ImageFetchError("Image URL has no host")

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        addresses = [str(_validate_address(host))]
    else:
        try:
            resolved = list(resolver(host))
        except OSError as exc:
            raise ImageFetchError("Image host could not be resolved") from exc
        if not resolved:
            raise ImageFetchError("Image host resolved to no addresses")
        # Every answer, not just the one we connect to: a name with one global and one
        # private A record is a rebinding attack that would otherwise pass on a retry.
        addresses = [str(_validate_address(item)) for item in resolved]

    address = addresses[0]
    connect_host = f"[{address}]" if ":" in address else address
    header_host = f"[{host}]" if literal is not None and ":" in host else host
    path = parsed.path or "/"
    # Fragments are client-side only; drop rather than reject so an otherwise fine
    # publisher URL is not thrown away over a "#" nobody meant to send.
    request_url = urlunsplit((scheme, f"{connect_host}:{default_port}", path, parsed.query, ""))
    # No port in the origin or the Host header: the port rule above already guarantees
    # the scheme default, and carrying it forward would put a ":80" in the Host of every
    # hop after a relative redirect.
    origin_url = urlunsplit((scheme, header_host, path, parsed.query, ""))
    return _Target(
        scheme=scheme,
        host=host,
        port=default_port,
        address=address,
        request_url=request_url,
        origin_url=origin_url,
        host_header=header_host,
    )


def _sniff_image_type(content: bytes) -> str:
    """Identify the payload from its magic bytes. CDNs mislabel images constantly, and a
    Content-Type header is attacker-influenced anyway, so the header never decides this.
    An SVG has no magic number and falls through to rejection, which is the point: it is
    a script container, not a picture."""
    if content.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if content.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        return "image/webp"
    return ""


def _read_body(response: httpx.Response, max_bytes: int) -> bytes:
    declared = response.headers.get("content-length")
    if declared:
        try:
            declared_bytes = int(declared)
        except ValueError as exc:
            raise ImageFetchError("Image response declared an invalid length") from exc
        if declared_bytes > max_bytes:
            raise ImageFetchError("Image exceeds the configured size limit")

    chunks: list[bytes] = []
    received = 0
    # The header above is only a fast reject: it can lie or be absent, so the count of
    # bytes actually taken off the socket is the limit that matters.
    for chunk in response.iter_bytes(chunk_size=_CHUNK_BYTES):
        received += len(chunk)
        if received > max_bytes:
            raise ImageFetchError("Image exceeds the configured size limit")
        chunks.append(chunk)
    if not received:
        raise ImageFetchError("Image response body was empty")
    return b"".join(chunks)


def fetch_remote_image(
    url: str,
    *,
    max_bytes: int,
    transport: httpx.BaseTransport | None = None,
    resolve_host: Callable[[str], Sequence[str]] | None = None,
) -> FetchedImage:
    """Fetch one remote image, or raise ImageFetchError. Never returns partial data."""
    if max_bytes <= 0:
        raise ImageFetchError("Image size limit must be positive")
    resolver = resolve_host if resolve_host is not None else _resolve_host

    current = url
    with httpx.Client(
        follow_redirects=False,  # each hop is revalidated by hand; httpx would not
        trust_env=False,  # a proxy from the environment would bypass the address pinning
        timeout=httpx.Timeout(10.0, connect=5.0),
        transport=transport,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            target = _prepare_target(current, resolver)
            # SNI and certificate verification still use the real hostname, so pinning
            # the connection to an IP does not weaken TLS.
            extensions = {"sni_hostname": target.host} if target.scheme == "https" else {}
            try:
                with client.stream(
                    "GET",
                    target.request_url,
                    headers={"Host": target.host_header},
                    extensions=extensions,
                ) as response:
                    if response.status_code in REDIRECT_STATUS_CODES:
                        location = response.headers.get("location")
                        if not location:
                            raise ImageFetchError("Image redirect had no location")
                        current = urljoin(target.origin_url, location)
                        continue
                    if response.status_code != 200:
                        raise ImageFetchError(f"Image request returned HTTP {response.status_code}")
                    content = _read_body(response, max_bytes)
            except (httpx.HTTPError, ssl.SSLError, OSError) as exc:
                raise ImageFetchError("Image request failed") from exc

            content_type = _sniff_image_type(content)
            if content_type not in SAFE_INLINE_IMAGE_TYPES:
                raise ImageFetchError("Image payload is not a supported image format")
            return FetchedImage(content_type=content_type, content=content)

    raise ImageFetchError("Image URL exceeded the redirect limit")
