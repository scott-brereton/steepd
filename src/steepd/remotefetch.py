"""Fetch bounded public HTTP resources without exposing Steepd's private network.

Every caller receives the fetched bytes, so an unchecked request would be a server-side
read oracle. This module owns the shared network boundary: it validates every URL hop and
every resolved address, pins the connection to an approved address, and bounds redirects,
time, and decoded response bytes.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

USER_AGENT = "Steepd/0.1"
MAX_URL_LENGTH = 2048
MAX_REDIRECTS = 3
REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})
ACCESS_DENIED_STATUS_CODES = frozenset({401, 402, 403, 451})

_DEFAULT_PORTS = {"http": 80, "https": 443}
_SHARED_ADDRESS_SPACE_V4 = ipaddress.ip_network("100.64.0.0/10")
_UNIQUE_LOCAL_V6 = ipaddress.ip_network("fc00::/7")
_BROADCAST_V4 = ipaddress.ip_address("255.255.255.255")
_CHUNK_BYTES = 64 * 1024


class RemoteFetchError(RuntimeError):
    """The resource could not be fetched safely and completely."""


class RemoteBodyTooLarge(RemoteFetchError):
    """The declared or streamed decoded response exceeded the caller's byte limit."""


class RemoteAccessDenied(RemoteFetchError):
    """The public site explicitly refused the request used for article capture."""

    def __init__(self, hostname: str, status_code: int) -> None:
        self.hostname = hostname
        self.status_code = status_code
        super().__init__(f"Remote site denied capture with HTTP {status_code}")


@dataclass(frozen=True, slots=True)
class FetchedRemote:
    content_type: str
    content: bytes
    final_url: str


@dataclass(frozen=True, slots=True)
class _Target:
    scheme: str
    host: str
    address: str
    request_url: str
    origin_url: str
    host_header: str


def _resolve_host(host: str) -> Sequence[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise RemoteFetchError("Remote host could not be resolved") from exc
    return [str(info[4][0]) for info in infos]


def _validate_address(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise RemoteFetchError("Remote host resolved to something that is not an IP address") from exc

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    blocked = (
        ip.is_unspecified
        or ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip == _BROADCAST_V4
        or (isinstance(ip, ipaddress.IPv4Address) and ip in _SHARED_ADDRESS_SPACE_V4)
        or (isinstance(ip, ipaddress.IPv6Address) and ip in _UNIQUE_LOCAL_V6)
        or not ip.is_global
    )
    if blocked:
        raise RemoteFetchError(f"Remote host resolves to a non-routable address: {ip}")
    return ip


def _prepare_target(url: str, resolver: Callable[[str], Sequence[str]]) -> _Target:
    if len(url) > MAX_URL_LENGTH:
        raise RemoteFetchError("Remote URL is too long")
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise RemoteFetchError("Remote URL could not be parsed") from exc

    scheme = parsed.scheme.casefold()
    if scheme not in _DEFAULT_PORTS:
        raise RemoteFetchError(f"Remote URL scheme is not fetchable: {scheme or 'none'}")
    if parsed.username is not None or parsed.password is not None:
        raise RemoteFetchError("Remote URL carries credentials")
    try:
        port = parsed.port
    except ValueError as exc:
        raise RemoteFetchError("Remote URL has an invalid port") from exc
    default_port = _DEFAULT_PORTS[scheme]
    if port not in {None, default_port}:
        raise RemoteFetchError("Remote URL uses a non-default port")
    host = (parsed.hostname or "").casefold()
    if not host:
        raise RemoteFetchError("Remote URL has no host")

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is None:
        # The Host header and SNI are ASCII-only, so an internationalized name has to go
        # over the wire in its IDNA form; a name that has none is not fetchable at all.
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise RemoteFetchError("Remote URL hostname could not be encoded") from exc

    if literal is not None:
        addresses = [str(_validate_address(host))]
    else:
        try:
            resolved = list(resolver(host))
        except OSError as exc:
            raise RemoteFetchError("Remote host could not be resolved") from exc
        if not resolved:
            raise RemoteFetchError("Remote host resolved to no addresses")
        addresses = [str(_validate_address(item)) for item in resolved]

    address = addresses[0]
    connect_host = f"[{address}]" if ":" in address else address
    header_host = f"[{host}]" if literal is not None and ":" in host else host
    path = parsed.path or "/"
    request_url = urlunsplit((scheme, f"{connect_host}:{default_port}", path, parsed.query, ""))
    origin_url = urlunsplit((scheme, header_host, path, parsed.query, ""))
    return _Target(
        scheme=scheme,
        host=host,
        address=address,
        request_url=request_url,
        origin_url=origin_url,
        host_header=header_host,
    )


def _read_body(response: httpx.Response, max_bytes: int) -> bytes:
    declared = response.headers.get("content-length")
    if declared:
        try:
            declared_bytes = int(declared)
        except ValueError as exc:
            raise RemoteFetchError("Remote response declared an invalid length") from exc
        if declared_bytes > max_bytes:
            raise RemoteBodyTooLarge("Remote response exceeds the configured size limit")

    chunks: list[bytes] = []
    received = 0
    for chunk in response.iter_bytes(chunk_size=_CHUNK_BYTES):
        received += len(chunk)
        if received > max_bytes:
            raise RemoteBodyTooLarge("Remote response exceeds the configured size limit")
        chunks.append(chunk)
    if not received:
        raise RemoteFetchError("Remote response body was empty")
    return b"".join(chunks)


def fetch_remote(
    url: str,
    *,
    max_bytes: int,
    transport: httpx.BaseTransport | None = None,
    resolve_host: Callable[[str], Sequence[str]] | None = None,
) -> FetchedRemote:
    """Fetch one complete public HTTP(S) resource or raise ``RemoteFetchError``."""
    if max_bytes <= 0:
        raise RemoteFetchError("Remote response size limit must be positive")
    resolver = resolve_host if resolve_host is not None else _resolve_host

    current = url
    with httpx.Client(
        follow_redirects=False,
        trust_env=False,
        timeout=httpx.Timeout(10.0, connect=5.0),
        transport=transport,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            target = _prepare_target(current, resolver)
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
                            raise RemoteFetchError("Remote redirect had no location")
                        current = urljoin(target.origin_url, location)
                        continue
                    if response.status_code in ACCESS_DENIED_STATUS_CODES:
                        raise RemoteAccessDenied(target.host, response.status_code)
                    if response.status_code != 200:
                        raise RemoteFetchError(f"Remote request returned HTTP {response.status_code}")
                    content = _read_body(response, max_bytes)
                    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
            except (httpx.HTTPError, ssl.SSLError, OSError) as exc:
                raise RemoteFetchError("Remote request failed") from exc

            return FetchedRemote(content_type=content_type, content=content, final_url=target.origin_url)

    raise RemoteFetchError("Remote URL exceeded the redirect limit")
