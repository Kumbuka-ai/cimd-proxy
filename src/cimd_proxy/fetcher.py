# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""CIMD document fetcher with SSRF and DNS-rebinding guards.

Refer to :mod:`draft-ietf-oauth-client-id-metadata-document-02` for the
document rules; the network rules below are the ones that keep this endpoint
from being turned into an SSRF pivot:

* URL structure: ``https``, non-empty path, no userinfo, no fragment. Byte-
  wise comparison — ``https://a.com/x`` and ``https://a.com:443/x`` are not
  the same identifier.
* DNS: we resolve ourselves and reject *any* address that is private,
  loopback, link-local, reserved, multicast, or unspecified. One tainted
  address fails the whole fetch, so a mixed A/AAAA record cannot bypass by
  offering a safe address alongside an unsafe one.
* Connection: the socket is opened to the exact IP we validated (DNS-
  rebinding protection); the hostname travels only in the ``Host`` header and
  in TLS SNI + certificate verification.
* Redirects are **not** followed.
* The body is read incrementally and truncated at ``max_bytes`` — we never
  buffer a giant response just to measure it.

There is no development-mode loopback exception, on purpose. The draft
permits one in test only; a production build without a way to enable it
cannot be tricked into enabling it.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx


class FetchError(Exception):
    """Raised when the CIMD URL cannot be fetched safely or the response is unusable."""


class SSRFRefused(FetchError):
    """Raised when the URL or its DNS resolution points into a forbidden network zone."""


class DocumentInvalid(FetchError):
    """Raised when the JSON document violates the CIMD schema."""


@dataclass(frozen=True, slots=True)
class ParsedClientIdUrl:
    scheme: str
    hostname: str
    port: int
    path: str
    query: str

    @property
    def authority(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return self.hostname if self.port == default else f"{self.hostname}:{self.port}"


@dataclass(frozen=True, slots=True)
class CimdDocument:
    client_id: str
    redirect_uris: tuple[str, ...]
    raw: dict[str, Any]
    cache_control: str | None


@dataclass(frozen=True, slots=True)
class FetchResult:
    document: CimdDocument
    resolved_ip: str


_FORBIDDEN_METHODS = frozenset({"client_secret_post", "client_secret_basic", "client_secret_jwt"})


def parse_client_id_url(url: str) -> ParsedClientIdUrl:
    """Byte-wise parse of a client-id URL, refusing every disallowed shape."""

    if not isinstance(url, str) or not url:
        raise SSRFRefused("client_id is empty")
    split = urlsplit(url)
    if split.scheme != "https":
        raise SSRFRefused("client_id must use https")
    if split.fragment:
        raise SSRFRefused("client_id must not carry a fragment")
    if "@" in split.netloc:
        raise SSRFRefused("client_id must not carry a userinfo component")
    if not split.hostname:
        raise SSRFRefused("client_id has no host")
    if not split.path or split.path == "/":
        raise SSRFRefused("client_id must have a non-empty path")
    port = split.port if split.port is not None else 443
    return ParsedClientIdUrl(
        scheme=split.scheme,
        hostname=split.hostname,
        port=port,
        path=split.path,
        query=split.query,
    )


def resolve_and_check_ips(hostname: str) -> list[str]:
    """Resolve ``hostname`` and refuse if any address is in a forbidden zone.

    Returns every resolved address so the caller can pin the connection to
    one of them and still know which siblings were safe.
    """

    try:
        infos = socket.getaddrinfo(hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFRefused(f"cannot resolve host {hostname!r}") from exc
    if not infos:
        raise SSRFRefused(f"cannot resolve host {hostname!r}")
    ips: list[str] = []
    seen: set[str] = set()
    for _family, _stype, _proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0]
        # IPv6 sockaddr can carry scope like "fe80::1%en0"; strip for parsing.
        raw_ip = ip_str.split("%", 1)[0]
        if raw_ip in seen:
            continue
        seen.add(raw_ip)
        addr = ipaddress.ip_address(raw_ip)
        for attr in (
            "is_private",
            "is_loopback",
            "is_link_local",
            "is_reserved",
            "is_multicast",
            "is_unspecified",
        ):
            if getattr(addr, attr):
                raise SSRFRefused(f"host {hostname!r} resolves to {raw_ip} ({attr}); refusing")
        ips.append(raw_ip)
    return ips


def validate_document(url: str, document: dict[str, Any]) -> CimdDocument:
    """Enforce the CIMD document invariants required by the draft."""

    if not isinstance(document, dict):
        raise DocumentInvalid("CIMD document is not a JSON object")
    client_id = document.get("client_id")
    if not isinstance(client_id, str):
        raise DocumentInvalid("CIMD document has no client_id")
    if client_id != url:
        raise DocumentInvalid("client_id in document does not match the URL byte-for-byte")
    if "client_secret" in document:
        raise DocumentInvalid("CIMD document must not carry client_secret")
    if "client_secret_expires_at" in document:
        raise DocumentInvalid("CIMD document must not carry client_secret_expires_at")
    method = document.get("token_endpoint_auth_method")
    if isinstance(method, str) and method in _FORBIDDEN_METHODS:
        raise DocumentInvalid(
            f"token_endpoint_auth_method {method!r} relies on a shared symmetric secret"
        )
    redirect_uris = document.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        raise DocumentInvalid("CIMD document must carry a non-empty redirect_uris array")
    if not all(isinstance(u, str) and u for u in redirect_uris):
        raise DocumentInvalid("every redirect_uris entry must be a non-empty string")
    return CimdDocument(
        client_id=client_id,
        redirect_uris=tuple(redirect_uris),
        raw=document,
        cache_control=None,
    )


class CimdFetcher:
    """The synchronous / async-agnostic CIMD fetcher.

    ``fetch`` performs the URL parse, the DNS check, and (on success) the
    pinned HTTPS GET. It returns the validated document plus the resolved IP
    the connection was pinned to (for the log).
    """

    def __init__(
        self,
        *,
        max_bytes: int,
        timeout_seconds: float,
        user_agent: str = "cimd-proxy/0.2",
    ) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._max_bytes = max_bytes
        self._timeout = timeout_seconds
        self._user_agent = user_agent

    async def fetch(self, url: str) -> FetchResult:
        parsed = parse_client_id_url(url)
        ips = resolve_and_check_ips(parsed.hostname)
        pinned_ip = ips[0]
        return await self._fetch_pinned(url, parsed, pinned_ip)

    async def _fetch_pinned(
        self, url: str, parsed: ParsedClientIdUrl, pinned_ip: str
    ) -> FetchResult:
        # Build a URL that dials the pinned IP directly. Hostname stays in the
        # Host header and in SNI / cert verification via `sni_hostname`.
        host_for_url = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
        pinned_url = f"{parsed.scheme}://{host_for_url}:{parsed.port}{parsed.path}"
        if parsed.query:
            pinned_url = f"{pinned_url}?{parsed.query}"
        headers = {
            "Host": parsed.authority,
            "User-Agent": self._user_agent,
            "Accept": "application/json",
        }
        async with httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=False,
            verify=True,
        ) as client:
            request = client.build_request("GET", pinned_url, headers=headers)
            request.extensions["sni_hostname"] = parsed.hostname
            try:
                async with client.stream(
                    request.method,
                    request.url,
                    headers=request.headers,
                    extensions=request.extensions,
                ) as response:
                    if response.status_code != 200:
                        raise FetchError(
                            f"upstream returned HTTP {response.status_code} for CIMD document"
                        )
                    buf = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=4096):
                        buf.extend(chunk)
                        if len(buf) > self._max_bytes:
                            raise FetchError(f"CIMD document exceeds max_bytes ({self._max_bytes})")
                    cache_control = response.headers.get("cache-control")
            except httpx.HTTPError as exc:
                raise FetchError(f"cannot fetch CIMD document: {exc}") from exc
        try:
            import json

            payload = json.loads(bytes(buf).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise DocumentInvalid("CIMD document is not valid JSON") from exc
        doc = validate_document(url, payload)
        doc = CimdDocument(
            client_id=doc.client_id,
            redirect_uris=doc.redirect_uris,
            raw=doc.raw,
            cache_control=cache_control,
        )
        return FetchResult(document=doc, resolved_ip=pinned_ip)
