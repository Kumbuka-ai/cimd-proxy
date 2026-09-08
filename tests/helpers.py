# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Test-only helpers.

* :class:`FakeFetcher` short-circuits the CIMD fetcher so tests do not touch
  the network. It still runs the real ``parse_client_id_url``,
  ``resolve_and_check_ips`` and ``validate_document`` — those are the guards
  the red probes measure, and replacing them accidentally would defeat the
  point of the pair.
"""

from __future__ import annotations

import socket
from collections.abc import Callable

from cimd_proxy.fetcher import (
    CimdDocument,
    CimdFetcher,
    FetchResult,
    parse_client_id_url,
    resolve_and_check_ips,
    validate_document,
)


class FakeFetcher(CimdFetcher):
    """A fetcher that runs the real guards but returns a canned document.

    The canned document is the *raw* dict — it goes through the same
    ``validate_document`` a real response would, so tests can measure that guard.
    """

    def __init__(
        self,
        raw_document: dict,
        *,
        pinned_ip: str = "203.0.113.1",
        skip_dns: bool = False,
    ) -> None:
        super().__init__(max_bytes=8192, timeout_seconds=5.0)
        self._raw = raw_document
        self._pinned_ip = pinned_ip
        self._skip_dns = skip_dns

    async def fetch(self, url: str) -> FetchResult:
        parsed = parse_client_id_url(url)
        if not self._skip_dns:
            resolve_and_check_ips(parsed.hostname)
        doc = validate_document(url, self._raw)
        return FetchResult(document=doc, resolved_ip=self._pinned_ip)


def install_fake_fetcher(app: object, raw_document: dict, **kwargs) -> None:
    """Replace ``app.state.cimd_service`` with one backed by a FakeFetcher."""

    from cimd_proxy.cache import TtlCache
    from cimd_proxy.cimd_service import CimdService

    service = app.state.cimd_service  # type: ignore[attr-defined]
    cache: TtlCache[CimdDocument] = TtlCache()
    app.state.cimd_service = CimdService(  # type: ignore[attr-defined]
        fetcher=FakeFetcher(raw_document, **kwargs),
        allowlist=service._allowlist,  # noqa: SLF001 - re-use whatever the app had
        cache=cache,
        cache_ttl_min=300,
        cache_ttl_max=86400,
    )


def resolver_returning(addrs: list[str]) -> Callable:
    """Build a ``socket.getaddrinfo`` replacement returning ``addrs``."""

    def _fn(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002
        infos = []
        for a in addrs:
            fam = socket.AF_INET6 if ":" in a else socket.AF_INET
            sockaddr = (a, port or 0) if fam == socket.AF_INET else (a, port or 0, 0, 0)
            infos.append((fam, socket.SOCK_STREAM, 6, "", sockaddr))
        return infos

    return _fn


def valid_document(client_id_url: str, *redirect_uris: str) -> dict:
    return {
        "client_id": client_id_url,
        "redirect_uris": list(redirect_uris) or ["https://claude.ai/api/mcp/auth_callback"],
        "token_endpoint_auth_method": "none",
    }
