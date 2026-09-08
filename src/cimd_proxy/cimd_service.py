# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""CIMD-document service: fetch + cache + policy.

The cache is populated only after both SSRF checks *and* the document schema
have accepted a response — a stored 404 or a stored malformed document would
render a bad client permanently un-fixable. The TTL comes from the response's
``Cache-Control: max-age`` header, clamped to ``[min, max]``; absent header
uses ``min``.
"""

from __future__ import annotations

from .allowlist import Allowlist
from .cache import TtlCache, choose_ttl
from .fetcher import (
    CimdDocument,
    CimdFetcher,
    DocumentInvalid,
    FetchError,
    FetchResult,
    SSRFRefused,
    parse_client_id_url,
)


class CimdService:
    def __init__(
        self,
        *,
        fetcher: CimdFetcher,
        allowlist: Allowlist,
        cache: TtlCache[CimdDocument],
        cache_ttl_min: int,
        cache_ttl_max: int,
    ) -> None:
        self._fetcher = fetcher
        self._allowlist = allowlist
        self._cache = cache
        self._ttl_min = cache_ttl_min
        self._ttl_max = cache_ttl_max

    def check_allowlist(self, client_id_url: str) -> None:
        """Raise :class:`SSRFRefused` if the URL host is not on the allowlist.

        Named ``check_allowlist`` and kept as a distinct step so that the
        RP1 test can measure exactly this guard (see red-probe control run).
        """

        parsed = parse_client_id_url(client_id_url)
        if not self._allowlist.allows(parsed.hostname):
            raise SSRFRefused(f"client_id host {parsed.hostname!r} is not on CIMD_ALLOWED_DOMAINS")

    async def obtain(self, client_id_url: str) -> CimdDocument:
        """Return a validated document, from cache when possible.

        On a cache hit the network is not touched at all.
        """

        cached = self._cache.get(client_id_url)
        if cached is not None:
            return cached
        result: FetchResult = await self._fetcher.fetch(client_id_url)
        ttl = choose_ttl(
            cache_control=result.document.cache_control,
            min_ttl=self._ttl_min,
            max_ttl=self._ttl_max,
        )
        self._cache.put(client_id_url, result.document, ttl)
        return result.document


__all__ = [
    "CimdService",
    "DocumentInvalid",
    "FetchError",
    "SSRFRefused",
]
