# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""CIMD-document service: fetch + cache.

The cache is populated only after both SSRF checks *and* the document schema
have accepted a response — a stored 404 or a stored malformed document would
render a bad client permanently un-fixable. The TTL comes from the response's
``Cache-Control: max-age`` header, clamped to ``[min, max]``; absent header
uses ``min``.

There is no host allowlist. A CIMD ``client_id`` URL is admitted on its
own shape (https, absolute, non-empty path, no fragment, no userinfo — see
:func:`fetcher.parse_client_id_url`) and the SSRF guard on the resolved
addresses is what keeps the fetch from being turned into an internal probe.
"""

from __future__ import annotations

from .cache import TtlCache, choose_ttl
from .fetcher import (
    CimdDocument,
    CimdFetcher,
    DocumentInvalid,
    FetchError,
    FetchResult,
    SSRFRefused,
)


class CimdService:
    def __init__(
        self,
        *,
        fetcher: CimdFetcher,
        cache: TtlCache[CimdDocument],
        cache_ttl_min: int,
        cache_ttl_max: int,
    ) -> None:
        self._fetcher = fetcher
        self._cache = cache
        self._ttl_min = cache_ttl_min
        self._ttl_max = cache_ttl_max

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
