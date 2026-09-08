# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""In-memory TTL cache for validated CIMD documents.

Only documents that have already passed the identity / SSRF / structure checks
are ever placed in the cache — a stored 404 or a stored malformed document
would render a bad client permanently un-fixable.

The cache carries a monotonic clock so tests can seed and advance time
deterministically.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class _Entry[T]:
    value: T
    expires_at: float


class TtlCache[T]:
    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._entries: dict[str, _Entry[T]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> T | None:
        now = self._clock()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.expires_at <= now:
                self._entries.pop(key, None)
                return None
            return entry.value

    def put(self, key: str, value: T, ttl_seconds: float) -> None:
        if ttl_seconds <= 0:
            return
        expires_at = self._clock() + ttl_seconds
        with self._lock:
            self._entries[key] = _Entry(value=value, expires_at=expires_at)

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


def _base_from_directive(cache_control_lower: str, default_ttl: int | None, min_ttl: int) -> int:
    """Return the raw TTL (unclamped) implied by a ``Cache-Control`` value."""

    max_age = _extract_max_age(cache_control_lower)
    if max_age is not None:
        return max_age
    if "no-store" in cache_control_lower or "no-cache" in cache_control_lower:
        return min_ttl
    return default_ttl if default_ttl is not None else min_ttl


def choose_ttl(
    *,
    cache_control: str | None,
    min_ttl: int,
    max_ttl: int,
    default_ttl: int | None = None,
) -> int:
    """Pick a TTL from an HTTP ``Cache-Control`` header, clamped to [min, max].

    * A ``no-store`` or ``no-cache`` directive forces the TTL to ``min_ttl``
      even though the plain reading would be "do not cache at all"; we prefer
      the loud-and-bounded behaviour of always caching briefly, so a rogue
      upstream cannot pin us in per-request-fetch mode.
    * If no directive is present, ``default_ttl`` is used; if that is ``None``,
      ``min_ttl`` is used.
    """

    if cache_control is None:
        base = default_ttl if default_ttl is not None else min_ttl
    else:
        base = _base_from_directive(cache_control.lower(), default_ttl, min_ttl)
    clamped = max(min_ttl, min(base, max_ttl))
    return int(clamped)


def _extract_max_age(cache_control_lower: str) -> int | None:
    for raw in cache_control_lower.split(","):
        directive = raw.strip()
        if not directive.startswith("max-age"):
            continue
        _, _, rhs = directive.partition("=")
        rhs = rhs.strip().strip('"')
        try:
            return int(rhs)
        except ValueError:
            return None
    return None
