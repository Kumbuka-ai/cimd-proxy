# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest

from cimd_proxy.cache import TtlCache, choose_ttl


class TestTtlCache:
    def test_hit(self) -> None:
        c: TtlCache[str] = TtlCache(clock=lambda: 0)
        c.put("k", "v", ttl_seconds=10)
        assert c.get("k") == "v"

    def test_miss(self) -> None:
        c: TtlCache[str] = TtlCache()
        assert c.get("nope") is None

    def test_expiry(self) -> None:
        t = [0.0]
        c: TtlCache[str] = TtlCache(clock=lambda: t[0])
        c.put("k", "v", ttl_seconds=10)
        t[0] = 9
        assert c.get("k") == "v"
        t[0] = 10
        assert c.get("k") is None

    def test_zero_ttl_does_not_store(self) -> None:
        c: TtlCache[str] = TtlCache()
        c.put("k", "v", ttl_seconds=0)
        assert c.get("k") is None

    def test_invalidate_and_clear(self) -> None:
        c: TtlCache[str] = TtlCache(clock=lambda: 0)
        c.put("a", "1", 100)
        c.put("b", "2", 100)
        assert len(c) == 2
        c.invalidate("a")
        assert c.get("a") is None
        c.clear()
        assert c.get("b") is None


class TestChooseTtl:
    def test_missing_header_uses_min(self) -> None:
        assert choose_ttl(cache_control=None, min_ttl=300, max_ttl=86400) == 300

    def test_default_ttl_overrides_min(self) -> None:
        assert choose_ttl(cache_control=None, min_ttl=300, max_ttl=86400, default_ttl=1200) == 1200

    def test_max_age_clamped_to_min(self) -> None:
        assert choose_ttl(cache_control="max-age=60", min_ttl=300, max_ttl=86400) == 300

    def test_max_age_clamped_to_max(self) -> None:
        assert choose_ttl(cache_control="max-age=1000000", min_ttl=300, max_ttl=86400) == 86400

    def test_max_age_in_range_used(self) -> None:
        assert choose_ttl(cache_control="max-age=1200", min_ttl=300, max_ttl=86400) == 1200

    def test_no_store_forces_min(self) -> None:
        assert choose_ttl(cache_control="no-store", min_ttl=300, max_ttl=86400) == 300

    @pytest.mark.parametrize(
        "header",
        ["private, max-age=1200", "public,  max-age = 1200 "],
    )
    def test_whitespace_and_multi_directive(self, header: str) -> None:
        assert choose_ttl(cache_control=header, min_ttl=300, max_ttl=86400) == 1200
