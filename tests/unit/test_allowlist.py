# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest

from cimd_proxy.allowlist import Allowlist


class TestAllowlist:
    def test_apex_match(self) -> None:
        al = Allowlist(["example.com"])
        assert al.allows("example.com")
        assert not al.allows("sub.example.com")
        assert not al.allows("notexample.com")

    def test_wildcard_matches_subdomains_only(self) -> None:
        al = Allowlist(["*.example.com"])
        assert al.allows("a.example.com")
        assert al.allows("a.b.example.com")
        assert not al.allows("example.com")
        assert not al.allows("evilexample.com")

    def test_prefix_boundary_is_label_based(self) -> None:
        # 'evilexample.com' must NOT match 'example.com' — this is why the
        # comparison is label-based, not substring-based.
        al = Allowlist(["example.com"])
        assert not al.allows("evilexample.com")

    def test_star_matches_everything(self) -> None:
        al = Allowlist(["*"])
        assert al.allows("anything.tld")
        assert al.allows("127.0.0.1")

    def test_case_insensitive(self) -> None:
        al = Allowlist(["Example.COM"])
        assert al.allows("example.com")
        assert al.allows("EXAMPLE.COM")

    def test_multi_pattern_parse(self) -> None:
        al = Allowlist.parse("claude.ai, *.claude.ai, chatgpt.com")
        assert al.allows("claude.ai")
        assert al.allows("api.claude.ai")
        assert al.allows("chatgpt.com")
        assert not al.allows("claude.com")

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            Allowlist([])
        with pytest.raises(ValueError):
            Allowlist(["", "   "])

    def test_empty_host_never_matches(self) -> None:
        al = Allowlist(["*"])
        assert not al.allows("")
