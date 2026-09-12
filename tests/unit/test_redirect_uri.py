# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for :mod:`cimd_proxy.redirect_uri` — the RFC 8252 §7.3/§8.3 rule."""

from __future__ import annotations

import pytest

from cimd_proxy.redirect_uri import (
    RedirectUriRefused,
    accept_registered,
    uri_matches_registration,
)


class TestAcceptRegistered:
    @pytest.mark.parametrize(
        "uri",
        [
            "https://claude.ai/api/mcp/auth_callback",
            "https://beliebige-fremde-domain.example/cb",
            "http://127.0.0.1:51580/callback",
            "http://127.0.0.1:43127/callback",
            "http://127.0.0.1/callback",
            "http://[::1]:51580/callback",
        ],
    )
    def test_admits(self, uri: str) -> None:
        accept_registered(uri)  # does not raise

    @pytest.mark.parametrize(
        "uri",
        [
            "http://evil.example/callback",
            "http://example.com/cb",
            "http://localhost:51580/callback",
            "http://127.0.0.2:51580/callback",  # loopback net but not the pinned literal
            "https://example.com/cb#frag",
            "https://user:pw@example.com/cb",
            "https://user@example.com/cb",
            "https:///no-host",
            "ftp://example.com/cb",
            "https:no-slash-no-host",
        ],
    )
    def test_refuses(self, uri: str) -> None:
        with pytest.raises(RedirectUriRefused):
            accept_registered(uri)


class TestUriMatchesRegistration:
    def test_byte_equal(self) -> None:
        assert uri_matches_registration(
            "https://claude.ai/cb", "https://claude.ai/cb"
        )

    def test_https_port_still_strict(self) -> None:
        # The loopback relaxation is scheme+host-scoped; https keeps byte-equal.
        assert not uri_matches_registration(
            "https://claude.ai:443/cb", "https://claude.ai/cb"
        )

    def test_loopback_port_agnostic(self) -> None:
        assert uri_matches_registration(
            "http://127.0.0.1:43127/callback", "http://127.0.0.1:51580/callback"
        )

    def test_loopback_ipv6_port_agnostic(self) -> None:
        assert uri_matches_registration(
            "http://[::1]:43127/callback", "http://[::1]:51580/callback"
        )

    def test_loopback_family_must_match(self) -> None:
        # 127.0.0.1 vs [::1] are different hosts even though both are loopback.
        assert not uri_matches_registration(
            "http://[::1]:51580/callback", "http://127.0.0.1:51580/callback"
        )

    def test_loopback_path_must_match(self) -> None:
        assert not uri_matches_registration(
            "http://127.0.0.1:43127/other", "http://127.0.0.1:51580/callback"
        )

    def test_loopback_query_must_match(self) -> None:
        assert not uri_matches_registration(
            "http://127.0.0.1:43127/cb?a=1", "http://127.0.0.1:51580/cb"
        )

    def test_fragment_never_matches(self) -> None:
        assert not uri_matches_registration(
            "http://127.0.0.1:43127/cb#f", "http://127.0.0.1:51580/cb"
        )

    def test_userinfo_never_matches(self) -> None:
        assert not uri_matches_registration(
            "http://u@127.0.0.1:43127/cb", "http://127.0.0.1:51580/cb"
        )

    def test_loopback_scheme_must_be_http(self) -> None:
        assert not uri_matches_registration(
            "https://127.0.0.1:51580/callback", "http://127.0.0.1:51580/callback"
        )
