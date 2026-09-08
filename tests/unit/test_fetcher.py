# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import socket

import pytest

from cimd_proxy.fetcher import (
    DocumentInvalid,
    SSRFRefused,
    parse_client_id_url,
    resolve_and_check_ips,
    validate_document,
)


class TestParseClientIdUrl:
    def test_valid(self) -> None:
        parsed = parse_client_id_url("https://claude.ai/mcp")
        assert parsed.hostname == "claude.ai"
        assert parsed.path == "/mcp"
        assert parsed.port == 443
        assert parsed.authority == "claude.ai"

    def test_non_https_refused(self) -> None:
        with pytest.raises(SSRFRefused):
            parse_client_id_url("http://claude.ai/x")

    def test_userinfo_refused(self) -> None:
        with pytest.raises(SSRFRefused):
            parse_client_id_url("https://user:pw@claude.ai/x")

    def test_fragment_refused(self) -> None:
        with pytest.raises(SSRFRefused):
            parse_client_id_url("https://claude.ai/x#frag")

    def test_empty_path_refused(self) -> None:
        with pytest.raises(SSRFRefused):
            parse_client_id_url("https://claude.ai")
        with pytest.raises(SSRFRefused):
            parse_client_id_url("https://claude.ai/")

    def test_non_default_port_authority(self) -> None:
        parsed = parse_client_id_url("https://claude.ai:8443/x")
        assert parsed.port == 8443
        assert parsed.authority == "claude.ai:8443"


class TestResolveAndCheckIps:
    @staticmethod
    def _fake_getaddrinfo(addrs: list[str]):
        def _fn(host: str, port, family=0, type=0, proto=0, flags=0):  # noqa: A002
            infos = []
            for a in addrs:
                fam = socket.AF_INET6 if ":" in a else socket.AF_INET
                sockaddr = (a, port or 0) if fam == socket.AF_INET else (a, port or 0, 0, 0)
                infos.append((fam, socket.SOCK_STREAM, 6, "", sockaddr))
            return infos

        return _fn

    def test_public_ip_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(socket, "getaddrinfo", self._fake_getaddrinfo(["8.8.8.8"]))
        assert resolve_and_check_ips("dns.google") == ["8.8.8.8"]

    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",  # loopback
            "10.1.2.3",  # private
            "192.168.1.1",  # private
            "169.254.1.1",  # link-local
            "0.0.0.0",  # unspecified
            "224.0.0.1",  # multicast
            "::1",  # loopback (v6)
            "fe80::1",  # link-local (v6)
        ],
    )
    def test_bad_ip_refused(self, monkeypatch: pytest.MonkeyPatch, ip: str) -> None:
        monkeypatch.setattr(socket, "getaddrinfo", self._fake_getaddrinfo([ip]))
        with pytest.raises(SSRFRefused):
            resolve_and_check_ips("evil.example")

    def test_one_bad_taint_fails_whole_lookup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Mixed A record: one safe (8.8.8.8), one loopback → the whole lookup fails.
        monkeypatch.setattr(socket, "getaddrinfo", self._fake_getaddrinfo(["8.8.8.8", "127.0.0.1"]))
        with pytest.raises(SSRFRefused):
            resolve_and_check_ips("mixed.example")

    def test_gaierror_maps_to_ssrf_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(*_a, **_k):
            raise socket.gaierror(8, "not found")

        monkeypatch.setattr(socket, "getaddrinfo", _boom)
        with pytest.raises(SSRFRefused):
            resolve_and_check_ips("noresolve.example")


class TestValidateDocument:
    def _min_doc(self, url: str) -> dict:
        return {
            "client_id": url,
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
        }

    def test_valid_document(self) -> None:
        url = "https://claude.ai/mcp"
        doc = validate_document(url, self._min_doc(url))
        assert doc.client_id == url
        assert doc.redirect_uris == ("https://claude.ai/api/mcp/auth_callback",)

    def test_client_id_mismatch_refused(self) -> None:
        with pytest.raises(DocumentInvalid, match="does not match"):
            validate_document(
                "https://claude.ai/mcp",
                {"client_id": "https://claude.ai/other", "redirect_uris": ["r"]},
            )

    def test_client_secret_forbidden(self) -> None:
        url = "https://claude.ai/mcp"
        doc = self._min_doc(url)
        doc["client_secret"] = "shhh"
        with pytest.raises(DocumentInvalid, match="client_secret"):
            validate_document(url, doc)

    def test_shared_secret_auth_method_forbidden(self) -> None:
        url = "https://claude.ai/mcp"
        doc = self._min_doc(url)
        doc["token_endpoint_auth_method"] = "client_secret_basic"
        with pytest.raises(DocumentInvalid, match="shared symmetric secret"):
            validate_document(url, doc)

    def test_missing_redirect_uris_refused(self) -> None:
        with pytest.raises(DocumentInvalid, match="redirect_uris"):
            validate_document("https://claude.ai/mcp", {"client_id": "https://claude.ai/mcp"})

    def test_empty_redirect_uri_refused(self) -> None:
        with pytest.raises(DocumentInvalid):
            validate_document(
                "https://claude.ai/mcp",
                {"client_id": "https://claude.ai/mcp", "redirect_uris": [""]},
            )

    def test_non_object_refused(self) -> None:
        with pytest.raises(DocumentInvalid):
            validate_document("https://claude.ai/mcp", ["not", "an", "object"])  # type: ignore[arg-type]
