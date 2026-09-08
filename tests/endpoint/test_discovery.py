# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable

from starlette.testclient import TestClient


class TestDiscovery:
    def test_rfc8414_shape(self, client: TestClient) -> None:
        r = client.get("/.well-known/oauth-authorization-server")
        assert r.status_code == 200
        doc = r.json()
        assert doc["issuer"] == "https://mcp-auth.example"
        assert doc["authorization_endpoint"] == "https://mcp-auth.example/authorize"
        assert doc["token_endpoint"] == "https://mcp-auth.example/token"
        assert doc["response_types_supported"] == ["code"]
        assert doc["grant_types_supported"] == ["authorization_code", "refresh_token"]
        assert doc["code_challenge_methods_supported"] == ["S256"]
        assert doc["client_id_metadata_document_supported"] is True
        assert doc["authorization_response_iss_parameter_supported"] is True
        # RFC 8414 §2 — scopes_supported names which scopes the server will honour.
        # The DEFAULT env (from conftest.base_env, absent PROXY_SCOPES_SUPPORTED)
        # falls back to the shipped default: "openid offline_access".
        assert doc["scopes_supported"] == ["openid", "offline_access"]
        # RFC 7591 §3 — registration_endpoint announces the DCR route.
        assert doc["registration_endpoint"] == "https://mcp-auth.example/register"

    def test_openid_alias(self, client: TestClient) -> None:
        a = client.get("/.well-known/oauth-authorization-server").json()
        b = client.get("/.well-known/openid-configuration").json()
        assert a == b

    def test_healthz(self, client: TestClient) -> None:
        r = client.get("/healthz")
        assert r.status_code == 200
        assert r.text == "ok"


class TestScopesSupportedFromConfig:
    def test_explicit_override(self, app_factory: Callable[..., object]) -> None:
        app = app_factory(PROXY_SCOPES_SUPPORTED="openid profile email")
        client = TestClient(app)  # type: ignore[arg-type]
        doc = client.get("/.well-known/oauth-authorization-server").json()
        assert doc["scopes_supported"] == ["openid", "profile", "email"]

    def test_empty_omits_field(self, app_factory: Callable[..., object]) -> None:
        # An empty configured value MUST omit the field entirely — a leaked
        # empty array would claim the server supports no scope at all, which
        # is a different statement than "the operator chose to say nothing".
        app = app_factory(PROXY_SCOPES_SUPPORTED="")
        client = TestClient(app)  # type: ignore[arg-type]
        doc = client.get("/.well-known/oauth-authorization-server").json()
        assert "scopes_supported" not in doc

    def test_whitespace_only_omits_field(self, app_factory: Callable[..., object]) -> None:
        # Same statement as empty — whitespace collapses to nothing.
        app = app_factory(PROXY_SCOPES_SUPPORTED="   \t\n  ")
        client = TestClient(app)  # type: ignore[arg-type]
        doc = client.get("/.well-known/oauth-authorization-server").json()
        assert "scopes_supported" not in doc
