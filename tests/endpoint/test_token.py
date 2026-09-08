# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import time

import respx
from httpx import Response
from starlette.testclient import TestClient

from cimd_proxy.envelope import (
    CodeEnvelope,
    EnvelopeCodec,
    RefreshEnvelope,
)
from cimd_proxy.pkce import derive_challenge, make_verifier

_UPSTREAM_TOKEN = "https://issuer.example/realms/x/protocol/openid-connect/token"


def _fresh_code_envelope(
    codec: EnvelopeCodec, *, verifier: str, exp_offset: int = 60
) -> tuple[str, CodeEnvelope]:
    env = CodeEnvelope(
        correlation_id="cid-1",
        upstream_code="upstream-code",
        upstream_verifier="upstream-verifier",
        resource="https://log.example",
        client_id="https://claude.ai/mcp",
        client_code_challenge=derive_challenge(verifier),
        redirect_uri="https://claude.ai/api/mcp/auth_callback",
        exp=int(time.time()) + exp_offset,
    )
    return codec.pack_code(env), env


class TestTokenAuthCode:
    @respx.mock
    def test_happy_path_wraps_refresh_token(self, client: TestClient, config) -> None:
        codec = EnvelopeCodec.from_key_string(config.secret_key)
        verifier = make_verifier()
        code, _env = _fresh_code_envelope(codec, verifier=verifier)
        respx.post(_UPSTREAM_TOKEN).mock(
            return_value=Response(
                200,
                json={
                    "access_token": "eyJ.jwt.payload",
                    "refresh_token": "upstream-refresh",
                    "expires_in": 300,
                    "token_type": "Bearer",
                    "scope": "openid",
                },
            )
        )
        r = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "client_id": "https://claude.ai/mcp",
            },
        )
        assert r.status_code == 200
        body = r.json()
        # Access token untouched by the proxy
        assert body["access_token"] == "eyJ.jwt.payload"
        # Refresh token wrapped
        assert body["refresh_token"] != "upstream-refresh"
        opened = codec.open_refresh(body["refresh_token"])
        assert isinstance(opened, RefreshEnvelope)
        assert opened.upstream_refresh_token == "upstream-refresh"
        assert opened.resource == "https://log.example"

    def test_bad_pkce_verifier(self, client: TestClient, config) -> None:
        codec = EnvelopeCodec.from_key_string(config.secret_key)
        verifier = make_verifier()
        code, _env = _fresh_code_envelope(codec, verifier=verifier)
        r = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": "wrong-verifier-wrong-verifier-wrong-verifier-w",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "client_id": "https://claude.ai/mcp",
            },
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"

    def test_expired_code_envelope(self, client: TestClient, config) -> None:
        codec = EnvelopeCodec.from_key_string(config.secret_key)
        verifier = make_verifier()
        # Create envelope that expires in the past.
        code, _env = _fresh_code_envelope(codec, verifier=verifier, exp_offset=-5)
        r = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "client_id": "https://claude.ai/mcp",
            },
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"

    def test_garbled_code_refused(self, client: TestClient) -> None:
        r = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "not-a-fernet-token",
                "code_verifier": "whatever",
            },
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"

    def test_unknown_grant_refused(self, client: TestClient) -> None:
        r = client.post("/token", data={"grant_type": "client_credentials"})
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_request"


class TestTokenRefresh:
    @respx.mock
    def test_refresh_round_trip(self, client: TestClient, config) -> None:
        codec = EnvelopeCodec.from_key_string(config.secret_key)
        wrapped_refresh = codec.pack_refresh(
            RefreshEnvelope(
                resource="https://log.example", upstream_refresh_token="upstream-refresh"
            )
        )
        respx.post(_UPSTREAM_TOKEN).mock(
            return_value=Response(
                200,
                json={
                    "access_token": "new.jwt.payload",
                    "refresh_token": "new-upstream-refresh",
                    "expires_in": 300,
                    "token_type": "Bearer",
                },
            )
        )
        r = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": wrapped_refresh},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["access_token"] == "new.jwt.payload"
        opened = codec.open_refresh(body["refresh_token"])
        assert opened.upstream_refresh_token == "new-upstream-refresh"
        assert opened.resource == "https://log.example"

    def test_garbled_refresh_refused(self, client: TestClient) -> None:
        r = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": "not-a-fernet-token"},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"

    def test_missing_refresh_refused(self, client: TestClient) -> None:
        r = client.post("/token", data={"grant_type": "refresh_token"})
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_request"


@respx.mock
def test_upstream_error_passed_through(client: TestClient, config) -> None:
    codec = EnvelopeCodec.from_key_string(config.secret_key)
    verifier = make_verifier()
    code, _env = _fresh_code_envelope(codec, verifier=verifier)
    respx.post(_UPSTREAM_TOKEN).mock(
        return_value=Response(400, json={"error": "invalid_grant", "error_description": "no"})
    )
    r = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "client_id": "https://claude.ai/mcp",
        },
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"
