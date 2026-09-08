# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlparse

from starlette.testclient import TestClient

from cimd_proxy.envelope import AuthorizeEnvelope, EnvelopeCodec


def _seed_state(codec: EnvelopeCodec) -> tuple[str, AuthorizeEnvelope]:
    env = AuthorizeEnvelope(
        correlation_id="cid-1",
        client_id="https://claude.ai/mcp",
        redirect_uri="https://claude.ai/api/mcp/auth_callback",
        state="orig-state",
        resource="https://log.example",
        client_code_challenge="chal",
        upstream_verifier="v-abc",
        scope="openid",
        exp=int(time.time()) + 600,
    )
    return codec.pack_authorize(env), env


class TestCallback:
    def test_success_returns_code_and_iss(self, client: TestClient, app, config) -> None:
        codec = EnvelopeCodec.from_key_string(config.secret_key)
        state, env = _seed_state(codec)
        r = client.get(
            "/callback", params={"code": "upstream-code", "state": state}, follow_redirects=False
        )
        assert r.status_code == 302
        loc = urlparse(r.headers["location"])
        actual_redirect = f"https://{loc.netloc}{loc.path}"
        assert actual_redirect == env.redirect_uri
        q = {k: v[0] for k, v in parse_qs(loc.query).items()}
        assert q["iss"] == config.public_url
        assert q["state"] == env.state
        assert "code" in q
        # The code returned to the client is a fresh CodeEnvelope, NOT the raw upstream code
        assert q["code"] != "upstream-code"
        opened = codec.open_code(q["code"])
        assert opened.upstream_code == "upstream-code"
        assert opened.correlation_id == env.correlation_id

    def test_missing_state_refused(self, client: TestClient) -> None:
        r = client.get("/callback", params={"code": "x"})
        assert r.status_code == 400
        assert "state" in r.text

    def test_invalid_state_refused(self, client: TestClient) -> None:
        r = client.get("/callback", params={"code": "x", "state": "not-a-fernet-token"})
        assert r.status_code == 400
        assert "invalid_request" in r.text

    def test_upstream_error_passed_through(self, client: TestClient, app, config) -> None:
        codec = EnvelopeCodec.from_key_string(config.secret_key)
        state, env = _seed_state(codec)
        r = client.get(
            "/callback",
            params={"error": "access_denied", "state": state},
            follow_redirects=False,
        )
        assert r.status_code == 302
        loc = urlparse(r.headers["location"])
        q = {k: v[0] for k, v in parse_qs(loc.query).items()}
        assert q["error"] == "access_denied"
        assert q["state"] == env.state
        assert q["iss"] == config.public_url
