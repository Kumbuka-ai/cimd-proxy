# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""POST /register — RFC 7591 dynamic client registration.

Structural checks for the endpoint: happy path with a minimal body; refusals
that map to ``invalid_client_metadata`` / ``invalid_redirect_uri``; and a
round-trip that opens the returned ``client_id`` envelope.
"""

from __future__ import annotations

from collections.abc import Callable

from starlette.testclient import TestClient

from cimd_proxy.envelope import EnvelopeCodec, RegistrationEnvelope


class TestRegisterHappyPath:
    def test_minimal_body_registers(self, client: TestClient, config) -> None:
        body = {
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
            "token_endpoint_auth_method": "none",
            "client_name": "Claude",
        }
        r = client.post("/register", json=body)
        assert r.status_code == 201, r.text
        payload = r.json()
        assert payload["redirect_uris"] == body["redirect_uris"]
        assert payload["token_endpoint_auth_method"] == "none"
        assert payload["client_name"] == "Claude"
        assert "client_secret" not in payload  # public clients only
        assert payload["grant_types"] == ["authorization_code", "refresh_token"]
        assert payload["response_types"] == ["code"]
        assert isinstance(payload["client_id_issued_at"], int)
        assert payload["client_id_issued_at"] > 0
        # The client_id round-trips as a RegistrationEnvelope.
        codec = EnvelopeCodec.from_key_string(config.secret_key)
        opened = codec.open_registration(payload["client_id"])
        assert isinstance(opened, RegistrationEnvelope)
        assert opened.redirect_uris == tuple(body["redirect_uris"])
        assert opened.token_endpoint_auth_method == "none"
        assert opened.client_name == "Claude"

    def test_omitted_auth_method_defaults_to_none(self, client: TestClient) -> None:
        body = {"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]}
        r = client.post("/register", json=body)
        assert r.status_code == 201, r.text
        assert r.json()["token_endpoint_auth_method"] == "none"


class TestRegisterRefusals:
    def test_missing_redirect_uris(self, client: TestClient) -> None:
        r = client.post("/register", json={})
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_redirect_uri"

    def test_empty_redirect_uris(self, client: TestClient) -> None:
        r = client.post("/register", json={"redirect_uris": []})
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_redirect_uri"

    def test_non_https_redirect(self, client: TestClient) -> None:
        r = client.post("/register", json={"redirect_uris": ["http://claude.ai/cb"]})
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_redirect_uri"

    def test_redirect_host_off_allowlist(self, app_factory: Callable[..., object]) -> None:
        app = app_factory(CIMD_ALLOWED_DOMAINS="claude.ai,*.claude.ai")
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.post("/register", json={"redirect_uris": ["https://evil.example/cb"]})
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_redirect_uri"
        assert "evil.example" in r.json()["error_description"]

    def test_client_secret_not_accepted(self, client: TestClient) -> None:
        r = client.post(
            "/register",
            json={
                "redirect_uris": ["https://claude.ai/cb"],
                "client_secret": "hunter2",
            },
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_client_metadata"

    def test_symmetric_auth_method_refused(self, client: TestClient) -> None:
        for method in ("client_secret_post", "client_secret_basic", "client_secret_jwt"):
            r = client.post(
                "/register",
                json={
                    "redirect_uris": ["https://claude.ai/cb"],
                    "token_endpoint_auth_method": method,
                },
            )
            assert r.status_code == 400, method
            assert r.json()["error"] == "invalid_client_metadata"

    def test_asymmetric_auth_method_also_refused(self, client: TestClient) -> None:
        # RFC 7591 lists more values, but the proxy supports only ``none``.
        r = client.post(
            "/register",
            json={
                "redirect_uris": ["https://claude.ai/cb"],
                "token_endpoint_auth_method": "private_key_jwt",
            },
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_client_metadata"

    def test_body_not_json(self, client: TestClient) -> None:
        r = client.post(
            "/register", content=b"not json", headers={"content-type": "application/json"}
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_client_metadata"

    def test_body_not_object(self, client: TestClient) -> None:
        r = client.post("/register", json=["not", "an", "object"])
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_client_metadata"
