# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlparse

import pytest
from starlette.testclient import TestClient

from cimd_proxy.envelope import AuthorizeEnvelope, EnvelopeCodec, RegistrationEnvelope

from ..helpers import install_fake_fetcher, valid_document

_CLIENT_ID = "https://claude.ai/mcp"
_REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"


def _authorize_params(**overrides: str) -> dict[str, str]:
    params = {
        "response_type": "code",
        "client_id": _CLIENT_ID,
        "redirect_uri": _REDIRECT_URI,
        "code_challenge": "challenge-abcdefghijklmnopqrstuvwx",
        "code_challenge_method": "S256",
        "state": "opaque-state",
        "resource": "https://log.example",
        "scope": "openid",
    }
    params.update(overrides)
    return params


class TestAuthorizeMissing:
    @pytest.mark.parametrize(
        "drop", ["response_type", "client_id", "redirect_uri", "code_challenge"]
    )
    def test_missing_required(self, client: TestClient, app, drop: str) -> None:
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        params = _authorize_params()
        params.pop(drop)
        r = client.get("/authorize", params=params)
        assert r.status_code == 400
        assert "invalid_request" in r.text


class TestAuthorizeBadResource:
    def test_missing_resource_no_default(self, client: TestClient, app) -> None:
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        params = _authorize_params()
        params.pop("resource")
        r = client.get("/authorize", params=params)
        assert r.status_code == 400
        assert "invalid_target" in r.text

    def test_unknown_resource(self, client: TestClient, app) -> None:
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        params = _authorize_params(resource="https://unknown.example")
        r = client.get("/authorize", params=params)
        assert r.status_code == 400
        assert "invalid_target" in r.text


class TestAuthorizeResourceTrailingSlash:
    """RFC 3986 §6.2.3 tolerance on the requested resource URI.

    The RESOURCE_n table stores ``https://log.example`` — no trailing slash,
    because ``_load_resources`` rstrips it. A client that sends the RFC-3986
    canonical form ``https://log.example/`` (empty path folded to ``/``) is
    naming the same resource and must reach the upstream. Anything beyond a
    root-only trailing slash — a longer path, a case fold — is a different
    identifier and stays refused.
    """

    def test_trailing_slash_on_root_is_tolerated(self, client: TestClient, app) -> None:
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        r = client.get(
            "/authorize",
            params=_authorize_params(resource="https://log.example/"),
            follow_redirects=False,
        )
        assert r.status_code == 302, r.text
        loc = urlparse(r.headers["location"])
        assert loc.netloc == "issuer.example"

    def test_exact_table_form_still_admitted(self, client: TestClient, app) -> None:
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        r = client.get(
            "/authorize",
            params=_authorize_params(resource="https://log.example"),
            follow_redirects=False,
        )
        assert r.status_code == 302, r.text

    def test_extra_path_still_refused(self, client: TestClient, app) -> None:
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        r = client.get("/authorize", params=_authorize_params(resource="https://log.example/foo"))
        assert r.status_code == 400
        assert "invalid_target" in r.text

    def test_case_not_folded(self, client: TestClient, app) -> None:
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        r = client.get("/authorize", params=_authorize_params(resource="https://LOG.example"))
        assert r.status_code == 400
        assert "invalid_target" in r.text

    def test_upstream_state_carries_table_url_not_client_url(
        self, client: TestClient, app, config
    ) -> None:
        # The authorize envelope is packed with entry.url (the table form) even
        # when the client sent the trailing-slash form. That is how a refresh
        # envelope issued today opens against the table tomorrow — and how a
        # v0.2.0 envelope, packed with the same rule, keeps opening under
        # v0.2.1.
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        r = client.get(
            "/authorize",
            params=_authorize_params(resource="https://log.example/"),
            follow_redirects=False,
        )
        assert r.status_code == 302
        q = {k: v[0] for k, v in parse_qs(urlparse(r.headers["location"]).query).items()}
        codec = EnvelopeCodec.from_key_string(config.secret_key)
        opened = codec.open_authorize(q["state"])
        assert opened.resource == "https://log.example"


class TestAuthorizePkceMethod:
    def test_plain_refused(self, client: TestClient, app) -> None:
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        r = client.get("/authorize", params=_authorize_params(code_challenge_method="plain"))
        assert r.status_code == 400
        assert "invalid_request" in r.text


class TestAuthorizeRedirectUriExact:
    def test_missing_from_document_refused(self, client: TestClient, app) -> None:
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        r = client.get(
            "/authorize",
            params=_authorize_params(redirect_uri="https://claude.ai/api/mcp/auth_callback/"),
        )
        assert r.status_code == 400
        assert "redirect_uri" in r.text

    def test_case_and_port_are_not_normalised(self, client: TestClient, app) -> None:
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        r = client.get(
            "/authorize",
            params=_authorize_params(redirect_uri="https://claude.ai:443/api/mcp/auth_callback"),
        )
        assert r.status_code == 400
        assert "redirect_uri" in r.text


class TestAuthorizeHappyPath:
    def test_redirects_to_upstream_with_envelope_state(
        self, client: TestClient, app, config
    ) -> None:
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        r = client.get("/authorize", params=_authorize_params(), follow_redirects=False)
        assert r.status_code == 302
        loc = urlparse(r.headers["location"])
        assert loc.scheme == "https"
        assert loc.netloc == "issuer.example"
        assert loc.path == "/realms/x/protocol/openid-connect/auth"
        q = {k: v[0] for k, v in parse_qs(loc.query).items()}
        assert q["response_type"] == "code"
        assert q["client_id"] == "log-mcp"  # upstream client id, not the CIMD URL
        assert q["redirect_uri"] == "https://mcp-auth.example/callback"
        assert q["code_challenge_method"] == "S256"
        # state must be a Fernet envelope opening to our sealed AuthorizeEnvelope
        codec = EnvelopeCodec.from_key_string(config.secret_key)
        opened = codec.open_authorize(q["state"])
        assert isinstance(opened, AuthorizeEnvelope)
        assert opened.client_id == _CLIENT_ID
        assert opened.redirect_uri == _REDIRECT_URI
        assert opened.resource == "https://log.example"
        assert opened.state == "opaque-state"


class TestAuthorizeScope:
    def test_client_scope_reaches_upstream_unchanged(self, client: TestClient, app) -> None:
        # A request that carries ``scope`` reaches the upstream with EXACTLY
        # that scope. The proxy fills silence with a configured default; it
        # never appends to a client's request.
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        r = client.get(
            "/authorize", params=_authorize_params(scope="openid"), follow_redirects=False
        )
        assert r.status_code == 302
        q = {k: v[0] for k, v in parse_qs(urlparse(r.headers["location"]).query).items()}
        assert q["scope"] == "openid"

    def test_missing_scope_uses_configured_default(
        self, app_factory, client: TestClient, app
    ) -> None:
        # The DEFAULT env (from conftest, no PROXY_DEFAULT_SCOPE) falls back
        # to the shipped default "openid offline_access".
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        params = _authorize_params()
        params.pop("scope")
        r = client.get("/authorize", params=params, follow_redirects=False)
        assert r.status_code == 302
        q = {k: v[0] for k, v in parse_qs(urlparse(r.headers["location"]).query).items()}
        assert q["scope"] == "openid offline_access"

    def test_missing_scope_respects_configured_override(self, app_factory) -> None:
        app = app_factory(PROXY_DEFAULT_SCOPE="openid profile email")
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        client = TestClient(app)  # type: ignore[arg-type]
        params = _authorize_params()
        params.pop("scope")
        r = client.get("/authorize", params=params, follow_redirects=False)
        assert r.status_code == 302
        q = {k: v[0] for k, v in parse_qs(urlparse(r.headers["location"]).query).items()}
        assert q["scope"] == "openid profile email"

    def test_client_scope_beats_configured_default(self, app_factory) -> None:
        # Even with a fat default configured, a client that asks for less
        # gets less. The proxy does not append to a client's request.
        app = app_factory(PROXY_DEFAULT_SCOPE="openid offline_access profile")
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.get(
            "/authorize", params=_authorize_params(scope="openid"), follow_redirects=False
        )
        assert r.status_code == 302
        q = {k: v[0] for k, v in parse_qs(urlparse(r.headers["location"]).query).items()}
        assert q["scope"] == "openid"

    def test_forwarded_log_carries_via(self, client: TestClient, app, caplog) -> None:
        # authorize.forwarded carries ``via`` so an operator reading the log
        # can tell a CIMD hit from a DCR hit.
        import logging

        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        with caplog.at_level(logging.INFO, logger="cimd_proxy.authorize"):
            r = client.get("/authorize", params=_authorize_params(), follow_redirects=False)
        assert r.status_code == 302
        forwarded = [
            rec
            for rec in caplog.records
            if isinstance(rec.msg, dict) and rec.msg.get("event") == "authorize.forwarded"
        ]
        assert forwarded, "expected an authorize.forwarded log record"
        assert forwarded[0].msg.get("via") == "cimd"

    def test_forwarded_log_carries_scope(self, client: TestClient, app, caplog) -> None:
        # authorize.forwarded MUST carry the chosen scope — that log line is
        # the diagnostic that closed the earlier round-trip through the Caddy
        # access log. Without it the operator cannot see what the proxy sent.
        import logging

        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        with caplog.at_level(logging.INFO, logger="cimd_proxy.authorize"):
            r = client.get("/authorize", params=_authorize_params(), follow_redirects=False)
        assert r.status_code == 302
        forwarded = [
            rec
            for rec in caplog.records
            if getattr(rec, "event", None) == "authorize.forwarded"
            or (isinstance(rec.msg, dict) and rec.msg.get("event") == "authorize.forwarded")
        ]
        assert forwarded, "expected an authorize.forwarded log record"
        payload = forwarded[0].msg if isinstance(forwarded[0].msg, dict) else vars(forwarded[0])
        assert payload.get("scope") == "openid"


class TestAuthorizeDcrRoute:
    """A ``client_id`` that opens as a RegistrationEnvelope drives the DCR route.

    The upstream request shape is identical to the CIMD route — same upstream
    ``client_id``, same envelope-in-state — and the only externally visible
    difference is the ``via`` field on ``authorize.forwarded``. That is the
    whole point of the second route: same wire, second registration protocol.
    """

    def _make_client_id(self, config, *redirect_uris: str) -> str:
        codec = EnvelopeCodec.from_key_string(config.secret_key)
        envelope = RegistrationEnvelope(
            redirect_uris=tuple(redirect_uris),
            token_endpoint_auth_method="none",
            client_id_issued_at=int(time.time()),
            client_name="Claude",
        )
        return codec.pack_registration(envelope)

    def test_dcr_client_id_redirects_to_upstream(self, client: TestClient, app, config) -> None:
        cid = self._make_client_id(config, _REDIRECT_URI)
        r = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": cid,
                "redirect_uri": _REDIRECT_URI,
                "code_challenge": "chal-abcdefghijklmnopqrstuvwx",
                "code_challenge_method": "S256",
                "state": "s",
                "resource": "https://log.example",
                "scope": "openid",
            },
            follow_redirects=False,
        )
        assert r.status_code == 302, r.text
        loc = urlparse(r.headers["location"])
        assert loc.netloc == "issuer.example"

    def test_dcr_redirect_uri_off_registration_refused(
        self, client: TestClient, app, config
    ) -> None:
        # The registered ``redirect_uris`` do not include the one the client
        # tries — refuse without redirecting, same class of refusal as CIMD.
        cid = self._make_client_id(config, "https://claude.ai/some/other/cb")
        r = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": cid,
                "redirect_uri": _REDIRECT_URI,
                "code_challenge": "chal-abcdefghijklmnopqrstuvwx",
                "code_challenge_method": "S256",
                "state": "s",
                "resource": "https://log.example",
                "scope": "openid",
            },
            follow_redirects=False,
        )
        assert r.status_code == 400
        assert "redirect_uri" in r.text

    def test_neither_url_nor_envelope_refused(self, client: TestClient) -> None:
        # A client_id that is neither a https URL nor a valid envelope is
        # refused typed — this is the "alles andere" case from the Auftrag.
        r = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "not-a-url-not-an-envelope",
                "redirect_uri": _REDIRECT_URI,
                "code_challenge": "chal-abcdefghijklmnopqrstuvwx",
                "code_challenge_method": "S256",
                "state": "s",
                "resource": "https://log.example",
                "scope": "openid",
            },
        )
        assert r.status_code == 400
        assert "invalid_client" in r.text

    def test_sibling_envelope_refused(self, client: TestClient, config) -> None:
        # A refresh envelope presented in the client_id slot must NOT unpack —
        # the tag field on every envelope is what stops it.
        from cimd_proxy.envelope import RefreshEnvelope

        codec = EnvelopeCodec.from_key_string(config.secret_key)
        rt = codec.pack_refresh(RefreshEnvelope(resource="r", upstream_refresh_token="x"))
        r = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": rt,
                "redirect_uri": _REDIRECT_URI,
                "code_challenge": "chal-abcdefghijklmnopqrstuvwx",
                "code_challenge_method": "S256",
                "state": "s",
                "resource": "https://log.example",
                "scope": "openid",
            },
        )
        assert r.status_code == 400
        assert "invalid_client" in r.text
