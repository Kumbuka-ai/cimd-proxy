# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""End-to-end flow against a fake OIDC provider running in-process.

Exercises /authorize → upstream authorize → /callback → /token → refresh
along BOTH registration routes:

* the CIMD route, where ``client_id`` is an https URL and the proxy resolves
  the metadata by fetch;
* the DCR route, where ``client_id`` is a Fernet ``RegistrationEnvelope``
  minted at ``/register`` and the proxy opens it directly.

The upstream is mocked with respx; the fake provider is a plain callable
that behaves like Keycloak's authorize endpoint (returns a 302 to the
client's redirect_uri with a fresh code). Both routes must arrive at the
same round-trip shape — same upstream client_id, same envelope on the
state, same Fernet-hidden upstream refresh_token in the /token response.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from httpx import Response
from starlette.testclient import TestClient

from cimd_proxy.envelope import EnvelopeCodec
from cimd_proxy.pkce import derive_challenge, make_verifier

from ..helpers import install_fake_fetcher, valid_document

_UPSTREAM_AUTHZ = "https://issuer.example/realms/x/protocol/openid-connect/auth"
_UPSTREAM_TOKEN = "https://issuer.example/realms/x/protocol/openid-connect/token"

_CLIENT_ID = "https://claude.ai/mcp"
_REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"


@pytest.mark.e2e
@respx.mock
def test_full_flow(client: TestClient, app, config) -> None:
    install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
    codec = EnvelopeCodec.from_key_string(config.secret_key)
    verifier = make_verifier()
    challenge = derive_challenge(verifier)

    # 1. Client hits /authorize; proxy sends us to Keycloak (mocked).
    r1 = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": _CLIENT_ID,
            "redirect_uri": _REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "opaque-state",
            "resource": "https://log.example",
            "scope": "openid",
        },
        follow_redirects=False,
    )
    assert r1.status_code == 302
    upstream = urlparse(r1.headers["location"])
    assert f"https://{upstream.netloc}{upstream.path}" == _UPSTREAM_AUTHZ
    upstream_qs = {k: v[0] for k, v in parse_qs(upstream.query).items()}
    upstream_state = upstream_qs["state"]  # our AuthorizeEnvelope

    # 2. Simulate Keycloak returning to the proxy's /callback with a code.
    r2 = client.get(
        "/callback",
        params={"code": "kc-upstream-code", "state": upstream_state},
        follow_redirects=False,
    )
    assert r2.status_code == 302
    client_redirect = urlparse(r2.headers["location"])
    assert f"https://{client_redirect.netloc}{client_redirect.path}" == _REDIRECT_URI
    client_qs = {k: v[0] for k, v in parse_qs(client_redirect.query).items()}
    assert client_qs["iss"] == config.public_url  # RFC 9207 / MCP SEP-2468
    assert client_qs["state"] == "opaque-state"
    client_code = client_qs["code"]
    assert client_code != "kc-upstream-code"  # freshly enveloped, not passed through

    # 3. Client exchanges the code at /token; proxy calls Keycloak's token endpoint (mocked).
    respx.post(_UPSTREAM_TOKEN).mock(
        return_value=Response(
            200,
            json={
                "access_token": "eyJ.first-jwt.payload",
                "refresh_token": "kc-refresh-1",
                "expires_in": 300,
                "token_type": "Bearer",
                "scope": "openid",
            },
        )
    )
    r3 = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": client_code,
            "code_verifier": verifier,
            "redirect_uri": _REDIRECT_URI,
            "client_id": _CLIENT_ID,
        },
    )
    assert r3.status_code == 200
    body = r3.json()
    assert body["access_token"] == "eyJ.first-jwt.payload"
    assert body["refresh_token"] != "kc-refresh-1"  # enveloped
    opened = codec.open_refresh(body["refresh_token"])
    assert opened.upstream_refresh_token == "kc-refresh-1"
    assert opened.resource == "https://log.example"

    # 4. Client refreshes; proxy calls Keycloak again, returns a new envelope.
    respx.post(_UPSTREAM_TOKEN).mock(
        return_value=Response(
            200,
            json={
                "access_token": "eyJ.second-jwt.payload",
                "refresh_token": "kc-refresh-2",
                "expires_in": 300,
                "token_type": "Bearer",
            },
        )
    )
    r4 = client.post(
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": body["refresh_token"]},
    )
    assert r4.status_code == 200
    body2 = r4.json()
    assert body2["access_token"] == "eyJ.second-jwt.payload"
    opened2 = codec.open_refresh(body2["refresh_token"])
    assert opened2.upstream_refresh_token == "kc-refresh-2"
    assert opened2.resource == "https://log.example"

    # 5. The Fernet envelope hides the raw upstream refresh token from the
    #    client — Assert that "kc-refresh-2" appears nowhere in the returned
    #    body once the envelope is in place.
    assert "kc-refresh-2" not in r4.text
    assert re.search(r"eyJ\.second-jwt\.payload", r4.text)


@pytest.mark.e2e
@respx.mock
def test_full_flow_dcr(client: TestClient, config) -> None:
    """Same round-trip through the DCR route rather than CIMD.

    The client registers via ``POST /register``, then presents the returned
    ``client_id`` (a Fernet envelope) at ``/authorize``. The proxy opens the
    envelope, checks ``redirect_uri`` against the sealed ``redirect_uris``,
    and drives the same upstream flow as the CIMD test.
    """
    verifier = make_verifier()
    challenge = derive_challenge(verifier)

    # 1. Register.
    r0 = client.post(
        "/register",
        json={
            "redirect_uris": [_REDIRECT_URI],
            "token_endpoint_auth_method": "none",
            "client_name": "Claude",
        },
    )
    assert r0.status_code == 201, r0.text
    dcr_client_id = r0.json()["client_id"]

    # 2. /authorize with the enveloped client_id.
    r1 = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": dcr_client_id,
            "redirect_uri": _REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "opaque-state",
            "resource": "https://log.example",
            "scope": "openid",
        },
        follow_redirects=False,
    )
    assert r1.status_code == 302
    upstream = urlparse(r1.headers["location"])
    assert f"https://{upstream.netloc}{upstream.path}" == _UPSTREAM_AUTHZ
    upstream_state = {k: v[0] for k, v in parse_qs(upstream.query).items()}["state"]

    # 3. Fake Keycloak returns a code to /callback.
    r2 = client.get(
        "/callback",
        params={"code": "kc-upstream-dcr-code", "state": upstream_state},
        follow_redirects=False,
    )
    assert r2.status_code == 302
    client_redirect = urlparse(r2.headers["location"])
    assert f"https://{client_redirect.netloc}{client_redirect.path}" == _REDIRECT_URI
    client_code = {k: v[0] for k, v in parse_qs(client_redirect.query).items()}["code"]
    assert client_code != "kc-upstream-dcr-code"  # enveloped, not passed through

    # 4. /token — proxy calls Keycloak; envelope hides the upstream refresh.
    respx.post(_UPSTREAM_TOKEN).mock(
        return_value=Response(
            200,
            json={
                "access_token": "eyJ.dcr-jwt.payload",
                "refresh_token": "kc-refresh-dcr",
                "expires_in": 300,
                "token_type": "Bearer",
                "scope": "openid",
            },
        )
    )
    r3 = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": client_code,
            "code_verifier": verifier,
            "redirect_uri": _REDIRECT_URI,
            "client_id": dcr_client_id,
        },
    )
    assert r3.status_code == 200, r3.text
    body = r3.json()
    assert body["access_token"] == "eyJ.dcr-jwt.payload"
    assert body["refresh_token"] != "kc-refresh-dcr"
    codec = EnvelopeCodec.from_key_string(config.secret_key)
    opened = codec.open_refresh(body["refresh_token"])
    assert opened.upstream_refresh_token == "kc-refresh-dcr"
    assert opened.resource == "https://log.example"
    # The upstream refresh token must not leak into the client-facing body.
    assert "kc-refresh-dcr" not in r3.text
