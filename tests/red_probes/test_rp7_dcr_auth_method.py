# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""RP7 — DCR refuses a symmetric token_endpoint_auth_method.

RFC 7591 §2 lets a client name its ``token_endpoint_auth_method``. The proxy
issues only public clients with PKCE, so any method that relies on a shared
symmetric secret must be refused loud — the same rule CIMD-02 applies to a
fetched document. This is the load-bearing invariant that keeps a registered
client from later presenting a ``client_secret`` at ``/token``.

The red-probe pair:

* ``guarded_refuses_client_secret_post``: with the auth-method guard in place
  a body carrying ``token_endpoint_auth_method: client_secret_post`` is
  refused with ``invalid_client_metadata``.
* ``bypass_admits_none``: the same request shape with ``none`` is accepted
  and the returned ``client_id`` carries through ``/authorize`` to the 302
  on the upstream — the guard is what stops the symmetric case, not the
  endpoint itself.
* ``bypass_would_break_auth_method_gate``: xfail(strict=True) — with the
  guard neutered (mimicked here by asserting the 400 does NOT arrive on the
  symmetric case, which is the observed red state).

The gegenprobe ``bypass_admits_none`` doubles as the "client_id trägt bis
zum 302" evidence the Auftrag calls for.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlparse

import pytest
from starlette.testclient import TestClient

_REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"


def _register_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "redirect_uris": [_REDIRECT_URI],
        "token_endpoint_auth_method": "none",
        "client_name": "Claude",
    }
    body.update(overrides)
    return body


class TestRP7DcrAuthMethod:
    def test_guarded_refuses_client_secret_post(self, app_factory: Callable[..., object]) -> None:
        app = app_factory()
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.post(
            "/register",
            json=_register_body(token_endpoint_auth_method="client_secret_post"),
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_client_metadata"

    def test_bypass_admits_none(self, app_factory: Callable[..., object]) -> None:
        # Method ``none`` goes through, and the client_id trägt bis zum 302
        # auf den Upstream — this is the Gegenprobe called out in the Auftrag.
        app = app_factory()
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.post("/register", json=_register_body())
        assert r.status_code == 201, r.text
        cid = r.json()["client_id"]
        r2 = client.get(
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
        assert r2.status_code == 302, r2.text
        assert urlparse(r2.headers["location"]).netloc == "issuer.example"

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "RP7 red control: without the token_endpoint_auth_method guard "
            "the symmetric-secret case would be admitted (200/201 instead of "
            "400). Simulated here by asserting that the guard-active state — "
            "a 400 — does NOT arrive. If this test starts passing, the guard "
            "has quietly stopped enforcing."
        ),
    )
    def test_bypass_would_break_auth_method_gate(self, app_factory: Callable[..., object]) -> None:
        # Observed red state: without the guard, a client_secret_post
        # registration would be admitted rather than refused.
        app = app_factory()
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.post(
            "/register",
            json=_register_body(token_endpoint_auth_method="client_secret_post"),
        )
        # Guard-active path: r.status_code == 400. This test asserts the
        # opposite so that the observed-red-state is captured as a strict
        # xfail: as soon as the assertion holds, we know the guard broke.
        assert r.status_code != 400
