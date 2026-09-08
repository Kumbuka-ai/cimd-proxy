# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""RP6 — the proxy fills scope silence with offline_access by default.

Measured 2026-09-06 against the deployed v0.1.0 proxy: three /authorize hits
in the Caddy access log carried no ``scope=`` parameter at all, and Keycloak
answered with tokens bound to the SSO session (no refresh grant). The cause
was in ``authorize.py`` — the code fell back to ``"openid"`` when the client
omitted ``scope`` — and v0.2.0 lifts that default into ``PROXY_DEFAULT_SCOPE``
with a shipped value of ``openid offline_access``.

The red-probe pair:

* ``guarded_defaults``: with ``PROXY_DEFAULT_SCOPE="openid offline_access"``
  a request that omits ``scope`` reaches the upstream carrying
  ``scope=openid offline_access`` — the fill-in is what makes the difference.
* ``bypass_defaults_shrunk``: with ``PROXY_DEFAULT_SCOPE="openid"`` the same
  request reaches the upstream carrying only ``scope=openid``; the
  ``offline_access`` claim is gone. This is what the deployed proxy did.
* ``bypass_would_break_default_gate``: xfail(strict=True) — with the default
  shrunk to plain ``openid`` the ``offline_access`` assertion no longer
  holds. The observed red state of the gate.

The gegenprobe (separate test): a request that MITBRINGT ``scope=openid``
reaches the upstream with exactly ``openid`` — the configured default does
NOT override an anfordernden Client, it only fills silence.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import parse_qs, urlparse

import pytest
from starlette.testclient import TestClient

from ..helpers import install_fake_fetcher, valid_document

_CLIENT_ID = "https://claude.ai/mcp"
_REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"


def _params_without_scope() -> dict[str, str]:
    return {
        "response_type": "code",
        "client_id": _CLIENT_ID,
        "redirect_uri": _REDIRECT_URI,
        "code_challenge": "challenge-abcdefghijklmnopqrstuvwx",
        "code_challenge_method": "S256",
        "state": "s",
        "resource": "https://log.example",
    }


def _upstream_scope(location: str) -> str:
    q = {k: v[0] for k, v in parse_qs(urlparse(location).query).items()}
    return q["scope"]


class TestRP6DefaultScope:
    def test_guarded_defaults(self, app_factory: Callable[..., object]) -> None:
        app = app_factory(PROXY_DEFAULT_SCOPE="openid offline_access")
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.get("/authorize", params=_params_without_scope(), follow_redirects=False)
        assert r.status_code == 302, r.text
        assert _upstream_scope(r.headers["location"]) == "openid offline_access"

    def test_bypass_defaults_shrunk(self, app_factory: Callable[..., object]) -> None:
        app = app_factory(PROXY_DEFAULT_SCOPE="openid")
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.get("/authorize", params=_params_without_scope(), follow_redirects=False)
        assert r.status_code == 302, r.text
        assert _upstream_scope(r.headers["location"]) == "openid"

    def test_gegenprobe_client_scope_not_overridden(
        self, app_factory: Callable[..., object]
    ) -> None:
        # Gegenprobe: a request MIT ``scope=openid`` reaches the upstream
        # with exactly ``openid`` — the default does NOT extend an
        # anfordernden Client.
        app = app_factory(PROXY_DEFAULT_SCOPE="openid offline_access profile")
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        client = TestClient(app)  # type: ignore[arg-type]
        params = _params_without_scope()
        params["scope"] = "openid"
        r = client.get("/authorize", params=params, follow_redirects=False)
        assert r.status_code == 302, r.text
        assert _upstream_scope(r.headers["location"]) == "openid"

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "RP6 red control: with PROXY_DEFAULT_SCOPE shrunk to 'openid' "
            "the offline_access assertion no longer holds — this is the "
            "observed red state of the default-scope gate."
        ),
    )
    def test_bypass_would_break_default_gate(self, app_factory: Callable[..., object]) -> None:
        app = app_factory(PROXY_DEFAULT_SCOPE="openid")
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.get("/authorize", params=_params_without_scope(), follow_redirects=False)
        assert r.status_code == 302, r.text
        assert _upstream_scope(r.headers["location"]) == "openid offline_access"
