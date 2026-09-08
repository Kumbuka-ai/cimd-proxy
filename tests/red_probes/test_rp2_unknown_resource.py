# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""RP2 — Unknown resource.

A ``resource`` value that is not in the RESOURCE_n table is rejected with
``invalid_target``. A missing ``resource`` value is likewise rejected, unless
``DEFAULT_RESOURCE`` names an entry.

The red-probe pair for the *unknown* variant:

* ``guarded_rejects_unknown``: RESOURCE_n table holds only
  ``https://log.example``; request with ``resource=https://unknown.example``
  → 400 invalid_target.
* ``bypass_admits_when_table_extended``: RESOURCE_n table now includes
  ``https://unknown.example``; the same request → 302 (upstream).
* ``bypass_would_break_rejection_gate``: xfail(strict=True).

The red-probe pair for the *missing* variant:

* ``guarded_rejects_missing``: no ``resource`` param, DEFAULT_RESOURCE is
  empty → 400 invalid_target.
* ``bypass_admits_when_default_set``: no ``resource`` param, DEFAULT_RESOURCE
  set → 302 (upstream).
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from starlette.testclient import TestClient

from ..helpers import install_fake_fetcher, valid_document

_CLIENT_ID = "https://claude.ai/mcp"
_REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"


def _params(**overrides: str) -> dict[str, str]:
    params = {
        "response_type": "code",
        "client_id": _CLIENT_ID,
        "redirect_uri": _REDIRECT_URI,
        "code_challenge": "chal-abcdefghijklmnopqrstuvwx",
        "code_challenge_method": "S256",
        "state": "s",
        "scope": "openid",
    }
    params.update(overrides)
    return params


class TestRP2UnknownResource:
    def test_guarded_rejects_unknown(self, app_factory: Callable[..., object]) -> None:
        app = app_factory()
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.get("/authorize", params=_params(resource="https://unknown.example"))
        assert r.status_code == 400
        assert "invalid_target" in r.text

    def test_bypass_admits_when_table_extended(self, app_factory: Callable[..., object]) -> None:
        app = app_factory(
            RESOURCE_1_URL="https://unknown.example",
            RESOURCE_1_ISSUER="https://issuer.example/realms/x",
            RESOURCE_1_CLIENT_ID="unknown-mcp",
        )
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.get(
            "/authorize",
            params=_params(resource="https://unknown.example"),
            follow_redirects=False,
        )
        assert r.status_code == 302, r.text

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "RP2 red control: with the resource added to the table the "
            "rejection assertion no longer holds — this is the observed red "
            "state of the resource gate."
        ),
    )
    def test_bypass_would_break_rejection_gate(self, app_factory: Callable[..., object]) -> None:
        app = app_factory(
            RESOURCE_1_URL="https://unknown.example",
            RESOURCE_1_ISSUER="https://issuer.example/realms/x",
            RESOURCE_1_CLIENT_ID="unknown-mcp",
        )
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        client = TestClient(app)  # type: ignore[arg-type]
        # follow_redirects=False so the failure lands as "302 == 400" and not
        # as an unrelated 404 from the follow-up to the upstream host.
        r = client.get(
            "/authorize",
            params=_params(resource="https://unknown.example"),
            follow_redirects=False,
        )
        assert r.status_code == 400
        assert "invalid_target" in r.text


class TestRP2MissingResource:
    def test_guarded_rejects_missing(self, app_factory: Callable[..., object]) -> None:
        app = app_factory()  # DEFAULT_RESOURCE stays empty
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.get("/authorize", params=_params())
        assert r.status_code == 400
        assert "invalid_target" in r.text

    def test_bypass_admits_when_default_set(self, app_factory: Callable[..., object]) -> None:
        app = app_factory(DEFAULT_RESOURCE="https://log.example")
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.get("/authorize", params=_params(), follow_redirects=False)
        assert r.status_code == 302, r.text
