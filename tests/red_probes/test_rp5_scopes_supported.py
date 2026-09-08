# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""RP5 — the proxy announces its scopes.

The discovery document (RFC 8414 §2) carries ``scopes_supported`` from the
configured value ``PROXY_SCOPES_SUPPORTED``; a client that does not see a
scope announced there will not request it. The v0.1.0 proxy did not emit the
field at all — measured against production 2026-09-06 — and Keycloak's own
answer to "no scope in the request" was to omit ``offline_access``, so the
refresh tokens ended up bound to the SSO session.

The red-probe pair:

* ``guarded_announces``: with ``PROXY_SCOPES_SUPPORTED="openid offline_access"``
  the discovery document carries ``offline_access`` in ``scopes_supported`` —
  the announcement is what a client would read to know it may ask for it.
* ``bypass_omits``: with ``PROXY_SCOPES_SUPPORTED=""`` the whole field is
  gone from the document — a client that consults the announcement finds
  nothing announced.
* ``bypass_would_break_announcement_gate``: xfail(strict=True) — with the
  configured value emptied, the ``offline_access`` assertion no longer holds.
  This is the observed red state of the gate.

The gegenprobe is spelled out separately: an empty configured value MUST
omit the field entirely rather than ship an empty array. An empty array is a
statement ("no scope is supported"); an absent field is silence.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from starlette.testclient import TestClient


class TestRP5ScopesSupported:
    def test_guarded_announces(self, app_factory: Callable[..., object]) -> None:
        app = app_factory(PROXY_SCOPES_SUPPORTED="openid offline_access")
        client = TestClient(app)  # type: ignore[arg-type]
        doc = client.get("/.well-known/oauth-authorization-server").json()
        assert "offline_access" in doc["scopes_supported"]

    def test_bypass_omits(self, app_factory: Callable[..., object]) -> None:
        app = app_factory(PROXY_SCOPES_SUPPORTED="")
        client = TestClient(app)  # type: ignore[arg-type]
        doc = client.get("/.well-known/oauth-authorization-server").json()
        assert "scopes_supported" not in doc

    def test_bypass_does_not_ship_empty_array(self, app_factory: Callable[..., object]) -> None:
        # Gegenprobe: an empty configured value MUST omit the field, not
        # ship an empty ``scopes_supported: []`` array. The two statements
        # are not the same and must not be conflated.
        app = app_factory(PROXY_SCOPES_SUPPORTED="")
        client = TestClient(app)  # type: ignore[arg-type]
        doc = client.get("/.well-known/oauth-authorization-server").json()
        assert doc.get("scopes_supported") != []

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "RP5 red control: with PROXY_SCOPES_SUPPORTED emptied, the "
            "announcement assertion no longer holds — this is the observed "
            "red state of the announcement gate."
        ),
    )
    def test_bypass_would_break_announcement_gate(self, app_factory: Callable[..., object]) -> None:
        app = app_factory(PROXY_SCOPES_SUPPORTED="")
        client = TestClient(app)  # type: ignore[arg-type]
        doc = client.get("/.well-known/oauth-authorization-server").json()
        assert "offline_access" in doc["scopes_supported"]
