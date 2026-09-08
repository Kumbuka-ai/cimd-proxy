# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""RP1 — Allowlist.

A client_id whose host is not on ``CIMD_ALLOWED_DOMAINS`` is rejected at
``/authorize`` with ``invalid_client``.

The red-probe pair:

* ``guarded_rejects``: allowlist = ``claude.ai,*.claude.ai``; the request
  carrying ``client_id`` from ``evil.example`` is rejected with 400
  ``invalid_client`` — the guard is what stops it.
* ``bypass_admits``: allowlist = ``*``; the exact same request reaches the
  upstream (302). This proves the guard is what mattered.
* ``bypass_would_break_rejection_gate``: xfail(strict=True) — with the guard
  neutered, the "guarded" assertion no longer holds. This is the observed red
  state of the gate.
"""

from __future__ import annotations

import socket
from collections.abc import Callable

import pytest
from starlette.testclient import TestClient

from ..helpers import install_fake_fetcher, resolver_returning, valid_document

_CLIENT_ID = "https://evil.example/mcp"
_REDIRECT_URI = "https://evil.example/cb"


@pytest.fixture(autouse=True)
def _stub_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give evil.example a benign TEST-NET-3 address so RP1 measures only the allowlist.

    Without this stub the SSRF guard would reject the request first (evil.example
    does not resolve at all), and the "bypass" run would be blocked by the wrong
    guard — defeating the purpose of RP1.
    """

    # Public unicast IP that passes every ipaddress zone check on Python 3.13,
    # so RP1 is measuring only the allowlist gate — not the SSRF gate.
    monkeypatch.setattr(socket, "getaddrinfo", resolver_returning(["8.8.8.8"]))


def _params(**overrides: str) -> dict[str, str]:
    params = {
        "response_type": "code",
        "client_id": _CLIENT_ID,
        "redirect_uri": _REDIRECT_URI,
        "code_challenge": "chal-abcdefghijklmnopqrstuvwx",
        "code_challenge_method": "S256",
        "state": "s",
        "resource": "https://log.example",
        "scope": "openid",
    }
    params.update(overrides)
    return params


class TestRP1Allowlist:
    def test_guarded_rejects(self, app_factory: Callable[..., object]) -> None:
        app = app_factory(CIMD_ALLOWED_DOMAINS="claude.ai,*.claude.ai")
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.get("/authorize", params=_params())
        assert r.status_code == 400
        assert "invalid_client" in r.text

    def test_bypass_admits(self, app_factory: Callable[..., object]) -> None:
        app = app_factory(CIMD_ALLOWED_DOMAINS="*")
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.get("/authorize", params=_params(), follow_redirects=False)
        assert r.status_code == 302, r.text
        assert r.headers["location"].startswith("https://issuer.example/")

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "RP1 red control: with the allowlist opened to '*' the rejection "
            "assertion no longer holds — this is the observed red state of "
            "the allowlist gate."
        ),
    )
    def test_bypass_would_break_rejection_gate(self, app_factory: Callable[..., object]) -> None:
        app = app_factory(CIMD_ALLOWED_DOMAINS="*")
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        client = TestClient(app)  # type: ignore[arg-type]
        # follow_redirects=False so the failure lands as "302 == 400" and not
        # as an unrelated 404 from the follow-up to the upstream host.
        r = client.get("/authorize", params=_params(), follow_redirects=False)
        assert r.status_code == 400
        assert "invalid_client" in r.text
