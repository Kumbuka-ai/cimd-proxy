# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""RP4 — SSRF.

A ``client_id`` whose hostname resolves to a loopback or otherwise reserved
address (RFC 6890) is refused **before** any HTTPS connection is opened.

* ``guarded_rejects``: ``socket.getaddrinfo`` returns 127.0.0.1 for the host
  → ``/authorize`` returns 400 invalid_client.
* ``bypass_admits``: :func:`cimd_proxy.fetcher.resolve_and_check_ips`
  monkey-patched to return a benign IP and skip the guards → the request
  reaches the upstream (302).
* ``bypass_would_break_rejection_gate``: xfail(strict=True).

RP4 is a specific addition over the earlier design because the follow-on
costs of *not* enforcing it are the highest of any probe. Do not skip.
"""

from __future__ import annotations

import socket
from collections.abc import Callable

import pytest
from starlette.testclient import TestClient

from cimd_proxy import fetcher as _fetcher_mod
from tests import helpers as _helpers

from ..helpers import install_fake_fetcher, resolver_returning, valid_document

# A hostname the tests will lie about the DNS resolution of; the string must
# be on the CIMD_ALLOWED_DOMAINS so the allowlist guard does not fire first.
_CLIENT_ID = "https://a.claude.ai/mcp"
_REDIRECT_URI = "https://claude.ai/cb"


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


class TestRP4Ssrf:
    def test_guarded_rejects(
        self, app_factory: Callable[..., object], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # DNS lies: the client_id's host resolves to 127.0.0.1.
        monkeypatch.setattr(socket, "getaddrinfo", resolver_returning(["127.0.0.1"]))
        app = app_factory()
        # FakeFetcher runs the real ``resolve_and_check_ips``, so the SSRF
        # guard is what triggers the rejection.
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.get("/authorize", params=_params())
        assert r.status_code == 400
        assert "invalid_client" in r.text

    def test_bypass_admits(
        self, app_factory: Callable[..., object], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # DNS still lies, but the guard is neutered — it accepts any address.
        monkeypatch.setattr(socket, "getaddrinfo", resolver_returning(["127.0.0.1"]))
        monkeypatch.setattr(
            _fetcher_mod,
            "resolve_and_check_ips",
            lambda host: ["203.0.113.1"],
        )
        # The helpers module holds its own reference — patch it too.
        monkeypatch.setattr(
            _helpers,
            "resolve_and_check_ips",
            lambda host: ["203.0.113.1"],
        )
        app = app_factory()
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.get("/authorize", params=_params(), follow_redirects=False)
        assert r.status_code == 302, r.text

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "RP4 red control: with the SSRF guard neutered, the rejection "
            "assertion no longer holds — this is the observed red state of "
            "the SSRF gate."
        ),
    )
    def test_bypass_would_break_rejection_gate(
        self, app_factory: Callable[..., object], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(socket, "getaddrinfo", resolver_returning(["127.0.0.1"]))
        monkeypatch.setattr(
            _fetcher_mod,
            "resolve_and_check_ips",
            lambda host: ["203.0.113.1"],
        )
        monkeypatch.setattr(
            _helpers,
            "resolve_and_check_ips",
            lambda host: ["203.0.113.1"],
        )
        app = app_factory()
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _REDIRECT_URI))
        client = TestClient(app)  # type: ignore[arg-type]
        # follow_redirects=False so the failure lands as "302 == 400" and not
        # as an unrelated 404 from the follow-up to the upstream host.
        r = client.get("/authorize", params=_params(), follow_redirects=False)
        assert r.status_code == 400
        assert "invalid_client" in r.text
