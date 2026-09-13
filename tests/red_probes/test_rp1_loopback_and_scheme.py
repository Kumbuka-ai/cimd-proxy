# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""RP1 — Loopback allowance and non-loopback http rejection (RFC 8252 §7.3 / §8.3).

Four gates measured here, each with an observed red state:

* **loopback allowance** — ``http://127.0.0.1:<port>`` (and ``[::1]``)
  registers 201. Neuter the loopback branch, and it flips to 400.
* **port-agnostic loopback match** — a DCR registration on
  ``http://127.0.0.1:51580`` accepts a request that arrives on
  ``http://127.0.0.1:43127`` (RFC 8252 §8.3). Neuter the port-agnostic
  matcher (fall back to byte-equality), and it flips to 400.
* **non-loopback http rejection** — ``http://evil.example/callback`` is
  rejected with ``invalid_redirect_uri``. Neuter the scheme guard, and
  it is admitted with 201.
* **localhost-name rejection** — ``http://localhost:51580/callback`` is
  rejected even though the port and path would otherwise be valid.
  Neuter the loopback-literal check, and it is admitted with 201.

Each ``bypass_would_break_*`` control is ``xfail(strict=True)`` so a future
change that quietly makes the bypass pass again turns the test suite red.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import pytest
from starlette.testclient import TestClient

from cimd_proxy import authorize as _authorize_mod
from cimd_proxy import redirect_uri as _redirect_uri_mod
from cimd_proxy.envelope import EnvelopeCodec, RegistrationEnvelope

# ---------------------------------------------------------------------------
# Loopback allowance — /register admits http://127.0.0.1:<port>/callback
# ---------------------------------------------------------------------------


class TestRP1LoopbackAllowance:
    def test_guarded_admits(self, client: TestClient) -> None:
        r = client.post(
            "/register",
            json={"redirect_uris": ["http://127.0.0.1:51580/callback"]},
        )
        assert r.status_code == 201, r.text

    def test_bypass_rejects(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        # Neuter the loopback allowance: pretend nothing is a loopback IP
        # literal, so the scheme check falls through to the http-not-permitted
        # branch and returns 400.
        monkeypatch.setattr(_redirect_uri_mod, "_LOOPBACK_LITERALS", frozenset())
        r = client.post(
            "/register",
            json={"redirect_uris": ["http://127.0.0.1:51580/callback"]},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_redirect_uri"

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "RP1 loopback-allowance red control: with the loopback branch "
            "removed, the 201 assertion no longer holds — this is the "
            "observed red state of the RFC 8252 §7.3 allowance."
        ),
    )
    def test_bypass_would_break_allowance(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(_redirect_uri_mod, "_LOOPBACK_LITERALS", frozenset())
        r = client.post(
            "/register",
            json={"redirect_uris": ["http://127.0.0.1:51580/callback"]},
        )
        assert r.status_code == 201


# ---------------------------------------------------------------------------
# Port-agnostic loopback match at /authorize step 4 (RFC 8252 §8.3)
# ---------------------------------------------------------------------------


def _make_dcr_client_id(config, *redirect_uris: str) -> str:
    codec = EnvelopeCodec.from_key_string(config.secret_key)
    envelope = RegistrationEnvelope(
        redirect_uris=tuple(redirect_uris),
        token_endpoint_auth_method="none",
        client_id_issued_at=int(time.time()),
        client_name="Native",
    )
    return codec.pack_registration(envelope)


def _authz_params(client_id: str, redirect_uri: str) -> dict[str, str]:
    return {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": "chal-abcdefghijklmnopqrstuvwx",
        "code_challenge_method": "S256",
        "state": "s",
        "resource": "https://log.example",
        "scope": "openid",
    }


class TestRP1PortAgnosticLoopback:
    def test_guarded_admits(self, client: TestClient, config) -> None:
        cid = _make_dcr_client_id(config, "http://127.0.0.1:51580/callback")
        r = client.get(
            "/authorize",
            params=_authz_params(cid, "http://127.0.0.1:43127/callback"),
            follow_redirects=False,
        )
        assert r.status_code == 302, r.text

    def test_bypass_rejects(
        self, client: TestClient, config, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Neuter the port-agnostic matcher: fall back to strict byte equality.
        # A registration on :51580 then no longer accepts :43127.
        monkeypatch.setattr(_authorize_mod, "uri_matches_registration", lambda a, b: a == b)
        cid = _make_dcr_client_id(config, "http://127.0.0.1:51580/callback")
        r = client.get(
            "/authorize",
            params=_authz_params(cid, "http://127.0.0.1:43127/callback"),
        )
        assert r.status_code == 400
        assert "redirect_uri" in r.text

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "RP1 port-agnostic red control: with the matcher reduced to "
            "byte equality, the 302 assertion no longer holds — this is "
            "the observed red state of the RFC 8252 §8.3 relaxation."
        ),
    )
    def test_bypass_would_break_match(
        self, client: TestClient, config, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(_authorize_mod, "uri_matches_registration", lambda a, b: a == b)
        cid = _make_dcr_client_id(config, "http://127.0.0.1:51580/callback")
        r = client.get(
            "/authorize",
            params=_authz_params(cid, "http://127.0.0.1:43127/callback"),
            follow_redirects=False,
        )
        assert r.status_code == 302


# ---------------------------------------------------------------------------
# Non-loopback http rejection — /register refuses http on a public host
# ---------------------------------------------------------------------------


class TestRP1NonLoopbackHttpRejection:
    def test_guarded_rejects(self, client: TestClient) -> None:
        r = client.post(
            "/register",
            json={"redirect_uris": ["http://evil.example/callback"]},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_redirect_uri"

    def test_bypass_admits(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        # Neuter the scheme guard entirely — every URI is admitted. Patch
        # both the source module AND the name the register module imported,
        # since register.py did `from .redirect_uri import accept_registered`
        # at module load and holds its own binding.
        monkeypatch.setattr(_redirect_uri_mod, "accept_registered", lambda uri: None)
        monkeypatch.setattr("cimd_proxy.register.accept_registered", lambda uri: None)
        r = client.post(
            "/register",
            json={"redirect_uris": ["http://evil.example/callback"]},
        )
        assert r.status_code == 201

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "RP1 non-loopback-http red control: with accept_registered "
            "neutered, the 400 assertion no longer holds — this is the "
            "observed red state of the http-rejection gate."
        ),
    )
    def test_bypass_would_break_rejection(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(_redirect_uri_mod, "accept_registered", lambda uri: None)
        monkeypatch.setattr("cimd_proxy.register.accept_registered", lambda uri: None)
        r = client.post(
            "/register",
            json={"redirect_uris": ["http://evil.example/callback"]},
        )
        assert r.status_code == 400


# ---------------------------------------------------------------------------
# localhost-name rejection — RFC 8252 §8.3 prefers the IP literal
# ---------------------------------------------------------------------------


class TestRP1LocalhostRejection:
    def test_guarded_rejects(self, client: TestClient) -> None:
        r = client.post(
            "/register",
            json={"redirect_uris": ["http://localhost:51580/callback"]},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_redirect_uri"

    def test_bypass_admits(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        # Extend the loopback set to include the DNS name 'localhost'; the
        # http scheme check then passes.
        monkeypatch.setattr(
            _redirect_uri_mod,
            "_LOOPBACK_LITERALS",
            frozenset({"127.0.0.1", "::1", "localhost"}),
        )
        r = client.post(
            "/register",
            json={"redirect_uris": ["http://localhost:51580/callback"]},
        )
        assert r.status_code == 201

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "RP1 localhost-name red control: with 'localhost' added to the "
            "loopback set, the 400 assertion no longer holds — this is the "
            "observed red state of the DNS-name rejection."
        ),
    )
    def test_bypass_would_break_rejection(
        self,
        app_factory: Callable[..., object],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            _redirect_uri_mod,
            "_LOOPBACK_LITERALS",
            frozenset({"127.0.0.1", "::1", "localhost"}),
        )
        app = app_factory()
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.post(
            "/register",
            json={"redirect_uris": ["http://localhost:51580/callback"]},
        )
        assert r.status_code == 400
