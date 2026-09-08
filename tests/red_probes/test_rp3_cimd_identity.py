# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""RP3 — Document identity.

A CIMD document whose ``client_id`` field is not byte-equal to the URL it was
fetched from is rejected. Refer to :mod:`cimd_proxy.fetcher.validate_document`.

* ``guarded_rejects``: fetcher returns a document whose ``client_id`` differs
  from the URL — ``/authorize`` returns 400 invalid_client.
* ``bypass_admits``: :func:`validate_document` monkey-patched to skip the
  identity check — the same call reaches the upstream (302).
* ``bypass_would_break_rejection_gate``: xfail(strict=True).
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from starlette.testclient import TestClient

from cimd_proxy import cimd_service as _cimd_service_mod
from cimd_proxy import fetcher as _fetcher_mod
from cimd_proxy.fetcher import CimdDocument

from ..helpers import install_fake_fetcher

_CLIENT_ID = "https://claude.ai/mcp"
_REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"

# Deliberate mismatch: document says a different client_id than the URL it
# came from. This is exactly what RP3 catches.
_MISMATCHED_DOC = {
    "client_id": "https://claude.ai/other",
    "redirect_uris": [_REDIRECT_URI],
    "token_endpoint_auth_method": "none",
}


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


def _neutered_validate_document(url: str, document: dict) -> CimdDocument:
    """Skip the identity check but leave the shape checks intact."""

    from cimd_proxy.fetcher import DocumentInvalid

    if not isinstance(document, dict):
        raise DocumentInvalid("not a dict")
    redirect_uris = document.get("redirect_uris") or []
    return CimdDocument(
        client_id=url,  # <-- lies: pretend the document identified itself as this URL
        redirect_uris=tuple(redirect_uris),
        raw=document,
        cache_control=None,
    )


class TestRP3CimdIdentity:
    def test_guarded_rejects(self, app_factory: Callable[..., object]) -> None:
        app = app_factory()
        install_fake_fetcher(app, _MISMATCHED_DOC)
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.get("/authorize", params=_params())
        assert r.status_code == 400
        assert "invalid_client" in r.text
        assert "does not match" in r.text

    def test_bypass_admits(
        self, app_factory: Callable[..., object], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Neuter the identity check both places it is imported from.
        monkeypatch.setattr(_fetcher_mod, "validate_document", _neutered_validate_document)
        monkeypatch.setattr(
            _cimd_service_mod, "validate_document", _neutered_validate_document, raising=False
        )
        # Also neuter the copy re-exported into the helpers module before it
        # is closed over by FakeFetcher.
        from tests import helpers as _h

        monkeypatch.setattr(_h, "validate_document", _neutered_validate_document)

        app = app_factory()
        install_fake_fetcher(app, _MISMATCHED_DOC)
        client = TestClient(app)  # type: ignore[arg-type]
        r = client.get("/authorize", params=_params(), follow_redirects=False)
        assert r.status_code == 302, r.text

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "RP3 red control: with the identity check neutered, the rejection "
            "assertion no longer holds — this is the observed red state of "
            "the CIMD identity gate."
        ),
    )
    def test_bypass_would_break_rejection_gate(
        self, app_factory: Callable[..., object], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(_fetcher_mod, "validate_document", _neutered_validate_document)
        monkeypatch.setattr(
            _cimd_service_mod, "validate_document", _neutered_validate_document, raising=False
        )
        from tests import helpers as _h

        monkeypatch.setattr(_h, "validate_document", _neutered_validate_document)

        app = app_factory()
        install_fake_fetcher(app, _MISMATCHED_DOC)
        client = TestClient(app)  # type: ignore[arg-type]
        # follow_redirects=False so the failure lands as "302 == 400" and not
        # as an unrelated 404 from the follow-up to the upstream host.
        r = client.get("/authorize", params=_params(), follow_redirects=False)
        assert r.status_code == 400
        assert "does not match" in r.text
