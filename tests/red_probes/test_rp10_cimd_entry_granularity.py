# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""RP10 — A CIMD entry that fails the redirect_uri shape check is dropped, not the document.

A document that lists ``http://example.com/cb`` next to
``https://app.example/cb`` stays usable for the https entry; the http entry is
dropped and can never pass ``/authorize`` step 4. Refer to
:func:`cimd_proxy.fetcher.validate_document`.

* ``guarded_admits``: ``/authorize`` with the kept entry reaches the upstream
  (302).
* ``bypass_rejects``: the filter replaced by the former all-or-nothing loop —
  the first failing entry refuses the whole document, 400 invalid_client.
* ``bypass_would_break_admission``: xfail(strict=True).
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from cimd_proxy import fetcher as _fetcher_mod
from cimd_proxy.redirect_uri import RedirectUriRefused, accept_registered

from ..helpers import install_fake_fetcher, valid_document

_CLIENT_ID = "https://claude.ai/mcp"
_KEPT = "https://app.example/cb"
_DROPPED = "http://example.com/cb"


def _params() -> dict[str, str]:
    return {
        "response_type": "code",
        "client_id": _CLIENT_ID,
        "redirect_uri": _KEPT,
        "code_challenge": "chal-abcdefghijklmnopqrstuvwx",
        "code_challenge_method": "S256",
        "state": "s",
        "resource": "https://log.example",
        "scope": "openid",
    }


def _all_or_nothing(redirect_uris: list[str]) -> tuple[str, ...]:
    """The rule before entries were filtered: the first failing entry refuses."""

    for uri in redirect_uris:
        try:
            accept_registered(uri)
        except RedirectUriRefused as exc:
            raise _fetcher_mod.DocumentInvalid(str(exc)) from exc
    return tuple(redirect_uris)


class TestRP10EntryGranularity:
    def test_guarded_admits(self, client: TestClient, app) -> None:
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _DROPPED, _KEPT))
        r = client.get("/authorize", params=_params(), follow_redirects=False)
        assert r.status_code == 302, r.text

    def test_bypass_rejects(
        self, client: TestClient, app, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(_fetcher_mod, "_usable_redirect_uris", _all_or_nothing)
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _DROPPED, _KEPT))
        r = client.get("/authorize", params=_params(), follow_redirects=False)
        assert r.status_code == 400
        assert "error=invalid_client" in r.text

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "RP10 red control: with the all-or-nothing loop back in place, "
            "the 302 assertion no longer holds."
        ),
    )
    def test_bypass_would_break_admission(
        self, client: TestClient, app, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(_fetcher_mod, "_usable_redirect_uris", _all_or_nothing)
        install_fake_fetcher(app, valid_document(_CLIENT_ID, _DROPPED, _KEPT))
        r = client.get("/authorize", params=_params(), follow_redirects=False)
        assert r.status_code == 302
