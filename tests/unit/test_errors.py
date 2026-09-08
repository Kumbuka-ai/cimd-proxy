# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from cimd_proxy.errors import (
    InvalidClient,
    InvalidGrant,
    InvalidRequest,
    InvalidTarget,
    OAuthError,
    ServerError,
    TemporarilyUnavailable,
    UnauthorizedClient,
)


class TestOAuthErrors:
    def test_shape(self) -> None:
        e = InvalidTarget("no such resource")
        assert e.error == "invalid_target"
        assert e.status_code == 400
        assert e.as_dict() == {
            "error": "invalid_target",
            "error_description": "no such resource",
        }

    def test_hierarchy(self) -> None:
        assert issubclass(InvalidRequest, OAuthError)
        assert issubclass(InvalidTarget, OAuthError)
        assert issubclass(InvalidClient, OAuthError)
        assert issubclass(UnauthorizedClient, OAuthError)
        assert issubclass(InvalidGrant, OAuthError)
        assert issubclass(ServerError, OAuthError)
        assert issubclass(TemporarilyUnavailable, OAuthError)

    def test_server_and_temp_are_5xx(self) -> None:
        assert ServerError("boom").status_code == 502
        assert TemporarilyUnavailable("later").status_code == 503
