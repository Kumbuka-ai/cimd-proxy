# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""OAuth 2.1 error codes and typed exceptions.

The proxy fails errors as loudly as OAuth permits: at `/authorize` we can either
render an error page or redirect to `redirect_uri` (only after `redirect_uri`
has itself been validated); at `/token` we return an OAuth error JSON body.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class OAuthError(Exception):
    """Base class for OAuth errors reported at either endpoint.

    ``error`` is one of the codes defined in RFC 6749 §4.1.2.1 / §5.2 or the
    codes registered by later profiles (RFC 6750, RFC 8628, OAuth 2.1).
    """

    error: str
    description: str
    status_code: int = 400

    def as_dict(self) -> dict[str, str]:
        return {"error": self.error, "error_description": self.description}

    def __str__(self) -> str:  # pragma: no cover - repr-only path
        return f"{self.error}: {self.description}"


class InvalidRequest(OAuthError):
    def __init__(self, description: str) -> None:
        super().__init__(error="invalid_request", description=description, status_code=400)


class InvalidTarget(OAuthError):
    def __init__(self, description: str) -> None:
        super().__init__(error="invalid_target", description=description, status_code=400)


class InvalidClient(OAuthError):
    def __init__(self, description: str, status_code: int = 400) -> None:
        super().__init__(error="invalid_client", description=description, status_code=status_code)


class UnauthorizedClient(OAuthError):
    def __init__(self, description: str) -> None:
        super().__init__(error="unauthorized_client", description=description, status_code=400)


class InvalidGrant(OAuthError):
    def __init__(self, description: str) -> None:
        super().__init__(error="invalid_grant", description=description, status_code=400)


class ServerError(OAuthError):
    def __init__(self, description: str) -> None:
        super().__init__(error="server_error", description=description, status_code=502)


class TemporarilyUnavailable(OAuthError):
    def __init__(self, description: str) -> None:
        super().__init__(error="temporarily_unavailable", description=description, status_code=503)
