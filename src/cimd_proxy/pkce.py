# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""PKCE (RFC 7636) helpers.

The proxy performs two PKCE flows:

* Between the client and the proxy: the client sends its ``code_challenge`` at
  ``/authorize`` and later its ``code_verifier`` at ``/token``. The proxy
  verifies the pair itself (never forwards).
* Between the proxy and the upstream: the proxy generates its own pair, sends
  the ``code_challenge`` to Keycloak, and hands the ``code_verifier`` back at
  the upstream token exchange.
"""

from __future__ import annotations

import base64
import hashlib
import secrets

_S256 = "S256"


def make_verifier(length: int = 64) -> str:
    """Return a PKCE ``code_verifier`` (RFC 7636 §4.1)."""

    if length < 43 or length > 128:
        raise ValueError("PKCE verifier length must be between 43 and 128")
    # token_urlsafe returns ~1.3 characters per byte; over-generate then trim.
    raw = secrets.token_urlsafe(96)
    return raw[:length]


def derive_challenge(verifier: str) -> str:
    """Return ``BASE64URL(SHA256(verifier))`` (unpadded)."""

    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify_challenge(verifier: str, challenge: str) -> bool:
    """Constant-time comparison of ``derive_challenge(verifier)`` and ``challenge``."""

    computed = derive_challenge(verifier)
    return secrets.compare_digest(computed, challenge)


def method() -> str:
    return _S256
