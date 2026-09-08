# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""RFC 8414 discovery document (also served at ``/.well-known/openid-configuration``).

``registration_endpoint`` is emitted when the DCR route is enabled — the proxy
speaks both sides at once: an https-URL ``client_id`` goes the CIMD route,
``client_id_metadata_document_supported: true`` still announces it, and a
posted DCR registration goes the RFC 7591 route.

``scopes_supported`` is fed from configuration (``PROXY_SCOPES_SUPPORTED``).
An empty configured value omits the field entirely rather than shipping an
empty array — an empty array would announce that the server supports no
scope at all, which is a different statement.
"""

from __future__ import annotations

from typing import Any


def build_discovery_document(
    public_url: str,
    *,
    scopes_supported: tuple[str, ...] = (),
    registration_endpoint: bool = False,
) -> dict[str, Any]:
    base = public_url.rstrip("/")
    doc: dict[str, Any] = {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "client_id_metadata_document_supported": True,
        "authorization_response_iss_parameter_supported": True,
    }
    if scopes_supported:
        doc["scopes_supported"] = list(scopes_supported)
    if registration_endpoint:
        doc["registration_endpoint"] = f"{base}/register"
    return doc
