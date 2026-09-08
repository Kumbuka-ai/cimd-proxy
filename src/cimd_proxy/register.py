# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""POST /register — RFC 7591 dynamic client registration.

The proxy speaks both CIMD (draft-ietf-oauth-client-id-metadata-document) and
DCR (RFC 7591) at once. A client that reads the discovery document sees both
``client_id_metadata_document_supported: true`` and a ``registration_endpoint``;
either route ends at ``/authorize`` with the same ``client_id`` shape from the
proxy's own point of view — the disambiguation is whether ``client_id`` parses
as an https-URL (CIMD) or opens as a Fernet envelope (DCR).

The registration is stateless. A ``client_id`` handed back here is a Fernet
envelope carrying the registered metadata; a later ``/authorize`` opens it and
checks ``redirect_uri`` against the ``redirect_uris`` sealed inside. No
database, no in-memory table. That is why this file exists at all — variant 2
(the proxy issuing its own tokens) would need a signing key and a JWKS; DCR
needs neither because the metadata rides with the client.

Validation follows the same three constraints CIMD-02 sets on a fetched
document, because they name the same class of unsafe registration:

* ``redirect_uris`` present and non-empty (RFC 7591 §2, requirement for the
  authorization_code grant);
* no ``client_secret`` — the proxy issues only public clients with PKCE;
* no symmetric ``token_endpoint_auth_method`` (``client_secret_post``,
  ``client_secret_basic``, ``client_secret_jwt``) — same reason.

The ``client_id_issued_at`` is written on the server side, per §3.2.1. A
``client_secret`` is never emitted — the response omits it entirely rather than
carry it with a value the client would then try to use.

The Allowlist decision (Frame): a DCR client has no domain the proxy could pin
it to — it has only its ``redirect_uris``. We apply ``CIMD_ALLOWED_DOMAINS`` to
the hosts of every ``redirect_uri``, because that host is the one thing an
attacker cannot freely choose without losing the callback. A registration that
lists a host outside the allowlist is refused loud at ``/register``; there is
no "register now, discover the refusal at /authorize" path.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .allowlist import Allowlist
from .config import ProxyConfig
from .correlation import bind_correlation_id, new_correlation_id
from .envelope import EnvelopeCodec, RegistrationEnvelope
from .logging_setup import get_logger, sanitize

_LOG = get_logger("cimd_proxy.register")

_FORBIDDEN_AUTH_METHODS = frozenset(
    {"client_secret_post", "client_secret_basic", "client_secret_jwt"}
)


class _RegistrationError(Exception):
    """Raised for a client-caused refusal of a POST /register body.

    RFC 7591 §3.2.2 names the error codes; we mirror ``invalid_client_metadata``
    and ``invalid_redirect_uri`` so a client can distinguish the two.
    """

    def __init__(self, error: str, description: str, status_code: int = 400) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.status_code = status_code


router = APIRouter()


@router.post(
    "/register",
    responses={
        201: {"description": "Client registered; response body per RFC 7591 §3.2.1."},
        400: {
            "description": (
                "Registration refused (invalid_client_metadata / invalid_redirect_uri)."
            )
        },
    },
)
async def register(request: Request) -> JSONResponse:
    cid = new_correlation_id()
    bind_correlation_id(cid)

    config: ProxyConfig = request.app.state.config
    codec: EnvelopeCodec = request.app.state.envelope_codec

    try:
        payload = await _read_json(request)
        redirect_uris, auth_method, client_name = _validate(payload, config.allowlist)
    except _RegistrationError as exc:
        _LOG.warning(
            {
                "event": "register.rejected",
                "error": exc.error,
                "error_description": sanitize(exc.description),
            }
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.error, "error_description": exc.description},
        )

    issued_at = int(time.time())
    envelope = RegistrationEnvelope(
        redirect_uris=redirect_uris,
        token_endpoint_auth_method=auth_method,
        client_id_issued_at=issued_at,
        client_name=client_name,
    )
    client_id = codec.pack_registration(envelope)

    _LOG.info(
        {
            "event": "register.issued",
            "client_name": sanitize(client_name),
            "redirect_uri_count": len(redirect_uris),
        }
    )

    # RFC 7591 §3.2.1: echo the accepted metadata, add server-issued fields.
    body: dict[str, Any] = {
        "client_id": client_id,
        "client_id_issued_at": issued_at,
        "redirect_uris": list(redirect_uris),
        "token_endpoint_auth_method": auth_method,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    }
    if client_name:
        body["client_name"] = client_name
    return JSONResponse(status_code=201, content=body)


async def _read_json(request: Request) -> dict[str, Any]:
    try:
        data = await request.json()
    except ValueError as exc:
        # ``UnicodeDecodeError`` derives from ``ValueError`` — one catch covers both.
        raise _RegistrationError(
            "invalid_client_metadata", f"request body is not valid JSON: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise _RegistrationError("invalid_client_metadata", "request body must be a JSON object")
    return data


def _validate(payload: dict[str, Any], allowlist: Allowlist) -> tuple[tuple[str, ...], str, str]:
    # client_secret in a request body is a category error — public clients only.
    if "client_secret" in payload:
        raise _RegistrationError(
            "invalid_client_metadata",
            "client_secret must not be supplied — the proxy issues public clients only",
        )

    raw_uris = payload.get("redirect_uris")
    if not isinstance(raw_uris, list) or not raw_uris:
        raise _RegistrationError("invalid_redirect_uri", "redirect_uris must be a non-empty array")
    if not all(isinstance(u, str) and u for u in raw_uris):
        raise _RegistrationError(
            "invalid_redirect_uri", "every redirect_uris entry must be a non-empty string"
        )
    for uri in raw_uris:
        _reject_disallowed_redirect(uri, allowlist)

    method = payload.get("token_endpoint_auth_method", "none")
    if not isinstance(method, str):
        raise _RegistrationError(
            "invalid_client_metadata", "token_endpoint_auth_method must be a string"
        )
    if method in _FORBIDDEN_AUTH_METHODS:
        raise _RegistrationError(
            "invalid_client_metadata",
            f"token_endpoint_auth_method {method!r} relies on a shared symmetric secret",
        )
    if method != "none":
        # RFC 7591 allows other values (e.g. private_key_jwt), but the proxy
        # supports only ``none`` — fail loud rather than silently coerce.
        raise _RegistrationError(
            "invalid_client_metadata",
            f"token_endpoint_auth_method {method!r} is not supported; only 'none' is permitted",
        )

    client_name = payload.get("client_name", "")
    if not isinstance(client_name, str):
        raise _RegistrationError("invalid_client_metadata", "client_name must be a string")
    return tuple(raw_uris), method, client_name


def _reject_disallowed_redirect(uri: str, allowlist: Allowlist) -> None:
    """Fail if the redirect_uri is malformed or its host is not on the allowlist.

    A ``redirect_uri`` must be an absolute https URL (no fragment); the host is
    the one axis of the URL an attacker cannot forge freely without losing the
    callback, so the allowlist decision hangs there.
    """
    split = urlsplit(uri)
    if split.scheme != "https":
        raise _RegistrationError("invalid_redirect_uri", f"redirect_uri {uri!r} must use https")
    if split.fragment:
        raise _RegistrationError(
            "invalid_redirect_uri", f"redirect_uri {uri!r} must not carry a fragment"
        )
    if not split.hostname:
        raise _RegistrationError("invalid_redirect_uri", f"redirect_uri {uri!r} has no host")
    if not allowlist.allows(split.hostname):
        raise _RegistrationError(
            "invalid_redirect_uri",
            f"redirect_uri host {split.hostname!r} is not on CIMD_ALLOWED_DOMAINS",
        )
