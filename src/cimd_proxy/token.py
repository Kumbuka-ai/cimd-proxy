# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""POST /token — authorization_code and refresh_token grants.

The load-bearing rule stays in force: the proxy never parses the access token.
The upstream token response is returned unchanged, except that
``refresh_token`` is replaced by a Fernet envelope carrying the upstream
refresh token plus the resource identifier — that is the reason no database is
required: the proxy learns from the token itself which upstream to talk to.
"""

from __future__ import annotations

from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse

from .config import ProxyConfig, ResourceEntry
from .correlation import bind_correlation_id
from .envelope import EnvelopeCodec, EnvelopeError, RefreshEnvelope
from .errors import InvalidGrant, InvalidRequest, OAuthError, ServerError
from .logging_setup import get_logger
from .pkce import verify_challenge
from .upstream import token_url

_LOG = get_logger("cimd_proxy.token")

router = APIRouter()


def _deps(request: Request) -> tuple[ProxyConfig, EnvelopeCodec]:
    return request.app.state.config, request.app.state.envelope_codec


@router.post("/token")
async def token(  # noqa: PLR0913 - OAuth token params are what they are
    _request: Request,
    grant_type: Annotated[str | None, Form()] = None,
    code: Annotated[str | None, Form()] = None,
    code_verifier: Annotated[str | None, Form()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
    refresh_token: Annotated[str | None, Form()] = None,
    scope: Annotated[str | None, Form()] = None,
    deps: Annotated[tuple[ProxyConfig, EnvelopeCodec], Depends(_deps)] = None,  # type: ignore[assignment]
):
    # The RFC 8707 `resource` form field is accepted (clients still send it)
    # but the proxy trusts the envelope's `resource` — routing already
    # happened at /authorize. See §5.4 of the design.
    config, codec = deps
    try:
        if grant_type == "authorization_code":
            return await _handle_auth_code(
                config=config,
                codec=codec,
                code=code,
                code_verifier=code_verifier,
                redirect_uri=redirect_uri,
                client_id=client_id,
            )
        if grant_type == "refresh_token":
            return await _handle_refresh(
                config=config,
                codec=codec,
                refresh_token=refresh_token,
                scope=scope,
            )
        raise InvalidRequest(
            f"grant_type must be 'authorization_code' or 'refresh_token', got {grant_type!r}"
        )
    except OAuthError as exc:
        safe_grant = (
            (grant_type or "").replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")
        )
        safe_desc = exc.description.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")
        _LOG.warning(
            {
                "event": "token.rejected",
                "grant_type": safe_grant,
                "error": exc.error,
                "error_description": safe_desc,
            }
        )
        return JSONResponse(status_code=exc.status_code, content=exc.as_dict())


async def _handle_auth_code(
    *,
    config: ProxyConfig,
    codec: EnvelopeCodec,
    code: str | None,
    code_verifier: str | None,
    redirect_uri: str | None,
    client_id: str | None,
) -> JSONResponse:
    if code is None:
        raise InvalidRequest("missing code")
    if code_verifier is None:
        raise InvalidRequest("missing code_verifier")
    try:
        code_env = codec.open_code(code)
    except EnvelopeError as exc:
        raise InvalidGrant(f"code envelope invalid or expired: {exc}") from exc
    bind_correlation_id(code_env.correlation_id)

    # exp is set at issuance (~60s TTL); enforce it here (Fernet's default TTL
    # is not applied to a code envelope because we may want to control it
    # explicitly for tests).
    import time as _time

    if code_env.exp <= int(_time.time()):
        raise InvalidGrant("code envelope expired")

    if redirect_uri is not None and redirect_uri != code_env.redirect_uri:
        raise InvalidGrant("redirect_uri does not match the redirect_uri from /authorize")
    if client_id is not None and client_id != code_env.client_id:
        raise InvalidGrant("client_id does not match the client_id from /authorize")
    if not verify_challenge(code_verifier, code_env.client_code_challenge):
        raise InvalidGrant("PKCE code_verifier does not match code_challenge")

    entry = config.resource_by_url(code_env.resource)
    if entry is None:
        # resource was validated at /authorize; if it vanished from the config
        # since then, do not silently succeed against a wrong client.
        raise ServerError(
            f"resource {code_env.resource!r} is no longer configured; refusing token exchange"
        )

    form: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code_env.upstream_code,
        "redirect_uri": f"{config.public_url}/callback",
        "code_verifier": code_env.upstream_verifier,
        "client_id": entry.client_id,
    }
    if entry.client_secret:
        form["client_secret"] = entry.client_secret

    upstream_response = await _post_form(token_url(entry.issuer), form)
    return _finalise_upstream_response(
        upstream_response,
        codec=codec,
        resource=entry.url,
    )


async def _handle_refresh(
    *,
    config: ProxyConfig,
    codec: EnvelopeCodec,
    refresh_token: str | None,
    scope: str | None,
) -> JSONResponse:
    if refresh_token is None:
        raise InvalidRequest("missing refresh_token")
    try:
        refresh_env = codec.open_refresh(refresh_token)
    except EnvelopeError as exc:
        raise InvalidGrant(f"refresh_token envelope invalid: {exc}") from exc

    entry = config.resource_by_url(refresh_env.resource)
    if entry is None:
        raise ServerError(
            f"resource {refresh_env.resource!r} is no longer configured; refusing refresh"
        )

    form: dict[str, str] = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_env.upstream_refresh_token,
        "client_id": entry.client_id,
    }
    if entry.client_secret:
        form["client_secret"] = entry.client_secret
    if scope:
        form["scope"] = scope

    upstream_response = await _post_form(token_url(entry.issuer), form)
    return _finalise_upstream_response(
        upstream_response,
        codec=codec,
        resource=entry.url,
    )


async def _post_form(url: str, form: dict[str, str]) -> httpx.Response:
    headers = {"Accept": "application/json"}
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            return await client.post(url, data=form, headers=headers)
        except httpx.HTTPError as exc:
            raise ServerError(f"upstream unreachable: {exc}") from exc


def _finalise_upstream_response(
    response: httpx.Response,
    *,
    codec: EnvelopeCodec,
    resource: str,
) -> JSONResponse:
    try:
        payload: dict[str, Any] = response.json()
    except ValueError as exc:
        raise ServerError("upstream token response is not valid JSON") from exc
    if response.status_code >= 400:
        # Pass the upstream error verbatim, preserving the OAuth error shape.
        _LOG.info(
            {
                "event": "token.upstream_error",
                "status_code": response.status_code,
                "error": payload.get("error"),
            }
        )
        return JSONResponse(status_code=response.status_code, content=payload)

    envelope_refresh = None
    if "refresh_token" in payload:
        envelope_refresh = codec.pack_refresh(
            RefreshEnvelope(
                resource=resource,
                upstream_refresh_token=payload["refresh_token"],
            )
        )
        payload["refresh_token"] = envelope_refresh
    _LOG.info(
        {
            "event": "token.issued",
            "resource": resource,
            "has_refresh": envelope_refresh is not None,
            "token_type": payload.get("token_type"),
            "expires_in": payload.get("expires_in"),
        }
    )
    return JSONResponse(status_code=200, content=payload)


__all__ = ["router", "ResourceEntry"]
