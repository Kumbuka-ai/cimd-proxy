# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Management endpoints for personal access tokens, and the assertion JWKS.

| Path | Method | Purpose |
|---|---|---|
| ``/pat/tokens`` | POST | create; the token is in this response and nowhere else, ever |
| ``/pat/tokens`` | GET | list the caller's own tokens, without any secret |
| ``/pat/tokens/{id}`` | DELETE | revoke one of the caller's own tokens |
| ``/pat/jwks.json`` | GET | public keys the upstream verifies assertions with |

Every management call needs the owner's own access token from an interactive
sign-in, judged by the upstream through introspection.
"""

from __future__ import annotations

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse, Response

from .errors import OAuthError
from .logging_setup import get_logger
from .pat import ManagementError, PatService

_LOG = get_logger("cimd_proxy.pat_api")

router = APIRouter()


def _service(request: Request) -> PatService:
    return request.app.state.pat_service


def _refusal(exc: ManagementError | OAuthError) -> JSONResponse:
    headers = {}
    if exc.status_code == 401:
        headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'
    _LOG.warning({"event": "pat.management_refused", "error": exc.error})
    return JSONResponse(status_code=exc.status_code, content=exc.as_dict(), headers=headers)


@router.post("/pat/tokens")
async def create_token(
    request: Request, authorization: str | None = Header(default=None)
) -> JSONResponse:
    service = _service(request)
    try:
        caller = await service.authenticate(authorization)
        try:
            body = await request.json()
        except ValueError:
            body = None
        record, token = await service.create(caller, service.parse_create(body))
    except (ManagementError, OAuthError) as exc:
        return _refusal(exc)
    return JSONResponse(
        status_code=201,
        content={"token": token, **record.public_view()},
        headers={"Cache-Control": "no-store"},
    )


@router.get("/pat/tokens")
async def list_tokens(
    request: Request, authorization: str | None = Header(default=None)
) -> JSONResponse:
    service = _service(request)
    try:
        caller = await service.authenticate(authorization)
        records = await service.list(caller)
    except (ManagementError, OAuthError) as exc:
        return _refusal(exc)
    return JSONResponse({"tokens": [r.public_view() for r in records]})


@router.delete("/pat/tokens/{token_id}")
async def revoke_token(
    token_id: str, request: Request, authorization: str | None = Header(default=None)
) -> Response:
    service = _service(request)
    try:
        caller = await service.authenticate(authorization)
        await service.revoke(caller, token_id)
    except (ManagementError, OAuthError) as exc:
        return _refusal(exc)
    return Response(status_code=204)


@router.get("/pat/jwks.json")
async def jwks(request: Request) -> JSONResponse:
    return JSONResponse(request.app.state.config.pat.signer.jwks())
