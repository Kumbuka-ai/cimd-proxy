# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""GET /callback — upstream returns here after the user's consent.

The upstream ``state`` is our authorize envelope. We open it, verify the
correlation id we sealed there, then hand the client a code envelope carrying
what ``/token`` needs to redeem the upstream code on the client's behalf.

RFC 9207 (echoed by MCP SEP-2468) requires ``iss`` on the response — clients on
the 2026-07-28 revision refuse a response without it and the failure looks
like a configuration error rather than a spec violation.

An upstream error is passed on to the client's ``redirect_uri`` unchanged, not
swallowed.
"""

from __future__ import annotations

import time
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse, RedirectResponse

from .config import ProxyConfig
from .correlation import bind_correlation_id
from .envelope import CodeEnvelope, EnvelopeCodec, EnvelopeError
from .logging_setup import get_logger

_LOG = get_logger("cimd_proxy.callback")
_CODE_TTL_SECONDS = 60

router = APIRouter()


def _deps(request: Request) -> tuple[ProxyConfig, EnvelopeCodec]:
    return request.app.state.config, request.app.state.envelope_codec


@router.get("/callback")
async def callback(
    request: Request,
    code: Annotated[str | None, Query()] = None,
    state: Annotated[str | None, Query()] = None,
    error: Annotated[str | None, Query()] = None,
    error_description: Annotated[str | None, Query()] = None,
    deps: Annotated[tuple[ProxyConfig, EnvelopeCodec], Depends(_deps)] = None,  # type: ignore[assignment]
):
    config, codec = deps
    if state is None:
        return PlainTextResponse(
            content="error=invalid_request\nerror_description=missing state\n",
            status_code=400,
        )
    try:
        authorize_env = codec.open_authorize(state)
    except EnvelopeError as exc:
        _LOG.warning({"event": "callback.state_invalid", "error": str(exc)})
        return PlainTextResponse(
            content="error=invalid_request\nerror_description=state envelope invalid or expired\n",
            status_code=400,
        )
    bind_correlation_id(authorize_env.correlation_id)

    if error is not None:
        # Pass the upstream error through to the original redirect_uri; do not
        # swallow it and do not attempt to "translate" the code — the client
        # sees the same reason the upstream gave.
        safe_err = (error or "").replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")
        safe_edesc = (
            (error_description or "")
            .replace("\r", "\\r")
            .replace("\n", "\\n")
            .replace("\x00", "\\0")
        )
        safe_res = (
            authorize_env.resource.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")
        )
        _LOG.info(
            {
                "event": "callback.upstream_error",
                "error": safe_err,
                "error_description": safe_edesc,
                "resource": safe_res,
            }
        )
        params = {"error": error}
        if error_description:
            params["error_description"] = error_description
        if authorize_env.state:
            params["state"] = authorize_env.state
        params["iss"] = config.public_url
        return RedirectResponse(
            url=f"{authorize_env.redirect_uri}?{urlencode(params)}",
            status_code=302,
        )

    if code is None:
        return PlainTextResponse(
            content="error=invalid_request\nerror_description=missing code\n",
            status_code=400,
        )

    code_env = CodeEnvelope(
        correlation_id=authorize_env.correlation_id,
        upstream_code=code,
        upstream_verifier=authorize_env.upstream_verifier,
        resource=authorize_env.resource,
        client_id=authorize_env.client_id,
        client_code_challenge=authorize_env.client_code_challenge,
        redirect_uri=authorize_env.redirect_uri,
        exp=int(time.time()) + _CODE_TTL_SECONDS,
    )
    code_str = codec.pack_code(code_env)
    params = {"code": code_str, "iss": config.public_url}
    if authorize_env.state:
        params["state"] = authorize_env.state
    safe_res = (
        authorize_env.resource.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")
    )
    safe_cid = (
        authorize_env.client_id.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")
    )
    _LOG.info(
        {
            "event": "callback.forwarded",
            "resource": safe_res,
            "client_id": safe_cid,
        }
    )
    return RedirectResponse(
        url=f"{authorize_env.redirect_uri}?{urlencode(params)}",
        status_code=302,
    )
