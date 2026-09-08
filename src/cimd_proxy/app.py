# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""FastAPI application factory.

Wires configuration, the CIMD service (fetcher + cache + policy), the envelope
codec and the routers into a ready-to-serve ASGI app.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.requests import Request

from .authorize import router as authorize_router
from .cache import TtlCache
from .callback import router as callback_router
from .cimd_service import CimdService
from .config import ProxyConfig, load_config
from .discovery import build_discovery_document
from .envelope import EnvelopeCodec
from .fetcher import CimdDocument, CimdFetcher
from .logging_setup import configure_logging
from .register import router as register_router
from .token import router as token_router


def create_app(config: ProxyConfig | None = None) -> FastAPI:
    """Build the ASGI app for a given configuration.

    Passing ``config=None`` reads the environment (fail-loud on missing values).
    """

    cfg = config if config is not None else load_config()
    configure_logging(cfg.log_level)

    fetcher = CimdFetcher(max_bytes=cfg.cimd_max_bytes, timeout_seconds=cfg.cimd_fetch_timeout)
    cache: TtlCache[CimdDocument] = TtlCache()
    cimd = CimdService(
        fetcher=fetcher,
        allowlist=cfg.allowlist,
        cache=cache,
        cache_ttl_min=cfg.cimd_cache_ttl_min,
        cache_ttl_max=cfg.cimd_cache_ttl_max,
    )
    codec = EnvelopeCodec.from_key_string(cfg.secret_key)

    app = FastAPI(title="cimd-proxy", version="0.2.1", docs_url=None, redoc_url=None)
    app.state.config = cfg
    app.state.cimd_service = cimd
    app.state.envelope_codec = codec
    app.state.cimd_cache = cache

    @app.get("/.well-known/oauth-authorization-server")
    async def discovery() -> JSONResponse:
        return JSONResponse(
            build_discovery_document(
                cfg.public_url,
                scopes_supported=cfg.scopes_supported,
                registration_endpoint=True,  # DCR route (Teil 3) is on
            )
        )

    @app.get("/.well-known/openid-configuration")
    async def openid_configuration_alias() -> JSONResponse:
        return JSONResponse(
            build_discovery_document(
                cfg.public_url,
                scopes_supported=cfg.scopes_supported,
                registration_endpoint=True,  # DCR route (Teil 3) is on
            )
        )

    @app.get("/healthz")
    async def healthz() -> PlainTextResponse:
        return PlainTextResponse("ok")

    @app.exception_handler(404)
    async def _not_found(_request: Request, _exc: Exception) -> JSONResponse:
        return JSONResponse(status_code=404, content={"error": "not_found"})

    app.include_router(authorize_router)
    app.include_router(callback_router)
    app.include_router(token_router)
    app.include_router(register_router)
    return app
