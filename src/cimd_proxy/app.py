# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""FastAPI application factory.

Wires configuration, the CIMD service (fetcher + cache + policy), the envelope
codec and the routers into a ready-to-serve ASGI app. When personal access
tokens are configured, the token store is opened at startup and the app refuses
to start while the database schema is behind the code (a newer schema is fine).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

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
from .keycloak import KeycloakClient
from .logging_setup import configure_logging
from .pat import TOKEN_EXCHANGE, PatService
from .pat_api import router as pat_router
from .pat_store import PatStore, PostgresPatStore
from .register import router as register_router
from .token import router as token_router


def create_app(
    config: ProxyConfig | None = None,
    *,
    pat_store: PatStore | None = None,
    keycloak: KeycloakClient | None = None,
) -> FastAPI:
    """Build the ASGI app for a given configuration.

    Passing ``config=None`` reads the environment (fail-loud on missing values).
    ``pat_store`` and ``keycloak`` replace the PostgreSQL store and the Keycloak
    client; tests pass them, production does not.
    """

    cfg = config if config is not None else load_config()
    configure_logging(cfg.log_level)

    fetcher = CimdFetcher(max_bytes=cfg.cimd_max_bytes, timeout_seconds=cfg.cimd_fetch_timeout)
    cache: TtlCache[CimdDocument] = TtlCache()
    cimd = CimdService(
        fetcher=fetcher,
        cache=cache,
        cache_ttl_min=cfg.cimd_cache_ttl_min,
        cache_ttl_max=cfg.cimd_cache_ttl_max,
    )
    codec = EnvelopeCodec.from_key_string(cfg.secret_key)

    pat_service: PatService | None = None
    owned_store: PostgresPatStore | None = None
    if cfg.pat is not None:
        if pat_store is None:
            owned_store = PostgresPatStore(cfg.pat.database_url, cfg.pat.database_schema)
            pat_store = owned_store
        pat_service = PatService(
            config=cfg,
            store=pat_store,
            keycloak=keycloak
            or KeycloakClient(
                realm_issuer=cfg.pat.realm_issuer,
                admin_client_id=cfg.pat.admin_client_id,
                admin_client_secret=cfg.pat.admin_client_secret,
                idp_alias=cfg.pat.idp_alias,
            ),
        )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        if owned_store is not None:
            await owned_store.open()
            try:
                await owned_store.check_schema()
            except BaseException:
                await owned_store.close()
                raise
        try:
            yield
        finally:
            if owned_store is not None:
                await owned_store.close()

    app = FastAPI(
        title="cimd-proxy", version="0.2.1", docs_url=None, redoc_url=None, lifespan=lifespan
    )
    app.state.config = cfg
    app.state.pat_service = pat_service
    app.state.cimd_service = cimd
    app.state.envelope_codec = codec
    app.state.cimd_cache = cache

    extra_grants = (TOKEN_EXCHANGE,) if pat_service is not None else ()

    @app.get("/.well-known/oauth-authorization-server")
    async def discovery() -> JSONResponse:
        return JSONResponse(
            build_discovery_document(
                cfg.public_url,
                scopes_supported=cfg.scopes_supported,
                registration_endpoint=True,  # DCR route (Teil 3) is on
                extra_grant_types=extra_grants,
            )
        )

    @app.get("/.well-known/openid-configuration")
    async def openid_configuration_alias() -> JSONResponse:
        return JSONResponse(
            build_discovery_document(
                cfg.public_url,
                scopes_supported=cfg.scopes_supported,
                registration_endpoint=True,  # DCR route (Teil 3) is on
                extra_grant_types=extra_grants,
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
    if pat_service is not None:
        app.include_router(pat_router)
    return app
