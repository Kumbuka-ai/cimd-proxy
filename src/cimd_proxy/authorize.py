# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""GET /authorize.

The proxy speaks two registration protocols at once. Which one applies is
disambiguated by the shape of ``client_id``:

* starts with ``https://`` — CIMD (draft-ietf-oauth-client-id-metadata-document);
* otherwise — opened as a Fernet ``RegistrationEnvelope`` from RFC 7591 DCR.

Anything that is neither a well-formed https-URL nor a valid registration
envelope is refused with a typed error rather than silently coerced.

Validation order matters. Every step decides whether the next is meaningful:

1. ``resource`` known (or covered by ``DEFAULT_RESOURCE``).
2. ``code_challenge_method`` == ``S256``.
3. CIMD route: ``client_id`` host on the allowlist, then CIMD document
   fetched and validated (identity, no secret, no shared-secret auth
   method, non-empty ``redirect_uris``). DCR route: envelope opened,
   ``redirect_uris`` list read from it (the allowlist has already been
   enforced at /register — see there for the frame decision).
4. ``redirect_uri`` byte-equal to an entry in the ``redirect_uris`` list
   the route produced.

Before step 4 has passed, an error must not redirect (OAuth 2.1 §4.1.2.1 —
redirecting to an unvalidated URI is itself a vulnerability). After step 4,
errors are OAuth-redirects; the endpoint never returns a bearer response.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse, RedirectResponse

from .cimd_service import CimdService, DocumentInvalid, FetchError, SSRFRefused
from .config import ProxyConfig, ResourceEntry
from .correlation import bind_correlation_id, new_correlation_id
from .envelope import AuthorizeEnvelope, EnvelopeCodec, EnvelopeError
from .errors import InvalidClient, InvalidRequest, InvalidTarget, OAuthError
from .fetcher import CimdDocument
from .logging_setup import get_logger
from .pkce import derive_challenge, make_verifier
from .upstream import authorize_url

_LOG = get_logger("cimd_proxy.authorize")

_ENVELOPE_TTL_SECONDS = 600


router = APIRouter()


@dataclass(frozen=True, slots=True)
class _AuthorizeParams:
    response_type: str | None
    client_id: str | None
    redirect_uri: str | None
    code_challenge: str | None
    code_challenge_method: str | None
    state: str | None
    resource: str | None
    scope: str | None


@dataclass(frozen=True, slots=True)
class _Validated:
    client_id: str
    redirect_uri: str
    code_challenge: str
    state: str
    scope: str
    resource_entry: ResourceEntry
    # Present when the CIMD route accepted the client_id; ``None`` on the DCR
    # route. The subsequent ``authorize.forwarded`` log line only distinguishes
    # the two by the ``via`` field, since neither should change the upstream
    # request shape.
    document: CimdDocument | None
    via: str  # "cimd" or "dcr"


def _deps(request: Request) -> tuple[ProxyConfig, CimdService, EnvelopeCodec]:
    return (
        request.app.state.config,
        request.app.state.cimd_service,
        request.app.state.envelope_codec,
    )


def _require_present(params: _AuthorizeParams) -> None:
    if params.response_type is None:
        raise InvalidRequest("missing response_type")
    if params.response_type != "code":
        raise InvalidRequest(f"unsupported response_type: {params.response_type!r}")
    if params.client_id is None:
        raise InvalidRequest("missing client_id")
    if params.redirect_uri is None:
        raise InvalidRequest("missing redirect_uri")
    if params.code_challenge is None:
        raise InvalidRequest("missing code_challenge")


def _pick_resource(config: ProxyConfig, resource: str | None) -> ResourceEntry:
    chosen = resource or config.default_resource
    if not chosen:
        raise InvalidTarget(
            "missing 'resource' parameter and no DEFAULT_RESOURCE is set; "
            f"known resources: {list(config.known_resources)}"
        )
    entry = config.resource_by_url(chosen)
    if entry is None:
        raise InvalidTarget(
            f"resource {chosen!r} is not a known target; "
            f"known resources: {list(config.known_resources)}"
        )
    return entry


async def _load_document(cimd: CimdService, client_id: str) -> CimdDocument:
    try:
        return await cimd.obtain(client_id)
    except (SSRFRefused, DocumentInvalid, FetchError) as exc:
        raise InvalidClient(str(exc)) from exc


async def _validate(
    config: ProxyConfig, cimd: CimdService, codec: EnvelopeCodec, params: _AuthorizeParams
) -> _Validated:
    _require_present(params)
    # These are non-None after _require_present, but the type checker cannot
    # see that; the cast is a bare assign for readability.
    client_id = params.client_id  # type: ignore[assignment]
    redirect_uri = params.redirect_uri  # type: ignore[assignment]
    code_challenge = params.code_challenge  # type: ignore[assignment]
    assert client_id is not None
    assert redirect_uri is not None
    assert code_challenge is not None

    entry = _pick_resource(config, params.resource)

    if params.code_challenge_method != "S256":
        raise InvalidRequest(
            f"code_challenge_method must be 'S256', got {params.code_challenge_method!r}"
        )

    if client_id.startswith("https://"):
        redirect_uris, document, via = await _validate_cimd(cimd, client_id)
    else:
        redirect_uris = _validate_dcr(codec, client_id)
        document = None
        via = "dcr"

    # RFC 3986 §6.2.1 comparison — no normalisation, no port defaulting,
    # no trailing-slash forgiveness.
    if redirect_uri not in redirect_uris:
        raise InvalidRequest(
            "redirect_uri is not registered "
            + ("in the CIMD document" if via == "cimd" else "on the DCR registration")
        )

    # Scope resolution: a client that says ``scope`` gets exactly that ---
    # the proxy does not append to a client's request, because appending would
    # amount to inventing a right past what the client asked for. Only silence
    # is filled, by the configured default. This is a ratified decision, not a
    # build choice.
    scope = params.scope if params.scope else config.default_scope

    return _Validated(
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        state=params.state or "",
        scope=scope,
        resource_entry=entry,
        document=document,
        via=via,
    )


async def _validate_cimd(
    cimd: CimdService, client_id: str
) -> tuple[tuple[str, ...], CimdDocument, str]:
    try:
        cimd.check_allowlist(client_id)
    except SSRFRefused as exc:
        raise InvalidClient(str(exc)) from exc
    document = await _load_document(cimd, client_id)
    return document.redirect_uris, document, "cimd"


def _validate_dcr(codec: EnvelopeCodec, client_id: str) -> tuple[str, ...]:
    """Open a DCR ``client_id`` envelope and read the registered redirect_uris.

    The envelope's own tag check refuses any of the other three envelope kinds
    (authorize / code / refresh) passed in this slot — a callback-shaped code
    presented here as a client_id would otherwise unpack silently.

    The allowlist has already been enforced at ``/register``: a registered
    ``redirect_uris`` list cannot contain a host outside CIMD_ALLOWED_DOMAINS.
    Re-checking here would be defence in depth, but it would also duplicate the
    responsibility for the decision. If the allowlist is tightened, an existing
    registration should re-fail at ``/authorize`` — that is F-note for a later
    sprint, called out in the return.
    """
    try:
        envelope = codec.open_registration(client_id)
    except EnvelopeError as exc:
        raise InvalidClient(
            "client_id is neither a https URL nor a valid registration envelope"
        ) from exc
    return envelope.redirect_uris


def _build_upstream_url(
    config: ProxyConfig,
    codec: EnvelopeCodec,
    validated: _Validated,
    cid: str,
) -> tuple[str, str]:
    upstream_verifier = make_verifier()
    upstream_challenge = derive_challenge(upstream_verifier)
    envelope = AuthorizeEnvelope(
        correlation_id=cid,
        client_id=validated.client_id,
        redirect_uri=validated.redirect_uri,
        state=validated.state,
        resource=validated.resource_entry.url,
        client_code_challenge=validated.code_challenge,
        upstream_verifier=upstream_verifier,
        scope=validated.scope,
        exp=int(time.time()) + _ENVELOPE_TTL_SECONDS,
    )
    envelope_str = codec.pack_authorize(envelope)

    upstream_params = {
        "response_type": "code",
        "client_id": validated.resource_entry.client_id,
        "redirect_uri": f"{config.public_url}/callback",
        "code_challenge": upstream_challenge,
        "code_challenge_method": "S256",
        "state": envelope_str,
        "scope": validated.scope,
    }
    target = f"{authorize_url(validated.resource_entry.issuer)}?{urlencode(upstream_params)}"
    return target, envelope_str


@router.get(
    "/authorize",
    responses={
        302: {"description": "Forwarded to the upstream authorization endpoint."},
        400: {"description": "OAuth error rendered as text/plain."},
    },
)
async def authorize(  # noqa: PLR0913 - OAuth authorize params are what they are
    _request: Request,
    response_type: Annotated[str | None, Query()] = None,
    client_id: Annotated[str | None, Query()] = None,
    redirect_uri: Annotated[str | None, Query()] = None,
    code_challenge: Annotated[str | None, Query()] = None,
    code_challenge_method: Annotated[str | None, Query()] = None,
    state: Annotated[str | None, Query()] = None,
    resource: Annotated[str | None, Query()] = None,
    scope: Annotated[str | None, Query()] = None,
    deps: Annotated[tuple[ProxyConfig, CimdService, EnvelopeCodec], Depends(_deps)] = None,  # type: ignore[assignment]
):
    config, cimd, codec = deps
    cid = new_correlation_id()
    bind_correlation_id(cid)

    params = _AuthorizeParams(
        response_type=response_type,
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        state=state,
        resource=resource,
        scope=scope,
    )
    try:
        validated = await _validate(config, cimd, codec, params)
    except OAuthError as exc:
        # Steps 0-5: no validated redirect target yet. Render an inline error.
        # Inline CR/LF/NUL neutralisation on user-controlled log fields
        # (defence in depth on top of json.dumps escaping).
        safe_desc = exc.description.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")
        safe_cid = (
            (client_id or "").replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")
        )
        safe_res = (resource or "").replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")
        _LOG.warning(
            {
                "event": "authorize.rejected",
                "error": exc.error,
                "error_description": safe_desc,
                "client_id": safe_cid,
                "resource": safe_res,
            }
        )
        return _render_authorize_error(exc)

    target, _envelope_str = _build_upstream_url(config, codec, validated, cid)
    safe_res = (
        validated.resource_entry.url.replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\x00", "\\0")
    )
    safe_cid = validated.client_id.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")
    # ``scope`` is a config value or a client-supplied one; both take the same
    # log-sanitising treatment as any other user-controlled field.
    safe_scope = validated.scope.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")
    _LOG.info(
        {
            "event": "authorize.forwarded",
            "resource": safe_res,
            "upstream_client_id": validated.resource_entry.client_id,
            "client_id": safe_cid,
            "scope": safe_scope,
            "via": validated.via,
        }
    )
    return RedirectResponse(url=target, status_code=302)


def _render_authorize_error(exc: OAuthError) -> PlainTextResponse:
    body = f"error={exc.error}\nerror_description={exc.description}\n"
    return PlainTextResponse(content=body, status_code=exc.status_code)
