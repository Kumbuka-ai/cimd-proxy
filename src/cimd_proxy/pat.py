# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Personal access tokens: create, list, revoke, and exchange for a short token.

The agent's view is two calls: it presents the token at ``/token`` with the
token-exchange grant and receives an ordinary, short-lived upstream access token
that carries only the roles of the token's permission set. How that token comes
about stays inside the proxy:

1. The token string is checked for prefix and checksum before anything is
   looked up; a mistyped or invented token never reaches the database.
2. The row is found by the SHA-256 of the token and checked for revocation,
   expiry and the requested resource.
3. The proxy signs a 60-second assertion naming the owner and presents it to
   the upstream with the JWT Authorization Grant, requesting exactly the token's
   client scopes — plus ``organization:<tenant>`` when the token is bound to a
   tenant, so a token created in one organization can never come back naming
   another (measured: a non-member gets no organization claim at all).
4. A refresh token, should the upstream ever send one, is dropped. The agent
   exchanges again when the short token runs out.

Who may carry which scope is decided by the upstream, not by the proxy: when a
token is created, the proxy performs one trial exchange per resource for the
requested set and refuses the token if the upstream drops any scope from it
(measured: Keycloak drops an optional client scope whose roles the user does
not hold).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .assertion import AssertionSigner
from .config import PatConfig, ProxyConfig, ResourceEntry
from .errors import InvalidGrant, InvalidRequest, InvalidTarget, OAuthError, ServerError
from .keycloak import Caller, KeycloakClient, LinkConflict
from .logging_setup import get_logger
from .pat_format import generate, is_well_formed, token_hash
from .pat_store import PatRecord, PatStore

# RFC 8693 identifiers, not credentials.
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105
DEFAULT_LIFETIME_DAYS = 90
LONG_LIFETIME_DAYS = 365

_LOG = get_logger("cimd_proxy.pat")


class ManagementError(Exception):
    """A refusal at the management endpoints, rendered as a JSON error body."""

    def __init__(self, status_code: int, error: str, description: str) -> None:
        super().__init__(description)
        self.status_code = status_code
        self.error = error
        self.description = description

    def as_dict(self) -> dict[str, str]:
        return {"error": self.error, "error_description": self.description}


@dataclass(frozen=True, slots=True)
class CreateRequest:
    name: str
    resources: tuple[str, ...]
    scopes: tuple[str, ...]
    lifetime_days: int
    allow_long_lifetime: bool
    organization: str | None


class PatService:
    def __init__(
        self,
        *,
        config: ProxyConfig,
        store: PatStore,
        keycloak: KeycloakClient,
    ) -> None:
        if config.pat is None:
            raise ValueError("personal access tokens are not configured")
        self._config = config
        self._pat: PatConfig = config.pat
        self._signer: AssertionSigner = config.pat.signer
        self._store = store
        self._keycloak = keycloak

    # --- management -------------------------------------------------------
    async def authenticate(self, authorization: str | None) -> Caller:
        scheme, _, credential = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not credential.strip():
            raise ManagementError(401, "invalid_token", "a bearer token is required")
        if is_well_formed(credential.strip()):
            raise ManagementError(
                403,
                "insufficient_scope",
                "a personal access token cannot manage tokens; sign in interactively",
            )
        claims = await self._keycloak.introspect(credential.strip())
        if not claims.get("active"):
            raise ManagementError(401, "invalid_token", "the bearer token is not active")
        if claims.get("iss", "").rstrip("/") != self._pat.realm_issuer:
            raise ManagementError(401, "invalid_token", "the bearer token is from another realm")
        if claims.get("typ") != "Bearer" or not claims.get("sub"):
            raise ManagementError(401, "invalid_token", "the bearer token is not an access token")
        if not claims.get("sid"):
            # Tokens from the JWT Authorization Grant carry no session (measured).
            # Refusing them keeps a leaked personal access token from minting more.
            raise ManagementError(
                403,
                "insufficient_scope",
                "managing tokens needs a token from an interactive sign-in",
            )
        return Caller(
            subject=claims["sub"],
            username=claims.get("preferred_username", ""),
            organizations=_organizations(claims.get("organization")),
        )

    def parse_create(self, body: Any) -> CreateRequest:
        if not isinstance(body, dict):
            raise ManagementError(400, "invalid_request", "the body must be a JSON object")
        name = body.get("name")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
            raise ManagementError(400, "invalid_request", "name must be 1 to 100 characters")
        resources = _string_list(body.get("resources"), "resources")
        if not resources:
            raise ManagementError(400, "invalid_request", "resources must name at least one")
        for url in resources:
            entry = self._config.resource_by_url(url)
            if entry is None or not entry.accepts_pat:
                raise ManagementError(
                    400, "invalid_target", f"resource {url!r} does not accept personal tokens"
                )
        scopes = _string_list(body.get("scopes", []), "scopes")
        outside = [s for s in scopes if s not in self._pat.scopes]
        if outside:
            raise ManagementError(
                400, "invalid_scope", f"scopes not offered for personal tokens: {outside}"
            )
        days, long_ok = _lifetime(body)
        organization = body.get("organization")
        if organization is not None and not isinstance(organization, str):
            raise ManagementError(400, "invalid_request", "organization must be a string")
        return CreateRequest(
            name=name.strip(),
            resources=tuple(self._config.resource_by_url(u).url for u in resources),  # type: ignore[union-attr]
            scopes=scopes,
            lifetime_days=days,
            allow_long_lifetime=long_ok,
            organization=organization,
        )

    async def create(self, caller: Caller, request: CreateRequest) -> tuple[PatRecord, str]:
        tenant = _tenant_for(caller, request.organization)
        try:
            await self._keycloak.ensure_link(caller)
        except LinkConflict as exc:
            raise ManagementError(409, "link_conflict", str(exc)) from exc
        for url in request.resources:
            await self._trial_exchange(caller, self._entry(url), request.scopes, tenant)

        now = datetime.now(UTC)
        record = PatRecord(
            id=uuid.uuid4(),
            tenant=tenant,
            realm_issuer=self._pat.realm_issuer,
            owner_sub=caller.subject,
            name=request.name,
            resources=request.resources,
            scopes=request.scopes,
            created_at=now,
            expires_at=now + timedelta(days=request.lifetime_days),
        )
        token = generate()
        await self._store.insert(record, token_hash(token))
        _LOG.info({"event": "pat.created", "pat_id": str(record.id), "tenant": tenant})
        return record, token

    async def list(self, caller: Caller) -> list[PatRecord]:
        return await self._store.list_for_owner(self._pat.realm_issuer, caller.subject)

    async def revoke(self, caller: Caller, token_id: str) -> None:
        try:
            parsed = uuid.UUID(token_id)
        except ValueError as exc:
            raise ManagementError(404, "not_found", "no such token") from exc
        if not await self._store.revoke(self._pat.realm_issuer, caller.subject, parsed):
            # Not found, already revoked and somebody else's look the same from outside.
            raise ManagementError(404, "not_found", "no such token")
        _LOG.info({"event": "pat.revoked", "pat_id": str(parsed)})

    async def _trial_exchange(
        self, caller: Caller, entry: ResourceEntry, scopes: tuple[str, ...], tenant: str
    ) -> None:
        response = await self._keycloak.jwt_bearer_grant(
            client_id=entry.pat_client_id,
            client_secret=entry.pat_client_secret,
            assertion=self._signer.sign(subject=caller.subject, audience=entry.issuer),
            scope=_scope_param(scopes, tenant),
        )
        payload = _json(response)
        if response.status_code != 200:
            raise ManagementError(
                502,
                "server_error",
                f"the token issuer refused a trial exchange for {entry.url!r}: "
                f"{payload.get('error')}: {payload.get('error_description')}",
            )
        granted = set(str(payload.get("scope", "")).split())
        missing = [s for s in scopes if s not in granted]
        if missing:
            raise ManagementError(
                403,
                "insufficient_scope",
                f"the owner may not carry {missing} at {entry.url!r}",
            )

    # --- exchange ---------------------------------------------------------
    async def exchange(
        self,
        *,
        subject_token: str | None,
        subject_token_type: str | None,
        requested_token_type: str | None,
        resource: str | None,
    ) -> dict[str, Any]:
        if not subject_token:
            raise InvalidRequest("missing subject_token")
        if subject_token_type != ACCESS_TOKEN_TYPE:
            raise InvalidRequest(f"subject_token_type must be {ACCESS_TOKEN_TYPE}")
        if requested_token_type not in (None, ACCESS_TOKEN_TYPE):
            raise InvalidRequest(f"requested_token_type must be {ACCESS_TOKEN_TYPE}")
        if not is_well_formed(subject_token):
            raise InvalidGrant("subject_token is not a valid personal access token")

        record = await self._store.find_by_hash(token_hash(subject_token))
        if record is None:
            raise InvalidGrant("subject_token is not a valid personal access token")
        now = datetime.now(UTC)
        if record.revoked_at is not None:
            raise InvalidGrant("the personal access token is revoked")
        if record.expires_at <= now:
            raise InvalidGrant("the personal access token is expired")
        if record.realm_issuer != self._pat.realm_issuer:
            raise InvalidGrant("the personal access token belongs to another realm")

        entry = self._resolve_resource(record, resource)
        response = await self._keycloak.jwt_bearer_grant(
            client_id=entry.pat_client_id,
            client_secret=entry.pat_client_secret,
            assertion=self._signer.sign(subject=record.owner_sub, audience=entry.issuer),
            scope=_scope_param(record.scopes, record.tenant),
        )
        payload = _json(response)
        if response.status_code != 200:
            _LOG.info(
                {
                    "event": "pat.exchange_refused_upstream",
                    "pat_id": str(record.id),
                    "status_code": response.status_code,
                    "error": payload.get("error"),
                }
            )
            raise _UpstreamRefusal(response.status_code, payload)

        dropped = payload.pop("refresh_token", None) is not None
        payload.pop("refresh_expires_in", None)
        payload["issued_token_type"] = ACCESS_TOKEN_TYPE
        await self._store.touch(record.id, now)
        _LOG.info(
            {
                "event": "pat.exchanged",
                "pat_id": str(record.id),
                "resource": entry.url,
                "refresh_token_dropped": dropped,
                "expires_in": payload.get("expires_in"),
            }
        )
        return payload

    def _resolve_resource(self, record: PatRecord, resource: str | None) -> ResourceEntry:
        if resource is None:
            if len(record.resources) != 1:
                raise InvalidTarget("resource is required: the token names more than one")
            resource = record.resources[0]
        entry = self._config.resource_by_url(resource)
        if entry is None or entry.url not in record.resources:
            raise InvalidTarget("the personal access token does not name this resource")
        if not entry.accepts_pat or entry.issuer != record.realm_issuer:
            raise InvalidTarget("this resource no longer accepts personal access tokens")
        return entry

    def _entry(self, url: str) -> ResourceEntry:
        entry = self._config.resource_by_url(url)
        if entry is None:  # pragma: no cover - parse_create already refused it
            raise ServerError(f"resource {url!r} is not configured")
        return entry


class _UpstreamRefusal(OAuthError):
    """The upstream's own OAuth error, passed through verbatim."""

    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        super().__init__(
            error=str(payload.get("error", "server_error")),
            description=str(payload.get("error_description", "")),
            status_code=status_code if 400 <= status_code < 500 else 502,
        )


def _json(response: Any) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError as exc:
        raise ServerError("upstream token response is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ServerError("upstream token response is not a JSON object")
    return payload


def _scope_param(scopes: tuple[str, ...], tenant: str) -> str:
    return " ".join([*scopes, *([f"organization:{tenant}"] if tenant else [])])


def _organizations(claim: Any) -> tuple[str, ...]:
    """Keycloak renders ``organization`` as a list of aliases or as a map keyed by alias."""

    if isinstance(claim, (list, dict)):
        aliases = [str(c) for c in claim]
    elif isinstance(claim, str) and claim:
        aliases = [claim]
    else:
        aliases = []
    return tuple(aliases)


def _tenant_for(caller: Caller, requested: str | None) -> str:
    if requested is not None:
        if requested not in caller.organizations:
            raise ManagementError(
                403, "insufficient_scope", "the owner is not a member of that organization"
            )
        return requested
    if len(caller.organizations) > 1:
        raise ManagementError(
            400,
            "invalid_request",
            "the owner belongs to several organizations; name one in 'organization'",
        )
    return caller.organizations[0] if caller.organizations else ""


def _lifetime(body: dict[str, Any]) -> tuple[int, bool]:
    days = body.get("expires_in_days", DEFAULT_LIFETIME_DAYS)
    if isinstance(days, bool) or not isinstance(days, int) or days < 1:
        raise ManagementError(400, "invalid_request", "expires_in_days must be >= 1")
    long_ok = body.get("allow_long_lifetime", False)
    if not isinstance(long_ok, bool):
        raise ManagementError(400, "invalid_request", "allow_long_lifetime must be a boolean")
    if days > LONG_LIFETIME_DAYS and not long_ok:
        raise ManagementError(
            400,
            "invalid_request",
            f"a lifetime above {LONG_LIFETIME_DAYS} days needs allow_long_lifetime: true",
        )
    return days, long_ok


def _string_list(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise ManagementError(400, "invalid_request", f"{field} must be a list of strings")
    return tuple(dict.fromkeys(value))
