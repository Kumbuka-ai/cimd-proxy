# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""The calls the personal-access-token path makes to Keycloak.

Three of them, all against the realm in ``PAT_REALM_ISSUER``:

* introspection of the caller's own access token at the management endpoints
  (RFC 7662), with the proxy's admin client as the introspecting party — the
  token is judged by the provider that issued it, not parsed here. Keycloak 26.7
  answers ``active: false`` when the introspecting client is not in the token's
  audience, and an owner's token is audienced for the resource it was issued
  for; the admin client therefore carries
  ``allow.token.introspection.without.audience.check=true`` (measured both ways);
* the federated identity link between the owner and the proxy's identity
  provider, which is how Keycloak maps an assertion's ``sub`` to a user. Setting
  it needs ``realm-management/manage-users`` on the admin client (measured: a
  client with ``view-users`` gets 403);
* the JWT Authorization Grant itself, presented by the resource's confidential
  upstream client.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from .errors import ServerError
from .upstream import token_url

JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
_TIMEOUT = 10.0


def _admin_base(realm_issuer: str) -> str:
    base, sep, realm = realm_issuer.rstrip("/").rpartition("/realms/")
    if not sep or not realm:
        raise ValueError(f"{realm_issuer!r} is not a Keycloak realm issuer")
    return f"{base}/admin/realms/{realm}"


@dataclass(frozen=True, slots=True)
class Caller:
    """The verified owner behind a management request."""

    subject: str
    username: str
    organizations: tuple[str, ...]


class LinkConflict(RuntimeError):
    """The owner is already linked to the identity provider under another id."""


class KeycloakClient:
    def __init__(
        self,
        *,
        realm_issuer: str,
        admin_client_id: str,
        admin_client_secret: str,
        idp_alias: str,
    ) -> None:
        self._issuer = realm_issuer.rstrip("/")
        self._admin_base = _admin_base(self._issuer)
        self._client_id = admin_client_id
        self._client_secret = admin_client_secret
        self._idp_alias = idp_alias

    async def _post(self, url: str, **kwargs: Any) -> httpx.Response:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            try:
                return await client.post(url, **kwargs)
            except httpx.HTTPError as exc:
                raise ServerError(f"upstream unreachable: {type(exc).__name__}") from exc

    async def introspect(self, access_token: str) -> dict[str, Any]:
        r = await self._post(
            f"{token_url(self._issuer)}/introspect",
            data={"token": access_token, "token_type_hint": "access_token"},
            auth=(self._client_id, self._client_secret),
        )
        if r.status_code != 200:
            raise ServerError(f"token introspection failed with HTTP {r.status_code}")
        return r.json()

    async def _admin_token(self) -> str:
        r = await self._post(
            token_url(self._issuer),
            data={"grant_type": "client_credentials"},
            auth=(self._client_id, self._client_secret),
        )
        if r.status_code != 200:
            raise ServerError(f"admin client login failed with HTTP {r.status_code}")
        return r.json()["access_token"]

    async def ensure_link(self, caller: Caller) -> None:
        """Link the owner to the proxy's identity provider, with ``sub`` as the external id."""

        headers = {"Authorization": f"Bearer {await self._admin_token()}"}
        url = f"{self._admin_base}/users/{caller.subject}/federated-identity"
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            try:
                existing = await client.get(url, headers=headers)
                if existing.status_code != 200:
                    raise ServerError(
                        f"reading the owner's identity links failed with HTTP "
                        f"{existing.status_code}"
                    )
                for link in existing.json():
                    if link.get("identityProvider") == self._idp_alias:
                        if link.get("userId") != caller.subject:
                            raise LinkConflict(
                                "the owner is linked to the token issuer under another id"
                            )
                        return
                created = await client.post(
                    f"{url}/{self._idp_alias}",
                    headers=headers,
                    json={
                        "identityProvider": self._idp_alias,
                        "userId": caller.subject,
                        "userName": caller.username or caller.subject,
                    },
                )
            except httpx.HTTPError as exc:
                raise ServerError(f"upstream unreachable: {type(exc).__name__}") from exc
        if created.status_code not in (201, 204):
            raise ServerError(f"linking the owner failed with HTTP {created.status_code}")

    async def jwt_bearer_grant(
        self, *, client_id: str, client_secret: str, assertion: str, scope: str
    ) -> httpx.Response:
        form = {
            "grant_type": JWT_BEARER,
            "assertion": assertion,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if scope:
            form["scope"] = scope
        return await self._post(
            token_url(self._issuer), data=form, headers={"Accept": "application/json"}
        )
