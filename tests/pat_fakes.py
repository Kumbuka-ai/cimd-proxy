# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Test doubles for the personal-access-token path.

:class:`InMemoryPatStore` mirrors the statements of the PostgreSQL store — owner
and realm in every caller-scoped ``WHERE``, revoke only an unrevoked row — and
counts every call, so a probe can assert that the database was *not* asked.
The PostgreSQL store itself is measured in ``tests/integration``; this double
does not stand in for that measurement.

:class:`FakeKeycloak` answers introspection from a table of known bearer tokens
and the JWT Authorization Grant from a function the test controls, and records
every grant it was asked for.
"""

from __future__ import annotations

import base64
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cimd_proxy.keycloak import Caller, LinkConflict
from cimd_proxy.pat_store import PatRecord

REALM = "https://issuer.example/realms/x"


class InMemoryPatStore:
    def __init__(self) -> None:
        self.rows: dict[bytes, PatRecord] = {}
        self.calls: list[str] = []

    async def insert(self, record: PatRecord, token_hash: bytes) -> None:
        self.calls.append("insert")
        if token_hash in self.rows:
            raise ValueError("duplicate token hash")
        self.rows[token_hash] = record

    async def find_by_hash(self, token_hash: bytes) -> PatRecord | None:
        self.calls.append("find_by_hash")
        return self.rows.get(token_hash)

    async def list_for_owner(self, realm_issuer: str, owner_sub: str) -> list[PatRecord]:
        self.calls.append("list_for_owner")
        return sorted(
            (
                r
                for r in self.rows.values()
                if r.realm_issuer == realm_issuer and r.owner_sub == owner_sub
            ),
            key=lambda r: (r.created_at, str(r.id)),
        )

    async def revoke(self, realm_issuer: str, owner_sub: str, token_id: uuid.UUID) -> bool:
        self.calls.append("revoke")
        for h, r in self.rows.items():
            if (
                r.id == token_id
                and r.realm_issuer == realm_issuer
                and r.owner_sub == owner_sub
                and r.revoked_at is None
            ):
                self.rows[h] = replace(r, revoked_at=datetime.now(r.created_at.tzinfo))
                return True
        return False

    async def touch(self, token_id: uuid.UUID, used_at: datetime) -> None:
        self.calls.append("touch")
        for h, r in self.rows.items():
            if r.id == token_id:
                self.rows[h] = replace(r, last_used_at=used_at)

    def by_id(self, token_id: str) -> PatRecord:
        return next(r for r in self.rows.values() if str(r.id) == token_id)


def _b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def assertion_claims(assertion: str) -> dict[str, Any]:
    return json.loads(_b64u_decode(assertion.split(".")[1]))


def assertion_header(assertion: str) -> dict[str, Any]:
    return json.loads(_b64u_decode(assertion.split(".")[0]))


@dataclass
class Grant:
    client_id: str
    client_secret: str
    assertion: str
    scope: str


def _default_grant(grant: Grant) -> httpx.Response:
    """Grant every requested scope; return a token that names them."""

    return httpx.Response(
        200,
        json={
            "access_token": f"upstream-at-for-{assertion_claims(grant.assertion)['sub']}",
            "token_type": "Bearer",
            "expires_in": 300,
            "scope": grant.scope,
        },
    )


@dataclass
class FakeKeycloak:
    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)
    respond: Callable[[Grant], httpx.Response] = _default_grant
    grants: list[Grant] = field(default_factory=list)
    links: dict[str, str] = field(default_factory=dict)
    introspections: int = 0

    def add_session(
        self, bearer: str, sub: str, *, sid: str | None = "sid-1", **claims: Any
    ) -> None:
        entry: dict[str, Any] = {
            "active": True,
            "iss": REALM,
            "typ": "Bearer",
            "sub": sub,
            "preferred_username": sub,
            **claims,
        }
        if sid is not None:
            entry["sid"] = sid
        self.sessions[bearer] = entry

    async def introspect(self, access_token: str) -> dict[str, Any]:
        self.introspections += 1
        return self.sessions.get(access_token, {"active": False})

    async def ensure_link(self, caller: Caller) -> None:
        existing = self.links.get(caller.subject)
        if existing is not None and existing != caller.subject:
            raise LinkConflict("the owner is linked to the token issuer under another id")
        self.links[caller.subject] = caller.subject

    async def jwt_bearer_grant(
        self, *, client_id: str, client_secret: str, assertion: str, scope: str
    ) -> httpx.Response:
        grant = Grant(client_id, client_secret, assertion, scope)
        self.grants.append(grant)
        return self.respond(grant)


def write_rsa_key(path: Path, bits: int = 2048) -> rsa.RSAPrivateKey:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return key
