# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Storage of personal access tokens.

A row holds the SHA-256 of the token and never the token. Every read and every
write that acts for a caller carries the caller's realm and subject in its
``WHERE`` clause, so a user can neither see nor revoke another user's token:
the restriction lives in the statement, not in a check after it.

The exchange looks a token up by hash alone, because the hash is the only thing
a presenter proves; the tenant check happens on the row it returns.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from psycopg import errors, sql
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from .migrate import latest_version


@dataclass(frozen=True, slots=True)
class PatRecord:
    id: uuid.UUID
    tenant: str
    realm_issuer: str
    owner_sub: str
    name: str
    resources: tuple[str, ...]
    scopes: tuple[str, ...]
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None

    def public_view(self) -> dict[str, object]:
        """The listing shape: everything about the token except anything secret."""

        return {
            "id": str(self.id),
            "name": self.name,
            "tenant": self.tenant,
            "resources": list(self.resources),
            "scopes": list(self.scopes),
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
        }


class PatStore(Protocol):
    async def insert(self, record: PatRecord, token_hash: bytes) -> None: ...

    async def find_by_hash(self, token_hash: bytes) -> PatRecord | None: ...

    async def list_for_owner(self, realm_issuer: str, owner_sub: str) -> list[PatRecord]: ...

    async def revoke(self, realm_issuer: str, owner_sub: str, token_id: uuid.UUID) -> bool: ...

    async def touch(self, token_id: uuid.UUID, used_at: datetime) -> None: ...


class SchemaBehind(RuntimeError):
    """The database schema is older than this code; run ``python -m cimd_proxy migrate``."""


_COLUMNS = sql.SQL(", ").join(
    sql.Identifier(c)
    for c in (
        "id",
        "tenant",
        "realm_issuer",
        "owner_sub",
        "name",
        "resources",
        "scopes",
        "created_at",
        "expires_at",
        "last_used_at",
        "revoked_at",
    )
)


def _record(row: dict) -> PatRecord:
    return PatRecord(
        id=row["id"],
        tenant=row["tenant"],
        realm_issuer=row["realm_issuer"],
        owner_sub=row["owner_sub"],
        name=row["name"],
        resources=tuple(row["resources"]),
        scopes=tuple(row["scopes"]),
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        last_used_at=row["last_used_at"],
        revoked_at=row["revoked_at"],
    )


class PostgresPatStore:
    def __init__(self, dsn: str, schema: str) -> None:
        self._schema = sql.Identifier(schema)
        self._table = sql.SQL("{}.personal_access_token").format(self._schema)
        self._pool = AsyncConnectionPool(dsn, min_size=1, max_size=5, open=False)

    async def open(self) -> None:
        await self._pool.open(wait=True)

    async def close(self) -> None:
        await self._pool.close()

    async def check_schema(self) -> None:
        try:
            async with self._pool.connection() as conn:
                cur = await conn.execute(
                    sql.SQL("SELECT coalesce(max(version), 0) FROM {}.schema_history").format(
                        self._schema
                    )
                )
                row = await cur.fetchone()
        except (errors.UndefinedTable, errors.InvalidSchemaName):
            row = None
        current = row[0] if row else 0
        if current != latest_version():
            raise SchemaBehind(
                f"database schema is at version {current}, this code needs {latest_version()}; "
                "run `python -m cimd_proxy migrate`"
            )

    async def insert(self, record: PatRecord, token_hash: bytes) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                sql.SQL(
                    "INSERT INTO {} (id, tenant, realm_issuer, owner_sub, name, token_hash, "
                    "resources, scopes, created_at, expires_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                ).format(self._table),
                (
                    record.id,
                    record.tenant,
                    record.realm_issuer,
                    record.owner_sub,
                    record.name,
                    token_hash,
                    list(record.resources),
                    list(record.scopes),
                    record.created_at,
                    record.expires_at,
                ),
            )

    async def find_by_hash(self, token_hash: bytes) -> PatRecord | None:
        async with self._pool.connection() as conn:
            cur = conn.cursor(row_factory=dict_row)
            await cur.execute(
                sql.SQL("SELECT {} FROM {} WHERE token_hash = %s").format(_COLUMNS, self._table),
                (token_hash,),
            )
            row = await cur.fetchone()
        return _record(row) if row else None

    async def list_for_owner(self, realm_issuer: str, owner_sub: str) -> list[PatRecord]:
        async with self._pool.connection() as conn:
            cur = conn.cursor(row_factory=dict_row)
            await cur.execute(
                sql.SQL(
                    "SELECT {} FROM {} WHERE realm_issuer = %s AND owner_sub = %s "
                    "ORDER BY created_at, id"
                ).format(_COLUMNS, self._table),
                (realm_issuer, owner_sub),
            )
            rows = await cur.fetchall()
        return [_record(r) for r in rows]

    async def revoke(self, realm_issuer: str, owner_sub: str, token_id: uuid.UUID) -> bool:
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                sql.SQL(
                    "UPDATE {} SET revoked_at = now() WHERE id = %s AND realm_issuer = %s "
                    "AND owner_sub = %s AND revoked_at IS NULL"
                ).format(self._table),
                (token_id, realm_issuer, owner_sub),
            )
            return cur.rowcount == 1

    async def touch(self, token_id: uuid.UUID, used_at: datetime) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                sql.SQL("UPDATE {} SET last_used_at = %s WHERE id = %s").format(self._table),
                (used_at, token_id),
            )
