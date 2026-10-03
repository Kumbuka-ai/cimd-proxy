# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Versioned schema migrations for the personal-access-token store.

Run as ``python -m cimd_proxy migrate`` with a role that owns the schema
(``PAT_MIGRATION_DATABASE_URL``). The proxy itself runs under a second role that
holds only the grants the migrations hand it (``PAT_DATABASE_APP_ROLE``), and it
refuses to start while the schema is behind the code (see
:meth:`cimd_proxy.pat_store.PostgresPatStore.check_schema`).

Migrations are the files ``migrations/V<n>__<name>.sql``, applied in order, each
in its own transaction, under an advisory lock so two runners cannot interleave.
An applied migration is never edited: a change is a new file.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from importlib import resources

import psycopg
from psycopg import sql

from .config import ConfigError

_FILE = re.compile(r"^V(\d+)__[a-z0-9_]+\.sql$")
_LOCK_KEY = 0x63696D64  # "cimd"
_IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def migrations() -> list[tuple[int, str]]:
    found = []
    for entry in resources.files("cimd_proxy.migrations").iterdir():
        match = _FILE.match(entry.name)
        if match:
            found.append((int(match.group(1)), entry.read_text(encoding="utf-8")))
    found.sort()
    versions = [v for v, _ in found]
    if versions != list(range(1, len(versions) + 1)):
        raise RuntimeError(f"migration versions must run 1..n without gaps, found {versions}")
    return found


def latest_version() -> int:
    return len(migrations())


def migrate(dsn: str, schema: str, app_role: str) -> list[int]:
    """Apply every pending migration; return the versions applied by this call."""

    for name, value in (("schema", schema), ("app role", app_role)):
        if not _IDENT.match(value):
            raise ConfigError(f"{name} {value!r} is not a plain lower-case identifier")
    params = {"schema": sql.Identifier(schema), "app_role": sql.Identifier(app_role)}
    applied: list[int] = []
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("SELECT pg_advisory_lock(%s)", (_LOCK_KEY,))
        try:
            conn.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {schema}").format(**params))
            conn.execute(
                sql.SQL(
                    "CREATE TABLE IF NOT EXISTS {schema}.schema_history ("
                    " version integer PRIMARY KEY,"
                    " applied_at timestamptz NOT NULL DEFAULT now())"
                ).format(**params)
            )
            row = conn.execute(
                sql.SQL("SELECT coalesce(max(version), 0) FROM {schema}.schema_history").format(
                    **params
                )
            ).fetchone()
            current = row[0] if row else 0
            for version, text in migrations():
                if version <= current:
                    continue
                with conn.transaction():
                    conn.execute(sql.SQL(text).format(**params))  # type: ignore[arg-type]
                    conn.execute(
                        sql.SQL("INSERT INTO {schema}.schema_history (version) VALUES (%s)").format(
                            **params
                        ),
                        (version,),
                    )
                applied.append(version)
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (_LOCK_KEY,))
    return applied


def main(env: Mapping[str, str] | None = None) -> int:
    src = env if env is not None else os.environ
    dsn = src.get("PAT_MIGRATION_DATABASE_URL", "").strip()
    if not dsn:
        raise ConfigError("PAT_MIGRATION_DATABASE_URL is required")
    schema = src.get("PAT_DATABASE_SCHEMA", "cimd_proxy").strip()
    app_role = src.get("PAT_DATABASE_APP_ROLE", "").strip()
    if not app_role:
        raise ConfigError("PAT_DATABASE_APP_ROLE is required")
    applied = migrate(dsn, schema, app_role)
    print(f"schema {schema}: applied {applied or 'nothing'}, now at version {latest_version()}")
    return 0
