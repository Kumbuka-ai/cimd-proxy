# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""The PostgreSQL store under the application role, against a real database."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from psycopg import errors

from cimd_proxy.migrate import latest_version, migrate
from cimd_proxy.pat_format import generate, token_hash
from cimd_proxy.pat_store import PatRecord, PostgresPatStore, SchemaBehind

from .conftest import SCHEMA, Database

pytestmark = pytest.mark.integration

REALM = "https://kc.example/realms/x"


def _record(owner: str = "alice", **changes) -> PatRecord:
    now = datetime.now(UTC)
    values = {
        "id": uuid.uuid4(),
        "tenant": "tenant-a",
        "realm_issuer": REALM,
        "owner_sub": owner,
        "name": "agent",
        "resources": ("https://res-x.example",),
        "scopes": ("set-memory",),
        "created_at": now,
        "expires_at": now + timedelta(days=90),
    }
    values.update(changes)
    return PatRecord(**values)


@pytest.fixture
async def store(database: Database):
    s = PostgresPatStore(database.app_dsn, SCHEMA)
    await s.open()
    yield s
    await s.close()


async def test_round_trip_under_the_application_role(store: PostgresPatStore) -> None:
    await store.check_schema()
    record = _record()
    token = generate()
    await store.insert(record, token_hash(token))

    found = await store.find_by_hash(token_hash(token))
    assert found is not None
    assert (found.id, found.owner_sub, found.tenant) == (record.id, "alice", "tenant-a")
    assert found.resources == ("https://res-x.example",)
    assert found.scopes == ("set-memory",)
    assert found.revoked_at is None
    assert found.last_used_at is None
    assert await store.find_by_hash(token_hash(generate())) is None

    used = datetime.now(UTC)
    await store.touch(record.id, used)
    found = await store.find_by_hash(token_hash(token))
    assert found is not None
    assert found.last_used_at is not None
    assert abs((found.last_used_at - used).total_seconds()) < 1


async def test_list_and_revoke_are_bound_to_realm_and_owner(store: PostgresPatStore) -> None:
    mine = _record(owner="owner-1")
    theirs = _record(owner="owner-2")
    await store.insert(mine, token_hash(generate()))
    await store.insert(theirs, token_hash(generate()))

    assert [r.id for r in await store.list_for_owner(REALM, "owner-1")] == [mine.id]
    assert await store.list_for_owner("https://kc.example/realms/other", "owner-1") == []
    assert not await store.revoke(REALM, "owner-1", theirs.id)
    assert not await store.revoke("https://kc.example/realms/other", "owner-2", theirs.id)
    assert await store.revoke(REALM, "owner-2", theirs.id)
    assert not await store.revoke(REALM, "owner-2", theirs.id)  # already revoked
    (listed,) = await store.list_for_owner(REALM, "owner-2")
    assert listed.revoked_at is not None


def test_application_role_holds_exactly_the_migration_grants(database: Database) -> None:
    table = f"{SCHEMA}.personal_access_token"
    with psycopg.connect(database.admin_dsn) as conn:

        def priv(sql: str) -> bool:
            row = conn.execute(sql).fetchone()
            assert row is not None
            return bool(row[0])

        assert priv(f"SELECT has_table_privilege('cimd_app', '{table}', 'SELECT')")
        assert priv(f"SELECT has_table_privilege('cimd_app', '{table}', 'INSERT')")
        assert not priv(f"SELECT has_table_privilege('cimd_app', '{table}', 'DELETE')")
        assert not priv(f"SELECT has_table_privilege('cimd_app', '{table}', 'TRUNCATE')")
        assert not priv(f"SELECT has_table_privilege('cimd_app', '{table}', 'UPDATE')")
        for column in ("last_used_at", "revoked_at"):
            assert priv(f"SELECT has_column_privilege('cimd_app', '{table}', '{column}', 'UPDATE')")
        for column in ("token_hash", "owner_sub", "tenant", "scopes", "resources", "expires_at"):
            assert not priv(
                f"SELECT has_column_privilege('cimd_app', '{table}', '{column}', 'UPDATE')"
            )
        assert priv(f"SELECT has_table_privilege('cimd_app', '{SCHEMA}.schema_history', 'SELECT')")
        assert not priv(
            f"SELECT has_table_privilege('cimd_app', '{SCHEMA}.schema_history', 'INSERT')"
        )
        assert not priv(f"SELECT has_schema_privilege('cimd_app', '{SCHEMA}', 'CREATE')")
        owner = conn.execute(
            "SELECT tableowner FROM pg_tables WHERE schemaname = %s AND tablename = %s",
            (SCHEMA, "personal_access_token"),
        ).fetchone()
        assert owner == ("cimd_migrator",)


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM cimd_proxy.personal_access_token",
        "UPDATE cimd_proxy.personal_access_token SET owner_sub = 'mallory'",
        "UPDATE cimd_proxy.personal_access_token SET expires_at = now() + interval '100 years'",
        "CREATE TABLE cimd_proxy.smuggled (x int)",
    ],
)
def test_application_role_is_refused_what_it_was_not_granted(
    database: Database, statement: str
) -> None:
    with psycopg.connect(database.app_dsn) as conn, pytest.raises(errors.InsufficientPrivilege):
        conn.execute(statement)


def test_constraints_refuse_impossible_rows(database: Database) -> None:
    with psycopg.connect(database.app_dsn) as conn, pytest.raises(errors.CheckViolation):
        conn.execute(
            "INSERT INTO cimd_proxy.personal_access_token "
            "(id, tenant, realm_issuer, owner_sub, name, token_hash, resources, scopes, "
            "created_at, expires_at) VALUES (%s, '', %s, 'a', 'n', %s, %s, %s, now(), now())",
            (uuid.uuid4(), REALM, b"\x00" * 32, ["https://r"], []),
        )


def test_migrate_is_idempotent(database: Database) -> None:
    assert migrate(database.migrator_dsn, SCHEMA, "cimd_app") == []
    with psycopg.connect(database.admin_dsn) as conn:
        row = conn.execute(f"SELECT max(version) FROM {SCHEMA}.schema_history").fetchone()
    assert row == (latest_version(),)


async def test_schema_behind_the_code_refuses_to_start(database: Database) -> None:
    with psycopg.connect(database.admin_dsn, autocommit=True) as conn:
        conn.execute("CREATE SCHEMA IF NOT EXISTS cimd_proxy_empty")
        conn.execute("GRANT USAGE ON SCHEMA cimd_proxy_empty TO cimd_app")
    store = PostgresPatStore(database.app_dsn, "cimd_proxy_empty")
    await store.open()
    try:
        with pytest.raises(SchemaBehind, match="version 0"):
            await store.check_schema()
    finally:
        await store.close()


async def test_schema_ahead_of_the_code_is_accepted(database: Database) -> None:
    """An image rolled back to an older version starts against its successor's schema."""

    with psycopg.connect(database.admin_dsn, autocommit=True) as conn:
        conn.execute("CREATE SCHEMA IF NOT EXISTS cimd_proxy_ahead")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS cimd_proxy_ahead.schema_history "
            "(version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
        )
        conn.execute(
            "INSERT INTO cimd_proxy_ahead.schema_history (version) VALUES (%s) "
            "ON CONFLICT DO NOTHING",
            (latest_version() + 1,),
        )
        conn.execute("GRANT USAGE ON SCHEMA cimd_proxy_ahead TO cimd_app")
        conn.execute("GRANT SELECT ON cimd_proxy_ahead.schema_history TO cimd_app")
    store = PostgresPatStore(database.app_dsn, "cimd_proxy_ahead")
    await store.open()
    try:
        await store.check_schema()
    finally:
        await store.close()


async def test_token_value_is_not_in_a_database_dump(
    store: PostgresPatStore, database: Database
) -> None:
    token = generate()
    await store.insert(_record(owner="dump-probe"), token_hash(token))
    dump = database.dump()
    assert "dump-probe" in dump  # the row is in the dump
    assert token_hash(token).hex() in dump  # as its hash
    assert token not in dump
    assert token[len("kmb_pat_") :] not in dump
