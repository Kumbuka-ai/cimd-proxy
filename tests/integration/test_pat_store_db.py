# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""The PostgreSQL store under the application role, against a real database."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from psycopg import errors

from cimd_proxy.migrations import latest_version
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
        history = f"{SCHEMA}.flyway_schema_history"
        assert priv(f"SELECT has_table_privilege('cimd_app', '{history}', 'SELECT')")
        for privilege in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
            assert not priv(f"SELECT has_table_privilege('cimd_app', '{history}', '{privilege}')")
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
        "ALTER TABLE cimd_proxy.personal_access_token ADD COLUMN smuggled int",
        "DROP TABLE cimd_proxy.personal_access_token",
        "UPDATE cimd_proxy.flyway_schema_history SET success = true",
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


def test_a_row_without_an_organization_cannot_exist(database: Database) -> None:
    now = datetime.now(UTC)
    row = (uuid.uuid4(), REALM, b"\x01" * 32, ["https://r"], [], now, now + timedelta(days=1))
    statement = (
        "INSERT INTO cimd_proxy.personal_access_token "
        "(id, tenant, realm_issuer, owner_sub, name, token_hash, resources, scopes, "
        "created_at, expires_at) VALUES (%s, '', %s, 'a', 'n', %s, %s, %s, %s, %s)"
    )
    with psycopg.connect(database.app_dsn) as conn, pytest.raises(errors.CheckViolation):
        conn.execute(statement, row)


async def test_schema_behind_the_code_refuses_to_start(database: Database, monkeypatch) -> None:
    """The database is at the latest migration; code that needs one more is refused."""

    import cimd_proxy.pat_store as pat_store

    monkeypatch.setattr(pat_store, "latest_version", lambda: latest_version() + 1)
    store = PostgresPatStore(database.app_dsn, SCHEMA)
    await store.open()
    try:
        with pytest.raises(SchemaBehind, match=f"version {latest_version()}, this code needs"):
            await store.check_schema()
    finally:
        await store.close()


async def test_an_unmigrated_schema_refuses_to_start(database: Database) -> None:
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

    result = database.migrate(env={"FLYWAY_SCHEMAS": "cimd_proxy_ahead"})
    assert result.returncode == 0, result.stdout + result.stderr
    with psycopg.connect(database.admin_dsn, autocommit=True) as conn:
        # What the history of a successor release looks like: one more applied row.
        conn.execute(
            "INSERT INTO cimd_proxy_ahead.flyway_schema_history (installed_rank, version, "
            "description, type, script, checksum, installed_by, execution_time, success) "
            "SELECT max(installed_rank) + 1, %s, 'successor', 'SQL', 'V9__successor.sql', 0, "
            "'cimd_migrator', 0, true FROM cimd_proxy_ahead.flyway_schema_history",
            (str(latest_version() + 1),),
        )
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
