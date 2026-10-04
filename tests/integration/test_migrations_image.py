# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""The cimd-proxy-migrations image, run as a deployment runs it, against PostgreSQL.

Each test that needs an empty database gets its own, in the same server, so the
probes do not depend on the order they run in.
"""

from __future__ import annotations

import base64

import psycopg
import pytest
from starlette.testclient import TestClient

from cimd_proxy.app import create_app
from cimd_proxy.config import load_config
from cimd_proxy.migrations import latest_version
from cimd_proxy.pat_store import SchemaBehind

from ..pat_fakes import write_rsa_key
from .conftest import APP_ROLE, SCHEMA, Database

pytestmark = pytest.mark.integration


def _output(result) -> str:
    return result.stdout + result.stderr


def _scalar(dsn: str, statement: str, *params: object) -> object:
    with psycopg.connect(dsn) as conn:
        row = conn.execute(statement, params).fetchone()
    return row[0] if row else None


def _history(dsn: str, schema: str = SCHEMA) -> list[tuple]:
    with psycopg.connect(dsn) as conn:
        return conn.execute(
            "SELECT installed_rank, version, checksum, success, installed_on "
            f"FROM {schema}.flyway_schema_history "
            "ORDER BY installed_rank"
        ).fetchall()


def test_cold_start_creates_schema_table_and_role_and_a_rerun_changes_nothing(
    database: Database,
) -> None:
    name = database.create_database()
    admin = database.dsn(name)
    role = f"app_{name}"

    first = database.migrate(env={"FLYWAY_PLACEHOLDERS_APP_ROLE": role}, database=name)
    assert first.returncode == 0, _output(first)
    assert _scalar(admin, "SELECT to_regclass('cimd_proxy.personal_access_token') IS NOT NULL")
    assert _scalar(
        admin,
        "SELECT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole "
        "FROM pg_roles WHERE rolname = %s",
        role,
    )
    assert (
        _scalar(
            admin, "SELECT nspowner::regrole::text FROM pg_namespace WHERE nspname = %s", SCHEMA
        )
        == "cimd_migrator"
    )
    history = _history(admin)
    assert [h[1] for h in history if h[1] is not None] == [str(latest_version())]

    second = database.migrate(env={"FLYWAY_PLACEHOLDERS_APP_ROLE": role}, database=name)
    assert second.returncode == 0, _output(second)
    assert "No migration necessary" in second.stdout
    validate = database.migrate(
        "validate", env={"FLYWAY_PLACEHOLDERS_APP_ROLE": role}, database=name
    )
    assert validate.returncode == 0, _output(validate)
    assert _history(admin) == history


def test_empty_credentials_exit_zero_and_create_nothing(database: Database) -> None:
    name = database.create_database()
    role = f"app_{name}"
    result = database.migrate(
        env={"FLYWAY_USER": "", "FLYWAY_PASSWORD": "", "FLYWAY_PLACEHOLDERS_APP_ROLE": role},
        database=name,
    )
    assert result.returncode == 0, _output(result)
    assert "not configured; nothing to migrate" in result.stdout
    admin = database.dsn(name)
    assert not _scalar(admin, "SELECT count(*) FROM pg_namespace WHERE nspname = %s", SCHEMA)
    assert not _scalar(admin, "SELECT count(*) FROM pg_roles WHERE rolname = %s", role)


def test_empty_credentials_need_no_database_at_all(database: Database) -> None:
    """Off is off: nothing is contacted, so an absent database cannot fail it either."""

    result = database.migrate(
        env={
            "FLYWAY_USER": "",
            "FLYWAY_PASSWORD": "",
            "FLYWAY_URL": "jdbc:postgresql://no-such-host.invalid:5432/x",
        }
    )
    assert result.returncode == 0, _output(result)


@pytest.mark.parametrize(
    "env",
    [{"FLYWAY_PASSWORD": ""}, {"FLYWAY_USER": ""}],
    ids=["user-without-password", "password-without-user"],
)
def test_half_configured_credentials_fail_loudly(database: Database, env: dict) -> None:
    result = database.migrate(env=env)
    assert result.returncode == 2, _output(result)
    assert "set both or neither" in result.stderr


@pytest.mark.parametrize(
    "env",
    [
        {"FLYWAY_PLACEHOLDERS_APP_ROLE": 'app"; DROP TABLE x; --'},
        {"FLYWAY_PLACEHOLDERS_APP_ROLE": "App"},
        {"FLYWAY_SCHEMAS": "a,b"},
        {"FLYWAY_PLACEHOLDERS_APP_ROLE": "x" * 64},
    ],
    ids=["quote", "upper-case", "two-schemas", "too-long"],
)
def test_identifiers_are_checked_before_flyway_runs(database: Database, env: dict) -> None:
    result = database.migrate(env=env)
    assert result.returncode == 2, _output(result)
    assert "Flyway" not in result.stdout  # it never started


def test_a_runtime_role_with_bypassrls_is_refused(database: Database) -> None:
    name = database.create_database()
    role = f"bypass_{name}"
    with psycopg.connect(database.admin_dsn, autocommit=True) as conn:
        conn.execute(f"CREATE ROLE {role} LOGIN BYPASSRLS")
    result = database.migrate(env={"FLYWAY_PLACEHOLDERS_APP_ROLE": role}, database=name)
    assert result.returncode != 0
    assert "CP002" in _output(result)
    admin = database.dsn(name)
    assert not _scalar(admin, "SELECT to_regclass('cimd_proxy.personal_access_token') IS NOT NULL")
    assert not _scalar(
        admin, "SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = %s", role
    )


def test_a_superuser_migrator_is_refused(database: Database) -> None:
    name = database.create_database()
    result = database.migrate(
        env={"FLYWAY_USER": "postgres", "FLYWAY_PASSWORD": "postgres"}, database=name
    )
    assert result.returncode != 0
    assert "CP001" in _output(result)
    assert not _scalar(
        database.dsn(name), "SELECT to_regclass('cimd_proxy.personal_access_token') IS NOT NULL"
    )


def test_the_proxy_does_not_start_against_an_unmigrated_schema(
    database: Database, tmp_path
) -> None:
    with psycopg.connect(database.admin_dsn, autocommit=True) as conn:
        conn.execute("CREATE SCHEMA IF NOT EXISTS cimd_proxy_unmigrated")
        conn.execute(f"GRANT USAGE ON SCHEMA cimd_proxy_unmigrated TO {APP_ROLE}")
    write_rsa_key(tmp_path / "key.pem")
    issuer = "https://issuer.example/realms/x"
    env = {
        "PROXY_PUBLIC_URL": "https://proxy.example",
        "PROXY_SECRET_KEY": base64.urlsafe_b64encode(b"k" * 32).decode(),
        "RESOURCE_0_URL": "https://res.example",
        "RESOURCE_0_ISSUER": issuer,
        "RESOURCE_0_CLIENT_ID": "res-interactive",
        "RESOURCE_0_PAT_CLIENT_ID": "res-pat",
        "RESOURCE_0_PAT_CLIENT_SECRET": "s",
        "PAT_DATABASE_URL": database.app_dsn,
        "PAT_DATABASE_SCHEMA": "cimd_proxy_unmigrated",
        "PAT_REALM_ISSUER": issuer,
        "PAT_IDP_ALIAS": "cimd-proxy-pat",
        "PAT_ADMIN_CLIENT_ID": "admin",
        "PAT_ADMIN_CLIENT_SECRET": "s",
        "PAT_SCOPES": "set-memory",
        "PAT_SIGNING_KEY_0_KID": "k",
        "PAT_SIGNING_KEY_0_FILE": str(tmp_path / "key.pem"),
        "PAT_SIGNING_KID": "k",
    }
    with pytest.raises(SchemaBehind, match="version 0"), TestClient(create_app(load_config(env))):
        pass
    env["PAT_DATABASE_SCHEMA"] = SCHEMA
    with TestClient(create_app(load_config(env))) as client:  # the control: migrated, starts
        assert client.get("/healthz").status_code == 200
