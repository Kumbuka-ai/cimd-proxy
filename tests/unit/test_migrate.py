# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest

from cimd_proxy import __main__ as entry
from cimd_proxy import migrate
from cimd_proxy.config import ConfigError


def test_migrations_are_numbered_from_one_without_gaps() -> None:
    versions = [v for v, _ in migrate.migrations()]
    assert versions == list(range(1, len(versions) + 1))
    assert migrate.latest_version() == len(versions) >= 1
    first = migrate.migrations()[0][1]
    assert "{schema}" in first and "{app_role}" in first


@pytest.mark.parametrize(("schema", "role"), [('x"; drop', "app"), ("ok", "Robert'); --")])
def test_identifiers_are_checked_before_connecting(schema: str, role: str) -> None:
    with pytest.raises(ConfigError, match="plain lower-case identifier"):
        migrate.migrate("postgresql://never.invalid/db", schema, role)


def test_main_needs_its_two_values() -> None:
    with pytest.raises(ConfigError, match="PAT_MIGRATION_DATABASE_URL"):
        migrate.main({})
    with pytest.raises(ConfigError, match="PAT_DATABASE_APP_ROLE"):
        migrate.main({"PAT_MIGRATION_DATABASE_URL": "postgresql://x/y"})


def test_main_passes_schema_and_role(monkeypatch, capsys) -> None:
    seen = {}

    def fake(dsn: str, schema: str, role: str) -> list[int]:
        seen.update(dsn=dsn, schema=schema, role=role)
        return [1]

    monkeypatch.setattr(migrate, "migrate", fake)
    assert (
        migrate.main(
            {
                "PAT_MIGRATION_DATABASE_URL": "postgresql://m/db",
                "PAT_DATABASE_SCHEMA": "pats",
                "PAT_DATABASE_APP_ROLE": "app",
            }
        )
        == 0
    )
    assert seen == {"dsn": "postgresql://m/db", "schema": "pats", "role": "app"}
    assert "applied [1]" in capsys.readouterr().out


def test_entrypoint_runs_the_migrate_subcommand(monkeypatch) -> None:
    monkeypatch.setattr(migrate, "main", lambda: 0)
    with pytest.raises(SystemExit) as exc:
        entry.main(["migrate"])
    assert exc.value.code == 0


def test_entrypoint_refuses_unknown_arguments() -> None:
    with pytest.raises(SystemExit, match="only subcommand is 'migrate'"):
        entry.main(["serve", "--now"])
