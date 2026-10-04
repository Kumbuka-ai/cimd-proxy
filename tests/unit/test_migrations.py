# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
from pathlib import Path

import pytest

from cimd_proxy import __main__ as entry
from cimd_proxy import migrations

ROOT = Path(__file__).resolve().parents[2]


def test_migrations_are_numbered_from_one_without_gaps() -> None:
    versions = migrations.versions()
    assert versions == list(range(1, len(versions) + 1))
    assert migrations.latest_version() == len(versions) >= 1


def test_a_gap_in_the_numbering_is_refused(tmp_path, monkeypatch) -> None:
    for name in ("V1__a.sql", "V3__c.sql"):
        (tmp_path / name).write_text("SELECT 1;")
    monkeypatch.setattr(migrations, "DIRECTORY", tmp_path)
    with pytest.raises(RuntimeError, match=r"without gaps, found \[1, 3\]"):
        migrations.latest_version()


def test_migrations_use_flyway_placeholders_only() -> None:
    """Flyway substitutes ``${...}``; the retired runner's ``{schema}`` form must not remain."""

    for path in sorted(migrations.DIRECTORY.glob("V*__*.sql")):
        text = path.read_text(encoding="utf-8")
        placeholders = set(re.findall(r"\$\{([^}]+)\}", text))
        assert placeholders <= {"flyway:defaultSchema", "app_role"}, path.name
        assert not re.search(r"(?<!\$)\{(schema|app_role)\}", text), path.name


def test_the_migrations_image_copies_this_directory() -> None:
    dockerfile = (ROOT / "Dockerfile.migrations").read_text(encoding="utf-8")
    assert "COPY src/cimd_proxy/migrations/*.sql /flyway/sql/" in dockerfile
    assert re.search(r"^FROM flyway/flyway:[^\s@]+@sha256:[0-9a-f]{64}$", dockerfile, re.M)


def test_entrypoint_takes_no_arguments() -> None:
    with pytest.raises(SystemExit, match="cimd-proxy-migrations image"):
        entry.main(["migrate"])
