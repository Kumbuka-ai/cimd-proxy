# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Containers for the integration tests: PostgreSQL with the production grant shape.

The database is set up the way the operator sets it up (see the README): a
shared database, a migrator role that may create the schema and owns what is in
it, and an application role that holds nothing but what the migrations grant.
The tests then run the proxy's store under the application role.

These tests need Docker. Without it they are skipped with the reason printed —
unless ``CIMD_PROXY_REQUIRE_INTEGRATION=1`` is set, as in CI, where a missing
Docker is a failure: a gate that silently does not run is no gate.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from dataclasses import dataclass

import psycopg
import pytest

from cimd_proxy.migrate import migrate

POSTGRES_IMAGE = "postgres:16-alpine"  # the production default (POSTGRES_VERSION)
SCHEMA = "cimd_proxy"


def docker_or_skip() -> None:
    try:
        import docker

        docker.from_env().ping()
    except Exception as exc:  # noqa: BLE001 - any failure means "no usable Docker"
        if os.environ.get("CIMD_PROXY_REQUIRE_INTEGRATION") == "1":
            pytest.fail(f"Docker is required for the integration tests: {exc}")
        pytest.skip(f"integration tests need Docker: {exc}")


@dataclass(frozen=True)
class Database:
    admin_dsn: str
    migrator_dsn: str
    app_dsn: str
    container: object

    def dump(self) -> str:
        """``pg_dump`` of the whole database, data included, as the superuser sees it."""

        code, out = self.container.exec(  # type: ignore[attr-defined]
            ["pg_dump", "-U", "postgres", "--data-only", "--inserts", "kumbuka"]
        )
        assert code == 0, out
        return out.decode()


def _wait_for(dsn: str, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            with psycopg.connect(dsn, connect_timeout=2):
                return
        except psycopg.OperationalError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.5)


@pytest.fixture(scope="session")
def database() -> Iterator[Database]:
    docker_or_skip()
    from testcontainers.core.container import DockerContainer

    container = (
        DockerContainer(POSTGRES_IMAGE)
        .with_env("POSTGRES_PASSWORD", "postgres")
        .with_env("POSTGRES_DB", "kumbuka")
        .with_exposed_ports(5432)
    )
    container.start()
    try:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(5432)
        base = f"postgresql://{{user}}:{{pw}}@{host}:{port}/kumbuka"
        admin = base.format(user="postgres", pw="postgres")
        _wait_for(admin)
        # A fresh postgres image may accept one connection during its init
        # restart; wait again after a pause so the setup does not race it.
        time.sleep(1)
        _wait_for(admin)
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute("CREATE ROLE cimd_migrator LOGIN PASSWORD 'migrator'")
            conn.execute("CREATE ROLE cimd_app LOGIN PASSWORD 'app'")
            conn.execute("GRANT CONNECT, CREATE ON DATABASE kumbuka TO cimd_migrator")
            conn.execute("GRANT CONNECT ON DATABASE kumbuka TO cimd_app")
        migrator = base.format(user="cimd_migrator", pw="migrator")
        migrate(migrator, SCHEMA, "cimd_app")
        yield Database(
            admin_dsn=admin,
            migrator_dsn=migrator,
            app_dsn=base.format(user="cimd_app", pw="app"),
            container=container,
        )
    finally:
        container.stop()
