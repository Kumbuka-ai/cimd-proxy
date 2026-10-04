# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Containers for the integration tests: PostgreSQL with the production grant shape.

The database is set up the way the operator sets it up (see deploy/README.md): a
shared database, a migrator role with CREATEROLE and CREATE on the database and
nothing more, and the ``cimd-proxy-migrations`` image -- built from this working
tree, so a change to a migration is measured as it will ship -- which creates
the schema, the runtime role and its grants. The runtime role's placeholder
password is then rotated, as the operator does, and the tests run the proxy's
store under that role.

These tests need Docker. Without it they are skipped with the reason printed --
unless ``CIMD_PROXY_REQUIRE_INTEGRATION=1`` is set, as in CI, where a missing
Docker is a failure: a gate that silently does not run is no gate.
"""

from __future__ import annotations

import os
import subprocess
import time
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

import psycopg
import pytest

POSTGRES_IMAGE = "postgres:16-alpine"  # the production default (POSTGRES_VERSION)
SCHEMA = "cimd_proxy"
APP_ROLE = "cimd_app"
MIGRATIONS_IMAGE = "cimd-proxy-migrations:integration-test"
ROOT = Path(__file__).resolve().parents[2]


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
    network: str

    def dump(self) -> str:
        """``pg_dump`` of the whole database, data included, as the superuser sees it."""

        code, out = self.container.exec(  # type: ignore[attr-defined]
            ["pg_dump", "-U", "postgres", "--data-only", "--inserts", "kumbuka"]
        )
        assert code == 0, out
        return out.decode()

    def dsn(self, database: str, user: str = "postgres", password: str = "postgres") -> str:
        return self.admin_dsn.replace("postgres:postgres@", f"{user}:{password}@").replace(
            "/kumbuka", f"/{database}"
        )

    def create_database(self) -> str:
        """A fresh, empty database in the same server, for probes that need one."""

        name = f"probe_{uuid.uuid4().hex[:8]}"
        with psycopg.connect(self.admin_dsn, autocommit=True) as conn:
            conn.execute(f"CREATE DATABASE {name}")
            conn.execute(f"GRANT CONNECT, CREATE ON DATABASE {name} TO cimd_migrator")
        return name

    def migrate(
        self, *args: str, env: Mapping[str, str] | None = None, database: str = "kumbuka"
    ) -> subprocess.CompletedProcess[str]:
        """Run the migrations image against ``database``; ``env`` replaces the defaults."""

        values = {
            "FLYWAY_URL": f"jdbc:postgresql://db:5432/{database}",
            "FLYWAY_USER": "cimd_migrator",
            "FLYWAY_PASSWORD": "migrator",
            "FLYWAY_PLACEHOLDERS_APP_ROLE": APP_ROLE,
        }
        values.update(env or {})
        command = ["docker", "run", "--rm", "--network", self.network]
        for key, value in values.items():
            command += ["-e", f"{key}={value}"]
        return subprocess.run(  # noqa: S603 - fixed binary, arguments built here
            [*command, MIGRATIONS_IMAGE, *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )


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


def _build_migrations_image() -> None:
    result = subprocess.run(  # noqa: S603 - fixed binary and arguments
        ["docker", "build", "-q", "-f", "Dockerfile.migrations", "-t", MIGRATIONS_IMAGE, "."],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=900,
    )
    assert result.returncode == 0, result.stderr


@pytest.fixture(scope="session")
def database() -> Iterator[Database]:
    docker_or_skip()
    from testcontainers.core.container import DockerContainer
    from testcontainers.core.network import Network

    _build_migrations_image()
    network = Network()
    network.create()
    container = (
        DockerContainer(POSTGRES_IMAGE)
        .with_env("POSTGRES_PASSWORD", "postgres")
        .with_env("POSTGRES_DB", "kumbuka")
        .with_exposed_ports(5432)
        .with_network(network)
        .with_network_aliases("db")
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
            conn.execute("CREATE ROLE cimd_migrator LOGIN CREATEROLE PASSWORD 'migrator'")
            conn.execute("GRANT CONNECT, CREATE ON DATABASE kumbuka TO cimd_migrator")
        db = Database(
            admin_dsn=admin,
            migrator_dsn=base.format(user="cimd_migrator", pw="migrator"),
            app_dsn=base.format(user=APP_ROLE, pw="app"),
            container=container,
            network=network.name,
        )
        result = db.migrate()
        assert result.returncode == 0, result.stdout + result.stderr
        with psycopg.connect(admin, autocommit=True) as conn:
            # The operator's rotation away from the migration's placeholder.
            conn.execute(f"ALTER ROLE {APP_ROLE} PASSWORD 'app'")
        yield db
    finally:
        container.stop()
        network.remove()
