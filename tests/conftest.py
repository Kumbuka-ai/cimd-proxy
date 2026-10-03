# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for cimd-proxy tests."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from cimd_proxy.app import create_app
from cimd_proxy.config import ProxyConfig, load_config


@pytest.fixture
def secret_key() -> str:
    return Fernet.generate_key().decode("ascii")


@pytest.fixture
def base_env(secret_key: str) -> dict[str, str]:
    return {
        "PROXY_PUBLIC_URL": "https://mcp-auth.example",
        "PROXY_SECRET_KEY": secret_key,
        "PROXY_PORT": "8080",
        "PROXY_BIND_HOST": "0.0.0.0",
        "LOG_LEVEL": "WARNING",
        "CIMD_DEBUG": "false",
        "CIMD_CACHE_TTL_MIN": "300",
        "CIMD_CACHE_TTL_MAX": "86400",
        "CIMD_MAX_BYTES": "5120",
        "CIMD_FETCH_TIMEOUT": "5",
        "DEFAULT_RESOURCE": "",
        "RESOURCE_0_URL": "https://log.example",
        "RESOURCE_0_ISSUER": "https://issuer.example/realms/x",
        "RESOURCE_0_CLIENT_ID": "log-mcp",
        "RESOURCE_0_CLIENT_SECRET": "",
    }


@pytest.fixture
def config(base_env: dict[str, str]) -> ProxyConfig:
    return load_config(base_env)


@pytest.fixture
def app_factory(base_env: dict[str, str]) -> Callable[..., object]:
    """Return a callable that builds an app with optional env overrides."""

    def _factory(**overrides: str) -> object:
        env = dict(base_env)
        env.update(overrides)
        cfg = load_config(env)
        return create_app(cfg)

    return _factory


@pytest.fixture
def app(app_factory: Callable[..., object]) -> object:
    return app_factory()


@pytest.fixture
def client(app: object) -> TestClient:
    return TestClient(app)  # type: ignore[arg-type]


# --- personal access tokens ----------------------------------------------


@pytest.fixture
def pat_key_file(tmp_path):
    from .pat_fakes import write_rsa_key

    path = tmp_path / "pat-signing-a.pem"
    write_rsa_key(path)
    return path


@pytest.fixture
def pat_env(base_env: dict[str, str], pat_key_file) -> dict[str, str]:
    from .pat_fakes import REALM

    env = dict(base_env)
    env.update(
        {
            "RESOURCE_0_PAT_CLIENT_ID": "log-mcp-pat",
            "RESOURCE_0_PAT_CLIENT_SECRET": "pat-client-secret",
            "RESOURCE_1_URL": "https://wlm.example",
            "RESOURCE_1_ISSUER": REALM,
            "RESOURCE_1_CLIENT_ID": "wlm-mcp",
            "RESOURCE_1_PAT_CLIENT_ID": "wlm-mcp-pat",
            "RESOURCE_1_PAT_CLIENT_SECRET": "pat-client-secret-y",
            "RESOURCE_2_URL": "https://interactive-only.example",
            "RESOURCE_2_ISSUER": REALM,
            "RESOURCE_2_CLIENT_ID": "interactive-mcp",
            "PAT_DATABASE_URL": "postgresql://unused.invalid/db",
            "PAT_REALM_ISSUER": REALM,
            "PAT_IDP_ALIAS": "cimd-proxy-pat",
            "PAT_ADMIN_CLIENT_ID": "cimd-proxy-admin",
            "PAT_ADMIN_CLIENT_SECRET": "admin-secret",
            "PAT_SCOPES": "set-memory set-dispatch",
            "PAT_SIGNING_KEY_0_KID": "key-a",
            "PAT_SIGNING_KEY_0_FILE": str(pat_key_file),
            "PAT_SIGNING_KID": "key-a",
        }
    )
    return env


@pytest.fixture
def pat_app_factory(pat_env: dict[str, str]):
    """Build a PAT-enabled app over an in-memory store and a fake Keycloak."""

    from .pat_fakes import FakeKeycloak, InMemoryPatStore

    def _factory(**overrides: str):
        env = dict(pat_env)
        env.update(overrides)
        store = InMemoryPatStore()
        keycloak = FakeKeycloak()
        app = create_app(load_config(env), pat_store=store, keycloak=keycloak)  # type: ignore[arg-type]
        return app, store, keycloak

    return _factory
