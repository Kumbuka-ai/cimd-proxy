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
        "CIMD_ALLOWED_DOMAINS": "claude.ai,*.claude.ai",
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
