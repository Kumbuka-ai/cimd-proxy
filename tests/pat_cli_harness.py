# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Drive the pat command line against the real proxy app, in-process.

The proxy is the real application over the in-memory store and the fake
Keycloak of :mod:`tests.pat_fakes`; the command talks to it through a Starlette
``TestClient``. The upstream's authorize and token endpoints are what the e2e
flow test mocks as well: the browser stub plays the upstream's redirect to
``/callback``, and the upstream token endpoint is a respx route that returns
the owner's access token. The last leg -- the browser following the proxy's
redirect to the loopback listener -- is a real HTTP request to 127.0.0.1.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

import httpx
from starlette.testclient import TestClient

UPSTREAM_TOKEN = "https://issuer.example/realms/x/protocol/openid-connect/token"
PROXY = "https://mcp-auth.example"
RESOURCE = "https://log.example"
# Distinctive values, so a search for them in output and files cannot hit by accident.
OWNER_ACCESS_TOKEN = "owner-at-3f9c1d7e5b2a4068"  # noqa: S105 - test value
UPSTREAM_REFRESH_TOKEN = "kc-refresh-8e1b6a2c4d0f"  # noqa: S105 - test value


@dataclass
class Browser:
    """Plays the browser and the upstream sign-in for one ``/authorize`` URL."""

    client: TestClient
    error: str | None = None
    tamper: Callable[[str], str] | None = None
    follow: bool = True
    opened: list[str] = field(default_factory=list)

    def __call__(self, url: str) -> None:
        self.opened.append(url)
        if not self.follow:
            return
        authorize = self.client.get(url, follow_redirects=False)
        assert authorize.status_code == 302, authorize.text
        upstream_state = parse_qs(urlsplit(authorize.headers["location"]).query)["state"][0]
        params = {"state": upstream_state}
        if self.error:
            params["error"] = self.error
        else:
            params["code"] = "kc-upstream-code"
        callback = self.client.get("/callback", params=params, follow_redirects=False)
        assert callback.status_code == 302, callback.text
        target = callback.headers["location"]
        if self.tamper is not None:
            target = self.tamper(target)
        httpx.get(target, timeout=5)


def mock_upstream(router) -> None:
    """The upstream token endpoint the proxy redeems the code at; loopback passes through."""

    router.route(host="127.0.0.1").pass_through()
    router.post(UPSTREAM_TOKEN).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": OWNER_ACCESS_TOKEN,
                "refresh_token": UPSTREAM_REFRESH_TOKEN,
                "expires_in": 300,
                "token_type": "Bearer",
                "scope": "openid",
            },
        )
    )


def recorded(client: TestClient) -> list[tuple[str, str]]:
    """Every request the command sends through ``client``, as (method, path)."""

    calls: list[tuple[str, str]] = []
    client.event_hooks = {"request": [lambda r: calls.append((r.method, r.url.path))]}
    return calls


def common_args(*extra: str) -> list[str]:
    return ["--proxy", PROXY, "--resource", RESOURCE, "--timeout", "5", *extra]
