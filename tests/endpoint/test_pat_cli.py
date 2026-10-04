# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""pat-create, pat-list and pat-revoke against the real proxy app.

The gates the command stands behind -- a set beyond the owner, no secret
outside the one output, nothing created after an aborted sign-in -- are the
red probes in ``tests/red_probes/test_rp9_pat_cli.py``. This file covers the
flow and its edges.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx
from starlette.testclient import TestClient

from cimd_proxy import pat_cli
from cimd_proxy.pat_format import token_hash

from ..pat_cli_harness import (
    OWNER_ACCESS_TOKEN,
    PROXY,
    RESOURCE,
    Browser,
    common_args,
    mock_upstream,
    recorded,
)


@pytest.fixture
def world(pat_app_factory):
    app, store, keycloak = pat_app_factory()
    keycloak.add_session(OWNER_ACCESS_TOKEN, "alice-sub", organization=["tenant-a"])
    client = TestClient(app, base_url=PROXY)
    with respx.mock(assert_all_called=False) as router:
        mock_upstream(router)
        yield client, store, keycloak


class TestCreate:
    def test_signs_in_through_the_proxy_and_prints_the_token_once(self, world, capsys) -> None:
        client, store, keycloak = world
        calls = recorded(client)
        browser = Browser(client)
        rc = pat_cli.create_main(
            common_args("--name", "nightly", "--set", "set-memory"),
            http=client,
            open_browser=browser,
        )
        out, err = capsys.readouterr()
        assert rc == 0, err
        token = out.strip()
        assert token.startswith("kmb_pat_")
        assert out == token + "\n"
        assert list(store.rows) == [token_hash(token)]
        record = store.rows[token_hash(token)]
        assert (record.name, record.scopes, record.resources) == (
            "nightly",
            ("set-memory",),
            (RESOURCE,),
        )
        assert "set-memory" in err and "tenant-a" in err
        # The interactive path of every MCP client: register, authorize, token, then manage.
        assert calls[:2] == [
            ("GET", "/.well-known/oauth-authorization-server"),
            ("POST", "/register"),
        ]
        assert ("POST", "/token") in calls
        assert calls[-1] == ("POST", "/pat/tokens")

    def test_without_set_it_asks_for_every_permitted_set(self, world, capsys) -> None:
        client, store, keycloak = world
        rc = pat_cli.create_main(
            common_args("--name", "all"), http=client, open_browser=Browser(client)
        )
        out, err = capsys.readouterr()
        assert rc == 0, err
        assert store.rows[token_hash(out.strip())].scopes == ("set-memory", "set-dispatch")
        assert keycloak.grants[-1].scope == "set-memory set-dispatch organization:tenant-a"

    def test_authorize_request_is_pkce_s256_on_a_loopback_redirect(self, world, capsys) -> None:
        client, _, _ = world
        browser = Browser(client)
        pat_cli.create_main(common_args("--name", "x"), http=client, open_browser=browser)
        query = {k: v[0] for k, v in parse_qs(urlsplit(browser.opened[0]).query).items()}
        assert query["code_challenge_method"] == "S256"
        assert len(query["code_challenge"]) == 43
        assert query["resource"] == RESOURCE
        assert query["scope"] == "openid"
        assert len(query["state"]) >= 43
        redirect = urlsplit(query["redirect_uri"])
        assert (redirect.scheme, redirect.hostname, redirect.path) == (
            "http",
            "127.0.0.1",
            "/callback",
        )
        assert redirect.port and redirect.port > 0

    def test_lifetime_organization_and_long_lifetime_reach_the_proxy(self, world, capsys) -> None:
        client, store, keycloak = world
        keycloak.add_session(OWNER_ACCESS_TOKEN, "alice-sub", organization=["tenant-a", "tenant-b"])
        rc = pat_cli.create_main(
            common_args(
                "--name",
                "long",
                "--expires-in-days",
                "400",
                "--allow-long-lifetime",
                "--organization",
                "tenant-b",
            ),
            http=client,
            open_browser=Browser(client),
        )
        out, err = capsys.readouterr()
        assert rc == 0, err
        record = store.rows[token_hash(out.strip())]
        assert record.tenant == "tenant-b"
        assert (record.expires_at - record.created_at).days == 400

    def test_a_refused_creation_names_the_reason_and_exits_non_zero(self, world, capsys) -> None:
        client, store, _ = world
        rc = pat_cli.create_main(
            common_args("--name", "x", "--expires-in-days", "400"),
            http=client,
            open_browser=Browser(client),
        )
        out, err = capsys.readouterr()
        assert rc == 1
        assert out == ""
        assert "invalid_request" in err and "allow_long_lifetime" in err
        assert store.rows == {}


class TestListAndRevoke:
    def test_list_shows_own_tokens_without_values(self, world, capsys) -> None:
        client, _, _ = world
        pat_cli.create_main(common_args("--name", "one"), http=client, open_browser=Browser(client))
        token = capsys.readouterr().out.strip()
        rc = pat_cli.list_main(common_args(), http=client, open_browser=Browser(client))
        out, err = capsys.readouterr()
        assert rc == 0, err
        assert "one" in out and "active" in out
        assert token not in out + err

    def test_revoke_revokes_and_a_second_revoke_is_refused(self, world, capsys) -> None:
        client, store, _ = world
        pat_cli.create_main(common_args("--name", "one"), http=client, open_browser=Browser(client))
        token = capsys.readouterr().out.strip()
        token_id = str(store.rows[token_hash(token)].id)
        rc = pat_cli.revoke_main(
            [*common_args(), token_id], http=client, open_browser=Browser(client)
        )
        assert rc == 0
        assert store.rows[token_hash(token)].revoked_at is not None
        capsys.readouterr()
        rc = pat_cli.revoke_main(
            [*common_args(), token_id], http=client, open_browser=Browser(client)
        )
        assert rc == 1
        assert "not_found" in capsys.readouterr().err


class TestSignInEdges:
    def test_a_redirect_from_another_issuer_is_refused(self, world, capsys) -> None:
        client, store, keycloak = world

        def other_issuer(target: str) -> str:
            return target.replace("iss=https%3A%2F%2Fmcp-auth.example", "iss=https%3A%2F%2Fevil")

        rc = pat_cli.create_main(
            common_args("--name", "x"),
            http=client,
            open_browser=Browser(client, tamper=other_issuer),
        )
        assert rc == 1
        assert "another issuer" in capsys.readouterr().err
        assert store.rows == {}
        assert keycloak.introspections == 0

    def test_the_loopback_listener_answers_one_redirect_only(self) -> None:
        with pat_cli.LoopbackReceiver() as receiver:
            base = receiver.redirect_uri
            assert httpx.get(base.replace("/callback", "/elsewhere")).status_code == 404
            assert httpx.get(f"{base}?code=a&state=s").status_code == 200
            assert httpx.get(f"{base}?code=b&state=t").status_code == 409
            assert receiver.wait(1) == {"code": "a", "state": "s"}

    def test_a_proxy_without_registration_is_refused(self, capsys) -> None:
        with respx.mock:
            respx.get(f"{PROXY}/.well-known/oauth-authorization-server").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "issuer": PROXY,
                        "authorization_endpoint": f"{PROXY}/authorize",
                        "token_endpoint": f"{PROXY}/token",
                        "code_challenge_methods_supported": ["S256"],
                    },
                )
            )
            rc = pat_cli.list_main(common_args(), open_browser=lambda _u: None)
        assert rc == 1
        assert "lacks an endpoint" in capsys.readouterr().err


class TestDiscovery:
    @respx.mock
    def test_the_proxy_is_found_from_the_resource_metadata(self) -> None:
        respx.get("https://mcp.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(
                200,
                json={"resource": "https://mcp.example/mcp", "authorization_servers": [PROXY]},
            )
        )
        with httpx.Client() as http:
            assert pat_cli.discover_proxy(http, "https://mcp.example/mcp") == PROXY

    @respx.mock
    def test_the_root_location_is_the_fallback(self) -> None:
        respx.get("https://mcp.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://mcp.example/.well-known/oauth-protected-resource").mock(
            return_value=httpx.Response(
                200,
                json={"resource": "https://mcp.example/mcp", "authorization_servers": [PROXY]},
            )
        )
        with httpx.Client() as http:
            assert pat_cli.discover_proxy(http, "https://mcp.example/mcp") == PROXY

    @pytest.mark.parametrize(
        ("document", "fragment"),
        [
            (
                {"resource": "https://other.example/mcp", "authorization_servers": [PROXY]},
                "another",
            ),
            ({"resource": "https://mcp.example/mcp", "authorization_servers": []}, "exactly one"),
            ({"resource": "https://mcp.example/mcp"}, "exactly one"),
        ],
    )
    @respx.mock
    def test_unusable_metadata_is_refused(self, document, fragment) -> None:
        respx.get("https://mcp.example/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(200, json=document)
        )
        with httpx.Client() as http, pytest.raises(pat_cli.CliError, match=fragment):
            pat_cli.discover_proxy(http, "https://mcp.example/mcp")

    @respx.mock
    def test_no_metadata_at_all_asks_for_the_proxy(self) -> None:
        respx.get(url__startswith="https://mcp.example/.well-known/").mock(
            return_value=httpx.Response(404)
        )
        with httpx.Client() as http, pytest.raises(pat_cli.CliError, match="--proxy"):
            pat_cli.discover_proxy(http, "https://mcp.example/mcp")

    @pytest.mark.parametrize(
        "url", ["http://auth.example", "ftp://auth.example", "https://", "http://10.0.0.1"]
    )
    def test_a_bearer_never_travels_in_clear(self, url) -> None:
        with httpx.Client() as http, pytest.raises(pat_cli.CliError, match="https"):
            pat_cli.read_endpoints(http, url)

    def test_a_resource_is_required(self, monkeypatch, capsys) -> None:
        monkeypatch.delenv(pat_cli.ENV_RESOURCE, raising=False)
        rc = pat_cli.list_main(["--proxy", PROXY], open_browser=lambda _u: None)
        assert rc == 1
        assert pat_cli.ENV_RESOURCE in capsys.readouterr().err

    def test_the_resource_may_come_from_the_environment(self, world, monkeypatch, capsys) -> None:
        client, _, _ = world
        monkeypatch.setenv(pat_cli.ENV_RESOURCE, RESOURCE)
        monkeypatch.setenv(pat_cli.ENV_PROXY, PROXY)
        rc = pat_cli.list_main([], http=client, open_browser=Browser(client))
        assert rc == 0, capsys.readouterr().err

    def test_an_unreachable_proxy_is_reported_without_detail(self, capsys) -> None:
        with respx.mock:
            respx.get(f"{PROXY}/.well-known/oauth-authorization-server").mock(
                side_effect=httpx.ConnectError("refused")
            )
            rc = pat_cli.list_main(common_args(), open_browser=lambda _u: None)
        assert rc == 1
        assert "ConnectError" in capsys.readouterr().err


def test_the_secret_holder_keeps_the_token_out_of_its_repr() -> None:
    endpoints = pat_cli.Endpoints("https://p", "https://p/a", "https://p/t", "https://p/r")
    session = pat_cli.SignedIn(endpoints=endpoints, access_token=OWNER_ACCESS_TOKEN)
    assert OWNER_ACCESS_TOKEN not in repr(session)
    assert session.headers == {"Authorization": f"Bearer {OWNER_ACCESS_TOKEN}"}


def test_the_commands_import_none_of_the_server_dependencies() -> None:
    import subprocess
    import sys

    probe = (
        "import sys, cimd_proxy.pat_cli; "
        "print(sorted(m for m in ('fastapi', 'starlette', 'psycopg', 'cryptography', 'uvicorn') "
        "if m in sys.modules))"
    )
    result = subprocess.run(  # noqa: S603 - fixed interpreter and argument
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "[]"
