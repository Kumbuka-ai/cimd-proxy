# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import httpx
import pytest
import respx

from cimd_proxy.errors import ServerError
from cimd_proxy.keycloak import Caller, KeycloakClient, LinkConflict

ISSUER = "https://kc.example/realms/x"
TOKEN = f"{ISSUER}/protocol/openid-connect/token"
LINKS = "https://kc.example/admin/realms/x/users/u-1/federated-identity"
CALLER = Caller(subject="u-1", username="alice", organizations=())


@pytest.fixture
def kc() -> KeycloakClient:
    return KeycloakClient(
        realm_issuer=ISSUER,
        admin_client_id="admin",
        admin_client_secret="s",
        idp_alias="pat-idp",
    )


def _admin_login(router: respx.Router) -> None:
    router.post(TOKEN, data={"grant_type": "client_credentials"}).mock(
        return_value=httpx.Response(200, json={"access_token": "admin-at"})
    )


def test_issuer_must_be_a_realm() -> None:
    with pytest.raises(ValueError, match="realm issuer"):
        KeycloakClient(
            realm_issuer="https://kc.example",
            admin_client_id="a",
            admin_client_secret="s",
            idp_alias="i",
        )


@respx.mock
async def test_introspection_uses_client_credentials(kc: KeycloakClient) -> None:
    route = respx.post(f"{TOKEN}/introspect").mock(
        return_value=httpx.Response(200, json={"active": True, "sub": "u-1"})
    )
    assert (await kc.introspect("owner-at"))["sub"] == "u-1"
    request = route.calls.last.request
    assert request.headers["authorization"].startswith("Basic ")
    assert b"token=owner-at" in request.content


@respx.mock
async def test_introspection_failure_is_a_server_error(kc: KeycloakClient) -> None:
    respx.post(f"{TOKEN}/introspect").mock(return_value=httpx.Response(401))
    with pytest.raises(ServerError, match="HTTP 401"):
        await kc.introspect("owner-at")


@respx.mock
async def test_unreachable_upstream_names_no_detail(kc: KeycloakClient) -> None:
    respx.post(f"{TOKEN}/introspect").mock(side_effect=httpx.ConnectError("boom owner-at"))
    with pytest.raises(ServerError) as exc:
        await kc.introspect("owner-at")
    assert "owner-at" not in exc.value.description


@respx.mock
async def test_existing_link_is_kept(kc: KeycloakClient) -> None:
    _admin_login(respx)
    respx.get(LINKS).mock(
        return_value=httpx.Response(200, json=[{"identityProvider": "pat-idp", "userId": "u-1"}])
    )
    create = respx.post(f"{LINKS}/pat-idp")
    await kc.ensure_link(CALLER)
    assert not create.called


@respx.mock
async def test_missing_link_is_created_with_sub_as_external_id(kc: KeycloakClient) -> None:
    _admin_login(respx)
    respx.get(LINKS).mock(
        return_value=httpx.Response(200, json=[{"identityProvider": "google", "userId": "g"}])
    )
    create = respx.post(f"{LINKS}/pat-idp").mock(return_value=httpx.Response(204))
    await kc.ensure_link(CALLER)
    body = create.calls.last.request.content
    assert b'"userId":"u-1"' in body.replace(b" ", b"")
    assert create.calls.last.request.headers["authorization"] == "Bearer admin-at"


@respx.mock
async def test_link_under_another_id_is_a_conflict(kc: KeycloakClient) -> None:
    _admin_login(respx)
    respx.get(LINKS).mock(
        return_value=httpx.Response(200, json=[{"identityProvider": "pat-idp", "userId": "x"}])
    )
    with pytest.raises(LinkConflict):
        await kc.ensure_link(CALLER)


@pytest.mark.parametrize(
    ("login", "read", "create", "message"),
    [
        (401, 200, 204, "admin client login failed"),
        (200, 403, 204, "reading the owner's identity links failed"),
        (200, 200, 403, "linking the owner failed"),
    ],
)
@respx.mock
async def test_link_failures_are_server_errors(kc, login, read, create, message) -> None:
    respx.post(TOKEN, data={"grant_type": "client_credentials"}).mock(
        return_value=httpx.Response(login, json={"access_token": "admin-at"})
    )
    respx.get(LINKS).mock(return_value=httpx.Response(read, json=[]))
    respx.post(f"{LINKS}/pat-idp").mock(return_value=httpx.Response(create))
    with pytest.raises(ServerError, match=message):
        await kc.ensure_link(CALLER)


@respx.mock
async def test_link_network_failure_is_a_server_error(kc: KeycloakClient) -> None:
    _admin_login(respx)
    respx.get(LINKS).mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(ServerError, match="unreachable"):
        await kc.ensure_link(CALLER)


@respx.mock
async def test_jwt_bearer_grant_form(kc: KeycloakClient) -> None:
    route = respx.post(TOKEN).mock(return_value=httpx.Response(200, json={}))
    await kc.jwt_bearer_grant(client_id="c", client_secret="s", assertion="a.b.c", scope="x y")
    form = dict(httpx.QueryParams(route.calls.last.request.content.decode()))
    assert form == {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": "a.b.c",
        "client_id": "c",
        "client_secret": "s",
        "scope": "x y",
    }
    await kc.jwt_bearer_grant(client_id="c", client_secret="s", assertion="a.b.c", scope="")
    assert "scope" not in dict(httpx.QueryParams(route.calls.last.request.content.decode()))
