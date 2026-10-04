# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""End to end: the proxy, a real PostgreSQL and a real Keycloak of the production version.

The proxy runs as a uvicorn server on the host; Keycloak runs in a container and
fetches the proxy's JWKS through ``host.docker.internal``. Owner tokens come
from an interactive-equivalent sign-in (password grant on a test-only public
client), so they carry a session like a browser sign-in does.

Each test names the gate it measures. The gates enforced by Keycloak — disabled
owner, foreign signing key, roles outside the set, rotation — can only be
measured here.
"""

from __future__ import annotations

import base64
import json
import logging
import socket
import threading
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
import uvicorn
from starlette.testclient import TestClient

from cimd_proxy.app import create_app
from cimd_proxy.config import load_config
from cimd_proxy.pat import ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE

from ..pat_fakes import write_rsa_key
from .conftest import SCHEMA, Database, docker_or_skip

pytestmark = pytest.mark.integration

KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.7.4"  # Kumbuka-ai/keycloak Dockerfile
REALM = "pat-it"
RES_X = "https://res-x.example"
RES_Y = "https://res-y.example"


def _claims(jwt: str) -> dict:
    part = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]


class Admin:
    def __init__(self, base: str) -> None:
        self.base = base
        self.http = httpx.Client(timeout=120)

    def token(self) -> str:
        r = self.http.post(
            f"{self.base}/realms/master/protocol/openid-connect/token",
            data={
                "client_id": "admin-cli",
                "username": "admin",
                "password": "admin",
                "grant_type": "password",
            },
        )
        r.raise_for_status()
        return r.json()["access_token"]

    def __call__(self, method: str, path: str, **kw) -> httpx.Response:
        r = self.http.request(
            method,
            f"{self.base}/admin/realms{path}",
            headers={"Authorization": f"Bearer {self.token()}"},
            **kw,
        )
        if r.status_code >= 400:
            raise AssertionError(f"{method} {path}: {r.status_code} {r.text}")
        return r

    def id_of(self, kind: str, **params) -> str:
        return self("GET", f"/{REALM}/{kind}", params=params).json()[0]["id"]


def _wait_http(url: str, timeout: float = 300) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            if httpx.get(url, timeout=3).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        if time.monotonic() > deadline:
            raise TimeoutError(f"{url} did not come up")
        time.sleep(2)


@dataclass
class World:
    kc: str
    realm_issuer: str
    admin: Admin
    proxy_url: str
    holder: dict
    env: dict
    key_dir: Path
    database: Database

    def owner_token(self, username: str) -> str:
        r = httpx.post(
            f"{self.realm_issuer}/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "owner-login",
                "username": username,
                "password": "pw",
                "scope": "openid",
            },
        )
        r.raise_for_status()
        return r.json()["access_token"]

    def proxy(self) -> httpx.Client:
        return httpx.Client(base_url=self.proxy_url, timeout=30)

    def serve(self, **overrides: str) -> None:
        """Swap the app behind the running server: a restart with new configuration."""

        env = dict(self.env)
        env.update(overrides)
        self.holder["app"] = create_app(load_config(env))

    def user_id(self, username: str) -> str:
        return self.admin.id_of("users", username=username, exact="true")


class _Dispatcher:
    """ASGI app that forwards to whichever proxy app is current, running its lifespan."""

    def __init__(self, holder: dict) -> None:
        self.holder = holder

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            msg = await receive()
            await send({"type": "lifespan.shutdown.complete"})
            return
        app = self.holder["app"]
        if app not in self.holder["startup"]:
            # Enter the app's own lifespan: it opens the store and checks the schema.
            context = app.router.lifespan_context(app)
            await context.__aenter__()
            self.holder["startup"][app] = context
        await app(scope, receive, send)


def _setup_realm(admin: Admin, proxy_url: str) -> None:
    admin(
        "POST",
        "",
        json={
            "realm": REALM,
            "enabled": True,
            "organizationsEnabled": True,
            "roles": {"realm": [{"name": "r-memory"}, {"name": "dispatch-executor"}]},
            "users": [
                {
                    "username": name,
                    "enabled": True,
                    "email": f"{name}@example.test",
                    "emailVerified": True,
                    "firstName": name,
                    "lastName": "Probe",
                    "credentials": [{"type": "password", "value": "pw", "temporary": False}],
                    "realmRoles": roles,
                }
                for name, roles in (
                    ("alice", ["r-memory", "dispatch-executor"]),
                    ("bob", ["r-memory"]),
                    ("carol", ["r-memory", "dispatch-executor"]),
                    ("dave", ["r-memory"]),
                )
            ],
            "clients": [
                {
                    "clientId": "owner-login",
                    "publicClient": True,
                    "directAccessGrantsEnabled": True,
                    "standardFlowEnabled": False,
                },
                {
                    "clientId": "cimd-proxy-admin",
                    "publicClient": False,
                    "secret": "it-admin-secret",
                    "serviceAccountsEnabled": True,
                    "standardFlowEnabled": False,
                    # Owner tokens are not audienced for the admin client; Keycloak
                    # 26.7 then answers introspection with active=false (measured).
                    "attributes": {"allow.token.introspection.without.audience.check": "true"},
                },
                *(
                    {
                        "clientId": f"{name}-pat",
                        "publicClient": False,
                        "secret": f"it-{name}-secret",
                        "standardFlowEnabled": False,
                        "fullScopeAllowed": False,
                        "attributes": {
                            "oauth2.jwt.authorization.grant.enabled": "true",
                            "oauth2.jwt.authorization.grant.idp": "cimd-proxy-pat",
                            "access.token.lifespan": "300",
                        },
                        "protocolMappers": [
                            {
                                "name": "aud",
                                "protocol": "openid-connect",
                                "protocolMapper": "oidc-audience-mapper",
                                "config": {
                                    "included.custom.audience": url,
                                    "access.token.claim": "true",
                                },
                            }
                        ],
                    }
                    for name, url in (("res-x", RES_X), ("res-y", RES_Y))
                ),
            ],
            "identityProviders": [
                {
                    "alias": "cimd-proxy-pat",
                    "providerId": "jwt-authorization-grant",
                    "enabled": True,
                    "config": {
                        "issuer": proxy_url,
                        "jwtAuthorizationGrantEnabled": "true",
                        "useJwksUrl": "true",
                        "jwksUrl": f"{proxy_url}/pat/jwks.json",
                        "jwtAuthorizationGrantAssertionSignatureAlg": "RS256",
                        "jwtAuthorizationGrantAllowedClockSkew": "5",
                    },
                }
            ],
        },
    )
    # The admin client may link users (manage-users) — that is the right it needs.
    sa = admin(
        "GET",
        f"/{REALM}/clients/{admin.id_of('clients', clientId='cimd-proxy-admin')}"
        "/service-account-user",
    ).json()
    rm = admin.id_of("clients", clientId="realm-management")
    role = admin("GET", f"/{REALM}/clients/{rm}/roles/manage-users").json()
    admin("POST", f"/{REALM}/users/{sa['id']}/role-mappings/clients/{rm}", json=[role])
    # Client scopes after the import: an import with its own scope list drops the built-ins.
    org_scope = next(
        s["id"]
        for s in admin("GET", f"/{REALM}/client-scopes").json()
        if s["name"] == "organization"
    )
    for scope, role_name in (("set-memory", "r-memory"), ("set-dispatch", "dispatch-executor")):
        admin(
            "POST",
            f"/{REALM}/client-scopes",
            json={
                "name": scope,
                "protocol": "openid-connect",
                "attributes": {"include.in.token.scope": "true"},
            },
        )
        sid = next(
            s["id"] for s in admin("GET", f"/{REALM}/client-scopes").json() if s["name"] == scope
        )
        realm_role = admin("GET", f"/{REALM}/roles/{role_name}").json()
        admin("POST", f"/{REALM}/client-scopes/{sid}/scope-mappings/realm", json=[realm_role])
        for client in ("res-x-pat", "res-y-pat"):
            cid = admin.id_of("clients", clientId=client)
            admin("PUT", f"/{REALM}/clients/{cid}/optional-client-scopes/{sid}")
    for client in ("res-x-pat", "res-y-pat"):
        cid = admin.id_of("clients", clientId=client)
        admin("PUT", f"/{REALM}/clients/{cid}/optional-client-scopes/{org_scope}")
    # The owner's interactive token names the owner's organizations, as in production.
    # It arrives as an optional scope; a PUT as default leaves it optional, so detach it first.
    login = admin.id_of("clients", clientId="owner-login")
    admin("DELETE", f"/{REALM}/clients/{login}/optional-client-scopes/{org_scope}")
    admin("PUT", f"/{REALM}/clients/{login}/default-client-scopes/{org_scope}")
    admin(
        "POST",
        f"/{REALM}/organizations",
        json={
            "name": "tenant-a",
            "alias": "tenant-a",
            "enabled": True,
            "domains": [{"name": "tenant-a.example.test"}],
        },
    )
    admin(
        "POST",
        f"/{REALM}/organizations",
        json={
            "name": "tenant-b",
            "alias": "tenant-b",
            "enabled": True,
            "domains": [{"name": "tenant-b.example.test"}],
        },
    )


def _add_member(world: World, org: str, username: str) -> None:
    oid = world.admin.id_of("organizations", search=org)
    world.admin("POST", f"/{REALM}/organizations/{oid}/members", json=world.user_id(username))


@pytest.fixture(scope="module")
def world(database: Database, tmp_path_factory) -> Iterator[World]:
    docker_or_skip()
    from testcontainers.core.container import DockerContainer

    port = _free_port()
    proxy_url = f"http://host.docker.internal:{port}"
    container = (
        DockerContainer(KEYCLOAK_IMAGE)
        .with_env("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
        .with_env("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
        .with_command("start-dev --features=cimd")
        .with_exposed_ports(8080)
        .with_kwargs(extra_hosts={"host.docker.internal": "host-gateway"})
    )
    container.start()
    server = None
    try:
        kc = f"http://{container.get_container_host_ip()}:{container.get_exposed_port(8080)}"
        _wait_http(f"{kc}/realms/master")
        admin = Admin(kc)
        _setup_realm(admin, proxy_url)
        realm_issuer = f"{kc}/realms/{REALM}"

        key_dir = tmp_path_factory.mktemp("pat-keys")
        for kid in ("key-a", "key-b", "foreign"):
            write_rsa_key(key_dir / f"{kid}.pem")
        env = {
            "PROXY_PUBLIC_URL": proxy_url,
            "PROXY_SECRET_KEY": base64.urlsafe_b64encode(b"k" * 32).decode(),
            "LOG_LEVEL": "INFO",
            "RESOURCE_0_URL": RES_X,
            "RESOURCE_0_ISSUER": realm_issuer,
            "RESOURCE_0_CLIENT_ID": "res-x-interactive",
            "RESOURCE_0_PAT_CLIENT_ID": "res-x-pat",
            "RESOURCE_0_PAT_CLIENT_SECRET": "it-res-x-secret",
            "RESOURCE_1_URL": RES_Y,
            "RESOURCE_1_ISSUER": realm_issuer,
            "RESOURCE_1_CLIENT_ID": "res-y-interactive",
            "RESOURCE_1_PAT_CLIENT_ID": "res-y-pat",
            "RESOURCE_1_PAT_CLIENT_SECRET": "it-res-y-secret",
            "PAT_DATABASE_URL": database.app_dsn,
            "PAT_DATABASE_SCHEMA": SCHEMA,
            "PAT_REALM_ISSUER": realm_issuer,
            "PAT_IDP_ALIAS": "cimd-proxy-pat",
            "PAT_ADMIN_CLIENT_ID": "cimd-proxy-admin",
            "PAT_ADMIN_CLIENT_SECRET": "it-admin-secret",
            "PAT_SCOPES": "set-memory set-dispatch",
            "PAT_SIGNING_KEY_0_KID": "key-a",
            "PAT_SIGNING_KEY_0_FILE": str(key_dir / "key-a.pem"),
            "PAT_SIGNING_KID": "key-a",
        }
        holder: dict = {"app": create_app(load_config(env)), "startup": {}}
        server = uvicorn.Server(
            uvicorn.Config(_Dispatcher(holder), host="0.0.0.0", port=port, log_level="warning")
        )
        threading.Thread(target=server.run, daemon=True).start()
        _wait_http(f"http://127.0.0.1:{port}/healthz", timeout=30)
        world = World(
            kc=kc,
            realm_issuer=realm_issuer,
            admin=admin,
            proxy_url=f"http://127.0.0.1:{port}",
            holder=holder,
            env=env,
            key_dir=key_dir,
            database=database,
        )
        # Every owner but dave belongs to an organization: a token is bound to one.
        for username in ("alice", "bob", "carol"):
            _add_member(world, "tenant-a", username)
        yield world
    finally:
        if server is not None:
            server.should_exit = True
        container.stop()


def _create(world: World, username: str, **body) -> httpx.Response:
    payload = {"name": f"agent-{uuid.uuid4().hex[:6]}", "resources": [RES_X], "scopes": []}
    payload.update(body)
    with world.proxy() as c:
        return c.post(
            "/pat/tokens",
            json=payload,
            headers={"Authorization": f"Bearer {world.owner_token(username)}"},
        )


def _exchange(world: World, token: str, **extra) -> httpx.Response:
    form = {
        "grant_type": TOKEN_EXCHANGE,
        "subject_token": token,
        "subject_token_type": ACCESS_TOKEN_TYPE,
        **extra,
    }
    with world.proxy() as c:
        return c.post("/token", data=form)


def _roles(access_token: str) -> list[str]:
    return sorted(_claims(access_token).get("realm_access", {}).get("roles", []))


def test_target_picture_pat_in_short_token_out(world: World) -> None:
    """The operator's acceptance: PAT in, short token with exactly the set's roles out."""

    r = _create(world, "alice", scopes=["set-memory"])
    assert r.status_code == 201, r.text
    token = r.json()["token"]
    for _ in range(2):  # an agent exchanges again when the short token runs out
        x = _exchange(world, token)
        assert x.status_code == 200, x.text
        body = x.json()
        claims = _claims(body["access_token"])
        assert claims["sub"] == world.user_id("alice")
        assert claims["aud"] == RES_X
        assert _roles(body["access_token"]) == ["r-memory"]
        assert body["issued_token_type"] == ACCESS_TOKEN_TYPE
        assert body["expires_in"] == 300
        assert "refresh_token" not in body


def test_set_without_dispatch_executor_yields_no_such_role(world: World) -> None:
    without = _create(world, "alice", scopes=["set-memory"]).json()["token"]
    with_it = _create(world, "alice", scopes=["set-memory", "set-dispatch"]).json()["token"]
    assert "dispatch-executor" not in _roles(_exchange(world, without).json()["access_token"])
    assert "dispatch-executor" in _roles(_exchange(world, with_it).json()["access_token"])


def test_set_beyond_the_owner_cannot_be_created(world: World) -> None:
    r = _create(world, "bob", scopes=["set-memory", "set-dispatch"])
    assert r.status_code == 403, r.text
    assert "set-dispatch" in r.json()["error_description"]
    assert _create(world, "bob", scopes=["set-memory"]).status_code == 201


def test_disabled_owner_gets_no_token(world: World) -> None:
    token = _create(world, "carol", scopes=["set-memory"]).json()["token"]
    uid = world.user_id("carol")
    rep = world.admin("GET", f"/{REALM}/users/{uid}").json()
    world.admin("PUT", f"/{REALM}/users/{uid}", json={**rep, "enabled": False})
    try:
        r = _exchange(world, token)
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"
        assert "access_token" not in r.json()
    finally:
        world.admin("PUT", f"/{REALM}/users/{uid}", json={**rep, "enabled": True})
    assert _exchange(world, token).status_code == 200


def test_token_from_a_pat_cannot_manage_pats(world: World) -> None:
    token = _create(world, "alice").json()["token"]
    short = _exchange(world, token).json()["access_token"]
    assert "sid" not in _claims(short)
    assert "sid" in _claims(world.owner_token("alice"))
    with world.proxy() as c:
        r = c.get("/pat/tokens", headers={"Authorization": f"Bearer {short}"})
    assert r.status_code == 403


def test_resource_and_revocation(world: World) -> None:
    created = _create(world, "alice").json()
    assert _exchange(world, created["token"], resource=RES_Y).json()["error"] == "invalid_target"
    with world.proxy() as c:
        alice = {"Authorization": f"Bearer {world.owner_token('alice')}"}
        bob = {"Authorization": f"Bearer {world.owner_token('bob')}"}
        assert created["id"] not in [
            t["id"] for t in c.get("/pat/tokens", headers=bob).json()["tokens"]
        ]
        assert c.delete(f"/pat/tokens/{created['id']}", headers=bob).status_code == 404
        assert _exchange(world, created["token"]).status_code == 200
        assert c.delete(f"/pat/tokens/{created['id']}", headers=alice).status_code == 204
    assert _exchange(world, created["token"]).json()["error"] == "invalid_grant"


def test_owner_without_an_organization_gets_no_token(world: World) -> None:
    r = _create(world, "dave", scopes=["set-memory"])
    assert r.status_code == 403, r.text
    assert r.json()["error"] == "organization_required"
    assert "token" not in r.json()
    with world.proxy() as c:
        listed = c.get(
            "/pat/tokens", headers={"Authorization": f"Bearer {world.owner_token('dave')}"}
        )
    assert listed.json()["tokens"] == []


def test_tenant_a_never_yields_tenant_b(world: World) -> None:
    r = _create(world, "carol", scopes=["set-memory"])
    assert r.status_code == 201, r.text
    assert r.json()["tenant"] == "tenant-a"
    token = r.json()["token"]
    assert _claims(_exchange(world, token).json()["access_token"])["organization"] == ["tenant-a"]
    _add_member(world, "tenant-b", "carol")
    claims = _claims(_exchange(world, token).json()["access_token"])
    assert claims["organization"] == ["tenant-a"]


def test_assertion_with_a_foreign_key_yields_no_token(world: World) -> None:
    token = _create(world, "alice").json()["token"]
    # A second proxy that shares database and upstream but signs with a key that is
    # not in the JWKS the upstream reads — even under the published kid.
    env = dict(world.env, PAT_SIGNING_KEY_0_FILE=str(world.key_dir / "foreign.pem"))
    with TestClient(create_app(load_config(env))) as foreign:
        r = foreign.post(
            "/token",
            data={
                "grant_type": TOKEN_EXCHANGE,
                "subject_token": token,
                "subject_token_type": ACCESS_TOKEN_TYPE,
            },
        )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"
    assert "access_token" not in r.json()


def test_secret_is_in_no_log_and_no_dump(world: World) -> None:
    records: list[str] = []

    class Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(self.format(record))

    handler = Collect()
    logging.getLogger().addHandler(handler)
    try:
        created = _create(world, "alice", scopes=["set-memory"]).json()
        token = created["token"]
        _exchange(world, token)
        with world.proxy() as c:
            c.delete(
                f"/pat/tokens/{created['id']}",
                headers={"Authorization": f"Bearer {world.owner_token('alice')}"},
            )
        refused = _exchange(world, token)
    finally:
        logging.getLogger().removeHandler(handler)
    assert any("pat.exchanged" in r for r in records)  # the log did capture the run
    assert all(token not in r for r in records)
    assert token not in refused.text
    assert token not in world.database.dump()


def test_rotation_new_key_works_removed_key_does_not(world: World) -> None:
    key_b = {
        "PAT_SIGNING_KEY_1_KID": "key-b",
        "PAT_SIGNING_KEY_1_FILE": str(world.key_dir / "key-b.pem"),
    }
    token = _create(world, "alice").json()["token"]
    assert _exchange(world, token).status_code == 200  # signed with key-a

    # Publish key-b next to key-a and sign with it. Keycloak fetches an unknown kid
    # only when its last fetch is at least ~10 s old (measured), so wait that out.
    world.serve(**key_b, PAT_SIGNING_KID="key-b")
    time.sleep(11)
    r = _exchange(world, token)
    assert r.status_code == 200, r.text

    # Remove key-a. A proxy still holding key-a stands for a leaked old key.
    world.serve(
        PAT_SIGNING_KEY_0_KID="key-b",
        PAT_SIGNING_KEY_0_FILE=key_b["PAT_SIGNING_KEY_1_FILE"],
        PAT_SIGNING_KID="key-b",
    )
    with TestClient(create_app(load_config(world.env))) as old:
        form = {
            "grant_type": TOKEN_EXCHANGE,
            "subject_token": token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
        }
        # Keycloak keeps a known key until it reloads (measured): the operator
        # clears its key cache as part of the rotation.
        assert old.post("/token", data=form).status_code == 200
        world.admin("POST", f"/{REALM}/clear-keys-cache")
        refused = old.post("/token", data=form)
        assert refused.status_code == 400, refused.text
        assert refused.json()["error"] == "invalid_grant"
    assert _exchange(world, token).status_code == 200  # key-b still works
