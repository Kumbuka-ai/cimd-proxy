# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Measure the Keycloak JWT Authorization Grant (RFC 7523) against a local container.

Not part of the proxy and not part of the test suite. It answers, against a
running Keycloak, whether the grant can carry personal access tokens:

  1. is the feature on without a flag, and at what maturity
  2. does a proxy-signed assertion, verified through a JWKS URL, yield a token
  3. how the assertion is matched to a user, and what right linking needs
  4. can the roles of the issued token be cut down per request
  5. disabled user, foreign key, expired assertion are refused
  6. lifetime of the issued token, and whether a refresh token comes along
  7. key rotation: new key accepted, removed key refused
  8. tenants as Keycloak organizations: which organization the issued token names,
     and which session markers it carries

Every probe runs ``--runs`` times (default 2) and the outcomes must agree.

Usage (Keycloak 26.7.4 on localhost:18080, admin/admin):

    docker run -d --name kc-jag -p 18080:8080 \\
      -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \\
      --add-host host.docker.internal:host-gateway \\
      quay.io/keycloak/keycloak:26.7.4 start-dev --features=cimd
    python measurements/jwt-authorization-grant/probe.py
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

HERE = Path(__file__).parent
ISSUER = "https://proxy.example.test"
REALM = "jag"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class Key:
    def __init__(self, kid: str) -> None:
        self.kid = kid
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwk(self) -> dict[str, str]:
        nums = self.private.public_key().public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": b64u(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
            "e": b64u(nums.e.to_bytes(3, "big")),
        }

    def sign(self, claims: dict[str, Any], kid: str | None = None) -> str:
        header = {"alg": "RS256", "typ": "JWT", "kid": kid or self.kid}
        signing_input = f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(claims).encode())}"
        sig = self.private.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input}.{b64u(sig)}"


class JwksServer:
    """Serves a mutable JWKS document; Keycloak fetches it through host.docker.internal."""

    def __init__(self, port: int) -> None:
        self.keys: list[Key] = []
        self.hits = 0
        self.started = time.monotonic()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                outer.hits += 1
                print(
                    f"    [jwks fetch #{outer.hits} at +{time.monotonic() - outer.started:.1f}s, "
                    f"serving {[k.kid for k in outer.keys]}]"
                )
                body = json.dumps({"keys": [k.jwk() for k in outer.keys]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: Any) -> None:
                return

        self.httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()


def jwt_claims(token: str) -> dict[str, Any]:
    return json.loads(b64u_decode(token.split(".")[1]))


class Probe:
    def __init__(self, kc: str, jwks_url: str, jwks: JwksServer) -> None:
        self.kc = kc.rstrip("/")
        self.jwks_url = jwks_url
        self.jwks = jwks
        self.http = httpx.Client(timeout=30)
        self.realm_issuer = f"{self.kc}/realms/{REALM}"
        self.token_endpoint = f"{self.realm_issuer}/protocol/openid-connect/token"

    # --- admin ------------------------------------------------------------
    def admin_token(self) -> str:
        r = self.http.post(
            f"{self.kc}/realms/master/protocol/openid-connect/token",
            data={
                "client_id": "admin-cli",
                "username": "admin",
                "password": "admin",
                "grant_type": "password",
            },
        )
        r.raise_for_status()
        return r.json()["access_token"]

    def admin(self, method: str, path: str, token: str | None = None, **kw: Any) -> httpx.Response:
        headers = {"Authorization": f"Bearer {token or self.admin_token()}"}
        return self.http.request(method, f"{self.kc}/admin/realms{path}", headers=headers, **kw)

    def setup_realm(self) -> None:
        self.admin("DELETE", f"/{REALM}")
        realm = json.loads((HERE / "realm.json").read_text())
        realm["identityProviders"][0]["config"]["jwksUrl"] = self.jwks_url
        r = self.admin("POST", "", json=realm)
        if r.status_code != 201:
            sys.exit(f"realm import failed: {r.status_code} {r.text}")
        # Client scopes are created after the import: a realm import that carries
        # its own clientScopes list replaces the built-in ones (roles, basic, ...).
        for scope, role in (("set-memory", "r-memory"), ("set-dispatch", "dispatch-executor")):
            self.admin(
                "POST",
                f"/{REALM}/client-scopes",
                json={
                    "name": scope,
                    "protocol": "openid-connect",
                    "attributes": {
                        "include.in.token.scope": "true",
                        "display.on.consent.screen": "false",
                    },
                },
            ).raise_for_status()
            sid = next(
                s["id"]
                for s in self.admin("GET", f"/{REALM}/client-scopes").json()
                if s["name"] == scope
            )
            role_rep = self.admin("GET", f"/{REALM}/roles/{role}").json()
            self.admin(
                "POST", f"/{REALM}/client-scopes/{sid}/scope-mappings/realm", json=[role_rep]
            ).raise_for_status()
            for client in ("up-x", "up-y"):
                cid = self.client_uuid(client)
                self.admin(
                    "PUT", f"/{REALM}/clients/{cid}/optional-client-scopes/{sid}"
                ).raise_for_status()

    def setup_organizations(self) -> None:
        rep = self.admin("GET", f"/{REALM}").json()
        rep["organizationsEnabled"] = True
        self.admin("PUT", f"/{REALM}", json=rep).raise_for_status()
        for org, member in (("tenant-a", "alice"), ("tenant-b", "bob")):
            self.admin(
                "POST",
                f"/{REALM}/organizations",
                json={
                    "name": org,
                    "alias": org,
                    "enabled": True,
                    "domains": [{"name": f"{org}.example.test"}],
                },
            ).raise_for_status()
            self.add_org_member(org, member)
        sid = next(
            s["id"]
            for s in self.admin("GET", f"/{REALM}/client-scopes").json()
            if s["name"] == "organization"
        )
        self.admin(
            "PUT", f"/{REALM}/clients/{self.client_uuid('up-x')}/default-client-scopes/{sid}"
        ).raise_for_status()

    def add_org_member(self, org: str, member: str) -> None:
        orgs = self.admin("GET", f"/{REALM}/organizations", params={"search": org}).json()
        self.admin(
            "POST", f"/{REALM}/organizations/{orgs[0]['id']}/members", json=self.user_id(member)
        ).raise_for_status()

    def client_uuid(self, client_id: str) -> str:
        clients = self.admin("GET", f"/{REALM}/clients", params={"clientId": client_id}).json()
        return clients[0]["id"]

    def clear_keys_cache(self) -> None:
        self.admin("POST", f"/{REALM}/clear-keys-cache").raise_for_status()

    def user_id(self, username: str) -> str:
        r = self.admin("GET", f"/{REALM}/users", params={"username": username, "exact": "true"})
        return r.json()[0]["id"]

    def set_user_enabled(self, username: str, enabled: bool) -> None:
        uid = self.user_id(username)
        rep = self.admin("GET", f"/{REALM}/users/{uid}").json()
        rep["enabled"] = enabled
        self.admin("PUT", f"/{REALM}/users/{uid}", json=rep).raise_for_status()

    def set_client_attr(self, client_id: str, key: str, value: str) -> None:
        cid = self.client_uuid(client_id)
        rep = self.admin("GET", f"/{REALM}/clients/{cid}").json()
        rep.setdefault("attributes", {})[key] = value
        self.admin("PUT", f"/{REALM}/clients/{cid}", json=rep).raise_for_status()

    def grant_proxy_admin_role(self, role: str) -> None:
        sa_user = self.admin(
            "GET", f"/{REALM}/clients/{self.client_uuid('proxy-admin')}/service-account-user"
        ).json()
        rm = {"id": self.client_uuid("realm-management")}
        role_rep = self.admin("GET", f"/{REALM}/clients/{rm['id']}/roles/{role}").json()
        self.admin(
            "POST",
            f"/{REALM}/users/{sa_user['id']}/role-mappings/clients/{rm['id']}",
            json=[role_rep],
        ).raise_for_status()

    def proxy_admin_token(self) -> str:
        r = self.http.post(
            self.token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": "proxy-admin",
                "client_secret": "measurement-only-proxy-admin",
            },
        )
        r.raise_for_status()
        return r.json()["access_token"]

    def link(self, username: str, token: str, external_id: str | None = None) -> int:
        uid = self.user_id(username)
        r = self.admin(
            "POST",
            f"/{REALM}/users/{uid}/federated-identity/pat-issuer",
            token=token,
            json={
                "identityProvider": "pat-issuer",
                "userId": external_id or uid,
                "userName": username,
            },
        )
        return r.status_code

    def unlink(self, username: str) -> None:
        uid = self.user_id(username)
        self.admin("DELETE", f"/{REALM}/users/{uid}/federated-identity/pat-issuer")

    # --- grant ------------------------------------------------------------
    def assertion(
        self,
        key: Key,
        sub: str,
        *,
        exp_in: int = 60,
        kid: str | None = None,
        aud: str | None = None,
        jti: str | None = None,
        iss: str = ISSUER,
    ) -> str:
        now = int(time.time())
        return key.sign(
            {
                "iss": iss,
                "sub": sub,
                "aud": aud or self.realm_issuer,
                "iat": now,
                "exp": now + exp_in,
                "jti": jti or str(uuid.uuid4()),
            },
            kid=kid,
        )

    def grant(
        self, assertion: str, *, client: str = "up-x", scope: str | None = None
    ) -> tuple[int, dict[str, Any]]:
        form = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
            "client_id": client,
            "client_secret": f"measurement-only-{client}",
        }
        if scope is not None:
            form["scope"] = scope
        r = self.http.post(self.token_endpoint, data=form)
        return r.status_code, r.json()


def summarise(status: int, body: dict[str, Any]) -> str:
    if status != 200:
        return f"{status} {body.get('error')} {body.get('error_description')!r}"
    c = jwt_claims(body["access_token"])
    roles = sorted(c.get("realm_access", {}).get("roles", []))
    return (
        f"200 sub={c.get('sub')} azp={c.get('azp')} aud={c.get('aud')} roles={roles} "
        f"scope={c.get('scope')!r} exp-iat={c['exp'] - c['iat']} "
        f"refresh_token={'present' if 'refresh_token' in body else 'absent'}"
    )


def claims_line(status: int, body: dict[str, Any]) -> str:
    if status != 200:
        return f"{status} {body.get('error')} {body.get('error_description')!r}"
    c = jwt_claims(body["access_token"])
    return (
        f"200 organization={c.get('organization')} sid={'present' if 'sid' in c else 'absent'} "
        f"typ={c.get('typ')} claims={sorted(c)}"
    )


def run(args: argparse.Namespace) -> int:
    jwks = JwksServer(args.jwks_port)
    key_a, key_b, key_a2 = Key("proxy-2026-a"), Key("foreign"), Key("proxy-2026-b")
    jwks.keys = [key_a]
    p = Probe(args.kc, f"http://{args.jwks_host}:{args.jwks_port}/jwks", jwks)
    p.setup_realm()
    results: dict[str, list[str]] = {}

    def record(name: str, fn: Any) -> None:
        outcomes = [fn() for _ in range(args.runs)]
        results[name] = outcomes
        agree = "agree" if len(set(outcomes)) == 1 else "DISAGREE"
        print(f"[{agree}] {name}")
        for i, o in enumerate(outcomes, 1):
            print(f"    run {i}: {o}")

    alice, bob, carol = p.user_id("alice"), p.user_id("bob"), p.user_id("carol")

    # 3. linking needs a right: none, view-users, manage-users
    record(
        "3a link alice with no realm-management role",
        lambda: f"HTTP {p.link('alice', p.proxy_admin_token())}",
    )
    p.grant_proxy_admin_role("view-users")
    record(
        "3b link alice with view-users", lambda: f"HTTP {p.link('alice', p.proxy_admin_token())}"
    )
    p.grant_proxy_admin_role("manage-users")

    def link_then_unlink(user: str) -> str:
        code = p.link(user, p.proxy_admin_token())
        p.unlink(user)
        return f"HTTP {code}"

    record(
        "3c link carol with manage-users (then unlinked again)", lambda: link_then_unlink("carol")
    )
    assert p.link("alice", p.proxy_admin_token()) == 204
    assert p.link("bob", p.proxy_admin_token()) == 204

    # 2. trust: a proxy-signed assertion through the JWKS URL
    record("2 alice, key A, no scope", lambda: summarise(*p.grant(p.assertion(key_a, alice))))

    # 3. user matching
    record(
        "3d carol unlinked, sub = her Keycloak id",
        lambda: summarise(*p.grant(p.assertion(key_a, carol))),
    )
    record(
        "3e sub = username 'alice' (link carries the Keycloak id)",
        lambda: summarise(*p.grant(p.assertion(key_a, "alice"))),
    )

    # 4. permission set per request
    for scope in ("set-memory", "set-dispatch", "set-memory set-dispatch"):
        record(
            f"4 alice scope={scope!r}",
            lambda s=scope: summarise(*p.grant(p.assertion(key_a, alice), scope=s)),
        )
    record(
        "4 bob scope='set-memory set-dispatch' (bob holds no dispatch-executor)",
        lambda: summarise(*p.grant(p.assertion(key_a, bob), scope="set-memory set-dispatch")),
    )
    record(
        "4 alice scope='offline_access' (offline scope on the jwt grant)",
        lambda: summarise(*p.grant(p.assertion(key_a, alice), scope="offline_access")),
    )
    record(
        "4 alice scope='set-unknown'",
        lambda: summarise(*p.grant(p.assertion(key_a, alice), scope="set-unknown")),
    )
    record(
        "4 client up-y (grant not enabled there)",
        lambda: summarise(*p.grant(p.assertion(key_a, alice), client="up-y")),
    )

    # 5. refusals
    def disabled() -> str:
        p.set_user_enabled("alice", False)
        try:
            return summarise(*p.grant(p.assertion(key_a, alice)))
        finally:
            p.set_user_enabled("alice", True)

    record("5a alice disabled", disabled)
    record("5a' alice re-enabled", lambda: summarise(*p.grant(p.assertion(key_a, alice))))
    record("5b foreign key, own kid", lambda: summarise(*p.grant(p.assertion(key_b, alice))))
    record(
        "5b' foreign key, spoofed kid of key A",
        lambda: summarise(*p.grant(p.assertion(key_b, alice, kid=key_a.kid))),
    )
    record(
        "5c expired assertion (exp = now - 5)",
        lambda: summarise(*p.grant(p.assertion(key_a, alice, exp_in=-5))),
    )
    record(
        "5d assertion lifetime above the IdP maximum (exp = now + 3600)",
        lambda: summarise(*p.grant(p.assertion(key_a, alice, exp_in=3600))),
    )

    def reuse() -> str:
        a = p.assertion(key_a, alice)
        first = summarise(*p.grant(a)).split()[0]
        return f"first={first} second={summarise(*p.grant(a))}"

    record("5e same assertion twice", reuse)
    record(
        "5f wrong issuer",
        lambda: summarise(*p.grant(p.assertion(key_a, alice, iss="https://evil.test"))),
    )

    # 6. lifetime
    for lifespan in ("60", "300"):
        p.set_client_attr("up-x", "access.token.lifespan", lifespan)
        record(
            f"6 access.token.lifespan={lifespan}",
            lambda: summarise(*p.grant(p.assertion(key_a, alice), scope="set-memory")),
        )

    # 7. rotation
    jwks.keys = [key_a, key_a2]
    record(
        "7a JWKS {A, A2} at once: new key A2",
        lambda: summarise(*p.grant(p.assertion(key_a2, alice))),
    )
    print(f"    (waiting {args.rotation_wait}s)")
    time.sleep(args.rotation_wait)
    record(
        f"7b JWKS {{A, A2}} after {args.rotation_wait}s: new key A2",
        lambda: summarise(*p.grant(p.assertion(key_a2, alice))),
    )
    record("7c JWKS {A, A2}: old key A", lambda: summarise(*p.grant(p.assertion(key_a, alice))))
    jwks.keys = [key_a2]
    print(f"    (A removed from the JWKS; waiting {args.rotation_wait}s)")
    time.sleep(args.rotation_wait)
    record(
        f"7d JWKS {{A2}} after {args.rotation_wait}s: removed key A",
        lambda: summarise(*p.grant(p.assertion(key_a, alice))),
    )
    p.clear_keys_cache()
    record(
        "7e JWKS {A2} after clear-keys-cache: removed key A",
        lambda: summarise(*p.grant(p.assertion(key_a, alice))),
    )
    record(
        "7f JWKS {A2} after clear-keys-cache: key A2",
        lambda: summarise(*p.grant(p.assertion(key_a2, alice))),
    )
    # 8. tenants as organizations, and session markers
    p.setup_organizations()
    record(
        "8a alice (member of tenant-a), no scope",
        lambda: claims_line(*p.grant(p.assertion(key_a2, alice))),
    )
    record(
        "8b alice, scope='organization:tenant-b' (not a member)",
        lambda: claims_line(*p.grant(p.assertion(key_a2, alice), scope="organization:tenant-b")),
    )
    record(
        "8c bob (member of tenant-b), no scope",
        lambda: claims_line(*p.grant(p.assertion(key_a2, bob))),
    )
    p.add_org_member("tenant-b", "alice")
    record(
        "8d alice member of tenant-a and tenant-b, no scope",
        lambda: claims_line(*p.grant(p.assertion(key_a2, alice))),
    )
    record(
        "8e alice member of both, scope='organization:tenant-a'",
        lambda: claims_line(*p.grant(p.assertion(key_a2, alice), scope="organization:tenant-a")),
    )
    p.set_client_attr("up-y", "oauth2.jwt.authorization.grant.enabled", "true")
    p.set_client_attr("up-y", "oauth2.jwt.authorization.grant.idp", "pat-issuer")
    record(
        "8f client up-y without the organization scope, scope='organization:tenant-a'",
        lambda: claims_line(
            *p.grant(p.assertion(key_a2, alice), client="up-y", scope="organization:tenant-a")
        ),
    )
    print(f"JWKS fetches by Keycloak: {jwks.hits}")

    disagreements = [k for k, v in results.items() if len(set(v)) != 1]
    if disagreements:
        print(f"DISAGREEING PROBES: {disagreements}")
        return 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--kc", default="http://localhost:18080")
    ap.add_argument("--jwks-host", default="host.docker.internal")
    ap.add_argument("--jwks-port", type=int, default=18099)
    ap.add_argument("--runs", type=int, default=2)
    ap.add_argument("--rotation-wait", type=int, default=15)
    return run(ap.parse_args())


if __name__ == "__main__":
    sys.exit(main())
