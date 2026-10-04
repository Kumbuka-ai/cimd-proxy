# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Management endpoints and the token exchange, over an in-memory store and a fake Keycloak."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from starlette.testclient import TestClient

from cimd_proxy.pat import ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE
from cimd_proxy.pat_format import token_hash

from ..pat_fakes import REALM, assertion_claims

AUTH = {"Authorization": "Bearer alice-session"}


@pytest.fixture
def pat(pat_app_factory):
    app, store, keycloak = pat_app_factory()
    keycloak.add_session("alice-session", "alice-sub", organization=["tenant-a"])
    keycloak.add_session("bob-session", "bob-sub", organization=["tenant-a"])
    return TestClient(app), store, keycloak


def _create(client: TestClient, headers=AUTH, **body):
    payload = {"name": "agent", "resources": ["https://log.example"], "scopes": ["set-memory"]}
    payload.update(body)
    return client.post("/pat/tokens", json=payload, headers=headers)


def _exchange(client: TestClient, token: str, **extra):
    form = {
        "grant_type": TOKEN_EXCHANGE,
        "subject_token": token,
        "subject_token_type": ACCESS_TOKEN_TYPE,
    }
    form.update(extra)
    return client.post("/token", data=form)


class TestCreate:
    def test_create_returns_the_token_once_and_stores_its_hash(self, pat) -> None:
        client, store, keycloak = pat
        r = _create(client)
        assert r.status_code == 201, r.text
        body = r.json()
        assert r.headers["cache-control"] == "no-store"
        token = body["token"]
        assert token.startswith("kmb_pat_")
        assert body["resources"] == ["https://log.example"]
        assert body["scopes"] == ["set-memory"]
        assert body["tenant"] == "tenant-a"
        created = datetime.fromisoformat(body["created_at"])
        assert datetime.fromisoformat(body["expires_at"]) - created == timedelta(days=90)
        assert list(store.rows) == [token_hash(token)]
        assert keycloak.links == {"alice-sub": "alice-sub"}
        trial = keycloak.grants[-1]
        assert (trial.client_id, trial.scope) == ("log-mcp-pat", "set-memory organization:tenant-a")
        assert assertion_claims(trial.assertion)["sub"] == "alice-sub"
        assert "token" not in client.get("/pat/tokens", headers=AUTH).json()["tokens"][0]

    def test_one_trial_exchange_per_resource(self, pat) -> None:
        client, _, keycloak = pat
        r = _create(client, resources=["https://log.example", "https://wlm.example"])
        assert r.status_code == 201
        assert [g.client_id for g in keycloak.grants] == ["log-mcp-pat", "wlm-mcp-pat"]

    def test_lifetime_can_be_chosen_and_long_lifetimes_need_saying_so(self, pat) -> None:
        client, _, _ = pat
        assert _create(client, expires_in_days=7).status_code == 201
        assert _create(client, expires_in_days=365).status_code == 201
        r = _create(client, expires_in_days=366)
        assert r.status_code == 400
        assert "allow_long_lifetime" in r.json()["error_description"]
        assert _create(client, expires_in_days=800, allow_long_lifetime=True).status_code == 201

    @pytest.mark.parametrize(
        ("body", "error"),
        [
            ({"name": ""}, "invalid_request"),
            ({"name": "x" * 101}, "invalid_request"),
            ({"resources": []}, "invalid_request"),
            ({"resources": "https://log.example"}, "invalid_request"),
            ({"resources": ["https://interactive-only.example"]}, "invalid_target"),
            ({"resources": ["https://unknown.example"]}, "invalid_target"),
            ({"scopes": ["offline_access"]}, "invalid_scope"),
            ({"expires_in_days": 0}, "invalid_request"),
            ({"expires_in_days": True}, "invalid_request"),
            ({"allow_long_lifetime": "yes"}, "invalid_request"),
            ({"organization": 5}, "invalid_request"),
        ],
    )
    def test_invalid_bodies_are_refused(self, pat, body, error) -> None:
        client, store, _ = pat
        r = _create(client, **body)
        assert r.status_code == 400
        assert r.json()["error"] == error
        assert store.rows == {}

    def test_non_object_body_is_refused(self, pat) -> None:
        client, _, _ = pat
        r = client.post("/pat/tokens", content=b"[]", headers=AUTH)
        assert r.status_code == 400
        r = client.post("/pat/tokens", content=b"not json", headers=AUTH)
        assert r.status_code == 400

    def test_trial_refusal_by_the_upstream_is_reported(self, pat) -> None:
        client, store, keycloak = pat
        keycloak.respond = lambda _g: httpx.Response(
            400, json={"error": "invalid_grant", "error_description": "User is not enabled"}
        )
        r = _create(client)
        assert r.status_code == 502
        assert "User is not enabled" in r.json()["error_description"]
        assert store.rows == {}

    def test_link_conflict_is_reported(self, pat) -> None:
        client, store, keycloak = pat
        keycloak.links["alice-sub"] = "someone-else"
        r = _create(client)
        assert r.status_code == 409
        assert store.rows == {}


class TestTenant:
    def test_single_organization_binds_the_token(self, pat) -> None:
        client, _, keycloak = pat
        keycloak.add_session("carol-session", "carol-sub", organization=["tenant-a"])
        r = _create(client, headers={"Authorization": "Bearer carol-session"})
        assert r.status_code == 201
        assert r.json()["tenant"] == "tenant-a"
        assert keycloak.grants[-1].scope == "set-memory organization:tenant-a"

    def test_organization_map_claim_is_read_by_alias(self, pat) -> None:
        client, _, keycloak = pat
        keycloak.add_session("carol-session", "carol-sub", organization={"tenant-a": {}})
        r = _create(client, headers={"Authorization": "Bearer carol-session"})
        assert r.json()["tenant"] == "tenant-a"

    def test_several_organizations_need_a_choice(self, pat) -> None:
        client, _, keycloak = pat
        keycloak.add_session("dave-session", "dave-sub", organization=["tenant-a", "tenant-b"])
        headers = {"Authorization": "Bearer dave-session"}
        assert _create(client, headers=headers).status_code == 400
        r = _create(client, headers=headers, organization="tenant-b")
        assert r.status_code == 201
        assert r.json()["tenant"] == "tenant-b"

    def test_a_foreign_organization_cannot_be_chosen(self, pat) -> None:
        client, _, keycloak = pat
        keycloak.add_session("carol-session", "carol-sub", organization="tenant-a")
        r = _create(
            client, headers={"Authorization": "Bearer carol-session"}, organization="tenant-b"
        )
        assert r.status_code == 403


class TestAuthentication:
    @pytest.mark.parametrize("header", [None, "Basic abc", "Bearer ", "Bearer unknown"])
    def test_missing_or_inactive_bearer_is_401(self, pat, header) -> None:
        client, _, _ = pat
        headers = {"Authorization": header} if header is not None else {}
        r = client.get("/pat/tokens", headers=headers)
        assert r.status_code == 401
        assert r.headers["www-authenticate"].startswith("Bearer")

    def test_token_from_another_realm_is_401(self, pat) -> None:
        client, _, keycloak = pat
        keycloak.add_session("x", "eve", iss="https://issuer.example/realms/other")
        assert client.get("/pat/tokens", headers={"Authorization": "Bearer x"}).status_code == 401

    def test_refresh_token_is_not_an_access_token(self, pat) -> None:
        client, _, keycloak = pat
        keycloak.add_session("x", "eve", typ="Refresh")
        assert client.get("/pat/tokens", headers={"Authorization": "Bearer x"}).status_code == 401

    def test_token_without_session_cannot_manage(self, pat) -> None:
        client, _, keycloak = pat
        keycloak.add_session("pat-derived", "alice-sub", sid=None)
        r = client.get("/pat/tokens", headers={"Authorization": "Bearer pat-derived"})
        assert r.status_code == 403

    def test_personal_access_token_as_bearer_is_refused_unasked(self, pat) -> None:
        client, _, keycloak = pat
        token = _create(client).json()["token"]
        before = keycloak.introspections
        r = client.get("/pat/tokens", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403
        assert keycloak.introspections == before


class TestListAndRevoke:
    def test_list_shows_only_own_tokens_without_secret(self, pat) -> None:
        client, _, _ = pat
        _create(client, name="mine")
        _create(client, headers={"Authorization": "Bearer bob-session"}, name="bobs")
        listed = client.get("/pat/tokens", headers=AUTH).json()["tokens"]
        assert [t["name"] for t in listed] == ["mine"]
        assert "token" not in listed[0]
        assert "token_hash" not in listed[0]

    def test_revoke_own_token(self, pat) -> None:
        client, _, _ = pat
        token_id = _create(client).json()["id"]
        assert client.delete(f"/pat/tokens/{token_id}", headers=AUTH).status_code == 204
        listed = client.get("/pat/tokens", headers=AUTH).json()["tokens"]
        assert listed[0]["revoked_at"] is not None
        assert client.delete(f"/pat/tokens/{token_id}", headers=AUTH).status_code == 404

    def test_revoke_of_a_malformed_id_is_404(self, pat) -> None:
        client, _, _ = pat
        assert client.delete("/pat/tokens/not-a-uuid", headers=AUTH).status_code == 404


class TestExchange:
    def test_exchange_yields_the_upstream_token_without_refresh(self, pat) -> None:
        client, store, keycloak = pat
        token = _create(client).json()["token"]
        keycloak.respond = lambda g: httpx.Response(
            200,
            json={
                "access_token": "short",
                "token_type": "Bearer",
                "expires_in": 300,
                "refresh_token": "never-to-the-agent",
                "refresh_expires_in": 1800,
                "scope": g.scope,
            },
        )
        r = _exchange(client, token)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["access_token"] == "short"
        assert body["issued_token_type"] == ACCESS_TOKEN_TYPE
        assert "refresh_token" not in body
        assert "refresh_expires_in" not in body
        assert r.headers["cache-control"] == "no-store"
        grant = keycloak.grants[-1]
        assert (grant.client_id, grant.client_secret) == ("log-mcp-pat", "pat-client-secret")
        assert grant.scope == "set-memory organization:tenant-a"
        claims = assertion_claims(grant.assertion)
        assert (claims["sub"], claims["aud"]) == ("alice-sub", REALM)
        assert store.by_id(_list_id(client)).last_used_at is not None

    def test_tenant_token_requests_its_organization(self, pat) -> None:
        client, _, keycloak = pat
        keycloak.add_session("carol-session", "carol-sub", organization=["tenant-a"])
        token = _create(client, headers={"Authorization": "Bearer carol-session"}).json()["token"]
        assert _exchange(client, token).status_code == 200
        assert keycloak.grants[-1].scope == "set-memory organization:tenant-a"

    def test_resource_is_required_when_the_token_names_several(self, pat) -> None:
        client, _, keycloak = pat
        token = _create(client, resources=["https://log.example", "https://wlm.example"]).json()[
            "token"
        ]
        r = _exchange(client, token)
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_target"
        r = _exchange(client, token, resource="https://wlm.example")
        assert r.status_code == 200
        assert keycloak.grants[-1].client_id == "wlm-mcp-pat"

    def test_upstream_refusal_is_passed_through(self, pat) -> None:
        client, _, keycloak = pat
        token = _create(client).json()["token"]
        keycloak.respond = lambda _g: httpx.Response(
            400, json={"error": "invalid_grant", "error_description": "User is not enabled"}
        )
        r = _exchange(client, token)
        assert r.status_code == 400
        assert r.json() == {"error": "invalid_grant", "error_description": "User is not enabled"}

    def test_upstream_server_failure_is_a_502(self, pat) -> None:
        client, _, keycloak = pat
        token = _create(client).json()["token"]
        keycloak.respond = lambda _g: httpx.Response(503, json={"error": "unavailable"})
        assert _exchange(client, token).status_code == 502
        keycloak.respond = lambda _g: httpx.Response(200, text="<html>")
        assert _exchange(client, token).status_code == 502
        keycloak.respond = lambda _g: httpx.Response(200, json=["not", "an", "object"])
        assert _exchange(client, token).status_code == 502

    @pytest.mark.parametrize(
        ("form", "fragment"),
        [
            ({"subject_token": ""}, "missing subject_token"),
            ({"subject_token_type": "urn:x"}, "subject_token_type"),
            ({"requested_token_type": "urn:ietf:params:oauth:token-type:id_token"}, "requested"),
        ],
    )
    def test_malformed_exchange_requests(self, pat, form, fragment) -> None:
        client, _, _ = pat
        token = _create(client).json()["token"]
        r = _exchange(client, token, **form)
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_request"
        assert fragment in r.json()["error_description"]

    def test_unknown_token_is_invalid_grant(self, pat) -> None:
        from cimd_proxy.pat_format import generate

        client, _, _ = pat
        r = _exchange(client, generate())
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"

    def test_token_from_another_realm_row_is_refused(self, pat) -> None:
        from dataclasses import replace

        client, store, _ = pat
        token = _create(client).json()["token"]
        h = token_hash(token)
        store.rows[h] = replace(store.rows[h], realm_issuer="https://issuer.example/realms/other")
        assert _exchange(client, token).json()["error"] == "invalid_grant"


def _list_id(client: TestClient) -> str:
    return client.get("/pat/tokens", headers=AUTH).json()["tokens"][0]["id"]


class TestDiscoveryAndJwks:
    def test_discovery_names_the_exchange_grant_only_when_configured(
        self, pat, client: TestClient
    ) -> None:
        pat_client, _, _ = pat
        for path in (
            "/.well-known/oauth-authorization-server",
            "/.well-known/openid-configuration",
        ):
            assert TOKEN_EXCHANGE in pat_client.get(path).json()["grant_types_supported"]
            assert TOKEN_EXCHANGE not in client.get(path).json()["grant_types_supported"]

    def test_jwks_publishes_public_keys_only(self, pat) -> None:
        client, _, _ = pat
        keys = client.get("/pat/jwks.json").json()["keys"]
        assert [k["kid"] for k in keys] == ["key-a"]
        assert "d" not in keys[0]
        assert "p" not in keys[0]

    def test_pat_routes_are_absent_without_configuration(self, client: TestClient) -> None:
        assert client.get("/pat/jwks.json").status_code == 404
        assert client.get("/pat/tokens").status_code == 404

    def test_exchange_grant_is_unknown_without_configuration(self, client: TestClient) -> None:
        r = client.post("/token", data={"grant_type": TOKEN_EXCHANGE, "subject_token": "x"})
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_request"

    def test_unknown_grant_names_the_exchange_when_configured(self, pat) -> None:
        client, _, _ = pat
        r = client.post("/token", data={"grant_type": "client_credentials"})
        assert r.status_code == 400
        assert TOKEN_EXCHANGE in r.json()["error_description"]


def test_expired_rows_are_refused_with_a_reason(pat) -> None:
    from dataclasses import replace

    client, store, _ = pat
    token = _create(client).json()["token"]
    h = token_hash(token)
    store.rows[h] = replace(store.rows[h], expires_at=datetime.now(UTC) - timedelta(seconds=1))
    r = _exchange(client, token)
    assert r.json() == {
        "error": "invalid_grant",
        "error_description": "the personal access token is expired",
    }
