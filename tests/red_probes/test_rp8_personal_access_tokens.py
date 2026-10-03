# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""RP8 — personal access tokens: the gates the proxy itself enforces.

Each gate has a guarded run that must refuse, a control run with the refusing
condition removed that must admit, and a strict-xfail control that asserts the
refusal in the admitting state — the recorded red state of the gate.

Gates that the upstream enforces (disabled owner, foreign signing key, roles
outside the set, key rotation) are measured against a real Keycloak in
``tests/integration/test_pat_keycloak.py``.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from starlette.testclient import TestClient

from cimd_proxy.pat import ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE
from cimd_proxy.pat_format import token_hash

ALICE = {"Authorization": "Bearer alice-session"}
BOB = {"Authorization": "Bearer bob-session"}


@pytest.fixture
def pat(pat_app_factory):
    app, store, keycloak = pat_app_factory()
    keycloak.add_session("alice-session", "alice-sub")
    keycloak.add_session("bob-session", "bob-sub")
    keycloak.add_session("carol-session", "carol-sub", organization=["tenant-a"])
    return TestClient(app), store, keycloak


def _create(client, headers=ALICE, **body) -> dict:
    payload = {"name": "agent", "resources": ["https://log.example"], "scopes": ["set-memory"]}
    payload.update(body)
    r = client.post("/pat/tokens", json=payload, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()


def _exchange(client, token: str, **extra):
    form = {
        "grant_type": TOKEN_EXCHANGE,
        "subject_token": token,
        "subject_token_type": ACCESS_TOKEN_TYPE,
    }
    form.update(extra)
    return client.post("/token", data=form)


def _set(store, token: str, **changes) -> None:
    h = token_hash(token)
    store.rows[h] = replace(store.rows[h], **changes)


class TestRP8RevokedAndExpired:
    def test_guarded_refuses_revoked(self, pat) -> None:
        client, _, _ = pat
        created = _create(client)
        assert client.delete(f"/pat/tokens/{created['id']}", headers=ALICE).status_code == 204
        r = _exchange(client, created["token"])
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"

    def test_guarded_refuses_expired(self, pat) -> None:
        client, store, _ = pat
        token = _create(client)["token"]
        _set(store, token, expires_at=datetime.now(UTC) - timedelta(seconds=1))
        r = _exchange(client, token)
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"

    def test_bypass_admits_live_token(self, pat) -> None:
        client, _, _ = pat
        assert _exchange(client, _create(client)["token"]).status_code == 200

    @pytest.mark.xfail(strict=True, reason="RP8 red control: a live token is admitted.")
    def test_bypass_would_break_revocation_gate(self, pat) -> None:
        client, _, _ = pat
        r = _exchange(client, _create(client)["token"])
        assert r.status_code == 400


class TestRP8ChecksumWithoutDatabase:
    def test_guarded_refuses_bad_checksum_unasked(self, pat) -> None:
        client, store, _ = pat
        token = _create(client)["token"]
        store.calls.clear()
        mistyped = token[:-1] + ("A" if token[-1] != "A" else "B")
        r = _exchange(client, mistyped)
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"
        assert store.calls == []

    def test_bypass_asks_the_store_for_a_well_formed_token(self, pat) -> None:
        client, store, _ = pat
        token = _create(client)["token"]
        store.calls.clear()
        _exchange(client, token)
        assert store.calls[0] == "find_by_hash"

    @pytest.mark.xfail(
        strict=True, reason="RP8 red control: a well-formed token reaches the store."
    )
    def test_bypass_would_break_checksum_gate(self, pat) -> None:
        client, store, _ = pat
        token = _create(client)["token"]
        store.calls.clear()
        _exchange(client, token)
        assert store.calls == []


class TestRP8ResourceBinding:
    def test_guarded_token_for_x_gets_nothing_for_y(self, pat) -> None:
        client, _, keycloak = pat
        token = _create(client, resources=["https://log.example"])["token"]
        grants_before = len(keycloak.grants)
        r = _exchange(client, token, resource="https://wlm.example")
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_target"
        assert len(keycloak.grants) == grants_before

    def test_bypass_admits_when_token_names_y(self, pat) -> None:
        client, _, keycloak = pat
        token = _create(client, resources=["https://log.example", "https://wlm.example"])["token"]
        r = _exchange(client, token, resource="https://wlm.example")
        assert r.status_code == 200
        assert keycloak.grants[-1].client_id == "wlm-mcp-pat"

    @pytest.mark.xfail(strict=True, reason="RP8 red control: a token naming Y is admitted for Y.")
    def test_bypass_would_break_resource_gate(self, pat) -> None:
        client, _, _ = pat
        token = _create(client, resources=["https://log.example", "https://wlm.example"])["token"]
        assert _exchange(client, token, resource="https://wlm.example").status_code == 400


class TestRP8Tenant:
    def test_guarded_tenant_token_requests_only_its_organization(self, pat) -> None:
        client, _, keycloak = pat
        token = _create(client, headers={"Authorization": "Bearer carol-session"})["token"]
        # carol joins tenant-b later; the token stays bound to tenant-a.
        keycloak.add_session("carol-session", "carol-sub", organization=["tenant-a", "tenant-b"])
        assert _exchange(client, token).status_code == 200
        scope = keycloak.grants[-1].scope.split()
        assert "organization:tenant-a" in scope
        assert not any(
            s.startswith("organization:") and s != "organization:tenant-a" for s in scope
        )

    def test_guarded_row_of_another_realm_is_refused(self, pat) -> None:
        client, store, keycloak = pat
        token = _create(client)["token"]
        _set(store, token, realm_issuer="https://issuer.example/realms/other")
        grants_before = len(keycloak.grants)
        assert _exchange(client, token).json()["error"] == "invalid_grant"
        assert len(keycloak.grants) == grants_before

    def test_bypass_token_without_tenant_requests_no_organization(self, pat) -> None:
        client, _, keycloak = pat
        token = _create(client)["token"]
        assert _exchange(client, token).status_code == 200
        assert "organization" not in keycloak.grants[-1].scope

    @pytest.mark.xfail(strict=True, reason="RP8 red control: no tenant, no organization scope.")
    def test_bypass_would_break_tenant_gate(self, pat) -> None:
        client, _, keycloak = pat
        token = _create(client)["token"]
        _exchange(client, token)
        assert "organization:" in keycloak.grants[-1].scope


class TestRP8ForeignOwner:
    def test_guarded_other_user_neither_sees_nor_revokes(self, pat) -> None:
        client, store, _ = pat
        created = _create(client)
        assert client.get("/pat/tokens", headers=BOB).json()["tokens"] == []
        assert client.delete(f"/pat/tokens/{created['id']}", headers=BOB).status_code == 404
        assert store.by_id(created["id"]).revoked_at is None

    def test_bypass_owner_sees_and_revokes(self, pat) -> None:
        client, _, _ = pat
        created = _create(client)
        assert len(client.get("/pat/tokens", headers=ALICE).json()["tokens"]) == 1
        assert client.delete(f"/pat/tokens/{created['id']}", headers=ALICE).status_code == 204

    @pytest.mark.xfail(strict=True, reason="RP8 red control: the owner can revoke.")
    def test_bypass_would_break_owner_gate(self, pat) -> None:
        client, _, _ = pat
        created = _create(client)
        assert client.delete(f"/pat/tokens/{created['id']}", headers=ALICE).status_code == 404


def _with_refresh(grant):
    return httpx.Response(
        200,
        json={
            "access_token": "short",
            "token_type": "Bearer",
            "expires_in": 300,
            "refresh_token": "upstream-refresh",
            "refresh_expires_in": 1800,
            "scope": grant.scope,
        },
    )


class TestRP8NoRefreshToken:
    def test_guarded_refresh_token_never_reaches_the_agent(self, pat) -> None:
        client, _, keycloak = pat
        token = _create(client)["token"]
        keycloak.respond = _with_refresh
        r = _exchange(client, token)
        assert r.status_code == 200
        assert "refresh_token" not in r.json()
        assert "upstream-refresh" not in r.text

    def test_bypass_upstream_did_send_one(self, pat) -> None:
        _client, _, keycloak = pat
        keycloak.respond = _with_refresh
        assert "refresh_token" in _with_refresh(type("G", (), {"scope": ""})()).json()

    @pytest.mark.xfail(strict=True, reason="RP8 red control: the upstream response carries one.")
    def test_bypass_would_break_refresh_gate(self, pat) -> None:
        assert "refresh_token" not in _with_refresh(type("G", (), {"scope": ""})()).json()


def _dropping(scope_to_drop: str):
    def respond(grant):
        kept = " ".join(s for s in grant.scope.split() if s != scope_to_drop)
        return httpx.Response(
            200,
            json={"access_token": "t", "token_type": "Bearer", "expires_in": 300, "scope": kept},
        )

    return respond


class TestRP8SetBeyondOwner:
    def test_guarded_set_the_owner_cannot_carry_is_refused(self, pat) -> None:
        client, store, keycloak = pat
        keycloak.respond = _dropping("set-dispatch")  # the upstream drops what bob cannot hold
        r = client.post(
            "/pat/tokens",
            json={
                "name": "agent",
                "resources": ["https://log.example"],
                "scopes": ["set-memory", "set-dispatch"],
            },
            headers=BOB,
        )
        assert r.status_code == 403
        assert "set-dispatch" in r.json()["error_description"]
        assert store.rows == {}

    def test_bypass_set_within_the_owner_is_created(self, pat) -> None:
        client, _, keycloak = pat
        keycloak.respond = _dropping("set-dispatch")
        _create(client, headers=BOB, scopes=["set-memory"])

    @pytest.mark.xfail(strict=True, reason="RP8 red control: a set within the owner is created.")
    def test_bypass_would_break_set_gate(self, pat) -> None:
        client, store, keycloak = pat
        keycloak.respond = _dropping("set-dispatch")
        client.post(
            "/pat/tokens",
            json={"name": "a", "resources": ["https://log.example"], "scopes": ["set-memory"]},
            headers=BOB,
        )
        assert store.rows == {}


class TestRP8SecretNowhere:
    def test_guarded_token_value_is_in_no_row_log_or_error(self, pat, caplog) -> None:
        client, store, keycloak = pat
        caplog.set_level(logging.DEBUG)
        created = _create(client)
        token = created["token"]
        _exchange(client, token)
        client.delete(f"/pat/tokens/{created['id']}", headers=ALICE)
        refused = _exchange(client, token)  # revoked now: an error that must not echo it
        listed = client.get("/pat/tokens", headers=ALICE)
        haystacks = [
            caplog.text,
            refused.text,
            listed.text,
            repr(list(store.rows.values())),
            repr([g.__dict__ for g in keycloak.grants]),
        ]
        assert all(token not in h for h in haystacks)
        assert token_hash(token) in store.rows

    def test_bypass_the_creation_response_does_carry_it(self, pat) -> None:
        client, _, _ = pat
        created = _create(client)
        assert created["token"].startswith("kmb_pat_")

    @pytest.mark.xfail(strict=True, reason="RP8 red control: the creation response holds it.")
    def test_bypass_would_break_secret_gate(self, pat) -> None:
        client, _, _ = pat
        r = client.post(
            "/pat/tokens",
            json={"name": "a", "resources": ["https://log.example"], "scopes": []},
            headers=ALICE,
        )
        assert "kmb_pat_" not in r.text
