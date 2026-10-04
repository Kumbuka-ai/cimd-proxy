# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""RP9 — the pat command line: the gates it stands behind.

(a) a permission set the owner may not carry gets no token: non-zero exit,
    nothing stored;
(b) no secret outside the one output: the personal access token appears on
    stdout exactly once and nowhere else, the owner's access token and the
    upstream refresh token appear nowhere -- not on stdout or stderr, not in a
    log record, not in a file under HOME or the temporary directory -- and no
    command takes a secret as an argument;
(c) an aborted sign-in creates nothing: an error in the redirect, a foreign
    state and a timeout all end the command before ``POST /pat/tokens``.

Each gate has a guarded run that must refuse, a control run with the refusing
condition removed that must admit, and a strict-xfail control that asserts the
refusal in the admitting state.
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx
import pytest
import respx
from starlette.testclient import TestClient

from cimd_proxy import pat_cli
from cimd_proxy.pat_format import token_hash

from ..pat_cli_harness import (
    OWNER_ACCESS_TOKEN,
    PROXY,
    UPSTREAM_REFRESH_TOKEN,
    Browser,
    common_args,
    mock_upstream,
    recorded,
)


@pytest.fixture
def world(pat_app_factory):
    app, store, keycloak = pat_app_factory()
    # The owner is bob, who holds the roles of set-memory and not of set-dispatch.
    keycloak.add_session(OWNER_ACCESS_TOKEN, "bob-sub", organization=["tenant-a"])

    def upstream(grant):
        kept = " ".join(s for s in grant.scope.split() if s != "set-dispatch")
        return httpx.Response(
            200,
            json={"access_token": "t", "token_type": "Bearer", "expires_in": 300, "scope": kept},
        )

    keycloak.respond = upstream
    client = TestClient(app, base_url=PROXY)
    with respx.mock(assert_all_called=False) as router:
        mock_upstream(router)
        yield client, store, keycloak


def _create(client, *args: str, browser: Browser | None = None) -> int:
    return pat_cli.create_main(
        common_args("--name", "agent", *args),
        http=client,
        open_browser=browser or Browser(client),
    )


# --- (a) a set beyond the owner ---------------------------------------------


class TestRP9SetBeyondOwner:
    def test_guarded_a_set_the_owner_cannot_carry_creates_nothing(self, world, capsys) -> None:
        client, store, _ = world
        rc = _create(client, "--set", "set-memory", "--set", "set-dispatch")
        out, err = capsys.readouterr()
        assert rc != 0
        assert out == ""
        assert "insufficient_scope" in err and "set-dispatch" in err
        assert store.rows == {}

    def test_bypass_a_set_within_the_owner_is_created(self, world, capsys) -> None:
        client, store, _ = world
        assert _create(client, "--set", "set-memory") == 0
        assert len(store.rows) == 1

    @pytest.mark.xfail(strict=True, reason="RP9 red control: a set within the owner is created.")
    def test_bypass_would_break_set_gate(self, world, capsys) -> None:
        client, store, _ = world
        _create(client, "--set", "set-memory")
        assert store.rows == {}


# --- (b) no secret outside the one output -----------------------------------


def _files_containing(roots: list[Path], needles: list[str]) -> list[str]:
    hits = []
    for root in roots:
        for path in root.rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                hits += [f"{path}: {n[:12]}…" for n in needles if n.encode() in data]
    return hits


class TestRP9SecretNowhere:
    @pytest.fixture
    def sandbox(self, tmp_path, monkeypatch, caplog):
        home, tmp = tmp_path / "home", tmp_path / "tmp"
        home.mkdir()
        tmp.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("TMPDIR", str(tmp))
        monkeypatch.setattr(tempfile, "tempdir", str(tmp))
        caplog.set_level(logging.DEBUG)
        return [home, tmp]

    def test_guarded_secrets_appear_only_in_the_one_output(
        self, world, capsys, caplog, sandbox
    ) -> None:
        client, store, _ = world
        argv = common_args("--name", "agent", "--set", "set-memory")
        rc = pat_cli.create_main(argv, http=client, open_browser=Browser(client))
        out, err = capsys.readouterr()
        assert rc == 0, err
        token = out.strip()
        assert token_hash(token) in store.rows
        # The personal access token: on stdout, once, alone.
        assert out == token + "\n"
        assert token not in err
        assert token not in caplog.text
        # The owner's access token and the upstream refresh token: nowhere.
        for secret in (OWNER_ACCESS_TOKEN, UPSTREAM_REFRESH_TOKEN):
            assert secret not in out
            assert secret not in err
            assert secret not in caplog.text
        assert _files_containing(sandbox, [token, OWNER_ACCESS_TOKEN, UPSTREAM_REFRESH_TOKEN]) == []
        # No secret was an argument.
        assert all(s not in " ".join(argv) for s in (token, OWNER_ACCESS_TOKEN))

    def test_guarded_a_refusal_echoes_no_secret(self, world, capsys, caplog, sandbox) -> None:
        client, _, _ = world
        rc = _create(client, "--set", "set-dispatch")
        out, err = capsys.readouterr()
        assert rc != 0
        assert out == ""
        for secret in (OWNER_ACCESS_TOKEN, UPSTREAM_REFRESH_TOKEN):
            assert secret not in err
            assert secret not in caplog.text

    def test_guarded_no_command_takes_a_secret_argument(self) -> None:
        secretish = ("token", "secret", "password", "bearer", "credential", "assertion")
        for parser in (pat_cli._create_parser(), pat_cli._list_parser(), pat_cli._revoke_parser()):
            dests = {a.dest for a in parser._actions}
            assert not [d for d in dests if any(s in d.lower() for s in secretish)], parser.prog

    def test_bypass_the_one_output_does_carry_the_token(self, world, capsys) -> None:
        client, _, _ = world
        _create(client, "--set", "set-memory")
        assert capsys.readouterr().out.startswith("kmb_pat_")

    @pytest.mark.xfail(strict=True, reason="RP9 red control: stdout carries the token.")
    def test_bypass_would_break_secret_gate(self, world, capsys) -> None:
        client, _, _ = world
        _create(client, "--set", "set-memory")
        assert "kmb_pat_" not in capsys.readouterr().out


# --- (c) an aborted sign-in creates nothing -------------------------------------


def _foreign_state(target: str) -> str:
    parts = urlsplit(target)
    query = {k: v[0] for k, v in parse_qs(parts.query).items()}
    query["state"] = "a-state-this-process-never-sent"
    return urlunsplit(parts._replace(query=urlencode(query)))


ABORTED = {
    "error-in-redirect": ({"error": "access_denied"}, ()),
    "foreign-state": ({"tamper": _foreign_state}, ()),
    "timeout": ({"follow": False}, ("--timeout", "0.3")),
}


class TestRP9AbortedSignIn:
    @pytest.mark.parametrize("case", list(ABORTED))
    def test_guarded_an_aborted_sign_in_creates_nothing(self, world, capsys, case) -> None:
        client, store, keycloak = world
        calls = recorded(client)
        browser_kwargs, extra = ABORTED[case]
        rc = _create(client, *extra, browser=Browser(client, **browser_kwargs))
        out, err = capsys.readouterr()
        assert rc != 0
        assert out == ""
        assert "nothing was created" in err
        assert ("POST", "/pat/tokens") not in calls
        assert ("POST", "/token") not in calls  # the code is not even redeemed
        assert keycloak.introspections == 0
        assert store.rows == {}

    def test_bypass_a_completed_sign_in_creates(self, world, capsys) -> None:
        client, store, _ = world
        calls = recorded(client)
        assert _create(client) == 0
        assert ("POST", "/pat/tokens") in calls
        assert len(store.rows) == 1

    @pytest.mark.xfail(strict=True, reason="RP9 red control: a completed sign-in creates.")
    def test_bypass_would_break_sign_in_gate(self, world, capsys) -> None:
        client, _, _ = world
        calls = recorded(client)
        _create(client)
        assert ("POST", "/pat/tokens") not in calls
