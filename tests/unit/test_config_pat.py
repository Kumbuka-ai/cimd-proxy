# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest

from cimd_proxy.config import ConfigError, load_config

from ..pat_fakes import write_rsa_key


def test_without_database_url_the_feature_is_off(base_env: dict[str, str]) -> None:
    assert load_config(base_env).pat is None


def test_stray_pat_keys_without_database_url_are_loud(base_env: dict[str, str]) -> None:
    env = dict(base_env, PAT_SCOPES="set-memory")
    with pytest.raises(ConfigError, match="PAT_SCOPES set but PAT_DATABASE_URL is not"):
        load_config(env)
    env = dict(base_env, RESOURCE_0_PAT_CLIENT_ID="x", RESOURCE_0_PAT_CLIENT_SECRET="y")
    with pytest.raises(ConfigError, match="PAT_DATABASE_URL is not"):
        load_config(env)


def test_full_configuration_loads(pat_env: dict[str, str]) -> None:
    cfg = load_config(pat_env)
    assert cfg.pat is not None
    assert cfg.pat.database_schema == "cimd_proxy"
    assert cfg.pat.scopes == ("set-memory", "set-dispatch")
    assert cfg.pat.signer.issuer == "https://mcp-auth.example"
    assert cfg.pat.signer.active_kid == "key-a"
    assert [r.accepts_pat for r in cfg.resources] == [True, True, False]


def test_assertion_issuer_can_be_set(pat_env: dict[str, str]) -> None:
    cfg = load_config(dict(pat_env, PAT_ASSERTION_ISSUER="https://other.example"))
    assert cfg.pat is not None
    assert cfg.pat.signer.issuer == "https://other.example"


@pytest.mark.parametrize(
    "missing",
    [
        "PAT_REALM_ISSUER",
        "PAT_IDP_ALIAS",
        "PAT_ADMIN_CLIENT_ID",
        "PAT_ADMIN_CLIENT_SECRET",
        "PAT_SCOPES",
        "PAT_SIGNING_KID",
    ],
)
def test_each_required_value_is_loud(pat_env: dict[str, str], missing: str) -> None:
    env = dict(pat_env)
    del env[missing]
    with pytest.raises(ConfigError, match=missing):
        load_config(env)


def test_pat_client_id_and_secret_go_together(pat_env: dict[str, str]) -> None:
    env = dict(pat_env)
    del env["RESOURCE_1_PAT_CLIENT_SECRET"]
    with pytest.raises(ConfigError, match="set together"):
        load_config(env)


def test_no_resource_accepting_pats_is_loud(pat_env: dict[str, str]) -> None:
    env = {k: v for k, v in pat_env.items() if "_PAT_CLIENT_" not in k}
    with pytest.raises(ConfigError, match="no RESOURCE_n_PAT_CLIENT_ID"):
        load_config(env)


def test_pat_resource_on_another_realm_is_loud(pat_env: dict[str, str]) -> None:
    env = dict(pat_env, RESOURCE_1_ISSUER="https://issuer.example/realms/other")
    with pytest.raises(ConfigError, match="is not PAT_REALM_ISSUER"):
        load_config(env)


def test_schema_name_must_be_a_plain_identifier(pat_env: dict[str, str]) -> None:
    with pytest.raises(ConfigError, match="PAT_DATABASE_SCHEMA"):
        load_config(dict(pat_env, PAT_DATABASE_SCHEMA='x"; drop'))


def test_signing_keys_rotate_through_the_table(pat_env: dict[str, str], tmp_path) -> None:
    write_rsa_key(tmp_path / "b.pem")
    env = dict(
        pat_env,
        PAT_SIGNING_KEY_1_KID="key-b",
        PAT_SIGNING_KEY_1_FILE=str(tmp_path / "b.pem"),
        PAT_SIGNING_KID="key-b",
    )
    cfg = load_config(env)
    assert cfg.pat is not None
    assert [k["kid"] for k in cfg.pat.signer.jwks()["keys"]] == ["key-a", "key-b"]


def test_signing_key_table_gap_is_loud(pat_env: dict[str, str], tmp_path) -> None:
    write_rsa_key(tmp_path / "c.pem")
    env = dict(
        pat_env, PAT_SIGNING_KEY_2_KID="key-c", PAT_SIGNING_KEY_2_FILE=str(tmp_path / "c.pem")
    )
    with pytest.raises(ConfigError, match="gap at index 1"):
        load_config(env)


def test_signing_key_table_must_not_be_empty(pat_env: dict[str, str]) -> None:
    env = {k: v for k, v in pat_env.items() if not k.startswith("PAT_SIGNING_KEY_")}
    with pytest.raises(ConfigError, match="PAT_SIGNING_KEY_0_KID"):
        load_config(env)


def test_duplicate_kid_is_loud(pat_env: dict[str, str]) -> None:
    env = dict(
        pat_env,
        PAT_SIGNING_KEY_1_KID="key-a",
        PAT_SIGNING_KEY_1_FILE=pat_env["PAT_SIGNING_KEY_0_FILE"],
    )
    with pytest.raises(ConfigError, match="unique"):
        load_config(env)


def test_unreadable_or_invalid_key_file_is_loud(pat_env: dict[str, str], tmp_path) -> None:
    with pytest.raises(ConfigError, match="cannot be read"):
        load_config(dict(pat_env, PAT_SIGNING_KEY_0_FILE=str(tmp_path / "missing.pem")))
    (tmp_path / "junk.pem").write_text("junk")
    with pytest.raises(ConfigError, match="unencrypted PEM"):
        load_config(dict(pat_env, PAT_SIGNING_KEY_0_FILE=str(tmp_path / "junk.pem")))


def test_active_kid_must_be_configured(pat_env: dict[str, str]) -> None:
    with pytest.raises(ConfigError, match="not configured"):
        load_config(dict(pat_env, PAT_SIGNING_KID="key-z"))
