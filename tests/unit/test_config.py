# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest

from cimd_proxy.config import ConfigError, load_config
from cimd_proxy.config import _normalise_requested_url as _normalise


def _min_env(**overrides: str) -> dict[str, str]:
    env = {
        "PROXY_PUBLIC_URL": "https://x.example",
        "PROXY_SECRET_KEY": "unused-secret",
        "CIMD_ALLOWED_DOMAINS": "claude.ai",
        "RESOURCE_0_URL": "https://a.example",
        "RESOURCE_0_ISSUER": "https://issuer.example",
        "RESOURCE_0_CLIENT_ID": "cid0",
    }
    env.update(overrides)
    return env


class TestRequired:
    @pytest.mark.parametrize(
        "missing",
        [
            "PROXY_PUBLIC_URL",
            "PROXY_SECRET_KEY",
            "CIMD_ALLOWED_DOMAINS",
            "RESOURCE_0_URL",
            "RESOURCE_0_ISSUER",
            "RESOURCE_0_CLIENT_ID",
        ],
    )
    def test_missing_required_fails_loud(self, missing: str) -> None:
        env = _min_env()
        env.pop(missing, None)
        with pytest.raises(ConfigError, match=missing):
            load_config(env)


class TestResourceTable:
    def test_gap_refused(self) -> None:
        env = _min_env(
            RESOURCE_2_URL="https://b.example",
            RESOURCE_2_ISSUER="https://issuer.example",
            RESOURCE_2_CLIENT_ID="cid2",
        )
        with pytest.raises(ConfigError, match="gap at index 1"):
            load_config(env)

    def test_contiguous_indices_are_loaded_in_order(self) -> None:
        env = _min_env(
            RESOURCE_1_URL="https://b.example",
            RESOURCE_1_ISSUER="https://issuer.example",
            RESOURCE_1_CLIENT_ID="cid1",
        )
        cfg = load_config(env)
        assert [r.url for r in cfg.resources] == [
            "https://a.example",
            "https://b.example",
        ]

    def test_secret_optional_marks_public(self) -> None:
        cfg = load_config(_min_env())
        assert cfg.resources[0].is_public is True

    def test_default_resource_must_be_in_table(self) -> None:
        env = _min_env(DEFAULT_RESOURCE="https://unknown.example")
        with pytest.raises(ConfigError, match="DEFAULT_RESOURCE"):
            load_config(env)


class TestScopesConfig:
    def test_default_scopes_supported(self) -> None:
        cfg = load_config(_min_env())
        assert cfg.scopes_supported == ("openid", "offline_access")

    def test_scopes_supported_explicit(self) -> None:
        cfg = load_config(_min_env(PROXY_SCOPES_SUPPORTED="openid profile email"))
        assert cfg.scopes_supported == ("openid", "profile", "email")

    def test_scopes_supported_empty_is_tuple_of_zero(self) -> None:
        cfg = load_config(_min_env(PROXY_SCOPES_SUPPORTED=""))
        assert cfg.scopes_supported == ()

    def test_scopes_supported_whitespace_only_is_tuple_of_zero(self) -> None:
        cfg = load_config(_min_env(PROXY_SCOPES_SUPPORTED="  \t\n  "))
        assert cfg.scopes_supported == ()

    def test_default_scope_default(self) -> None:
        cfg = load_config(_min_env())
        assert cfg.default_scope == "openid offline_access"

    def test_default_scope_explicit(self) -> None:
        cfg = load_config(_min_env(PROXY_DEFAULT_SCOPE="openid"))
        assert cfg.default_scope == "openid"

    def test_default_scope_whitespace_normalised(self) -> None:
        cfg = load_config(_min_env(PROXY_DEFAULT_SCOPE="  openid    offline_access\t"))
        assert cfg.default_scope == "openid offline_access"


class TestResourceLookupNormalisation:
    """The requested URI is folded just enough to match the table shape.

    RFC 3986 §6.2.3: for a scheme requiring an authority, an empty path and a
    ``/`` path denote the same resource. The tabelle side already strips a
    trailing slash in ``_load_resources``; the request side folds the exact
    counterpart on lookup. Nothing beyond that is normalised — case, port,
    percent-encoding, dot-segments, query and fragment are left alone.
    """

    def test_lookup_tolerates_trailing_slash_on_root(self) -> None:
        cfg = load_config(_min_env(RESOURCE_0_URL="https://log.example"))
        assert cfg.resource_by_url("https://log.example/") is cfg.resources[0]

    def test_lookup_still_matches_exact(self) -> None:
        cfg = load_config(_min_env(RESOURCE_0_URL="https://log.example"))
        assert cfg.resource_by_url("https://log.example") is cfg.resources[0]

    def test_lookup_refuses_extra_path(self) -> None:
        cfg = load_config(_min_env(RESOURCE_0_URL="https://log.example"))
        assert cfg.resource_by_url("https://log.example/foo") is None

    def test_lookup_refuses_extra_path_with_trailing_slash(self) -> None:
        cfg = load_config(_min_env(RESOURCE_0_URL="https://log.example"))
        assert cfg.resource_by_url("https://log.example/foo/") is None

    def test_lookup_does_not_fold_case(self) -> None:
        cfg = load_config(_min_env(RESOURCE_0_URL="https://log.example"))
        assert cfg.resource_by_url("https://LOG.example") is None
        assert cfg.resource_by_url("https://LOG.example/") is None

    def test_lookup_leaves_query_string_alone(self) -> None:
        # A trailing slash on the root path plus a query stays as the client
        # sent it — the tabelle carries no query, so the two do not match, and
        # normalising the slash away here would be a change of statement.
        cfg = load_config(_min_env(RESOURCE_0_URL="https://log.example"))
        assert cfg.resource_by_url("https://log.example/?x=1") is None

    def test_normalise_direct_cases(self) -> None:
        # The narrow contract, pinned at the function level so a future change
        # cannot accidentally widen the tolerance without rewriting this test.
        assert _normalise("https://log.example/") == "https://log.example"
        assert _normalise("https://log.example") == "https://log.example"
        assert _normalise("https://log.example/foo") == "https://log.example/foo"
        assert _normalise("https://log.example/foo/") == "https://log.example/foo/"
        assert _normalise("https://LOG.example/") == "https://LOG.example"
        assert _normalise("https://log.example:8443/") == "https://log.example:8443"
        assert _normalise("") == ""


class TestNumericBounds:
    def test_ttl_min_must_not_exceed_max(self) -> None:
        env = _min_env(CIMD_CACHE_TTL_MIN="1000", CIMD_CACHE_TTL_MAX="500")
        with pytest.raises(ConfigError, match="CIMD_CACHE_TTL_MIN"):
            load_config(env)

    def test_max_bytes_positive(self) -> None:
        env = _min_env(CIMD_MAX_BYTES="0")
        with pytest.raises(ConfigError):
            load_config(env)

    def test_bool_parsing(self) -> None:
        cfg = load_config(_min_env(CIMD_DEBUG="true"))
        assert cfg.cimd_debug is True
        bad_env = _min_env(CIMD_DEBUG="maybe")
        with pytest.raises(ConfigError):
            load_config(bad_env)
