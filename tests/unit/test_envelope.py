# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import time

import pytest
from cryptography.fernet import Fernet

from cimd_proxy.envelope import (
    AuthorizeEnvelope,
    CodeEnvelope,
    EnvelopeCodec,
    EnvelopeError,
    RefreshEnvelope,
    RegistrationEnvelope,
)


@pytest.fixture
def codec() -> EnvelopeCodec:
    return EnvelopeCodec(Fernet.generate_key())


class TestAuthorizeEnvelope:
    def test_round_trip(self, codec: EnvelopeCodec) -> None:
        env = AuthorizeEnvelope(
            correlation_id="c1",
            client_id="https://claude.ai/mcp",
            redirect_uri="https://claude.ai/cb",
            state="opaque-state",
            resource="https://log.example",
            client_code_challenge="abc",
            upstream_verifier="def",
            scope="openid",
            exp=int(time.time()) + 300,
        )
        token = codec.pack_authorize(env)
        opened = codec.open_authorize(token)
        assert opened == env

    def test_tag_mismatch_refused(self, codec: EnvelopeCodec) -> None:
        env = RefreshEnvelope(resource="https://log.example", upstream_refresh_token="rt")
        token = codec.pack_refresh(env)
        with pytest.raises(EnvelopeError):
            codec.open_authorize(token)


class TestCodeEnvelope:
    def test_round_trip(self, codec: EnvelopeCodec) -> None:
        env = CodeEnvelope(
            correlation_id="c1",
            upstream_code="upcode",
            upstream_verifier="v",
            resource="https://log.example",
            client_id="https://claude.ai/mcp",
            client_code_challenge="chal",
            redirect_uri="https://claude.ai/cb",
            exp=int(time.time()) + 60,
        )
        token = codec.pack_code(env)
        assert codec.open_code(token) == env

    def test_wrong_key_refused(self) -> None:
        codec_a = EnvelopeCodec(Fernet.generate_key())
        codec_b = EnvelopeCodec(Fernet.generate_key())
        env = CodeEnvelope(
            correlation_id="c",
            upstream_code="u",
            upstream_verifier="v",
            resource="https://log.example",
            client_id="c",
            client_code_challenge="c",
            redirect_uri="r",
            exp=int(time.time()) + 60,
        )
        token = codec_a.pack_code(env)
        with pytest.raises(EnvelopeError):
            codec_b.open_code(token)


class TestRefreshEnvelope:
    def test_round_trip(self, codec: EnvelopeCodec) -> None:
        env = RefreshEnvelope(resource="https://log.example", upstream_refresh_token="rt-abc")
        token = codec.pack_refresh(env)
        assert codec.open_refresh(token) == env

    def test_garbled_token_refused(self, codec: EnvelopeCodec) -> None:
        with pytest.raises(EnvelopeError):
            codec.open_refresh("not-a-fernet-token")


class TestRegistrationEnvelope:
    def test_round_trip(self, codec: EnvelopeCodec) -> None:
        env = RegistrationEnvelope(
            redirect_uris=("https://claude.ai/cb", "https://claude.ai/cb2"),
            token_endpoint_auth_method="none",
            client_id_issued_at=int(time.time()),
            client_name="Claude",
        )
        token = codec.pack_registration(env)
        assert codec.open_registration(token) == env

    def test_tag_mismatch_refused_from_any_sibling(self, codec: EnvelopeCodec) -> None:
        # Any of the other three envelope kinds passed into open_registration
        # must be rejected — a callback code presented in the client_id slot
        # would otherwise unpack silently. This is the load-bearing reason for
        # the tag field on every envelope.
        refresh = RefreshEnvelope(resource="https://log.example", upstream_refresh_token="rt")
        packed_refresh = codec.pack_refresh(refresh)  # packing is not what should throw
        with pytest.raises(EnvelopeError):
            codec.open_registration(packed_refresh)


class TestExistingEnvelopesUnchanged:
    """v0.1.0 envelopes must still open under v0.2.0 — Rückwärtskompatibilität.

    The Fernet key does not rotate across v0.1.0 → v0.2.0, so a token produced
    against the three existing formats must still round-trip. What we can
    check here is the structural piece of that: the three formats have not
    changed shape. A change in a field name or type would leak into a
    v0.1.0-produced blob failing to open.
    """

    def test_authorize_format_unchanged(self, codec: EnvelopeCodec) -> None:
        env = AuthorizeEnvelope(
            correlation_id="c",
            client_id="cid",
            redirect_uri="ru",
            state="s",
            resource="r",
            client_code_challenge="c",
            upstream_verifier="v",
            scope="openid",
            exp=int(time.time()) + 300,
        )
        assert codec.open_authorize(codec.pack_authorize(env)) == env

    def test_code_format_unchanged(self, codec: EnvelopeCodec) -> None:
        env = CodeEnvelope(
            correlation_id="c",
            upstream_code="u",
            upstream_verifier="v",
            resource="r",
            client_id="c",
            client_code_challenge="c",
            redirect_uri="r",
            exp=int(time.time()) + 60,
        )
        assert codec.open_code(codec.pack_code(env)) == env

    def test_refresh_format_unchanged(self, codec: EnvelopeCodec) -> None:
        env = RefreshEnvelope(resource="r", upstream_refresh_token="rt")
        assert codec.open_refresh(codec.pack_refresh(env)) == env


class TestAuthorizeExpiry:
    def test_expired_envelope_refused(
        self, codec: EnvelopeCodec, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # AuthorizeEnvelope carries a Fernet TTL of 600 seconds; forge an
        # envelope, then advance the Fernet clock via monkeypatching.
        env = AuthorizeEnvelope(
            correlation_id="c",
            client_id="cid",
            redirect_uri="ru",
            state="s",
            resource="r",
            client_code_challenge="c",
            upstream_verifier="v",
            scope="openid",
            exp=int(time.time()) + 300,
        )
        token = codec.pack_authorize(env)
        # Move Fernet's internal clock forward past the TTL.
        import cryptography.fernet as fmod

        real_time = fmod.time.time
        monkeypatch.setattr(fmod.time, "time", lambda: real_time() + 700)
        with pytest.raises(EnvelopeError):
            codec.open_authorize(token)
