# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Fernet envelopes for authorization state, refresh tokens and DCR registrations.

The proxy holds no server-side state. The information that a naive server would
put in a database — the pending PKCE challenge, the resource selection, the
upstream refresh token, and the metadata of a dynamically registered client —
is instead packed into a Fernet envelope handed back to the client (as ``state``
at `/authorize`, as ``code`` returned from `/callback`, as ``refresh_token``
returned from `/token`, and as the ``client_id`` returned from `/register`).

The load-bearing rule is that the proxy never reads the access token; the code
handed to the client contains only what the proxy itself needs on the round
trip. `envelope.py` is the one module that would grow if variant 2 (own
issuance) were ever built: today only :class:`RefreshEnvelope` would need a new
sibling that additionally carries whatever the proxy would sign into a token
of its own. Do not anticipate that here.

The RFC 7591 registration envelope is why a DCR route does not need a database:
the ``client_id`` handed back is a self-describing Fernet blob carrying the
registered metadata. A ``/authorize`` hit later opens it and applies the same
redirect-uri check the CIMD document would have carried.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, ClassVar, Self

from cryptography.fernet import Fernet, InvalidToken


class EnvelopeError(Exception):
    """Raised when an envelope cannot be opened (bad key, tampered, expired)."""


@dataclass(frozen=True, slots=True)
class AuthorizeEnvelope:
    """State handed to Keycloak during `/authorize`, returned as ``state`` to `/callback`."""

    TAG: ClassVar[str] = "az"
    correlation_id: str
    client_id: str
    redirect_uri: str
    state: str
    resource: str
    client_code_challenge: str
    upstream_verifier: str
    scope: str
    exp: int


@dataclass(frozen=True, slots=True)
class CodeEnvelope:
    """Handed to the client as ``code``; carries the upstream code plus what
    the proxy needs to redeem it on the client's behalf.
    """

    TAG: ClassVar[str] = "cd"
    correlation_id: str
    upstream_code: str
    upstream_verifier: str
    resource: str
    client_id: str
    client_code_challenge: str
    redirect_uri: str
    exp: int


@dataclass(frozen=True, slots=True)
class RefreshEnvelope:
    """Handed to the client as ``refresh_token``; carries the upstream refresh
    token plus the resource identifier needed to route the refresh call.

    Note that the proxy never sets an ``exp`` here: refresh-token lifetime is
    the upstream's business; the proxy re-issues an envelope on every refresh.
    """

    TAG: ClassVar[str] = "rt"
    resource: str
    upstream_refresh_token: str


@dataclass(frozen=True, slots=True)
class RegistrationEnvelope:
    """Handed to the client as ``client_id`` from `/register`; carries the
    registered client's metadata so `/authorize` can validate its redirect_uri
    without a database lookup.

    The upstream client remains the statically configured resource client — a
    dynamically registered client rides that upstream, it does not get one of
    its own. All the proxy needs on the round trip is the client's
    ``redirect_uris`` and enough audit data to explain who was talking.

    No ``exp`` — a registration outlives the current session. The Fernet key
    itself is the one thing whose rotation would end all registrations at
    once; that is deliberate.
    """

    TAG: ClassVar[str] = "rg"
    redirect_uris: tuple[str, ...]
    token_endpoint_auth_method: str
    client_id_issued_at: int
    client_name: str = ""


class EnvelopeCodec:
    """Fernet-backed encoder/decoder.

    Every envelope carries a ``tag`` field naming its dataclass, so we refuse to
    open an envelope of the wrong kind — a callback-shaped code passed at the
    refresh endpoint would otherwise unpack silently.
    """

    def __init__(self, key: bytes) -> None:
        self._fernet = Fernet(key)

    def pack_authorize(self, env: AuthorizeEnvelope) -> str:
        return self._pack(env)

    def pack_code(self, env: CodeEnvelope) -> str:
        return self._pack(env)

    def pack_refresh(self, env: RefreshEnvelope) -> str:
        return self._pack(env)

    def pack_registration(self, env: RegistrationEnvelope) -> str:
        return self._pack(env)

    def open_authorize(self, token: str) -> AuthorizeEnvelope:
        payload = self._open(token, AuthorizeEnvelope.TAG, ttl_seconds=600)
        return AuthorizeEnvelope(**{k: v for k, v in payload.items() if k != "tag"})

    def open_code(self, token: str) -> CodeEnvelope:
        payload = self._open(token, CodeEnvelope.TAG, ttl_seconds=None)
        return CodeEnvelope(**{k: v for k, v in payload.items() if k != "tag"})

    def open_refresh(self, token: str) -> RefreshEnvelope:
        payload = self._open(token, RefreshEnvelope.TAG, ttl_seconds=None)
        return RefreshEnvelope(**{k: v for k, v in payload.items() if k != "tag"})

    def open_registration(self, token: str) -> RegistrationEnvelope:
        payload = self._open(token, RegistrationEnvelope.TAG, ttl_seconds=None)
        clean = {k: v for k, v in payload.items() if k != "tag"}
        # ``redirect_uris`` round-trips through JSON as a list — turn it back
        # into the tuple the dataclass declares.
        if "redirect_uris" in clean and isinstance(clean["redirect_uris"], list):
            clean["redirect_uris"] = tuple(clean["redirect_uris"])
        return RegistrationEnvelope(**clean)

    def _pack(
        self,
        env: AuthorizeEnvelope | CodeEnvelope | RefreshEnvelope | RegistrationEnvelope,
    ) -> str:
        payload = asdict(env)
        payload["tag"] = env.TAG
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self._fernet.encrypt(blob).decode("ascii")

    def _open(self, token: str, expected_tag: str, ttl_seconds: int | None) -> dict[str, Any]:
        try:
            blob = (
                self._fernet.decrypt(token.encode("ascii"), ttl=ttl_seconds)
                if ttl_seconds is not None
                else self._fernet.decrypt(token.encode("ascii"))
            )
        except InvalidToken as exc:
            raise EnvelopeError("envelope invalid or expired") from exc
        except ValueError as exc:
            # UnicodeError is a ValueError subclass; the single catch covers both.
            raise EnvelopeError("envelope malformed") from exc
        try:
            payload: dict[str, Any] = json.loads(blob.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise EnvelopeError("envelope payload not JSON") from exc
        if payload.get("tag") != expected_tag:
            raise EnvelopeError(
                f"envelope tag mismatch (expected {expected_tag!r}, got {payload.get('tag')!r})"
            )
        return payload

    @classmethod
    def from_key_string(cls, key: str) -> Self:
        return cls(key.encode("ascii"))
