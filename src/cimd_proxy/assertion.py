# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Signed assertions for the JWT Authorization Grant (RFC 7523), and their JWKS.

This is the one place where the proxy signs something. The assertion is not a
token any resource server sees: it is presented once to the upstream token
endpoint, which verifies it against the JWKS published here and then issues an
ordinary access token of its own. Its lifetime is capped at 60 seconds and every
assertion carries a fresh ``jti``, so the upstream's replay cache refuses a
second use.

Keys are RSA, read from PEM files named in the environment — never from the
database. Every configured key is published; only the active one signs. That is
what makes rotation possible without a gap: publish the new key, switch the
active key, remove the old one.
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MAX_ASSERTION_LIFETIME = 60


class SigningKeyError(ValueError):
    """A configured signing key cannot be used."""


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass(frozen=True, slots=True)
class SigningKey:
    kid: str
    private_key: rsa.RSAPrivateKey

    @classmethod
    def from_pem(cls, kid: str, pem: bytes) -> SigningKey:
        try:
            key = serialization.load_pem_private_key(pem, password=None)
        except (ValueError, TypeError) as exc:
            raise SigningKeyError(
                f"signing key {kid!r} is not an unencrypted PEM private key"
            ) from exc
        if not isinstance(key, rsa.RSAPrivateKey):
            raise SigningKeyError(f"signing key {kid!r} is not an RSA key")
        if key.key_size < 2048:
            raise SigningKeyError(f"signing key {kid!r} is shorter than 2048 bits")
        return cls(kid=kid, private_key=key)

    def public_jwk(self) -> dict[str, str]:
        numbers = self.private_key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": _b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": _b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        }


@dataclass(frozen=True, slots=True)
class AssertionSigner:
    issuer: str
    keys: tuple[SigningKey, ...]
    active_kid: str

    def __post_init__(self) -> None:
        if not any(k.kid == self.active_kid for k in self.keys):
            raise SigningKeyError(f"active signing key {self.active_kid!r} is not configured")

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        return {"keys": [k.public_jwk() for k in self.keys]}

    def sign(self, *, subject: str, audience: str, lifetime: int = MAX_ASSERTION_LIFETIME) -> str:
        if not 0 < lifetime <= MAX_ASSERTION_LIFETIME:
            raise ValueError(f"assertion lifetime must be within 1..{MAX_ASSERTION_LIFETIME}s")
        key = next(k for k in self.keys if k.kid == self.active_kid)
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": key.kid}
        claims = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "exp": now + lifetime,
            "jti": str(uuid.uuid4()),
        }
        signing_input = (
            f"{_b64u(json.dumps(header, separators=(',', ':')).encode())}."
            f"{_b64u(json.dumps(claims, separators=(',', ':')).encode())}"
        )
        signature = key.private_key.sign(
            signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
        )
        return f"{signing_input}.{_b64u(signature)}"
