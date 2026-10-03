# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from cimd_proxy.assertion import AssertionSigner, SigningKey, SigningKeyError

from ..pat_fakes import assertion_claims, assertion_header


def _pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64u_int(value: str) -> int:
    return int.from_bytes(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big")


def test_signature_verifies_against_the_published_jwk(rsa_key) -> None:
    signer = AssertionSigner(
        issuer="https://proxy.example",
        keys=(SigningKey.from_pem("k1", _pem(rsa_key)),),
        active_kid="k1",
    )
    assertion = signer.sign(subject="user-1", audience="https://kc.example/realms/x")
    jwk = signer.jwks()["keys"][0]
    public = rsa.RSAPublicNumbers(_b64u_int(jwk["e"]), _b64u_int(jwk["n"])).public_key()
    head, body, sig = assertion.split(".")
    public.verify(
        base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)),
        f"{head}.{body}".encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    assert assertion_header(assertion) == {"alg": "RS256", "typ": "JWT", "kid": "k1"}
    claims = assertion_claims(assertion)
    assert claims["iss"] == "https://proxy.example"
    assert claims["sub"] == "user-1"
    assert claims["aud"] == "https://kc.example/realms/x"
    assert claims["exp"] - claims["iat"] == 60
    assert abs(claims["iat"] - time.time()) < 5
    assert claims["jti"]


def test_every_assertion_has_a_fresh_jti(rsa_key) -> None:
    signer = AssertionSigner("i", (SigningKey.from_pem("k1", _pem(rsa_key)),), "k1")
    jtis = {assertion_claims(signer.sign(subject="s", audience="a"))["jti"] for _ in range(20)}
    assert len(jtis) == 20


def test_all_keys_are_published_and_only_the_active_one_signs(rsa_key) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer = AssertionSigner(
        "i",
        (SigningKey.from_pem("old", _pem(rsa_key)), SigningKey.from_pem("new", _pem(other))),
        "new",
    )
    assert [k["kid"] for k in signer.jwks()["keys"]] == ["old", "new"]
    assert assertion_header(signer.sign(subject="s", audience="a"))["kid"] == "new"
    for jwk in signer.jwks()["keys"]:
        assert set(jwk) == {"kty", "use", "alg", "kid", "n", "e"}  # no private member


@pytest.mark.parametrize("lifetime", [0, 61, -1])
def test_lifetime_outside_one_to_sixty_seconds_is_refused(rsa_key, lifetime: int) -> None:
    signer = AssertionSigner("i", (SigningKey.from_pem("k1", _pem(rsa_key)),), "k1")
    with pytest.raises(ValueError):
        signer.sign(subject="s", audience="a", lifetime=lifetime)


def test_unknown_active_kid_is_refused(rsa_key) -> None:
    with pytest.raises(SigningKeyError):
        AssertionSigner("i", (SigningKey.from_pem("k1", _pem(rsa_key)),), "k2")


def test_non_rsa_short_and_garbage_keys_are_refused() -> None:
    with pytest.raises(SigningKeyError, match="not an RSA key"):
        SigningKey.from_pem("ec", _pem(ec.generate_private_key(ec.SECP256R1())))
    short = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(SigningKeyError, match="shorter than 2048"):
        SigningKey.from_pem("short", _pem(short))
    with pytest.raises(SigningKeyError, match="unencrypted PEM"):
        SigningKey.from_pem("junk", b"not a key")
