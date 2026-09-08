# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import hashlib

import pytest

from cimd_proxy.pkce import derive_challenge, make_verifier, method, verify_challenge


class TestPkce:
    def test_challenge_matches_rfc7636(self) -> None:
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        # From RFC 7636 §4.4
        expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        assert derive_challenge(verifier) == expected

    def test_verifier_length_bounds(self) -> None:
        with pytest.raises(ValueError):
            make_verifier(length=42)
        with pytest.raises(ValueError):
            make_verifier(length=129)

    def test_verify_challenge_true_and_false(self) -> None:
        v = make_verifier()
        c = derive_challenge(v)
        assert verify_challenge(v, c) is True
        assert verify_challenge(v, c + "0") is False
        assert verify_challenge(v + "0", c) is False

    def test_method_is_s256(self) -> None:
        assert method() == "S256"

    def test_challenge_is_url_safe_and_unpadded(self) -> None:
        v = make_verifier()
        c = derive_challenge(v)
        assert "=" not in c
        # Recompute manually
        expected = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=")
        assert c == expected.decode()
