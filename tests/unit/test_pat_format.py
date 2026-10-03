# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib

import pytest

from cimd_proxy import pat_format


def test_generated_token_has_the_documented_shape() -> None:
    token = pat_format.generate()
    assert token.startswith("kmb_pat_")
    assert len(token) == pat_format.TOKEN_LENGTH == 8 + 43 + 6
    assert pat_format.is_well_formed(token)


def test_tokens_do_not_repeat() -> None:
    assert len({pat_format.generate() for _ in range(200)}) == 200


@pytest.mark.parametrize("position", [8, 20, 50, -1])
def test_one_changed_character_fails_the_checksum(position: int) -> None:
    token = pat_format.generate()
    chars = list(token)
    chars[position] = "A" if chars[position] != "A" else "B"
    assert not pat_format.is_well_formed("".join(chars))


@pytest.mark.parametrize(
    "candidate",
    [
        "",
        "kmb_pat_",
        "ghp_" + "a" * 53,
        "kmb_pat_" + "a" * 48,  # one short
        "kmb_pat_" + "a" * 50,  # one long
        "kmb_pat_" + "-" * 49,  # outside the alphabet
    ],
)
def test_malformed_candidates_are_refused(candidate: str) -> None:
    assert not pat_format.is_well_formed(candidate)


def test_hash_is_sha256_of_the_whole_string() -> None:
    token = pat_format.generate()
    assert pat_format.token_hash(token) == hashlib.sha256(token.encode()).digest()


def test_base62_refuses_a_value_that_does_not_fit() -> None:
    with pytest.raises(ValueError):
        pat_format._base62(62**2, 2)
