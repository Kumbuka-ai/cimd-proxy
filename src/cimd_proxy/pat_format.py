# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""The personal access token as a string: generation, checksum, hash.

Shape: ``kmb_pat_`` + 43 base62 characters (256 bits of randomness) + 6 base62
characters of CRC32 over everything before them. The prefix lets a secret
scanner recognise a leaked token; the checksum lets the proxy discard a
mistyped or made-up token without asking the database.

Only the SHA-256 of the whole string is ever stored. With 256 bits of
randomness a fast hash is enough: there is nothing to brute-force.
"""

from __future__ import annotations

import hashlib
import secrets
import zlib

PREFIX = "kmb_pat_"
_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_RANDOM_BYTES = 32
_RANDOM_CHARS = 43  # ceil(256 / log2(62))
_CHECKSUM_CHARS = 6  # ceil(32 / log2(62))
TOKEN_LENGTH = len(PREFIX) + _RANDOM_CHARS + _CHECKSUM_CHARS


def _base62(value: int, width: int) -> str:
    chars = []
    for _ in range(width):
        value, rem = divmod(value, 62)
        chars.append(_ALPHABET[rem])
    if value:
        raise ValueError("value does not fit the requested width")
    return "".join(reversed(chars))


def _checksum(body: str) -> str:
    return _base62(zlib.crc32(body.encode("ascii")), _CHECKSUM_CHARS)


def generate() -> str:
    body = PREFIX + _base62(
        int.from_bytes(secrets.token_bytes(_RANDOM_BYTES), "big"), _RANDOM_CHARS
    )
    return body + _checksum(body)


def is_well_formed(token: str) -> bool:
    """Prefix, length, alphabet and checksum — everything decidable without a lookup."""

    if len(token) != TOKEN_LENGTH or not token.startswith(PREFIX):
        return False
    tail = token[len(PREFIX) :]
    if any(c not in _ALPHABET for c in tail):
        return False
    body, check = token[:-_CHECKSUM_CHARS], token[-_CHECKSUM_CHARS:]
    return secrets.compare_digest(_checksum(body), check)


def token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()
