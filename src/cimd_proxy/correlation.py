# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Correlation IDs travel with every authorization flow.

An id is minted at ``/authorize``, packed into the state envelope, unpacked in
``/callback``, packed into the code envelope, and unpacked again at ``/token``.
Every log line records it. Without this thread a failed connect attempt cannot
be reconstructed from the log at all.
"""

from __future__ import annotations

import secrets
from contextvars import ContextVar

_CURRENT: ContextVar[str] = ContextVar("cimd_correlation_id", default="-")


def new_correlation_id() -> str:
    """Mint a URL-safe correlation id (13 chars, 78 bits of entropy)."""

    return secrets.token_urlsafe(10)[:13]


def bind_correlation_id(cid: str) -> None:
    """Bind the current correlation id for the current request context."""

    _CURRENT.set(cid)


def current_correlation_id() -> str:
    return _CURRENT.get()
