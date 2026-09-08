# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Host-vs-domain matching for the CIMD allowlist.

The allowlist consists of comma-separated patterns:

* ``example.com`` — matches exactly ``example.com``
* ``*.example.com`` — matches every proper sub-domain of ``example.com``
  (``a.example.com``, ``a.b.example.com``); does **not** match the apex
* ``*`` — matches every host (used only for RP1's bypass control run and, if
  ever, an explicit operator override)

Matching is case-insensitive on the hostname and compares label by label so
that ``evilexample.com`` never matches ``example.com``.
"""

from __future__ import annotations


def _matches_wildcard(pattern: str, host_labels: list[str]) -> bool:
    """Return True when ``pattern`` is ``*.suffix`` and host is a proper sub-domain."""

    suffix = pattern[2:]  # strip leading ``*.``
    if not suffix:
        return False
    suffix_labels = suffix.split(".")
    if len(host_labels) <= len(suffix_labels):
        return False
    return host_labels[-len(suffix_labels) :] == suffix_labels


def _pattern_matches(pattern: str, host_l: str, host_labels: list[str]) -> bool:
    if pattern == "*":
        return True
    if pattern == host_l:
        return True
    if pattern.startswith("*."):
        return _matches_wildcard(pattern, host_labels)
    return False


class Allowlist:
    def __init__(self, patterns: list[str]) -> None:
        cleaned = [p.strip().lower() for p in patterns if p.strip()]
        if not cleaned:
            raise ValueError("allowlist must not be empty")
        self._patterns = tuple(cleaned)

    @property
    def patterns(self) -> tuple[str, ...]:
        return self._patterns

    def allows(self, host: str) -> bool:
        if not host:
            return False
        host_l = host.lower()
        host_labels = host_l.split(".")
        return any(_pattern_matches(p, host_l, host_labels) for p in self._patterns)

    @classmethod
    def parse(cls, raw: str) -> Allowlist:
        return cls(list(raw.split(",")))
