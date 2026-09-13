# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Redirect-URI policy — RFC 8252 sections 7.3 and 8.3.

Two rules live here, and only these two:

* :func:`accept_registered` decides whether a ``redirect_uri`` is a valid
  registration. ``https`` is required for every host except the IP loopback
  literals ``127.0.0.1`` and ``::1`` (RFC 8252 §7.3), where ``http`` is
  explicitly permitted because the connection never leaves the device and a
  loopback interface cannot carry a publicly verifiable certificate. The name
  ``localhost`` is refused because it is DNS-resolvable and RFC 8252 §8.3
  recommends the IP literal instead. No fragment, non-empty host, no
  userinfo.

* :func:`uri_matches_registration` is the equality used at ``/authorize``
  step 4. RFC 3986 §6.2.1 byte comparison is the default; RFC 8252 §8.3
  drops port equality when BOTH URIs are loopback ``http`` URIs, because the
  client picks the port at run time. Nothing else is normalised — case,
  percent-encoding, dot segments and trailing slashes are left alone on
  purpose.

The rule is the same on both entry paths (DCR and CIMD).
"""

from __future__ import annotations

from urllib.parse import SplitResult, urlsplit

_LOOPBACK_LITERALS = frozenset({"127.0.0.1", "::1"})


class RedirectUriRefused(Exception):
    """Raised when a redirect_uri fails the registration-time policy."""


def accept_registered(uri: str) -> None:
    """Refuse a redirect_uri that violates the registration policy.

    Returns ``None`` on success; raises :class:`RedirectUriRefused` with an
    error_description body caller may forward to the client.
    """

    split = urlsplit(uri)
    if split.fragment:
        raise RedirectUriRefused(f"redirect_uri {uri!r} must not carry a fragment")
    if "@" in (split.netloc or ""):
        raise RedirectUriRefused(f"redirect_uri {uri!r} must not carry a userinfo component")
    if not split.hostname:
        raise RedirectUriRefused(f"redirect_uri {uri!r} has no host")
    if split.scheme == "https":
        return
    if split.scheme == "http":
        if split.hostname in _LOOPBACK_LITERALS:
            return
        raise RedirectUriRefused(
            f"redirect_uri {uri!r} must use https "
            "(http is permitted only for the loopback IP literals "
            "127.0.0.1 or [::1] per RFC 8252 §7.3)"
        )
    raise RedirectUriRefused(f"redirect_uri {uri!r} must use https or a loopback http scheme")


def uri_matches_registration(requested: str, registered: str) -> bool:
    """Return True when a requested redirect_uri matches a registered one.

    Byte-equality first (RFC 3986 §6.2.1). Port equality is dropped when both
    URIs are loopback ``http`` URIs (RFC 8252 §8.3); otherwise every other
    axis must match on the nose — nothing here is normalised.
    """

    if requested == registered:
        return True
    r = urlsplit(requested)
    s = urlsplit(registered)
    if not _is_loopback_http(r) or not _is_loopback_http(s):
        return False
    if r.fragment or s.fragment:
        return False
    if "@" in (r.netloc or "") or "@" in (s.netloc or ""):
        return False
    return r.hostname == s.hostname and r.path == s.path and r.query == s.query


def _is_loopback_http(split: SplitResult) -> bool:
    return split.scheme == "http" and split.hostname in _LOOPBACK_LITERALS
