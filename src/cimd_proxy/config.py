# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Configuration loading — ENV only, fail-loud on every missing required value.

The indexed ``RESOURCE_n_*`` shape is deliberate: these values are written into
``deploy.env`` and read via ``docker compose --env-file``, where embedded JSON
does not quote reliably. Indices are read contiguously from 0; the first gap
ends the table, and a set higher index over a gap is a loud startup error.

``RESOURCE_n_ISSUER`` is redundant today (both resources share the same realm),
but a resource on a different realm or another provider then becomes a table
entry, not a structural break.

Personal access tokens are an optional block, switched on by
``PAT_DATABASE_URL``. Without it the proxy runs exactly as before and no
``PAT_*`` key may be set; with it every required ``PAT_*`` value is checked at
start like everything else. ``RESOURCE_n_PAT_CLIENT_ID`` / ``_SECRET`` name the
confidential upstream client the exchange uses for a resource: the JWT
Authorization Grant refuses public clients, and a resource's interactive client
is often public.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .assertion import AssertionSigner, SigningKey, SigningKeyError


class ConfigError(RuntimeError):
    """Raised when the environment cannot be turned into a valid configuration."""


@dataclass(frozen=True, slots=True)
class ResourceEntry:
    url: str
    issuer: str
    client_id: str
    client_secret: str  # empty for public clients
    pat_client_id: str = ""  # empty: personal access tokens cannot name this resource
    pat_client_secret: str = ""

    @property
    def is_public(self) -> bool:
        return not self.client_secret

    @property
    def accepts_pat(self) -> bool:
        return bool(self.pat_client_id)


@dataclass(frozen=True, slots=True)
class PatConfig:
    database_url: str
    database_schema: str
    realm_issuer: str
    idp_alias: str
    admin_client_id: str
    admin_client_secret: str
    scopes: tuple[str, ...]
    signer: AssertionSigner


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    public_url: str
    secret_key: str
    port: int
    bind_host: str
    log_level: str
    cimd_debug: bool
    cimd_cache_ttl_min: int
    cimd_cache_ttl_max: int
    cimd_max_bytes: int
    cimd_fetch_timeout: float
    default_resource: str
    scopes_supported: tuple[str, ...] = ()
    default_scope: str = ""
    resources: tuple[ResourceEntry, ...] = field(default_factory=tuple)
    pat: PatConfig | None = None

    def resource_by_url(self, url: str) -> ResourceEntry | None:
        target = _normalise_requested_url(url)
        for entry in self.resources:
            if entry.url == target:
                return entry
        return None

    @property
    def known_resources(self) -> tuple[str, ...]:
        return tuple(r.url for r in self.resources)


def _normalise_requested_url(url: str) -> str:
    """Bring a requested resource URI to the shape the RESOURCE_n table holds.

    RFC 3986 §6.2.3 (scheme-based normalisation): for a scheme that requires an
    authority — ``https`` is one — an empty path and a ``/`` path denote the
    same resource. ``_load_resources`` writes every table entry with a
    ``rstrip("/")``, so ``https://host`` and ``https://host/`` land as the same
    key on the table side; the request side must fold the same way, or a
    client that appends a canonical ``/`` after normalising its own URI (RFC
    3986 §6.2.3 says the client is right to do so) is refused for a difference
    that carries no meaning.

    Nothing else is normalised. Case is not folded, ports are not defaulted,
    percent-encoding is not decoded, dot segments are not resolved, query and
    fragment are not touched. Each of those would turn a tolerance into an
    attack surface, and the measured case does not need any of them.
    """
    if not url:
        return url
    parts = urlsplit(url)
    if parts.path == "/" and not parts.query and not parts.fragment:
        return urlunsplit(parts._replace(path=""))
    return url


def load_config(env: Mapping[str, str] | None = None) -> ProxyConfig:
    src = env if env is not None else os.environ
    public_url = _required(src, "PROXY_PUBLIC_URL").rstrip("/")
    secret_key = _required(src, "PROXY_SECRET_KEY")
    port = _int(src.get("PROXY_PORT", "8080"), "PROXY_PORT")
    bind_host = src.get("PROXY_BIND_HOST", "0.0.0.0").strip() or "0.0.0.0"

    log_level = src.get("LOG_LEVEL", "INFO").strip().upper() or "INFO"
    cimd_debug = _bool(src.get("CIMD_DEBUG", "false"), "CIMD_DEBUG")

    ttl_min = _int(src.get("CIMD_CACHE_TTL_MIN", "300"), "CIMD_CACHE_TTL_MIN")
    ttl_max = _int(src.get("CIMD_CACHE_TTL_MAX", "86400"), "CIMD_CACHE_TTL_MAX")
    if ttl_min <= 0 or ttl_max <= 0:
        raise ConfigError("CIMD_CACHE_TTL_MIN and CIMD_CACHE_TTL_MAX must be positive")
    if ttl_min > ttl_max:
        raise ConfigError("CIMD_CACHE_TTL_MIN must be <= CIMD_CACHE_TTL_MAX")

    max_bytes = _int(src.get("CIMD_MAX_BYTES", "5120"), "CIMD_MAX_BYTES")
    if max_bytes <= 0:
        raise ConfigError("CIMD_MAX_BYTES must be positive")

    fetch_timeout = _float(src.get("CIMD_FETCH_TIMEOUT", "5"), "CIMD_FETCH_TIMEOUT")
    if fetch_timeout <= 0:
        raise ConfigError("CIMD_FETCH_TIMEOUT must be positive")

    default_resource = src.get("DEFAULT_RESOURCE", "").strip()

    scopes_supported = _parse_scope_list(src.get("PROXY_SCOPES_SUPPORTED", "openid offline_access"))
    default_scope = _parse_scope_string(src.get("PROXY_DEFAULT_SCOPE", "openid offline_access"))

    resources = _load_resources(src)
    if default_resource and not any(r.url == default_resource for r in resources):
        raise ConfigError(
            f"DEFAULT_RESOURCE {default_resource!r} is not present in the RESOURCE_n table"
        )

    pat = _load_pat(src, public_url, resources)

    return ProxyConfig(
        public_url=public_url,
        secret_key=secret_key,
        port=port,
        bind_host=bind_host,
        log_level=log_level,
        cimd_debug=cimd_debug,
        cimd_cache_ttl_min=ttl_min,
        cimd_cache_ttl_max=ttl_max,
        cimd_max_bytes=max_bytes,
        cimd_fetch_timeout=fetch_timeout,
        default_resource=default_resource,
        scopes_supported=scopes_supported,
        default_scope=default_scope,
        resources=tuple(resources),
        pat=pat,
    )


_SCHEMA_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def _load_pat(
    env: Mapping[str, str], public_url: str, resources: list[ResourceEntry]
) -> PatConfig | None:
    database_url = env.get("PAT_DATABASE_URL", "").strip()
    if not database_url:
        stray = sorted(
            k for k in env if (k.startswith("PAT_") or "_PAT_CLIENT_" in k) and env[k].strip()
        )
        if stray:
            raise ConfigError(
                f"{', '.join(stray)} set but PAT_DATABASE_URL is not; "
                "personal access tokens are either fully configured or off"
            )
        return None

    schema = env.get("PAT_DATABASE_SCHEMA", "cimd_proxy").strip()
    if not _SCHEMA_NAME.match(schema):
        raise ConfigError(f"PAT_DATABASE_SCHEMA {schema!r} is not a plain lower-case identifier")
    realm_issuer = _required(env, "PAT_REALM_ISSUER").rstrip("/")
    scopes = _parse_scope_list(_required(env, "PAT_SCOPES"))

    pat_resources = [r for r in resources if r.accepts_pat]
    if not pat_resources:
        raise ConfigError(
            "PAT_DATABASE_URL is set but no RESOURCE_n_PAT_CLIENT_ID is; "
            "a personal access token could not name any resource"
        )
    for entry in pat_resources:
        if entry.issuer != realm_issuer:
            raise ConfigError(
                f"resource {entry.url!r} accepts personal access tokens but its issuer "
                f"{entry.issuer!r} is not PAT_REALM_ISSUER {realm_issuer!r}"
            )

    return PatConfig(
        database_url=database_url,
        database_schema=schema,
        realm_issuer=realm_issuer,
        idp_alias=_required(env, "PAT_IDP_ALIAS"),
        admin_client_id=_required(env, "PAT_ADMIN_CLIENT_ID"),
        admin_client_secret=_required(env, "PAT_ADMIN_CLIENT_SECRET"),
        scopes=scopes,
        signer=_load_signer(env, public_url),
    )


def _load_signer(env: Mapping[str, str], public_url: str) -> AssertionSigner:
    """Read the indexed ``PAT_SIGNING_KEY_n_KID`` / ``_FILE`` table, contiguous from 0."""

    keys: list[SigningKey] = []
    index = 0
    while f"PAT_SIGNING_KEY_{index}_KID" in env or f"PAT_SIGNING_KEY_{index}_FILE" in env:
        kid = _required(env, f"PAT_SIGNING_KEY_{index}_KID")
        path = Path(_required(env, f"PAT_SIGNING_KEY_{index}_FILE"))
        try:
            pem = path.read_bytes()
        except OSError as exc:
            raise ConfigError(f"PAT_SIGNING_KEY_{index}_FILE cannot be read: {exc}") from exc
        try:
            keys.append(SigningKey.from_pem(kid, pem))
        except SigningKeyError as exc:
            raise ConfigError(str(exc)) from exc
        index += 1
    higher = sorted(
        k for k in env if re.match(r"^PAT_SIGNING_KEY_\d+_", k) and int(k.split("_")[3]) >= index
    )
    if higher:
        raise ConfigError(f"PAT_SIGNING_KEY table has a gap at index {index}: {', '.join(higher)}")
    if not keys:
        raise ConfigError("PAT_SIGNING_KEY_0_KID and PAT_SIGNING_KEY_0_FILE are required")
    if len({k.kid for k in keys}) != len(keys):
        raise ConfigError("PAT_SIGNING_KEY_n_KID values must be unique")

    issuer = env.get("PAT_ASSERTION_ISSUER", "").strip() or public_url
    try:
        return AssertionSigner(
            issuer=issuer, keys=tuple(keys), active_kid=_required(env, "PAT_SIGNING_KID")
        )
    except SigningKeyError as exc:
        raise ConfigError(str(exc)) from exc


def _parse_scope_list(raw: str) -> tuple[str, ...]:
    """Whitespace-split into a tuple; an empty or whitespace-only value yields ().

    A leading empty tuple is the signal for `build_discovery_document` to omit
    ``scopes_supported`` entirely rather than announce an empty array. An empty
    array would claim the server supports no scope at all — a different
    statement from "the operator chose to say nothing here".
    """
    return tuple(raw.split())


def _parse_scope_string(raw: str) -> str:
    """Whitespace-normalise a scope string.

    A scope value is a space-separated list of tokens (RFC 6749 §3.3). Any
    inbound whitespace shape collapses to a single-space canonical form so the
    default lands on the wire in exactly the shape the upstream expects.
    """
    return " ".join(raw.split())


def _load_resources(env: Mapping[str, str]) -> list[ResourceEntry]:
    entries: list[ResourceEntry] = []
    index = 0
    highest_seen = -1
    # Establish highest-set index across all four axes so we can catch a gap.
    for key in env:
        if not key.startswith("RESOURCE_"):
            continue
        rest = key[len("RESOURCE_") :]
        idx_str, sep, _tail = rest.partition("_")
        if not sep or not idx_str.isdigit():
            continue
        n = int(idx_str)
        if n > highest_seen:
            highest_seen = n
    while index <= highest_seen:
        prefix = f"RESOURCE_{index}_"
        keys = {k for k in env if k.startswith(prefix)}
        if not keys:
            raise ConfigError(
                f"RESOURCE table has a gap at index {index}; set higher indices are ignored"
            )
        url = _required(env, f"{prefix}URL").rstrip("/")
        issuer = _required(env, f"{prefix}ISSUER").rstrip("/")
        client_id = _required(env, f"{prefix}CLIENT_ID")
        client_secret = env.get(f"{prefix}CLIENT_SECRET", "")
        pat_client_id = env.get(f"{prefix}PAT_CLIENT_ID", "").strip()
        pat_client_secret = env.get(f"{prefix}PAT_CLIENT_SECRET", "").strip()
        if bool(pat_client_id) != bool(pat_client_secret):
            raise ConfigError(
                f"{prefix}PAT_CLIENT_ID and {prefix}PAT_CLIENT_SECRET are set together or not at "
                "all; the JWT Authorization Grant needs a confidential client"
            )
        # A double-slash-only URL is not a valid resource identifier.
        if "://" not in url:
            raise ConfigError(f"{prefix}URL {url!r} is not a URL")
        if "://" not in issuer:
            raise ConfigError(f"{prefix}ISSUER {issuer!r} is not a URL")
        entries.append(
            ResourceEntry(
                url=url,
                issuer=issuer,
                client_id=client_id,
                client_secret=client_secret,
                pat_client_id=pat_client_id,
                pat_client_secret=pat_client_secret,
            )
        )
        index += 1
    return entries


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name)
    if value is None or not value.strip():
        raise ConfigError(f"{name} is required")
    return value.strip()


def _int(raw: str, name: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def _float(raw: str, name: str) -> float:
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc


def _bool(raw: str, name: str) -> bool:
    lowered = raw.strip().lower()
    if lowered in {"true", "1", "yes", "on"}:
        return True
    if lowered in {"false", "0", "no", "off", ""}:
        return False
    raise ConfigError(f"{name} must be a boolean, got {raw!r}")
