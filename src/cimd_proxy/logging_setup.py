# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""Line-oriented JSON logging with a mandatory redaction filter.

Log entries always carry ``ts``, ``level``, ``logger``, ``msg`` and — when
present — the correlation id and any structured fields. Secrets are truncated
to the first six characters and marked with ``…``; enough to spot re-use, too
little to leak.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

from .correlation import current_correlation_id

_SECRET_FIELDS = frozenset(
    {
        "access_token",
        "refresh_token",
        "code",
        "code_verifier",
        "client_secret",
        "PROXY_SECRET_KEY",
        "secret_key",
        "upstream_refresh_token",
        "upstream_code",
        "upstream_verifier",
    }
)


def sanitize(value: str | None) -> str | None:
    """Neutralise CR/LF/NUL in a value destined for a log field.

    ``json.dumps`` escapes these on its own, but a defence-in-depth pass is
    cheap and stops log-forging even if the sink is ever replaced by a
    line-oriented formatter. The chained ``.replace`` shape is recognised as
    a sanitizer by static-analysis taint tracking (Sonar S5145).
    """

    if value is None:
        return None
    return value.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")


def redact(value: object) -> object:
    """Walk a payload and truncate every value whose key names a secret.

    Non-secret string values pass through untouched — otherwise every log line
    becomes unreadable. Dicts and lists are walked recursively so a secret
    field is caught however deeply it is nested.
    """

    if isinstance(value, dict):
        return {
            k: (_redact_string(v) if k in _SECRET_FIELDS else redact(v)) for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


def _redact_string(value: object) -> str:
    text = str(value)
    if len(text) <= 6:
        return "…"
    return text[:6] + "…"


class RedactionFilter(logging.Filter):
    """Redact secret-shaped fields in ``extra`` and in the message payload."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Snapshot the keys so we can mutate the dict while iterating.
        for attr in tuple(record.__dict__.keys()):
            if attr in _SECRET_FIELDS:
                record.__dict__[attr] = _redact_string(record.__dict__[attr])
        if isinstance(record.msg, dict):
            record.msg = redact(record.msg)
        fields = record.__dict__.get("fields")
        if isinstance(fields, dict):
            record.__dict__["fields"] = redact(fields)
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "cid": current_correlation_id(),
        }
        if isinstance(record.msg, dict):
            payload["fields"] = record.msg
            payload["msg"] = record.msg.get("event", "")
        else:
            payload["msg"] = record.getMessage()
        fields = record.__dict__.get("fields")
        if isinstance(fields, dict):
            payload.setdefault("fields", {}).update(fields)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)


def configure_logging(level: str = "INFO") -> None:
    """Install stdout JSON logging with the redaction filter.

    Idempotent; safe to call multiple times (test setup, worker startup).
    """

    root = logging.getLogger()
    # Snapshot handlers before mutating the list we iterate over.
    for handler in tuple(root.handlers):
        root.removeHandler(handler)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactionFilter())
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    # Silence noisy libraries at the same level as ours; uvicorn's access log
    # is left to uvicorn's own config so ops can dial it independently.
    logging.getLogger("httpx").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
