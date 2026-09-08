# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import logging

import pytest

from cimd_proxy.correlation import bind_correlation_id
from cimd_proxy.logging_setup import (
    JsonFormatter,
    RedactionFilter,
    configure_logging,
    redact,
)


class TestRedactFn:
    def test_leaves_non_secret_strings_alone(self) -> None:
        assert redact({"event": "authorize.rejected", "resource": "https://log.example"}) == {
            "event": "authorize.rejected",
            "resource": "https://log.example",
        }

    def test_truncates_secret_field_values(self) -> None:
        redacted = redact({"access_token": "eyJlong.token.value", "event": "issued"})
        assert redacted["access_token"] == "eyJlon…"  # type: ignore[index]
        assert redacted["event"] == "issued"  # type: ignore[index]

    def test_nested_secret_field(self) -> None:
        redacted = redact({"outer": {"code_verifier": "s3cretVerifier9999"}})
        assert redacted["outer"]["code_verifier"] == "s3cret…"  # type: ignore[index]

    def test_short_secret_fully_hidden(self) -> None:
        redacted = redact({"code": "abcd"})
        assert redacted["code"] == "…"  # type: ignore[index]


class TestRedactionFilter:
    def test_filter_redacts_extras(self) -> None:
        record = logging.LogRecord(
            name="t",
            level=logging.INFO,
            pathname="",
            lineno=1,
            msg="hello",
            args=(),
            exc_info=None,
        )
        record.access_token = "eyJlong.token.value"  # type: ignore[attr-defined]
        record.fields = {"refresh_token": "rt-longlong"}  # type: ignore[attr-defined]
        RedactionFilter().filter(record)
        assert record.access_token.endswith("…")  # type: ignore[attr-defined]
        assert record.fields["refresh_token"].endswith("…")  # type: ignore[attr-defined]


class TestJsonFormatter:
    def test_carries_correlation_id(self) -> None:
        bind_correlation_id("cid-xyz")
        fmt = JsonFormatter()
        record = logging.LogRecord(
            name="cimd_proxy.test",
            level=logging.INFO,
            pathname="",
            lineno=1,
            msg={"event": "authorize.forwarded", "resource": "https://log.example"},
            args=(),
            exc_info=None,
        )
        payload = json.loads(fmt.format(record))
        assert payload["cid"] == "cid-xyz"
        assert payload["fields"]["event"] == "authorize.forwarded"


class TestConfigureLogging:
    def test_installs_json_stdout_and_redacts(
        self, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
    ) -> None:
        # capfd captures both stdout and stderr; the JSON handler writes to stdout.
        configure_logging("INFO")
        log = logging.getLogger("cimd_proxy.smoke")
        log.info({"event": "smoke", "access_token": "eyJlong.token.value"})
        captured = capfd.readouterr()
        line = captured.out.strip().splitlines()[-1]
        payload = json.loads(line)
        assert payload["fields"]["access_token"].endswith("…")
        assert payload["fields"]["event"] == "smoke"
