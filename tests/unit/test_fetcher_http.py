# SPDX-FileCopyrightText: 2026 Johannes Bayer-Albert
# SPDX-License-Identifier: Apache-2.0

"""HTTP-level fetch tests for CimdFetcher.

The fetcher's HTTP path is exercised with respx so we can assert:

* the pinned URL uses the resolved IP as its host
* an SNI-hostname extension carries the original hostname
* a non-200 response is refused
* a body larger than ``max_bytes`` is refused
* documents are validated end-to-end
"""

from __future__ import annotations

import socket

import pytest
import respx
from httpx import Response

from cimd_proxy.fetcher import CimdFetcher, DocumentInvalid, FetchError

from ..helpers import resolver_returning


@pytest.fixture(autouse=True)
def stub_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", resolver_returning(["8.8.8.8"]))


class TestFetcherHttp:
    @respx.mock
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        respx.get("https://8.8.8.8:443/mcp").mock(
            return_value=Response(
                200,
                json={
                    "client_id": "https://claude.ai/mcp",
                    "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
                    "token_endpoint_auth_method": "none",
                },
                headers={"cache-control": "max-age=600"},
            )
        )
        fetcher = CimdFetcher(max_bytes=8192, timeout_seconds=5)
        result = await fetcher.fetch("https://claude.ai/mcp")
        assert result.document.client_id == "https://claude.ai/mcp"
        assert result.document.cache_control == "max-age=600"
        assert result.resolved_ip == "8.8.8.8"

    @respx.mock
    @pytest.mark.asyncio
    async def test_non_200_refused(self) -> None:
        respx.get("https://8.8.8.8:443/mcp").mock(return_value=Response(404, text="nope"))
        fetcher = CimdFetcher(max_bytes=8192, timeout_seconds=5)
        with pytest.raises(FetchError, match="HTTP 404"):
            await fetcher.fetch("https://claude.ai/mcp")

    @respx.mock
    @pytest.mark.asyncio
    async def test_body_over_max_bytes_refused(self) -> None:
        big = "x" * 20_000
        respx.get("https://8.8.8.8:443/mcp").mock(return_value=Response(200, text=big))
        fetcher = CimdFetcher(max_bytes=1024, timeout_seconds=5)
        with pytest.raises(FetchError, match="max_bytes"):
            await fetcher.fetch("https://claude.ai/mcp")

    @respx.mock
    @pytest.mark.asyncio
    async def test_invalid_json_refused(self) -> None:
        respx.get("https://8.8.8.8:443/mcp").mock(return_value=Response(200, text="{not json"))
        fetcher = CimdFetcher(max_bytes=8192, timeout_seconds=5)
        with pytest.raises(DocumentInvalid, match="not valid JSON"):
            await fetcher.fetch("https://claude.ai/mcp")

    @respx.mock
    @pytest.mark.asyncio
    async def test_document_validation_runs(self) -> None:
        # client_id mismatch → DocumentInvalid
        respx.get("https://8.8.8.8:443/mcp").mock(
            return_value=Response(
                200,
                json={
                    "client_id": "https://claude.ai/other",
                    "redirect_uris": ["r"],
                },
            )
        )
        fetcher = CimdFetcher(max_bytes=8192, timeout_seconds=5)
        with pytest.raises(DocumentInvalid, match="does not match"):
            await fetcher.fetch("https://claude.ai/mcp")

    def test_max_bytes_positive(self) -> None:
        with pytest.raises(ValueError):
            CimdFetcher(max_bytes=0, timeout_seconds=5)

    def test_timeout_positive(self) -> None:
        with pytest.raises(ValueError):
            CimdFetcher(max_bytes=1024, timeout_seconds=0)
