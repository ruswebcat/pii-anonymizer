# FILE: tests/test_upstream.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-UPSTREAM contract: URLs and keys are built from config, failures map to stable codes, and the streaming tail buffer keeps a token whole.
#   SCOPE: url building, key injection, non-streaming round trip, HTTP and URL errors, invalid JSON, tail buffered streaming equivalence.
#   DEPENDS: M-UPSTREAM, M-TEST-HARNESS
#   LINKS: V-M-UPSTREAM, M-UPSTREAM
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   FakeResponse - response double for the injectable opener
#   UpstreamTests - unittest case set for UpstreamClient
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-1 M-UPSTREAM verification.
# END_CHANGE_SUMMARY

import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.upstream import DEFAULT_TAIL, UpstreamClient, UpstreamError  # noqa: E402
from tests import harness  # noqa: E402


class FakeResponse:
    """Response double with a status, a body and an optional chunk size."""

    def __init__(self, body: bytes, status: int = 200, chunk_size: int | None = None) -> None:
        self.status = status
        self._body = body
        self._chunk_size = chunk_size
        self._offset = 0

    def read(self, size: int | None = None) -> bytes:
        if size is None:
            data = self._body[self._offset :]
            self._offset = len(self._body)
            return data
        data = self._body[self._offset : self._offset + size]
        self._offset += len(data)
        return data

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc_info) -> None:
        return None

    def close(self) -> None:
        return None


class UpstreamTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.config = harness.temp_config(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _client(self, response) -> UpstreamClient:
        def opener(request, timeout):
            opener.last_request = request  # type: ignore[attr-defined]
            opener.last_timeout = timeout  # type: ignore[attr-defined]
            if isinstance(response, Exception):
                raise response
            return response

        return UpstreamClient(self.config, opener=opener)

    def test_build_url_uses_route_table(self) -> None:
        client = self._client(FakeResponse(b"{}"))
        self.assertEqual(
            client.build_url("ds", "/v1/chat/completions"),
            "https://api.deepseek.com/v1/chat/completions",
        )
        self.assertEqual(
            client.build_url("nord", "/v1/chat/completions"),
            "https://nordrouter.com/v1/chat/completions",
        )

    def test_build_url_without_leading_slash(self) -> None:
        client = self._client(FakeResponse(b"{}"))
        self.assertEqual(
            client.build_url("ds", "v1/models"), "https://api.deepseek.com/v1/models"
        )

    def test_unknown_route_rejected(self) -> None:
        client = self._client(FakeResponse(b"{}"))
        with self.assertRaises(UpstreamError) as ctx:
            client.build_url("mystery", "/v1")
        self.assertEqual(ctx.exception.code, "UPSTREAM_BAD_ROUTE")

    def test_request_carries_provider_key(self) -> None:
        client = self._client(FakeResponse(b"{}"))
        request = client.build_request("ds", "/v1/chat/completions", {"messages": []})
        self.assertEqual(request.get_header("Authorization"), "Bearer ds-test")
        self.assertEqual(request.get_header("Content-type"), "application/json")

    def test_forward_json_round_trip(self) -> None:
        body = json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()
        client = self._client(FakeResponse(body))
        status, parsed = client.forward_json("ds", "/v1/chat/completions", {"messages": []})
        self.assertEqual(status, 200)
        self.assertEqual(parsed["choices"][0]["message"]["content"], "ok")

    def test_http_error_maps_to_stable_code(self) -> None:
        error = urllib.error.HTTPError(
            "https://api.deepseek.com/v1",
            401,
            "unauthorized",
            None,  # type: ignore[arg-type] - runtime accepts None for headers
            io.BytesIO(b'{"detail":"nope"}'),
        )
        client = self._client(error)
        with self.assertRaises(UpstreamError) as ctx:
            client.forward_json("ds", "/v1/chat/completions", {})
        self.assertEqual(ctx.exception.code, "UPSTREAM_UNAUTHORIZED")
        self.assertEqual(ctx.exception.status, 401)

    def test_url_error_maps_to_timeout(self) -> None:
        client = self._client(urllib.error.URLError("timed out"))
        with self.assertRaises(UpstreamError) as ctx:
            client.forward_json("ds", "/v1/chat/completions", {})
        self.assertEqual(ctx.exception.code, "UPSTREAM_TIMEOUT")

    def test_non_json_body_maps_to_bad_gateway(self) -> None:
        client = self._client(FakeResponse(b"<html>error</html>"))
        with self.assertRaises(UpstreamError) as ctx:
            client.forward_json("ds", "/v1/chat/completions", {})
        self.assertEqual(ctx.exception.code, "UPSTREAM_BAD_GATEWAY")

    def test_missing_key_rejected(self) -> None:
        class KeylessConfig:
            routes = {"ds": "https://api.deepseek.com"}
            provider_keys: dict = {}
            request_timeout = 30

        client = UpstreamClient(KeylessConfig(), opener=lambda request, timeout: FakeResponse(b"{}"))  # type: ignore[arg-type]
        with self.assertRaises(UpstreamError) as ctx:
            client.build_request("ds", "/v1/chat/completions", {})
        self.assertEqual(ctx.exception.code, "UPSTREAM_UNAUTHORIZED")

    def test_stream_tail_preserves_every_byte(self) -> None:
        payload = b"data: " + ("\u27e6T-ABCDEF234567\u27e7" * 5).encode() + b"\n\n"
        chunks = [payload[index : index + 7] for index in range(0, len(payload), 7)]
        emitted = list(UpstreamClient.iter_with_tail(chunks, tail=DEFAULT_TAIL))
        self.assertEqual(b"".join(emitted), payload)

    def test_stream_tail_holds_back_at_least_tail_bytes(self) -> None:
        chunks = [b"a" * 100, b"b" * 100, b"c" * 100]
        emitted = list(UpstreamClient.iter_with_tail(chunks, tail=64))
        self.assertEqual(len(emitted), 4)
        self.assertLessEqual(len(emitted[-1]), 64)
        self.assertEqual(b"".join(emitted), b"".join(chunks))

    def test_forward_stream_yields_chunks(self) -> None:
        body = b"data: " + b"x" * 3000 + b"\n\n"
        client = self._client(FakeResponse(body))
        chunks = list(client.forward_stream("ds", "/v1/chat/completions", {"stream": True}))
        self.assertEqual(b"".join(chunks), body)
        self.assertGreater(len(chunks), 2)


if __name__ == "__main__":
    unittest.main()
