# FILE: src/upstream.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Forward anonymized requests to the configured model providers with the right key and pass non-streaming and streaming responses back.
#   SCOPE: URL building from the route table, key injection, JSON forwarding, SSE chunk streaming with a tail buffer that keeps tokens unbroken, stable error codes.
#   DEPENDS: M-CONFIG
#   LINKS: M-UPSTREAM, V-M-UPSTREAM, fn-forward_json, fn-forward_stream, fn-iter_with_tail
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   DEFAULT_TAIL - bytes held back while streaming
#   UpstreamError - transport failure with a stable code
#   UpstreamClient - provider transport owned by the proxy
#   fn-forward_json - send a non-streaming request
#   fn-forward_stream - yield streaming chunks
#   fn-iter_with_tail - hold back a tail so tokens cannot be split
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-1 M-UPSTREAM: key injection moved into the proxy; no payload or header is ever logged.
# END_CHANGE_SUMMARY

"""Upstream transport.

Implements M-UPSTREAM from docs/ARCHITECTURE.md. The proxy owns the
provider keys, so the agent never talks to a provider directly. Streaming keeps
a tail buffer (risk-2 in the plan): a token must not be split between SSE chunks
or the model would receive half a sentinel and detokenization would break.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Iterator
from typing import Any

from src.config import ProxyConfig

LOGGER_NAME = "UpstreamClient"
LOG_MARKER = "[UpstreamClient][forward_stream][BLOCK_FORWARD_STREAM]"

DEFAULT_TAIL = 64
STREAM_READ_SIZE = 1024


class UpstreamError(RuntimeError):
    """Transport failure with a stable code.

    # START_CONTRACT: UpstreamError
    #   PURPOSE: Give the router a stable failure classification.
    #   INPUTS: { code: str - stable code, message: str - detail, status: int - http status }
    #   OUTPUTS: { UpstreamError - exception instance }
    #   SIDE_EFFECTS: none
    #   LINKS: M-UPSTREAM, M-ROUTER, V-M-UPSTREAM
    # END_CONTRACT: UpstreamError
    """

    def __init__(self, code: str, message: str, status: int = 502) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status = status


# START_BLOCK_FORWARD_STREAM
class UpstreamClient:
    """Transport to the model providers on behalf of the agent.

    # START_CONTRACT: UpstreamClient
    #   PURPOSE: Build requests from the route table and stream responses back.
    #   INPUTS: { config: ProxyConfig, opener: Callable | None - injectable transport for tests }
    #   OUTPUTS: { UpstreamClient - ready client }
    #   SIDE_EFFECTS: performs outbound HTTPS calls
    #   LINKS: M-CONFIG, M-ROUTER, V-M-UPSTREAM
    # END_CONTRACT: UpstreamClient
    """

    def __init__(
        self,
        config: ProxyConfig,
        opener: Callable[[urllib.request.Request, int], Any] | None = None,
    ) -> None:
        self._config = config
        self._open = opener or (lambda request, timeout: urllib.request.urlopen(request, timeout=timeout))

    def build_url(self, route: str, path: str) -> str:
        """Return the absolute upstream URL for a route prefix and path."""
        base = self._config.routes.get(route)
        if base is None:
            raise UpstreamError("UPSTREAM_BAD_ROUTE", f"неизвестный префикс маршрута: {route!r}", status=404)
        if not path.startswith("/"):
            path = "/" + path
        return base + path

    def build_request(self, route: str, path: str, payload: dict) -> urllib.request.Request:
        """Build an authorized JSON request for the provider.

        # START_CONTRACT: build_request
        #   PURPOSE: Inject the provider key and JSON body.
        #   INPUTS: { route: str - route prefix, path: str - upstream path, payload: dict - anonymized body }
        #   OUTPUTS: { urllib.request.Request - ready request }
        #   SIDE_EFFECTS: none
        #   LINKS: M-CONFIG, V-M-UPSTREAM
        # END_CONTRACT: build_request
        """
        key = self._config.provider_keys.get(route)
        if not key:
            raise UpstreamError("UPSTREAM_UNAUTHORIZED", f"no key for route {route!r}", status=401)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return urllib.request.Request(
            self.build_url(route, path),
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {key}",
            },
        )

    def forward_json(
        self, route: str, path: str, payload: dict, timeout: int | None = None
    ) -> tuple[int, dict]:
        """Send a non-streaming request and return status plus parsed body.

        # START_CONTRACT: forward_json
        #   PURPOSE: One-shot request/response exchange.
        #   INPUTS: { route: str, path: str, payload: dict, timeout: int | None }
        #   OUTPUTS: { tuple[int, dict] - status and response body }
        #   SIDE_EFFECTS: performs an outbound HTTPS call
        #   LINKS: M-ROUTER, V-M-UPSTREAM
        # END_CONTRACT: forward_json
        """
        request = self.build_request(route, path, payload)
        effective_timeout = timeout or self._config.request_timeout
        try:
            with self._open(request, effective_timeout) as response:
                status = getattr(response, "status", 200)
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            code = "UPSTREAM_UNAUTHORIZED" if exc.code == 401 else "UPSTREAM_BAD_GATEWAY"
            raise UpstreamError(code, f"provider returned {exc.code}: {detail}", status=exc.code) from exc
        except urllib.error.URLError as exc:
            raise UpstreamError("UPSTREAM_TIMEOUT", f"provider unreachable: {exc.reason}") from exc
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise UpstreamError("UPSTREAM_BAD_GATEWAY", "provider returned non-JSON body") from exc
        return int(status), parsed

    def forward_stream(
        self, route: str, path: str, payload: dict, timeout: int | None = None
    ) -> Iterator[bytes]:
        """Yield streaming chunks from the provider.

        # START_CONTRACT: forward_stream
        #   PURPOSE: Pass SSE through while keeping the connection alive.
        #   INPUTS: { route: str, path: str, payload: dict, timeout: int | None }
        #   OUTPUTS: { Iterator[bytes] - raw chunks }
        #   SIDE_EFFECTS: performs an outbound HTTPS call
        #   LINKS: M-ROUTER, V-M-UPSTREAM
        # END_CONTRACT: forward_stream
        """
        request = self.build_request(route, path, payload)
        effective_timeout = timeout or self._config.request_timeout
        try:
            response = self._open(request, effective_timeout)
        except urllib.error.HTTPError as exc:
            code = "UPSTREAM_UNAUTHORIZED" if exc.code == 401 else "UPSTREAM_BAD_GATEWAY"
            raise UpstreamError(code, f"provider returned {exc.code}", status=exc.code) from exc
        except urllib.error.URLError as exc:
            raise UpstreamError("UPSTREAM_TIMEOUT", f"provider unreachable: {exc.reason}") from exc

        def generator() -> Iterator[bytes]:
            try:
                while True:
                    chunk = response.read(STREAM_READ_SIZE)
                    if not chunk:
                        break
                    yield chunk
            finally:
                close = getattr(response, "close", None)
                if callable(close):
                    close()

        return generator()

    @staticmethod
    def iter_with_tail(chunks: Iterable[bytes], tail: int = DEFAULT_TAIL) -> Iterator[bytes]:
        """Yield chunks while holding back the last ``tail`` bytes.

        # START_CONTRACT: iter_with_tail
        #   PURPOSE: Guarantee that a downstream detokenizer never sees half a token.
        #   INPUTS: { chunks: Iterable[bytes] - raw chunks, tail: int - bytes to hold back }
        #   OUTPUTS: { Iterator[bytes] - chunks with the tail preserved for the next round }
        #   SIDE_EFFECTS: none
        #   LINKS: M-DETOKENIZER, V-M-UPSTREAM
        # END_CONTRACT: iter_with_tail
        """
        if tail <= 0:
            for chunk in chunks:
                yield chunk
            return
        pending = b""
        for chunk in chunks:
            pending += chunk
            if len(pending) <= tail:
                continue
            emit, pending = pending[:-tail], pending[-tail:]
            yield emit
        if pending:
            yield pending
# END_BLOCK_FORWARD_STREAM
