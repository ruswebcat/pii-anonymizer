# FILE: tools/stream_probe.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Prove end to end over real sockets that a streaming request goes through the proxy, reaches the provider anonymized, and comes back restored only on a trusted channel.
#   SCOPE: fake SSE provider, real proxy service with the real dictionary, token split across chunks, channel comparison, counts only.
#   DEPENDS: M-ROUTER, M-STREAM-RELAY, M-TOKENIZER, M-DETOKENIZER
#   LINKS: V-M-STREAM-RELAY, Phase-11
#   ROLE: TOOL
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   FakeProvider - SSE provider that records what it received
#   run_probe - end-to-end run for one channel
#   main - command line entry point
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-11 шаг 7: прибор замера потока.
# END_CHANGE_SUMMARY

"""Streaming probe (Phase-11).

Проверяет поток на живом сокете: поднимает поддельного провайдера, который
отвечает потоком SSE и записывает, что именно до него дошло, и настоящий прокси
с настоящим словарём. Значения для проверки — синтетические, ПД клиентов в
скрипте нет. Наружу печатаются только числа.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import urllib.request
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.config import load_config  # noqa: E402
from src.router import build_service, make_handler  # noqa: E402

ENV_FILE = Path.home() / ".config/pii-proxy/pii-proxy.env"
PROBE_FIO = "Иванов Иван Иванович"
PROBE_PHONE = "+79001112233"
PROBE_VALUES = (PROBE_FIO, PROBE_PHONE)
SPLIT_AT = 6


def read_env_file(path: Path) -> dict[str, str]:
    """Read a systemd environment file into a mapping."""
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


class FakeProvider:
    """SSE provider that echoes the anonymized text and records the request."""

    def __init__(self) -> None:
        self.bodies: list[str] = []
        self.server: ThreadingHTTPServer | None = None
        self.port = 0

    def start(self) -> str:
        """Start the provider on a free port and return its base URL."""

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

            def do_POST(self) -> None:  # noqa: N802 - stdlib signature
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length).decode("utf-8")
                self.server.provider.bodies.append(raw)  # type: ignore[attr-defined]
                payload = json.loads(raw)
                message = payload.get("messages")[-1].get("content") or ""
                if not payload.get("stream"):
                    # Клиент потока не просил (режим json_only): отвечаем как обычный провайдер.
                    body = json.dumps(
                        {"choices": [{"index": 0, "message": {"role": "assistant", "content": message}}]},
                        ensure_ascii=False,
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                frames = []
                half = SPLIT_AT
                for part in (message[:half], message[half : half * 2], message[half * 2 :]):
                    frames.append(
                        b"data: "
                        + json.dumps(
                            {"choices": [{"index": 0, "delta": {"content": part}}]},
                            ensure_ascii=False,
                        ).encode("utf-8")
                        + b"\n\n"
                    )
                frames.append(
                    b"data: "
                    + json.dumps({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}).encode(
                        "utf-8"
                    )
                    + b"\n\n"
                )
                frames.append(b"data: [DONE]\n\n")
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                for frame in frames:
                    self.wfile.write(b"%x\r\n" % len(frame) + frame + b"\r\n")
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.provider = self  # type: ignore[attr-defined]
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{self.port}/v1"

    def stop(self) -> None:
        """Stop the provider."""
        if self.server is not None:
            self.server.shutdown()


class ProxyRig:
    """Real proxy service on a local port, wired to the fake provider."""

    def __init__(self, base_url: str, stream_mode: str) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        env = read_env_file(ENV_FILE)
        env["PII_PROXY_MAP_DB"] = os.path.join(self.tmp.name, "probe_map.db")
        env["PII_PROXY_AUDIT_LOG"] = os.path.join(self.tmp.name, "probe_audit.jsonl")
        config = load_config(env)
        config = replace(
            config,
            host="127.0.0.1",
            port=0,
            routes={"ds": base_url},
            stream_mode=stream_mode,
            dry_run=False,
        )
        self.container = [config]
        self.service = build_service(config)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.service))
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        """Stop the proxy and drop the temporary store."""
        self.server.shutdown()
        self.tmp.cleanup()


def run_probe(channel: str, stream_mode: str = "auto") -> dict:
    """Run one end-to-end streaming request and return counts only."""
    provider = FakeProvider()
    base_url = provider.start()
    rig = ProxyRig(base_url, stream_mode)
    try:
        payload = {
            "model": "probe-model",
            "stream": True,
            "messages": [
                {
                    "role": "system",
                    "content": f"Ты помощник. Метка канала доставки: [[delivery:{channel}]]",
                },
                {"role": "user", "content": f"Клиент {PROBE_FIO}, телефон {PROBE_PHONE}."},
            ],
        }
        request = urllib.request.Request(
            f"http://127.0.0.1:{rig.port}/ds/v1/chat/completions",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            content_type = response.headers.get("Content-Type", "")
            raw = response.read().decode("utf-8")
    finally:
        provider.stop()
        rig.stop()

    upstream_text = " ".join(provider.bodies)
    return {
        "channel": channel,
        "stream_mode": stream_mode,
        "content_type_is_sse": content_type.startswith("text/event-stream"),
        "has_done_frame": "[DONE]" in raw,
        "frames": len([line for line in raw.splitlines() if line.startswith("data:")]),
        "values_in_provider_request": sum(1 for value in PROBE_VALUES if value in upstream_text),
        "values_in_client_answer": sum(1 for value in PROBE_VALUES if value in raw),
        "token_leaked_to_client": any("P:" in line and "[[" in raw for line in raw.splitlines()),
    }


def main() -> int:
    """Run the probe for both channels and for the buffered fallback."""
    rows = [
        run_probe("mattermost"),
        run_probe("telegram"),
        run_probe("mattermost", stream_mode="json_only"),
    ]
    print("| Канал | Режим | Тип ответа | Кадров | [DONE] | ПД у провайдера | ПД у клиента |")
    print("|---|---|---|---|---|---|---|")
    for row in rows:
        print(
            f"| {row['channel']} | {row['stream_mode']} | "
            f"{'SSE' if row['content_type_is_sse'] else 'JSON'} | "
            f"{row['frames']} | {'да' if row['has_done_frame'] else 'нет'} | "
            f"{row['values_in_provider_request']} | {row['values_in_client_answer']} |"
        )
    ok = (
        all(row["content_type_is_sse"] and row["has_done_frame"] for row in rows)
        and all(row["values_in_provider_request"] == 0 for row in rows)
        and rows[0]["values_in_client_answer"] == len(PROBE_VALUES)
        and rows[1]["values_in_client_answer"] == 0
        and rows[2]["values_in_client_answer"] == len(PROBE_VALUES)
    )
    print("итог:", "ПРОЙДЕНО" if ok else "НЕ ПРОЙДЕНО")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
