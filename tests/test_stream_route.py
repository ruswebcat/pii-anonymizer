# FILE: tests/test_stream_route.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the two-path routing added in Phase-11: a streaming request goes through the relay, a buffered request stays on the JSON path, and the json_only switch serves a streaming client from the buffered path.
#   SCOPE: path selection by the request flag, restoration on the stream for a trusted channel, retention for an untrusted one, json_only fallback, dry-run streaming, fail-closed before the first frame.
#   DEPENDS: M-ROUTER, M-STREAM-RELAY, M-CONFIG
#   LINKS: V-M-STREAM-RELAY, V-M-ROUTER, Phase-11
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   build_stream_chunks - canned provider SSE stream with a token in the text
#   StreamRouteTests - two-path routing behaviour
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-11 шаг 5: выбор пути и паритет восстановления.
# END_CHANGE_SUMMARY

import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.audit import AuditJournal  # noqa: E402
from src.normalize import normalize  # noqa: E402
from src.router import ProxyService, RouterError, StreamResponse, build_service  # noqa: E402
from src.token_factory import make_token  # noqa: E402
from tests import harness  # noqa: E402

CHAT_PATH = "/v1/chat/completions"
FIO = "Иванов Иван Иванович"
PHONE = "79000000001"


def build_stream_chunks(token: str, phone_token: str) -> list[bytes]:
    """Build a provider stream that carries issued tokens in text and tool arguments."""
    first = {
        "choices": [{"index": 0, "delta": {"role": "assistant", "content": f"Клиент {token[:5]}"}}]
    }
    second = {"choices": [{"index": 0, "delta": {"content": f"{token[5:]} , телефон {phone_token}"}}]}
    tool_start = {
        "choices": [
            {
                "index": 0,
                "delta": {
                    "tool_calls": [
                        {"index": 0, "function": {"name": "fb_client", "arguments": '{"name": "'}}
                    ]
                },
            }
        ]
    }
    # Хвост аргументов закрывает строку и объект: собираем отдельной переменной,
    # чтобы не путаться в фигурных скобках JSON и f-строки.
    tail = token + '"}'
    tool_end = {
        "choices": [
            {
                "index": 0,
                "delta": {"tool_calls": [{"index": 0, "function": {"arguments": tail}}]},
            }
        ]
    }
    finish = {"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}
    frames = [first, second, tool_start, tool_end, finish]
    return [b"data: " + json.dumps(f, ensure_ascii=False).encode("utf-8") + b"\n\n" for f in frames] + [
        b"data: [DONE]\n\n"
    ]


def stream_payload(channel: str = "mattermost", extra: dict | None = None) -> dict:
    """Build a streaming chat completion body carrying PII and the channel marker."""
    payload = {
        "model": "deepseek-flash",
        "stream": True,
        "messages": [
            {
                "role": "system",
                "content": f"Ты помощник. Метка: [[delivery:{channel}]]. Клиент {FIO}, телефон {PHONE}.",
            },
            {"role": "user", "content": "Дай сводку"},
        ],
    }
    if extra:
        payload.update(extra)
    return payload


class StreamRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.config = harness.temp_config(self._tmp.name)
        self.store = harness.temp_map_store(self._tmp.name)
        self.audit = AuditJournal(os.path.join(self._tmp.name, "audit.jsonl"))
        self.token_p = make_token("P", normalize("P", FIO), self.config.token_key)
        self.token_t = make_token("T", normalize("T", PHONE), self.config.token_key)
        self.store.store(self.token_p, "P", FIO)
        self.store.store(self.token_t, "T", PHONE)
        self.upstream = harness.FakeUpstream()
        self.upstream.stream_chunks = build_stream_chunks(self.token_p, self.token_t)
        self.service = build_service(
            self.config, store=self.store, upstream=self.upstream, audit=self.audit
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def collect(self, result) -> str:
        self.assertIsInstance(result, StreamResponse)
        return b"".join(result.chunks).decode("utf-8")

    def test_streaming_request_goes_through_the_relay(self) -> None:
        result = self.service.handle_chat_completions(stream_payload(), "ds", CHAT_PATH, None)
        text = self.collect(result)
        self.assertIn("[DONE]", text)
        self.assertIn("Иванов Иван Иванович", text)
        self.assertNotIn("P:", text.split('"arguments"')[0])

    def test_streamed_usage_updates_the_provider_cache_metric(self) -> None:
        """Кэш провайдера обязан считаться на потоковом пути — им ходят мессенджеры.

        Дефект 19.09.2026: счётчик наполнялся только непотоковыми вызовами, поэтому в
        healthz живого контура было три запроса и ни одного попадания, хотя владелец назвал
        попадание в кэш DeepSeek ключевым фактором приёмки.
        """
        usage_frame = b"data: " + json.dumps(
            {
                "choices": [],
                "usage": {"prompt_cache_hit_tokens": 360448, "prompt_cache_miss_tokens": 20406},
            }
        ).encode("utf-8") + b"\n\n"
        self.upstream.stream_chunks = list(self.upstream.stream_chunks) + [usage_frame]
        result = self.service.handle_chat_completions(stream_payload(), "ds", CHAT_PATH, None)
        self.collect(result)
        provider_cache = self.service.health()["provider_cache"]
        self.assertEqual(provider_cache["requests"], 1)
        self.assertEqual(provider_cache["hit_tokens"], 360448)
        self.assertEqual(provider_cache["miss_tokens"], 20406)

    def test_buffered_request_keeps_the_json_path(self) -> None:
        payload = stream_payload()
        payload["stream"] = False
        payload["messages"][0]["content"] = "Ты помощник. Клиент " + FIO
        status, body = self.service.handle_chat_completions(payload, "ds", CHAT_PATH, None)
        self.assertEqual(status, 200)
        self.assertIn("choices", body)
        self.assertEqual(self.upstream.calls[-1]["payload"].get("stream"), False)

    def test_untrusted_channel_keeps_codes_on_the_stream(self) -> None:
        """Telegram: текст не восстанавливается, аргументы инструментов — всегда.

        Так решено владельцем: аргументы исполняет агент, а не человек, поэтому
        они восстанавливаются на любом канале; текст — только на доверенном.
        """
        result = self.service.handle_chat_completions(
            stream_payload(channel="telegram"), "ds", CHAT_PATH, None
        )
        text = self.collect(result)
        visible = text.split('"arguments"')[0]
        self.assertNotIn("Иванов Иван Иванович", visible)
        self.assertNotIn("79000000001", visible)
        self.assertIn("Иванов Иван Иванович", text)

    def test_tool_arguments_are_restored_on_the_stream(self) -> None:
        result = self.service.handle_chat_completions(stream_payload(), "ds", CHAT_PATH, None)
        text = self.collect(result)
        self.assertIn("Иванов Иван Иванович", text)
        self.assertIn("fb_client", text)

    def test_json_only_mode_serves_one_frame(self) -> None:
        config = replace(self.config, stream_mode="json_only")
        service = build_service(
            config, store=self.store, upstream=self.upstream, audit=self.audit
        )
        payload = stream_payload()
        result = service.handle_chat_completions(payload, "ds", CHAT_PATH, None)
        text = self.collect(result)
        frames = [line for line in text.splitlines() if line.startswith("data:")]
        self.assertEqual(len(frames), 2)
        self.assertTrue(frames[-1].endswith("[DONE]"))
        # Провайдеру поток не запрашивается: обмен идёт как раньше.
        self.assertNotIn("stream", self.upstream.calls[-1]["payload"])

    def test_dry_run_streams_without_calling_the_provider(self) -> None:
        config = replace(self.config, dry_run=True)
        service = build_service(
            config, store=self.store, upstream=self.upstream, audit=self.audit
        )
        before = len(self.upstream.calls)
        result = service.handle_chat_completions(stream_payload(), "ds", CHAT_PATH, None)
        text = self.collect(result)
        self.assertIn("dry_run", text)
        self.assertEqual(len(self.upstream.calls), before)

    def test_failure_before_the_stream_is_still_a_status(self) -> None:
        """Fail-closed до первого кадра: неизвестный маршрут даёт ошибку, а не поток."""
        with self.assertRaises(RouterError):
            self.service.handle_chat_completions(stream_payload(), "nope", CHAT_PATH, None)
        self.assertEqual(len(self.upstream.calls), 0)

    def test_stream_closes_with_a_journal_record(self) -> None:
        """Журнал пишется при вычитывании потока, а не при его создании."""
        result = self.service.handle_chat_completions(stream_payload(), "ds", CHAT_PATH, None)
        self.collect(result)
        with open(self.audit._path, encoding="utf-8") as handle:
            raw = handle.read()
        self.assertIn("stream_closed", raw)
        self.assertNotIn("Иванов", raw)


if __name__ == "__main__":
    unittest.main()
