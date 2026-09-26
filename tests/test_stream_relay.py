# FILE: tests/test_stream_relay.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the streaming relay: frame splitting across chunk boundaries, channel-aware restoration of text, tool-call arguments restored before the finish frame, and fail-closed behaviour.
#   SCOPE: iter_frames boundaries, hold buffer across deltas, trusted versus untrusted channel, tool-call accumulation, broken frame and store failure, keep-alive frames, journal records.
#   DEPENDS: M-STREAM-RELAY, M-DETOKENIZER, M-AUDIT
#   LINKS: V-M-STREAM-RELAY, M-STREAM-RELAY
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   FakePolicy - channel decision stub
#   FakeDetokenizer - restoration stub with the real sentinel format
#   IterFramesTests - frame boundary handling
#   StreamRelayTests - restoration, tools and fail-closed behaviour
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-11 шаг 3-6: поток рядом с непотоковым путём.
# END_CHANGE_SUMMARY

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.audit import AuditJournal  # noqa: E402
from src.channel_policy import DECISION_DETOKENIZE, DECISION_KEEP  # noqa: E402
from src.detokenizer import DetokenizeError, StreamDetokenizer  # noqa: E402
from src.stream_relay import DONE_FRAME, StreamRelay, confirmed_position, iter_frames  # noqa: E402
from src.token_factory import SENTINEL_CLOSE, SENTINEL_OPEN  # noqa: E402

CODE = f"{SENTINEL_OPEN}P-AB12CD34EF56{SENTINEL_CLOSE}"
PHONE = f"{SENTINEL_OPEN}T-AB12CD34EF56{SENTINEL_CLOSE}"
VALUES = {"P-AB12CD34EF56": "Иванов Иван", "T-AB12CD34EF56": "+79001112233"}


def frame(payload: dict | str) -> bytes:
    """Build one SSE frame the way a provider does."""
    if isinstance(payload, str):
        return f"data: {payload}\n\n".encode("utf-8")
    return b"data: " + json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n\n"


def delta_frame(content: str) -> bytes:
    """Build a text delta frame."""
    return frame({"choices": [{"index": 0, "delta": {"content": content}}]})


class FakePolicy:
    """Channel decision stub: Mattermost restores, anything else keeps codes."""

    def __init__(self, trusted: str = "mattermost") -> None:
        self._trusted = trusted

    def decide_for_text(self, channel: str | None) -> str:
        return DECISION_DETOKENIZE if str(channel or "") == self._trusted else DECISION_KEEP


class FakeDetokenizer:
    """Restoration stub that uses the real sentinel format and raise switches."""

    def __init__(self, trusted: str = "mattermost") -> None:
        self._policy = FakePolicy(trusted)
        self.fail = False
        self.text_calls = 0
        self.tool_calls = 0

    def _restore(self, text: str, allowed=None) -> tuple[str, int]:
        hits = 0
        for key, value in VALUES.items():
            marker = f"{SENTINEL_OPEN}{key}{SENTINEL_CLOSE}"
            if marker in text:
                text = text.replace(marker, value)
                hits += 1
        return text, hits

    def detokenize_text(self, text: str, channel=None, session_id="", allowed=None, occurrences=None):
        """Restore values in user-visible text.

        Дублёр повторяет интерфейс настоящего детокенизатора (Phase-7): потоковый путь
        передаёт сюда счётчик вхождений, и без параметра поток падал бы на дублёре.
        """
        self.text_calls += 1
        if self.fail:
            raise DetokenizeError("store_unavailable", "store is down")
        return self._restore(text, allowed)

    def detokenize_tool_args(self, payload: dict, session_id="", allowed=None):
        """Restore values inside tool-call arguments."""
        self.tool_calls += 1
        if self.fail:
            raise DetokenizeError("store_unavailable", "store is down")
        args = payload["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
        restored, hits = self._restore(args, allowed)
        payload["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = restored
        return payload, {"P": hits} if hits else {}


class IterFramesTests(unittest.TestCase):
    def test_frame_split_between_chunks_is_reassembled(self) -> None:
        raw = frame({"a": 1}) + frame({"b": 2})
        chunks = [raw[:7], raw[7:19], raw[19:]]
        frames = list(iter_frames(chunks))
        self.assertEqual(len(frames), 2)
        self.assertTrue(frames[0].endswith(b"\n\n"))

    def test_code_split_between_chunks_survives(self) -> None:
        """Код, разрезанный посередине, не теряется при разборе кадров."""
        body = delta_frame(f"клиент {CODE} записан")
        middle = body.index(SENTINEL_OPEN.encode("utf-8")) + 2
        frames = list(iter_frames([body[:middle], body[middle:]]))
        self.assertEqual(len(frames), 1)
        self.assertIn(CODE.encode("utf-8"), frames[0])

    def test_crlf_frames_are_understood(self) -> None:
        raw = b'data: {"a": 1}\r\n\r\ndata: [DONE]\r\n\r\n'
        frames = list(iter_frames([raw]))
        self.assertEqual(len(frames), 2)

    def test_tail_without_terminator_is_not_dropped(self) -> None:
        frames = list(iter_frames([b"data: {}\n\n", b"data: {\"b\""]))
        self.assertEqual(len(frames), 2)


class StreamRelayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.journal = AuditJournal(os.path.join(self.tmp.name, "audit.jsonl"))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def relay(self, chunks, channel: str = "mattermost", detokenizer=None, on_usage=None):
        detok = detokenizer or FakeDetokenizer()
        relay = StreamRelay(
            detok, self.journal, channel, "sess-1", frozenset(), on_usage=on_usage
        )
        return relay, list(relay.relay(iter(chunks)))

    def test_usage_frame_reaches_the_provider_cache_counter(self) -> None:
        """Служебный кадр `usage` обязан дойти до счётчика кэша: иначе фактор приёмки слеп.

        Мессенджеры ходят потоком, и до этой правки в healthz попадали только непотоковые
        вызовы: три запроса и ни одного попадания в кэш DeepSeek (живой разбор 19.09.2026).
        """
        seen: list[dict] = []
        usage_frame = frame(
            {
                "choices": [],
                "usage": {"prompt_cache_hit_tokens": 360448, "prompt_cache_miss_tokens": 20406},
            }
        )
        _relay, out = self.relay(
            [delta_frame("ок"), usage_frame, frame("[DONE]")], on_usage=seen.append
        )
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["usage"]["prompt_cache_hit_tokens"], 360448)
        # Кадр клиенту уходит без изменений: счётчик не имеет права править поток.
        self.assertIn(b"prompt_cache_hit_tokens", b"".join(out))

    def test_usage_frame_without_a_counter_is_passed_through(self) -> None:
        """Счётчика нет — поток всё равно уходит клиенту целиком."""
        usage_frame = frame({"choices": [], "usage": {"prompt_cache_hit_tokens": 1}})
        _relay, out = self.relay([usage_frame, frame("[DONE]")])
        self.assertIn(b"prompt_cache_hit_tokens", b"".join(out))

    def test_trusted_channel_restores_text(self) -> None:
        _relay, out = self.relay([delta_frame(f"клиент {CODE}"), frame("[DONE]")])
        text = b"".join(out).decode("utf-8")
        self.assertIn("Иванов Иван", text)
        self.assertNotIn("P:ab12", text)

    def test_untrusted_channel_keeps_codes(self) -> None:
        _relay, out = self.relay(
            [delta_frame(f"клиент {CODE}"), frame("[DONE]")], channel="telegram"
        )
        text = b"".join(out).decode("utf-8")
        self.assertNotIn("Иванов Иван", text)
        self.assertIn("P-AB12CD34EF56", text)

    def test_code_split_between_deltas_is_restored_whole(self) -> None:
        """Код разорван между двумя дельтами: буфер удержания собирает его обратно."""
        first = CODE[:6]
        second = CODE[6:]
        _relay, out = self.relay([delta_frame(first), delta_frame(second), frame("[DONE]")])
        text = b"".join(out).decode("utf-8")
        self.assertIn("Иванов Иван", text)
        self.assertNotIn("AB12CD34EF56", text)

    def test_keep_alive_frames_pass_through(self) -> None:
        _relay, out = self.relay([b": keep-alive\n\n", frame("[DONE]")])
        self.assertIn(b": keep-alive", b"".join(out))

    def test_tool_arguments_restored_before_finish_frame(self) -> None:
        """Аргументы инструмента уходят до кадра завершения, иначе агент исполнит пустое."""
        first = frame(
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "function": {"name": "fb_client", "arguments": '{"name": "'},
                                }
                            ]
                        },
                    }
                ]
            }
        )
        second = frame(
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {"index": 0, "function": {"arguments": f'{CODE}"}}'}}
                            ]
                        },
                    }
                ]
            }
        )
        finish = frame({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})
        _relay, out = self.relay([first, second, finish, frame("[DONE]")])
        text = b"".join(out).decode("utf-8")
        self.assertIn('"arguments": "{\\"name\\": \\"Иванов Иван\\"}"', text)
        self.assertLess(text.index('"arguments": "{\\"name\\"'), text.index('"finish_reason"'))

    def test_broken_frame_closes_the_stream(self) -> None:
        """Неразобранный кадр: поток закрывается ошибкой, частичный ответ не уходит."""
        bad = b"data: {not json\n\n"
        _relay, out = self.relay([delta_frame(f"{CODE}"), bad, frame("[DONE]")])
        text = b"".join(out).decode("utf-8")
        self.assertIn("stream_broken", text)
        self.assertTrue(text.endswith("[DONE]\n\n"))

    def test_store_failure_is_fail_closed(self) -> None:
        detok = FakeDetokenizer()
        detok.fail = True
        relay, out = self.relay([delta_frame(f"{CODE}"), frame("[DONE]")], detokenizer=detok)
        text = b"".join(out).decode("utf-8")
        self.assertIn("stream_broken", text)
        self.assertEqual(relay.restored, 0)

    def test_journal_records_stream_closed_without_values(self) -> None:
        _relay, _out = self.relay([delta_frame(f"клиент {CODE}"), frame("[DONE]")])
        raw = open(self.journal._path, encoding="utf-8").read()
        self.assertIn("stream_closed", raw)
        self.assertNotIn("Иванов", raw)
        self.assertNotIn("ab12", raw)

    def test_journal_records_stream_error(self) -> None:
        self.relay([b"data: {broken\n\n"])
        raw = open(self.journal._path, encoding="utf-8").read()
        self.assertIn("stream_error", raw)

    def test_tail_without_done_frame_is_flushed(self) -> None:
        """Провайдер закрыл поток без [DONE]: хвост всё равно доходит до клиента."""
        _relay, out = self.relay([delta_frame(f"клиент {CODE} записан")])
        text = b"".join(out).decode("utf-8")
        self.assertIn("Иванов Иван", text)
        self.assertIn("записан", text)

    def test_stream_detokenizer_uses_the_same_gate(self) -> None:
        """Проверка паритета: тот же канал — то же решение, что у буферного пути."""
        detok = FakeDetokenizer()
        for channel in ("mattermost", "telegram", None):
            stream = StreamDetokenizer(
                detok, channel, "sess-1", frozenset(), boundary=confirmed_position
            )
            self.assertEqual(
                stream._allowed,
                detok._policy.decide_for_text(channel) == DECISION_DETOKENIZE,
                msg=f"канал {channel!r}",
            )


if __name__ == "__main__":
    unittest.main()
