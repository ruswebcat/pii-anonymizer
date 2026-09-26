# FILE: tests/test_detokenizer.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-DETOKENIZER contract: tool arguments are always restored, text only on trusted channels, unknown tokens never guessed, and streaming never emits half a token.
#   SCOPE: text restoration by channel, channel_blocked auditing, unknown token handling, JSON tool arguments, response walking, stream hold buffer behaviour.
#   DEPENDS: M-DETOKENIZER, M-TEST-HARNESS
#   LINKS: V-M-DETOKENIZER, VF-002, VF-003
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   DetokenizerTests - unittest case set for PayloadDetokenizer and StreamDetokenizer
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-1 M-DETOKENIZER verification.
# END_CHANGE_SUMMARY

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.audit import AuditJournal  # noqa: E402
from src.channel_policy import ChannelPolicy  # noqa: E402
from src.detokenizer import (  # noqa: E402
    PayloadDetokenizer,
    StreamDetokenizer,
    collect_identifiers,
)
from src.map_store import MapStoreError, TokenMapStore  # noqa: E402
from src.stream_relay import confirmed_position  # noqa: E402 - критерий разреза задаёт вызывающий
from src.token_factory import make_token  # noqa: E402
from tests import harness  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()

KEY = b"detokenizer-test-key-32-bytes!!!"
FIO = "Иванов Иван Иванович"
LEGACY_FRAMED_P = "[[P-ABCDEF234567]]"
LEGACY_EXOTIC_P = "\u27e6P-ABCDEF234567\u27e7"


class RequestScopedDetokenizer:
    """The detokenizer as the router drives it: the request allow-list is supplied.

    Phase-4 mechanism 2 restores only identifiers that were present in the
    request, so these unit tests model exactly that — whatever the response
    mentions is treated as having been in the request. The gate itself is
    verified separately against the real detokenizer with an explicit allow-list.
    """

    def __init__(self, inner) -> None:
        self._inner = inner

    def __getattr__(self, name: str):
        return getattr(self._inner, name)

    def detokenize_text(self, text, channel, session_id="", allowed=None):
        allowed = collect_identifiers(text) if allowed is None else allowed
        return self._inner.detokenize_text(text, channel, session_id, allowed)

    def detokenize_string(self, text, session_id="", allowed=None):
        allowed = collect_identifiers(text) if allowed is None else allowed
        return self._inner.detokenize_string(text, session_id, allowed)

    def detokenize_tool_args(self, payload, session_id="", allowed=None):
        if allowed is None:
            allowed = collect_identifiers(json.dumps(payload, ensure_ascii=False))
        return self._inner.detokenize_tool_args(payload, session_id, allowed)

    def detokenize_response(self, payload, channel, session_id="", allowed=None):
        if allowed is None:
            allowed = collect_identifiers(json.dumps(payload, ensure_ascii=False))
        return self._inner.detokenize_response(payload, channel, session_id, allowed)


class DetokenizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = harness.temp_map_store(self._tmp.name)
        self.audit = AuditJournal(os.path.join(self._tmp.name, "audit.jsonl"))
        self.policy = ChannelPolicy({"mattermost", "local"})
        self.real = PayloadDetokenizer(self.store, self.policy, self.audit)
        self.detokenizer = RequestScopedDetokenizer(self.real)
        self.token = make_token("P", "иванов иван иванович", KEY)
        self.store.store(self.token, "P", FIO)

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def test_text_restored_for_mattermost(self) -> None:
        text, counters = self.detokenizer.detokenize_text(
            f"клиент {self.token} продлил", "mattermost", "s1"
        )
        self.assertEqual(text, f"клиент {FIO} продлил")
        self.assertEqual(counters["replaced"], 1)

    def test_text_kept_for_telegram_and_audited(self) -> None:
        text, counters = self.detokenizer.detokenize_text(f"клиент {self.token}", "telegram", "s1")
        self.assertIn(self.token, text)
        self.assertNotIn(FIO, text)
        self.assertEqual(counters["kept"], 1)
        actions = [record["action"] for record in self.audit.export_for_regulator()]
        self.assertIn("channel_blocked", actions)

    def test_truncated_token_at_the_end_is_replaced(self) -> None:
        """An answer cut mid-token must not show token debris to the reader."""
        text = "Список обзвона:\n19. Наталья / нет / ⟦T-T7EUOEUNGB"
        restored, counts = self.detokenizer.detokenize_text(text, "mattermost")
        self.assertNotIn("[[", restored)
        self.assertTrue(restored.endswith("…"))
        self.assertGreaterEqual(counts.get("unknown", 0), 1)

    def test_unknown_token_is_counted_and_kept(self) -> None:
        unknown = "\u27e6P-ZZZZZZZZZZZZ\u27e7"
        text, counters = self.detokenizer.detokenize_text(unknown, "mattermost", "s1")
        self.assertEqual(text, unknown)
        self.assertEqual(counters["unknown"], 1)

    def test_tool_arguments_always_restored(self) -> None:
        payload = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "crm_get_client",
                                    "arguments": json.dumps({"fio": self.token}, ensure_ascii=False),
                                }
                            }
                        ]
                    }
                }
            ]
        }
        restored, counters = self.detokenizer.detokenize_tool_args(payload, "s1")
        arguments = json.loads(restored["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"])
        self.assertEqual(arguments["fio"], FIO)
        self.assertEqual(counters["replaced"], 1)

    def test_ascii_framing_survives_a_json_round_trip(self) -> None:
        """ASCII framing needs no escaping, which is why it replaced the exotic one.

        The exotic brackets were also seen escaped as ``\\u27e6``; the ASCII form
        survives json.dumps verbatim, so there is no escape surface left to miss.
        """
        escaped = json.dumps({"fio": self.token}, ensure_ascii=True)
        self.assertIn(self.token, escaped)
        self.assertNotIn("\\u005b", escaped)
        payload = {"choices": [{"message": {"tool_calls": [{"function": {"arguments": escaped}}]}}]}
        restored, counters = self.detokenizer.detokenize_tool_args(payload, "s1")
        arguments = restored["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
        self.assertEqual(json.loads(arguments)["fio"], FIO)
        self.assertEqual(counters["replaced"], 1)

    def test_legacy_framed_token_is_still_restored(self) -> None:
        """Bindings created before the compact form must keep resolving."""
        self.store.store(LEGACY_FRAMED_P, "P", FIO)
        text, counters = self.detokenizer.detokenize_text(
            f"клиент {LEGACY_FRAMED_P}", "mattermost"
        )
        self.assertEqual(text, f"клиент {FIO}")
        self.assertEqual(counters["replaced"], 1)

    def test_legacy_exotic_token_is_still_restored(self) -> None:
        """The original exotic framing is read through the canonical form."""
        self.store.store(LEGACY_FRAMED_P, "P", FIO)
        text, counters = self.detokenizer.detokenize_text(
            f"клиент {LEGACY_EXOTIC_P}", "mattermost"
        )
        self.assertEqual(text, f"клиент {FIO}")
        self.assertEqual(counters["replaced"], 1)

    def test_legacy_escaped_token_is_still_restored(self) -> None:
        self.store.store(LEGACY_FRAMED_P, "P", FIO)
        escaped = json.dumps({"fio": LEGACY_EXOTIC_P}, ensure_ascii=True)
        self.assertIn("\\u27e6", escaped)
        payload = {"choices": [{"message": {"tool_calls": [{"function": {"arguments": escaped}}]}}]}
        # The allow-list comes from the request, where the identifier appeared in
        # its raw form — exactly as the router would supply it.
        restored, counters = self.real.detokenize_tool_args(
            payload, "s1", collect_identifiers(LEGACY_FRAMED_P)
        )
        arguments = restored["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
        self.assertEqual(json.loads(arguments)["fio"], FIO)
        self.assertEqual(counters["replaced"], 1)

    # START_BLOCK_RESTORE_GUARD
    def test_code_absent_from_the_request_is_not_restored(self) -> None:
        """Механизм 2: код, которого не было в запросе, значение не подставляет."""
        text, counters = self.real.detokenize_text(
            f"клиент {self.token}", "mattermost", "s1", frozenset()
        )
        self.assertEqual(text, f"клиент {self.token}")
        self.assertEqual(counters["replaced"], 0)
        self.assertEqual(counters["not_in_request"], 1)

    def test_foreign_code_cannot_inject_another_value(self) -> None:
        """Даже существующий код чужого клиента не восстановится, если его не было в запросе.

        Это защита от придуманного моделью кода: без неё короткий код мог бы
        подставить другому человеку чужое значение.
        """
        foreign = make_token("P", "петров пётр петрович", KEY)
        self.store.store(foreign, "P", "Петров Пётр Петрович")
        allowed = collect_identifiers(f"в запросе был только {self.token}")
        text, counters = self.real.detokenize_text(
            f"клиент {foreign}", "mattermost", "s1", allowed
        )
        self.assertNotIn("Петров", text)
        self.assertIn(foreign, text)
        self.assertEqual(counters["not_in_request"], 1)

    def test_missing_allow_list_restores_nothing(self) -> None:
        """Забытый набор означает «ничего не восстанавливаем»: отказ, а не дыра."""
        text, counters = self.real.detokenize_text(f"клиент {self.token}", "mattermost", "s1")
        self.assertIn(self.token, text)
        self.assertEqual(counters["replaced"], 0)

    def test_allow_list_from_the_request_restores(self) -> None:
        """Набор, собранный из тела запроса, восстанавливает значение."""
        allowed = collect_identifiers(f"история: клиент {self.token}")
        text, counters = self.real.detokenize_text(
            f"ответ про {self.token}", "mattermost", "s1", allowed
        )
        self.assertEqual(text, f"ответ про {FIO}")
        self.assertEqual(counters["replaced"], 1)
    # END_BLOCK_RESTORE_GUARD

    def test_bare_legacy_code_is_restored(self) -> None:
        """The model drops the framing; the reader must still get the value.

        Measured 16.09.2026: asked to copy a code, the model returned
        "P-DAEL6G25PQGC" without brackets 6 times out of 6.
        """
        self.store.store(LEGACY_FRAMED_P, "P", FIO)
        bare = LEGACY_FRAMED_P[2:-2]
        text, counters = self.detokenizer.detokenize_text(f"клиент {bare}", "mattermost")
        self.assertEqual(text, f"клиент {FIO}")
        self.assertEqual(counters["replaced"], 1)

    def test_numeric_identifier_is_restored_as_number(self) -> None:
        token = make_token("C", "35209", KEY)
        self.store.store(token, "C", "35209")
        payload = {"choices": [{"message": {"tool_calls": [{"function": {"arguments": json.dumps({"client_id": token})}}]}}]}
        restored, _ = self.detokenizer.detokenize_tool_args(payload, "s1")
        arguments = json.loads(restored["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"])
        self.assertEqual(arguments["client_id"], 35209)
        self.assertIsInstance(arguments["client_id"], int)

    def test_response_restores_args_and_channel_text(self) -> None:
        payload = {
            "choices": [
                {
                    "message": {
                        "content": f"Клиент {self.token}",
                        "tool_calls": [
                            {"function": {"name": "f", "arguments": json.dumps({"fio": self.token})}}
                        ],
                    }
                }
            ]
        }
        restored, counters = self.detokenizer.detokenize_response(payload, "mattermost", "s1")
        message = restored["choices"][0]["message"]
        self.assertEqual(message["content"], f"Клиент {FIO}")
        self.assertEqual(json.loads(message["tool_calls"][0]["function"]["arguments"])["fio"], FIO)
        self.assertEqual(counters["tool_args_replaced"], 1)

    def test_response_keeps_text_for_telegram(self) -> None:
        payload = {"choices": [{"message": {"content": f"Клиент {self.token}"}}]}
        restored, _ = self.detokenizer.detokenize_response(payload, "telegram", "s1")
        self.assertIn(self.token, restored["choices"][0]["message"]["content"])

    def test_store_failure_raises(self) -> None:
        class BrokenStore:
            # С Phase-7 восстановление спрашивает список наблюдённых форм первым:
            # дублёр обязан падать так же, как настоящий справочник.
            def load_value(self, token: str):
                raise MapStoreError("MAP_STORE_UNAVAILABLE", "gone")

            def load_forms(self, token: str):
                raise MapStoreError("MAP_STORE_UNAVAILABLE", "gone")

            def load_identity(self, token: str):
                raise MapStoreError("MAP_STORE_UNAVAILABLE", "gone")

        detokenizer = PayloadDetokenizer(BrokenStore(), self.policy, None)
        with self.assertRaises(Exception) as ctx:
            detokenizer.detokenize_text(
                self.token, "mattermost", "s1", collect_identifiers(self.token)
            )
        self.assertEqual(getattr(ctx.exception, "code", ""), "DETOK_STORE_FAILED")

    def test_stream_never_emits_half_token(self) -> None:
        full = f"клиент {self.token} купил карту"
        stream = StreamDetokenizer(
            self.real, "mattermost", "s1", collect_identifiers(full), boundary=confirmed_position
        )
        pieces = [stream.feed(full[index : index + 5]) for index in range(0, len(full), 5)]
        pieces.append(stream.flush())
        emitted = "".join(pieces)
        self.assertEqual(emitted, f"клиент {FIO} купил карту")
        self.assertNotIn("[[", emitted)

    def test_stream_for_telegram_passes_through(self) -> None:
        text = f"клиент {self.token}"
        stream = StreamDetokenizer(
            self.real, "telegram", "s1", collect_identifiers(text), boundary=confirmed_position
        )
        emitted = stream.feed(text) + stream.flush()
        self.assertEqual(emitted, text)

    def test_stream_flush_returns_pending(self) -> None:
        """Удержание ровно по подтверждённой позиции: хвост, из которого может выйти код."""
        stream = StreamDetokenizer(
            self.real, "mattermost", "s1", frozenset(), boundary=confirmed_position
        )
        self.assertEqual(stream.feed("клиент zP"), "клиент ")
        self.assertEqual(stream.flush(), "zP")


class ObservedFormRestoreTests(unittest.TestCase):
    """Восстановление берёт наблюдённую форму, согласуя её по порядку вхождений."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = TokenMapStore(os.path.join(self._tmp.name, "obs.db"), KEY)
        self.policy = ChannelPolicy(("mattermost",))
        self.detokenizer = PayloadDetokenizer(self.store, self.policy, None)
        self.token = make_token("P", "иванов", KEY)

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def restore(self, text: str):
        return self.detokenizer.detokenize_text(
            text, "mattermost", "obs", collect_identifiers(text + self.token)
        )

    def test_forms_follow_the_order_of_occurrence(self) -> None:
        self.store.store(self.token, "P", "Ивановой", "иванов")
        self.store.append_form(self.token, "Иванов")
        restored, counters = self.restore(f"письмо {self.token}, затем {self.token}")
        self.assertEqual(restored, "письмо Ивановой, затем Иванов")
        self.assertEqual(counters["replaced"], 2)

    def test_extra_occurrence_falls_back_to_nominative(self) -> None:
        """Формы нет (код повторился в авторском тексте модели) — отдаём именительный."""
        self.store.store(self.token, "P", "Иванов", "иванов")
        restored, _counters = self.restore(f"{self.token} и {self.token}")
        self.assertEqual(restored, "Иванов и Иванов")

    def test_legacy_row_without_identity_keeps_old_behaviour(self) -> None:
        self.store.store(self.token, "P", "Ивановой")
        restored, _counters = self.restore(f"{self.token} и {self.token}")
        self.assertEqual(restored, "Ивановой и Ивановой")

    def test_nominative_uses_the_base_value_when_never_observed(self) -> None:
        self.store.store(self.token, "P", "Ивановой", "иванов")
        restored, _counters = self.restore(f"{self.token} и {self.token}")
        # Первое вхождение — наблюдённая форма, дальше основа значения из справочника.
        self.assertEqual(restored, "Ивановой и иванов")

    def test_stream_and_buffered_paths_agree(self) -> None:
        self.store.store(self.token, "P", "Ивановой", "иванов")
        self.store.append_form(self.token, "Иванов")
        text = f"первый {self.token}, второй {self.token} и третий {self.token}"
        allowed = collect_identifiers(self.token)
        buffered, _counters = self.detokenizer.detokenize_text(text, "mattermost", "obs", allowed)
        stream = StreamDetokenizer(
            self.detokenizer, "mattermost", "obs", allowed, boundary=confirmed_position
        )
        parts = [stream.feed(chunk) for chunk in (text[:6], text[6:20], text[20:])]
        parts.append(stream.flush())
        self.assertEqual("".join(parts), buffered)

    def test_exact_token_argument_is_restored_as_the_base(self) -> None:
        """Аргумент инструмента — не текст: падеж здесь неуместен, отдаём основу."""
        self.store.store(self.token, "P", "Ивановой", "иванов")
        self.store.append_form(self.token, "Иванов")
        payload = {"choices": [{"message": {"tool_calls": [{"function": {"arguments": json.dumps({"surname": self.token})}}]}}]}
        restored, _counters = self.detokenizer.detokenize_tool_args(
            payload, "obs", collect_identifiers(self.token)
        )
        arguments = restored["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
        self.assertIn("Иванов", arguments)
        self.assertNotIn("Ивановой", arguments)

if __name__ == "__main__":
    unittest.main()
