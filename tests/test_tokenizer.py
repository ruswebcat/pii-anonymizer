# FILE: tests/test_tokenizer.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-TOKENIZER contract: the whole payload is anonymized, embedded JSON stays valid, tokens are consistent and store failures block processing.
#   SCOPE: system and history coverage, tool results, tool-call arguments, determinism across fields, statistics, store failure handling, cache usage.
#   DEPENDS: M-TOKENIZER, M-TEST-HARNESS
#   LINKS: V-M-TOKENIZER, M-TOKENIZER, VF-001
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   TokenizerTests - unittest case set for PayloadTokenizer
#   build_payload - helper building an OpenAI-compatible payload with PII
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-1 M-TOKENIZER verification, including the VF-001 no-PII-reaches-model scenario.
# END_CHANGE_SUMMARY

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.audit import AuditJournal  # noqa: E402
from src.detect_name import NameDetector  # noqa: E402
from src.map_store import MapStoreError, TokenMapStore  # noqa: E402
from src.token_factory import (  # noqa: E402
    CODE_LENGTH,
    candidate_tokens,
    find_tokens,
    is_valid_token,
    parse_token,
)
from src.tokenizer import PayloadTokenizer, TokenizeError  # noqa: E402
from tests import harness  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()

KEY = b"tokenizer-test-key-32-bytes-long!!"
FIO = "Иванов Иван Иванович"
PHONE = "79000000001"


# START_BLOCK_BUILD_FIXTURES
def build_payload() -> dict:
    """Build a payload carrying PII in system, history, tool result and tool arguments."""
    return {
        "model": "deepseek-flash",
        "stream": False,
        "messages": [
            {"role": "system", "content": f"Ты помощник. Клиент {FIO}, телефон {PHONE}."},
            {"role": "user", "content": "Собери обзвон по БЧК за сентябрь"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "crm_get_client",
                            "arguments": json.dumps({"client_id": 35209, "phone": PHONE}),
                        },
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "call_1",
                "content": json.dumps(
                    {"client_id": 35209, "fio": FIO, "phone": PHONE, "club": "Центральный"},
                    ensure_ascii=False,
                ),
            },
        ],
    }
# END_BLOCK_BUILD_FIXTURES


class TokenizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = harness.temp_map_store(self._tmp.name)
        self.audit = AuditJournal(os.path.join(self._tmp.name, "audit.jsonl"))
        self.tokenizer = PayloadTokenizer(KEY, self.store, NameDetector(), audit=self.audit)

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def test_no_pii_value_survives_in_payload(self) -> None:
        anonymized, stats = self.tokenizer.tokenize_payload(build_payload(), "s1")
        serialized = json.dumps(anonymized, ensure_ascii=False)
        self.assertNotIn(FIO, serialized)
        self.assertNotIn(PHONE, serialized)
        self.assertNotIn("35209", serialized)
        self.assertTrue(stats)
        self.assertIn("P", stats)
        self.assertIn("T", stats)

    def test_system_message_is_tokenized(self) -> None:
        anonymized, _ = self.tokenizer.tokenize_payload(build_payload(), "s1")
        system = anonymized["messages"][0]["content"]
        self.assertNotIn(FIO, system)
        self.assertTrue(find_tokens(system))

    def test_tool_arguments_stay_valid_json(self) -> None:
        anonymized, _ = self.tokenizer.tokenize_payload(build_payload(), "s1")
        arguments = anonymized["messages"][2]["tool_calls"][0]["function"]["arguments"]
        parsed = json.loads(arguments)
        self.assertIn("zC", parsed["client_id"])
        self.assertIn("zT", parsed["phone"])

    def test_same_value_gets_same_token_across_fields(self) -> None:
        anonymized, _ = self.tokenizer.tokenize_payload(build_payload(), "s1")
        system_tokens = {full for _, _, _, full in find_tokens(anonymized["messages"][0]["content"])}
        tool_tokens = {
            full
            for _, _, _, full in find_tokens(anonymized["messages"][3]["content"])
        }
        self.assertTrue(system_tokens & tool_tokens)

    def test_bindings_allow_round_trip(self) -> None:
        anonymized, _ = self.tokenizer.tokenize_payload(build_payload(), "s1")
        content = anonymized["messages"][3]["content"]
        spans = find_tokens(content)
        self.assertTrue(spans)
        restored = []
        for _, _, _, token in spans:
            value = self.store.load_value(token)
            self.assertIsNotNone(value)
            restored.append(value)
        self.assertIn(PHONE, restored)

    def test_plain_report_text_is_untouched(self) -> None:
        payload = {"model": "m", "messages": [{"role": "user", "content": "Продажи сентября: 214 карт"}]}
        anonymized, stats = self.tokenizer.tokenize_payload(payload, "s1")
        self.assertEqual(anonymized["messages"][0]["content"], payload["messages"][0]["content"])
        self.assertEqual(stats, {})

    def test_statistics_count_classes(self) -> None:
        _, stats = self.tokenizer.tokenize_payload(build_payload(), "s1")
        self.assertGreaterEqual(stats.get("T", 0), 1)
        self.assertGreaterEqual(stats.get("P", 0), 1)
        self.assertGreaterEqual(stats.get("C", 0), 1)

    def test_audit_receives_tokenization_events(self) -> None:
        self.tokenizer.tokenize_payload(build_payload(), "s1")
        records = self.audit.export_for_regulator()
        self.assertTrue(records)
        self.assertTrue(all(record["action"] == "tokenized" for record in records))
        self.assertFalse(self.audit.contains_any([FIO, PHONE]))

    def test_store_failure_blocks_processing(self) -> None:
        class BrokenStore:
            # Интерфейс присвоения кода с Phase-7: идентичность и наблюдённые формы.
            def store(self, token, cls, value, identity=""):  # noqa: D401 - double
                raise MapStoreError("MAP_STORE_UNAVAILABLE", "disk gone")

            def load_value(self, token):  # noqa: D401 - double
                return None

            def load_identity(self, token):  # noqa: D401 - double
                return None

            def append_form(self, token, form, limit=8):  # noqa: D401 - double
                return False

        tokenizer = PayloadTokenizer(KEY, BrokenStore(), NameDetector())
        with self.assertRaises(TokenizeError) as ctx:
            tokenizer.tokenize_payload(build_payload(), "s1")
        self.assertEqual(ctx.exception.code, "TOKENIZE_STORE_FAILED")

    def test_cache_is_used_for_repeated_blocks(self) -> None:
        class CountingCache:
            def __init__(self) -> None:
                self.hits = 0
                self.data: dict = {}

            def get(self, key: str, verify=None):
                value = self.data.get(key)
                if value is not None:
                    self.hits += 1
                return value

            def put(self, key: str, value: str, tag: str = "") -> None:
                self.data[key] = value

        cache = CountingCache()
        tokenizer = PayloadTokenizer(KEY, self.store, NameDetector(), cache=cache)
        tokenizer.tokenize_payload(build_payload(), "s1")
        _, stats = tokenizer.tokenize_payload(build_payload(), "s1")
        self.assertGreater(cache.hits, 0)
        self.assertGreater(stats.get("cache_hits", 0), 0)

    # START_BLOCK_COLLISION_RESOLUTION
    def test_collision_is_resolved_without_touching_the_other_binding(self) -> None:
        """Механизм 1: два разных значения никогда не получают один код.

        Коллизия провоцируется искусственно: первый кандидат значения занят
        другим значением, как это случилось бы при совпадении 40-битных кодов.
        """
        value = "Иванов Иван Иванович"
        candidates = list(candidate_tokens("P", "иванов иван иванович", KEY))
        self.store.store(candidates[0], "P", "другое значение")

        payload = {"messages": [{"role": "user", "content": f"Клиент {value}."}]}
        anonymized, stats = self.tokenizer.tokenize_payload(payload, "s1")

        text = json.dumps(anonymized, ensure_ascii=False)
        self.assertIn(candidates[1], text)
        self.assertNotIn(candidates[0] + '"', text)
        self.assertGreaterEqual(stats.get("collisions_resolved", 0), 1)
        self.assertEqual(self.store.load_value(candidates[0]), "другое значение")
        self.assertEqual(self.store.load_value(candidates[1]), value)
    # END_BLOCK_COLLISION_RESOLUTION

    def test_tokens_are_well_formed(self) -> None:
        anonymized, _ = self.tokenizer.tokenize_payload(build_payload(), "s1")
        for _, _, cls, token in find_tokens(json.dumps(anonymized, ensure_ascii=False)):
            parsed_cls, code = parse_token(token)
            self.assertEqual(parsed_cls, cls)
            self.assertEqual(len(code), CODE_LENGTH)
            self.assertTrue(is_valid_token(token), token)

    # START_BLOCK_CACHE_PREFIX_STABILITY
    def test_history_prefix_is_stable_when_conversation_grows(self) -> None:
        """The cached prefix of the provider must not change between turns."""
        payload = build_payload()
        first, _ = self.tokenizer.tokenize_payload(payload, "s1")
        grown = json.loads(json.dumps(payload, ensure_ascii=False))
        grown["messages"].append({"role": "user", "content": f"Ещё вопрос, телефон {PHONE}"})
        second, _ = self.tokenizer.tokenize_payload(grown, "s2")
        first_prefix = json.dumps(first["messages"], ensure_ascii=False)
        second_prefix = json.dumps(
            second["messages"][: len(first["messages"])], ensure_ascii=False
        )
        self.assertEqual(first_prefix, second_prefix)

    def test_retokenizing_restored_text_reproduces_the_same_tokens(self) -> None:
        """Detokenize then tokenize again must be a fixed point (prompt cache safety)."""
        from src.channel_policy import ChannelPolicy
        from src.detokenizer import PayloadDetokenizer

        detokenizer = PayloadDetokenizer(
            self.store, ChannelPolicy({"mattermost"}), self.audit
        )
        tokenized, _ = self.tokenizer.tokenize_payload(build_payload(), "s1")
        for message in tokenized["messages"]:
            content = message.get("content")
            if not isinstance(content, str) or not find_tokens(content):
                continue
            restored, _ = detokenizer.detokenize_text(content, "mattermost", "s1")
            again = self.tokenizer.tokenize_text(restored, "s2")
            self.assertEqual(again, content, msg=content[:60])

    def test_tool_definitions_are_never_renamed(self) -> None:
        """A tool name under function.name must survive untouched."""
        payload = {
            "model": "m",
            "messages": [{"role": "user", "content": f"Клиент {FIO}"}],
            "tools": [
                {
                    "type": "function",
                    "function": {"name": "crm_get_client", "description": "Читает клиента"},
                }
            ],
            "tool_calls": [{"function": {"name": "crm_get_client", "arguments": "{}"}}],
        }
        anonymized, _ = self.tokenizer.tokenize_payload(payload, "s1")
        self.assertEqual(anonymized["tools"][0]["function"]["name"], "crm_get_client")
        self.assertEqual(
            anonymized["tool_calls"][0]["function"]["name"], "crm_get_client"
        )
        self.assertIn("zP", json.dumps(anonymized, ensure_ascii=False))

    def test_latin_person_names_under_name_keys_are_tokenized(self) -> None:
        """CRM holds Latin-script names; detectors know only Cyrillic shapes."""
        payload = {
            "model": "m",
            "messages": [
                {
                    "role": "tool",
                    "content": json.dumps(
                        {"name": "Testa", "surname": "Stubson", "club": "Центральный"}
                    ),
                }
            ],
        }
        anonymized, stats = self.tokenizer.tokenize_payload(payload, "s1")
        text = json.dumps(anonymized, ensure_ascii=False)
        self.assertNotIn("Testa", text)
        self.assertNotIn("Stubson", text)
        self.assertGreaterEqual(stats.get("P", 0), 2)

    def test_technical_values_under_name_keys_are_left_alone(self) -> None:
        payload = {
            "model": "m",
            "messages": [
                {
                    "role": "tool",
                    "content": json.dumps({"name": "assistant", "value": "ok", "data": "items"}),
                }
            ],
        }
        anonymized, _ = self.tokenizer.tokenize_payload(payload, "s1")
        text = json.dumps(anonymized, ensure_ascii=False)
        self.assertIn("assistant", text)
        self.assertNotIn("zP", text)

    def test_untidy_latin_name_with_trailing_junk_is_tokenized(self) -> None:
        """Real data is messy: the last survivor of the re-id run looked like this."""
        payload = {
            "model": "m",
            "messages": [
                {"role": "tool", "content": json.dumps({"name": "Terekhina???????"})}
            ],
        }
        anonymized, _ = self.tokenizer.tokenize_payload(payload, "s1")
        self.assertNotIn("Terekhina", json.dumps(anonymized, ensure_ascii=False))

    def test_contact_objects_use_their_own_contact_type(self) -> None:
        """{"contact_type": "phone", "contact": "..."} must be tokenized by kind."""
        payload = {
            "model": "m",
            "messages": [
                {
                    "role": "tool",
                    "content": json.dumps(
                        {
                            "contacts": [
                                {"contact_type": "phone", "contact": "7900000000000001"},
                                {"contact_type": "email", "contact": "someone@example.ru"},
                                {"contact_type": "other", "contact": "ВИДНО"},
                            ]
                        }
                    ),
                }
            ],
        }
        anonymized, stats = self.tokenizer.tokenize_payload(payload, "s1")
        text = json.dumps(anonymized, ensure_ascii=False)
        self.assertNotIn("7900000000000001", text)
        self.assertNotIn("someone@example.ru", text)
        self.assertIn("ВИДНО", text)
        self.assertGreaterEqual(stats.get("T", 0), 1)
        self.assertGreaterEqual(stats.get("E", 0), 1)

    def test_short_codes_under_name_keys_are_left_alone(self) -> None:
        payload = {
            "model": "m",
            "messages": [
                {"role": "tool", "content": json.dumps({"name": "MSK", "surname": "V2"})}
            ],
        }
        anonymized, _ = self.tokenizer.tokenize_payload(payload, "s1")
        text = json.dumps(anonymized, ensure_ascii=False)
        self.assertIn("MSK", text)
        self.assertIn("V2", text)

    def test_repeated_identical_turn_keeps_token_bytes_identical(self) -> None:
        """Two consecutive identical requests must serialize to identical bytes."""
        payload = build_payload()
        first, _ = self.tokenizer.tokenize_payload(payload, "s1")
        second, _ = self.tokenizer.tokenize_payload(payload, "s2")
        self.assertEqual(
            json.dumps(first, ensure_ascii=False), json.dumps(second, ensure_ascii=False)
        )
    # END_BLOCK_CACHE_PREFIX_STABILITY


class PersonCodeTests(unittest.TestCase):
    """Код присваивается персоне: все падежные формы одного клиента — один код."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.real_store = TokenMapStore(os.path.join(self._tmp.name, "person.db"), KEY)
        self.tokenizer = PayloadTokenizer(
            KEY, self.real_store, NameDetector({"P": ["Иванов", "Терёхина"]})
        )

    def tearDown(self) -> None:
        self.real_store.close()
        self._tmp.cleanup()

    def codes_of(self, text: str) -> set[str]:
        anonymized = self.tokenizer.tokenize_text(text, "person")
        return {span[3] for span in find_tokens(anonymized)}

    def test_all_case_forms_share_one_code(self) -> None:
        codes = set()
        for form in ("Иванов", "Иванова", "Иванову", "Ивановым", "Иванове"):
            codes.update(self.codes_of(f"Анкета: {form}"))
        self.assertEqual(len(codes), 1, msg=f"форм больше одного кода: {codes}")

    def test_second_form_does_not_walk_to_another_candidate(self) -> None:
        """Повтор с другой падежной формой не должен уводить персону на второй код."""
        first = self.codes_of("Анкета: Иванова")
        second = self.codes_of("Анкета: Иванов")
        self.assertEqual(first, second)

    def test_two_clients_keep_two_codes(self) -> None:
        self.assertNotEqual(self.codes_of("Анкета: Иванов"), self.codes_of("Анкета: Терёхина"))

    def test_observed_forms_are_kept_in_order(self) -> None:
        token = next(iter(self.codes_of("Анкета: Иванова")))
        self.tokenizer.tokenize_text("Анкета: Иванов", "person")
        self.assertEqual(self.real_store.load_identity(token), "иванов")
        self.assertEqual(self.real_store.load_forms(token), ["Иванова", "Иванов"])

if __name__ == "__main__":
    unittest.main()
