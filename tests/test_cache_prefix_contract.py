# FILE: tests/test_cache_prefix_contract.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Guard the acceptance-critical property that the proxy does not break the provider prompt cache: the request prefix must stay byte-identical across turns, a cache hit must return exactly what a cache miss returns, and enabling keyed digests must not change the anonymized output.
#   SCOPE: full pipeline through ProxyService with dictionary, NER, validator and cache wired as in production.
#   DEPENDS: M-ROUTER, M-TOKENIZER, M-DETOKENIZER, M-CACHE, M-DICT
#   LINKS: V-M-CACHE, V-M-TOKENIZER, V-M-ROUTER, acceptance
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   CachePrefixContractTests - prefix identity, cache transparency, digest transparency
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-3: the owner named prompt-cache preservation a key acceptance factor on 15.09.2026.
# END_CHANGE_SUMMARY

"""Prompt-cache acceptance checks.

DeepSeek charges less for the part of a request that matches the previous one, so
"the cache still works" is a measurable property, not a feeling. Three invariants
are checked here through the *full* pipeline (dictionary + cache), not at
tokenizer level alone:

1. **prefix identity** — every message already present in the previous request
   serializes to the same bytes on the next turn, so the provider's cached prefix
   still matches;
2. **cache transparency** — a cache hit returns byte-identical text to a miss,
   otherwise the second turn would silently differ from the first;
3. **digest transparency** — moving the dictionary to keyed digests must not
   change a single byte of the anonymized output.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detect_name import NameDetector  # noqa: E402
from src.detect_ner import NerDetector  # noqa: E402
from src.dictionary import SCHEMA_DIGEST, PiiDictionary, value_digest  # noqa: E402
from src.token_factory import find_tokens  # noqa: E402
from src.normalize import normalize  # noqa: E402
from src.router import build_service  # noqa: E402
from tests.harness import FakeUpstream, temp_config  # noqa: E402

CLIENT_NAME = "Иванов Иван Иванович"
CLIENT_PHONE = "79000000001"
CLIENT_ID = 35209


def conversation_payload(turns: int = 3) -> dict:
    """Build an OpenAI-shaped request with a realistic client-heavy history."""
    messages = [
        {"role": "system", "content": "Ты помощник сети фитнес-клубов."},
        {"role": "user", "content": f"Проверь клиента {CLIENT_NAME}, телефон {CLIENT_PHONE}"},
        {
            "role": "tool",
            "content": json.dumps(
                {"client_id": CLIENT_ID, "fio": CLIENT_NAME, "phone": CLIENT_PHONE},
                ensure_ascii=False,
            ),
        },
        {"role": "assistant", "content": "Карта активна, продление в ноябре."},
    ]
    return {"model": "deepseek-flash", "stream": False, "messages": messages[:turns]}


# START_BLOCK_CACHE_CONTRACT
class CachePrefixContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.config = temp_config(self._tmp.name)
        # Two independent files, so no test depends on the order of another one.
        self.raw_path = os.path.join(self._tmp.name, "dict_raw.json")
        self.keyed_path = os.path.join(self._tmp.name, "dict_keyed.json")
        with open(self.raw_path, "w", encoding="utf-8") as handle:
            json.dump(
                {"P": [CLIENT_NAME], "T": [CLIENT_PHONE], "C": [str(CLIENT_ID)]},
                handle,
                ensure_ascii=False,
            )
        key = self.config.token_key
        with open(self.keyed_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "schema": SCHEMA_DIGEST,
                    "values": 3,
                    "digests": {
                        "C": [value_digest(key, "C", normalize("C", str(CLIENT_ID)))],
                        "P": [value_digest(key, "P", normalize("P", CLIENT_NAME))],
                        "T": [value_digest(key, "T", normalize("T", CLIENT_PHONE))],
                    },
                },
                handle,
                ensure_ascii=False,
            )

    def _service(self, dictionary_path: str, keyed: bool = False) -> object:
        dictionary = (
            PiiDictionary(dictionary_path, key=self.config.dictionary_key)
            if keyed
            else PiiDictionary(dictionary_path)
        )
        upstream = FakeUpstream()
        self._upstream = upstream
        service = build_service(
            temp_config(self._tmp.name),
            upstream=upstream,
            validator=None,
            ner=NerDetector("none"),
            dictionary=dictionary,
        )
        self.addCleanup(service.close)
        return service

    def _anonymize(self, service, payload: dict) -> dict:
        """Return what the provider would receive, i.e. the anonymized body."""
        status, body = service.handle_chat_completions(
            payload, "ds", "/v1/chat/completions", "mattermost"
        )
        self.assertEqual(status, 200, msg=json.dumps(body, ensure_ascii=False)[:200])
        return self._upstream.last_payload

    def test_prefix_stays_identical_when_the_conversation_grows(self) -> None:
        service = self._service(self.raw_path)
        previous: list[str] = []
        for turns in (2, 3, 4):
            anonymized = self._anonymize(service, conversation_payload(turns))
            current = [
                json.dumps(message, ensure_ascii=False) for message in anonymized["messages"]
            ]
            for index, before in enumerate(previous):
                self.assertEqual(
                    before, current[index], msg=f"сообщение {index} изменилось между ходами"
                )
            previous = current

    def test_cache_hit_returns_the_same_bytes_as_a_miss(self) -> None:
        service = self._service(self.raw_path)
        payload = {
            "model": "deepseek-flash",
            "stream": False,
            "messages": [{"role": "user", "content": f"Клиент {CLIENT_NAME}"}],
        }
        first = self._anonymize(service, payload)
        second = self._anonymize(service, payload)
        self.assertEqual(
            json.dumps(first, ensure_ascii=False), json.dumps(second, ensure_ascii=False)
        )
        self.assertGreater(service.health()["cache"]["hits"], 0)

    def test_keyed_dictionary_produces_identical_output(self) -> None:
        payload = conversation_payload(4)
        raw_output = self._anonymize(self._service(self.raw_path), payload)
        keyed_output = self._anonymize(self._service(self.keyed_path, keyed=True), payload)
        self.assertEqual(
            json.dumps(raw_output, ensure_ascii=False, sort_keys=True),
            json.dumps(keyed_output, ensure_ascii=False, sort_keys=True),
        )
        serialized = json.dumps(keyed_output, ensure_ascii=False)
        self.assertNotIn(CLIENT_NAME, serialized)
        self.assertNotIn(CLIENT_PHONE, serialized)

    def test_keyed_dictionary_is_actually_used(self) -> None:
        """Guard the reverse failure: a dictionary that never fires proves nothing."""
        detector = NameDetector(PiiDictionary(self.keyed_path, key=self.config.dictionary_key))
        matches = detector.detect_names("Позвонить Иванову Сергею Геннадийовичу")
        self.assertTrue(matches, msg="словарь-отпечаток не сработал: проверка потеряла смысл")

    def test_dictionary_digest_is_not_a_token_and_cannot_be_resolved(self) -> None:
        """Holding the dictionary key must not let anyone link a token to a client.

        This is the reason the dictionary has its own key: if the digests were keyed
        with the token key, anyone with the dictionary file could compute the token
        of a known client and find that exact token inside a request.
        """
        service = self._service(self.keyed_path, keyed=True)
        anonymized = self._anonymize(service, conversation_payload(4))
        tokens = [
            token
            for _, _, cls, token in find_tokens(json.dumps(anonymized, ensure_ascii=False))
            if cls == "P"
        ]
        self.assertTrue(tokens)
        digest = value_digest(
            self.config.dictionary_key, "P", normalize("P", CLIENT_NAME)
        )
        token_digest = value_digest(self.config.token_key, "P", normalize("P", CLIENT_NAME))
        for token in tokens:
            self.assertNotEqual(token, digest)
            self.assertNotIn(digest, token)
            self.assertNotEqual(token, token_digest)
            self.assertNotIn(digest[:8], token)

    def test_prefix_is_stable_with_the_keyed_dictionary(self) -> None:
        service = self._service(self.keyed_path, keyed=True)
        previous: list[str] = []
        for turns in (2, 3, 4):
            anonymized = self._anonymize(service, conversation_payload(turns))
            current = [
                json.dumps(message, ensure_ascii=False) for message in anonymized["messages"]
            ]
            for index, before in enumerate(previous):
                self.assertEqual(before, current[index], msg=f"сообщение {index}")
            previous = current

    def test_client_data_never_reaches_the_upstream_body(self) -> None:
        upstream = FakeUpstream()
        self._upstream = upstream
        service = build_service(
            temp_config(self._tmp.name),
            upstream=upstream,
            validator=None,
            ner=NerDetector("none"),
            dictionary=PiiDictionary(self.keyed_path, key=self.config.token_key),
        )
        self.addCleanup(service.close)
        self._anonymize(service, conversation_payload(4))
        sent = json.dumps(upstream.calls, ensure_ascii=False)
        self.assertNotIn(CLIENT_NAME, sent)
        self.assertNotIn(CLIENT_PHONE, sent)
# END_BLOCK_CACHE_CONTRACT


if __name__ == "__main__":
    unittest.main()
