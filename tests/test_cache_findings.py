# FILE: tests/test_cache_findings.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Guard the 26.09.2026 decision to cache blocks WITH findings: the key must carry the dictionary signature and the schema version, a hit must be byte-identical to a miss, every code in a cached block must still resolve to the same value, and the session question must stay answered (codes are not session-bound, so the session is deliberately not in the key).
#   SCOPE: cache-level signature and tag behaviour plus the full pipeline through ProxyService with a real store, a real dictionary and the block cache wired as in production.
#   DEPENDS: M-CACHE, M-TOKENIZER, M-MAP-STORE, M-ROUTER, M-DICT
#   LINKS: V-M-CACHE, V-M-TOKENIZER, V-M-ROUTER, acceptance
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   SignatureKeyTests - signature, schema version and staleness at cache level
#   FindingsBlocksAreCached - блок с находками: попадание равно промаху, устаревший код не отдаётся
#   SessionBindingTests - коды не привязаны к сессии: доказательство и следствие для ключа
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - решение владельца 26.09.2026: кэшировать и блоки с находками, но под подписью справочника и с проверкой разрешимости кодов.
# END_CHANGE_SUMMARY

"""Checks for caching blocks that carry findings.

Until 26.09.2026 the cache only stored blocks where nothing was found, and a live
dialog gained almost nothing from it: almost every message carries a code. The
refusal was lifted together with the reason for it — the anonymized result
depends on the state of the dictionary and on the correspondence table, so both
are now part of the contract:

1. the dictionary signature and the key scheme version are part of the key, so a
   changed dictionary invalidates **every** entry at once;
2. an entry is only served while every code inside it still resolves to the same
   value, otherwise it is a miss, the entry is dropped and the block is
   anonymized again;
3. codes are not bound to a session (the store keeps one row per code, and
   ``session_id`` is a per-request audit correlation id), so the session is
   deliberately **not** part of the key.
"""

import hashlib
import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.cache import CACHE_KEY_SCHEMA, TokenizationCache  # noqa: E402
from src.detect_ner import NerDetector  # noqa: E402
from src.dictionary import PiiDictionary  # noqa: E402
from src.router import build_service  # noqa: E402
from src.token_factory import find_tokens  # noqa: E402
from tests.harness import FakeUpstream, temp_config  # noqa: E402

CLIENT_NAME = "Иванов Иван Иванович"
CLIENT_PHONE = "79000000001"
CLEAN_BLOCK = "Отчёт по клубу готов, продлений больше, ячейки по пять соблюдены."
NAME_BLOCK = f"Проверь клиента {CLIENT_NAME}, телефон +7 912 345-67-89, клуб Квартальный."


# START_BLOCK_SIGNATURE_KEY
class SignatureKeyTests(unittest.TestCase):
    """Подпись справочника и версия схемы — часть ключа, а не пожелание."""

    def test_the_key_carries_the_signature_and_the_schema_version(self) -> None:
        text, signature = "блок", "путь/справочник|0123456789abcdef"
        expected = hashlib.sha256(
            f"v{CACHE_KEY_SCHEMA}\x00{signature}\x00{text}".encode("utf-8")
        ).hexdigest()
        self.assertEqual(TokenizationCache.key_for(text, signature), expected)
        self.assertNotEqual(
            TokenizationCache.key_for(text, signature),
            TokenizationCache.key_for(text, signature + "x"),
        )
        # Схема входит в материал ключа: без неё смена состава ключа не гасила бы записи.
        self.assertIn(f"v{CACHE_KEY_SCHEMA}", f"v{CACHE_KEY_SCHEMA}\x00{signature}\x00{text}")

    def test_a_changed_dictionary_signature_turns_the_whole_cache_into_misses(self) -> None:
        stamp = {"live": (100.0, 5000)}
        cache = TokenizationCache(
            8, signature="путь|ключ", signature_source=lambda: stamp["live"]
        )
        cache.put("блок", "обезличенный текст", "tag")
        self.assertEqual(cache.get("блок"), "обезличенный текст")
        self.assertEqual(cache.stats()["signature_changes"], 0)

        # Справочник переписан (время правки и размер изменились) — старая запись недействительна.
        stamp["live"] = (200.0, 6000)
        self.assertIsNone(cache.get("блок"))
        stats = cache.stats()
        self.assertEqual(stats["signature_changes"], 1)
        self.assertEqual(stats["entries"], 0)
        self.assertEqual(stats["bytes"], 0)

    def test_a_stale_entry_is_dropped_and_counted(self) -> None:
        cache = TokenizationCache(8)
        cache.put("блок", "обезличенный текст", "tag")
        self.assertEqual(cache.get("блок", verify=lambda value, tag: tag == "tag"), "обезличенный текст")
        self.assertIsNone(cache.get("блок", verify=lambda value, tag: False))
        stats = cache.stats()
        self.assertEqual((stats["stale"], stats["entries"]), (1, 0))

    def test_a_block_without_changes_is_never_verified(self) -> None:
        """Блок без находок хранит сам себя: своих связей у записи нет, проверять нечего."""

        def forbidden(value: str, tag: str) -> bool:  # pragma: no cover - не должен вызываться
            raise AssertionError("проверка вызвана для блока без находок")

        cache = TokenizationCache(8)
        cache.put(CLEAN_BLOCK, CLEAN_BLOCK, "")
        self.assertEqual(cache.get(CLEAN_BLOCK, verify=forbidden), CLEAN_BLOCK)
        self.assertEqual(cache.stats()["hits"], 1)

    def test_an_untagged_rewritten_entry_is_not_served(self) -> None:
        """Запись без отпечатка связей недоказуема — её не отдают."""
        cache = TokenizationCache(8)
        cache.put("блок", "обезличенный", "")
        self.assertIsNone(cache.get("блок", verify=lambda value, tag: bool(tag)))
# END_BLOCK_SIGNATURE_KEY


# START_BLOCK_CACHE_FINDINGS
class FindingsBlocksAreCached(unittest.TestCase):
    """Блоки с находками: та же прозрачность, что и у блоков без находок."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dictionary_path = os.path.join(self._tmp.name, "dict_raw.json")
        with open(self.dictionary_path, "w", encoding="utf-8") as handle:
            json.dump({"P": [CLIENT_NAME], "T": [CLIENT_PHONE]}, handle, ensure_ascii=False)

    def _service(self, **overrides):
        upstream = FakeUpstream()
        self._upstream = upstream
        service = build_service(
            temp_config(self._tmp.name, **overrides),
            upstream=upstream,
            validator=None,
            ner=NerDetector("none"),
            dictionary=PiiDictionary(self.dictionary_path),
        )
        self.addCleanup(service.close)
        return service

    @staticmethod
    def _payload() -> dict:
        return {
            "model": "deepseek-flash",
            "stream": False,
            "messages": [
                {"role": "system", "content": CLEAN_BLOCK},
                {"role": "user", "content": NAME_BLOCK},
            ],
        }

    def _anonymize(self, service, payload: dict) -> dict:
        status, body = service.handle_chat_completions(
            payload, "ds", "/v1/chat/completions", "mattermost"
        )
        self.assertEqual(status, 200, msg=json.dumps(body, ensure_ascii=False)[:200])
        return self._upstream.last_payload

    @staticmethod
    def _stats(service) -> dict:
        return service.health()["cache"]

    def test_a_findings_block_really_has_findings(self) -> None:
        """Опорное условие самих проверок: блок с находками — не пустое место."""
        service = self._service()
        self.assertTrue(service._tokenizer.detect(NAME_BLOCK))
        self.assertFalse(service._tokenizer.detect(CLEAN_BLOCK))

    def test_a_hit_is_byte_identical_to_a_miss_on_a_block_with_findings(self) -> None:
        """Контракт прозрачности: попадание обязано отдать те же байты, что и промах."""
        cached = self._service()
        first = self._anonymize(cached, self._payload())
        after_first = self._stats(cached)
        second = self._anonymize(cached, self._payload())
        after_second = self._stats(cached)

        self.assertGreater(after_first["misses"], 0, msg="блок с находками не был обезличен")
        self.assertEqual(
            json.dumps(first, ensure_ascii=False, sort_keys=True),
            json.dumps(second, ensure_ascii=False, sort_keys=True),
        )
        # Второй запрос не потратил ни одного промаха: блок с находками обслужен из кэша.
        self.assertEqual(after_second["misses"], after_first["misses"])
        self.assertGreater(after_second["hits"], after_first["hits"])
        self.assertEqual(after_second["stale"], 0)
        self.assertNotIn(CLIENT_NAME, json.dumps(second, ensure_ascii=False))

        # И то же самое рядом с выключенным кэшем: каждый блок считается заново.
        uncached = self._service(PII_PROXY_BLOCK_CACHE="false")
        recomputed = self._anonymize(uncached, self._payload())
        self.assertEqual(
            json.dumps(recomputed, ensure_ascii=False, sort_keys=True),
            json.dumps(second, ensure_ascii=False, sort_keys=True),
        )
        self.assertEqual(self._stats(uncached)["hits"], 0)

    def test_the_prefix_between_requests_is_not_broken_by_the_findings_cache(self) -> None:
        """Рост диалога не меняет уже отправленные блоки — иначе поедет кэш провайдера."""
        service = self._service()
        history: list[dict] = []
        previous: list[str] = []
        for index in range(3):
            history.append(
                {"role": "user", "content": f"[ход {index}] Ещё вопрос по клубу Центральный."}
            )
            payload = self._payload()
            payload["messages"].extend(history)
            anonymized = self._anonymize(service, payload)
            current = [
                json.dumps(message, ensure_ascii=False) for message in anonymized["messages"]
            ]
            for position, before in enumerate(previous):
                self.assertEqual(before, current[position], msg=f"сообщение {position} изменилось")
            previous = current
        self.assertGreater(service.health()["cache"]["hits"], 0)

    def test_an_unresolvable_code_is_a_miss_and_the_block_is_stored_again(self) -> None:
        """Код перестал разрешаться (TTL/перенос справочника) — запись недействительна."""
        service = self._service()
        first = self._anonymize(service, self._payload())
        self._anonymize(service, self._payload())
        before = self._stats(service)
        self.assertGreater(before["hits"], 0)

        # Связка исчезла: так выглядит очистка справочника соответствия.
        removed = service._store.purge_expired(now=time.time() + 10**9)
        self.assertGreater(removed, 0)

        again = self._anonymize(service, self._payload())
        after = self._stats(service)
        self.assertGreaterEqual(after["stale"], 1, msg="устаревшая запись не была отброшена")
        self.assertGreater(after["misses"], before["misses"])
        # Блок обезличен заново и записан заново: код снова разрешается.
        self.assertEqual(
            json.dumps(first, ensure_ascii=False, sort_keys=True),
            json.dumps(again, ensure_ascii=False, sort_keys=True),
        )
        self.assertNotIn(CLIENT_NAME, json.dumps(again, ensure_ascii=False))
        for _, _, _cls, token in find_tokens(json.dumps(again, ensure_ascii=False)):
            self.assertIsNotNone(service._store.load_value(token), msg=f"код {token} не разрешается")

    def test_a_code_resolving_into_another_value_is_a_miss(self) -> None:
        """Худший случай: код в кэше разрешается, но уже в другое значение.

        Без проверки на попадании такой блок ушёл бы провайдеру с кодом чужого
        человека, а клиент увидел бы в ответе чужое значение.
        """
        service = self._service()
        first = self._anonymize(service, self._payload())
        tokens = [
            item[3]
            for item in find_tokens(json.dumps(first, ensure_ascii=False))
            if item[2] == "P"
        ]
        self.assertTrue(tokens, msg="в блоке нет ни одного кода персоны")
        token = tokens[0]

        service._store.purge_expired(now=time.time() + 10**9)
        service._store.store(token, "P", "Заглушков Сергей Петрович", "pd:другой-человек")
        before = self._stats(service)

        again = self._anonymize(service, self._payload())
        after = self._stats(service)
        self.assertGreaterEqual(after["stale"], 1, msg="запись с чужим кодом была отдана")
        self.assertGreater(after["misses"], before["misses"])

        new_tokens = [
            item[3]
            for item in find_tokens(json.dumps(again, ensure_ascii=False))
            if item[2] == "P"
        ]
        self.assertTrue(new_tokens)
        self.assertNotIn(token, new_tokens, msg="клиент получил код, занятый другим человеком")
        self.assertEqual(service._store.load_value(token), "Заглушков Сергей Петрович")
        self.assertNotIn(CLIENT_NAME, json.dumps(again, ensure_ascii=False))

    def test_blocks_without_findings_behave_as_before(self) -> None:
        """Прежнее поведение не изменилось: блок без находок кэшируется без отпечатка."""
        service = self._service()
        payload = {
            "model": "deepseek-flash",
            "stream": False,
            "messages": [{"role": "system", "content": CLEAN_BLOCK}],
        }
        first = self._anonymize(service, payload)
        after_first = self._stats(service)
        second = self._anonymize(service, payload)
        after_second = self._stats(service)
        self.assertEqual(
            json.dumps(first, ensure_ascii=False), json.dumps(second, ensure_ascii=False)
        )
        self.assertEqual(after_second["misses"], after_first["misses"])
        self.assertGreater(after_second["hits"], after_first["hits"])
        self.assertEqual(after_second["stale"], 0)

    def test_a_changed_dictionary_file_invalidates_the_cache_without_a_reload_call(self) -> None:
        """Смена справочника гасит кэш целиком, даже если перезагрузку никто не просил."""
        service = self._service()
        self._anonymize(service, self._payload())
        self._anonymize(service, self._payload())
        before = self._stats(service)
        self.assertGreater(before["hits"], 0)

        with open(self.dictionary_path, "w", encoding="utf-8") as handle:
            json.dump({"P": [CLIENT_NAME, "Заглушкин Пётр Ильич"], "T": [CLIENT_PHONE]}, handle, ensure_ascii=False)
        info = os.stat(self.dictionary_path)
        os.utime(self.dictionary_path, (info.st_atime, info.st_mtime + 5))

        self._anonymize(service, self._payload())
        after = self._stats(service)
        self.assertGreaterEqual(after["signature_changes"], 1)
        self.assertGreater(after["misses"], before["misses"])

    def test_healthz_shows_the_signature_and_the_stale_counter(self) -> None:
        service = self._service()
        cache = service.health()["cache"]
        for key in ("signature", "stale", "signature_changes", "hits", "misses", "bytes"):
            self.assertIn(key, cache)
        self.assertEqual(len(cache["signature"]), 12)
# END_BLOCK_CACHE_FINDINGS


# START_BLOCK_SESSION_BINDING
class SessionBindingTests(unittest.TestCase):
    """Сессионная привязка: доказательство, что её нет, и следствие для ключа кэша."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dictionary_path = os.path.join(self._tmp.name, "dict_raw.json")
        with open(self.dictionary_path, "w", encoding="utf-8") as handle:
            json.dump({"P": [CLIENT_NAME], "T": [CLIENT_PHONE]}, handle, ensure_ascii=False)

    def _service(self, **overrides):
        upstream = FakeUpstream()
        self._upstream = upstream
        service = build_service(
            temp_config(self._tmp.name, **overrides),
            upstream=upstream,
            validator=None,
            ner=NerDetector("none"),
            dictionary=PiiDictionary(self.dictionary_path),
        )
        self.addCleanup(service.close)
        return service

    def test_the_same_value_gets_the_same_code_in_any_session(self) -> None:
        """Код выводится из значения и справочника, а не из сессии.

        Иначе включение сессии в ключ кэша было бы обязательным; проверяем обратное:
        две разные сессии одной и той же персоне выдают один и тот же код.
        """
        service = self._service(PII_PROXY_BLOCK_CACHE="false")
        tokenizer = service._tokenizer
        first, _ = tokenizer.tokenize_payload(
            {"messages": [{"role": "user", "content": NAME_BLOCK}]}, "сессия-1"
        )
        second, _ = tokenizer.tokenize_payload(
            {"messages": [{"role": "user", "content": NAME_BLOCK}]}, "сессия-2"
        )
        self.assertEqual(
            json.dumps(first, ensure_ascii=False), json.dumps(second, ensure_ascii=False)
        )
        tokens = {item[3] for item in find_tokens(json.dumps(first, ensure_ascii=False)) if item[2] == "P"}
        self.assertEqual(len(tokens), 1, msg="одной персоне выдали разные коды")

    def test_the_session_id_is_a_per_request_correlation_id(self) -> None:
        """Сессия в этой службе — идентификатор одного запроса, а не разговора.

        Ровно поэтому её нет в ключе кэша: иначе каждая запись досталась бы только
        тому запросу, который её сделал, и кэш не попадал бы никогда.
        """
        service = self._service()
        self.assertNotEqual(service.new_session_id(), service.new_session_id())
        service.handle_chat_completions(
            {"messages": [{"role": "user", "content": NAME_BLOCK}]},
            "ds",
            "/v1/chat/completions",
            "mattermost",
        )
        first_sessions = {
            record.get("session_id") for record in service._audit.export_for_regulator()
        }
        # Второй запрос несёт новый блок (промах), значит у него своя сессия — и в его
        # записях видно, что разговора между запросами не существует.
        service.handle_chat_completions(
            {"messages": [{"role": "user", "content": NAME_BLOCK + " Уточняет адрес."}]},
            "ds",
            "/v1/chat/completions",
            "mattermost",
        )
        second_sessions = {
            record.get("session_id") for record in service._audit.export_for_regulator()
        }
        self.assertTrue(first_sessions)
        self.assertLess(first_sessions, second_sessions, msg="сессия не сменилась между запросами")
# END_BLOCK_SESSION_BINDING


if __name__ == "__main__":
    unittest.main()
