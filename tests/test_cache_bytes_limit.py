# FILE: tests/test_cache_bytes_limit.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the second cache bound: the byte budget next to the entry count. The entry count alone says nothing about memory (a hundred blocks can be ten kilobytes or ten megabytes), so the bound that keeps a re-sent history is measured in bytes.
#   SCOPE: M-CACHE byte budget and eviction counters, config wiring in build_service, exposure through healthz, and byte identity of the anonymized output with the budget active versus the cache switched off.
#   DEPENDS: M-CACHE, M-CONFIG, M-ROUTER, M-TOKENIZER, M-DICT
#   LINKS: M-CACHE, V-M-CACHE, V-M-ROUTER, acceptance
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   BytesBudgetCacheTests - byte budget, both bounds at once, counters, disabled mode
#   BytesBudgetServiceTests - config wiring and healthz visibility, output identity
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - M-CACHE v1.1.0: the byte budget arrived because a live dialog (hundreds of messages, hundreds of kilobytes) was evicted by a cap counted in blocks.
# END_CHANGE_SUMMARY

"""Byte-budget checks for M-CACHE.

The entry count and the byte budget are two different questions, and the cache
must answer both: "how many blocks fit" and "how much memory do they take". The
checks below pin the second bound, prove that the first one still holds, prove
that the acceptance contract of the prefix suite survives (the anonymized bytes
are the same whether the budget served a hit or the cache was switched off), and
prove that the settings the owner already has in the config file reach the cache
and the health endpoint.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.cache import CacheError, TokenizationCache  # noqa: E402
from src.detect_ner import NerDetector  # noqa: E402
from src.dictionary import PiiDictionary  # noqa: E402
from src.router import ProxyService, build_service  # noqa: E402
from tests.harness import FakeUpstream, temp_config  # noqa: E402

CLIENT_NAME = "Иванов Иван Иванович"
CLIENT_PHONE = "79000000001"
MEGABYTE = 1024 * 1024


class BytesBudgetCacheTests(unittest.TestCase):
    """Unit behaviour of the byte budget."""

    def test_byte_budget_evicts_the_least_recently_used_entry(self) -> None:
        cache = TokenizationCache(1000, max_bytes=1000)
        cache.put("первый", "a" * 400)
        cache.put("второй", "b" * 400)
        self.assertEqual(cache.stats()["bytes"], 800)
        cache.get("первый")  # «второй» становится самым старым
        cache.put("третий", "c" * 400)
        self.assertIsNone(cache.get("второй"))
        self.assertEqual(cache.get("первый"), "a" * 400)
        self.assertEqual(cache.get("третий"), "c" * 400)
        stats = cache.stats()
        self.assertEqual((stats["entries"], stats["bytes"]), (2, 800))
        self.assertEqual(stats["evictions"], 1)

    def test_both_bounds_are_held_at_once(self) -> None:
        """Ни один предел не отменяет другой: вытесняем, пока не соблюдены оба."""
        by_entries = TokenizationCache(2, max_bytes=1000)
        for index in range(3):
            by_entries.put(f"блок{index}", "a" * 100)
        self.assertEqual(by_entries.stats()["entries"], 2)
        self.assertEqual(by_entries.stats()["evictions"], 1)
        self.assertEqual(by_entries.stats()["bytes"], 200)

        by_bytes = TokenizationCache(100, max_bytes=150)
        for index in range(2):
            by_bytes.put(f"блок{index}", "a" * 100)
        self.assertEqual(by_bytes.stats()["entries"], 1)
        self.assertEqual(by_bytes.stats()["bytes"], 100)
        self.assertEqual(by_bytes.stats()["evictions"], 1)

    def test_rewriting_an_entry_does_not_double_count_its_bytes(self) -> None:
        cache = TokenizationCache(10, max_bytes=10000)
        cache.put("блок", "a" * 300)
        cache.put("блок", "b" * 500)
        stats = cache.stats()
        self.assertEqual((stats["entries"], stats["bytes"], stats["evictions"]), (1, 500, 0))
        self.assertEqual(cache.get("блок"), "b" * 500)

    def test_block_bigger_than_the_budget_is_not_kept(self) -> None:
        """Предел — потолок памяти, он важнее желания оставить блок."""
        cache = TokenizationCache(10, max_bytes=100)
        cache.put("блок", "a" * 300)
        stats = cache.stats()
        self.assertEqual((stats["entries"], stats["bytes"]), (0, 0))
        self.assertEqual(stats["evictions"], 1)
        self.assertIsNone(cache.get("блок"))

    def test_zero_budget_means_no_byte_budget(self) -> None:
        cache = TokenizationCache(10, max_bytes=0)
        self.assertEqual(cache.stats()["limit_bytes"], 0)
        cache.put("первый", "a" * 5000)
        cache.put("второй", "b" * 5000)
        stats = cache.stats()
        self.assertEqual((stats["entries"], stats["bytes"], stats["evictions"]), (2, 10000, 0))

    def test_negative_budget_is_rejected(self) -> None:
        with self.assertRaises(CacheError) as context:
            TokenizationCache(10, max_bytes=-1)
        self.assertEqual(context.exception.code, "CACHE_BAD_SIZE")

    def test_disabled_cache_ignores_the_budget(self) -> None:
        cache = TokenizationCache(0, max_bytes=1000)
        self.assertFalse(cache.enabled)
        self.assertEqual(cache.stats()["limit_bytes"], 1000)
        cache.put("блок", "a" * 10)
        self.assertIsNone(cache.get("блок"))
        stats = cache.stats()
        self.assertEqual((stats["entries"], stats["bytes"], stats["evictions"]), (0, 0, 0))

    def test_stats_expose_the_byte_budget(self) -> None:
        cache = TokenizationCache(7, max_bytes=4096)
        cache.put("блок", "a" * 120)
        stats = cache.stats()
        for key in ("bytes", "entries", "evictions", "limit_bytes"):
            self.assertIn(key, stats)
        self.assertEqual(stats["entries"], stats["size"])
        self.assertEqual(stats["bytes"], 120)
        self.assertEqual(stats["limit_bytes"], 4096)
        self.assertEqual(stats["max_entries"], 7)

    def test_a_single_capacity_argument_keeps_the_old_behaviour(self) -> None:
        """Старый вызов TokenizationCache(cache_size) обязан работать без правок."""
        cache = TokenizationCache(2)
        self.assertTrue(cache.enabled)
        self.assertEqual(cache.stats()["limit_bytes"], 0)
        for index in range(3):
            cache.put(f"блок{index}", "a" * 10000)
        stats = cache.stats()
        self.assertEqual((stats["entries"], stats["bytes"], stats["evictions"]), (2, 20000, 1))

    def test_a_realistic_history_fits_without_eviction(self) -> None:
        """Ради этого бюджет и нужен: живой диалог целиком, без вытеснения начала."""
        cache = TokenizationCache(512, max_bytes=64 * MEGABYTE)
        for index in range(400):
            cache.put(f"[ход {index}] история диалога", "x" * 1500)
        stats = cache.stats()
        self.assertEqual(stats["entries"], 400)
        self.assertEqual(stats["bytes"], 600_000)
        self.assertEqual(stats["evictions"], 0)
        self.assertEqual(stats["limit_bytes"], 64 * MEGABYTE)

    def test_a_hit_returns_the_bytes_that_a_miss_would_recompute(self) -> None:
        cache = TokenizationCache(10, max_bytes=10000)
        text = "блок, в котором ничего не нашлось"
        recomputed = "обезличенный результат блока"

        self.assertIsNone(cache.get(text))  # промах: считаем заново
        cache.put(text, recomputed)
        hit = cache.get(text)  # попадание: отдаём ровно то же
        self.assertIsNotNone(hit)
        self.assertEqual(hit, recomputed)
        self.assertEqual(str(hit).encode("utf-8"), recomputed.encode("utf-8"))


class BytesBudgetServiceTests(unittest.TestCase):
    """The settings the owner already has must reach the cache, and be visible."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dictionary_path = os.path.join(self._tmp.name, "dict_raw.json")
        with open(self.dictionary_path, "w", encoding="utf-8") as handle:
            json.dump({"P": [CLIENT_NAME], "T": [CLIENT_PHONE]}, handle, ensure_ascii=False)

    def _service(self, **overrides) -> ProxyService:
        upstream = FakeUpstream()
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
    def _conversation(turns: int) -> dict:
        messages = [
            {"role": "system", "content": "Ты помощник сети фитнес-клубов."},
            {"role": "user", "content": f"Проверь клиента {CLIENT_NAME}, телефон {CLIENT_PHONE}"},
            {"role": "assistant", "content": "Карта активна, продление в ноябре."},
            {"role": "tool", "content": "Отчёт по клубу готов, продлений больше."},
        ]
        return {"model": "deepseek-flash", "stream": False, "messages": messages[:turns]}

    def _anonymize(self, service: ProxyService, payload: dict) -> dict:
        status, body = service.handle_chat_completions(
            payload, "ds", "/v1/chat/completions", "mattermost"
        )
        self.assertEqual(status, 200, msg=json.dumps(body, ensure_ascii=False)[:200])
        return service._upstream.last_payload

    def test_the_configured_budget_reaches_the_cache(self) -> None:
        service = self._service(PII_PROXY_BLOCK_CACHE_MB="8", PII_PROXY_CACHE_SIZE="7")
        stats = service.health()["cache"]
        self.assertEqual(stats["limit_bytes"], 8 * MEGABYTE)
        self.assertEqual(stats["max_entries"], 7)

    def test_the_switch_switches_the_cache_off(self) -> None:
        service = self._service(PII_PROXY_BLOCK_CACHE="false")
        self.assertFalse(service._cache.enabled)
        service_off = service.health()["cache"]
        self.assertEqual(service_off["entries"], 0)
        self.assertEqual(service_off["bytes"], 0)
        self._anonymize(service, self._conversation(4))
        after = service.health()["cache"]
        self.assertEqual((after["entries"], after["bytes"], after["hits"]), (0, 0, 0))

    def test_healthz_reports_bytes_entries_evictions_and_the_limit(self) -> None:
        service = self._service(PII_PROXY_BLOCK_CACHE_MB="1")
        self._anonymize(service, self._conversation(4))
        stats = service.health()["cache"]
        for key in ("bytes", "entries", "evictions", "limit_bytes"):
            self.assertIn(key, stats)
        self.assertEqual(stats["limit_bytes"], MEGABYTE)
        self.assertGreater(stats["entries"], 0)
        self.assertGreater(stats["bytes"], 0)

    def test_the_configured_budget_really_evicts(self) -> None:
        """Минимальный бюджет настройки (1 МБ) — это то, что держит живой кэш."""
        service = self._service(PII_PROXY_BLOCK_CACHE_MB="1")
        cache = service._cache
        cache.put("первый большой блок", "x" * (600 * 1024))
        cache.put("второй большой блок", "y" * (600 * 1024))
        stats = service.health()["cache"]
        self.assertLessEqual(stats["bytes"], MEGABYTE)
        self.assertGreater(stats["evictions"], 0)
        self.assertEqual(stats["limit_bytes"], MEGABYTE)

    def test_the_anonymized_bytes_are_identical_with_the_cache_on_and_off(self) -> None:
        """Контракт прозрачности: попадание и промах дают одни и те же байты.

        Одна служба держит кэш с бюджетом, вторая выключена настройкой, то есть
        считает каждый блок заново. Растущий диалог обязан обезличиться побайтово
        одинаково, иначе бюджет что-то сломал бы молча.
        """
        cached = self._service(PII_PROXY_BLOCK_CACHE_MB="64")
        uncached = self._service(PII_PROXY_BLOCK_CACHE="false")
        for turns in (2, 3, 4):
            from_cached = self._anonymize(cached, self._conversation(turns))
            from_uncached = self._anonymize(uncached, self._conversation(turns))
            self.assertEqual(
                json.dumps(from_cached, ensure_ascii=False, sort_keys=True),
                json.dumps(from_uncached, ensure_ascii=False, sort_keys=True),
            )
        self.assertGreater(cached.health()["cache"]["hits"], 0)
        self.assertEqual(uncached.health()["cache"]["hits"], 0)


if __name__ == "__main__":
    unittest.main()
