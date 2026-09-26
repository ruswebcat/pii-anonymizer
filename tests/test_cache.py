# FILE: tests/test_cache.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-CACHE contract: hits and misses, LRU eviction, disabled mode, and the guarantee that raw values never enter the cache.
#   SCOPE: M-CACHE unit checks only.
#   DEPENDS: src/cache.py
#   LINKS: M-CACHE, V-M-CACHE, tests/test_cache.py
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   CacheTests - unittest suite for TokenizationCache
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-2 checks for the performance layer.
# END_CHANGE_SUMMARY

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.cache import CacheError, TokenizationCache  # noqa: E402

# START_BLOCK_TEST_CACHE
FIO = "Иванов Иван Иванович"


class CacheTests(unittest.TestCase):
    def test_miss_then_hit(self) -> None:
        cache = TokenizationCache(8)
        self.assertIsNone(cache.get("блок текста"))
        cache.put("блок текста", "обезличенный блок")
        self.assertEqual(cache.get("блок текста"), "обезличенный блок")
        stats = cache.stats()
        self.assertEqual((stats["hits"], stats["misses"], stats["size"]), (1, 1, 1))

    def test_key_is_a_hash_not_the_text(self) -> None:
        key = TokenizationCache.key_for(FIO)
        self.assertEqual(len(key), 64)
        self.assertNotIn("Иванов", key)
        self.assertNotIn(FIO, key)

    def test_identical_text_gives_identical_key(self) -> None:
        self.assertEqual(
            TokenizationCache.key_for("один блок"), TokenizationCache.key_for("один блок")
        )
        self.assertNotEqual(
            TokenizationCache.key_for("один блок"), TokenizationCache.key_for("другой блок")
        )

    def test_raw_values_never_enter_the_cache(self) -> None:
        cache = TokenizationCache(8)
        cache.put(f"клиент {FIO}", "клиент ⟦P-AAAAAAAAAAAA⟧")
        self.assertFalse(cache.contains_any([FIO, "Иванов", "79000000001"]))

    def test_least_recently_used_entry_is_evicted(self) -> None:
        cache = TokenizationCache(2)
        cache.put("первый", "1")
        cache.put("второй", "2")
        cache.get("первый")  # второй становится самым старым
        cache.put("третий", "3")
        self.assertIsNone(cache.get("второй"))
        self.assertEqual(cache.get("первый"), "1")
        self.assertEqual(cache.get("третий"), "3")
        self.assertEqual(cache.stats()["size"], 2)

    def test_disabled_cache_does_nothing(self) -> None:
        cache = TokenizationCache(0)
        self.assertFalse(cache.enabled)
        cache.put("блок", "значение")
        self.assertIsNone(cache.get("блок"))
        self.assertEqual(cache.stats()["size"], 0)

    def test_negative_capacity_is_rejected(self) -> None:
        with self.assertRaises(CacheError) as context:
            TokenizationCache(-1)
        self.assertEqual(context.exception.code, "CACHE_BAD_SIZE")

    def test_clear_drops_entries_but_keeps_counters(self) -> None:
        cache = TokenizationCache(4)
        cache.put("блок", "значение")
        cache.get("блок")
        cache.clear()
        self.assertEqual(cache.stats()["size"], 0)
        self.assertEqual(cache.stats()["hits"], 1)
# END_BLOCK_TEST_CACHE


if __name__ == "__main__":
    unittest.main()
