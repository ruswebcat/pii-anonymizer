# FILE: tests/test_ner_tag_cache.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the morphology tag cache: one parse per distinct word, identical tags on a hit, bounded memory, safe clearing.
#   SCOPE: cache hit/miss behaviour with a spy analyzer, eviction bound, clear_tag_cache, thread safety smoke.
#   DEPENDS: src/detect_ner.py
#   LINKS: M-NER, V-M-NER, Phase-19
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   SpyAnalyzer - analyzer that counts parses and returns fixed tags
#   TagCacheTests - behaviour of the morphology tag cache
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-19 (23.09.2026): проверки кэша разборов; в тестах только заглушки-слова.
# END_CHANGE_SUMMARY
"""Morphology is the hottest step of the pipeline, so its cache is verified directly."""

import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import src.detect_ner as ner  # noqa: E402

# START_BLOCK_TEST_TAG_CACHE
WORD_A = "заглушкин"
WORD_B = "заглушкина"


class SpyAnalyzer:
    """Анализатор-заглушка: считает разборы и отдаёт теги имени."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def parse(self, word: str):  # noqa: ANN201 - форма ответа pymorphy
        self.calls.append(word)

        class Tag:
            grammemes = {"Surn", "sing", "nomn"}

        class Parse:
            tag = Tag()

        return [Parse()]


class BrokenAnalyzer:
    """Анализатор, который всегда падает: сбой не должен ломать обработку."""

    def parse(self, word: str):  # noqa: ANN201 - форма ответа pymorphy
        raise RuntimeError("сломан")


class TagCacheTests(unittest.TestCase):
    """Один разбор на слово, одинаковый ответ при попадании, память ограничена."""

    def setUp(self) -> None:
        ner.clear_tag_cache()

    def tearDown(self) -> None:
        ner.clear_tag_cache()

    def test_the_same_word_is_parsed_once(self) -> None:
        analyzer = SpyAnalyzer()
        first = ner._tag_names(analyzer, WORD_A)
        second = ner._tag_names(analyzer, WORD_A)
        self.assertEqual(first, second)
        self.assertEqual([WORD_A], analyzer.calls, "повторный разбор того же слова не нужен")
        stats = ner.tag_cache_stats()
        self.assertEqual(1, stats["hits"])
        self.assertEqual(1, stats["misses"])

    def test_different_case_is_a_different_key(self) -> None:
        """Морфология различает регистр, поэтому ключ кэша тоже обязан его различать."""
        analyzer = SpyAnalyzer()
        ner._tag_names(analyzer, WORD_A)
        ner._tag_names(analyzer, WORD_A.capitalize())
        self.assertEqual(2, len(analyzer.calls))

    def test_cache_is_bounded_and_evicts_oldest(self) -> None:
        original_limit = ner._TAG_CACHE_LIMIT
        ner._TAG_CACHE_LIMIT = 2
        try:
            analyzer = SpyAnalyzer()
            ner._tag_names(analyzer, "слово1")
            ner._tag_names(analyzer, "слово2")
            ner._tag_names(analyzer, "слово3")
            self.assertEqual(2, ner.tag_cache_stats()["size"], "размер кэша ограничен")
            ner._tag_names(analyzer, "слово1")
            self.assertEqual(4, len(analyzer.calls), "вытесненное слово разбирается заново")
        finally:
            ner._TAG_CACHE_LIMIT = original_limit

    def test_broken_analyzer_is_cached_as_no_tags(self) -> None:
        self.assertEqual((), ner._tag_names(BrokenAnalyzer(), WORD_B))
        self.assertEqual((), ner._tag_names(BrokenAnalyzer(), WORD_B))

    def test_clear_empties_the_cache(self) -> None:
        ner._tag_names(SpyAnalyzer(), WORD_A)
        self.assertEqual(1, ner.tag_cache_stats()["size"])
        ner.clear_tag_cache()
        self.assertEqual(0, ner.tag_cache_stats()["size"])

    def test_concurrent_lookups_stay_consistent(self) -> None:
        analyzer = SpyAnalyzer()
        results: list[tuple[str, ...]] = []
        lock = threading.Lock()

        def worker() -> None:
            value = ner._tag_names(analyzer, WORD_A)
            with lock:
                results.append(value)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(8, len(results))
        self.assertTrue(all(value == results[0] for value in results))
# END_BLOCK_TEST_TAG_CACHE


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
