# FILE: tests/test_service_lexicon.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify M-SERVICE-LEXICON: the operator's service lexicon ships a neutral empty default and is read from a configuration mapping, the environment and a JSON file, keeping the operator's categories.
#   SCOPE: empty default, category-mapping form, single-line form, environment variables, JSON file, merge without duplicates, case and whitespace normalisation.
#   DEPENDS: M-SERVICE-LEXICON
#   LINKS: V-M-SERVICE-LEXICON, M-SERVICE-LEXICON
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   ServiceLexiconTests - набор проверок раздела служебной лексики оператора
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - решение владельца 25.09.2026: клубно-тарифные слова ушли из кода в настройки, поэтому у раздела есть своя проверка: пустое умолчание и три способа чтения.
# END_CHANGE_SUMMARY

"""Проверка раздела служебной лексики оператора (M-SERVICE-LEXICON).

Проверяется главное обещание раздела: своего набора тарифов в коде нет (умолчание пусто), а слова
оператора приходят из настроек любым из трёх способов — сопоставлением с категориями, строкой
окружения или файлом JSON. Значений клиентов здесь нет и быть не может: это лексика оператора.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.service_lexicon import (  # noqa: E402
    DEFAULT_CATEGORY,
    ENV_SERVICE_LEXICON,
    ENV_SERVICE_LEXICON_FILE,
    ServiceLexicon,
    from_env,
    from_mapping,
    load_json,
    merge,
)


class ServiceLexiconTests(unittest.TestCase):
    def test_default_is_empty(self) -> None:
        """Умолчание публичной сборки — пустая лексика: чужих тарифов в коде нет."""
        lexicon = ServiceLexicon()
        self.assertTrue(lexicon.is_empty())
        self.assertEqual(0, lexicon.word_count)
        self.assertEqual(0, lexicon.category_count)

    def test_mapping_keeps_the_categories(self) -> None:
        lexicon = from_mapping(
            {"тарифы и клубы": ["Годовой", "Базовый"], "услуги": ["пробное занятие"]}
        )
        self.assertEqual(2, lexicon.category_count)
        self.assertEqual(3, lexicon.word_count)
        self.assertEqual(("годовой", "базовый"), lexicon.by_category["тарифы и клубы"])

    def test_mapping_normalises_case_whitespace_and_duplicates(self) -> None:
        lexicon = from_mapping({"тарифы": ["  Годовой ", "годовой", "Годовой"]})
        self.assertEqual(("годовой",), lexicon.by_category["тарифы"])

    def test_a_plain_string_lands_in_the_default_category(self) -> None:
        lexicon = from_mapping("Годовой, Базовый;утренняя группа")
        self.assertEqual(("годовой", "базовый", "утренняя группа"), lexicon.by_category[DEFAULT_CATEGORY])

    def test_empty_entries_are_dropped(self) -> None:
        self.assertTrue(from_mapping({"тарифы": ["", "   "]}).is_empty())
        self.assertTrue(from_mapping(None).is_empty())
        self.assertTrue(from_mapping("").is_empty())

    def test_environment_reads_a_comma_string(self) -> None:
        lexicon = from_env({ENV_SERVICE_LEXICON: "Годовой,Базовый"})
        self.assertEqual(("годовой", "базовый"), lexicon.by_category[DEFAULT_CATEGORY])

    def test_environment_reads_a_categorised_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "service-lexicon.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"тарифы и клубы": ["Годовой"]}, handle, ensure_ascii=False)
            lexicon = from_env(
                {ENV_SERVICE_LEXICON: "пробное занятие", ENV_SERVICE_LEXICON_FILE: path}
            )
        self.assertEqual(2, lexicon.category_count)
        self.assertEqual(("годовой",), lexicon.by_category["тарифы и клубы"])
        self.assertEqual(("пробное занятие",), lexicon.by_category[DEFAULT_CATEGORY])

    def test_absent_file_leaves_the_lexicon_empty(self) -> None:
        self.assertTrue(load_json("/nonexistent/service-lexicon.json").is_empty())

    def test_merge_unions_categories_without_duplicates(self) -> None:
        merged = merge(
            from_mapping({"тарифы": ["Годовой"]}),
            from_mapping({"тарифы": ["Годовой", "Базовый"], "услуги": ["пробное занятие"]}),
        )
        self.assertEqual(("годовой", "базовый"), merged.by_category["тарифы"])
        self.assertEqual(("пробное занятие",), merged.by_category["услуги"])


if __name__ == "__main__":
    unittest.main()
