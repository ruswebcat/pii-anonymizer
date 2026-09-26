# FILE: tests/test_detect_stem.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify that declined surnames are recognized through their stem (M-DETECT-NAME with M-NAME-FORMS): «Терёхиной» and «Иванову» are found from the open list, ordinary text stays untouched, and a broken list does not stop recognition.
#   SCOPE: stem lookup with ё and without, client-context gate, broken list fail-open, single-word limit.
#   DEPENDS: M-DETECT-NAME, M-NAME-FORMS
#   LINKS: V-M-DETECT-NAME, Phase-12
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   make_layer - открытый список из нескольких фамилий
#   StemDetectionTests - склонённые формы, обычный текст, битый список
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-12 шаг 2: обратный ход к основе вместо генерации форм кандидата.
# END_CHANGE_SUMMARY

import gzip
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detect_name import NameDetector  # noqa: E402
from src.name_layer import load_name_layer  # noqa: E402


def make_layer(directory: str, values: list[str]):
    """Write a minimal open list and load it."""
    path = os.path.join(directory, "layer.json.gz")
    payload = {
        "schema": 1,
        "meta": {"source": "https://example.test/names", "licence": "BSD-3-Clause"},
        "values": {"P": values},
    }
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False)
    return load_name_layer(path)


class StemDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.detector = NameDetector(
            None, make_layer(self._tmp.name, ["терехин", "иванов", "токенец"])
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def found(self, text: str) -> list[str]:
        return [match.raw for match in self.detector.detect_names(text)]

    def test_declined_surname_with_yo_is_found(self) -> None:
        """«Терёхиной» → основа «терехин»: список хранит «ё», ключ сравнения — тоже."""
        self.assertIn("Терёхиной", self.found("клиент Терёхиной, телефон 79001112233"))

    def test_declined_surname_without_yo_is_found(self) -> None:
        self.assertIn("Иванову", self.found("выгрузка: Иванову; 79001112233"))

    def test_ordinary_text_is_left_alone(self) -> None:
        """Без признаков данных склонённая форма не заменяется."""
        self.assertEqual(self.found("Терёхиной и солнце"), [])
        self.assertEqual(self.found("Терёхин и общество"), [])

    def test_broken_layer_does_not_stop_detection(self) -> None:
        """Битый список не должен ронять распознавание (fail-open)."""

        class Broken:
            def contains(self, *_args, **_kwargs):
                raise RuntimeError("список недоступен")

        detector = NameDetector(None, Broken())
        self.assertEqual(detector.detect_names("клиент Терёхиной, телефон 79001112233"), [])

    def test_multiword_is_not_stemmed(self) -> None:
        """Основы считаются от одного слова: многословное значение в основы не разбирается."""
        self.assertFalse(self.detector._layer_knows_stem("Иванов Иван Иванович"))  # noqa: SLF001


if __name__ == "__main__":
    unittest.main()
