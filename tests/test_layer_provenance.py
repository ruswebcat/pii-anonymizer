# FILE: tests/test_layer_provenance.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Держать происхождение открытого слоя проверяемым: точная ссылка на список Natasha и лицензионная оговорка обязаны присутствовать и в собранном файле, и в документации репозитория.
#   SCOPE: запись ссылки и лицензии в meta сборщиком, сохранение оговорки в meta, наличие точной ссылки и оговорки в README репозитория.
#   DEPENDS: M-NAME-LAYER
#   LINKS: V-M-NAME-LAYER, M-NAME-LAYER, Phase-9
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   NATASHA_LAST_PAGE - точная ссылка на источник списка фамилий Natasha
#   ProvenanceInMetaTests - ссылка и лицензия едут в meta собранного слоя
#   DocumentedSourceTests - точная ссылка и оговорка присутствуют в документах репозитория
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.1 - решение владельца 25.09.2026: точная ссылка на источник словарей Natasha и лицензионная оговорка держатся теперь и в docs/LICENCES.md, а не только в README. Раздел лицензий — документ, на который смотрит юридическая проверка, и ссылка в нём обязана ломать сборку при удалении.
#   PREVIOUS: v1.0.0 - решение владельца 19.09.2026: словарь Natasha остаётся, поэтому ссылка на источник и лицензионная оговорка фиксируются кодом, а не только текстом отчёта.
# END_CHANGE_SUMMARY

"""Происхождение открытого слоя (решение владельца 19.09.2026).

Словарь Natasha оставлен в работе, хотя на сами данные лицензия не заявлена (MIT относится к
коду репозитория; возможно, словарь производный от OpenCorpora под CC BY-SA). Раз данные
используются, ссылка на источник и оговорка должны быть проверяемыми: этот модуль падает,
если ссылку убрали из документов или сборщик перестал писать её в meta. Оговорка — не
формальность: по ней владелец принимает решение о допустимости.

Значений клиентов здесь нет и быть не может: источники открытые.
"""

import gzip
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools.build_name_layer import (  # noqa: E402
    SOURCE_REGISTRY,
    SourceSpec,
    build,
)

#: Точная человекочитаемая ссылка на источник списка фамилий Natasha.
NATASHA_LAST_PAGE = "https://github.com/natasha/natasha/blob/master/natasha/data/dict/last.txt"

#: Оговорка, которую сборщик обязан сохранить рядом с данными.
LICENCE_CAVEAT = "MIT репозитория; на сами данные лицензия не заявлена"


class ProvenanceInMetaTests(unittest.TestCase):
    """Ссылка и лицензия едут вместе с собранным файлом слоя."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.fixture = os.path.join(self._tmp.name, "last.txt")
        with open(self.fixture, "w", encoding="utf-8") as handle:
            handle.write("Тесля\nСкрытница\n")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _build(self) -> dict:
        registry = SOURCE_REGISTRY["natasha:last"]
        spec = SourceSpec(
            path=self.fixture,
            kind="wordlist",
            url=registry["raw"],
            page=NATASHA_LAST_PAGE,
            licence=LICENCE_CAVEAT,
            note=registry["note"],
        )
        return build([spec])

    def test_page_and_licence_land_in_meta(self) -> None:
        payload = self._build()
        source = payload["meta"]["sources"][0]
        self.assertEqual(source["page"], NATASHA_LAST_PAGE)
        self.assertEqual(source["licence"], LICENCE_CAVEAT)
        self.assertEqual(source["values"], 2)

    def test_caveat_survives_a_round_trip_through_the_file(self) -> None:
        """Оговорка обязана читаться из готового файла, а не только из памяти сборщика."""
        payload = self._build()
        target = os.path.join(self._tmp.name, "layer.json.gz")
        with gzip.open(target, "wt", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)
        with gzip.open(target, "rt", encoding="utf-8") as handle:
            restored = json.load(handle)
        source = restored["meta"]["sources"][0]
        self.assertEqual(source["page"], NATASHA_LAST_PAGE)
        self.assertIn("не заявлена", source["licence"])
        self.assertIn(NATASHA_LAST_PAGE, source["note"])

    def test_registry_holds_the_exact_link(self) -> None:
        entry = SOURCE_REGISTRY["natasha:last"]
        self.assertEqual(entry["page"], NATASHA_LAST_PAGE)
        self.assertIn(NATASHA_LAST_PAGE, entry["note"])


class DocumentedSourceTests(unittest.TestCase):
    """Точная ссылка и оговорка обязаны быть в документах репозитория.

    Проверка намеренно строковая: её смысл в том, чтобы удаление ссылки ломало сборку, а не
    проходило незамеченным. Замер и состав словаря при этом не трогаются.
    """

    DOCUMENTS = ("README.md", "docs/LICENCES.md")

    def test_documents_carry_the_exact_natasha_link(self) -> None:
        for name in self.DOCUMENTS:
            with self.subTest(document=name):
                text = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn(
                    NATASHA_LAST_PAGE,
                    text,
                    msg=f"{name}: нет точной ссылки на источник списка Natasha",
                )

    def test_documents_carry_the_licence_caveat(self) -> None:
        for name in self.DOCUMENTS:
            with self.subTest(document=name):
                text = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn(
                    LICENCE_CAVEAT,
                    text,
                    msg=f"{name}: нет лицензионной оговорки о словаре Natasha",
                )

    def test_readme_names_the_merged_layer_size(self) -> None:
        """README обязан показывать состав объединённого слоя, а не прежнее число."""
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("410 368", text, msg="README описывает прежний размер слоя")
        self.assertIn("natasha/natasha", text, msg="README не называет второй источник")


if __name__ == "__main__":
    unittest.main()
