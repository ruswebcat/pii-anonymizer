# FILE: tests/test_build_name_layer.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the open-layer builder over several sources: both source shapes are read, the filters stay exactly as before, provenance (URL, licence, note, per-source sha256) lands in meta, and the merge counts each value once while showing each source's own contribution.
#   SCOPE: чтение csv/zip и списка слов, комментарии и пустые строки, фильтры латиница/мусор/форма/коротко, слияние и дедупликация, происхождение и контрольные суммы, разбор аргументов CLI.
#   DEPENDS: M-NAME-LAYER
#   LINKS: V-M-NAME-LAYER, M-NAME-LAYER, Phase-9
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   WordlistReadingTests - комментарии, пустые строки, вид источника по расширению
#   FilterTests - те же фильтры, что были у одного источника
#   MergeTests - слияние двух независимых списков и вклад каждого
#   ProvenanceTests - адрес, лицензия, оговорка и sha256 каждого источника в meta
#   CommandLineTests - разбор аргументов и отказ при сдвиге списков
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-9 шаг 3: сборка объединённого слоя из datacoon и списка Natasha.
# END_CHANGE_SUMMARY

"""Сборка открытого слоя из нескольких источников.

Настоящих данных клиентов здесь нет: все значения — слова из открытых списков и заглушки.
"""

import gzip
import hashlib
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from build_name_layer import (  # noqa: E402
    KIND_NAMES,
    KIND_WORDS,
    BuildError,
    SourceSpec,
    build,
    collect_values,
    detect_source_kind,
    main,
    read_source,
)
from src.name_layer import load_name_layer  # noqa: E402


def _write_wordlist(path: Path, lines: list[str]) -> Path:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_names_csv(path: Path, rows: list[tuple[str, str, str]]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        body = "first_name,last_name,middle_name,sex\n" + "".join(
            f"{first},{last},{middle},m\n" for first, last, middle in rows
        )
        archive.writestr("data-distinct.csv", body)
    return path


class WordlistReadingTests(unittest.TestCase):
    """Список слов читается построчно, комментарии и пустые строки отбрасываются."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_kind_is_detected_from_the_extension(self) -> None:
        self.assertEqual(detect_source_kind("last.txt"), KIND_WORDS)
        self.assertEqual(detect_source_kind("data-distinct.zip"), KIND_NAMES)
        self.assertEqual(detect_source_kind("data-distinct.csv"), KIND_NAMES)

    def test_wordlist_skips_comments_and_blank_lines(self) -> None:
        path = _write_wordlist(self.dir / "last.txt", ["# комментарий", "иванов", "", "  ", "петров"])
        self.assertEqual(list(read_source(SourceSpec(str(path)))), ["иванов", "петров"])

    def test_wordlist_from_the_csv_columns(self) -> None:
        path = _write_names_csv(self.dir / "names.zip", [("Иван", "Иванов", "Иванович")])
        self.assertEqual(sorted(read_source(SourceSpec(str(path)))), ["Иван", "Иванов", "Иванович"])

    def test_missing_source_fails_loudly(self) -> None:
        with self.assertRaises(BuildError) as ctx:
            list(read_source(SourceSpec(str(self.dir / "nope.txt"))))
        self.assertEqual(ctx.exception.code, "LAYER_SOURCE_MISSING")


class FilterTests(unittest.TestCase):
    """Фильтры остались теми же, что были у одного источника."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_latin_junk_short_and_shape_are_rejected(self) -> None:
        path = _write_wordlist(
            self.dir / "mixed.txt",
            ["иванов", "Terekhin", "нет данных", "аб", "иванов-петров", "12345", "петровa"],
        )
        values, stats, _contributions = collect_values([SourceSpec(str(path))])
        self.assertEqual(values["P"], {"иванов", "иванов-петров"})
        # «петровa» с латинской «a» на конце — это латиница, а не форма: фильтр порядка важен.
        self.assertEqual(stats["отклонено: латиница"], 2)
        self.assertEqual(stats["отклонено: мусор"], 1)
        self.assertEqual(stats["отклонено: коротко"], 1)
        self.assertEqual(stats["отклонено: форма"], 1)

    def test_values_are_folded_to_lowercase(self) -> None:
        path = _write_wordlist(self.dir / "caps.txt", ["ИВАНОВ", "Иванов"])
        values, _stats, _contributions = collect_values([SourceSpec(str(path))])
        self.assertEqual(values["P"], {"иванов"})


class MergeTests(unittest.TestCase):
    """Два независимых списка сливаются, вклад каждого считается отдельно."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_union_keeps_every_value_once(self) -> None:
        first = _write_names_csv(self.dir / "names.zip", [("Иван", "Иванов", "Иванович")])
        second = _write_wordlist(self.dir / "last.txt", ["иванов", "скрытниц", "обрезко"])
        values, stats, contributions = collect_values(
            [SourceSpec(str(first)), SourceSpec(str(second), url="https://example.test/last.txt")]
        )
        self.assertEqual(values["P"], {"иван", "иванов", "иванович", "скрытниц", "обрезко"})
        self.assertEqual(contributions["https://example.test/last.txt"], 3)
        self.assertEqual(stats["принято"], 6, msg="пересечение считается по каждому источнику")

    def test_payload_carries_the_union_and_counts(self) -> None:
        first = _write_names_csv(self.dir / "names.zip", [("Иван", "Иванов", "Иванович")])
        second = _write_wordlist(self.dir / "last.txt", ["скрытниц"])
        payload = build([SourceSpec(str(first)), SourceSpec(str(second))])
        self.assertEqual(payload["schema"], 1)
        self.assertEqual(payload["meta"]["counts"]["P"], 4)
        self.assertEqual(sorted(payload["values"]["P"]), ["иван", "иванов", "иванович", "скрытниц"])


class ProvenanceTests(unittest.TestCase):
    """Адрес, лицензия, оговорка и контрольная сумма каждого источника остаются в файле слоя."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_every_source_reports_its_own_digest_and_licence(self) -> None:
        first = _write_names_csv(self.dir / "names.zip", [("Иван", "Иванов", "Иванович")])
        second = _write_wordlist(self.dir / "last.txt", ["скрытниц"])
        specs = [
            SourceSpec(str(first), url="https://example.test/names", licence="BSD-3-Clause"),
            SourceSpec(
                str(second),
                url="https://example.test/last.txt",
                licence="MIT репозитория; на сами данные лицензия не заявлена",
                note="происхождение словаря не задокументировано",
            ),
        ]
        payload = build(specs)
        sources = payload["meta"]["sources"]
        self.assertEqual(len(sources), 2)
        for spec, source in zip(specs, sources):
            with self.subTest(file=source["file"]):
                digest = hashlib.sha256(Path(spec.path).read_bytes()).hexdigest()
                self.assertEqual(source["sha256"], digest)
                self.assertEqual(source["url"], spec.url)
                self.assertTrue(source["licence"])
        self.assertIn("на сами данные лицензия не заявлена", sources[1]["licence"])
        self.assertEqual(sources[1]["note"], "происхождение словаря не задокументировано")
        self.assertIn("example.test/names", payload["meta"]["source"])
        self.assertIn("last.txt", payload["meta"]["licence"])

    def test_without_a_source_the_build_refuses(self) -> None:
        with self.assertRaises(BuildError) as ctx:
            build([])
        self.assertEqual(ctx.exception.code, "LAYER_NO_SOURCE")


class CommandLineTests(unittest.TestCase):
    """CLI собирает файл слоя и отказывается работать со сдвинутыми списками."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_two_sources_are_written_into_one_layer_file(self) -> None:
        first = _write_names_csv(self.dir / "names.zip", [("Иван", "Иванов", "Иванович")])
        second = _write_wordlist(self.dir / "last.txt", ["скрытниц", "обрезко"])
        out = self.dir / "layer.json.gz"
        code = main(
            [
                "--source", str(first), "--source-url", "https://example.test/names",
                "--source-licence", "BSD-3-Clause",
                "--source", str(second), "--source-url", "https://example.test/last.txt",
                "--source-licence", "MIT репозитория; на данные не заявлена",
                "--out", str(out),
            ]
        )
        self.assertEqual(code, 0)
        layer = load_name_layer(str(out))
        self.assertIsNotNone(layer)
        self.assertEqual(layer.size, 5)
        with gzip.open(out, "rt", encoding="utf-8") as handle:
            meta = json.load(handle)["meta"]
        self.assertEqual(len(meta["sources"]), 2)
        self.assertEqual(meta["counts"]["P"], 5)

    def test_shifted_licence_list_is_refused(self) -> None:
        first = _write_names_csv(self.dir / "names.zip", [("Иван", "Иванов", "Иванович")])
        second = _write_wordlist(self.dir / "last.txt", ["скрытниц"])
        with self.assertRaises(BuildError) as ctx:
            main(["--source", str(first), "--source", str(second), "--source-licence", "BSD-3-Clause"])
        self.assertEqual(ctx.exception.code, "LAYER_SOURCE_ARITY")

    def test_without_a_source_the_cli_refuses(self) -> None:
        with self.assertRaises(BuildError) as ctx:
            main(["--out", str(self.dir / "layer.json.gz")])
        self.assertEqual(ctx.exception.code, "LAYER_NO_SOURCE")


if __name__ == "__main__":
    unittest.main()
