# FILE: tests/test_name_coherence.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify M-NAME-COHERENCE — the co-occurrence index: card parts become keyed digests, order does not matter, planned pairs confirm and foreign pairs do not, and a broken index is refused instead of silently disabling the guard.
#   SCOPE: combo digests, order insensitivity, tool builder on a fake fetcher, file round trip with permissions, refusal of readable or broken files, confirmation of card pairs and refusal of glued pairs.
#   DEPENDS: M-NAME-COHERENCE
#   LINKS: V-M-NAME-COHERENCE
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   NameCoherenceTests - индекс сочетаний: сборка, файл, подтверждение
#   BuildNameCombosToolTests - инструмент сборки на подставном чтении страниц
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-17 (20.09.2026): регрессия индекса со-встречаемости и инструмента его сборки.
# END_CHANGE_SUMMARY

import gzip
import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.name_coherence import (  # noqa: E402
    CoherenceError,
    build_combos,
    combo_digest,
    combos_payload,
    is_candidate,
    is_part_value,
    load_name_coherence,
    write_combos,
)
from tools.build_name_combos import cards_from_api, main as build_main  # noqa: E402

DICT_KEY = b"coherence-test-dict-key-32-byte!"
#: Синтетические карточки: значения выдуманы, настоящих клиентов здесь быть не может.
CARDS = (
    ("Иванов", "Иван", "Иванович"),
    ("Печёнов", "Сергей", "Сергеевич"),
)


class NameCoherenceTests(unittest.TestCase):
    """Индекс сочетаний: ключ, файл, подтверждение."""

    def test_digest_is_order_insensitive(self) -> None:
        # В карточках поля перепутаны местами, поэтому пара обязана подтверждаться в любом порядке.
        self.assertEqual(
            combo_digest(DICT_KEY, ["Иванов", "Иван"]),
            combo_digest(DICT_KEY, ["Иван", "Иванов"]),
        )

    def test_digest_needs_two_distinct_parts(self) -> None:
        self.assertIsNone(combo_digest(DICT_KEY, ["Иванов"]))
        self.assertIsNone(combo_digest(DICT_KEY, ["Иванов", "иванов"]))

    def test_card_pairs_are_confirmed_and_foreign_pairs_are_not(self) -> None:
        digests, counters = build_combos(CARDS, DICT_KEY)
        self.assertEqual(counters["cards"], 2)
        self.assertGreater(counters["pairs"], 0)
        index = load_name_coherence(_write_index(self, digests))
        assert index is not None
        self.assertTrue(index.confirm(DICT_KEY, ["Иванов", "Иван"]))
        self.assertTrue(index.confirm(DICT_KEY, ["Иванов", "Иван", "Иванович"]))
        # Склейка из разных карточек — именно то, из-за чего появилась выдуманная персона.
        self.assertFalse(index.confirm(DICT_KEY, ["Иванов", "Сергей"]))
        self.assertFalse(index.confirm(DICT_KEY, ["Иванов", "Сергей", "Сергеевич"]))

    def test_index_file_has_no_readable_values(self) -> None:
        digests, _counters = build_combos(CARDS, DICT_KEY)
        path = _write_index(self, digests)
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            payload = json.load(handle)
        rendered = json.dumps(payload, ensure_ascii=False)
        for part in ("Иванов", "Иван", "Сергеевич"):
            self.assertNotIn(part, rendered)
        self.assertTrue(payload["keyed"])
        self.assertTrue(all(len(item) == 16 for item in payload["combos"]))

    def test_index_file_is_0600(self) -> None:
        digests, _ = build_combos(CARDS, DICT_KEY)
        path = _write_index(self, digests)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), stat.S_IRUSR | stat.S_IWUSR)

    def test_missing_index_at_configured_path_is_refused(self) -> None:
        missing = os.path.join(self._tmpdir(), "absent.json.gz")
        with self.assertRaises(CoherenceError) as ctx:
            load_name_coherence(missing)
        self.assertEqual(ctx.exception.code, "COHERENCE_FILE_MISSING")

    def test_readable_index_is_refused(self) -> None:
        path = os.path.join(self._tmpdir(), "plain.json.gz")
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            json.dump({"schema": 1, "keyed": False, "combos": ["иванов иван"]}, handle)
        with self.assertRaises(CoherenceError) as ctx:
            load_name_coherence(path)
        self.assertEqual(ctx.exception.code, "COHERENCE_PLAIN")

    def test_unconfigured_index_is_not_an_error(self) -> None:
        self.assertIsNone(load_name_coherence(""))

    def test_candidate_shape_limits_the_check(self) -> None:
        self.assertTrue(is_candidate(["Иванов", "Иван"]))
        self.assertTrue(is_part_value("Иванов"))
        self.assertFalse(is_candidate(["79000000001", "Иван"]))
        self.assertFalse(is_candidate(["Иванов"]))
        self.assertFalse(is_part_value("79000000001"))
        self.assertFalse(is_part_value("два слова"))
        self.assertFalse(is_part_value("|"))

    def _tmpdir(self) -> str:
        if not hasattr(self, "_tmp"):
            self._tmp = tempfile.TemporaryDirectory()
            self.addCleanup(self._tmp.cleanup)
        return self._tmp.name


class BuildNameCombosToolTests(unittest.TestCase):
    """Инструмент сборки: страницы клиентов → файл индекса, без сети."""

    PAGES = {
        1: {
            "items": [
                {"id": 1, "name": "Тестовцева", "surname": "Марина", "patronymic": ""},
                {"id": 2, "name": "Тестовцев", "surname": "Геннадий", "patronymic": "Васильевич"},
            ],
            "total_count": 2,
        }
    }

    def _fetcher(self, url: str) -> dict:
        page = int(url.split("page=")[1].split("&")[0])
        return self.PAGES.get(page, {"items": [], "total_count": 2})

    def test_cards_are_read_from_the_configured_fields(self) -> None:
        cards = list(cards_from_api(self._fetcher, base="https://example.invalid/api/v2"))
        self.assertEqual(cards[0], ("Марина", "Тестовцева"))
        self.assertEqual(cards[1], ("Геннадий", "Тестовцев", "Васильевич"))

    def test_tool_writes_a_keyed_index_and_prints_only_numbers(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        key_path = os.path.join(tmp.name, "dict.key")
        with open(key_path, "wb") as handle:
            handle.write(DICT_KEY)
        os.chmod(key_path, 0o600)
        out = os.path.join(tmp.name, "pii_combos.json.gz")
        code = build_main(
            [
                "--out",
                out,
                "--key-file",
                key_path,
                "--base",
                "https://example.invalid/api/v2",
            ],
            fetcher=self._fetcher,
        )
        self.assertEqual(code, 0)
        index = load_name_coherence(out)
        self.assertIsNotNone(index)
        assert index is not None
        # Пара из карточки 1 подтверждается, склейка из разных карточек — нет.
        self.assertTrue(index.confirm(DICT_KEY, ["Тестовцева", "Марина"]))
        self.assertFalse(index.confirm(DICT_KEY, ["Тестовцева", "Геннадий"]))
        self.assertEqual(index.snapshot()["cards"], 2)

    def test_tool_refuses_without_a_key_file(self) -> None:
        """Без ключа отпечатков индекс собрать нельзя: файл ключа обязателен."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with self.assertRaises(FileNotFoundError):
            build_main(
                [
                    "--out",
                    os.path.join(tmp.name, "x.json.gz"),
                    "--key-file",
                    os.path.join(tmp.name, "absent.key"),
                ],
                fetcher=self._fetcher,
                env_values={},
            )

    def test_tool_prints_no_values(self) -> None:
        """Отчёт инструмента — только числа: значений клиентов в выводе нет."""
        import contextlib
        import io

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        key_path = os.path.join(tmp.name, "dict.key")
        with open(key_path, "wb") as handle:
            handle.write(DICT_KEY)
        os.chmod(key_path, 0o600)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            build_main(
                ["--out", os.path.join(tmp.name, "y.json.gz"), "--key-file", key_path],
                fetcher=self._fetcher,
            )
        printed = buffer.getvalue()
        for part in ("Тестовцева", "Марина", "Васильевич"):
            self.assertNotIn(part, printed)
        self.assertIn("combos=", printed)


def _write_index(test: unittest.TestCase, digests: set[str]) -> str:
    """Записать индекс во временный файл и вернуть путь."""
    tmp = tempfile.TemporaryDirectory()
    test.addCleanup(tmp.cleanup)
    path = os.path.join(tmp.name, "pii_combos.json.gz")
    write_combos(path, combos_payload(digests, {"source": "test", "cards": len(CARDS)}))
    return path


if __name__ == "__main__":
    unittest.main()
