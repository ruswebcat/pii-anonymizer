# FILE: tests/test_dictionary.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-DICT contract: loading, exact lookup, hot reload by file change, graceful behaviour on a missing or broken file, and snapshots without values.
#   SCOPE: M-DICT unit checks only.
#   DEPENDS: src/dictionary.py
#   LINKS: M-DICT, V-M-DICT, tests/test_dictionary.py
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   DictionaryTests - unittest suite for PiiDictionary
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-2 checks for the exact-match layer.
# END_CHANGE_SUMMARY

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.dictionary import (  # noqa: E402
    SCHEMA_DIGEST,
    DictionaryError,
    PiiDictionary,
    value_digest,
)
from src.normalize import normalize  # noqa: E402

# START_BLOCK_TEST_DICTIONARY
FIO = "Иванов Иван Иванович"
PHONE = "79000000001"


class DictionaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "pii_dict.json")
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump({"P": [FIO, "Петруш Татьяна"], "T": [PHONE], "C": ["35209"]}, handle)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_loads_values_and_reports_size(self) -> None:
        dictionary = PiiDictionary(self.path)
        self.assertEqual(dictionary.size, 4)
        self.assertIn(FIO, dictionary.values_for("P"))
        self.assertEqual(dictionary.values_for("T"), [PHONE])

    def test_lookup_is_normalized_and_class_aware(self) -> None:
        dictionary = PiiDictionary(self.path)
        self.assertEqual(dictionary.lookup(normalize("P", FIO)), "P")
        self.assertEqual(dictionary.lookup(normalize("T", PHONE), "T"), "T")
        self.assertIsNone(dictionary.lookup("Неизвестный Иван Иванович"))
        self.assertIsNone(dictionary.lookup(normalize("T", PHONE), "P"))

    def test_missing_file_is_not_an_error(self) -> None:
        dictionary = PiiDictionary(os.path.join(self._tmp.name, "нет-такого.json"))
        self.assertEqual(dictionary.size, 0)
        self.assertEqual(dictionary.values_for("P"), [])
        self.assertIsNone(dictionary.lookup("Иванов Иван Иванович"))
        self.assertEqual(dictionary.snapshot()["warnings"], [])

    def test_broken_file_degrades_to_empty_with_warning(self) -> None:
        broken = os.path.join(self._tmp.name, "broken.json")
        with open(broken, "w", encoding="utf-8") as handle:
            handle.write("{ это не json")
        dictionary = PiiDictionary(broken)
        self.assertEqual(dictionary.size, 0)
        self.assertTrue(dictionary.snapshot()["warnings"])

    def test_unknown_classes_and_shapes_are_ignored(self) -> None:
        mixed = os.path.join(self._tmp.name, "mixed.json")
        with open(mixed, "w", encoding="utf-8") as handle:
            json.dump({"P": [FIO], "X": ["мусор"], "T": "не список", "A": [""]}, handle)
        dictionary = PiiDictionary(mixed)
        self.assertEqual(dictionary.size, 1)
        self.assertEqual(sorted(dictionary.snapshot()["counts"]), ["P"])

    def test_hot_reload_picks_up_a_new_version(self) -> None:
        dictionary = PiiDictionary(self.path)
        self.assertIsNone(dictionary.lookup(normalize("P", "Новиков Пётр Ильич")))
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump({"P": [FIO, "Новиков Пётр Ильич"]}, handle)
        os.utime(self.path, (os.stat(self.path).st_atime, os.stat(self.path).st_mtime + 5))
        self.assertTrue(dictionary.reload_if_changed())
        self.assertEqual(dictionary.lookup(normalize("P", "Новиков Пётр Ильич")), "P")
        self.assertFalse(dictionary.reload_if_changed())

    def test_snapshot_never_contains_values(self) -> None:
        dictionary = PiiDictionary(self.path)
        blob = json.dumps(dictionary.snapshot(), ensure_ascii=False)
        self.assertNotIn(FIO, blob)
        self.assertNotIn(PHONE, blob)
        self.assertEqual(dictionary.snapshot()["counts"]["P"], 2)

    def test_error_codes_are_stable(self) -> None:
        with self.assertRaises(DictionaryError) as context:
            raise DictionaryError("DICT_BAD_ROOT", "root must be an object")
        self.assertEqual(context.exception.code, "DICT_BAD_ROOT")
# END_BLOCK_TEST_DICTIONARY


# START_BLOCK_TEST_KEYED_DICTIONARY
class KeyedDictionaryTests(unittest.TestCase):
    """Schema 2: the file holds keyed digests, never readable values."""

    KEY = b"keyed-dictionary-test-key-32bytes"

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "pii_dict.json")
        payload = {
            "schema": SCHEMA_DIGEST,
            "generated_by": "M-DICT-EXPORT",
            "values": 2,
            "digests": {
                "P": [value_digest(self.KEY, "P", normalize("P", FIO))],
                "T": [value_digest(self.KEY, "T", normalize("T", PHONE))],
            },
        }
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_file_contains_no_readable_values(self) -> None:
        with open(self.path, encoding="utf-8") as handle:
            blob = handle.read()
        self.assertNotIn(FIO, blob)
        self.assertNotIn("Иванов", blob)
        self.assertNotIn(PHONE, blob)

    def test_lookup_works_with_the_key(self) -> None:
        dictionary = PiiDictionary(self.path, key=self.KEY)
        self.assertTrue(dictionary.snapshot()["keyed"])
        self.assertEqual(dictionary.size, 2)
        self.assertEqual(dictionary.lookup(normalize("P", FIO), "P"), "P")
        self.assertEqual(dictionary.lookup(normalize("T", PHONE), "T"), "T")
        self.assertIsNone(dictionary.lookup("Неизвестный Иван Иванович", "P"))

    def test_wrong_key_matches_nothing(self) -> None:
        dictionary = PiiDictionary(self.path, key=b"another-key-32-bytes-long-123456")
        self.assertIsNone(dictionary.lookup(normalize("P", FIO), "P"))

    def test_missing_key_is_reported_and_harmless(self) -> None:
        dictionary = PiiDictionary(self.path)
        self.assertIsNone(dictionary.lookup(normalize("P", FIO), "P"))
        self.assertTrue(dictionary.snapshot()["warnings"])

    def test_values_for_is_empty_in_keyed_mode(self) -> None:
        dictionary = PiiDictionary(self.path, key=self.KEY)
        self.assertEqual(dictionary.values_for("P"), [])

    def test_hot_reload_switches_to_the_new_version(self) -> None:
        dictionary = PiiDictionary(self.path, key=self.KEY)
        payload = {
            "schema": SCHEMA_DIGEST,
            "values": 1,
            "digests": {"P": [value_digest(self.KEY, "P", normalize("P", "Новиков Пётр Ильич"))]},
        }
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)
        os.utime(self.path, (os.stat(self.path).st_atime, os.stat(self.path).st_mtime + 5))
        self.assertTrue(dictionary.reload_if_changed())
        self.assertEqual(dictionary.lookup(normalize("P", "Новиков Пётр Ильич"), "P"), "P")
        self.assertIsNone(dictionary.lookup(normalize("P", FIO), "P"))
# END_BLOCK_TEST_KEYED_DICTIONARY


if __name__ == "__main__":
    unittest.main()
