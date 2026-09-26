# FILE: tests/test_reid_suite.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-REID-TEST contract: the suite reports on 100 records, detects a deliberately broken anonymizer, counts k-groups, and never puts values into the report.
#   SCOPE: full sample run, failing-case detection, k-anonymity grouping, report hygiene, log marker.
#   DEPENDS: M-REID-TEST, M-TOKENIZER, M-TEST-HARNESS
#   LINKS: V-M-REID-TEST, tests/test_reid_suite.py
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   NoopTokenizer - deliberately broken pipeline used to prove the suite can fail
#   ReidSuiteTests - unittest suite for ReidentificationSuite
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-3 checks for the re-identification act.
# END_CHANGE_SUMMARY

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detect_name import NameDetector  # noqa: E402
from src.map_store import TokenMapStore  # noqa: E402
from src.reid_suite import LOG_MARKER, ReidentificationSuite  # noqa: E402
from src.tokenizer import PayloadTokenizer  # noqa: E402
from tests.harness import LogCapture, sample_clients  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()

# START_BLOCK_TEST_REID_SUITE
TOKEN_KEY = b"reid-suite-test-key-32-bytes-long!"


class NoopTokenizer:
    """Tokenizer double that anonymizes nothing, to prove the suite notices."""

    def tokenize_payload(self, payload, session_id=""):  # noqa: ANN001, ANN202
        return payload, {}


def build_tokenizer(tmpdir: str) -> PayloadTokenizer:
    store = TokenMapStore(os.path.join(tmpdir, "reid.db"), b"s" * 32, 90)
    return PayloadTokenizer(TOKEN_KEY, store, NameDetector())


class ReidSuiteTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tokenizer = build_tokenizer(self._tmp.name)
        self.records = sample_clients(100)
        self.dictionary_path = os.path.join(self._tmp.name, "dict.json")
        with open(self.dictionary_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "schema": 2,
                    "values": 1,
                    "digests": {"T": ["0123456789abcdef"]},
                },
                handle,
            )

    def test_report_covers_one_hundred_records(self) -> None:
        suite = ReidentificationSuite(self.tokenizer, k=5, dictionary_path=self.dictionary_path)
        report = suite.run_reid_test(self.records)
        self.assertEqual(report.records, 100)
        self.assertEqual(report.k_threshold, 5)
        self.assertEqual(len(report.payload_digest), 64)
        self.assertEqual(len(report.attacks), 3)
        self.assertEqual(report.successes, 0)
        self.assertEqual(report.verdict, "личность не восстановлена")

    def test_report_contains_no_personal_values(self) -> None:
        suite = ReidentificationSuite(self.tokenizer, dictionary_path=self.dictionary_path)
        report = suite.run_reid_test(self.records)
        markdown = report.to_markdown()
        for record in self.records[:20]:
            self.assertNotIn(str(record["fio"]), markdown)
            self.assertNotIn(str(record["phone"]), markdown)
            self.assertNotIn(str(record["address"]), markdown)

    def test_broken_anonymizer_is_detected(self) -> None:
        """A test that cannot fail proves nothing: a no-op pipeline must be caught."""
        suite = ReidentificationSuite(NoopTokenizer(), dictionary_path=self.dictionary_path)
        report = suite.run_reid_test(self.records)
        self.assertGreater(report.successes, 0)
        self.assertEqual(report.verdict, "ЕСТЬ УСПЕШНАЯ АТАКА")

    def test_k_anonymity_counts_small_groups(self) -> None:
        suite = ReidentificationSuite(self.tokenizer, k=5)
        # Identical quasi-identifiers: one group of 100, nothing below the threshold.
        identical = [
            {**record, "club": "Центральный", "card": "12 мес", "amount": 28000}
            for record in self.records
        ]
        self.assertEqual(suite.k_anonymity_check(identical), 0)
        self.assertGreater(suite.k_anonymity_check(self.records), 0)

    def test_limitations_name_the_residual_risks(self) -> None:
        suite = ReidentificationSuite(self.tokenizer, dictionary_path=self.dictionary_path)
        report = suite.run_reid_test(self.records)
        text = report.to_markdown()
        self.assertIn("Ограничения метода", text)
        self.assertTrue(any("порога k" in item for item in report.limitations))
        self.assertTrue(any("владелец ключей" in item for item in report.limitations))

    def test_log_marker_is_emitted(self) -> None:
        suite = ReidentificationSuite(self.tokenizer, dictionary_path=self.dictionary_path)
        # assertLogs sets the level, so the marker is captured without the test
        # having to reconfigure logging globally.
        with self.assertLogs("ReidentificationSuite", level="INFO") as capture:
            suite.run_reid_test(self.records)
        self.assertTrue(any(LOG_MARKER in message for message in capture.output))

    def test_dictionary_attack_works_without_a_dictionary(self) -> None:
        suite = ReidentificationSuite(self.tokenizer)
        report = suite.run_reid_test(self.records)
        attack = [item for item in report.attacks if item.name == "Связывание по словарю"][0]
        self.assertEqual(attack.attempts, 0)
        self.assertTrue(any("словарь не передавался" in item for item in report.limitations))

    def test_garbage_short_values_are_not_reported(self) -> None:
        """CRM has one-character names; a naive search would flag them all."""
        records = [
            {"client_id": 1, "fio": "|", "phone": "—", "club": "Центральный"},
            {"client_id": 2, "fio": "Иванов Иван Иванович", "phone": "79000000001"},
        ]
        suite = ReidentificationSuite(self.tokenizer)
        report = suite.run_reid_test(records)
        direct = [item for item in report.attacks if item.name == "Прямой поиск значений"][0]
        self.assertEqual(direct.successes, 0, msg="короткие мусорные значения дали ложную тревогу")

    def test_iso_birth_date_is_tokenized_in_the_sample(self) -> None:
        """A real ISO birth date must not survive the run."""
        records = [{"client_id": 1, "fio": "Иванов Сергей", "birth_date": "1985-03-12"}]
        suite = ReidentificationSuite(self.tokenizer)
        report = suite.run_reid_test(records)
        self.assertEqual(report.successes, 0)

    def test_readable_dictionary_would_be_caught(self) -> None:
        """If an export ever wrote readable values, this attack must see it."""
        readable = os.path.join(self._tmp.name, "readable.json")
        with open(readable, "w", encoding="utf-8") as handle:
            json.dump({"T": [self.records[0]["phone"]]}, handle, ensure_ascii=False)
        suite = ReidentificationSuite(self.tokenizer, dictionary_path=readable)
        report = suite.run_reid_test(self.records)
        attack = [item for item in report.attacks if item.name == "Связывание по словарю"][0]
        self.assertGreater(attack.successes, 0)
# END_BLOCK_TEST_REID_SUITE


if __name__ == "__main__":
    unittest.main()
