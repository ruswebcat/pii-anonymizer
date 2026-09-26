# FILE: tests/test_detect_ner.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-NER contract: pluggable backends work, stopwords are filtered, a missing backend degrades to a silent no-op, and a crashing backend never breaks the pipeline.
#   SCOPE: unavailable backend, injected backend, stopword rejection, backend failure recovery, status reporting.
#   DEPENDS: src/detect_ner.py
#   LINKS: M-NER, V-M-NER, tests/test_detect_ner.py
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   FakeBackend - backend double returning fixed spans
#   NerDetectorTests - unittest suite for NerDetector
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-2 checks for the optional free-text layer.
# END_CHANGE_SUMMARY

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detect_ner import NerDetector  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()

# START_BLOCK_TEST_NER
class FakeBackend:
    """Minimal backend double: reports fixed spans."""

    name = "fake"

    def __init__(self, spans=None, fail=False) -> None:
        self._spans = spans or []
        self._fail = fail

    def detect(self, text: str):
        if self._fail:
            raise RuntimeError("backend exploded")
        return [
            {"start": start, "end": end, "text": text[start:end]}
            for start, end in self._spans
            if start < len(text)
        ]


class NerDetectorTests(unittest.TestCase):
    def test_missing_backend_degrades_to_noop(self) -> None:
        detector = NerDetector("none")
        self.assertFalse(detector.available)
        self.assertEqual(detector.detect_names("пришёл Иванов Сергей"), [])
        status = detector.ner_status()
        self.assertFalse(status["available"])
        self.assertEqual(status["backend"], "none")

    def test_auto_mode_without_packages_is_unavailable(self) -> None:
        detector = NerDetector("auto")
        self.assertIn(detector.load_backend(), ("morphology", "neural", "none"))
        self.assertEqual(detector.ner_status()["backend"], detector.load_backend())

    def test_backend_spans_become_class_p_matches(self) -> None:
        text = "Звонили Иванов Иван Иванович, ждёт карту"
        start = text.index("Иванов")
        end = start + len("Иванов Иван Иванович")
        detector = NerDetector("morphology", backend_factory=lambda: FakeBackend([(start, end)]))
        matches = detector.detect_names(text)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].cls, "P")
        self.assertEqual(matches[0].normalized, "иванов иван иванович")

    def test_stopwords_from_backend_are_rejected(self) -> None:
        text = "Клуб Центральный, тариф Годовой"
        # Смещения считаются от текста: слова собственной лексики длятся столько, сколько их длина.
        spans = [
            (text.index(word), text.index(word) + len(word))
            for word in ("Центральный", "Годовой")
        ]
        detector = NerDetector("morphology", backend_factory=lambda: FakeBackend(spans))
        self.assertEqual(detector.detect_names(text), [])

    def test_backend_failure_is_contained(self) -> None:
        detector = NerDetector("morphology", backend_factory=lambda: FakeBackend(fail=True))
        self.assertEqual(detector.detect_names("Иванов Сергей"), [])
        status = detector.ner_status()
        self.assertFalse(status["available"])
        self.assertTrue(status["errors"])

    def test_empty_text_returns_nothing(self) -> None:
        detector = NerDetector("morphology", backend_factory=lambda: FakeBackend([(0, 3)]))
        self.assertEqual(detector.detect_names(""), [])
# END_BLOCK_TEST_NER


# START_BLOCK_TEST_NER_INTEGRATION
def _morphology_available() -> bool:
    """Return True when a real morphology backend is installed."""
    for module_name in ("pymorphy3", "pymorphy2"):
        try:
            __import__(module_name)
            return True
        except ImportError:
            continue
    return False


@unittest.skipUnless(_morphology_available(), "pymorphy is not installed on this host")
class MorphologyIntegrationTests(unittest.TestCase):
    """Checks against the real backend, skipped when it is absent.

    These are the checks that justify the module's existence: a single declined
    surname ("Ивановой") is invisible to shape heuristics, while the morphology
    backend recognizes it from the grammatical tag.
    """

    def test_declined_single_surname_is_found_where_shapes_fail(self) -> None:
        from src.detect_name import NameDetector

        text = "Звонили Ивановой, отказалась продлевать. Перезвонить Заглушкову."
        self.assertEqual(NameDetector().detect_names(text), [])
        detector = NerDetector("morphology")
        self.assertTrue(detector.available)
        found = [text[match.start : match.end] for match in detector.detect_names(text)]
        self.assertIn("Ивановой", found)
        self.assertIn("Заглушкову", found)

    def test_club_names_are_filtered_by_stopwords(self) -> None:
        detector = NerDetector("morphology")
        self.assertEqual(detector.detect_names("Клуб Центральный открыт"), [])

    def test_backend_is_fast_after_the_first_load(self) -> None:
        import time

        detector = NerDetector("morphology")
        detector.detect_names("Звонили Ивановой")  # прогреваем модель
        started = time.perf_counter()
        detector.detect_names("Отчёт по продажам за период, клуб Центральный, 120 карт")
        self.assertLess(time.perf_counter() - started, 0.5)
# END_BLOCK_TEST_NER_INTEGRATION


if __name__ == "__main__":
    unittest.main()
