# FILE: tests/test_detect_name.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-DETECT-NAME contract: names of every real-world shape are found and club, city and service words never become class P.
#   SCOPE: full name, declined forms, initials, all caps, dictionary hits, stopword rejection, merge behaviour.
#   DEPENDS: M-DETECT-NAME, M-NORM
#   LINKS: V-M-DETECT-NAME, M-DETECT-NAME
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   NameDetectorTests - unittest case set for NameDetector
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-1 M-DETECT-NAME verification.
# END_CHANGE_SUMMARY

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detect_name import NameDetector  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()


class NameDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = NameDetector()

    def test_full_name_detected(self) -> None:
        text = "Клиент Иванов Иван Иванович купил годовую карту"
        matches = self.detector.detect_names(text)
        self.assertEqual(len(matches), 1)
        self.assertEqual(text[matches[0].start : matches[0].end], "Иванов Иван Иванович")
        self.assertEqual(matches[0].normalized, "иванов иван иванович")

    def test_declined_surname_detected(self) -> None:
        for text, expected in [
            ("Звонили Ивановой Ольге", "Ивановой Ольге"),
            ("Отдали карту Заглушкову Дмитрию", "Заглушкову Дмитрию"),
            ("Написала Скрытницова Анна", "Скрытницова Анна"),
        ]:
            matches = self.detector.detect_names(text)
            self.assertEqual(len(matches), 1, msg=text)
            self.assertEqual(text[matches[0].start : matches[0].end], expected)

    def test_initials_detected(self) -> None:
        matches = self.detector.detect_names("Запись на 10:00: Иванов С.В., Центральный")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].cls, "P")

    def test_uppercase_name_detected(self) -> None:
        matches = self.detector.detect_names("ЕРМАКОВ СЕРГЕЙ — карта 12 мес")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].cls, "P")

    def test_dictionary_hit_without_surname_shape(self) -> None:
        detector = NameDetector({"P": ["Петруш"]})
        matches = detector.detect_names("Анкета Петруш Татьяна, стажёр")
        self.assertTrue(matches)
        self.assertEqual(matches[0].cls, "P")

    def test_club_and_city_words_never_become_names(self) -> None:
        for text in [
            "Пример Спорт Центральный — центр города",
            "ПРИМЕР СПОРТ БАЗОВЫЙ",
            "Примерск, Квартальный, Базовый, Центральный",
            "ИТОГО ПО ПРОДАЖАМ",
            "Клуб Годовой, тариф Годовой, акция сентября",
        ]:
            matches = self.detector.detect_names(text)
            self.assertEqual(matches, [], msg=text)

    def test_service_headers_not_names(self) -> None:
        text = "ФИО, Телефон, Дата рождения, Карта"
        self.assertEqual(self.detector.detect_names(text), [])

    def test_multiple_names_detected(self) -> None:
        text = "Иванов Сергей купил карту, Печёнова Ольга продлила"
        matches = self.detector.detect_names(text)
        self.assertEqual(len(matches), 2)

    def test_empty_text_returns_nothing(self) -> None:
        self.assertEqual(self.detector.detect_names(""), [])

    def test_known_names_reads_dictionary_object(self) -> None:
        class FakeDictionary:
            def values_for(self, cls: str) -> list[str]:
                return ["Иванов"] if cls == "P" else []

        detector = NameDetector(FakeDictionary())
        self.assertEqual(detector.known_names(), ["Иванов"])
        self.assertTrue(detector.detect_names("пришёл Иванов, без имени"))

    # START_BLOCK_DICTIONARY_PERFORMANCE
    def test_large_dictionary_stays_fast(self) -> None:
        """A 20k-client dictionary must not make the detector crawl.

        Dictionary matching is candidate-driven precisely because the real export
        holds tens of thousands of clients; a per-name regex scan would take
        minutes per request. This is the regression guard for that design.
        """
        import time

        names = [f"Тестовый{i} Клиент{i}" for i in range(20000)]
        dictionary = {"P": names}
        detector = NameDetector(dictionary)
        filler = "Отчёт по продажам за период, клуб Центральный, 120 карт. " * 400
        text = filler + " Звонили Иванов Иван Иванович, ждёт карту"
        started = time.perf_counter()
        matches = detector.detect_names(text)
        elapsed = time.perf_counter() - started
        self.assertTrue(matches)
        self.assertLess(elapsed, 2.0, msg=f"detect_names took {elapsed:.2f}s")
    # END_BLOCK_DICTIONARY_PERFORMANCE


class ClientFormAttributionTests(unittest.TestCase):
    """Склонённое значение клиентского слоя находится и относится к своей персоне."""

    def test_declined_client_value_is_found_and_attributed(self) -> None:
        detector = NameDetector({"P": ["Терёхина"]})
        matches = detector.detect_names("Анкета: Терёхиной 79001112233")
        self.assertTrue(matches, "склонённая форма клиента обязана находиться")
        self.assertEqual(matches[0].identity, "терехина")

    def test_generated_form_is_recognised_and_attributed(self) -> None:
        detector = NameDetector({"P": ["Иванов"]})
        matches = detector.detect_names("Анкета: Ивановым 79001112233")
        self.assertTrue(matches)
        self.assertEqual(matches[0].identity, "иванов")

    def test_two_clients_keep_two_identities(self) -> None:
        """«Иванов» и «Иванова» — два клиента, и падеж не смешивает их."""
        detector = NameDetector({"P": ["Иванов", "Иванова"]})
        first = detector.detect_names("Анкета: Иванов")
        second = detector.detect_names("Анкета: Иванова")
        self.assertEqual(first[0].identity, "иванов")
        self.assertEqual(second[0].identity, "иванова")
        self.assertNotEqual(first[0].identity, second[0].identity)

    def test_identity_for_confirmed_value_only(self) -> None:
        detector = NameDetector({"P": ["Терёхина"]})
        self.assertEqual(detector.identity_for("Терёхиной"), "терехина")
        self.assertIsNone(detector.identity_for("Стаб"))

    def test_identity_counters_carry_no_values(self) -> None:
        detector = NameDetector({"P": ["Иванов"]})
        detector.detect_names("Анкета: Иванова")
        counters = detector.identity_counters()
        self.assertGreaterEqual(counters["client_form"], 1)
        self.assertNotIn("иванов", str(counters).lower())

    def test_multiword_value_keeps_its_own_identity(self) -> None:
        detector = NameDetector({"P": ["Иванов Иван Иванович"]})
        matches = detector.detect_names("Анкета: Иванов Иван Иванович")
        self.assertTrue(matches)
        self.assertEqual(matches[0].identity, "иванов иван иванович")

if __name__ == "__main__":
    unittest.main()

class StandaloneNameGuardTests(unittest.TestCase):
    """Заслон от засорённого словаря (находка 16.09.2026).

    Выгрузка словаря содержит не только фамилии, но и обычные слова: «Для», «Карта»,
    «Клиент», «Клуб», «Тренер», «Сайт», «Пример». Без заслона «Для рекламы» превращалось
    в «zPXXXXXXX рекламы», «ПримерСпорт» ломался на код и обрывок, а обрывок валидатор
    принимал за остаточные ПД и блокировал весь запрос.
    """

    def setUp(self) -> None:
        self.detector = NameDetector(
            {"P": ["Для", "Карта", "Клиент", "Клуб", "Тренер", "Сайт", "Пример", "Спорт", "Иванов", "Иванов Иван Иванович"]}
        )

    def test_common_words_are_not_names(self) -> None:
        for text in ("Для рекламы", "Карта клиента", "Клуб Пример", "Сайт сети"):
            self.assertEqual(self.detector.detect_names(text), [], msg=text)

    def test_camel_case_word_is_not_split_into_names(self) -> None:
        """«Пример» и «Спорт» внутри «ПримерСпорт» — части слова, а не имена."""
        self.assertEqual(self.detector.detect_names("папка _ПримерСпорт общие"), [])

    def test_real_surname_is_still_detected(self) -> None:
        matches = self.detector.detect_names("клиент Иванов Иван Иванович")
        self.assertTrue(matches, msg="ФИО обязано распознаваться")
        self.assertTrue(any("Иванов" in match.raw for match in matches))

    def test_single_surname_is_still_detected(self) -> None:
        """Однофамильное совпадение проходит: морфология видит фамилию."""
        matches = self.detector.detect_names("Иванов, карта 12 мес")
        self.assertTrue(matches, msg="фамилия обязана распознаваться вне слова")

    def test_name_glued_into_a_word_is_left_alone(self) -> None:
        self.assertEqual(self.detector.detect_names("отчётИванов"), [])


if __name__ == "__main__":
    unittest.main()
