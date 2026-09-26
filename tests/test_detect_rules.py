# FILE: tests/test_detect_rules.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-DETECT-RULES contract: formats and context are detected, report dates and amounts are not, and tabular headers force tokenization.
#   SCOPE: phone forms, e-mail, documents, address, birth-date context gating, client identifiers, tabular detection, overlap merging, false-positive guards.
#   DEPENDS: M-DETECT-RULES
#   LINKS: V-M-DETECT-RULES, M-DETECT-RULES
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   RuleDetectorTests - unittest case set for detect_rules and detect_tabular
#   classes_of - helper collecting classes from a match list
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.1.0 - шапкой таблицы считается только строка коротких подписей; абзац с перечислением полей («ФИО, телефон, почта, адрес, дата рождения») больше не обезличивает соседние строки.
#   PREVIOUS: v1.0.0 - Phase-1 M-DETECT-RULES verification, including the zero-false-positive assertions from the verification plan.
# END_CHANGE_SUMMARY

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detect_rules import PiiMatch, detect_rules, detect_tabular, merge_matches  # noqa: E402
from tests import harness  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()


def classes_of(matches: list[PiiMatch]) -> set[str]:
    return {match.cls for match in matches}


class RuleDetectorTests(unittest.TestCase):
    def test_phone_forms_detected(self) -> None:
        for text in [
            "Телефон клиента: 79000000001",
            "тел. +7 900 000-00-01",
            "8 (900) 000 00 01 — основной",
        ]:
            matches = detect_rules(text)
            phones = [m for m in matches if m.cls == "T"]
            self.assertEqual(len(phones), 1, msg=text)
            self.assertEqual(phones[0].normalized, "79000000001")

    def test_amounts_are_not_phones(self) -> None:
        text = "Сумма 28000 руб, доплата 15500, скидка 3000"
        self.assertEqual([m for m in detect_rules(text) if m.cls == "T"], [])

    def test_report_date_is_not_a_birth_date(self) -> None:
        text = "Отчёт за период 01.09.2026 — 15.09.2026, продаж 120"
        self.assertEqual([m for m in detect_rules(text) if m.cls == "D"], [])

    def test_birth_date_requires_context_and_keeps_year_open(self) -> None:
        text = "Дата рождения: 12.03.1985, клуб Центральный"
        matches = [m for m in detect_rules(text) if m.cls == "D"]
        self.assertEqual(len(matches), 1)
        span = text[matches[0].start : matches[0].end]
        self.assertEqual(span, "12.03")
        self.assertNotIn("1985", span)
        self.assertEqual(matches[0].open_suffix, ".1985")

    def test_email_detected(self) -> None:
        matches = [m for m in detect_rules("почта: Client-7@Example.RU") if m.cls == "E"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].normalized, "client-7@example.ru")

    def test_documents_detected(self) -> None:
        text = "СНИЛС 123-456-789 00"
        matches = [m for m in detect_rules(text) if m.cls == "I"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].normalized, "12345678900")

    def test_address_detected_with_house_and_flat(self) -> None:
        text = "Клиент живёт: ул. Заводская, д. 19А, кв. 5"
        matches = [m for m in detect_rules(text) if m.cls == "A"]
        self.assertEqual(len(matches), 1)
        self.assertIn("19А", text[matches[0].start : matches[0].end])
        self.assertIn("кв", text[matches[0].start : matches[0].end])

    def test_client_identifier_detected(self) -> None:
        for text in ["client_id=35209", "client_id: 35209", "№ карты 35209"]:
            matches = [m for m in detect_rules(text) if m.cls == "C"]
            self.assertEqual(len(matches), 1, msg=text)
            self.assertEqual(matches[0].normalized, "35209")

    def test_card_type_column_is_not_treated_as_identifier(self) -> None:
        text = "Карта,Сумма\n12 мес,28000"
        self.assertEqual(detect_tabular(text), [])

    def test_tabular_detection_uses_headers(self) -> None:
        records = harness.sample_clients(3)
        csv_text = harness.synthetic_csv(records)
        matches = detect_tabular(csv_text)
        self.assertTrue({"P", "T", "E", "D", "A", "C"} <= classes_of(matches))
        self.assertIn(records[0]["fio"], csv_text)

    def test_tabular_detection_leaves_birth_year_open(self) -> None:
        csv_text = "ФИО,Телефон,Дата рождения\nИванов Сергей,79000000001,12.03.1985"
        matches = detect_tabular(csv_text)
        covered = "".join(csv_text[m.start : m.end] for m in matches)
        self.assertIn("12.03", covered)
        self.assertNotIn("1985", covered)

    def test_tabular_ignores_club_and_card_columns(self) -> None:
        csv_text = "ФИО,Клуб,Карта,Сумма\nИванов Сергей,Квартальный,12 мес,28000"
        matches = detect_tabular(csv_text)
        self.assertEqual(classes_of(matches), {"P"})

    def test_a_prose_line_is_not_a_header_row(self) -> None:
        """Абзац с перечислением подписей полей — не шапка таблицы (находка 26.09.2026).

        В строке системного промпта стоят «телефон», «почта», «адрес» и «дата рождения» через
        запятую — этого хватало, чтобы строка считалась заголовком, а каждая следующая строка
        блока — данными: слово «адрес» заменялось кодом класса «адрес» (161 замена в одном
        блоке, где персональных данных нет вовсе). Имя колонки — короткая подпись, абзац — нет.
        """
        line = (
            "Персональные данные клиентов (ФИО, телефон, почта, адрес, дата рождения) "
            "приходят в коде и восстанавливаются доверенной границей."
        )
        self.assertEqual(detect_tabular(f"{line}\n{line}\n"), [])

    def test_a_short_header_still_maps_columns(self) -> None:
        """Положительный контроль: короткая шапка по-прежнему задаёт классы колонок."""
        csv_text = "client_id,ФИО,Телефон,Дата рождения,Адрес\n35209,Иванов Сергей,79000000001,12.03.1985,ул. Садовая 3а"
        self.assertTrue({"C", "P", "T", "D", "A"} <= classes_of(detect_tabular(csv_text)))

    def test_merge_matches_prefers_longest_span(self) -> None:
        short = PiiMatch(0, 5, "T", "79372", "79372")
        long = PiiMatch(0, 11, "C", "79000000001", "79000000001")
        merged = merge_matches([short, long])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].cls, "C")

    def test_merge_matches_keeps_disjoint_spans(self) -> None:
        first = PiiMatch(0, 5, "C", "35209", "35209")
        second = PiiMatch(10, 15, "C", "35210", "35210")
        self.assertEqual(len(merge_matches([first, second])), 2)

    def test_no_matches_for_plain_report_text(self) -> None:
        text = "Продажи сентября: 214 карт, выручка 7 900 000 руб, конверсия 15%"
        self.assertEqual(detect_rules(text), [])

    def test_json_payload_with_birth_key_does_not_tokenize_report_dates(self) -> None:
        """One long JSON line must not turn every date into a birth date."""
        payload_line = (
            '{"messages": [{"role": "tool", "content": "{\\"Дата рождения\\": \\"12.03.1985\\", '
            '\\"period\\": \\"01.09.2026 - 15.09.2026\\"}"}]}'
        )
        matches = [m for m in detect_rules(payload_line) if m.cls == "D"]
        covered = [payload_line[m.start : m.end] for m in matches]
        self.assertEqual(covered, ["12.03"])
        self.assertNotIn("01.09", "".join(covered))
        self.assertNotIn("15.09", "".join(covered))

    def test_iso_birth_date_with_context_is_tokenized_by_month_day(self) -> None:
        """The year stays open, so only the trailing month-day is taken."""
        text = 'Клиент, дата рождения: "1985-03-12", клуб Центральный'
        matches = [m for m in detect_rules(text) if m.cls == "D"]
        self.assertEqual([text[m.start : m.end] for m in matches], ["03-12"])
        self.assertEqual(matches[0].normalized, "12.03")

    def test_unix_timestamp_is_not_a_document(self) -> None:
        """A 10-digit epoch in created_at blocked every real selection (15.09.2026)."""
        text = '{"created_at": 1789502911, "updated_at": 1789503000, "club": "Центральный"}'
        self.assertEqual([m for m in detect_rules(text) if m.cls == "I"], [])

    def test_millisecond_timestamp_is_not_a_document(self) -> None:
        text = '{"created_at_ms": 1789502911123}'
        self.assertEqual([m for m in detect_rules(text) if m.cls == "I"], [])

    def test_real_documents_are_still_detected(self) -> None:
        """Cutting false positives must not blind the detector to real documents."""
        cases = {
            "СНИЛС 123-456-789 00 выдан": "123-456-789 00",
            "паспорт 45 06 123456": "45 06 123456",
            "ИНН 500100732259": "500100732259",
        }
        for text, expected in cases.items():
            matches = [m for m in detect_rules(text) if m.cls == "I"]
            self.assertTrue(matches, msg=f"документ не найден: {text}")
            self.assertIn(expected, matches[0].raw)

    def test_bare_twelve_digit_number_is_not_a_document(self) -> None:
        text = '{"some_counter": 123456789012}'
        self.assertEqual([m for m in detect_rules(text) if m.cls == "I"], [])

    def test_iso_date_without_context_is_left_alone(self) -> None:
        text = 'Отчёт за период "2026-09-01" — "2026-09-15", продаж 120'
        self.assertEqual([m for m in detect_rules(text) if m.cls == "D"], [])


if __name__ == "__main__":
    unittest.main()
