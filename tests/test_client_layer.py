# FILE: tests/test_client_layer.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify M-DICT: name fields only, form-based classification (a phone in the surname field becomes class T), service objects and placeholders dropped with counters, deduplication and the diff against the open list.
#   SCOPE: service objects, placeholders, phone reclassification, other fields ignored, deduplication and sorting, diff keeping only unknown values, counters free of values.
#   DEPENDS: M-DICT
#   LINKS: V-M-DICT, Phase-12
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   ClientLayerTests - разбор полей, счётчики, diff
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-12 шаг 3: слой строится только из полей ФИО, по форме значения.
# END_CHANGE_SUMMARY

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.client_layer import (  # noqa: E402
    CLASS_NAME,
    CLASS_PHONE,
    build_client_layer,
    build_forms_index,
    classify_field,
    diff_against_open,
)

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()


class ClientLayerTests(unittest.TestCase):
    def test_phone_in_surname_field_is_reclassified_not_dropped(self) -> None:
        """Телефон, ошибочно записанный в фамилию, — это данные клиента, а не мусор."""
        cls, cleaned, reason = classify_field("+7 (900) 111-22-33")
        self.assertEqual(cls, CLASS_PHONE)
        self.assertEqual(reason, "")

    def test_service_object_is_dropped(self) -> None:
        """Служебный объект CRM — не человек."""
        for value in ("CRM", "База", "Admin", "Общая База Клиентов"):
            with self.subTest(value=value):
                cls, _cleaned, reason = classify_field(value)
                self.assertIsNone(cls)
                self.assertEqual(reason, "service_object")

    def test_placeholder_is_dropped(self) -> None:
        """Заглушка вместо значения — не данные («|», «-», «???»)."""
        for value in ("|", "-", "???"):
            with self.subTest(value=value):
                cls, _cleaned, reason = classify_field(value)
                self.assertIsNone(cls)
                self.assertEqual(reason, "placeholder")

    def test_empty_field_is_dropped(self) -> None:
        """Пустое поле — тоже не значение, но причина отказа другая."""
        cls, _cleaned, reason = classify_field("   ")
        self.assertIsNone(cls)
        self.assertEqual(reason, "empty")

    def test_build_uses_name_fields_only(self) -> None:
        """Поля карточки, не относящиеся к ФИО, в слой не попадают."""
        layer, counters = build_client_layer(
            [{"surname": "Терёхин", "name": "Артём", "manager": "CRM", "phone": "79001112233"}]
        )
        self.assertEqual(layer[CLASS_NAME], ["артем", "терехин"])
        self.assertEqual(counters["records"], 1)
        self.assertNotIn("phone", str(counters))

    def test_counters_do_not_carry_values(self) -> None:
        """Счётчики описывают отброшенное числом, а не содержимым."""
        _layer, counters = build_client_layer(
            [{"surname": "CRM"}, {"name": "|"}, {"name": "Тестовочка"}]
        )
        self.assertEqual(counters.get("dropped_service_object"), 1)
        self.assertEqual(counters.get("dropped_placeholder"), 1)
        for key in counters:
            self.assertNotIn("тестовочка", key.lower())

    def test_values_are_deduplicated_and_sorted(self) -> None:
        layer, _counters = build_client_layer(
            [{"surname": "Терёхин"}, {"surname": "терехин"}, {"surname": "Сахнов"}]
        )
        self.assertEqual(layer[CLASS_NAME], ["сахнов", "терехин"])

    def test_diff_keeps_only_unknown_values(self) -> None:
        """Diff: в клиентском слое остаётся только то, чего нет в открытом списке."""
        layer = {CLASS_NAME: ["терехин", "токенец"]}
        out, counters = diff_against_open(layer, ["терехин", "иванов"])
        self.assertEqual(out[CLASS_NAME], ["токенец"])
        self.assertEqual(counters["covered_by_open"], 1)
        self.assertEqual(counters["kept"], 1)


class ClientFormsIndexTests(unittest.TestCase):
    """Индекс форм клиентского слоя: форма → значение (M-NAME-IDENTITY, шаг 2 фазы)."""

    def test_declined_form_points_to_its_value(self) -> None:
        _exact, forms, counters = build_forms_index(["Терёхина"])
        # Ключи индекса — сложенные («ё»→«е»), как и ключи идентичности.
        self.assertEqual(forms["терехиной"], "Терёхина")
        self.assertEqual(forms["терехину"], "Терёхина")
        self.assertGreaterEqual(counters["forms"], 2)

    def test_exact_spelling_is_kept_apart_from_forms(self) -> None:
        exact, forms, _counters = build_forms_index(["Иванов"])
        self.assertEqual(exact["иванов"], "Иванов")
        self.assertNotIn("иванов", forms)

    def test_ambiguous_form_is_dropped_not_guessed(self) -> None:
        """«Иванову» порождается и «Иванов», и «Иванова» — в индекс не попадает."""
        _exact, forms, counters = build_forms_index(["Иванов", "Иванова"])
        self.assertNotIn("иванову", forms)
        self.assertGreaterEqual(counters["ambiguous"], 1)

    def test_latin_value_stays_exact_only(self) -> None:
        exact, forms, counters = build_forms_index(["Terekhina"])
        self.assertEqual(exact["terekhina"], "Terekhina")
        self.assertFalse(forms)
        self.assertEqual(counters["latin_exact_only"], 1)

    def test_counters_carry_numbers_only(self) -> None:
        _exact, _forms, counters = build_forms_index(["Терёхина"])
        for key, value in counters.items():
            self.assertIsInstance(key, str)
            self.assertIsInstance(value, int, msg=key)
        self.assertNotIn("терехина", str(counters).lower())

if __name__ == "__main__":
    unittest.main()
