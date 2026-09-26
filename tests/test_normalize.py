# FILE: tests/test_normalize.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-NORM contract: equivalent spellings collapse to one canonical string and the birth year stays open.
#   SCOPE: phone forms, name forms, e-mail, address, documents, client ids, birth date split, unsupported class, idempotence.
#   DEPENDS: M-NORM
#   LINKS: V-M-NORM, M-NORM
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   NormalizeTests - unittest case set for normalize and split_birth_date
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-1 M-NORM verification.
# END_CHANGE_SUMMARY

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.normalize import NormalizeError, normalize, split_birth_date  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()


class NormalizeTests(unittest.TestCase):
    def test_phone_forms_collapse_to_one_canonical_value(self) -> None:
        forms = [
            "79000000001",
            "+7 900 000-00-01",
            "8 (900) 000 00 01",
            "7-900-000-0001",
            "89000000001",
        ]
        canonical = {normalize("T", value) for value in forms}
        self.assertEqual(canonical, {"79000000001"})

    def test_ten_digit_phone_gets_country_code(self) -> None:
        self.assertEqual(normalize("T", "9000000001"), "79000000001")

    def test_bad_phone_is_rejected(self) -> None:
        with self.assertRaises(NormalizeError) as ctx:
            normalize("T", "123")
        self.assertEqual(ctx.exception.code, "NORM_BAD_PHONE")

    def test_name_forms_collapse(self) -> None:
        forms = ["Иванов Иван Иванович", "иванов  иван иванович", "ИВАНОВ ИВАН ИВАНОВИЧ"]
        canonical = {normalize("P", value) for value in forms}
        self.assertEqual(canonical, {"иванов иван иванович"})

    def test_initial_form_collapses_to_name_key(self) -> None:
        self.assertEqual(normalize("P", "Иванов С.В."), "иванов с в")

    def test_email_lowercased(self) -> None:
        self.assertEqual(normalize("E", "  Ivan.Petrov@Example.RU "), "ivan.petrov@example.ru")

    def test_bad_email_is_rejected(self) -> None:
        with self.assertRaises(NormalizeError):
            normalize("E", "not-an-email")

    def test_address_collapses(self) -> None:
        self.assertEqual(
            normalize("A", "ул. Заводская, д. 19А, кв. 5"),
            normalize("A", "ул Заводская д 19А кв 5"),
        )

    def test_document_digits_only(self) -> None:
        self.assertEqual(normalize("I", "123-456-789 00"), "12345678900")

    def test_client_id_strips_leading_zeros(self) -> None:
        self.assertEqual(normalize("C", "00035209"), "35209")

    def test_birth_date_splits_day_month_from_open_year(self) -> None:
        self.assertEqual(split_birth_date("12.03.1985"), ("12.03", "1985"))
        self.assertEqual(split_birth_date("1.7.1990"), ("01.07", "1990"))

    def test_birth_date_short_year_is_expanded(self) -> None:
        self.assertEqual(split_birth_date("05.05.85"), ("05.05", "1985"))
        self.assertEqual(split_birth_date("05.05.12"), ("05.05", "2012"))

    def test_iso_birth_date_is_supported(self) -> None:
        """CRM returns ISO dates; an unsupported format means "not anonymized"."""
        self.assertEqual(split_birth_date("1985-03-12"), ("12.03", "1985"))
        with self.assertRaises(NormalizeError):
            split_birth_date("1985-13-40")

    def test_bad_birth_date_is_rejected(self) -> None:
        with self.assertRaises(NormalizeError) as ctx:
            split_birth_date("32.13.1985")
        self.assertEqual(ctx.exception.code, "NORM_BAD_DATE")

    def test_unsupported_class_is_rejected(self) -> None:
        with self.assertRaises(NormalizeError) as ctx:
            normalize("Z", "value")
        self.assertEqual(ctx.exception.code, "NORM_UNSUPPORTED_CLASS")

    def test_normalization_is_idempotent(self) -> None:
        for cls, value in [
            ("T", "8 (900) 000 00 01"),
            ("P", "Иванов Иван Иванович"),
            ("E", "Ivan@Example.ru"),
            ("A", "ул. Мира, д. 85"),
            ("I", "123-456-789 00"),
            ("C", "00035209"),
        ]:
            once = normalize(cls, value)
            self.assertEqual(once, normalize(cls, once), msg=f"class {cls} not idempotent")


if __name__ == "__main__":
    unittest.main()
