# FILE: tests/test_name_forms.py
# VERSION: 3.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify M-NAME-FORMS against the expectations of the reference library itself: normalization before comparison, case forms of male and female surnames, given names and patronymics, indeclinable values and the form ceiling.
#   SCOPE: ё to е folding, Терёхин/Терёхина/Артём/Каримова/Абдуллин/Васильевич forms, Ткач by gender, Дюма and Шевченко indeclinable, five forms per gender, missing tables fail loudly.
#   DEPENDS: M-NAME-FORMS
#   LINKS: V-M-NAME-FORMS, Phase-12
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   REFERENCE_EXPECTATIONS - ожидания, снятые с эталонной библиотеки (Petrovich 2.0.1, MIT)
#   NameFormsTests - нормализация, формы по родам, потолок, отсутствие таблиц
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v3.0.0 - Phase-12 шаг 1: ожидания выровнены по эталонной библиотеке, расхождений 0 из 13.
# END_CHANGE_SUMMARY

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.name_forms import (  # noqa: E402
    MAX_FORMS,
    NameForms,
    NameFormsError,
    forms_index,
    name_forms,
    normalize_name,
)

# Ожидания сняты прогоном эталонной библиотеки (Petrovich 2.0.1, лицензия MIT) на тех же
# таблицах: наши формы совпали с ней во всех 13 случаях. Хранятся здесь как контракт:
# если перенос разойдётся с эталоном, тест это покажет.
REFERENCE_EXPECTATIONS = (
    ("Абдуллин", "lastname", "male", ("Абдуллина", "Абдуллину", "Абдуллине")),
    ("Ткач", "lastname", "male", ("Ткача", "Ткачу")),
    ("Каримова", "lastname", "female", ("Каримовой", "Каримову")),
    ("Терёхин", "lastname", "male", ("Терёхина", "Терёхину", "Терёхиным", "Терёхине")),
    ("Терёхина", "lastname", "female", ("Терёхиной", "Терёхину")),
    ("Артём", "firstname", "male", ("Артёма", "Артёму", "Артёмом", "Артёме")),
    ("Дамир", "firstname", "male", ("Дамира", "Дамиру", "Дамире")),
    ("Васильевич", "middlename", "male", ("Васильевича", "Васильевичу", "Васильевиче")),
)


class NameFormsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.forms = NameForms()
        self.count = self.forms.load()

    def keys(self, value: str, kind: str = "lastname", gender: str | None = None) -> set[str]:
        """Return the normalized forms generated for a value."""
        return {normalize_name(form) for form in self.forms.forms(value, kind, gender)}

    def test_rules_are_loaded(self) -> None:
        """Таблицы petrovich-rules (MIT) лежат в репозитории и читаются."""
        self.assertGreater(self.count, 10)
        self.assertIn("lastname", self.forms.kinds)

    def test_normalization_folds_yo_and_case(self) -> None:
        """Нормализация обязательна: без «ё в е» значение «Печёнов» не найдётся."""
        self.assertEqual(normalize_name("  Печёнов  "), "печенов")
        self.assertEqual(normalize_name("«Терёхиной»"), "терехиной")
        self.assertEqual(normalize_name("ТЕРЕХИН,"), "терехин")

    def test_matches_the_reference_library(self) -> None:
        """Перенос совпадает с эталоном: каждая его форма обязана быть среди наших."""
        for value, kind, gender, expected_forms in REFERENCE_EXPECTATIONS:
            generated = self.keys(value, kind, gender)
            for expected in expected_forms:
                with self.subTest(value=value, form=expected):
                    self.assertIn(normalize_name(expected), generated)

    def test_female_surname_form_seen_in_text_is_found(self) -> None:
        """«Терёхиной» из текста находится от значения «Терёхина» из справочника."""
        self.assertIn("терехиной", self.keys("Терёхина"))

    def test_indeclinable_values_stay_single(self) -> None:
        """Дюма и Шевченко не склоняются — и в мужском роде тоже."""
        for value in ("Дюма", "Шевченко"):
            with self.subTest(value=value):
                self.assertEqual(
                    [normalize_name(f) for f in self.forms.forms(value, "lastname", "male")],
                    [normalize_name(value)],
                )

    def test_tkach_by_gender_like_the_reference(self) -> None:
        """Эталон: «Ткач» в женском роде не меняется, в мужском даёт «Ткача»."""
        self.assertIn("ткача", self.keys("Ткач", "lastname", "male"))
        self.assertEqual(
            [normalize_name(f) for f in self.forms.forms("Ткач", "lastname", "female")], ["ткач"]
        )

    def test_hyphenated_surname(self) -> None:
        """Бонч-Бруевич: сегменты обрабатываются по отдельности, дефис сохраняется."""
        generated = self.keys("Бонч-Бруевич", "lastname", "male")
        self.assertTrue(any(form.startswith("бонч") and form.endswith("бруевича") for form in generated))

    def test_indeclinable_segment_stays_in_every_gender(self) -> None:
        """«Бонч» из исключений не склоняется и в женском проходе: «Бонча-Бруевич» не бывает.

        Порт отбрасывал правило-исключение с признаком «androgynous», когда шёл проход по
        женскому роду, и написание получало форму, которой в русском языке нет. Прибор метрик
        считал такие формы пропущенными вхождениями (замер 19.09.2026: 4 пропуска rep_rate),
        а выгрузка складывала их отпечатки в словарь.
        """
        forms = name_forms("Бонч-Бруевич", "lastname")
        self.assertIn("бонч-бруевича", [normalize_name(form) for form in forms])
        for form in forms:
            lowered = normalize_name(form)
            with self.subTest(form=form):
                self.assertNotIn("бонча", lowered, msg="исключение склонено в женском проходе")
                self.assertNotIn(".", form, msg="маркер «сохранить» попал в написание")

    def test_keep_marker_leaves_the_word_alone(self) -> None:
        """Модификатор «сохранить» оставляет слово как есть, а не дописывает точку."""
        for value in ("Дюма", "Дюссар", "Шевченко"):
            with self.subTest(value=value):
                self.assertEqual(
                    [normalize_name(f) for f in name_forms(value, "lastname")],
                    [normalize_name(value)],
                )

    def test_form_ceiling_per_gender(self) -> None:
        """Потолок: по одному роду — не больше пяти падежей плюс исходное написание."""
        for value in ("Иванов", "Терёхин", "Дюма", "Бонч-Бруевич", "Шевченко"):
            for gender in ("male", "female"):
                with self.subTest(value=value, gender=gender):
                    self.assertLessEqual(
                        len(self.forms.forms(value, "lastname", gender)), MAX_FORMS + 1
                    )

    def test_index_maps_forms_to_values(self) -> None:
        index = forms_index(["Терёхина", "Иванов"])
        self.assertEqual(index.get("терехиной"), "Терёхина")
        self.assertEqual(index.get("иванову"), "Иванов")

    def test_missing_tables_fail_loudly(self) -> None:
        """Нет таблиц — ошибка, а не тихое «форма не найдена»."""
        missing = NameForms(Path("/tmp/нет-таких-правил-совсем"))
        with self.assertRaises(NameFormsError) as ctx:
            missing.load()
        self.assertEqual(ctx.exception.code, "rules_missing")


if __name__ == "__main__":
    unittest.main()
