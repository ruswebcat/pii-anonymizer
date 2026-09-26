# FILE: tests/test_dict_noise_report.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Проверить измеритель служебной лексики в классе «имена»: счётчики по категориям по отпечаткам, отсутствие значений клиентов в отчёте, лексику оператора из настроек и снятие остатка через staged → проверка → бэкап → замена.
#   SCOPE: load_digests, in_dictionary, scan по категориям, escaping по стоп-листу, build_lexicon с лексикой оператора, render_report без значений, apply_removal в режиме без изменений и в боевом.
#   DEPENDS: M-DICT, M-DICT-WRITE, M-DETECT-NAME, M-SERVICE-LEXICON
#   LINKS: V-M-DICT-HYGIENE, M-DICT-HYGIENE
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   NoiseFixture - стенд: справочник с настоящими заглушками и служебной лексикой
#   LexiconInCodeTests - клубно-тарифных слов в коде нет, они приходят из настроек
#   NoiseScanTests - счётчики по категориям и распознавание по отпечатку
#   NoiseRenderTests - отчёт без значений клиентов
#   NoiseApplyTests - снятие остатка: staged, проверка, бэкап, замена
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.1.0 - решение владельца 25.09.2026: клубно-тарифная лексика ушла из кода в настройки. Проверка держит это машинно: категории тарифов и услуг в коде нет, а заданная в настройках лексика попадает в замер и в отчёт.
#   PREVIOUS: v1.0.0 - Phase-16: измеритель шума под проверкой. Настоящих персональных данных в тестах нет — только заглушки и служебные слова.
# END_CHANGE_SUMMARY

"""Тесты измерителя служебной лексики (Phase-16, M-DICT-HYGIENE).

Проверяется главное свойство инструмента: он говорит о шуме числами и словами служебной
лексики, не читая и не печатая ни одного значения клиента.
"""

import os
import sys
import unittest
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src import dict_write  # noqa: E402
from src.dict_export import to_keyed_digests  # noqa: E402
from tools.dict_noise_report import (  # noqa: E402
    OWN_TERMS_CATEGORY,
    SERVICE_LEXICON,
    apply_removal,
    build_lexicon,
    in_dictionary,
    load_digests,
    render_report,
    scan,
)

KEY = b"n" * 32
REAL_STUBS = ["Иванов Иван", "Сидоров Пётр", "Токенец", "Тесля", "Testa"]
SERVICE_STUBS = ["Продажи", "Гость", "Запись", "Менеджер", "Бухгалтер", "Фотограф", "Тест", "Новый"]


def ok_runner(argv: Sequence[str]) -> tuple[int, str]:
    """Подстановка прибора: планки выдержаны."""
    return 0, "все планки выдержаны"


class NoiseFixture(unittest.TestCase):
    """Стенд: справочник с заглушками клиентов и служебной лексикой в классе «имена»."""

    def setUp(self) -> None:
        import tempfile

        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.key_path = os.path.join(self.dir.name, "dict.key")
        Path(self.key_path).write_bytes(KEY)
        self.live = dict_write.write_staged(
            to_keyed_digests({"P": REAL_STUBS + SERVICE_STUBS}, KEY),
            os.path.join(self.dir.name, "pii_dict.json"),
        )
        self.keys, self.values = load_digests(self.live, KEY)


#: Слова, которые имеют смысл только для клубной сети: в коде публичной сборки их быть не должно
#: (решение владельца 25.09.2026). Набор нейтральный — это общие слова отрасли, а не бренд сети.
CLUB_WORDS = (
    "тариф",
    "абонемент",
    "фитнес",
    "тренировка",
    "бассейн",
    "сауна",
    "клубная карта",
    "рассрочка",
)


class LexiconInCodeTests(NoiseFixture):
    """Клубно-тарифной лексики в коде нет: она приходит из настроек.

    Проверка машинная, а не декларация: возврат клубного слова в код обязан красить сборку, иначе
    решение владельца живёт только в тексте отчёта.
    """

    def test_club_tariff_category_is_not_in_the_code(self) -> None:
        self.assertNotIn("услуги и тарифы", SERVICE_LEXICON)

    def test_no_club_word_sits_in_the_code_lexicon(self) -> None:
        in_code = {word for words in SERVICE_LEXICON.values() for word in words}
        for word in CLUB_WORDS:
            self.assertNotIn(word, in_code, f"клубное слово вернулось в код: {word}")

    def test_generic_categories_stay_in_the_code(self) -> None:
        """Общие категории остались: они встречаются в карточке любой организации."""
        self.assertEqual(
            {
                "служебные слова и должности",
                "статусы и состояния",
                "технические объекты и поля",
                "шаблоны-заглушки",
                "обрывки и обрубки",
            },
            set(SERVICE_LEXICON),
        )

    def test_default_lexicon_has_no_configured_categories(self) -> None:
        """Умолчание пусто: без настроек замер идёт только по общим категориям."""
        lexicon = build_lexicon()
        self.assertEqual(set(SERVICE_LEXICON), set(lexicon))
        self.assertNotIn(OWN_TERMS_CATEGORY, lexicon)

    def test_configured_lexicon_is_measured_alongside_the_generic_categories(self) -> None:
        lexicon = build_lexicon(
            {"тарифы и клубы": ["Годовой", "Базовый"]}, own_terms=["Пример Спорт"]
        )
        self.assertEqual(("годовой", "базовый"), lexicon["тарифы и клубы"])
        self.assertEqual(("пример спорт",), lexicon[OWN_TERMS_CATEGORY])
        for name in SERVICE_LEXICON:
            self.assertIn(name, lexicon)

    def test_configured_words_are_reported_by_the_scan(self) -> None:
        """Слово из настроек попадает в отчёт: категория оператора видна, а не подразумевается."""
        lexicon = build_lexicon({"тарифы и клубы": ["Продажи", "Тренер"]})
        report = scan(self.live, KEY, lexicon)
        by_name = {item.name: item for item in report.categories}
        self.assertIn("тарифы и клубы", by_name)
        self.assertEqual(1, by_name["тарифы и клубы"].present)
        self.assertTrue(by_name["тарифы и клубы"].words)


class NoiseScanTests(NoiseFixture):
    """Счётчики по категориям и распознавание по отпечатку."""

    def test_dictionary_knows_stub_and_not_absent_word(self) -> None:
        self.assertTrue(in_dictionary(self.keys, KEY, "Продажи"))
        self.assertTrue(in_dictionary(self.keys, KEY, "Иванов Иван"))
        self.assertFalse(in_dictionary(self.keys, KEY, "Расписание"))

    def test_scan_counts_service_words_by_category(self) -> None:
        report = scan(self.live, KEY, {"служебные слова и должности": ("продажи", "гость", "менеджер")})
        self.assertEqual(1, len(report.categories))
        category = report.categories[0]
        self.assertEqual(3, category.checked)
        self.assertEqual(3, category.present)
        self.assertEqual(0, category.escaping)
        self.assertEqual(len(REAL_STUBS) + len(SERVICE_STUBS), report.class_values)

    def test_scan_does_not_dump_the_whole_class(self) -> None:
        # Измеритель отвечает про слова лексики, а не про всё содержимое класса:
        # одно слово из трёх проверенных нашлось — остальные значения класса не считаются шумом.
        report = scan(self.live, KEY, {"служебные слова": ("продажи", "расписание", "скидка")})
        self.assertEqual(3, report.categories[0].checked)
        self.assertEqual(1, report.present_total)
        self.assertEqual(len(REAL_STUBS) + len(SERVICE_STUBS), report.class_values)

    def test_full_lexicon_reports_counters_for_every_category(self) -> None:
        report = scan(self.live, KEY)
        self.assertEqual(len(SERVICE_LEXICON), len(report.categories))
        self.assertGreaterEqual(report.present_total, len(SERVICE_STUBS))

    def test_escaping_column_shows_words_outside_the_stop_list(self) -> None:
        # «Расписание» — служебное слово, которого нет в стоп-листе: именно такие строки
        # колонка «не закрыто стоп-листом» и обязана показывать.
        payload = to_keyed_digests({"P": ["Расписание"]}, KEY)
        path = dict_write.write_staged(payload, os.path.join(self.dir.name, "other.json"))
        report = scan(path, KEY, {"услуги": ("расписание", "продажи")})
        category = report.categories[0]
        self.assertEqual(2, category.checked)
        self.assertEqual(1, category.present)
        self.assertEqual(1, category.escaping)


class NoiseRenderTests(NoiseFixture):
    """Отчёт: числа и служебные слова, ни одного значения клиента."""

    def test_report_has_numbers_and_no_client_values(self) -> None:
        report = scan(self.live, KEY)
        text = render_report(report)
        self.assertIn("Служебная лексика в классе «имена»", text)
        self.assertIn(str(report.present_total), text)
        for value in REAL_STUBS:
            self.assertNotIn(value, text, value)

    def test_report_dict_is_json_ready(self) -> None:
        import json

        payload = scan(self.live, KEY).to_dict()
        json.dumps(payload, ensure_ascii=False)
        self.assertIn("categories", payload)


class NoiseApplyTests(NoiseFixture):
    """Снятие остатка: сначала staged и прибор, потом замена."""

    def test_dry_run_removal_changes_nothing(self) -> None:
        before = Path(self.live).read_bytes()
        report = scan(self.live, KEY, {"служебные слова": ("продажи", "гость")})
        outcome = apply_removal(report, KEY, self.key_path, dry_run=True)
        self.assertEqual(2, outcome["removed"])
        self.assertEqual("dry_run", outcome["reason"])
        self.assertEqual(before, Path(self.live).read_bytes())

    def test_removal_installs_clean_dictionary_with_backup(self) -> None:
        report = scan(self.live, KEY, {"служебные слова": ("продажи", "гость")})
        outcome = apply_removal(report, KEY, self.key_path, runner=ok_runner, dry_run=False)
        self.assertTrue(outcome["apply"]["applied"])
        self.assertTrue(os.path.exists(outcome["apply"]["backup_path"]))
        self.assertEqual(len(REAL_STUBS) + len(SERVICE_STUBS) - 2, outcome["values_after"])
        keys, _ = load_digests(self.live, KEY)
        self.assertFalse(in_dictionary(keys, KEY, "Продажи"))
        self.assertTrue(in_dictionary(keys, KEY, "Токенец"))
        after = scan(self.live, KEY, {"служебные слова": ("продажи", "гость")})
        self.assertEqual(0, after.present_total)

    def test_removal_without_service_words_does_nothing(self) -> None:
        report = scan(self.live, KEY, {"услуги": ("расписание",)})
        outcome = apply_removal(report, KEY, self.key_path, runner=ok_runner)
        self.assertEqual("nothing_to_remove", outcome["reason"])


if __name__ == "__main__":
    unittest.main()
