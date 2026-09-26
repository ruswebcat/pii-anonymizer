# FILE: tests/test_dict_write.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Проверить путь записи справочника: добавление и удаление значений отпечатками, staged с правами 0600, проверка прибором до замены, бэкап, атомарная замена и неизменность живого файла при любом сбое.
#   SCOPE: schema guard, remove_values с формо-отпечатками, add_values с формами и спорными формами, has_value, retotal, write_staged, check_staged через подстановку, backup_live, install_staged, apply в успехе и в отказах.
#   DEPENDS: M-DICT-WRITE, M-DICT, M-DICT-EXPORT
#   LINKS: V-M-DICT-WRITE, M-INCIDENT-TRAINER, M-DICT-HYGIENE
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   DictWriteFixture - общий стенд: справочник, ключ, каталог
#   DictValueTests - добавление, удаление и проверка присутствия значения
#   DictStagedTests - staged-файл и его права
#   DictCheckTests - проверка прибором и её подстановка
#   DictApplyTests - бэкап, замена и fail-closed поведение
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-16: путь записи справочника под проверкой. Все значения — заглушки (Иванов, Сидоров), настоящих персональных данных в тестах нет.
# END_CHANGE_SUMMARY

"""Тесты записи клиентского справочника (Phase-16, M-DICT-WRITE).

Значения в тестах — заглушки. Проверяется не «структура файла», а поведение при отказах:
провал прибора, сбой проверки и сбой записи обязаны оставить живой справочник неизменным.
"""

import json
import os
import stat
import sys
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src import dict_write  # noqa: E402
from src.detect_name import is_person_name, own_lexicon_ok  # noqa: E402
from src.dict_export import to_keyed_digests  # noqa: E402
from src.dictionary import PiiDictionary  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()

KEY = b"t" * 32
STUBS = ["Иванов Иван", "Сидоров Пётр", "Продажи", "Гость", "Запись"]


def ok_runner(argv: Sequence[str]) -> tuple[int, str]:
    """Подстановка прибора: планки выдержаны."""
    return 0, "все планки выдержаны"


def bad_runner(argv: Sequence[str]) -> tuple[int, str]:
    """Подстановка прибора: планки не выдержаны."""
    return 1, "recall 0.42 ниже планки"


class DictWriteFixture(unittest.TestCase):
    """Стенд: справочник schema 3 в отдельном каталоге плюс файл ключа."""

    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        base = os.path.join(self.dir.name, "pii_dict.json")
        self.key_path = os.path.join(self.dir.name, "dict.key")
        Path(self.key_path).write_bytes(KEY)
        self.live = dict_write.write_staged(to_keyed_digests({"P": list(STUBS)}, KEY), base)
        self.payload = dict_write.load_payload(self.live)

    def live_bytes(self) -> bytes:
        """Содержимое живого файла как есть — доказательство «не изменился»."""
        return Path(self.live).read_bytes()


class DictValueTests(DictWriteFixture):
    """Добавление, удаление и проверка присутствия значения."""

    def test_has_value_sees_stub_and_not_absent_one(self) -> None:
        self.assertTrue(dict_write.has_value(self.payload, KEY, "P", "Иванов Иван"))
        self.assertTrue(dict_write.has_value(self.payload, KEY, "P", "Продажи"))
        self.assertFalse(dict_write.has_value(self.payload, KEY, "P", "Сидорова Ольга"))

    def test_remove_drops_value_and_its_form_digests(self) -> None:
        updated, stats = dict_write.remove_values(
            self.payload, KEY, "P", ["Продажи", "Гость", "Запись", "НетТакого"]
        )
        self.assertEqual(3, stats.removed)
        self.assertEqual(1, stats.absent)
        self.assertFalse(dict_write.has_value(updated, KEY, "P", "Продажи"))
        self.assertTrue(dict_write.has_value(updated, KEY, "P", "Иванов Иван"))
        self.assertEqual(len(STUBS) - 3, updated["values"])
        forms_before = len((self.payload.get("forms") or {}).get("P") or {})
        forms_after = len((updated.get("forms") or {}).get("P") or {})
        self.assertEqual(forms_before, forms_after + stats.form_digests)

    def test_remove_of_absent_value_changes_nothing(self) -> None:
        updated, stats = dict_write.remove_values(self.payload, KEY, "P", ["НетТакого"])
        self.assertEqual(0, stats.removed)
        self.assertEqual(self.payload["digests"]["P"], updated["digests"]["P"])

    def test_add_value_and_its_forms_keep_one_identity(self) -> None:
        updated, stats = dict_write.add_values(self.payload, KEY, "P", ["Сидорова", "Сидоров"])
        self.assertEqual(2, stats.added)
        self.assertGreater(stats.form_digests, 0)
        self.assertTrue(dict_write.has_value(updated, KEY, "P", "Сидорова"))
        self.assertEqual(len(STUBS) + 2, updated["values"])

    def test_add_of_known_value_is_counted_not_duplicated(self) -> None:
        updated, stats = dict_write.add_values(self.payload, KEY, "P", ["Иванов Иван"])
        self.assertEqual(0, stats.added)
        self.assertEqual(1, stats.already_present)
        self.assertEqual(len(STUBS), updated["values"])

    def test_known_case_form_counts_as_known(self) -> None:
        # Рантайм берёт падежную форму впереди точного написания: «Сидорову» получает код
        # персоны «Сидоров», значит добавлять её отдельно нечего.
        updated, _ = dict_write.add_values(self.payload, KEY, "P", ["Сидоров"])
        self.assertTrue(dict_write.has_value(updated, KEY, "P", "Сидорову"))
        second, stats = dict_write.add_values(updated, KEY, "P", ["Сидорову"])
        self.assertEqual(0, stats.added)
        self.assertEqual(1, stats.already_present)

    def test_removed_service_word_is_not_a_name_by_runtime_rule(self) -> None:
        # До правки «Продажи» проходило правило «кириллица от четырёх букв» (предохранитель от
        # редких фамилий), и единственной защитой был стоп-лист детектора. Теперь слово закрыто
        # стоп-листом и в общем предикате имени — рантайм и стоп-лист говорят одно и то же.
        self.assertFalse(is_person_name("Продажи"))
        self.assertFalse(is_person_name("Гость"))
        self.assertFalse(is_person_name("Менеджер"))
        for word in ("Продажи", "Гость", "Запись", "Менеджер", "Тест", "Бухгалтер", "Фотограф"):
            self.assertFalse(own_lexicon_ok(word), word)

    def test_service_word_inside_a_full_name_stays_a_person(self) -> None:
        # Разделение наборов стоп-листа: служебное слово закрыто ЦЕЛИКОМ, но внутри настоящего
        # ФИО оно допустимо. Регрессия, найденная 20.09.2026 полным сьютом: без разделения
        # «Тестов Тест Тестович» перестал обезличиваться — то есть чистка съела данные.
        self.assertTrue(is_person_name("Тестов Тест Тестович"))
        self.assertFalse(is_person_name("Тест"))
        self.assertTrue(own_lexicon_ok("Тестов Тест Тестович"))
        self.assertFalse(own_lexicon_ok("Тест"))
        self.assertFalse(own_lexicon_ok("Гость"))
        # Значение из одних служебных слов — тоже служебная лексика, но ФИО внутри него цело.
        self.assertFalse(own_lexicon_ok("Новый Неизвестно"))
        self.assertFalse(own_lexicon_ok("Гость Запись"))
        # Брендовый набор проверяется и словом внутри значения — оборот с брендом закрыт целиком.
        self.assertFalse(own_lexicon_ok("Мой Пример Спорт"))

    def test_positive_control_rare_and_foreign_surnames_stay_names(self) -> None:
        # Положительный контроль: редкие и нерусские фамилии обязаны остаться именами,
        # иначе чистка снова начнёт терять значения клиентов (замер 17.09.2026: −12,9%).
        for value in ("Токенец", "Тесля", "Скрытниц", "Токенцова", "Стабко", "Testa", "Тестовочка", "Стабсон"):
            self.assertTrue(is_person_name(value), value)
            self.assertTrue(own_lexicon_ok(value), value)


class DictStagedTests(DictWriteFixture):
    """staged-файл: права 0600, живой файл не тронут."""

    def test_staged_has_owner_only_mode_and_leaves_live_alone(self) -> None:
        before = self.live_bytes()
        path = dict_write.write_staged(self.payload, os.path.join(self.dir.name, "pii_dict.json.staged"))
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(0o600, mode)
        self.assertEqual(before, self.live_bytes())
        self.assertFalse(os.path.exists(path + ".tmp"))

    def test_schema_guard_refuses_readable_dictionary(self) -> None:
        readable = os.path.join(self.dir.name, "readable.json")
        Path(readable).write_text(json.dumps({"schema": 1, "values": {"P": ["Иванов"]}}), encoding="utf-8")
        with self.assertRaises(dict_write.DictWriteError) as caught:
            dict_write.load_payload(readable)
        self.assertEqual("DICT_SCHEMA_UNSUPPORTED", caught.exception.code)

    def test_missing_dictionary_raises_machine_code(self) -> None:
        with self.assertRaises(dict_write.DictWriteError) as caught:
            dict_write.load_payload(os.path.join(self.dir.name, "no-such.json"))
        self.assertEqual("DICT_MISSING", caught.exception.code)


class DictCheckTests(DictWriteFixture):
    """Проверка прибором до замены."""

    def test_check_passes_and_reports_failure(self) -> None:
        passed, _ = dict_write.check_staged(self.live, self.key_path, runner=ok_runner)
        self.assertTrue(passed)
        passed, output = dict_write.check_staged(self.live, self.key_path, runner=bad_runner)
        self.assertFalse(passed)
        self.assertIn("планки", output)

    def test_check_runner_crash_is_treated_as_failure(self) -> None:
        def broken(argv: Sequence[str]) -> tuple[int, str]:
            raise RuntimeError("прибор упал")

        passed, output = dict_write.check_staged(self.live, self.key_path, runner=broken)
        self.assertFalse(passed)
        self.assertIn("METRICS_RUNNER_FAILED", output)


class DictApplyTests(DictWriteFixture):
    """Бэкап, замена и поведение при отказах: живой справочник важнее прогона."""

    def test_apply_replaces_live_and_keeps_backup(self) -> None:
        updated, stats = dict_write.remove_values(self.payload, KEY, "P", ["Продажи", "Гость"])
        result = dict_write.apply(
            self.live, updated, self.key_path, runner=ok_runner, stamp="20260920-120000"
        )
        self.assertTrue(result.applied)
        self.assertTrue(result.metrics_passed)
        self.assertTrue(os.path.exists(result.backup_path))
        self.assertEqual(len(STUBS) - 2, result.values_after)
        self.assertEqual(len(STUBS), result.values_before)
        self.assertEqual(2, stats.removed)
        self.assertFalse(os.path.exists(result.staged_path))

    def test_failed_check_leaves_live_untouched(self) -> None:
        before = self.live_bytes()
        updated, _ = dict_write.remove_values(self.payload, KEY, "P", ["Продажи"])
        result = dict_write.apply(self.live, updated, self.key_path, runner=bad_runner)
        self.assertFalse(result.applied)
        self.assertFalse(result.metrics_passed)
        self.assertEqual("metrics_not_passed", result.reason)
        self.assertEqual(before, self.live_bytes())
        self.assertTrue(os.path.exists(result.staged_path))
        self.assertEqual("", result.backup_path)

    def test_crashed_check_does_not_touch_live(self) -> None:
        before = self.live_bytes()

        def broken(argv: Sequence[str]) -> tuple[int, str]:
            raise OSError("нет прибора")

        result = dict_write.apply(self.live, self.payload, self.key_path, runner=broken)
        self.assertFalse(result.applied)
        self.assertEqual(before, self.live_bytes())

    def test_unwritable_directory_raises_and_live_survives(self) -> None:
        before = self.live_bytes()
        blocked = os.path.join(self.dir.name, "blocked")
        os.makedirs(blocked)
        os.chmod(blocked, 0o500)
        self.addCleanup(os.chmod, blocked, 0o700)
        with self.assertRaises(dict_write.DictWriteError) as caught:
            dict_write.apply(
                self.live,
                self.payload,
                self.key_path,
                staged_path=os.path.join(blocked, "pii_dict.json.staged"),
                runner=ok_runner,
            )
        self.assertEqual("DICT_WRITE_FAILED", caught.exception.code)
        self.assertEqual(before, self.live_bytes())

    def test_installed_dictionary_is_readable_by_the_runtime(self) -> None:
        updated, _ = dict_write.add_values(self.payload, KEY, "P", ["Сидорова"])
        result = dict_write.apply(self.live, updated, self.key_path, runner=ok_runner)
        self.assertTrue(result.applied)
        mode = stat.S_IMODE(os.stat(self.live).st_mode)
        self.assertEqual(0o600, mode)
        dictionary = PiiDictionary(self.live, key=KEY)
        self.assertGreater(dictionary.load(), 0)
        counts = dictionary.snapshot()["counts"]
        self.assertEqual(len(STUBS) + 1, counts["P"])


if __name__ == "__main__":
    unittest.main()
