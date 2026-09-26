# FILE: tests/test_dict_export.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-DICT-EXPORT contract: field mapping, pagination, atomic permission-hardened writes, and the missing-key guard — all without touching the network.
#   SCOPE: extraction, pagination through an injected fetcher, atomic write, CLI guard.
#   DEPENDS: src/dict_export.py
#   LINKS: M-DICT-EXPORT, V-M-DICT-EXPORT, tests/test_dict_export.py
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   DictExportTests - unittest suite for the dictionary export
#   DictionaryHygieneTests - Phase-6 checks that service records and junk never reach the dictionary
#   DictHygienePhase16Tests - Phase-16 checks for the noise rule: initials, times, technical strings, common words
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.1.0 - Phase-16 M-DICT-HYGIENE: проверки правила шума (инициал, время, техзнаки, ведущая цифра, обычное слово), предохранителя по открытому списку и защита от регрессий — телефон со скобками и дата остаются в словаре.
#   PREVIOUS: v1.0.0 - Phase-2 checks for the CRM export.
# END_CHANGE_SUMMARY

import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.dict_export import (  # noqa: E402
    ExportError,
    build_dictionary,
    extract_values,
    fetch_pages,
    main,
    noise_kind,
    shape_class,
    to_keyed_digests,
    write_dictionary_atomic,
)
from src.dictionary import SCHEMA_DIGEST, SCHEMA_FORMS  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()

# START_BLOCK_TEST_DICT_EXPORT
FIO = "Иванов Иван Иванович"
PHONE = "79000000001"


class DictExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_extract_values_maps_fields_and_primary_key(self) -> None:
        records = [
            {"id": 35209, "fio": FIO, "phone": PHONE, "email": "a@b.ru", "unknown": "мусор"},
            {"id": 35210, "fio": FIO, "phone": None, "сlub": "Центральный"},
        ]
        data = extract_values(records)
        self.assertEqual(data["P"], [FIO])
        self.assertEqual(data["T"], [PHONE])
        self.assertEqual(data["E"], ["a@b.ru"])
        self.assertEqual(data["C"], ["35209", "35210"])
        self.assertNotIn("мусор", json.dumps(data, ensure_ascii=False))

    def test_extract_values_skips_nested_and_overlong(self) -> None:
        records = [{"phone": {"raw": PHONE}, "fio": "я" * 300, "name": "Петруш Татьяна"}]
        data = extract_values(records)
        self.assertEqual(data.get("T"), None)
        self.assertEqual(data["P"], ["Петруш Татьяна"])

    def test_fetch_pages_walks_pagination(self) -> None:
        pages = {
            1: {"items": [{"id": 1}, {"id": 2}]},
            2: {"items": [{"id": 3}]},
        }

        def fetcher(path: str):
            page = int(path.split("page=")[1].split("&")[0])
            return pages.get(page, {"items": []})

        items = fetch_pages(fetcher, "/client", page_size=2, max_pages=10)
        self.assertEqual([item["id"] for item in items], [1, 2, 3])

    def test_fetch_pages_accepts_bare_lists(self) -> None:
        def fetcher(path: str):
            page = int(path.split("page=")[1].split("&")[0])
            return [{"id": 7}] if page == 1 else []

        self.assertEqual(len(fetch_pages(fetcher, "/client", page_size=1)), 1)

    def test_build_dictionary_combines_pages(self) -> None:
        def fetcher(path: str):
            return {"items": [{"id": 1, "fio": FIO}]}

        data = build_dictionary(fetcher, max_pages=1)
        self.assertEqual(data["P"], [FIO])
        self.assertEqual(data["C"], ["1"])

    def test_atomic_write_sets_owner_only_permissions(self) -> None:
        target = os.path.join(self._tmp.name, "pii_dict.json")
        write_dictionary_atomic(target, {"P": [FIO]})
        self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)
        with open(target, "r", encoding="utf-8") as handle:
            self.assertEqual(json.load(handle)["P"], [FIO])
        leftovers = [name for name in os.listdir(self._tmp.name) if name.startswith(".dict-")]
        self.assertEqual(leftovers, [])

    def test_missing_key_stops_the_export(self) -> None:
        code = main(
            ["--out", os.path.join(self._tmp.name, "out.json")],
            env_values={"OTHER": "1"},
        )
        self.assertEqual(code, 2)

    def test_full_export_writes_the_dictionary(self) -> None:
        """End to end with an injected fetcher: no network, real file written.

        The readable form is now the explicit opt-in (--raw); the digest form,
        which is the default, is checked below.
        """
        target = os.path.join(self._tmp.name, "exported.json")

        def fetcher(path: str):
            page = int(path.split("page=")[1].split("&")[0])
            if page > 1:
                return {"items": []}
            return {"items": [{"id": 35209, "fio": FIO, "phone": PHONE}]}

        code = main(
            ["--out", target, "--raw"],
            fetcher=fetcher,
            env_values={"CRM_API_KEY": "test-key"},
        )
        self.assertEqual(code, 0)
        with open(target, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertEqual(data["P"], [FIO])
        self.assertEqual(data["C"], ["35209"])
        self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)

    def test_default_export_writes_keyed_digests(self) -> None:
        """The default export must leave no readable personal data on disk."""
        target = os.path.join(self._tmp.name, "keyed.json")
        key_path = os.path.join(self._tmp.name, "token.key")
        with open(key_path, "wb") as handle:
            handle.write(b"k" * 32)
        os.chmod(key_path, 0o600)

        def fetcher(path: str):
            page = int(path.split("page=")[1].split("&")[0])
            if page > 1:
                return {"items": []}
            return {"items": [{"id": 35209, "fio": FIO, "phone": PHONE}]}

        code = main(
            ["--out", target, "--key-file", key_path],
            fetcher=fetcher,
            env_values={"CRM_API_KEY": "test-key"},
        )
        self.assertEqual(code, 0)
        blob = open(target, encoding="utf-8").read()
        self.assertNotIn(FIO, blob)
        self.assertNotIn("Иванов", blob)
        self.assertNotIn(PHONE, blob)
        # Схема 3 (Phase-8): отпечатки значений плюс отпечатки падежных форм.
        self.assertEqual(json.loads(blob)["schema"], SCHEMA_FORMS)

        from src.dictionary import PiiDictionary
        from src.normalize import normalize

        dictionary = PiiDictionary(target, key=b"k" * 32)
        self.assertEqual(dictionary.lookup(normalize("P", FIO), "P"), "P")
        self.assertEqual(dictionary.lookup(normalize("T", PHONE), "T"), "T")
        # Падежная форма значения разрешается в ту же персону, читаемых значений в файле нет.
        self.assertEqual(
            dictionary.identity_digest("Иванову", "P"),
            dictionary.identity_digest("Иванов", "P"),
            msg="падежная форма обязана ссылаться на отпечаток своего значения",
        )
        self.assertIsNone(dictionary.identity_digest("Петрову", "P"))

    def test_keyed_digests_cover_birth_dates_by_day_month(self) -> None:
        """Class D must digest the day-month key, matching the tokenizer."""
        key = b"d" * 32
        payload = to_keyed_digests({"D": ["12.03.1985", "07.11.1990"], "P": [FIO]}, key)
        self.assertIn("D", payload["digests"], msg="класс дат рождения потерян")
        from src.dictionary import value_digest
        from src.normalize import split_birth_date

        day_month, _year = split_birth_date("12.03.1985")
        self.assertIn(value_digest(key, "D", day_month), payload["digests"]["D"])

    def test_default_export_without_a_key_refuses_to_write(self) -> None:
        target = os.path.join(self._tmp.name, "no-key.json")

        def fetcher(path: str):
            return {"items": [{"id": 1, "fio": FIO}]}

        code = main(
            ["--out", target, "--key-file", os.path.join(self._tmp.name, "absent.key")],
            fetcher=fetcher,
            env_values={"CRM_API_KEY": "test-key"},
        )
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(target))

    def test_preview_writes_nothing(self) -> None:
        target = os.path.join(self._tmp.name, "preview.json")

        def fetcher(path: str):
            return {"items": []}

        code = main(
            ["--out", target, "--preview"],
            fetcher=fetcher,
            env_values={"CRM_API_KEY": "test-key"},
        )
        self.assertEqual(code, 0)
        self.assertFalse(os.path.exists(target))

    def test_error_codes_are_stable(self) -> None:
        error = ExportError("EXPORT_API_ERROR", "CRM returned 500")
        self.assertEqual(error.code, "EXPORT_API_ERROR")

    # START_BLOCK_TEST_NESTED_EXTRACTION
    def test_contacts_list_is_mapped_by_contact_type(self) -> None:
        """The real DTO keeps phone and e-mail in a nested contacts list."""
        records = [
            {
                "id": 35209,
                "contacts": [
                    {"contact_type": "phone", "contact": PHONE},
                    {"contact_type": "email", "contact": "a@b.ru"},
                    {"contact_type": "unknown_kind", "contact": "мусор"},
                ],
            }
        ]
        data = extract_values(records)
        self.assertEqual(data["T"], [PHONE])
        self.assertEqual(data["E"], ["a@b.ru"])
        self.assertNotIn("мусор", json.dumps(data, ensure_ascii=False))

    def test_manager_object_contributes_staff_names(self) -> None:
        records = [
            {
                "id": 1,
                "manager": {"full_name": "Токенчукова Юлия", "phone": "79001234567", "roles": [1, 2]},
            }
        ]
        data = extract_values(records)
        self.assertIn("Токенчукова Юлия", data["P"])
        self.assertIn("79001234567", data["T"])

    def test_club_object_is_not_indexed(self) -> None:
        """A club address and switchboard are not a person's data."""
        records = [
            {
                "id": 1,
                "name": "Иванов Иван",
                "club": {"name": "Центральный", "address": "б-р Садовая 3а", "phone": "84810000001"},
            }
        ]
        data = extract_values(records)
        blob = json.dumps(data, ensure_ascii=False)
        self.assertIn("Иванов Иван", blob)
        self.assertNotIn("Центральный", blob)
        self.assertNotIn("б-р Мещерина", blob)
        self.assertNotIn("84810000001", blob)

    def test_patronymic_and_card_are_mapped(self) -> None:
        records = [{"id": 1, "surname": "Иванов", "name": "Иван", "patronymic": "Иванович", "card": "C-9912"}]
        data = extract_values(records)
        self.assertIn("Иванович", data["P"])
        self.assertIn("C-9912", data["C"])
    # END_BLOCK_TEST_NESTED_EXTRACTION
# END_BLOCK_TEST_DICT_EXPORT


if __name__ == "__main__":
    unittest.main()

class DictionaryHygieneTests(unittest.TestCase):
    """Чистка выгрузки (Phase-6): мусор не попадает в словарь, данные не теряются.

    Замеры 16.09.2026: 59,5% значений класса P не были именами, крупнейший источник —
    объект manager со служебными записями («CRM», «База», «Системы», «Admin»).
    """

    def test_service_records_are_dropped(self) -> None:
        stats: dict[str, int] = {}
        records = [
            {
                "id": 1,
                "name": "Иванов Иван Иванович",
                "manager": {"name": "CRM", "surname": "Admin", "patronymic": "Клиентов"},
            }
        ]
        data = extract_values(records, stats=stats)
        names = data.get("P", [])
        self.assertIn("Иванов Иван Иванович", names)
        for service in ("CRM", "Admin", "Клиентов"):
            self.assertNotIn(service, names, msg=f"служебная запись попала в словарь: {service}")
        dropped = stats.get("dropped_not_a_name", 0) + stats.get("dropped_own_vocabulary", 0)
        self.assertGreaterEqual(dropped, 3)

    def test_own_vocabulary_is_dropped(self) -> None:
        stats: dict[str, int] = {}
        data = extract_values([{"id": 2, "name": "Квартальный", "surname": "Пример"}], stats=stats)
        self.assertEqual(data.get("P", []), [])
        self.assertGreaterEqual(stats.get("dropped_own_vocabulary", 0), 2)

    def test_odd_client_values_are_kept(self) -> None:
        """Значения непривычной формы — это данные клиента, их нельзя выбрасывать.

        Замер 17.09.2026: первая версия чистки выбрасывала такие значения, и обезличивание
        падало до 73% — данные уходили в модель открытым текстом.
        """
        data = extract_values(
            [
                {"id": 7, "surname": "Stubnick"},
                {"id": 8, "name": "Тестовочка"},
                {"id": 9, "name": "Testuser1985"},
            ]
        )
        names = data.get("P", [])
        for value in ("Stubnick", "Тестовочка", "Testuser1985"):
            self.assertIn(value, names, msg=f"потеряно значение клиента: {value}")

    def test_junk_markers_are_dropped(self) -> None:
        stats: dict[str, int] = {}
        data = extract_values([{"id": 3, "name": "|", "surname": "-", "patronymic": "???"}], stats=stats)
        self.assertEqual(data.get("P", []), [])

    def test_misfiled_phone_is_reclassified_not_lost(self) -> None:
        """Телефон в поле фамилии — данные клиента: переносим в свой класс, не удаляем."""
        stats: dict[str, int] = {}
        data = extract_values([{"id": 4, "surname": "79000000007"}], stats=stats)
        self.assertIn("79000000007", data.get("T", []))
        self.assertNotIn("79000000007", data.get("P", []))
        self.assertEqual(stats.get("reclassified_to_T"), 1)

    def test_misfiled_email_is_reclassified(self) -> None:
        stats: dict[str, int] = {}
        data = extract_values([{"id": 5, "name": "client@example.ru"}], stats=stats)
        self.assertIn("client@example.ru", data.get("E", []))
        self.assertEqual(stats.get("reclassified_to_E"), 1)

    def test_real_full_name_stays_in_place(self) -> None:
        data = extract_values([{"id": 6, "name": "Петрова Анна Сергеевна"}])
        self.assertIn("Петрова Анна Сергеевна", data.get("P", []))


# START_BLOCK_TEST_DICT_HYGIENE_PHASE16
class StubNameLayer:
    """Открытый список для проверки предохранителя: знает ровно переданные значения."""

    def __init__(self, known: tuple[str, ...] = ()) -> None:
        self._known = set(known)

    def contains(self, value: str, cls: str | None = None) -> bool:
        return value in self._known


class DictHygienePhase16Tests(unittest.TestCase):
    """Phase-16: шум в поле имени отбрасывается, но только там, где признак доказуем.

    Замер 20.09.2026 на живой выгрузке (4 000 записей): правило убрало 269 значений из
    3 296 (шум 9,2% → 3,0%), при этом ни одно из отброшенных не было настоящей фамилией
    по открытому списку и ни одно не имело заглавной буквы с фамильным окончанием.
    """

    def test_noise_kinds_are_named(self) -> None:
        self.assertEqual(noise_kind("Н."), "short")
        self.assertEqual(noise_kind("06:30"), "time")
        self.assertEqual(noise_kind("V_2026"), "technical")
        self.assertEqual(noise_kind("29а"), "digit_lead")
        self.assertEqual(noise_kind("дом"), "common_word")

    def test_real_values_are_not_noise(self) -> None:
        # Значения, которые просто записаны непривычно, шумом не считаются: их хранит словарь.
        for value in ("Тестовочка", "Stubnick", "Токенчукова Анна", "Testa", "Stubko"):
            self.assertIsNone(noise_kind(value), value)

    def test_surname_read_as_common_word_stays_in_the_dictionary(self) -> None:
        # «Беркут», «Камыш», «Тополь» — настоящие фамилии, которые морфология читает обычным
        # словом. Правило шума их не касается: рантайм признаёт значение именем.
        stats: dict[str, int] = {}
        data = extract_values([{"id": "1", "surname": "Беркут"}], stats=stats)
        self.assertIn("Беркут", data.get("P", []))
        self.assertFalse([key for key in stats if key.startswith("dropped_noise_")])

    def test_noise_leaves_the_name_class_and_is_counted(self) -> None:
        stats: dict[str, int] = {}
        data = extract_values(
            [
                {
                    "id": "1",
                    "surname": "Тестовочка",
                    "name": "Н.",
                    "patronymic": "06:30",
                    "manager": {"surname": "V_2026"},
                }
            ],
            stats=stats,
        )
        names = data.get("P", [])
        self.assertIn("Тестовочка", names)
        for dropped in ("Н.", "06:30", "V_2026"):
            self.assertNotIn(dropped, names)
            self.assertNotIn(dropped, data.get("D", []))
        self.assertEqual(stats.get("dropped_noise_short"), 1)
        self.assertEqual(stats.get("dropped_noise_time"), 1)
        self.assertEqual(stats.get("dropped_noise_technical"), 1)

    def test_digit_leading_junk_is_dropped(self) -> None:
        stats: dict[str, int] = {}
        data = extract_values([{"id": "1", "name": "29а"}], stats=stats)
        self.assertNotIn("29а", data.get("P", []))
        self.assertEqual(stats.get("dropped_noise_digit_lead"), 1)

    def test_sloppy_date_is_reclassified_not_dropped(self) -> None:
        # Дата без ведущего нуля — это значение клиента, а не шум: класс D, не отбрасывание.
        stats: dict[str, int] = {}
        data = extract_values([{"id": "1", "surname": "3.14.1985"}], stats=stats)
        self.assertIn("3.14.1985", data.get("D", []))
        self.assertNotIn("3.14.1985", data.get("P", []))
        self.assertNotIn("dropped_noise_digit_lead", stats)

    def test_phone_with_parentheses_is_not_dropped(self) -> None:
        # Регрессия: скобки попали в список технических знаков, но телефон — значение клиента,
        # поэтому он обязан остаться в словаре (форма уводит его в свой класс).
        self.assertEqual(shape_class("+7 (900) 000-00-01"), "T")
        stats: dict[str, int] = {}
        data = extract_values([{"id": "1", "surname": "+7 900 000 00 01"}], stats=stats)
        self.assertTrue(
            any("+7 900 000 00 01" in values for values in data.values()),
            data,
        )
        self.assertFalse([key for key in stats if key.startswith("dropped_noise_")])

    def test_open_layer_keeps_a_short_real_value(self) -> None:
        # Предохранитель: короткое значение, которое знает открытый список, остаётся в словаре.
        stats: dict[str, int] = {}
        data = extract_values([{"id": "1", "surname": "Ын"}], stats=stats, layer=StubNameLayer(("Ын",)))
        self.assertIn("Ын", data.get("P", []))
        self.assertNotIn("dropped_noise_short", stats)

    def test_short_value_without_the_layer_is_dropped(self) -> None:
        stats: dict[str, int] = {}
        data = extract_values([{"id": "1", "surname": "Ын"}], stats=stats)
        self.assertNotIn("Ын", data.get("P", []))
        self.assertEqual(stats.get("dropped_noise_short"), 1)

    def test_build_dictionary_passes_the_layer(self) -> None:
        def fetcher(path: str) -> dict:
            return {"items": [{"id": "1", "surname": "Ын"}]}

        stats: dict[str, int] = {}
        data = build_dictionary(
            fetcher, max_pages=1, stats=stats, layer=StubNameLayer(("Ын",))
        )
        self.assertIn("Ын", data.get("P", []))

    def test_manager_initials_do_not_reach_the_dictionary(self) -> None:
        stats: dict[str, int] = {}
        data = extract_values(
            [{"id": "1", "surname": "Токенчук", "manager": {"name": "Н."}}], stats=stats
        )
        self.assertIn("Токенчук", data.get("P", []))
        self.assertNotIn("Н.", data.get("P", []))
        self.assertEqual(stats.get("dropped_noise_short"), 1)
# END_BLOCK_TEST_DICT_HYGIENE_PHASE16


class ShapeClassTests(unittest.TestCase):
    """Форма значения решает его класс."""

    def test_shapes_are_recognised(self) -> None:
        self.assertEqual(shape_class("79000000007"), "T")
        self.assertEqual(shape_class("+7 900 111 22 33"), "T")
        self.assertEqual(shape_class("client@example.ru"), "E")
        self.assertEqual(shape_class("19.03.1985"), "D")
        self.assertEqual(shape_class("1985-03-19"), "D")
        self.assertEqual(shape_class("123456"), "C")

    def test_names_are_not_shaped(self) -> None:
        for value in ("Иванов Иван Иванович", "Петрова", "Тестовочка"):
            self.assertIsNone(shape_class(value), msg=value)


if __name__ == "__main__":
    unittest.main()
