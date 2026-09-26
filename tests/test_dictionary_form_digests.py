# FILE: tests/test_dictionary_form_digests.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Prove that a hashed dictionary (schema 3) keeps one anonymization code per person in every case form, that it holds no readable value, and that files of the older schemas stay readable.
#   SCOPE: form digests written by the export, ambiguity policy, no-plaintext invariant, backward compatibility of schemas 1/2, end-to-end code-per-person and the detokenizer guard against a digest leaking into text.
#   DEPENDS: M-DICT-EXPORT, M-DICT, M-NAME-IDENTITY, M-TOKENIZER, M-DETOKENIZER
#   LINKS: V-M-DICT-EXPORT, V-M-NAME-IDENTITY, Phase-8
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   KEY - ключ отпечатков в тестах
#   FormDigestExportTests - выгрузка schema 3: отпечатки форм, неоднозначность, отсутствие читаемых значений
#   FamilyIdentityTests - одна персона на семью падежных форм (Phase-14)
#   SchemaCompatibilityTests - чтение старых схем
#   CodePerPersonTests - один код на персону во всех падежах на хешированном словаре
#   DetokenizerGuardTests - отпечаток не выходит в восстановленный текст
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.1.0 - Phase-14: семьи падежных форм — написание-падеж (в том числе запись карточки другого клиента) получает код персоны-основы.
#   PREVIOUS: v1.0.0 - Phase-8 (19.09.2026): планка PhCons ровно 1,0 на хешированном справочнике; замер до правки — 0,875, после — 1,0.
# END_CHANGE_SUMMARY

"""Формо-дигесты выгрузки (Phase-8).

Словарь продакшена хранит отпечатки значений, поэтому сгенерировать падежные формы он сам не
может — значения он не видит. До правки склонённое написание разрешалось основой открытого
списка или не разрешалось вовсе, и один клиент получал несколько кодов: замер на
хешированном справочнике давал PhCons 0,875 и RepRate 0,966. Схема 3 несёт отпечатки форм со
ссылкой на отпечаток своего значения — этого достаточно, чтобы код оставался один на персону.

Значений клиентов здесь нет: словарь строится из заведомых заглушек.
"""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.detect_name import NameDetector  # noqa: E402
from src.detokenizer import PayloadDetokenizer  # noqa: E402
from src.dict_export import _add_form_digest, to_keyed_digests  # noqa: E402
from src.dictionary import (  # noqa: E402
    SCHEMA_DIGEST,
    SCHEMA_FORMS,
    PiiDictionary,
    value_digest,
)
from src.map_store import TokenMapStore  # noqa: E402
from src.name_identity import DIGEST_IDENTITY_PREFIX, is_digest_identity  # noqa: E402
from src.normalize import normalize  # noqa: E402
from src.token_factory import find_tokens  # noqa: E402
from src.tokenizer import PayloadTokenizer  # noqa: E402

KEY = b"form-digest-suite-key-32-bytes!!"

#: Заглушки: настоящие значения клиентов в приборе и тестах недопустимы.
VALUES = ["Иванов", "Печёнов", "Скрытница"]
FIO = "Иванов Иван Иванович"


class FormDigestExportTests(unittest.TestCase):
    """Выгрузка schema 3: отпечатки форм и никаких читаемых значений."""

    def setUp(self) -> None:
        self.payload = to_keyed_digests({"P": list(VALUES) + [FIO], "T": ["79000000001"]}, KEY)

    def test_schema_is_three_and_forms_are_present(self) -> None:
        self.assertEqual(self.payload["schema"], SCHEMA_FORMS)
        self.assertIn("P", self.payload["forms"])
        self.assertTrue(self.payload["forms"]["P"], msg="блок формо-дигестов пуст")

    def test_no_readable_value_survives_in_the_file(self) -> None:
        blob = json.dumps(self.payload, ensure_ascii=False)
        for value in VALUES + [FIO, "79000000001"]:
            with self.subTest(value=value):
                self.assertNotIn(value, blob)
        self.assertNotIn("иванов", blob.lower())
        # Отпечатки — шестнадцатеричные строки фиксированной длины, а не слова.
        for form_digest, base_digest in self.payload["forms"]["P"].items():
            self.assertRegex(form_digest, r"^[0-9a-f]{16}$")
            self.assertRegex(base_digest, r"^[0-9a-f]{16}$")

    def test_declined_form_points_at_its_value_digest(self) -> None:
        digests = self.payload["forms"]["P"]
        for form in ("иванову", "ивановым", "иванове"):
            with self.subTest(form=form):
                form_digest = value_digest(KEY, "P", form)
                self.assertEqual(
                    digests.get(form_digest),
                    value_digest(KEY, "P", "иванов"),
                    msg=f"форма {form} не ссылается на отпечаток значения",
                )
        # Женская форма другого значения: «Скрытнице» — от «Скрытница».
        self.assertEqual(
            digests.get(value_digest(KEY, "P", "скрытнице")),
            value_digest(KEY, "P", "скрытница"),
        )

    def test_form_equal_to_a_value_is_resolved_through_its_family(self) -> None:
        """Значение-падеж не заводит собственный код: «Скрытницы» — падеж от «Скрытница».

        Решение владельца 18.09.2026 «код присваивается персоне, а не падежной форме»: написание,
        порождённое как падеж другого написания, указывает на персону-основу, даже если карточка
        другого клиента хранит ровно это написание. Замер 19.09.2026 на настоящем справочнике:
        без этого правила 15 значений из 40 получали несколько кодов (PhCons 0,625 при планке
        ровно 1,0).
        """
        payload = to_keyed_digests({"P": ["Скрытница", "Скрытницы"]}, KEY)
        forms = payload.get("forms", {}).get("P", {})
        self.assertEqual(
            forms.get(value_digest(KEY, "P", "скрытницы")),
            value_digest(KEY, "P", "скрытница"),
            msg="падеж значения не сведён к персоне-основе",
        )

    def test_ambiguous_spelling_of_two_bases_is_not_resolved(self) -> None:
        """Написание, порождённое двумя разными основами, персоной не становится.

        Проверяется сам запрет угадывать: приём выгрузки обязан отбросить написание, на которое
        претендуют две основы, а не выбрать одну из них. Настоящие семьи схлопывают такие
        столкновения, поэтому запрет проверяется напрямую — на служебном вызове.
        """
        pairs: dict[str, str] = {}
        ambiguous: set[str] = set()
        _add_form_digest(pairs, ambiguous, "скрытнице", value_digest(KEY, "P", "скрытница"), KEY, "P")
        _add_form_digest(pairs, ambiguous, "скрытнице", value_digest(KEY, "P", "скрытницы"), KEY, "P")
        self.assertNotIn(value_digest(KEY, "P", "скрытнице"), pairs)
        self.assertIn(value_digest(KEY, "P", "скрытнице"), ambiguous)

    def test_latin_value_generates_no_forms(self) -> None:
        payload = to_keyed_digests({"P": ["Terekhina"]}, KEY)
        self.assertNotIn("P", payload.get("forms", {}) or {}, msg="латиница не склоняется")

    def test_non_name_classes_get_no_forms(self) -> None:
        payload = to_keyed_digests({"T": ["79000000001"], "P": VALUES}, KEY)
        self.assertEqual(set(payload["forms"]), {"P"})


class FamilyIdentityTests(unittest.TestCase):
    """Одна персона на семью падежных форм — на файле словаря, а не на служебных вызовах."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        payload = to_keyed_digests({"P": ["Скрытница", "Скрытницы", "Елена", "Елены"]}, KEY)
        path = os.path.join(self._tmp.name, "family.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)
        self.dictionary = PiiDictionary(path, key=KEY)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _identities(self, value: str) -> set[str]:
        """Все отпечатки, которые справочник выдаёт написанию и его падежам."""
        from src.name_forms import name_forms

        found: set[str] = set()
        for kind in ("lastname", "firstname", "patronymic"):
            for form in [value] + list(name_forms(value, kind)):
                text = (form or "").strip()
                if not text or not text[:1].isalpha():
                    continue
                identity = self.dictionary.identity_digest(text, "P")
                if identity:
                    found.add(identity)
        return found

    def test_value_and_its_case_forms_share_one_identity(self) -> None:
        """«Скрытницы» — падеж «Скрытница»: карточка второго клиента кода не заводит."""
        for value in ("Скрытница", "Елена"):
            with self.subTest(value=value):
                self.assertEqual(
                    len(self._identities(value)),
                    1,
                    msg=f"значение {value} получает несколько отпечатков",
                )

    def test_colliding_spelling_resolves_to_the_family_base(self) -> None:
        """Написание-омоним не перебивает персону: «Елены» — падеж «Елена».

        Если бы блок формо-дигестов уступал точным отпечаткам, это написание получило бы
        собственный код — ровно тот дефект, из-за которого PhCons на настоящем справочнике
        равнялся 0,625 при планке ровно 1,0.
        """
        self.assertEqual(
            self.dictionary.identity_digest("Елены", "P"),
            self.dictionary.identity_digest("Елена", "P"),
        )


class SchemaCompatibilityTests(unittest.TestCase):
    """Старые файлы обязаны читаться: schema 1 и schema 2 остаются в строю."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, payload: dict, name: str = "dict.json") -> str:
        path = os.path.join(self._tmp.name, name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)
        return path

    def test_schema_two_file_is_read_without_forms(self) -> None:
        payload = {
            "schema": SCHEMA_DIGEST,
            "generated_by": "M-DICT-EXPORT",
            "values": 1,
            "digests": {"P": [value_digest(KEY, "P", "иванов")]},
        }
        dictionary = PiiDictionary(self._write(payload), key=KEY)
        self.assertEqual(dictionary.lookup(normalize("P", "Иванов"), "P"), "P")
        # Форм в старом файле нет — идентичность-отпечаток недоступна, и это честно.
        self.assertIsNone(dictionary.identity_digest("Иванову", "P"))
        self.assertEqual(dictionary.snapshot()["form_digests"], 0)

    def test_readable_file_of_schema_one_still_works(self) -> None:
        path = self._write({"P": ["Иванов", "Иванов Иван Иванович"]})
        dictionary = PiiDictionary(path)
        self.assertEqual(dictionary.lookup(normalize("P", "Иванов"), "P"), "P")
        self.assertEqual(dictionary.values_for("P"), ["Иванов", "Иванов Иван Иванович"])
        self.assertIsNone(dictionary.identity_digest("Иванов", "P"))

    def test_schema_three_file_reports_form_count(self) -> None:
        payload = to_keyed_digests({"P": VALUES}, KEY)
        dictionary = PiiDictionary(self._write(payload), key=KEY)
        self.assertEqual(dictionary.snapshot()["form_digests"], len(payload["forms"]["P"]))


class CodePerPersonTests(unittest.TestCase):
    """Один код на персону во всех падежах — на хешированном словаре продакшен-вида."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = TokenMapStore(
            os.path.join(self._tmp.name, "code.db"), fernet_key=b"f" * 32
        )
        payload = to_keyed_digests({"P": list(VALUES) + [FIO]}, KEY)
        self.dictionary = PiiDictionary(
            self._write(payload), key=KEY
        )

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def _write(self, payload: dict) -> str:
        path = os.path.join(self._tmp.name, "pii_dict.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)
        return path

    def _tokenizer(self, detector: NameDetector) -> PayloadTokenizer:
        return PayloadTokenizer(os.urandom(32), self.store, detector)

    def test_detector_resolves_a_declined_form_to_the_value_identity(self) -> None:
        detector = NameDetector(self.dictionary)
        identity = detector.identity_for("Скрытнице")
        self.assertIsNotNone(identity, msg="падежная форма не разрешилась")
        assert identity is not None
        self.assertEqual(identity, detector.identity_for("Скрытница"))
        self.assertTrue(is_digest_identity(identity))

    def test_all_case_forms_share_one_code(self) -> None:
        detector = NameDetector(self.dictionary)
        tokenizer = self._tokenizer(detector)
        codes = set()
        for form in ("Анкета: Иванов", "Анкета: Иванова", "Анкета: Иванову", "Анкета: Ивановым"):
            with self.subTest(form=form):
                result = tokenizer.tokenize_text(form, "forms")
                found = find_tokens(result)
                self.assertTrue(found, msg=f"форма не заменена: {form}")
                codes.add(found[0][3])
        self.assertEqual(len(codes), 1, msg=f"один человек получил несколько кодов: {codes}")

    def test_schema_two_file_gives_several_codes_the_defect_is_reproducible(self) -> None:
        """Положительный контроль: без блока форм дефект воспроизводится.

        Это тот самый замер, из-за которого Phase-8 и появилась: на старом файле падежные
        формы не сводятся к одной персоне. Если тест перестанет падать — планка перестала
        что-либо значить.
        """
        legacy = to_keyed_digests({"P": ["Скрытница"]}, KEY)
        legacy.pop("forms")
        legacy["schema"] = SCHEMA_DIGEST
        legacy_path = os.path.join(self._tmp.name, "legacy.json")
        with open(legacy_path, "w", encoding="utf-8") as handle:
            json.dump(legacy, handle, ensure_ascii=False)
        dictionary = PiiDictionary(legacy_path, key=KEY)
        # Точное написание — да, падеж — нет: блок форм отсутствует.
        self.assertEqual(dictionary.lookup(normalize("P", "Скрытница"), "P"), "P")
        self.assertIsNone(dictionary.identity_digest("Скрытнице", "P"))

    def test_a_common_word_is_not_a_client_value(self) -> None:
        """Формо-дигест подтверждает только написание, порождённое значением справочника."""
        detector = NameDetector(self.dictionary)
        self.assertIsNone(
            detector.identity_for("Зданию"),
            msg="постороннее слово получило персону",
        )

    def test_common_word_that_is_a_case_form_needs_data_context(self) -> None:
        """Обычное слово рядом с данными заменяется, в обычном тексте — нет.

        «Скрытнице» — форма значения клиента из выгрузки, но и слово в тексте. Подтверждение
        словарём сильнее проверки формы, поэтому рядом с признаками работы с данными замена
        обязана произойти; без них текст остаётся целым (замер 19.09.2026 на боевом
        справочнике schema 3: без этого условия чистый корпус прибора дал 6 ложных замен).
        """
        detector = NameDetector(self.dictionary)
        tokenizer = self._tokenizer(detector)
        with_context = "Анкета клиента: Скрытнице звонить"
        self.assertTrue(
            find_tokens(tokenizer.tokenize_text(with_context, "ctx")),
            msg="рядом с данными замена обязана произойти",
        )
        prose = "Пришлите рекламе и скрытнице отчёт"
        self.assertEqual(
            tokenizer.tokenize_text(prose, "ctx"),
            prose,
            msg="обычный текст менять нельзя",
        )

    def test_dictionary_never_exposes_readable_values(self) -> None:
        self.assertEqual(self.dictionary.values_for("P"), [])
        self.assertTrue(self.dictionary.snapshot()["keyed"])


class DetokenizerGuardTests(unittest.TestCase):
    """Служебный отпечаток не имеет права попасть в восстановленный текст."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = TokenMapStore(
            os.path.join(self._tmp.name, "detok.db"), fernet_key=b"f" * 32
        )

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def test_digest_identity_never_becomes_text(self) -> None:
        identity = DIGEST_IDENTITY_PREFIX + "0123456789abcdef"
        restored = PayloadDetokenizer._nominative_form("P", ["Ивановой"], identity, "Ивановой")
        self.assertEqual(restored, "Ивановой")
        self.assertNotIn("pd:", restored)

    def test_digest_identity_falls_back_to_the_stored_value(self) -> None:
        identity = DIGEST_IDENTITY_PREFIX + "0123456789abcdef"
        restored = PayloadDetokenizer._nominative_form("P", [], identity, "Иванов")
        self.assertEqual(restored, "Иванов")

    def test_readable_identity_is_untouched(self) -> None:
        restored = PayloadDetokenizer._nominative_form("P", ["Ивановой"], "иванов", None)
        self.assertEqual(restored, "иванов")


if __name__ == "__main__":
    unittest.main()
