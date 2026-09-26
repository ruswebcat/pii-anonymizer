# FILE: tests/test_name_residual_gate.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Guard the last stage of name recognition: a value that no dictionary confirms must carry two or three independent features (capital letters, a name tag, a productive surname ending), while dictionary confirmation always outranks the shape check.
#   SCOPE: признаков имени, отказ от заглавных деловых оборотов, положительный контроль настоящих ФИО, приоритет справочника над формой, счётчик остановленных замен.
#   DEPENDS: M-DETECT-NAME, M-TOKENIZER
#   LINKS: V-M-DETECT-NAME, M-DETECT-NAME, Phase-9
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   CAPS_BUSINESS_CORPUS - заглавные деловые обороты, которые не являются ФИО
#   CAPS_NAME_CORPUS - настоящие ФИО заглавными буквами (положительный контроль)
#   FeatureCountTests - признаки имени и продуктивные окончания
#   ConfirmationBeatsShapeTests - справочник сильнее проверки формы
#   DetectorEvidenceTests - заслон подключён к распознаванию
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-9 шаг 1: замер 19.09.2026 показал 12 ложных замен на заглавных деловых оборотах; заслон требует два-три признака, справочник по-прежнему сильнее формы.
# END_CHANGE_SUMMARY

"""Заслон на неподтверждённых кандидатах (Phase-9 шаг 1).

До правки шаблон «два слова заглавными буквами» принимал за ФИО любой деловой оборот:
достаточно было заглавной буквы — одного слабого признака. Прибор качества показывал
12 ложных замен на зафиксированном корпусе. Морфология здесь ПОМОЩНИК, а не судья:
подтверждение справочником снимает проверку формы всегда, иначе редкая фамилия из
открытого списка перестаёт находиться (на этом один раз уже был регресс).
"""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.detect_name import (  # noqa: E402
    FEATURE_CAPITAL,
    FEATURE_ENDING,
    FEATURE_MORPHOLOGY,
    FEATURES_REQUIRED,
    NameDetector,
    is_person_name,
    name_features,
    surname_is_productive,
    unconfirmed_name_is_strong,
)
from src.map_store import TokenMapStore  # noqa: E402
from src.name_layer import NameLayer  # noqa: E402
from src.token_factory import find_tokens  # noqa: E402
from src.tokenizer import PayloadTokenizer  # noqa: E402

KEY = b"residual-gate-suite-key-32-bytes!!"

# Заглавные деловые обороты: по одной заглавной букве их принимать нельзя.
CAPS_BUSINESS_CORPUS: tuple[str, ...] = (
    "ВЫРУЧКА ПРОДАЖИ за месяц",
    "ОПЛАТА ТОПОЛЬ закрыт",
    "РАСПИСАНИЕ ЗАНЯТИЕ открыто",
    "БАЛАНС ГОСТЬ и запись",
    "НОВОСТИ КОМПАНИИ для клуба",
    "ТРЕНИРОВКА ЗАПИСЬ открыта",
)

# Положительный контроль: настоящие ФИО заглавными буквами обязаны заменяться.
CAPS_NAME_CORPUS: tuple[str, ...] = (
    "ИВАНОВ ИВАН",
    "БЕРЁЗОВ ПЁТР СЕРГЕЕВИЧ",
)

DICTIONARY = {
    "P": ["Иванов Иван Иванович", "Иванов", "Печёнов", "Токенец", "Сахнов Артём"],
}


class FeatureCountTests(unittest.TestCase):
    """Признаки имени считаются независимо друг от друга."""

    def test_productive_endings_are_recognised(self) -> None:
        for value in ("Иванов", "Терёхин", "Пушкин", "Достоевский", "Шевченко", "Скрытнев", "Токенчук"):
            with self.subTest(value=value):
                self.assertTrue(surname_is_productive(value), msg=value)

    def test_rare_surname_without_a_productive_ending_needs_a_dictionary(self) -> None:
        """«Токенец» оканчивается на «-ик», и образцом фамилии окончание не является.

        Именно поэтому справочник обязан оставаться главным: у такой фамилии форма не даёт
        второго признака, и держать её находкой может только список (тест 18.09.2026).
        """
        self.assertFalse(surname_is_productive("Токенец"))
        self.assertFalse(unconfirmed_name_is_strong("ТОКЕНЕЦ"))
        self.assertTrue(NameDetector({"P": ["Токенец"]})._shape_admission_ok("ТОКЕНЕЦ"))

    def test_inflected_endings_are_not_productive_samples(self) -> None:
        """«-ых», «-ым», «-ого» — формы известной основы, а не образец новой фамилии."""
        for value in ("Скрытниных", "Ивановым", "Мещериного", "нов", "ин", "дом"):
            with self.subTest(value=value):
                self.assertFalse(surname_is_productive(value), msg=value)

    def test_capital_only_value_carries_one_feature(self) -> None:
        features = name_features("ВЫРУЧКА ПРОДАЖИ")
        self.assertIn(FEATURE_CAPITAL, features)
        self.assertNotIn(FEATURE_ENDING, features)
        self.assertFalse(unconfirmed_name_is_strong("ВЫРУЧКА ПРОДАЖИ"))

    def test_a_real_name_carries_two_or_three_features(self) -> None:
        for value in ("ИВАНОВ ИВАН", "БЕРЁЗОВ ПЁТР", "СКРЫТНИНЫХ ПЁТР"):
            with self.subTest(value=value):
                self.assertGreaterEqual(len(name_features(value)), FEATURES_REQUIRED, msg=value)
                self.assertTrue(unconfirmed_name_is_strong(value), msg=value)

    def test_lowercase_value_carries_no_capital_feature(self) -> None:
        self.assertNotIn(FEATURE_CAPITAL, name_features("иванов"))
        self.assertIn(FEATURE_MORPHOLOGY, name_features("иванов") | name_features("Иван"))

    def test_empty_value_is_not_strong(self) -> None:
        self.assertFalse(unconfirmed_name_is_strong(""))
        self.assertFalse(unconfirmed_name_is_strong("   "))


class ConfirmationBeatsShapeTests(unittest.TestCase):
    """Подтверждение справочником сильнее проверки формы."""

    def test_open_layer_confirms_a_rare_surname_the_shape_cannot_read(self) -> None:
        """«Тесля» не проходит ни морфологию, ни продуктивное окончание — но он в списке."""
        layer = NameLayer({"P": {"тесля"}}, {"source": "test", "licence": "n/a"})
        detector = NameDetector(DICTIONARY, name_layer=layer)
        self.assertFalse(unconfirmed_name_is_strong("тесля"))
        self.assertTrue(
            detector._shape_admission_ok("Тесля"),
            msg="подтверждение открытым списком обязано перевесить проверку формы",
        )

    def test_client_dictionary_confirms_a_rare_surname(self) -> None:
        detector = NameDetector({"P": ["Тесля"]})
        self.assertTrue(detector._shape_admission_ok("ТЕСЛЯ"))

    def test_shape_rule_still_holds_without_any_dictionary(self) -> None:
        detector = NameDetector()
        self.assertFalse(detector._shape_admission_ok("ВЫРУЧКА ПРОДАЖИ"))
        self.assertTrue(detector._shape_admission_ok("ИВАНОВ ПЁТР"))

    def test_export_rule_is_untouched(self) -> None:
        """Выгрузка словаря продолжает держать редкие значения: её правило не ужесточалось."""
        for value in ("Скрытница", "Скрытниц", "Токенец", "Скрытниных"):
            with self.subTest(value=value):
                self.assertTrue(is_person_name(value), msg=value)


class DetectorEvidenceTests(unittest.TestCase):
    """Заслон подключён к распознаванию и не выпускает неподтверждённые обороты."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = TokenMapStore(os.path.join(self._tmp.name, "gate.db"), fernet_key=b"f" * 32)
        self.detector = NameDetector(DICTIONARY)
        self.tokenizer = PayloadTokenizer(KEY, self.store, self.detector)

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def _tokens_in(self, text: str) -> list[tuple[str, str]]:
        payload = {"messages": [{"role": "user", "content": text}]}
        anonymized, _stats = self.tokenizer.tokenize_payload(payload, "gate")
        serialized = json.dumps(anonymized, ensure_ascii=False)
        return [(span[2], span[3]) for span in find_tokens(serialized)]

    def test_caps_business_words_are_not_replaced(self) -> None:
        for text in CAPS_BUSINESS_CORPUS:
            with self.subTest(text=text):
                self.assertEqual(self._tokens_in(text), [], msg=f"ложная замена: {text}")

    def test_caps_business_words_are_not_detected(self) -> None:
        for text in CAPS_BUSINESS_CORPUS:
            with self.subTest(text=text):
                self.assertEqual(self.detector.detect_names(text), [], msg=text)

    def test_caps_real_names_are_replaced(self) -> None:
        for text in CAPS_NAME_CORPUS:
            with self.subTest(text=text):
                matches = self.detector.detect_names(text)
                self.assertTrue(matches, msg=f"потеряна настоящая находка: {text}")

    def test_rare_surname_confirmed_by_the_layer_survives_the_gate(self) -> None:
        layer = NameLayer({"P": {"тесля"}}, {"source": "test", "licence": "n/a"})
        detector = NameDetector(DICTIONARY, name_layer=layer)
        matches = detector.detect_names("ТЕСЛЯ ОЛЬГА")
        self.assertTrue(matches, msg="фамилия из открытого списка потеряна")

    def test_counter_shows_how_many_replacements_the_gate_stopped(self) -> None:
        self.detector.detect_names("ВЫРУЧКА ПРОДАЖИ")
        counters = self.detector.evidence_counters()
        self.assertGreaterEqual(counters["rejected_unconfirmed"], 1)
        self.assertEqual(self.detector.detect_names("ИВАНОВ ИВАН"), self.detector.detect_names("ИВАНОВ ИВАН"))
        self.assertEqual(self.detector.evidence_counters()["rejected_unconfirmed"], counters["rejected_unconfirmed"])

    def test_mixed_line_loses_exactly_the_name(self) -> None:
        text = "ВЫРУЧКА ПРОДАЖИ и клиент ИВАНОВ ИВАН"
        result = self.tokenizer.tokenize_text(text, "gate")
        self.assertIn("ВЫРУЧКА ПРОДАЖИ", result)
        self.assertNotIn("ИВАНОВ", result)


if __name__ == "__main__":
    unittest.main()
