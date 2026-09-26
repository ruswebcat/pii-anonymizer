# FILE: tests/test_detect_ru_pii.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify Russian identifier recognition and its wiring into the shared rule set: control sums confirm СНИЛС/ИНН/ОГРН/ОГРНИП, marker words confirm passport/КПП/БИК/счёт/полис/водительское, plain numbers and fragments are rejected, and the pipeline tokenizes them without blocking the request.
#   SCOPE: контрольные суммы, слова-признаки, отсечение обрывков, порядок находок, подключение к общему набору находок и к конвейеру «токенизатор + заслон».
#   DEPENDS: M-DETECT-RU-PII, M-DETECT-RULES, M-TOKENIZER, M-VALIDATOR
#   LINKS: V-M-DETECT-RU-PII, M-DETECT-RU-PII, Phase-9
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   ControlSumTests - контрольные суммы СНИЛС, ИНН, ОГРН, ОГРНИП
#   DetectionTests - слова-признаки, отсечение обрывков, порядок находок
#   WiringTests - находки видны общему набору правил, то есть и токенизатору, и заслону
#   PipelineTests - сквозной прогон: обезличивание проходит, заслон не блокирует
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-9 шаг 2: модуль перенесён из /tmp/ru-pii-regex в репозиторий и подключён к M-DETECT-RULES.
# END_CHANGE_SUMMARY

"""Российские идентификаторы: форма, контрольная сумма и подключение к конвейеру.

Настоящих персональных данных здесь нет и быть не может: все номера — контрольные примеры
с сходящейся суммой либо заглушки.
"""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.detect_name import NameDetector  # noqa: E402
from src.detect_rules import CLASS_DOCUMENT, detect_rules, merge_matches  # noqa: E402
from src.detect_ru_pii import (  # noqa: E402
    detect_ru_pii,
    inn_ok,
    iter_ru_pii,
    ogrn_ok,
    ogrnip_ok,
    snils_ok,
)
from src.map_store import TokenMapStore  # noqa: E402
from src.token_factory import find_tokens  # noqa: E402
from src.tokenizer import PayloadTokenizer  # noqa: E402
from src.validator import ResidualPiiValidator  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()

KEY = b"ru-identifiers-suite-key-32-byte!"
DICTIONARY = {"P": ["Иванов Иван Иванович", "Иванов"]}


class ControlSumTests(unittest.TestCase):
    """Контрольные суммы подтверждают номер, опечатка — нет."""

    def test_snils_control_sum(self) -> None:
        self.assertTrue(snils_ok("112-233-445 95"))
        self.assertFalse(snils_ok("112-233-445 94"))
        self.assertFalse(snils_ok("1122334459"))

    def test_inn_control_digits(self) -> None:
        self.assertTrue(inn_ok("7707083893"))
        self.assertFalse(inn_ok("7707083894"))
        self.assertTrue(inn_ok("500100732259"))
        self.assertFalse(inn_ok("500100732258"))

    def test_ogrn_and_ogrnip_control_digit(self) -> None:
        self.assertTrue(ogrn_ok("1027700132195"))
        self.assertFalse(ogrn_ok("1027700132196"))
        self.assertTrue(ogrnip_ok("304500116000157"))
        self.assertFalse(ogrnip_ok("304500116000158"))


class DetectionTests(unittest.TestCase):
    """Что признаётся находкой, а что нет."""

    def test_snils_found_without_context(self) -> None:
        """У СНИЛС есть контрольная сумма — слово рядом не требуется."""
        found = detect_ru_pii("страховой номер 112-233-445 95 в базе")
        self.assertEqual(
            [(name, value) for _cls, value, _s, _e, name in found],
            [("снилс", "112-233-445 95")],
        )

    def test_inn_found_without_context(self) -> None:
        found = detect_ru_pii("ИНН 500100732259 и всё")
        self.assertIn("инн", [name for *_rest, name in found])

    def test_plain_ten_digit_number_is_not_inn(self) -> None:
        self.assertEqual(detect_ru_pii("заказ 1234567890 отгружен"), [])

    def test_account_needs_marker_word(self) -> None:
        number = "40817810099910004312"
        self.assertEqual(detect_ru_pii(f"номер {number} в выгрузке"), [])
        found = detect_ru_pii(f"расчётный счёт {number} открыт")
        self.assertEqual([name for *_rest, name in found], ["расчётный счёт"])

    def test_passport_needs_marker_word(self) -> None:
        self.assertEqual(detect_ru_pii("код 45 09 123456 в системе"), [])
        found = detect_ru_pii("паспорт 45 09 123456 выдан отделом")
        self.assertEqual([name for *_rest, name in found], ["паспорт"])

    def test_fragment_of_longer_number_is_rejected(self) -> None:
        self.assertEqual(detect_ru_pii("счёт 1408178100999100043120 конец"), [])

    def test_real_text_with_names_and_phone_has_no_documents(self) -> None:
        text = "Клиент Иванов Иван Иванович, телефон 79001112233, запись на 12.10.2026"
        self.assertEqual(detect_ru_pii(text), [])

    def test_findings_are_ordered_by_position(self) -> None:
        found = detect_ru_pii("ИНН 500100732259, паспорт 45 09 123456 выдан")
        positions = [start for _cls, _value, start, _end, _name in found]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(len(found), 2)

    def test_iterator_matches_the_list(self) -> None:
        text = "ИНН 500100732259 и всё"
        self.assertEqual(list(iter_ru_pii(text)), detect_ru_pii(text))

    def test_unix_timestamp_is_not_an_inn(self) -> None:
        """Регресс 19.09.2026: разряды ИНН у метки времени сошлись случайно.

        Находка 15.09.2026 (M-DETECT-RULES) — голое число из `created_at` читалось документом
        и заслон закрывал каждый запрос с выгрузкой. Здесь то же правило, потому что у
        «1789502911» контрольные разряды ИНН сходятся.
        """
        self.assertTrue(inn_ok("1789502911"))
        self.assertEqual(detect_ru_pii('{"created_at": 1789502911}'), [])
        self.assertEqual(
            [match for match in detect_rules('{"created_at": 1789502911}') if match.cls == CLASS_DOCUMENT],
            [],
        )


class WiringTests(unittest.TestCase):
    """Находки видны общему набору правил — значит и токенизатору, и заслону."""

    def test_ru_identifiers_are_part_of_detect_rules(self) -> None:
        text = "ИНН 500100732259 и всё"
        matches = merge_matches(detect_rules(text))
        self.assertTrue(
            [match for match in matches if match.cls == CLASS_DOCUMENT],
            msg="М-DETECT-RU-PII не подключён к общему набору находок",
        )

    def test_one_detection_source_for_tokenizer_and_gate(self) -> None:
        """Заслон и токенизатор обязаны видеть один набор: иначе запрос блокируется."""
        text = "паспорт 45 09 123456 выдан отделом"
        detector = NameDetector(DICTIONARY)
        tokenizer = PayloadTokenizer(KEY, _store(), detector)
        try:
            from src.validator import ResidualPiiValidator as Gate

            gate = Gate(detector)
            payload = {"messages": [{"role": "user", "content": text}]}
            anonymized, _stats = tokenizer.tokenize_payload(payload, "ru")
            verdict = gate.validate_outgoing(anonymized, payload)
            self.assertTrue(verdict.clean, msg=f"запрос заблокирован: {verdict.code}")
        finally:
            tokenizer._store.close()

    def test_omc_policy_needs_its_marker(self) -> None:
        number = "1234567890123456"
        self.assertEqual(detect_ru_pii(f"номер {number} в системе"), [])
        self.assertEqual(
            [name for *_rest, name in detect_ru_pii(f"полис ОМС {number}")],
            ["полис ОМС"],
        )

    def test_driving_licence_is_written_with_spaces(self) -> None:
        """Водительское пишут «77 АА 123456» — с пробелами; без них правило не срабатывало."""
        for text in ("водительское удостоверение 77 АА 123456", "водительское 77АА123456"):
            with self.subTest(text=text):
                self.assertEqual(
                    [name for *_rest, name in detect_ru_pii(text)], ["водительское"], msg=text
                )
        self.assertEqual(detect_ru_pii("код 77 АА 123456 в системе"), [])


class PipelineTests(unittest.TestCase):
    """Сквозной прогон: идентификатор заменяется кодом и не остаётся в исходящем тексте."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = TokenMapStore(os.path.join(self._tmp.name, "ru.db"), fernet_key=b"f" * 32)
        self.detector = NameDetector(DICTIONARY)
        self.tokenizer = PayloadTokenizer(KEY, self.store, self.detector)
        self.gate = ResidualPiiValidator(self.detector)

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def _anonymize(self, text: str) -> str:
        payload = {"messages": [{"role": "user", "content": text}]}
        anonymized, _stats = self.tokenizer.tokenize_payload(payload, "ru")
        return anonymized["messages"][0]["content"]

    def test_snils_is_tokenized_as_class_i(self) -> None:
        result = self._anonymize("страховой номер 112-233-445 95 в базе")
        self.assertNotIn("112-233-445", result)
        self.assertTrue(find_tokens(result), msg="СНИЛС обязан получить код")

    def test_inn_is_tokenized_and_not_blocked(self) -> None:
        text = "ИНН 500100732259 клиента Иванов Иван Иванович"
        payload = {"messages": [{"role": "user", "content": text}]}
        anonymized, _stats = self.tokenizer.tokenize_payload(payload, "ru")
        outgoing = anonymized["messages"][0]["content"]
        self.assertNotIn("500100732259", outgoing)
        self.assertTrue(self.gate.validate_outgoing(anonymized, payload).clean)

    def test_plain_number_is_left_alone_and_does_not_block(self) -> None:
        text = "заказ 1234567890 отгружен, выручка 1 234 567 рублей"
        payload = {"messages": [{"role": "user", "content": text}]}
        anonymized, _stats = self.tokenizer.tokenize_payload(payload, "ru")
        outgoing = anonymized["messages"][0]["content"]
        self.assertEqual(outgoing, text)
        self.assertTrue(self.gate.validate_outgoing(anonymized, payload).clean)

    def test_two_documents_keep_two_codes(self) -> None:
        text = "ИНН 500100732259, паспорт 45 09 123456 выдан отделом"
        result = self._anonymize(text)
        tokens = find_tokens(result)
        self.assertEqual(len(tokens), 2, msg="каждый идентификатор обязан получить свой код")
        self.assertEqual(json.dumps(result, ensure_ascii=False), json.dumps(result, ensure_ascii=False))


def _store() -> TokenMapStore:
    """Временное хранилище для проверки согласия токенизатора и заслона."""
    directory = tempfile.mkdtemp(prefix="ru-wiring-")
    return TokenMapStore(os.path.join(directory, "wiring.db"), fernet_key=b"f" * 32)


if __name__ == "__main__":
    unittest.main()
