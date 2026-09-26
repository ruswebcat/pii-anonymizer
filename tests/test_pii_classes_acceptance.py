# FILE: tests/test_pii_classes_acceptance.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: One acceptance set for every agreed PII class — names, phones, e-mail, birth dates, addresses, card numbers, documents — so each class has its own check instead of being covered only through names.
#   SCOPE: phone spellings, phone near-misses, own club numbers, e-mail forms, birth date with the year left open, card numbers, SNILS/passport/INN shapes, detokenization round-trip.
#   DEPENDS: M-TOKENIZER, M-DETOKENIZER, M-DETECT-RULES, M-DETECT-NAME
#   LINKS: V-M-TOKENIZER, Phase-10
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   CLIENT - placeholder phone and mail used by the tests
#   make_service - tokenizer over a small dictionary
#   PhoneFormatTests - spellings and near-misses
#   OtherClassTests - the remaining classes
#   RoundTripTests - codes come back on a trusted channel
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - 17.09.2026: acceptance across all agreed PII classes.
# END_CHANGE_SUMMARY

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.channel_policy import ChannelPolicy  # noqa: E402
from src.detect_name import NameDetector  # noqa: E402
from src.detokenizer import PayloadDetokenizer, collect_identifiers  # noqa: E402
from src.map_store import TokenMapStore  # noqa: E402
from src.normalize import normalize  # noqa: E402
from src.token_factory import find_tokens  # noqa: E402
from src.tokenizer import PayloadTokenizer  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()

# Заглушки: настоящие данные клиентов в тесты не попадают.
CLIENT_PHONE = "79001112233"
CLIENT_MAIL = "client.test@example.com"
CLIENT_CARD = "100200300"
CLIENT_NAME = "Тестов Тест Тестович"
CLIENT_BIRTH = "12.03.1985"
CLIENT_ADDRESS = "ул. Тестовая 1, кв. 2"
#: Телефоны ресепции демонстрационного контура (из настроек, не из кода).
DEMO_CLUB_LANDLINE = "+7 (8481) 000-011"
DEMO_CLUB_NUMBERS = ("79001110011", "78481000011")
CLUB_PHONE_SHAPES = [
    "+7 (8481) 000-011",
    "8 (8481) 000-011",
    "+79001110011",
    "8 8481 000 011",
]


class _FakeDictionary:
    """Словарь заглушек: значения нормализуются так же, как в настоящем словаре."""

    def __init__(self, values: dict[str, list[str]]) -> None:
        self._index: dict[str, set[str]] = {}
        for cls, items in values.items():
            bucket = self._index.setdefault(cls, set())
            for item in items:
                try:
                    bucket.add(normalize(cls, item))
                except Exception:  # noqa: BLE001 - заглушка, форма значения не важна
                    bucket.add(item.strip().lower())
                bucket.add(item.strip().lower())

    def lookup(self, value: str, cls: str = "P") -> str | None:
        probe = value.strip().lower()
        return cls if probe in self._index.get(cls, set()) else None

    def values_for(self, cls: str) -> list[str]:
        return sorted(self._index.get(cls, set()))


def make_service(values: dict[str, list[str]]) -> tuple[PayloadTokenizer, PayloadDetokenizer, TokenMapStore]:
    """Build a tokenizer and a detokenizer over a placeholder dictionary."""
    tmp = tempfile.mkdtemp()
    store = TokenMapStore(os.path.join(tmp, "map.db"), fernet_key=b"t" * 32)
    tokenizer = PayloadTokenizer(b"acceptance-tests-key-32-bytes!!", store, NameDetector(_FakeDictionary(values)))
    detokenizer = PayloadDetokenizer(store, ChannelPolicy(frozenset({"mattermost"})))
    return tokenizer, detokenizer, store


def anonymize(tokenizer: PayloadTokenizer, text: str) -> str:
    payload, _stats = tokenizer.tokenize_payload({"messages": [{"role": "user", "content": text}]}, "t")
    return payload["messages"][0]["content"]


class PhoneFormatTests(unittest.TestCase):
    """Телефон: все записи, которые встречаются в CRM и в выгрузках."""

    def setUp(self) -> None:
        self.tokenizer, self.detokenizer, self.store = make_service({"T": [CLIENT_PHONE]})
        core = CLIENT_PHONE[-10:]
        operator, rest = core[:3], core[3:]
        self.shapes = {
            "+7 с пробелами": f"+7 {operator} {rest[:3]}-{rest[3:5]}-{rest[5:]}",
            "8 со скобками": f"8 ({operator}) {rest[:3]}-{rest[3:5]}-{rest[5:]}",
            "слитно с 7": f"7{core}",
            "слитно с 8": f"8{core}",
            "плюс со скобками": f"+7({operator}){rest}",
            "только пробелы": f"+7 {operator} {rest[:3]} {rest[3:5]} {rest[5:]}",
            "дефисы": f"8-{operator}-{rest[:3]}-{rest[3:5]}-{rest[5:]}",
        }

    def tearDown(self) -> None:
        self.store.close()

    def test_every_spelling_is_replaced(self) -> None:
        for title, phone in self.shapes.items():
            with self.subTest(spelling=title):
                result = anonymize(self.tokenizer, f"клиент, телефон {phone}, клуб Центральный")
                self.assertNotIn(phone, result, msg=f"номер не заменён: {title}")
                self.assertTrue(find_tokens(json.dumps(result, ensure_ascii=False)))

    def test_phone_is_replaced_in_every_position(self) -> None:
        core = CLIENT_PHONE[-10:]
        for text in (
            f"позвони {core}",
            f"телефон: +7{core}",
            f"Клиент|{core}|Центральный",
            f"номер в строке таблицы; {core}; да",
        ):
            with self.subTest(text=text):
                self.assertNotIn(core, anonymize(self.tokenizer, text))

    def test_numbers_that_are_not_phones_are_left_alone(self) -> None:
        for text in (
            "выручка 28 000 рублей",
            "1 234 567 рублей за месяц",
            "карта на 12 мес за 16 000",
            "год 2026, месяц 09",
            "задача № 35209 закрыта",
            "продление на 6 мес",
        ):
            with self.subTest(text=text):
                self.assertEqual(anonymize(self.tokenizer, text), text)

    def test_own_club_numbers_are_never_replaced(self) -> None:
        """Номер клуба — не данные клиента, его нельзя превращать в код."""
        tokenizer, _detokenizer, store = make_service({"T": [CLIENT_PHONE, *DEMO_CLUB_NUMBERS]})
        try:
            for shape in CLUB_PHONE_SHAPES:
                with self.subTest(shape=shape):
                    text = f"телефон клуба {shape}"
                    self.assertEqual(anonymize(tokenizer, text), text)
        finally:
            store.close()

    def test_client_phone_still_replaced_next_to_club_phone(self) -> None:
        tokenizer, _detokenizer, store = make_service({"T": [CLIENT_PHONE, *DEMO_CLUB_NUMBERS]})
        try:
            text = f"клуб {DEMO_CLUB_LANDLINE}, клиент {CLIENT_PHONE}"
            result = anonymize(tokenizer, text)
            self.assertNotIn(CLIENT_PHONE, result)
            self.assertIn("8481", result)
        finally:
            store.close()


class OtherClassTests(unittest.TestCase):
    """Остальные оговорённые классы: почта, дата рождения, адрес, карта, документы."""

    def setUp(self) -> None:
        self.tokenizer, self.detokenizer, self.store = make_service(
            {
                "P": [CLIENT_NAME],
                "T": [CLIENT_PHONE],
                "E": [CLIENT_MAIL],
                "D": [CLIENT_BIRTH],
                "A": [CLIENT_ADDRESS],
                "C": [CLIENT_CARD],
            }
        )

    def tearDown(self) -> None:
        self.store.close()

    def test_email_forms_are_replaced(self) -> None:
        for text in (
            f"почта {CLIENT_MAIL}",
            f"e-mail: {CLIENT_MAIL.upper()}",
            f"Клиент|{CLIENT_MAIL}|Центральный",
        ):
            with self.subTest(text=text):
                result = anonymize(self.tokenizer, text)
                self.assertNotIn(CLIENT_MAIL.upper(), result.upper())

    def test_birth_date_keeps_the_year_open(self) -> None:
        """Год рождения остаётся открытым — токенизируются только день и месяц."""
        result = anonymize(self.tokenizer, f"дата рождения {CLIENT_BIRTH}")
        self.assertIn("1985", result, msg="год обязан остаться открытым")
        self.assertNotIn("12.03", result, msg="день и месяц обязаны быть заменены")

    def test_address_card_and_documents_are_replaced(self) -> None:
        cases = (
            ("адрес", CLIENT_ADDRESS),
            ("номер карты", CLIENT_CARD),
            ("СНИЛС", "112-233-445 95"),
            ("паспорт", "45 12 № 345678"),
            ("ИНН", "771234567890"),
        )
        for title, value in cases:
            with self.subTest(cls=title):
                result = anonymize(self.tokenizer, f"клиент, {title} {value}, клуб Центральный")
                self.assertNotIn(value, result, msg=f"не заменено: {title}")


class RoundTripTests(unittest.TestCase):
    """Код возвращается в значение при детокенизации на доверенном канале."""

    def test_every_class_comes_back(self) -> None:
        tokenizer, detokenizer, store = make_service(
            {"P": [CLIENT_NAME], "T": [CLIENT_PHONE], "E": [CLIENT_MAIL], "C": [CLIENT_CARD]}
        )
        try:
            text = f"ФИО {CLIENT_NAME}, телефон {CLIENT_PHONE}, почта {CLIENT_MAIL}, карта {CLIENT_CARD}"
            tokenized, _stats = tokenizer.tokenize_payload(
                {"messages": [{"role": "user", "content": text}]}, "t"
            )
            serialized = json.dumps(tokenized, ensure_ascii=False)
            for value in (CLIENT_NAME, CLIENT_PHONE, CLIENT_MAIL, CLIENT_CARD):
                self.assertNotIn(value, serialized, msg=f"значение ушло в модель открытым: {value}")
            anonymized = tokenized["messages"][0]["content"]
            allowed = collect_identifiers(serialized)
            restored = detokenizer.detokenize_string(anonymized, "t", allowed=allowed)
            for value in (CLIENT_NAME, CLIENT_PHONE, CLIENT_MAIL, CLIENT_CARD):
                self.assertIn(value, restored, msg=f"значение не вернулось: {value}")
        finally:
            store.close()

    def test_channel_policy_decides_who_gets_values_back(self) -> None:
        """Mattermost — доверенный канал, Telegram — нет."""
        tokenizer, detokenizer, store = make_service({"T": [CLIENT_PHONE]})
        try:
            tokenized, _stats = tokenizer.tokenize_payload(
                {"messages": [{"role": "user", "content": f"телефон {CLIENT_PHONE}"}]}, "t"
            )
            anonymized = tokenized["messages"][0]["content"]
            self.assertNotIn(CLIENT_PHONE, anonymized)
            for channel, should_restore in (("mattermost", True), ("telegram", False)):
                with self.subTest(channel=channel):
                    response = {"choices": [{"message": {"content": anonymized}}]}
                    allowed = collect_identifiers(anonymized)
                    restored, _counters = detokenizer.detokenize_response(
                        response, channel, allowed=allowed
                    )
                    content = restored["choices"][0]["message"]["content"]
                    self.assertEqual(CLIENT_PHONE in content, should_restore)
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
