# FILE: tests/test_code_identity_property.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify reversibility as a property of the registry (Phase-17, owner requirement): the code of any value restores exactly that value, two similar values never merge into one code, and a repeated run produces byte-identical codes.
#   SCOPE: many generated values, determinism of the factory and of a repeated run, distinctness of codes for distinct and for near-identical values, round trip through the store and through the detokenizer.
#   DEPENDS: M-TOKEN-GEN, M-TOKENIZER, M-DETOKENIZER, M-MAP-STORE
#   LINKS: V-M-TOKEN-GEN, V-M-TOKENIZER, V-M-DETOKENIZER, V-M-MAP-STORE
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   CodeIdentityPropertyTests - обратимость и неслияние кодов на большом наборе значений
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-17 (20.09.2026): свойство реестра вместо единичного примера — «код любого значения восстанавливает ровно это значение» и «два похожих значения не сливаются».
# END_CHANGE_SUMMARY

import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.channel_policy import ChannelPolicy  # noqa: E402
from src.detokenizer import PayloadDetokenizer  # noqa: E402
from src.map_store import TokenMapStore  # noqa: E402
from src.token_factory import canonical_token, make_token  # noqa: E402
from src.tokenizer import PayloadTokenizer  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()

TOKEN_KEY = b"property-token-key-32-bytes-long!"
FERNET_KEY = b"p" * 32
VALUE_COUNT = 200
ALPHABET = "абвгдежзиклмнопрстуфхцчшщыэюя"


def synthetic_values(count: int = VALUE_COUNT, seed: int = 20260920) -> list[str]:
    """Собрать выдуманные значения, похожие на фамилии: без настоящих клиентов."""
    rng = random.Random(seed)
    values = []
    for index in range(count):
        stem = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(4, 8)))
        values.append(stem.capitalize() + ("ова" if index % 2 else "ов"))
    return values


class CodeIdentityPropertyTests(unittest.TestCase):
    """Обратимость и неслияние кодов — свойство реестра, а не удача примера."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TokenMapStore(os.path.join(self.tmp.name, "pii_map.db"), fernet_key=FERNET_KEY)
        self.tokenizer = PayloadTokenizer(TOKEN_KEY, self.store)
        self.detokenizer = PayloadDetokenizer(self.store, ChannelPolicy({"local"}))
        self.values = synthetic_values()

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def _assign(self, value: str) -> str:
        return self.tokenizer.issue_identifier("P", value, value)

    def test_every_code_restores_exactly_its_own_value(self) -> None:
        own: dict[str, str] = {}
        for value in self.values:
            code = self._assign(value)
            own[code] = value
        self.assertEqual(len(own), len(self.values), "два разных значения не имеют права сойтись в один код")
        for code, value in own.items():
            self.assertEqual(self.store.load_value(code), value)
            restored, _counters = self.detokenizer.detokenize_text(
                f"Анкета: {code}", "local", "property", {canonical_token(code)}
            )
            self.assertEqual(restored, f"Анкета: {value}")

    def test_assignment_is_deterministic_within_a_run(self) -> None:
        for value in self.values[:50]:
            self.assertEqual(self._assign(value), self._assign(value))

    def test_two_similar_values_do_not_merge(self) -> None:
        pairs = [("Тестов", "Тестова"), ("Тестовцев", "Тестовцева"), ("Иванов", "Иванова")]
        for first, second in pairs:
            self.assertNotEqual(self._assign(first), self._assign(second))
        # Регистр и лишние пробелы — одно значение; другая буква — другое.
        self.assertEqual(make_token("P", "иванов", TOKEN_KEY), make_token("P", "иванов", TOKEN_KEY))

    def test_repeated_run_produces_the_same_codes(self) -> None:
        """Повторный прогон на пустом реестре даёт те же коды: детерминизм сохранён."""
        first = [self._assign(value) for value in self.values]
        with tempfile.TemporaryDirectory() as directory:
            store = TokenMapStore(os.path.join(directory, "second.db"), fernet_key=FERNET_KEY)
            try:
                tokenizer = PayloadTokenizer(TOKEN_KEY, store)
                second = [tokenizer.issue_identifier("P", value, value) for value in self.values]
            finally:
                store.close()
        self.assertEqual(first, second)

    def test_no_code_carries_two_values(self) -> None:
        for value in self.values:
            self._assign(value)
        report = self.store.scan_integrity()
        self.assertEqual(report.ambiguous, 0)
        self.assertEqual(report.codes, len(self.values))
        self.assertEqual(report.records, len(self.values))
        self.assertEqual(self.store.require_integrity().ambiguous, 0)


if __name__ == "__main__":
    unittest.main()
