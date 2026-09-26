# FILE: tests/test_validator_string_scope.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Keep the residual-PII gate scanning the same units as the tokenizer, so a serialized-payload artefact can never block every request again.
#   SCOPE: per-string scanning, regression on the 18.09.2026 Mattermost block, real-name detection still blocked, fail-closed on unscannable fragments.
#   DEPENDS: M-VALIDATOR, M-TOKENIZER
#   LINKS: V-M-VALIDATOR
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   ValidatorScopeTests - the gate scans strings, not the JSON dump
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - 18.09.2026: 403 на каждый запрос Mattermost из-за сканирования сериализованного payload.
# END_CHANGE_SUMMARY

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.detect_name import NameDetector  # noqa: E402
from src.validator import ResidualPiiValidator  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()


class _Dictionary:
    """Словарь заглушек: знает одно имя."""

    def __init__(self, values: dict[str, list[str]]) -> None:
        self._values = values

    def lookup(self, value: str, cls: str = "P") -> str | None:
        return cls if value.strip().lower() in self._values.get(cls, []) else None

    def values_for(self, cls: str) -> list[str]:
        return list(self._values.get(cls, []))


class ValidatorScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = ResidualPiiValidator(NameDetector(_Dictionary({"P": ["тестов тест тестович"]})))

    def test_serialized_payload_does_not_create_findings(self) -> None:
        """Регресс 18.09.2026: в сериализованном JSON рядом с обычными словами появляются
        кавычки, запятые и цифры, и правило клиентского контекста принимало за данные
        имена, которые токенизатор законно оставил. Запрос блокировался целиком."""
        payload = {
            "model": "deepseek-flash",
            "messages": [
                {"role": "system", "content": "Ты помощник сети. Клуб Центральный; выручка 2026 года."},
                {"role": "user", "content": "покажи выручку за сентябрь"},
            ],
            "tools": [{"type": "function", "function": {"name": "crm", "parameters": {}}}],
        }
        verdict = self.validator.validate_outgoing(payload)
        self.assertTrue(verdict.clean, msg=f"ложная блокировка: {verdict.reasons}")

    def test_real_name_is_still_blocked(self) -> None:
        payload = {"messages": [{"role": "user", "content": "клиент Тестов Тест Тестович, телефон 79123456789"}]}
        verdict = self.validator.validate_outgoing(payload)
        self.assertFalse(verdict.clean, msg="имя обязано блокироваться")
        self.assertEqual(verdict.code, "residual_pii")

    def test_nested_structures_are_scanned(self) -> None:
        payload = {"messages": [{"role": "tool", "content": [{"text": "клиент Тестов Тест Тестович"}]}]}
        verdict = self.validator.validate_outgoing(payload)
        self.assertFalse(verdict.clean, msg="вложенные структуры обязаны проверяться")

    def test_unscannable_payload_is_blocked(self) -> None:
        verdict = self.validator.validate_outgoing({"messages": [{"role": "user", "content": {1, 2, 3}}]})
        self.assertFalse(verdict.clean, msg="непонятный payload обязан блокироваться")
        self.assertEqual(verdict.code, "validator_error")

    def test_plain_scalars_are_allowed(self) -> None:
        payload = {"model": "deepseek-flash", "temperature": 0.2, "stream": False, "metadata": None}
        self.assertTrue(self.validator.validate_outgoing(payload).clean)

    def test_pair_mode_blocks_a_value_that_survived(self) -> None:
        """Основной режим: значение найдено в оригинале и осталось в исходящем запросе."""
        original = {"messages": [{"role": "user", "content": "клиент Тестов Тест Тестович"}]}
        anonymized = {"messages": [{"role": "user", "content": "клиент Тестов Тест Тестович"}]}
        verdict = self.validator.validate_outgoing(anonymized, original)
        self.assertFalse(verdict.clean)
        self.assertEqual(verdict.code, "residual_pii")

    def test_pair_mode_allows_a_replaced_value(self) -> None:
        original = {"messages": [{"role": "user", "content": "клиент Тестов Тест Тестович"}]}
        anonymized = {"messages": [{"role": "user", "content": "клиент zPAAAAAAAA"}]}
        self.assertTrue(self.validator.validate_outgoing(anonymized, original).clean)

    def test_pair_mode_does_not_invent_findings(self) -> None:
        """Регресс 18.09.2026: после замены текст короче, «клиентский контекст» смещается.
        Проверка по оригиналу не должна считать ПД то, что обезличивать не требовалось."""
        text = "Задача: проверить отчёт по продажам; клуб Центральный"
        original = {"messages": [{"role": "system", "content": text}]}
        anonymized = {"messages": [{"role": "system", "content": text}]}
        self.assertTrue(self.validator.validate_outgoing(anonymized, original).clean)


if __name__ == "__main__":
    unittest.main()
