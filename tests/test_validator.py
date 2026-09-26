# FILE: tests/test_validator.py
# VERSION: 1.0.1
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-VALIDATOR contract: the second pass catches residual personal data, never mistakes its own tokens for findings, and fails closed.
#   SCOPE: clean payloads, residual names and phones, table headers with token values, serialization failure, второй проход по остатку (Вариант 1).
#   DEPENDS: src/validator.py
#   LINKS: M-VALIDATOR, V-M-VALIDATOR, tests/test_validator.py
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   ValidatorTests - unittest suite for ResidualPiiValidator
#   RepairPassTests - Вариант 1: остаток заменяется вторым проходом, решение остаётся за проверкой
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.2 - дефект-фикс 19.09.2026: починка доводит замену до всех вхождений значения в строке (в том числе с другим пробелом) и не крутится, если менять нечего; счётчик замен не считает заменой код, равный значению.
#   PREVIOUS: v1.0.1 - Phase-15 шаг 2: проверки второго прохода — замена остатка, суд по результату, сбой замены, ссылка не остаток.
#   EARLIER: v1.0.0 - Phase-2 checks for the pre-flight gate.
# END_CHANGE_SUMMARY

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tokenizer import TokenizeError  # noqa: E402
from src.validator import ResidualPiiValidator, ValidationReason, ValidationVerdict  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()

# START_BLOCK_TEST_VALIDATOR
FIO = "Иванов Иван Иванович"
PHONE = "79000000001"


def token(letter: str = "P") -> str:
    return f"\u27e6{letter}-7GX25J4OJM3A\u27e7"


class ValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = ResidualPiiValidator()

    def test_clean_payload_passes(self) -> None:
        payload = {
            "model": "deepseek-flash",
            "messages": [
                {"role": "user", "content": f"Клиент {token()} продлил карту"},
                {"role": "tool", "content": f'{{"client_id": "{token("C")}"}}'},
            ],
        }
        verdict = self.validator.validate_outgoing(payload)
        self.assertTrue(verdict.clean)
        self.assertEqual(verdict.code, "")

    def test_residual_name_blocks(self) -> None:
        payload = {"messages": [{"role": "user", "content": f"Клиент {FIO} продлил"}]}
        verdict = self.validator.validate_outgoing(payload)
        self.assertFalse(verdict.clean)
        self.assertEqual(verdict.code, "residual_pii")
        self.assertIn(ValidationReason(cls="P", count=1), verdict.reasons)

    def test_a_name_in_a_phrase_before_a_url_is_still_a_residual(self) -> None:
        """Живой отказ 19.09.2026: ссылка в сорока знаках справа освобождала находку целиком.

        Имя в обычной фразе перед адресом («Клиент …, карта: https://…») переставало считаться
        остатком, и промах детектора на нём уходил провайдеру открытым текстом. Границы ссылки
        проверяются вплотную: «внутри адреса» — это сегмент адреса, а не слово рядом с ним.
        """
        text = f"Клиент {FIO}, карта: https://crm.example.com/lk/client?fio={FIO}"
        payload = {"messages": [{"role": "user", "content": text}]}
        verdict = self.validator.validate_outgoing(payload, payload)
        self.assertFalse(verdict.clean)
        # Судится только вхождение в обычной фразе: копия внутри параметра ссылки освобождена.
        self.assertEqual(
            [(reason.cls, reason.count) for reason in verdict.reasons], [("P", 1)]
        )

    def test_residual_phone_blocks(self) -> None:
        payload = {"messages": [{"role": "tool", "content": f"телефон {PHONE}"}]}
        verdict = self.validator.validate_outgoing(payload)
        self.assertFalse(verdict.clean)
        self.assertEqual([reason.cls for reason in verdict.reasons], ["T"])

    def test_tokens_are_never_reported_as_residue(self) -> None:
        """A table column headed ФИО full of tokens must not block the request."""
        payload = {
            "messages": [
                {
                    "role": "tool",
                    "content": f"ФИО,Телефон,Карта\n{token()},{token('T')},12 мес\n",
                }
            ]
        }
        verdict = self.validator.validate_outgoing(payload)
        self.assertTrue(verdict.clean, msg=str(verdict.reasons))

    def test_compact_code_in_a_csv_cell_is_not_residue(self) -> None:
        """Компактный код без обрамления не должен считаться остаточными ПД.

        Phase-4 убрала обрамление, поэтому проверка «внутри кода» больше не может
        опираться на скобки: иначе каждая обезличенная выгрузка стала бы 403.
        """
        payload = {
            "messages": [
                {"role": "tool", "content": f"ФИО,Телефон,Карта\n{token()},{token('T')},12 мес\n"}
            ]
        }
        verdict = self.validator.validate_outgoing(payload)
        self.assertTrue(verdict.clean, msg=str(verdict.reasons))

    def test_serialization_failure_blocks(self) -> None:
        verdict = self.validator.validate_outgoing({"broken": {1, 2, 3}})
        self.assertFalse(verdict.clean)
        self.assertEqual(verdict.code, "validator_error")

    def test_verdict_is_a_value_object(self) -> None:
        verdict = ValidationVerdict(clean=True)
        with self.assertRaises(Exception):
            verdict.clean = False  # type: ignore[misc] - frozen on purpose


class RepairPassTests(unittest.TestCase):
    """Вариант 1 (Phase-15 шаг 2): найденный остаток заменяется, а не блокирует запрос.

    Заслон обязан остаться судьёй: починка не отменяет проверку, а повторная проверка
    решает, идти запросу или нет.
    """

    def setUp(self) -> None:
        self.validator = ResidualPiiValidator()
        # Промах детектора: значение осталось в исходящем запросе как есть (так выглядит
        # инцидент — первый проход его не заменил).
        self.original = {"messages": [{"role": "user", "content": f"Клиент {FIO}, продлил карту."}]}
        self.anonymized = {
            "messages": [{"role": "user", "content": f"Клиент {FIO}, продлил карту."}]
        }

    def test_residual_is_replaced_and_the_verdict_goes_clean(self) -> None:
        """Остаток уходит кодом той же фабрики; повторная проверка чиста."""
        issued: list[tuple[str, str, str]] = []

        def issue(cls: str, identity: str, raw: str) -> str:
            issued.append((cls, identity, raw))
            return f"z{cls}482193"

        report = self.validator.repair_outgoing(self.anonymized, self.original, issue)
        self.assertEqual(report.total, 1)
        self.assertEqual(report.replaced, {"P": 1})
        self.assertEqual(report.classes, ("P",))
        self.assertIn(report.rules[0], {"tabular", "rules", "names"})
        # Фабрика кодов получила именно то значение, которое нашёл заслон, — не нормализованное,
        # а наблюдённое: код обязан совпасть с тем, что выдал бы первый проход.
        self.assertEqual(issued, [("P", "иванов иван иванович", FIO)])
        text = self.anonymized["messages"][0]["content"]
        self.assertNotIn(FIO, text)
        self.assertIn("zP482193", text)
        self.assertTrue(self.validator.validate_outgoing(self.anonymized, self.original).clean)

    def test_the_repaired_result_is_judged_again_not_trusted(self) -> None:
        """«Починено» — это не слово исполнителя: судит повторная проверка.

        Фабрика кодов, вернувшая само значение (сломанный или чужой источник кодов), не
        должна превратиться в разрешение на отправку. Замены при этом не происходит — и
        счётчик замен обязан это показать, а не записать единицу ради красивого отчёта.
        """
        report = self.validator.repair_outgoing(
            self.anonymized, self.original, lambda cls, identity, raw: raw
        )
        self.assertEqual(report.total, 0, msg="код, равный значению, — не замена")
        self.assertIn(FIO, self.anonymized["messages"][0]["content"])
        verdict = self.validator.validate_outgoing(self.anonymized, self.original)
        self.assertFalse(verdict.clean)
        self.assertEqual(verdict.code, "residual_pii")

    def test_failed_replacement_propagates_and_leaves_the_residual(self) -> None:
        """Сбой замены не глотается: запрос остаётся грязным, и его ждёт блокировка."""

        def issue(cls: str, identity: str, raw: str) -> str:
            raise TokenizeError("TOKENIZE_STORE_FAILED", "store is gone")

        with self.assertRaises(TokenizeError):
            self.validator.repair_outgoing(self.anonymized, self.original, issue)
        self.assertIn(FIO, self.anonymized["messages"][0]["content"])
        self.assertFalse(self.validator.validate_outgoing(self.anonymized, self.original).clean)

    def test_a_link_segment_is_not_repaired(self) -> None:
        """Правило починки совпадает с правилом проверки: слово внутри ссылки не остаток."""
        original = {
            "messages": [{"role": "user", "content": f"https://example.ru/cards?name={FIO}&view=1"}]
        }
        anonymized = {
            "messages": [{"role": "user", "content": f"https://example.ru/cards?name={FIO}&view=1"}]
        }
        self.assertTrue(self.validator.validate_outgoing(anonymized, original).clean)
        report = self.validator.repair_outgoing(anonymized, original, lambda cls, identity, raw: "zP1")
        self.assertEqual(report.total, 0)

    def test_a_value_inside_a_link_does_not_deadlock_the_repair(self) -> None:
        """Живой инцидент 19.09.2026: копия внутри ссылки держала запрос в вечном отказе.

        Заслон судит вхождение по оригиналу и освобождает только то вхождение, которое само
        стоит в ссылке. Копия значения внутри ссылки при этом попадает в окно соседа и
        считается остатком, а починка отказывалась её менять (своё правило ссылки) — проход
        не давал прогресса, и запрос уходил в отказ `replacement_failed` навсегда: владелец
        без ответа. Починка обязана закрыть то, чего требует проверка.
        """
        text = f"Клиент {FIO} /{FIO}"
        original = {"messages": [{"role": "user", "content": text}]}
        anonymized = {"messages": [{"role": "user", "content": text}]}
        self.assertFalse(self.validator.validate_outgoing(anonymized, original).clean)

        issued: list[str] = []

        def issue(cls: str, identity: str, raw: str) -> str:
            issued.append(raw)
            return "zP482193"

        report = self.validator.repair_outgoing(anonymized, original, issue)
        self.assertGreaterEqual(report.total, 2)
        patched = anonymized["messages"][0]["content"]
        self.assertNotIn(FIO, patched)
        self.assertEqual(patched.count("zP482193"), 2)
        self.assertTrue(
            self.validator.validate_outgoing(anonymized, original).clean,
            msg="остаток остался — запрос снова уйдёт в отказ",
        )

    def test_every_occurrence_of_the_residual_is_replaced(self) -> None:
        """Остаток уходит кодом во всех вхождениях строки (дефект 19.09.2026).

        Живой инцидент: пять находок, пять замен и всё равно отказ replacement_failed.
        Причина — починка правила одно вхождение (то, что попадало в окно после соседа),
        а проверка продолжала видеть соседние вхождения того же значения.
        """
        text = f"Клиент {FIO}, повтор {FIO}, ещё раз {FIO}."
        original = {"messages": [{"role": "user", "content": text}]}
        anonymized = {"messages": [{"role": "user", "content": text}]}
        verdict = self.validator.validate_outgoing(anonymized, original)
        self.assertEqual([(reason.cls, reason.count) for reason in verdict.reasons], [("P", 3)])
        issued: list[tuple[str, str, str]] = []

        def issue(cls: str, identity: str, raw: str) -> str:
            issued.append((cls, identity, raw))
            return "zP482193"

        report = self.validator.repair_outgoing(anonymized, original, issue)
        self.assertEqual(report.total, 3)
        self.assertEqual(report.replaced, {"P": 3})
        # Один код на значение: фабрика кодов детерминирована, и повторный вызов не нужен —
        # иначе на каждое вхождение в справочник ушла бы лишняя связка.
        self.assertEqual(issued, [("P", "иванов иван иванович", FIO)])
        body = anonymized["messages"][0]["content"]
        self.assertNotIn(FIO, body)
        self.assertEqual(body.count("zP482193"), 3)
        self.assertTrue(self.validator.validate_outgoing(anonymized, original).clean)

    def test_a_residual_written_with_another_spacing_is_replaced(self) -> None:
        """Значение с другим пробелом — тоже остаток и тоже уходит кодом.

        Токенизатор убирает вхождения точной подстрокой, поэтому запись с двойным или
        неразрывным пробелом переживает его второй проход; заслон судит по нормализованному
        тексту и обязан заменить такую запись, а не блокировать запрос из-за неё.
        """
        for separator in ("  ", "\u00a0"):
            with self.subTest(separator=repr(separator)):
                spaced = FIO.replace(" ", separator)
                original = {"messages": [{"role": "user", "content": f"Клиент {spaced}, продлил."}]}
                anonymized = {"messages": [{"role": "user", "content": f"Клиент {spaced}, продлил."}]}
                verdict = self.validator.validate_outgoing(anonymized, original)
                self.assertFalse(verdict.clean)
                report = self.validator.repair_outgoing(
                    anonymized, original, lambda cls, identity, raw: "zP777"
                )
                self.assertEqual(report.total, 1)
                body = anonymized["messages"][0]["content"]
                self.assertEqual(body, "Клиент zP777, продлил.")
                self.assertTrue(self.validator.validate_outgoing(anonymized, original).clean)

    def test_the_repair_stops_instead_of_looping_when_there_is_nothing_to_replace(self) -> None:
        """Проход без замены завершает починку: сдвиг границ не превращается в цикл."""
        original = {"messages": [{"role": "user", "content": f"Клиент {FIO}."}]}
        anonymized = {"messages": [{"role": "user", "content": "Клиент →."}]}
        report = self.validator.repair_outgoing(
            anonymized, original, lambda cls, identity, raw: "zP1"
        )
        self.assertEqual(report.total, 0)
        self.assertEqual(anonymized["messages"][0]["content"], "Клиент →.")
# END_BLOCK_TEST_VALIDATOR


if __name__ == "__main__":
    unittest.main()
