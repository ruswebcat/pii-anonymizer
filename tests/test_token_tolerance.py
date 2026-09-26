# FILE: tests/test_token_tolerance.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Проверить, что искажённая копия кода (разделители, кириллица, цифровой двойник) опознаётся и восстанавливается к исходному виду, а обычный текст кодом не считается.
#   SCOPE: толерантный проход нормализации в token_factory, защита от ложных срабатываний и от выдумывания усечённых кодов.
#   DEPENDS: src.token_factory
#   LINKS: M-TOKEN-GEN, fn-normalise_code_run, fn-find_tokens, V-M-TOKEN-GEN
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   TokenToleranceTests - искажения кода, которые модель допускает при переписывании
#   NoFalsePositiveTests - обычный текст и усечённые коды не должны опознаваться
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-20: закрыт класс «код доехал до клиента» (замер 23.09.2026).
# END_CHANGE_SUMMARY

import unittest

from src.token_factory import (
    CODE_SEPARATORS,
    CONFUSED_TO_BASE32,
    find_tokens,
    normalise_code_run,
)

# Валидный компактный код: класс P, восемь знаков base32 (без 0, 1, 8, 9).
CODE = "zPABCDE2GH"
CLASS = "P"


def canonicals(text: str) -> list[str]:
    return [item[3] for item in find_tokens(text)]


# START_BLOCK_TOLERANCE_TESTS
class TokenToleranceTests(unittest.TestCase):
    """Искажения, которые модель допускает, переписывая код."""

    def test_exact_code_is_found(self) -> None:
        self.assertEqual(canonicals(f"значение: {CODE}"), [CODE])

    def test_separator_inside_code(self) -> None:
        """Пробел, дефис, неразрывный пробел и невидимый знак внутри кода — вёрстка и перенос."""
        for broken in (
            f"{CODE[:4]} {CODE[4:]}",
            f"{CODE[:4]}-{CODE[4:]}",
            f"{CODE[:4]}\u00a0{CODE[4:]}",
            f"{CODE[:4]}\u200b{CODE[4:]}",
            f"{CODE[:3]} {CODE[3]} {CODE[4:]}",
        ):
            with self.subTest(broken=broken):
                self.assertEqual(canonicals(f"номер: {broken}."), [CODE])

    def test_markup_around_code(self) -> None:
        """Модель оборачивает код в разметку — это не мешает восстановлению."""
        for broken in (f"**{CODE}**", f"`{CODE}`", f"«{CODE}»"):
            with self.subTest(broken=broken):
                self.assertEqual(canonicals(broken), [CODE])

    def test_cyrillic_lookalikes(self) -> None:
        """Русская раскладка внутри кода: буквы выглядят как латинские."""
        broken = "".join({"A": "А", "B": "В", "C": "С", "E": "Е", "G": "Г"}.get(ch, ch) for ch in CODE)
        self.assertEqual(canonicals(f"код {broken}"), [CODE])

    def test_digit_confusion(self) -> None:
        """Цифровой двойник вместо буквы base32: O/0, I/1, B/8, G/9."""
        base = "zPOBI2GH4L"
        broken = base.replace("O", "0").replace("I", "1").replace("B", "8")
        self.assertEqual(canonicals(broken), [base])

    def test_code_is_found_only_once(self) -> None:
        """Толерантный проход не должен задваивать уже найденный код."""
        self.assertEqual(canonicals(f"вот {CODE}, ещё раз {CODE}"), [CODE, CODE])

    def test_code_inside_sentence_keeps_words(self) -> None:
        """Код в середине фразы спасается, соседние слова не приклеиваются."""
        broken = f"{CODE[:4]} {CODE[4:]}"
        self.assertEqual(canonicals(f"скопируй {broken} сюда"), [CODE])

    def test_normalise_code_run_contract(self) -> None:
        self.assertEqual(normalise_code_run(CODE), (CLASS, CODE))
        self.assertIsNone(normalise_code_run(CODE[:6]))
        self.assertIsNone(normalise_code_run("wordwordword"))
        self.assertIsNone(normalise_code_run("zQABCDE2GH"))  # класса Q нет

    def test_confusion_table_is_reversible(self) -> None:
        """Таблица подмен не должна содержать самих букв base32 в качестве ключей."""
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567":
            self.assertNotIn(letter, CONFUSED_TO_BASE32)
        self.assertNotIn("z", CONFUSED_TO_BASE32)
# END_BLOCK_TOLERANCE_TESTS


# START_BLOCK_NO_FALSE_POSITIVE_TESTS
class NoFalsePositiveTests(unittest.TestCase):
    """Что кодом считаться не должно — иначе появились бы выдуманные значения."""

    def test_ordinary_russian_text(self) -> None:
        text = "Замерзли, закупили зелень, заказали зал и занятие. Звонил заказчику."

        self.assertEqual(find_tokens(text), [])

    def test_ordinary_latin_text(self) -> None:
        text = "zebra zone zoom zephyr zzz z2 z7"

        self.assertEqual(find_tokens(text), [])

    def test_truncated_code_is_not_invented(self) -> None:
        """Усечённый код восстановить нельзя — догадка была бы выдуманным значением."""
        self.assertEqual(find_tokens(f"код {CODE[:6]}"), [])

    def test_separators_are_not_a_code_by_themselves(self) -> None:
        self.assertEqual(find_tokens("z" + " " * 12), [])

    def test_long_word_starting_with_z(self) -> None:
        text = "zapisalis, zanimalis, zaboleli"

        self.assertEqual(find_tokens(text), [])
# END_BLOCK_NO_FALSE_POSITIVE_TESTS


if __name__ == "__main__":
    unittest.main()
