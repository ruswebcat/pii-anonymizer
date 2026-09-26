# FILE: tests/test_token_factory.py
# VERSION: 2.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-TOKEN-GEN contract: compact codes are deterministic across processes and turns, hide the value, resolve collisions deterministically, and keep every older surface readable.
#   SCOPE: compact code shape, determinism across processes, deterministic candidate walk, case-insensitive recognition, legacy surface compatibility, malformed rejection, key sensitivity.
#   DEPENDS: M-TOKEN-GEN, M-NORM
#   LINKS: V-M-TOKEN-GEN, M-TOKEN-GEN
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   TokenFactoryTests - unittest case set for make_token, candidate_tokens, parse_token, canonical_token, find_tokens
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v2.0.0 - Phase-4: compact code (z + class + 8 base32) replaced the framed 12-character token; collisions resolved by a deterministic candidate walk; case-insensitive recognition.
# END_CHANGE_SUMMARY

import os
import subprocess
import sys
import unittest
from itertools import islice

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.normalize import normalize  # noqa: E402
from src.token_factory import (  # noqa: E402
    CODE_PATTERN,
    TokenError,
    candidate_tokens,
    canonical_token,
    find_tokens,
    is_valid_token,
    make_token,
    parse_token,
)

KEY = b"unit-test-key-material-32-bytes!!"
LEGACY_FRAMED = "[[T-ABCDEF234567]]"
LEGACY_EXOTIC = "\u27e6T-ABCDEF234567\u27e7"


class TokenFactoryTests(unittest.TestCase):
    def test_same_input_same_token(self) -> None:
        first = make_token("T", normalize("T", "+7 900 000-00-01"), KEY)
        second = make_token("T", normalize("T", "89000000001"), KEY)
        self.assertEqual(first, second)

    def test_token_hides_the_value(self) -> None:
        token = make_token("P", normalize("P", "Иванов Сергей"), KEY)
        self.assertNotIn("иванов", token.lower().replace("z", "", 1))
        self.assertNotIn("Иванов", token)

    def test_different_classes_produce_different_tokens(self) -> None:
        self.assertNotEqual(make_token("P", "35209", KEY), make_token("C", "35209", KEY))

    def test_different_keys_produce_different_tokens(self) -> None:
        first = make_token("T", "79000000001", KEY)
        second = make_token("T", "79000000001", b"another-key-material-32-bytes!!!")
        self.assertNotEqual(first, second)

    def test_code_shape_is_ten_characters(self) -> None:
        """Префикс z, буква класса, 8 знаков base32 — 40 бит, без обрамления.

        Обрамление убрано по замеру 16.09.2026: экзотические скобки модель
        искажала в 6 случаях из 6, а скобки и дефис стоили токенов провайдера.
        """
        token = make_token("T", "79000000001", KEY)
        self.assertTrue(token.startswith("zT"), token)
        self.assertEqual(len(token), 10)
        self.assertTrue(CODE_PATTERN.fullmatch(token), token)

    def test_parse_token_round_trip(self) -> None:
        token = make_token("E", "client@example.ru", KEY)
        cls, code = parse_token(token)
        self.assertEqual(cls, "E")
        self.assertEqual(len(code), 8)

    def test_code_is_recognised_in_any_case(self) -> None:
        token = make_token("P", "иванов иван", KEY)
        for variant in (token, token.lower(), token.upper(), token.swapcase()):
            self.assertEqual(parse_token(variant), parse_token(token), variant)
            self.assertEqual(canonical_token(variant), token, variant)
            self.assertTrue(is_valid_token(variant), variant)

    def test_candidate_walk_is_deterministic_and_distinct(self) -> None:
        """Обход кандидатов нужен для разрешения коллизий и обязан быть детерминированным.

        Недетерминированный обход сломал бы кэш модели: одно и то же значение
        получило бы разные коды в разных запросах.
        """
        first_run = list(islice(candidate_tokens("P", "иванов иван", KEY), 4))
        second_run = list(islice(candidate_tokens("P", "иванов иван", KEY), 4))
        self.assertEqual(first_run, second_run)
        self.assertEqual(first_run[0], make_token("P", "иванов иван", KEY))
        self.assertEqual(len(set(first_run)), 4)
        for candidate in first_run:
            self.assertTrue(CODE_PATTERN.fullmatch(candidate), candidate)

    def test_candidates_differ_between_values(self) -> None:
        left = list(islice(candidate_tokens("P", "иванов иван", KEY), 2))
        right = list(islice(candidate_tokens("P", "петров пётр", KEY), 2))
        self.assertFalse(set(left) & set(right))

    def test_legacy_framed_tokens_still_parse(self) -> None:
        for legacy in (LEGACY_FRAMED, LEGACY_EXOTIC):
            self.assertEqual(parse_token(legacy), ("T", "ABCDEF234567"), legacy)
            self.assertEqual(canonical_token(legacy), LEGACY_FRAMED, legacy)
            self.assertTrue(is_valid_token(legacy), legacy)

    def test_legacy_bare_token_still_parses(self) -> None:
        """Модель умеет терять обрамление — такой код обязан остаться распознаваемым."""
        bare = "T-ABCDEF234567"
        self.assertEqual(parse_token(bare), ("T", "ABCDEF234567"))
        self.assertEqual(canonical_token(bare), LEGACY_FRAMED)

    def test_malformed_token_rejected(self) -> None:
        for candidate in [
            "",
            "T-ABCDEF",
            "[[T-abc]]",
            "[[Z-ABCDEF234567]]",
            "zT123",
            "zZABCDEF23",
            "zT12345678",
            "no token here",
        ]:
            with self.assertRaises(TokenError, msg=candidate):
                parse_token(candidate)

    def test_is_valid_token(self) -> None:
        token = make_token("C", "35209", KEY)
        self.assertTrue(is_valid_token(token))
        self.assertFalse(is_valid_token(token + "x"))

    def test_find_tokens_returns_spans(self) -> None:
        token = make_token("C", "35209", KEY)
        text = f"клиент {token} купил карту"
        spans = find_tokens(text)
        self.assertEqual(len(spans), 1)
        start, end, cls, full = spans[0]
        self.assertEqual(cls, "C")
        self.assertEqual(full, token)
        self.assertEqual(text[start:end], token)

    def test_find_tokens_covers_every_surface(self) -> None:
        compact = make_token("C", "35209", KEY)
        text = f"новый {compact} старый {LEGACY_FRAMED} экзотика {LEGACY_EXOTIC}"
        found = [span[3] for span in find_tokens(text)]
        self.assertEqual(found, [compact, LEGACY_FRAMED, LEGACY_FRAMED])

    def test_code_glued_to_a_word_is_not_a_token(self) -> None:
        token = make_token("C", "35209", KEY)
        self.assertEqual(find_tokens(f"идентификатор{token}"), [])

    def test_empty_key_rejected(self) -> None:
        with self.assertRaises(TokenError) as ctx:
            make_token("T", "79000000001", b"")
        self.assertEqual(ctx.exception.code, "TOKEN_KEY_UNAVAILABLE")

    def test_determinism_across_processes(self) -> None:
        script = (
            "import sys; sys.path.insert(0, %r); "
            "from src.token_factory import make_token; "
            "print(make_token('T', '79000000001', %r))"
            % (os.path.dirname(os.path.dirname(os.path.abspath(__file__))), KEY)
        )
        out = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, check=True
        ).stdout.strip()
        self.assertEqual(out, make_token("T", "79000000001", KEY))


if __name__ == "__main__":
    unittest.main()
