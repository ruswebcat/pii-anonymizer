# FILE: tests/test_validator_pair_cache.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the validator pair cache: a clean pair is not re-scanned, a dirty pair is never remembered as clean, the cache dies with the dictionary and stays bounded.
#   SCOPE: counting detector calls through a spy, clean/dirty behaviour, dictionary signature invalidation, bound, repair path.
#   DEPENDS: src/validator.py
#   LINKS: M-VALIDATOR, V-M-VALIDATOR, Phase-19
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   PairCacheTests - behaviour of the validator pair cache
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-19 (23.09.2026): проверки кэша пар заслона; в текстах тестов только заглушки.
# END_CHANGE_SUMMARY
"""The gate must get cheaper on repeated history without ever going blind."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.validator import ResidualPiiValidator  # noqa: E402

# START_BLOCK_TEST_VALIDATOR_PAIR_CACHE
CLEAN_ORIGINAL = "Сводка за неделю: продано 12 карт, выручка выросла."
CLEAN_ANONYMIZED = "Сводка за неделю: продано 12 карт, выручка выросла."
DIRTY_ORIGINAL = "Клиент Заглушкин Заглушка Заглушкович, телефон 79000000001."
DIRTY_ANONYMIZED = "Клиент Заглушкин Заглушка Заглушкович, телефон 79000000001."


def payload_of(text: str) -> dict:
    """Тело запроса с одним сообщением — так же плоский, как приходит из Hermes."""
    return {"model": "stub", "messages": [{"role": "user", "content": text}]}


class CountingValidator(ResidualPiiValidator):
    """Заслон со счётчиком обращений к детекторам: проверяем, что работа не повторяется."""

    def __init__(self) -> None:
        super().__init__()
        self.scans = 0

    def _channel_matches(self, text: str):  # noqa: ANN201 - форма родителя
        self.scans += 1
        return super()._channel_matches(text)


class PairCacheTests(unittest.TestCase):
    """Чистая пара считается один раз, грязная никогда не считается чистой."""

    def test_clean_pair_is_scanned_once(self) -> None:
        validator = CountingValidator()
        first = validator.validate_outgoing(payload_of(CLEAN_ANONYMIZED), payload_of(CLEAN_ORIGINAL))
        scans_after_first = validator.scans
        second = validator.validate_outgoing(payload_of(CLEAN_ANONYMIZED), payload_of(CLEAN_ORIGINAL))
        self.assertTrue(first.clean and second.clean)
        self.assertGreater(scans_after_first, 0, "первый раз строка обязана быть разобрана")
        self.assertEqual(scans_after_first, validator.scans, "повтор пары не разбирается заново")

    def test_dirty_pair_is_never_remembered_as_clean(self) -> None:
        validator = CountingValidator()
        first = validator.validate_outgoing(payload_of(DIRTY_ANONYMIZED), payload_of(DIRTY_ORIGINAL))
        second = validator.validate_outgoing(payload_of(DIRTY_ANONYMIZED), payload_of(DIRTY_ORIGINAL))
        self.assertFalse(first.clean, "значение на месте — заслон обязан это видеть")
        self.assertFalse(second.clean, "повтор не смеет объявить грязную пару чистой")

    def test_changed_outgoing_text_is_scanned_again(self) -> None:
        validator = CountingValidator()
        validator.validate_outgoing(payload_of(CLEAN_ANONYMIZED), payload_of(CLEAN_ORIGINAL))
        baseline = validator.scans
        validator.validate_outgoing(payload_of(CLEAN_ANONYMIZED + " Хвост."), payload_of(CLEAN_ORIGINAL))
        self.assertGreater(validator.scans, baseline, "изменённая пара судится заново")

    def test_dictionary_reload_drops_the_cache(self) -> None:
        validator = CountingValidator()
        signature = {"value": "первый"}

        def dictionary_signature() -> str:
            return signature["value"]

        validator._names.dictionary_signature = dictionary_signature  # type: ignore[attr-defined]
        validator.validate_outgoing(payload_of(CLEAN_ANONYMIZED), payload_of(CLEAN_ORIGINAL))
        self.assertGreaterEqual(validator.pair_cache_stats()["size"], 1)
        signature["value"] = "второй"
        baseline = validator.scans
        validator.validate_outgoing(payload_of(CLEAN_ANONYMIZED), payload_of(CLEAN_ORIGINAL))
        self.assertGreater(validator.scans, baseline, "после перезагрузки справочника пара судится снова")

    def test_cache_is_bounded(self) -> None:
        validator = CountingValidator()
        validator._pair_cache_limit = 2
        for index in range(5):
            text = f"{CLEAN_ORIGINAL} Вариант {index}."
            validator.validate_outgoing(payload_of(text), payload_of(text))
        stats = validator.pair_cache_stats()
        self.assertEqual(2, stats["size"])
        self.assertEqual(2, stats["limit"])

    def test_absent_original_keeps_the_strict_path(self) -> None:
        """Без оригинала проверка идёт по обезличенному телу — кэш пар тут не участвует."""
        validator = CountingValidator()
        verdict = validator.validate_outgoing(payload_of(CLEAN_ANONYMIZED))
        self.assertTrue(verdict.clean)
        self.assertEqual(0, validator.scans, "этот путь судит обезличенный текст, а не пары")
        self.assertEqual(0, validator.pair_cache_stats()["size"], "кэш пар на нём не заполняется")
# END_BLOCK_TEST_VALIDATOR_PAIR_CACHE


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
