# FILE: tests/test_dictionary_signature.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Guard the 26.09.2026 repair of the "dictionary changed" wiring: the detector really exposes the live dictionary signature (path, mtime, size), so the tokenizer block cache and the validator pair cache drop on a real dictionary file change and keep their hits when the file is untouched.
#   SCOPE: signature liveness and path inclusion through NameDetector and its _KnownValues wrapper, tokenization cache reset on a real file change, validator pair cache reset on the same change, byte-identity of the anonymized result across the change, graceful None for file-less and broken sources.
#   DEPENDS: M-DICT, M-DETECT-NAME, M-TOKENIZER, M-VALIDATOR, M-CACHE
#   LINKS: V-M-DETECT-NAME, V-M-CACHE, V-M-VALIDATOR, fn-dictionary_signature
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   fn-write_dictionary - заглушечный справочник на диске
#   fn-bump_mtime - сдвинуть время правки файла, не меняя содержимое
#   fn-payload_of - тело запроса с одним сообщением
#   DictionarySignatureTests - подпись живая, несёт путь и меняется при правке файла
#   TokenizerCacheResetTests - кэш токенизации сбрасывается при смене справочника и попадает без неё
#   ValidatorCacheResetTests - кэш пар заслона ведёт себя так же
#   AnonymizationByteIdentityTests - обезличивание не изменилось: попадание равно промаху
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - 26.09.2026: проверки краснеют на коде до правки (подпись была вечным None) и зеленеют после починки проводки подписи через _KnownValues.
# END_CHANGE_SUMMARY

"""Проверки смены справочника для кэшей токенизатора и заслона.

Находка аудита 26.09.2026: `NameDetector.dictionary_signature()` всегда возвращал `None`,
поэтому `_dictionary_changed()` в токенизаторе и `_pair_cache_is_stale()` в заслоне не
срабатывали, а справочник меняется без перезапуска службы. Здесь проверяется, что подпись
живая, доходит до потребителей и что на смене файла кэши действительно сбрасываются —
а без изменений лишней работы не делают.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.cache import TokenizationCache  # noqa: E402
from src.detect_name import NameDetector  # noqa: E402
from src.detect_ner import NerDetector  # noqa: E402
from src.dictionary import PiiDictionary, dictionary_signature, live_file_state  # noqa: E402
from src.map_store import TokenMapStore  # noqa: E402
from src.router import build_service  # noqa: E402
from src.tokenizer import PayloadTokenizer  # noqa: E402
from src.validator import ResidualPiiValidator  # noqa: E402
from tests.harness import FakeUpstream, temp_config  # noqa: E402

# START_BLOCK_TEST_DICTIONARY_SIGNATURE
CLIENT_NAME = "Иванов Иван Иванович"
CLIENT_PHONE = "79000000001"
NAME_BLOCK = f"Отчёт для клиента {CLIENT_NAME} готов, продлений больше."
CLEAN_TEXT = "Сводка за неделю: продано 12 карт, выручка выросла."


def write_dictionary(path: str, entries: dict[str, list[str]]) -> str:
    """Записать заглушечный справочник на диск и вернуть путь."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(entries, handle, ensure_ascii=False)
    return path


def bump_mtime(path: str, seconds: float = 5.0) -> None:
    """Сдвинуть время правки файла вперёд, не трогая содержимое."""
    info = os.stat(path)
    os.utime(path, (info.st_atime, info.st_mtime + seconds))


def payload_of(text: str) -> dict:
    """Тело запроса с одним сообщением — так же плоский, как приходит из Hermes."""
    return {"model": "stub", "messages": [{"role": "user", "content": text}]}
# END_BLOCK_TEST_DICTIONARY_SIGNATURE


class DictionarySignatureTests(unittest.TestCase):
    """Подпись справочника живая: путь входит в неё, правка файла её меняет."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "dict_raw.json")
        write_dictionary(self.path, {"P": [CLIENT_NAME], "T": [CLIENT_PHONE]})

    def test_the_detector_signature_carries_the_path(self) -> None:
        detector = NameDetector(PiiDictionary(self.path))
        signature = detector.dictionary_signature()
        self.assertTrue(signature and signature.startswith(self.path + "|"), signature)
        # Подпись детектора и подпись справочника — один и тот же код, а не две формулы.
        self.assertEqual(signature, dictionary_signature(detector._dictionary))

    def test_the_signature_changes_when_the_file_is_edited(self) -> None:
        detector = NameDetector(PiiDictionary(self.path))
        before = detector.dictionary_signature()
        bump_mtime(self.path)
        self.assertNotEqual(before, detector.dictionary_signature(), "подпись обязана реагировать на правку файла")

    def test_the_signature_changes_when_the_size_changes(self) -> None:
        detector = NameDetector(PiiDictionary(self.path))
        before = detector.dictionary_signature()
        write_dictionary(
            self.path,
            {"P": [CLIENT_NAME, "Заглушкин Пётр Ильич"], "T": [CLIENT_PHONE]},
        )
        bump_mtime(self.path)
        self.assertNotEqual(before, detector.dictionary_signature(), "размер входит в подпись")

    def test_a_different_file_gives_a_different_signature(self) -> None:
        other = os.path.join(self._tmp.name, "other.json")
        shutil.copyfile(self.path, other)
        first = NameDetector(PiiDictionary(self.path)).dictionary_signature()
        second = NameDetector(PiiDictionary(other)).dictionary_signature()
        self.assertNotEqual(first, second, "замена справочника другим файлом меняет подпись")

    def test_a_source_without_a_file_has_no_signature(self) -> None:
        self.assertIsNone(NameDetector({"P": [CLIENT_NAME]}).dictionary_signature())
        self.assertIsNone(dictionary_signature({"P": [CLIENT_NAME]}))
        self.assertIsNone(live_file_state(object()))

    def test_a_broken_source_does_not_raise(self) -> None:
        class Broken:
            """Источник, который падает на подписи: кэш не должен терять заслон."""

            def file_signature(self) -> tuple[float, int]:
                raise OSError("boom")

        self.assertIsNone(live_file_state(Broken()))
        self.assertIsNone(dictionary_signature(Broken()))


class _CountingTokenizer(PayloadTokenizer):
    """Токенизатор с кэшем: считаем попадания через счётчики самого кэша."""

    def __init__(self, store: TokenMapStore, names: NameDetector) -> None:
        self.cache = TokenizationCache(64)
        super().__init__(b"t" * 32, store, names, cache=self.cache)


class TokenizerCacheResetTests(unittest.TestCase):
    """Кэш токенизации сбрасывается при смене справочника и попадает без неё."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "dict_raw.json")
        write_dictionary(self.path, {"P": [CLIENT_NAME], "T": [CLIENT_PHONE]})
        self.store = TokenMapStore(os.path.join(self._tmp.name, "map.db"), b"f" * 32, 90)
        self.addCleanup(self.store.close)

    def _tokenizer(self) -> _CountingTokenizer:
        return _CountingTokenizer(self.store, NameDetector(PiiDictionary(self.path)))

    def test_a_real_dictionary_change_drops_the_block_cache(self) -> None:
        tokenizer = self._tokenizer()
        first = tokenizer.tokenize_text(NAME_BLOCK)
        self.assertEqual(tokenizer.cache.stats()["hits"], 0)
        second = tokenizer.tokenize_text(NAME_BLOCK)
        self.assertEqual(second, first)
        self.assertEqual(tokenizer.cache.stats()["hits"], 1, "повтор блока обязан попасть в кэш")

        bump_mtime(self.path)
        after_change = tokenizer.tokenize_text(NAME_BLOCK)
        self.assertEqual(after_change, first, "смена подписи не смеет менять сам результат")
        self.assertEqual(tokenizer.cache.stats()["hits"], 1, "запись пережила смену справочника")

        self.assertEqual(tokenizer.tokenize_text(NAME_BLOCK), first)
        self.assertEqual(tokenizer.cache.stats()["hits"], 2, "кэш обязан снова попадать")

    def test_an_untouched_dictionary_keeps_the_hits(self) -> None:
        tokenizer = self._tokenizer()
        tokenizer.tokenize_text(NAME_BLOCK)
        tokenizer.tokenize_text(NAME_BLOCK)
        tokenizer.tokenize_text(NAME_BLOCK)
        self.assertEqual(tokenizer.cache.stats()["hits"], 2, "неизменный справочник не сбрасывает кэш")


class _CountingValidator(ResidualPiiValidator):
    """Заслон со счётчиком обращений к детекторам."""

    def __init__(self, names: NameDetector) -> None:
        super().__init__(names)
        self.scans = 0

    def _channel_matches(self, text: str):  # noqa: ANN201 - форма родителя
        self.scans += 1
        return super()._channel_matches(text)


class ValidatorCacheResetTests(unittest.TestCase):
    """Кэш пар заслона сбрасывается при смене справочника и попадает без неё."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "dict_raw.json")
        write_dictionary(self.path, {"P": [CLIENT_NAME], "T": [CLIENT_PHONE]})

    def _validator(self) -> _CountingValidator:
        return _CountingValidator(NameDetector(PiiDictionary(self.path)))

    def test_a_real_dictionary_change_drops_the_pair_cache(self) -> None:
        validator = self._validator()
        payload = payload_of(CLEAN_TEXT)
        for _ in range(2):
            validator.validate_outgoing(payload_of(CLEAN_TEXT), payload)
        baseline = validator.scans
        self.assertGreater(baseline, 0, "первый раз пара обязана быть разобрана")
        self.assertGreaterEqual(validator.pair_cache_stats()["size"], 1)

        bump_mtime(self.path)
        validator.validate_outgoing(payload_of(CLEAN_TEXT), payload)
        self.assertGreater(validator.scans, baseline, "после смены справочника пара судится снова")

    def test_an_untouched_dictionary_keeps_the_pair_hit(self) -> None:
        validator = self._validator()
        payload = payload_of(CLEAN_TEXT)
        validator.validate_outgoing(payload_of(CLEAN_TEXT), payload)
        baseline = validator.scans
        validator.validate_outgoing(payload_of(CLEAN_TEXT), payload)
        self.assertEqual(baseline, validator.scans, "неизменный справочник оставляет попадание")


class AnonymizationByteIdentityTests(unittest.TestCase):
    """Проводка подписи не изменила поведение обезличивания: на том же запросе — те же байты."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "dict_raw.json")
        write_dictionary(self.path, {"P": [CLIENT_NAME], "T": [CLIENT_PHONE]})

    def _service(self):
        upstream = FakeUpstream()
        service = build_service(
            temp_config(self._tmp.name),
            upstream=upstream,
            validator=None,
            ner=NerDetector("none"),
            dictionary=PiiDictionary(self.path),
        )
        self.addCleanup(service.close)
        return service, upstream

    def _anonymize(self, service, upstream, payload: dict) -> str:
        status, body = service.handle_chat_completions(
            payload, "ds", "/v1/chat/completions", "mattermost"
        )
        self.assertEqual(status, 200, msg=json.dumps(body, ensure_ascii=False)[:200])
        return json.dumps(upstream.last_payload, ensure_ascii=False, sort_keys=True)

    def test_the_outgoing_bytes_survive_a_dictionary_touch(self) -> None:
        service, upstream = self._service()
        payload = {
            "model": "deepseek-flash",
            "stream": False,
            "messages": [{"role": "user", "content": NAME_BLOCK}],
        }
        first = self._anonymize(service, upstream, payload)
        self.assertNotIn(CLIENT_NAME, first)

        # Прогретый кэш: повтор даёт те же байты.
        self.assertEqual(first, self._anonymize(service, upstream, payload))

        # Справочник «потрогали» (время правки сдвинулось) — результат обязан совпасть байт-в-байт.
        bump_mtime(self.path)
        self.assertEqual(first, self._anonymize(service, upstream, payload))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
