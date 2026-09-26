# FILE: tests/test_stream_property.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the confirmed-position criterion of M-STREAM-RELAY and prove the property «stream equals the buffered path for any split of the provider stream».
#   SCOPE: criterion tails for every code surface, lookbehind blocking, hard hold limit, random and exhaustive splits of the answer text, codes split mid-way, a code glued to a word, an escaped legacy surface, a hallucinated code outside the allow-list, tool-call arguments, trusted and untrusted channels.
#   DEPENDS: M-STREAM-RELAY, M-TOKEN-GEN, M-DETOKENIZER
#   LINKS: V-M-STREAM-RELAY, M-STREAM-RELAY, Phase-12
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   Pipeline - обезличивание запроса, выдача кодам значений, справочник на временном файле
#   build_answer - ответ модели с кодами, включая трудные случаи
#   sse_bytes - поток провайдера: кадры ответа, разрезанные на произвольные куски
#   client_text - что увидел клиент: конкатенация текста из кадров потока
#   CriterionTests - критерий подтверждённой позиции и предел удержания
#   StreamEqualsBufferedTests - property-тест «поток равен непотоковому пути»
#   ToolArgumentPropertyTests - аргументы инструментов при любом разбиении
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-12 шаг 5: свойство взято у veilstream (Apache-2.0), предел удержания — у piighost (MIT).
# END_CHANGE_SUMMARY

"""Свойство потока: при любом разбиении результат тот же, что у непотокового пути.

Почему это отдельный класс проверок. Старый разрез искал обрамляющие скобки, а компактный
код (`zP…`) обрамления не имеет — код мог разъехаться по двум кадрам, и клиент получил бы
недостроенный код вместо значения. Юнит-тест на «код, разрезанный между чанками» это ловит
только для той формы, которую в нём написали. Свойство ловит это на всех формах сразу:
как бы провайдер ни нарезал поток, текст клиента обязан совпасть с непотоковым путём —
поэтому проверка идёт сравнением, а не поиском подстроки.

Критерий подтверждённой позиции и сама постановка свойства заимствованы у veilstream
(Apache-2.0), жёсткий предел удержания — у piighost (MIT).
"""

import json
import os
import random
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.audit import AuditJournal  # noqa: E402
from src.detokenizer import PayloadDetokenizer, collect_identifiers  # noqa: E402
from src.map_store import TokenMapStore  # noqa: E402
from src.channel_policy import ChannelPolicy  # noqa: E402
from src.detect_name import NameDetector  # noqa: E402
from src.stream_relay import MAX_HOLD_CHARS, StreamRelay, confirmed_position  # noqa: E402
from src.token_factory import (  # noqa: E402
    LEGACY_OPEN,
    SENTINEL_CLOSE,
    SENTINEL_OPEN,
    find_tokens,
    token_prefix_length,
)
from src.tokenizer import PayloadTokenizer  # noqa: E402

KEY = b"stream-property-suite-key-32b!!!"
FIO = "Иванов Иван Иванович"
PHONE = "79001112233"
LEGACY_VALUE = "Печёнов Пётр Иванович"
LEGACY_CODE = f"{SENTINEL_OPEN}P-ABCDEF23GHJK{SENTINEL_CLOSE}"
ESCAPED = "\\u27e6P-ABCDEF23GHJK\\u27e7"
SESSION = "stream-property"


class Pipeline:
    """Настоящий конвейер обезличивания и восстановления на временном справочнике."""

    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TokenMapStore(os.path.join(self.tmp.name, "map.db"), fernet_key=b"f" * 32)
        self.journal = AuditJournal(os.path.join(self.tmp.name, "audit.jsonl"))
        dictionary = {"P": [FIO, "Петров Пётр Петрович"], "T": [PHONE]}
        self.tokenizer = PayloadTokenizer(KEY, self.store, NameDetector(dictionary))
        self.detokenizer = PayloadDetokenizer(self.store, ChannelPolicy(["mattermost"]), None)
        payload = {
            "model": "property-test",
            "messages": [{"role": "user", "content": f"Анкета: {FIO}, телефон {PHONE}"}],
        }
        anonymized, _stats = self.tokenizer.tokenize_payload(payload, SESSION)
        self.anonymized_text = json.dumps(anonymized, ensure_ascii=False)
        # Экранированная легаси-форма читается наравне с обрамлённой: связываем её каноническую
        # запись и берём в список выданных, чтобы проверить восстановление и на этой поверхности
        # (экранирование ломало восстановление молча — находка Phase-1).
        self.store.store(LEGACY_CODE, "P", LEGACY_VALUE)
        self.allowed = collect_identifiers(self.anonymized_text, LEGACY_CODE)

    def close(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def codes_of(self, cls: str) -> list[str]:
        """Коды класса в порядке появления в обезличенном запросе."""
        found: list[str] = []
        for span in find_tokens(self.anonymized_text):
            if span[2] == cls and span[3] not in found:
                found.append(span[3])
        return found


def build_answer(pipe: Pipeline, seed: int) -> str:
    """Ответ модели с кодами: включая случаи, на которых ломается наивный разрез."""
    rng = random.Random(seed)
    person = pipe.codes_of("P")[0]
    phone = pipe.codes_of("T")[0]
    pieces = [
        f"Клиент {person} записан, телефон {phone}.",
        # Код, приклеенный к букве: у компактного кода есть просмотр назад, и непотоковый
        # путь такой код не восстановит — поток обязан поступить так же.
        f"Служебная строка X{person} остаётся текстом.",
        # Выдуманный моделью код: его нет в запросе, восстанавливать нельзя нигде.
        "Фантом zPZZZZZZZZ не восстанавливается.",
        # Экранированная легаси-форма допускается к чтению наравне с обрамлённой.
        f"Архив: {ESCAPED} и {LEGACY_CODE}.",
        "Готово." if rng.random() < 0.5 else "Готово",
    ]
    if rng.random() < 0.5:
        # Код в самом конце ответа: правая граница появляется только с остановкой потока.
        pieces.append(f"Код в конце {phone}")
    return " ".join(pieces)


def frame(payload: dict | str) -> bytes:
    """Кадр SSE так, как его шлёт провайдер."""
    if isinstance(payload, str):
        return f"data: {payload}\n\n".encode("utf-8")
    return b"data: " + json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n\n"


def delta_frame(content: str) -> bytes:
    """Кадр с куском текста."""
    return frame({"choices": [{"index": 0, "delta": {"content": content}}]})


def sse_bytes(answer: str, splits: list[int], byte_split: int | None = None) -> list[bytes]:
    """Поток провайдера: ответ, разрезанный по данным позициям, и произвольные куски.

    ``splits`` режет текст ответа между кадрами, ``byte_split`` — сам байтовый поток
    (провайдер вправе разрезать и кадр): обе оси обязаны быть проверены.
    """
    bounds = [0, *splits, len(answer)]
    raw = b"".join(delta_frame(answer[bounds[i] : bounds[i + 1]]) for i in range(len(bounds) - 1))
    raw += frame("[DONE]")
    if byte_split is None:
        return [raw]
    return [raw[index : index + byte_split] for index in range(0, len(raw), byte_split)]


def client_text(frames: list[bytes]) -> str:
    """Что увидел клиент: конкатенация текста из кадров, ошибок быть не должно."""
    pieces: list[str] = []
    for item in frames:
        body = item.decode("utf-8").strip()
        if not body.startswith("data:"):
            continue
        payload = body[len("data:") :].strip()
        if payload == "[DONE]":
            continue
        event = json.loads(payload)
        if "error" in event:
            raise AssertionError(f"поток закрылся ошибкой: {event['error'].get('code')}")
        for choice in event.get("choices", []) or []:
            delta = choice.get("delta") or choice.get("message") or {}
            content = delta.get("content")
            if isinstance(content, str):
                pieces.append(content)
    return "".join(pieces)


def tool_arguments(frames: list[bytes]) -> str:
    """Собранные аргументы инструмента из кадров потока."""
    arguments = ""
    for item in frames:
        body = item.decode("utf-8").strip()
        if not body.startswith("data:") or body[len("data:") :].strip() == "[DONE]":
            continue
        event = json.loads(body[len("data:") :].strip())
        for choice in event.get("choices", []) or []:
            delta = choice.get("delta") or {}
            for call in delta.get("tool_calls") or []:
                function = call.get("function") or {}
                if function.get("arguments"):
                    arguments = function["arguments"]
    return arguments


class CriterionTests(unittest.TestCase):
    """Критерий подтверждённой позиции: что удерживается, а что уже можно отдать."""

    def held(self, text: str) -> int:
        return len(text) - confirmed_position(text, MAX_HOLD_CHARS)

    def test_ordinary_text_is_fully_confirmed(self) -> None:
        for text in ("Готово", "Клиент записан, телефон", "short", "Отчёт за период"):
            with self.subTest(text=text):
                self.assertEqual(self.held(text), 0)

    def test_beginnings_of_every_surface_are_held(self) -> None:
        tails = (
            "z",
            "zP",
            "zPABCDEF2",
            f"{SENTINEL_OPEN}",
            f"{SENTINEL_OPEN}P",
            f"{SENTINEL_OPEN}P-ABCDEF23GHJK",
            f"{LEGACY_OPEN}P-ABCDEF23GHJK",
            "P-ABCDEF23GHJK",
            "\\u27e6P-ABCDEF2",
        )
        for tail in tails:
            with self.subTest(tail=tail):
                self.assertEqual(self.held(f"текст {tail}"), len(tail))

    def test_trailing_code_start_waits_even_after_a_letter(self) -> None:
        """Просмотр назад не учитывается намеренно: иначе следующий кусок разберётся иначе.

        «XzPAY4P5LAD» в целом тексте кодом не является (слева буква), но если отдать «Xz»,
        следующий кусок начнётся посреди кода и разберётся иначе, чем непотоковый путь
        (найдено этим самым свойством, 18.09.2026). Поэтому «z» удерживается.
        """
        glued = "XzPAY4P5LAD"
        self.assertEqual(self.held(glued), len(glued) - 1)
        self.assertEqual(token_prefix_length("оказалось"), 0)

    def test_capital_latin_tail_waits_because_it_looks_like_a_surface(self) -> None:
        """Латинские заглавные на конце похожи на форму без обрамления: ждём следующий знак.

        Азбука кода — A-Z2-7, поэтому «EPORT» в хвосте «REPORT» неотличим от начала формы
        без обрамления. Ожидание стоит задержки кадра, а не текста: кириллица кодом быть
        не может и уходит сразу.
        """
        self.assertEqual(self.held("REPORT"), 5)
        self.assertEqual(self.held("REPORT "), 0)
        self.assertEqual(self.held("ОТЧЁТ"), 0)

    def test_single_bracket_waits_too(self) -> None:
        """Одиночная «[» — начало обрамлённого кода: отдать её нельзя, иначе «[[» разъедется."""
        self.assertEqual(self.held("клиент ["), 1)
        self.assertEqual(self.held("см. [1]"), 0)

    def test_hard_limit_caps_the_hold(self) -> None:
        """Жёсткий предел удержания: буфер не растёт бесконечно, даже на длинном коде."""
        pending = f"{SENTINEL_OPEN}P-ABCDEF23GHJK"
        self.assertGreater(len(pending), 8)
        self.assertEqual(confirmed_position(pending, 8), 8)
        self.assertEqual(len(pending) - confirmed_position(pending, MAX_HOLD_CHARS), len(pending))
        self.assertGreaterEqual(MAX_HOLD_CHARS, 26)

    def test_complete_code_at_the_end_waits_for_its_right_border(self) -> None:
        """Правая граница кода неизвестна, пока не пришёл следующий знак: удерживаем."""
        code = "zPABCDEF24"
        self.assertEqual(self.held(code), len(code))
        self.assertEqual(self.held(f"текст {code} и ещё"), 0)


class StreamEqualsBufferedTests(unittest.TestCase):
    """Property: поток равен непотоковому пути при любом разбиении."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pipe = Pipeline()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.pipe.close()

    def reference(self, answer: str, channel: str) -> str:
        """Непотоковый путь: тот же текст, восстановленный одним вызовом."""
        restored, _counters = self.pipe.detokenizer.detokenize_text(
            answer, channel, SESSION, self.pipe.allowed
        )
        return restored

    def stream(self, answer: str, splits: list[int], channel: str, byte_split=None) -> str:
        """Потоковый путь: релей на тех же данных."""
        relay = StreamRelay(
            self.pipe.detokenizer, self.pipe.journal, channel, SESSION, self.pipe.allowed
        )
        chunks = sse_bytes(answer, splits, byte_split)
        return client_text(list(relay.relay(iter(chunks))))

    def test_random_splits_match_the_buffered_path(self) -> None:
        rng = random.Random(20260918)
        for seed in range(40):
            answer = build_answer(self.pipe, seed)
            count = rng.randrange(1, 12)
            splits = sorted(rng.randrange(1, len(answer)) for _ in range(count))
            byte_split = rng.choice([None, 1, 3, 17, 64])
            with self.subTest(seed=seed, splits=len(splits), byte_split=byte_split):
                expected = self.reference(answer, "mattermost")
                self.assertEqual(self.stream(answer, splits, "mattermost", byte_split), expected)

    def test_every_single_split_matches(self) -> None:
        """Проверяем не выборку, а все разрезы короткого ответа: свойство обязано держаться везде."""
        answer = f"Клиент {self.pipe.codes_of('P')[0]} записан, телефон {self.pipe.codes_of('T')[0]}."
        expected = self.reference(answer, "mattermost")
        for cut in range(1, len(answer)):
            with self.subTest(cut=cut):
                self.assertEqual(self.stream(answer, [cut], "mattermost"), expected)

    def test_every_pair_of_splits_matches(self) -> None:
        """Два разреза подряд: код, разъехавшийся на три куска, обязан собраться."""
        answer = f"Телефон клиента {self.pipe.codes_of('T')[0]} и всё."
        expected = self.reference(answer, "mattermost")
        for first in range(1, len(answer)):
            for second in range(first + 1, len(answer)):
                with self.subTest(first=first, second=second):
                    self.assertEqual(self.stream(answer, [first, second], "mattermost"), expected)

    def test_untrusted_channel_keeps_the_text_identical(self) -> None:
        rng = random.Random(7)
        for seed in range(10):
            answer = build_answer(self.pipe, seed)
            splits = sorted(rng.randrange(1, len(answer)) for _ in range(5))
            with self.subTest(seed=seed):
                self.assertEqual(self.stream(answer, splits, "telegram"), answer)

    def test_untrusted_channel_never_shows_a_value(self) -> None:
        """Telegram значения не восстанавливает: в потоке обязаны остаться только коды."""
        for seed in range(10):
            answer = build_answer(self.pipe, seed)
            relay_output = self.stream(answer, [len(answer) // 3], "telegram")
            with self.subTest(seed=seed):
                self.assertNotIn(FIO, relay_output)
                self.assertNotIn("Иван Иванович", relay_output)
                self.assertNotIn(PHONE, relay_output)

    def test_code_glued_to_a_letter_is_left_alone_like_the_buffered_path(self) -> None:
        glued = f"X{self.pipe.codes_of('P')[0]}"
        expected = self.reference(glued, "mattermost")
        for cut in range(1, len(glued) + 1):
            with self.subTest(cut=cut):
                self.assertEqual(self.stream(glued, [cut], "mattermost"), expected)


class ToolArgumentPropertyTests(unittest.TestCase):
    """Аргументы инструмента обязаны восстанавливаться при любом разбиении тоже."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pipe = Pipeline()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.pipe.close()

    def arguments(self, argument_text: str, splits: list[int]) -> str:
        """Поток с аргументами инструмента, разрезанными по данным позициям."""
        call = {
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [
                            {"index": 0, "function": {"name": "fb_client", "arguments": ""}}
                        ]
                    },
                }
            ]
        }
        frames: list[bytes] = []
        bounds = [0, *splits, len(argument_text)]
        for index in range(len(bounds) - 1):
            chunk = argument_text[bounds[index] : bounds[index + 1]]
            call["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"] = chunk
            frames.append(frame(json.loads(json.dumps(call))))
        frames.append(frame({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}))
        frames.append(frame("[DONE]"))
        relay = StreamRelay(
            self.pipe.detokenizer, self.pipe.journal, "mattermost", SESSION, self.pipe.allowed
        )
        return tool_arguments(list(relay.relay(iter(frames))))

    def test_arguments_match_the_buffered_path_for_any_split(self) -> None:
        code = self.pipe.codes_of("P")[0]
        raw = json.dumps({"fio": code, "phone": self.pipe.codes_of("T")[0]}, ensure_ascii=False)
        reference_payload = {
            "choices": [
                {"message": {"tool_calls": [{"function": {"name": "f", "arguments": raw}}]}}
            ]
        }
        expected, _counters = self.pipe.detokenizer.detokenize_tool_args(
            reference_payload, SESSION, self.pipe.allowed
        )
        reference = expected["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
        self.assertIn(FIO, reference)
        for cut in range(1, len(raw)):
            with self.subTest(cut=cut):
                restored = self.arguments(raw, [cut])
                self.assertEqual(json.loads(restored), json.loads(reference))


if __name__ == "__main__":
    unittest.main()
