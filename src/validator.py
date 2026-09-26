# FILE: src/validator.py
# VERSION: 1.4.0
# START_MODULE_CONTRACT
#   PURPOSE: Independent pre-flight check that the outgoing request really carries no personal data; a residual is repaired by a second tokenization pass (Вариант 1) and blocked only when that repair fails.
#   SCOPE: full-payload serialization, detector cross-check, token-span exclusion, per-class reasons, second-pass repair of surviving occurrences with the same detector and the same code factory, fail-closed verdict on internal errors.
#   DEPENDS: M-DETECT-RULES, M-DETECT-NAME, M-TOKENIZER
#   LINKS: M-VALIDATOR, V-M-VALIDATOR, fn-validate_outgoing, fn-repair_outgoing, type-ValidationVerdict, type-RepairReport
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   ValidationReason - class and count of a residual finding
#   ValidationVerdict - clean flag, reason code, reasons
#   RepairReport - итог второго прохода: счётчики замен и правила-источники находок
#   ResidualPiiValidator - second-pass detector over the anonymized payload
#   fn-validate_outgoing - return clean or blocked
#   fn-repair_outgoing - заменить найденный остаток тем же детектором и той же фабрикой кодов
#   fn-_pair_key - отпечаток пары «исходная строка → исходящая строка»
#   fn-pair_cache_stats - счётчики кэша пар без значений текста
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.4.0 - Phase-19 (23.09.2026, быстродействие): пара «исходная строка → исходящая строка», уже судимая чистой, больше не переразбирается — на каждом ходу пересылается вся история, и заслон тратил на неё 4,4 с из 7 с повторного прохода. Кэш держит только отпечатки пары (значений текста в нём нет) и сбрасывается при перезагрузке справочника; грязная пара в кэш не попадает никогда.
#   PREVIOUS: v1.3.0 - дефект-фикс 20.09.2026 (красный флаг прибора: заслон нашёл 617 значений, 307 ушло провайдеру, запрос при этом проходил): критерий остатка переведён с «вхождения по соседям» на «значение по написанию». Прежний критерий молча отвечал «не уцелело», когда якорь-сосед не находился после замены соседнего значения, — и запрос объявлялся чистым, хотя значение стояло в исходящем тексте. Теперь судит написание без учёта регистра тем же предикатом, что у токенизатора и починки (M-TOKEN-GEN).
#   PREVIOUS: v1.2.1 - дефект-фикс 19.09.2026 (живой отказ 20:36, владелец без ответа): починка закрывает все вхождения значения, включая копию внутри ссылки (отказ менять её давал вечный replacement_failed: проверка требует замены — починка обязана её выполнить), а правило «внутри ссылки» уточнено до вплотную окружающих знаков адреса — прежде адрес в сорока знаках справа освобождал и обычное имя перед ним, и промах детектора уходил провайдеру открытым текстом.
#   PREVIOUS: v1.2.0 - Phase-15 шаг 4 (дефект-фикс 19.09.2026): починка доводит замену до конца — значение, найденное заслоном, уходит кодом во всех своих вхождениях внутри строки, а не в одном окне; проходы повторяются, пока есть остаток (не больше трёх). Живой инцидент 19.09: 5 находок, 5 замен и всё равно отказ replacement_failed — заслон видел остаток, который починка не убрала.
#   EARLIER: v1.1.0 - Phase-15 шаг 2 (Вариант 1): остаток ПД не блокирует запрос, а заменяется вторым проходом; заслон считает находки и правила-источники один раз, и тем же кодом судит результат. Блокировка остаётся там, где замена не удалась.
#   EARLIER: v1.0.0 - Phase-2 M-VALIDATOR: the gate that turns "the tokenizer is probably right" into evidence.
# END_CHANGE_SUMMARY

"""Residual PII validator.

Implements M-VALIDATOR from docs/ARCHITECTURE.md. The point of a second pass
is independence: it re-runs the detectors over the already anonymized payload and
looks for anything that still looks like personal data. Two details matter:

* spans that are (or contain) tokens are not findings — otherwise a table column
  headed "ФИО" full of tokens would block every request;
* an internal error blocks the request instead of letting it through, because a
  broken gate is worse than a closed one.

Phase-15 (Вариант 1, решение владельца 19.09.2026): остаток больше не отказ. Заслон нашёл
вхождение — второй проход заменяет ровно это вхождение кодом той же фабрики, что и первый
проход, и запрос уходит провайдеру. Что при этом НЕ меняется: судит результат тот же
критерий (``_survivors`` используется и проверкой, и починкой), ничего не «додумывается»
(замена идёт кодом, а не удалением и не маскировкой), и если замена не удалась или после неё
остаток остался — запрос по-прежнему блокируется.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
import threading
from collections import OrderedDict
from typing import Any, Callable, Iterator

from src.detect_name import NameDetector
from src.detect_rules import PiiMatch, detect_rules, detect_tabular, merge_matches
from src.token_factory import (
    find_tokens,
    flexible_pattern,
    is_valid_token,
    replace_value_occurrences,
    same_value_text,
    word_bounded,
)

LOGGER_NAME = "ResidualPiiValidator"
LOG_MARKER = "[ResidualPiiValidator][validate_outgoing][BLOCK_VALIDATE_OUTGOING]"

#: Сколько раз починка повторяет замену остатка. Три прохода — запас на строки, где
#: значение записано с другим пробелом и находится за первым окном; больше не нужно:
#: проход без замены означает, что дальше будет то же самое.
MAX_REPAIR_PASSES = 3


@dataclass(frozen=True)
class ValidationReason:
    """One residual finding, described by class and count only."""

    cls: str
    count: int
    # Диагностика (PII_PROXY_DEBUG_FINDINGS=true): первые знаки значения и форма
    # окружения, всё остальное закрыто маской. Значения целиком не попадают даже
    # сюда — журнал и логи остаются без ПД, а разбор всё равно возможен.
    samples: tuple[str, ...] = ()


@dataclass(frozen=True)
class ValidationVerdict:
    """Result of the pre-flight check.

    # START_CONTRACT: ValidationVerdict
    #   PURPOSE: Tell the router whether to proceed, and why not.
    #   INPUTS: { clean: bool, code: str, reasons: tuple[ValidationReason, ...] }
    #   OUTPUTS: { ValidationVerdict - value object }
    #   SIDE_EFFECTS: none
    #   LINKS: M-ROUTER, V-M-VALIDATOR
    # END_CONTRACT: ValidationVerdict
    """

    clean: bool
    code: str = ""
    reasons: tuple[ValidationReason, ...] = ()


@dataclass(frozen=True)
class RepairReport:
    """Итог второго прохода: что заменено и каким правилом найдено.

    # START_CONTRACT: RepairReport
    #   PURPOSE: Отдать роутеру числа починки и правило-источник находки, не отдавая значений.
    #   INPUTS: { replaced: dict[str, int] - заменённые вхождения по классам, rules: tuple[str, ...] - машинные коды правил }
    #   OUTPUTS: { RepairReport - value object }
    #   SIDE_EFFECTS: none
    #   LINKS: M-ROUTER, M-INCIDENT-JOURNAL, V-M-VALIDATOR
    # END_CONTRACT: RepairReport

    В отчёте только классы, числа и машинные коды правил: он попадает в журнал инцидентов и
    в журнал аудита, где значениям места нет.
    """

    replaced: dict[str, int] = field(default_factory=dict)
    rules: tuple[str, ...] = ()

    @property
    def total(self) -> int:
        """Сколько вхождений заменено вторым проходом."""
        return sum(int(count) for count in self.replaced.values())

    @property
    def classes(self) -> tuple[str, ...]:
        """Классы заменённых вхождений в устойчивом порядке."""
        return tuple(sorted(self.replaced))


# START_BLOCK_VALIDATE_OUTGOING
class ResidualPiiValidator:
    """Second-pass detector over the anonymized payload.

    # START_CONTRACT: ResidualPiiValidator
    #   PURPOSE: Block any request that still carries recognizable PII.
    #   INPUTS: { name_detector: NameDetector | None, use_tabular: bool }
    #   OUTPUTS: { ResidualPiiValidator - ready validator }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-RULES, M-DETECT-NAME, M-ROUTER, V-M-VALIDATOR
    # END_CONTRACT: ResidualPiiValidator
    """

    def __init__(
        self,
        name_detector: NameDetector | None = None,
        use_tabular: bool = True,
    ) -> None:
        self._names = name_detector or NameDetector()
        # Кэш «эта пара строк уже судилась и была чистой» (Phase-19). На каждом ходу
        # пересылается вся история: без кэша детекторы заново разбирают те же строки.
        # Хранятся только отпечатки пары — значения текста в кэше не задерживаются.
        self._pair_cache: "OrderedDict[str, bool]" = OrderedDict()
        self._pair_cache_limit = 4096
        self._pair_cache_lock = threading.Lock()
        self._dictionary_marker: Any = None
        self._use_tabular = use_tabular

    def validate_outgoing(self, payload: dict, original: dict | None = None) -> ValidationVerdict:
        """Return clean or blocked for an anonymized payload.

        # START_CONTRACT: validate_outgoing
        #   PURPOSE: Independent evidence that no PII is leaving.
        #   INPUTS: { payload: dict - anonymized request body, original: dict | None - the same request before anonymization }
        #   OUTPUTS: { ValidationVerdict - verdict with reasons }
        #   SIDE_EFFECTS: none
        #   LINKS: M-ROUTER, V-M-VALIDATOR, VF-004
        # END_CONTRACT: validate_outgoing

        Находка 18.09.2026: проверять только обезличенный текст нельзя. После замены текст
        становится короче, соседние знаки меняются, и правило «клиентского контекста»
        срабатывает там, где токенизатор его не видел — валидатор считал остаточными ПД
        то, что обезличивать не требовалось, и блокировал каждый запрос Mattermost (403).
        Поэтому при наличии оригинала проверка идёт по оригиналу: каждое найденное в нём
        значение обязано отсутствовать в исходящем запросе.
        """
        if not isinstance(payload, dict):
            return ValidationVerdict(clean=False, code="validator_error")

        if original is not None and isinstance(original, dict):
            return self._validate_against_original(payload, original)

        residual: dict[str, int] = {}
        try:
            for text in _iter_strings(payload):
                if not text.strip():
                    continue
                token_spans = [(match[0], match[1]) for match in find_tokens(text)]
                found: list[PiiMatch] = []
                if self._use_tabular:
                    found.extend(detect_tabular(text))
                found.extend(detect_rules(text))
                found.extend(self._names.detect_names(text))
                for match in merge_matches(found):
                    if _overlaps_tokens(match, token_spans):
                        continue
                    residual[match.cls] = residual.get(match.cls, 0) + 1
        except Exception:  # noqa: BLE001 - a broken gate must fail closed, not open
            return ValidationVerdict(clean=False, code="validator_error")

        return _verdict(residual)

    def _validate_against_original(self, payload: dict, original: dict) -> ValidationVerdict:
        """Compare detections in the original with tokens in the outgoing body, per class.

        # START_CONTRACT: _validate_against_original
        #   PURPOSE: Keep the gate strict without inventing findings the tokenizer never saw.
        #   INPUTS: { payload: dict - anonymized body, original: dict - body before anonymization }
        #   OUTPUTS: { ValidationVerdict - verdict with reasons }
        #   SIDE_EFFECTS: none
        #   LINKS: M-TOKENIZER, V-M-VALIDATOR
        # END_CONTRACT: _validate_against_original

        Находка 18.09.2026 (две ошибки подряд, обе исправлены здесь):

        1. Проверять обезличенный текст нельзя: после замены он короче, соседние знаки
           меняются, и правило «клиентского контекста» срабатывало там, где токенизатор его
           не видел — валидатор блокировал каждый запрос Mattermost.
        2. Проверять по значениям тоже нельзя: одно и то же имя встречается в тексте много
           раз, и часть вхождений токенизатор осознанно оставляет (нет признаков работы с
           данными). Значение «отсутствует» — не то же самое, что «заменено».

        Поэтому сравнение идёт по классам: сколько находок детектор дал в исходной строке
        и сколько кодов соответствующего класса стоит в исходящей. Недостача кода — это
        остаточные ПД; излишек — норма (значение уже встречалось раньше и получило код).

        Phase-15: поиск вхождений вынесен в ``_survivors`` и общий с ``repair_outgoing`` —
        проверка и починка обязаны судить одним и тем же кодом, иначе починенный запрос
        снова окажется «грязным» по другой формулировке правила.
        """
        residual: dict[str, int] = {}
        samples: dict[str, list[str]] = {}
        try:
            for _location, match, _rule, original_text in self._survivors(payload, original):
                residual[match.cls] = residual.get(match.cls, 0) + 1
                if len(samples.setdefault(match.cls, [])) < 3:
                    samples[match.cls].append(_masked_sample(original_text, match))
        except Exception:  # noqa: BLE001 - a broken gate must fail closed, not open
            return ValidationVerdict(clean=False, code="validator_error")

        return _verdict(residual, samples)

    def repair_outgoing(
        self,
        payload: dict,
        original: dict,
        issue: Callable[[str, str, str], str],
    ) -> RepairReport:
        """Заменить найденный остаток вторым проходом: тем же детектором и той же фабрикой кодов.

        # START_CONTRACT: repair_outgoing
        #   PURPOSE: Дать Варианту 1 выполнить обещание «пользователь получает ответ», не ослабляя fail-closed.
        #   INPUTS: { payload: dict - обезличенный запрос (правится на месте), original: dict - исходный запрос, issue: Callable[[str, str, str], str] - выдача кода тем же присвоением, что в первом проходе }
        #   OUTPUTS: { RepairReport - заменённые вхождения по классам и правила-источники }
        #   SIDE_EFFECTS: правит строки payload, вызывает issue (запись связки в справочник)
        #   LINKS: M-TOKENIZER, M-ROUTER, M-INCIDENT-JOURNAL, V-M-VALIDATOR
        # END_CONTRACT: repair_outgoing

        Ничего не «додумывается»: заменяются ровно те вхождения, которые нашёл тот же
        детектор по тому же критерию (``_survivors``), и заменяются кодом — удаление,
        маскировка и «похоже на мусор» здесь не применяются.

        Дефект 19.09.2026: починка меняла одно вхождение на окно после соседа, а проверка
        судила по тому же окну — если значение встречалось в строке несколькими рядом
        стоящими вхождениями или было записано с другим пробелом, часть вхождений
        оставалась в исходящем тексте. Инцидент выглядел так: пять находок, пять замен и
        всё равно отказ ``replacement_failed``, владелец без ответа. Поэтому теперь
        значение уходит кодом во **всех** своих вхождениях внутри строки (``_replace_all``),
        а проход повторяется, пока заслон видит остаток, — но не больше ``MAX_REPAIR_PASSES``
        раз, чтобы сбой не превратился в бесконечный цикл.

        Исключения наружу не глотаются: сбой справочника или исчерпание пространства кодов
        обязан остановить запрос, а не превратиться в «починено».
        """
        replaced: dict[str, int] = {}
        rules: list[str] = []
        # Один код на значение: фабрика кодов детерминирована, и повторный вызов тут же
        # вернул бы тот же код, но лишний вызов — лишняя запись связки в справочник.
        tokens: dict[tuple[str, str], str] = {}
        for _pass in range(MAX_REPAIR_PASSES):
            in_pass = 0
            for (holder, key, _current), match, rule, _original_text in self._survivors(
                payload, original
            ):
                if holder is None:
                    # Строка верхнего уровня: править нечего — она не в payload, а сам payload.
                    continue
                identity = match.identity or match.normalized or match.raw
                token = tokens.get((match.cls, identity))
                if token is None:
                    token = issue(match.cls, match.identity or match.normalized, match.raw)
                    tokens[(match.cls, identity)] = token
                # Текущий текст берётся заново: несколько остатков в одной строке правятся
                # по очереди, и второй не должен затереть первый устаревшей копией.
                patched, done = _replace_all(holder[key], match.raw, token)
                if done <= 0:
                    continue
                holder[key] = patched
                replaced[match.cls] = replaced.get(match.cls, 0) + done
                in_pass += done
                if rule and rule not in rules:
                    rules.append(rule)
            if not in_pass:
                # Прохода без замены хватит: дальше будет то же самое.
                break
        return RepairReport(replaced=replaced, rules=tuple(rules))

    # START_BLOCK_VALIDATOR_PAIR_CACHE
    def _pair_key(self, original_text: str, outgoing_text: str) -> str:
        """Отпечаток пары «исходная строка → исходящая строка».

        # START_CONTRACT: _pair_key
        #   PURPOSE: Опознать пару, которую уже судили, не храня значений текста.
        #   INPUTS: { original_text: str - строка до обезличивания, outgoing_text: str - строка после }
        #   OUTPUTS: { str - шестнадцатеричный отпечаток пары }
        #   SIDE_EFFECTS: none
        #   LINKS: M-VALIDATOR, M-TOKENIZER, Phase-19
        # END_CONTRACT: _pair_key
        """
        digest = hashlib.sha1()
        digest.update(original_text.encode("utf-8", "replace"))
        digest.update(b"\x00")
        digest.update(outgoing_text.encode("utf-8", "replace"))
        return digest.hexdigest()

    def _pair_cache_is_stale(self) -> bool:
        """Сказать, что справочник перезагрузился и суждения о парах устарели."""
        current = getattr(self._names, "dictionary_signature", None)
        if not callable(current):
            return False
        try:
            signature = current()
        except Exception:  # noqa: BLE001 - сбой словаря не повод терять заслон
            return False
        if signature is None:
            return False
        if self._dictionary_marker is None:
            self._dictionary_marker = signature
            return False
        if signature != self._dictionary_marker:
            self._dictionary_marker = signature
            return True
        return False

    def _pair_is_clean(self, key: str) -> bool:
        """Проверить, судилась ли эта пара и была ли она чистой."""
        with self._pair_cache_lock:
            return bool(self._pair_cache.get(key))

    def _remember_clean_pair(self, key: str) -> None:
        """Запомнить пару как чистую. Грязные пары сюда не попадают никогда."""
        with self._pair_cache_lock:
            self._pair_cache[key] = True
            self._pair_cache.move_to_end(key)
            while len(self._pair_cache) > self._pair_cache_limit:
                self._pair_cache.popitem(last=False)

    def pair_cache_stats(self) -> dict[str, int]:
        """Счётчики кэша пар: размер и предел (значений текста в кэше нет)."""
        with self._pair_cache_lock:
            return {"size": len(self._pair_cache), "limit": self._pair_cache_limit}
    # END_BLOCK_VALIDATOR_PAIR_CACHE

    def _survivors(
        self, payload: dict, original: dict
    ) -> Iterator[tuple[tuple[Any, Any, str], PiiMatch, str, str]]:
        """Найти вхождения, найденные в исходном запросе и оставшиеся в исходящем.

        # START_CONTRACT: _survivors
        #   PURPOSE: Один критерий «это остаток» для проверки и для починки.
        #   INPUTS: { payload: dict - обезличенный запрос, original: dict - исходный запрос }
        #   OUTPUTS: { Iterator[tuple[tuple[Any, Any, str], PiiMatch, str, str]] - (место правки, находка, правило-источник, исходный текст) }
        #   SIDE_EFFECTS: none
        #   LINKS: M-TOKENIZER, M-DETECT-RULES, M-DETECT-NAME, V-M-VALIDATOR
        # END_CONTRACT: _survivors

        Проверяются сообщения (там живут данные клиентов). Блок `tools` — статические
        схемы инструментов: клиентских значений в нём нет, а слова из описаний
        совпадают с фамилиями в словаре (находка 18.09.2026 — 403 на каждый запрос).

        Правило-источник берётся из того канала, который дал находку: сплошной проход
        правил, табличная форма или распознавание имён. Это машинный код для журнала, а
        не текст.

        Дефект 20.09.2026: находок может быть несколько на одно значение, и каждая судится
        одинаково — «значение осталось в исходящей строке». Отдельного суждения по позиции
        больше нет: оно молчало, когда соседнее значение уже заменено кодом и окно соседей
        не находилось.
        """
        if self._pair_cache_is_stale():
            with self._pair_cache_lock:
                self._pair_cache.clear()
        for original_text, (holder, key, outgoing_text) in zip(
            _iter_strings(original.get("messages", [])),
            _iter_locations(payload.get("messages", [])),
        ):
            if not original_text.strip():
                continue
            pair_key = self._pair_key(original_text, outgoing_text)
            if self._pair_is_clean(pair_key):
                # На каждом ходу пересылается вся история, а неизменённые пары уже судились
                # и были чистыми: разбирать их заново незачем (Phase-19). Грязная пара сюда
                # не попадает никогда — она либо починена, либо запрос заблокирован.
                continue
            found = self._channel_matches(original_text)
            rules: dict[tuple[int, int, str], str] = {}
            for rule, match in found:
                # Первый канал, увидевший вхождение, и есть правило-источник: табличная форма
                # точнее правил, правила точнее распознавания имён по словарю.
                rules.setdefault((match.start, match.end, match.cls), rule)
            survivors = [
                match
                for match in merge_matches([match for _rule, match in found])
                if _occurrence_survived(original_text, match, outgoing_text)
            ]
            if not survivors:
                self._remember_clean_pair(pair_key)
                continue
            for match in survivors:
                yield (
                    (holder, key, outgoing_text),
                    match,
                    rules.get((match.start, match.end, match.cls), ""),
                    original_text,
                )

    def _channel_matches(self, text: str) -> list[tuple[str, PiiMatch]]:
        """Собрать находки по каналам обнаружения, сохранив источник каждой.

        # START_CONTRACT: _channel_matches
        #   PURPOSE: Знать правило-источник находки, не меняя сами детекторы.
        #   INPUTS: { text: str - блок текста }
        #   OUTPUTS: { list[tuple[str, PiiMatch]] - (машинный код правила, находка) }
        #   SIDE_EFFECTS: none
        #   LINKS: M-DETECT-RULES, M-DETECT-NAME, V-M-VALIDATOR
        # END_CONTRACT: _channel_matches
        """
        found: list[tuple[str, PiiMatch]] = []
        if self._use_tabular:
            found.extend(("tabular", match) for match in detect_tabular(text))
        found.extend(("rules", match) for match in detect_rules(text))
        found.extend(("names", match) for match in self._names.detect_names(text))
        return found


def _masked_sample(original_text: str, match: PiiMatch) -> str:
    """Describe a surviving finding without carrying the value.

    # START_CONTRACT: _masked_sample
    #   PURPOSE: Make a fail-closed block diagnosable without putting PII into logs.
    #   INPUTS: { original_text: str - text the finding came from, match: PiiMatch - the finding }
    #   OUTPUTS: { str - " первые2…(длина) | форма окружения " }
    #   SIDE_EFFECTS: none
    #   LINKS: M-VALIDATOR, V-M-VALIDATOR, V-M-STREAM-RELAY
    # END_CONTRACT: _masked_sample
    """
    value = _normalize_space(match.raw).strip()
    head = value[:2] + "…" if len(value) > 2 else "…"
    window = original_text[max(0, match.start - 25) : match.end + 25]
    shape = re.sub(r"\w", "•", window)
    return f"{head}({len(value)}) | {shape}"


def _verdict(residual: dict[str, int], samples: dict[str, list[str]] | None = None) -> ValidationVerdict:
    """Turn per-class counters into a verdict."""
    if not residual:
        return ValidationVerdict(clean=True)
    samples = samples or {}
    reasons = tuple(
        ValidationReason(cls=cls, count=count, samples=tuple(samples.get(cls, ())))
        for cls, count in sorted(residual.items())
    )
    return ValidationVerdict(clean=False, code="residual_pii", reasons=reasons)


def _normalize_space(text: str) -> str:
    """Collapse whitespace so windows compare across the replacement."""
    return re.sub(r"\s+", " ", text or "")


def _occurrence_survived(original_text: str, match: PiiMatch, outgoing_text: str) -> bool:
    """Return True when the value of this finding is still in the outgoing text.

    # START_CONTRACT: _occurrence_survived
    #   PURPOSE: Судить значение по написанию: «Иванов» и «ИВАНОВ» — одно значение, а не два разных.
    #   INPUTS: { original_text: str, match: PiiMatch, outgoing_text: str - исходящая строка }
    #   OUTPUTS: { bool - True when the value survived }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKEN-GEN, M-TOKENIZER, M-VALIDATOR
    # END_CONTRACT: _occurrence_survived

    Прежний критерий судил ВХОЖДЕНИЕ по соседям: 14 знаков слева обязаны были найтись в
    исходящем тексте, и только после них искалось само значение. Дефект 20.09.2026: соседнее
    значение тоже заменяется кодом, окно соседей сдвигается, и `find` не находил якорь —
    критерий молча отвечал «не уцелело», то есть объявлял запрос чистым, хотя значение
    стояло в исходящем тексте открытым (прибор: 617 находок, 307 ушло провайдеру). Тихая
    ветка «судить не о чем» и была причиной: у проверки, которая отпускает запрос, не может
    быть исхода «доказательства нет» — есть только «значение ушло» или «значение осталось».

    Регистр не важен, пробелы — тоже: значение уходит провайдеру одним написанием и
    возвращается в другом, а персональные данные от этого персональными быть не перестают.
    Вхождение внутри ссылки или пути освобождается тем же правилом, что и у токенизатора
    (сегмент адреса — не упоминание человека).
    """
    value = _normalize_space(match.raw).strip()
    if not value:
        return False
    if _inside_link(original_text, match.start, match.end):
        # Слово внутри адреса ссылки — это часть URL, а не упоминание человека.
        return False
    pattern = flexible_pattern(value)
    if not pattern:
        return False
    return re.search(word_bounded(pattern), outgoing_text or "", re.IGNORECASE) is not None


def _flexible(text: str) -> str:
    """Собрать шаблон, устойчивый к пробелам и неразрывным пробелам.

    # START_CONTRACT: _flexible
    #   PURPOSE: Найти значение там, где оно записано чуть иначе по пробелам, не теряя границ слова.
    #   INPUTS: { text: str - фрагмент текста }
    #   OUTPUTS: { str - исходник регулярного выражения }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKEN-GEN, M-VALIDATOR, V-M-VALIDATOR
    # END_CONTRACT: _flexible

    Реализация живёт в M-TOKEN-GEN: тем же предикатом пользуется токенизатор, иначе
    «заслон нашёл» и «токенизатор заменил» снова начнут говорить о разном (дефект
    20.09.2026).
    """
    return flexible_pattern(text)


def _wrapped(pattern: str) -> str:
    """Ограничить шаблон границами слова, как это делает проверка вхождения.

    # START_CONTRACT: _wrapped
    #   PURPOSE: Не заменить часть другого слова (то же правило границ, что у _occurrence_survived).
    #   INPUTS: { pattern: str - исходник шаблона }
    #   OUTPUTS: { str - исходник шаблона с границами }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKEN-GEN, M-VALIDATOR, V-M-VALIDATOR
    # END_CONTRACT: _wrapped
    """
    return word_bounded(pattern)


def _replace_all(outgoing_text: str, raw: str, token: str) -> tuple[str, int]:
    """Заменить значением кода все его вхождения в строке, кроме частей ссылок.

    # START_CONTRACT: _replace_all
    #   PURPOSE: Довести замену до конца: остаток, который видит заслон, должен уйти кодом целиком.
    #   INPUTS: { outgoing_text: str - текущая строка исходящего запроса, raw: str - наблюдённое значение, token: str - выданный код }
    #   OUTPUTS: { tuple[str, int] - строка с кодами и число замен }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKENIZER, M-ROUTER, V-M-VALIDATOR
    # END_CONTRACT: _replace_all

    Дефект 19.09.2026: прежняя починка правила ровно одно вхождение — то, что попадало в
    окно после соседа слева. Если значение стояло в строке несколькими вхождениями или
    было записано с другим пробелом, часть вхождений оставалась в исходящем тексте, и
    повторная проверка отправляла запрос в блокировку (``replacement_failed``). Токенизатор
    поступает иначе — он убирает все вхождения значения в строке, — и починка обязана делать
    то же самое.

    Второй дефект того же дня (живой отказ 20:36, владелец без ответа): починка отказывалась
    менять копию внутри ссылки — «это правило проверки». Правило ссылки принадлежит
    **проверке**: она уже применила его к судимому вхождению и всё равно потребовала замены,
    а окно после соседа слева накрывает копию внутри ссылки. Отказ починки означал, что
    проход не даёт прогресса, проверка остаётся красной, и запрос уходит в отказ навсегда
    (в живом инциденте — 20 замен и всё равно ``replacement_failed``). Поэтому теперь
    починка закрывает **все** вхождения значения в строке: то, чего требует проверка,
    обязано быть выполнено, а не перепроверено своим правилом.
    """
    pattern = _flexible(raw)
    if not pattern or not outgoing_text:
        return outgoing_text, 0
    # Одна реализация на токенизатор и починку (M-TOKEN-GEN): сравнение по написанию,
    # любой регистр, любые пробелы, потолок по числу вхождений.
    return replace_value_occurrences(outgoing_text, raw, token)


def _same_value(observed: str, token: str) -> bool:
    """Совпадает ли выданный код с самим значением (по нормализованному виду).

    # START_CONTRACT: _same_value
    #   PURPOSE: Не принять «замену» за замену, если фабрика кодов вернула само значение.
    #   INPUTS: { observed: str - найденный текст, token: str - выданный код }
    #   OUTPUTS: { bool - True, когда менять нечего }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKEN-GEN, M-TOKENIZER, M-VALIDATOR
    # END_CONTRACT: _same_value
    """
    return same_value_text(observed, token)


def _inside_link(text: str, start: int, end: int) -> bool:
    """Return True when the finding sits inside a URL or a file path.

    # START_CONTRACT: _inside_link
    #   PURPOSE: Do not judge URL and path segments as person mentions.
    #   INPUTS: { text: str, start: int - начало находки, end: int - конец находки }
    #   OUTPUTS: { bool - True when the span is part of a link or path }
    #   SIDE_EFFECTS: none
    #   LINKS: V-M-VALIDATOR
    # END_CONTRACT: _inside_link

    Находка 18.09.2026: два пятибуквенных значения из словаря совпали с сегментами адресов
    ссылок в системном промпте («…/docs/…?…=»). Это не упоминание человека, и держать из-за
    этого весь запрос заблокированным нельзя.

    Уточнение 19.09.2026 (живой отказ 20:36 и тест сквозного пути): прежнее правило считало
    находку «внутри ссылки», если ссылка стояла **где угодно** в сорока знаках справа, — и
    настоящее имя в обычной фразе перед адресом («Клиент Иванов Иван Иванович, карта:
    https://…») переставало считаться остатком. Промах детектора на таком значении уходил
    провайдеру открытым текстом. Теперь «внутри ссылки» — это только находка, вплотную
    окружённая знаками адреса (слева или справа), то есть действительно сегмент адреса,
    а не слово рядом с ним.
    """
    before = text[max(0, start - 1) : start]
    after = text[end : end + 1]
    if before in ("/", "\\", ".", "-", "=", "&", "?", ":", "@"):
        return True
    if after in ("/", "\\", "?", "&", "=", ":", "@"):
        return True
    return "://" in text[max(0, start - 3) : start] or "://" in text[end : end + 4]


def _count_by_class(matches: list[PiiMatch]) -> dict[str, int]:
    """Count matches per class."""
    counts: dict[str, int] = {}
    for match in matches:
        counts[match.cls] = counts.get(match.cls, 0) + 1
    return counts


def _iter_locations(node: Any, parent: Any = None, key: Any = None) -> Iterator[tuple[Any, Any, str]]:
    """Yield (container, key, text) for every string inside a payload, in order.

    # START_CONTRACT: _iter_locations
    #   PURPOSE: Дать и проверке, и починке одну и ту же последовательность строк вместе с местом правки.
    #   INPUTS: { node: Any - фрагмент payload, parent: Any - контейнер строки, key: Any - ключ или индекс строки }
    #   OUTPUTS: { Iterator[tuple[Any, Any, str]] - контейнер, ключ, текст }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKENIZER, V-M-VALIDATOR
    # END_CONTRACT: _iter_locations

    Порядок обхода обязан совпадать у проверки и починки: вхождения сопоставляются по
    позиции строки в запросе (``zip``), поэтому второй обход «своими словами» сдвинул бы
    правку на соседнее сообщение. Возвращается именно контейнер, чтобы замену можно было
    записать на место (строки в Python неизменяемы).
    """
    if isinstance(node, str):
        yield parent, key, node
    elif isinstance(node, dict):
        for name, value in node.items():
            yield from _iter_locations(value, node, name)
    elif isinstance(node, (list, tuple)):
        for index, item in enumerate(node):
            yield from _iter_locations(item, node, index)
    elif node is None or isinstance(node, (int, float, bool)):
        return
    else:
        # Неизвестный фрагмент нельзя проверить — значит нельзя и пропустить запрос.
        raise TypeError(f"unscannable payload fragment: {type(node).__name__}")


def _iter_strings(node: Any) -> Iterator[str]:
    """Yield every string inside a payload, in order.

    # START_CONTRACT: _iter_strings
    #   PURPOSE: Scan the same units the tokenizer scans, not the serialized JSON.
    #   INPUTS: { node: Any - payload fragment }
    #   OUTPUTS: { Iterator[str] - string values }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKENIZER, V-M-VALIDATOR
    # END_CONTRACT: _iter_strings

    Находка 18.09.2026: валидатор сканировал payload как один текст после `json.dumps`.
    В сериализованном виде рядом с обычным словом оказываются кавычки, запятые и цифры
    ключей, и правило «клиентского контекста» принимало за данные имена, которые
    токенизатор законно оставил — запрос блокировался целиком (403 на каждый запрос
    Mattermost). Проверка обязана смотреть те же строки, что и токенизация.

    Phase-15: обход один — ``_iter_locations``; эта функция только отбрасывает место правки.
    """
    for _container, _key, text in _iter_locations(node):
        yield text


def _overlaps_tokens(match: PiiMatch, token_spans: list[tuple[int, int]]) -> bool:
    """Return True when a finding sits inside or overlaps a token.

    # START_CONTRACT: _overlaps_tokens
    #   PURPOSE: Keep the validator from flagging its own tokens.
    #   INPUTS: { match: PiiMatch, token_spans: list[tuple[int, int]] }
    #   OUTPUTS: { bool - True when the finding overlaps a token }
    #   SIDE_EFFECTS: none
    #   LINKS: V-M-VALIDATOR
    # END_CONTRACT: _overlaps_tokens
    """
    if "\u27e6" in match.raw or "\u27e7" in match.raw or "[[" in match.raw:
        return True
    # Compact codes (Phase-4) carry no framing, so the surface check above cannot
    # see them: recognise the identifier itself, otherwise every anonymized
    # selection would look like residual personal data and block the request.
    if is_valid_token(match.raw.strip()):
        return True
    return any(
        match.start < token_end and token_start < match.end
        for token_start, token_end in token_spans
    )
# END_BLOCK_VALIDATE_OUTGOING
