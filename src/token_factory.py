# FILE: src/token_factory.py
# VERSION: 2.3.0
# START_MODULE_CONTRACT
#   PURPOSE: Produce deterministic, non-reversible identifiers for PII values, walk deterministic alternative candidates when one is taken, and recognize every identifier surface in text.
#   SCOPE: compact code generation (class letter plus 8 base32 characters), deterministic candidate walk, parsing and canonicalisation across all supported surfaces, discovery in text, malformed rejection.
#   DEPENDS: none
#   LINKS: M-TOKEN-GEN, V-M-TOKEN-GEN, fn-make_token, fn-candidate_tokens, fn-parse_token, fn-find_tokens, fn-canonical_token
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   CODE_PREFIX - leading letter that marks a compact identifier
#   CODE_LENGTH - number of base32 characters in a compact identifier
#   CODE_PATTERN - regular expression matching a compact identifier inside text
#   TOKEN_PATTERN - regular expression matching a framed identifier
#   BARE_TOKEN_PATTERN - framed identifier without its framing
#   MAX_SURFACE_CHARS - длина самой длинной поверхности кода (нужна потоку)
#   fn-flexible_pattern - шаблон значения, устойчивый к пробелам
#   fn-word_bounded - ограничить шаблон границами слова
#   fn-iter_value_occurrences - вхождения значения в текст по написанию, а не по позиции
#   fn-replace_value_occurrences - заменить все вхождения значения кодом
#   fn-same_value_text - совпадает ли запись с кодом (по написанию)
#   TokenError - malformed or unparsable identifier
#   make_token - deterministic compact identifier for class and normalized value
#   candidate_tokens - deterministic alternative identifiers for collision resolution
#   parse_token - split any identifier surface into class and code
#   canonical_token - canonical form of any accepted surface
#   fn-normalise_code_run - вернуть искажённую копию кода к исходному виду
#   fn-find_tokens - locate every identifier inside a text block
#   token_prefix_length - длина хвоста, из которого любое продолжение может собрать код
#   is_valid_token - cheap validity check
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v2.3.0 - Phase-20 (дефект-фикс 23.09.2026): искажённая копия кода снова восстанавливается. Замер на живом коде: из одиннадцати типовых искажений распознавались семь — разделитель внутри кода (пробел, дефис, перенос), кириллические похожие буквы и цифровые двойники (0/O, 1/I, 8/B, 9/G) не распознавались, и клиент получал код вместо значения. Добавлены таблица подмен, снятие разделителей и толерантный проход; границы жёсткие — код не собирается из обычной фразы, из слова («XzPAY4P5LAD»), усечённый код не достраивается, значения по-прежнему берутся только из справочника.
#   PREVIOUS: v2.2.0 - Phase-15 шаг 6 (дефект-фикс 20.09.2026): предикат «это то же значение» переехал сюда и стал общим для токенизатора, заслона и починки. Причина: у токенизатора сравнение шло по точному написанию, у заслона — по позиции с соседями; из-за расхождения двух критериев значение уходило кодом в одном написании и оставалось в исходящем запросе в другом («Иванов» заменён, «ИВАНОВ» ушёл провайдеру).
#   PREVIOUS: v2.1.0 - Phase-12 шаг 5: token_prefix_length — поверхностное правило для потока: по нему решается, подтверждена ли позиция разреза (критерий взят у veilstream, Apache-2.0).
#   PREVIOUS: v2.0.0 - Phase-4 CompactIdentifiers: the identifier is now `z<class><8 base32>` (40 bits, no framing). Reasons, all measured on 16.09.2026: the framed 12-character token cost 58% more provider tokens than the raw value it replaced, the 8-character form costs 11%, and every framing is a surface the model can mangle (exotic brackets were dropped in 6 of 6 attempts). Legacy framings stay readable, and candidate_tokens exists so a taken identifier can be skipped without ever silent-clobbering another value.
#   PREVIOUS: v1.0.0 - Phase-1 M-TOKEN-GEN: framed token per TZ section 3, F-4; ASCII framing from 16.09.2026.
# END_CHANGE_SUMMARY

"""Deterministic identifier factory.

Implements M-TOKEN-GEN from docs/ARCHITECTURE.md. The identifier is a
compact code: ``zP482193`` — a leading ``z``, the class letter, then eight base32
characters (40 bits). Measured on 16.09.2026: this form costs 11% more provider
tokens than the raw value it replaces, while the framed 12-character token cost
58%, and a framing is one more surface the model can damage.

Determinism is a hard requirement (UC-004): the same class plus normalized value
must always yield the same identifier, in any process, because the upstream
prompt cache is keyed on the literal prefix of the request. ``candidate_tokens``
keeps that property while allowing an identifier that is already taken by
another value to be skipped — the walk depends only on the value and the key,
never on the order of arrival.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from typing import Iterable, Iterator

LOGGER_NAME = "TokenFactory"
LOG_MARKER = "[TokenFactory][make_token][BLOCK_MAKE_TOKEN]"

# Compact identifier surface (current form since Phase-4, 16.09.2026).
CODE_PREFIX = "z"
CODE_LENGTH = 8
CLASS_LETTERS = "PTEDAIC"
MAX_CANDIDATES = 64

# Framed surfaces kept readable for bindings created before Phase-4: the ASCII
# framing introduced on 16.09.2026 during the framing-fidelity work and the
# original exotic brackets. Both carry a twelve character digest.
SENTINEL_OPEN = "[["
SENTINEL_CLOSE = "]]"
LEGACY_OPEN = "\u27e6"
LEGACY_CLOSE = "\u27e7"
DIGEST_LENGTH = 12

CODE_PATTERN = re.compile(
    rf"(?<![A-Za-z0-9А-Яа-яЁё]){CODE_PREFIX}([PTEDAIC])([A-Z2-7]{{{CODE_LENGTH}}})(?![A-Za-z0-9А-Яа-яЁё])",
    re.IGNORECASE,
)
CODE_SURFACE_PATTERN = re.compile(
    rf"{CODE_PREFIX}([PTEDAIC])([A-Z2-7]{{{CODE_LENGTH}}})", re.IGNORECASE
)

TOKEN_PATTERN = re.compile(
    rf"{re.escape(SENTINEL_OPEN)}([PTEDAIC])-([A-Z2-7]{{{DIGEST_LENGTH}}}){re.escape(SENTINEL_CLOSE)}"
    rf"|{re.escape(LEGACY_OPEN)}([PTEDAIC])-([A-Z2-7]{{{DIGEST_LENGTH}}}){re.escape(LEGACY_CLOSE)}"
)

# Two framings and two surface forms per framing: the legacy ⟦…⟧ (also seen as its
# \u escape sequence in escaped JSON) and the ASCII [[…]]. Detection must accept
# all of them, because tool arguments returned by a provider are frequently
# escaped (ensure_ascii=True) and an unnoticed escape silently defeats
# detokenization.
TOKEN_SURFACE_PATTERN = re.compile(
    r"(?:\u27e6|\\u27e6)([PTEDAIC])-([A-Z2-7]{%d})(?:\u27e7|\\u27e7)"
    r"|\[\[([PTEDAIC])-([A-Z2-7]{%d})\]\]" % (DIGEST_LENGTH, DIGEST_LENGTH)
)

# Defensive surface: the model sometimes drops the framing entirely. Measured on
# 16.09.2026 — asked to copy a code it returned the bare "P-DAEL6G25PQGC" 6 times
# out of 6, while another wording kept the brackets. A bare class letter plus a
# twelve character base32 digest does not occur in ordinary text.
BARE_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9-])([PTEDAIC])-([A-Z2-7]{%d})(?![A-Za-z0-9-])" % DIGEST_LENGTH
)


class TokenError(ValueError):
    """Malformed token.

    # START_CONTRACT: TokenError
    #   PURPOSE: Signal a token that cannot be parsed or generated.
    #   INPUTS: { code: str - machine code, message: str - human text }
    #   OUTPUTS: { TokenError - raised }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKEN-GEN
    # END_CONTRACT: TokenError
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def token_groups(match: re.Match) -> tuple[str, str]:
    """Return (class, digest) from whichever framed alternative matched."""
    if match.group(1) is not None:
        return match.group(1), match.group(2)
    return match.group(3), match.group(4)


# START_BLOCK_MAKE_TOKEN
def _code_for(cls: str, normalized: str, key: bytes, salt: int) -> str:
    """Derive one candidate identifier; salt 0 is the primary candidate."""
    message = f"{cls}:{normalized}" if salt == 0 else f"{cls}:{normalized}#{salt}"
    digest = hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()
    encoded = base64.b32encode(digest).decode("ascii").rstrip("=")
    return f"{CODE_PREFIX}{cls}{encoded[:CODE_LENGTH]}"


def make_token(cls: str, normalized: str, key: bytes) -> str:
    """Return the deterministic compact identifier for a class and value.

    # START_CONTRACT: make_token
    #   PURPOSE: Derive the primary identifier for a normalized value.
    #   INPUTS: { cls: str - class letter, normalized: str - normalized value, key: bytes - token key }
    #   OUTPUTS: { str - identifier such as zP482193 }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKENIZER, V-M-TOKEN-GEN, fn-candidate_tokens
    # END_CONTRACT: make_token
    """
    _validate_inputs(cls, key)
    return _code_for(cls, normalized, key, 0)


def candidate_tokens(cls: str, normalized: str, key: bytes) -> Iterator[str]:
    """Yield deterministic identifier candidates, primary first.

    # START_CONTRACT: candidate_tokens
    #   PURPOSE: Let the tokenizer skip an identifier that is already taken by another value without breaking determinism or the prompt cache.
    #   INPUTS: { cls: str - class letter, normalized: str - normalized value, key: bytes - token key }
    #   OUTPUTS: { Iterator[str] - candidate identifiers in a stable order }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKENIZER, V-M-TOKEN-GEN
    # END_CONTRACT: candidate_tokens
    """
    _validate_inputs(cls, key)
    for salt in range(MAX_CANDIDATES):
        yield _code_for(cls, normalized, key, salt)


def _validate_inputs(cls: str, key: bytes) -> None:
    """Reject an unusable class or key before any derivation happens."""
    if not key:
        raise TokenError("TOKEN_KEY_UNAVAILABLE", "token key is empty")
    if not cls or cls not in CLASS_LETTERS:
        raise TokenError("TOKEN_BAD_CLASS", f"unsupported class: {cls!r}")
# END_BLOCK_MAKE_TOKEN


# START_BLOCK_PARSE_TOKEN
def parse_token(token: str) -> tuple[str, str]:
    """Split any accepted identifier surface into class and code.

    # START_CONTRACT: parse_token
    #   PURPOSE: Validate and decompose an identifier string.
    #   INPUTS: { token: str - candidate identifier }
    #   OUTPUTS: { tuple[str, str] - (class, code) }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETOKENIZER, M-VALIDATOR, V-M-TOKEN-GEN
    # END_CONTRACT: parse_token
    """
    text = (token or "").strip()
    compact = CODE_SURFACE_PATTERN.fullmatch(text)
    if compact:
        return compact.group(1).upper(), compact.group(2).upper()
    framed = TOKEN_SURFACE_PATTERN.fullmatch(text)
    if framed:
        return token_groups(framed)
    bare = BARE_TOKEN_PATTERN.fullmatch(text)
    if bare:
        return bare.group(1), bare.group(2)
    raise TokenError("TOKEN_MALFORMED", f"not an identifier: {token!r}")


def canonical_token(token: str) -> str:
    """Return the canonical framed or compact form of any accepted surface.

    Bindings are stored under the canonical string, so a surface that arrived
    without framing, in the legacy framing, or in another case must be
    normalised before the correspondence table is consulted — otherwise the
    lookup silently misses and the reader keeps seeing the code.
    """
    text = (token or "").strip()
    if CODE_SURFACE_PATTERN.fullmatch(text):
        cls, code = parse_token(text)
        return f"{CODE_PREFIX}{cls}{code}"
    cls, digest = parse_token(text)
    return f"{SENTINEL_OPEN}{cls}-{digest}{SENTINEL_CLOSE}"
# END_BLOCK_PARSE_TOKEN


# START_BLOCK_CODE_NORMALISATION
#: Знаки, которыми модель подменяет буквы base32: цифры-двойники и кириллические похожие.
#: Замер 23.09.2026 на живом коде: из одиннадцати типовых искажений распознавались семь,
#: а именно эти три класса (разделитель внутри кода, кириллица, цифровой двойник) — нет,
#: и клиент получал код вместо значения. Таблица возвращает коду исходный вид; значение
#: по-прежнему берётся только из справочника — догадок о значении здесь нет.
CONFUSED_TO_BASE32: dict[str, str] = {
    "0": "O", "1": "I", "8": "B", "9": "G",
    "А": "A", "В": "B", "С": "C", "Е": "E", "Г": "G", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "Т": "T", "Х": "X", "У": "Y", "І": "I",
    "а": "A", "в": "B", "с": "C", "е": "E", "г": "G", "к": "K", "м": "M", "н": "H",
    "о": "O", "р": "P", "т": "T", "х": "X", "у": "Y", "і": "I",
}

#: Предельная длина кода вместе с разделителями внутри него. Разделитель допустим внутри
#: кода, но не должен растянуть его на пол-строки — иначе обычный текст («zebra zone zoom»)
#: собирался бы в «код» и подстановка выдала бы выдуманное значение.
MAX_CODE_SPAN = 20

#: Разделители, которые попадают внутрь кода из-за вёрстки или переноса строки: пробелы,
#: невидимые знаки, дефис, подчёркивание, знаки разметки. Смысла не несут — снимаются.
CODE_SEPARATORS = " \t\r\n\u00a0\u200b\u200c\u200d\u2060-_*`·•.,'’\"«»|/"

#: Максимальная длина «кодового» пробега: компактный код (10 знаков) плюс запас на разделители.
MAX_CODE_RUN = 32

#: Знаки, из которых может состоять «кодовый» пробег: буквы кода, классы, двойники, разделители.
CODE_RUN_CHARS = frozenset(
    "zZ" + CLASS_LETTERS + CLASS_LETTERS.lower()
    + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz234567"
    + "".join(CONFUSED_TO_BASE32) + CODE_SEPARATORS
)


def normalise_code_run(run: str) -> tuple[str, str] | None:
    """Вернуть (класс, канонический компактный код) для искажённой копии кода.

    # START_CONTRACT: normalise_code_run
    #   PURPOSE: Спасти код, который модель переписала с подменой знаков, разделителями или в кириллице.
    #   INPUTS: { run: str - «кодовый» пробег текста (разделители допустимы) }
    #   OUTPUTS: { tuple[str, str] | None - (класс, канонический код) либо None, если это не код }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKEN-GEN, fn-find_tokens, V-M-TOKEN-GEN
    # END_CONTRACT: normalise_code_run
    """
    cleaned = [ch for ch in (run or "") if ch not in CODE_SEPARATORS]
    if len(cleaned) != CODE_LENGTH + 2 or cleaned[0] not in ("z", "Z"):
        return None
    mapped = [CONFUSED_TO_BASE32.get(ch, ch).upper() for ch in cleaned[1:]]
    cls, body = mapped[0], "".join(mapped[1:])
    if cls not in CLASS_LETTERS or not re.fullmatch(rf"[A-Z2-7]{{{CODE_LENGTH}}}", body):
        return None
    return cls, f"{CODE_PREFIX}{cls}{body}"
# END_BLOCK_CODE_NORMALISATION


# START_BLOCK_FIND_TOKENS
def find_tokens(text: str) -> list[tuple[int, int, str, str]]:
    """Find every identifier inside a text block, canonicalised.

    # START_CONTRACT: find_tokens
    #   PURPOSE: Return identifier spans for detokenization and residual checks.
    #   INPUTS: { text: str - arbitrary text }
    #   OUTPUTS: { list[tuple[int, int, str, str]] - (start, end, class, canonical identifier) }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETOKENIZER, V-M-DETOKENIZER
    # END_CONTRACT: find_tokens
    """
    text = text or ""
    found: list[tuple[int, int, str, str]] = []
    framed: list[tuple[int, int]] = []
    for match in TOKEN_SURFACE_PATTERN.finditer(text):
        cls, _digest = token_groups(match)
        found.append((match.start(), match.end(), cls, canonical_token(match.group(0))))
        framed.append((match.start(), match.end()))
    for match in BARE_TOKEN_PATTERN.finditer(text):
        start, end = match.start(), match.end()
        if any(start < framed_end and framed_start < end for framed_start, framed_end in framed):
            continue  # already covered by a framed match
        found.append((start, end, match.group(1), canonical_token(match.group(0))))
    for match in CODE_PATTERN.finditer(text):
        start, end = match.start(), match.end()
        if any(start < framed_end and framed_start < end for framed_start, framed_end in framed):
            continue
        found.append((start, end, match.group(1).upper(), canonical_token(match.group(0))))
    # Толерантный проход: модель переписывает код с подменой знаков, кириллицей или
    # разделителями — строгие шаблоны такие копии не видят, и клиент получает код вместо
    # значения (замер 23.09.2026). Берём «кодовый» пробег, оставляем в нём ровно десять
    # значимых знаков (столько их в компактном коде) и возвращаем к исходному виду.
    # Значения это не выдумывает: кода нет в справочнике — он остаётся кодом и попадает
    # в счётчик unknown, который виден в журнале.
    for match in re.finditer(r"[zZ]", text):
        if match.start() > 0 and text[match.start() - 1].isalnum():
            continue  # код приклеен к слову («XzPAY4P5LAD») — это не код
        if any(start <= match.start() < end for start, end, _cls, _canon in found):
            continue
        run = text[match.start() : match.start() + MAX_CODE_RUN]
        significant = [(idx, ch) for idx, ch in enumerate(run) if ch not in CODE_SEPARATORS][: CODE_LENGTH + 2]
        if len(significant) < CODE_LENGTH + 2:
            continue
        span_end = match.start() + significant[-1][0] + 1
        if span_end - match.start() > MAX_CODE_SPAN:
            continue  # разделители разнесли знаки далеко — это не код, а обычная фраза
        raw = "".join(ch for _idx, ch in significant)
        if not any(ch.isupper() or ch.isdigit() for ch in raw):
            continue  # настоящее написание кода несёт заглавные или цифры; слово — нет
        normalised = normalise_code_run(raw)
        if normalised is None:
            continue
        cls, canonical = normalised
        found.append((match.start(), span_end, cls, canonical))
    found.sort(key=lambda item: item[0])
    return found


def is_valid_token(token: str) -> bool:
    """Return True when the string is exactly one well formed identifier."""
    text = (token or "").strip()
    return bool(
        CODE_SURFACE_PATTERN.fullmatch(text)
        or TOKEN_SURFACE_PATTERN.fullmatch(text)
        or BARE_TOKEN_PATTERN.fullmatch(text)
    )
# END_BLOCK_FIND_TOKENS


# START_BLOCK_TOKEN_PREFIX
#: Семейства «хвостов», из которых любое продолжение может собрать код: те же поверхности,
#: что ищет find_tokens, но допущены недостроенные их части. По этому правилу поток решает,
#: подтверждена ли позиция разреза (критерий подтверждённой позиции — veilstream, Apache-2.0).
#:
#: Правило намеренно без просмотра назад: разрез, который «знает», что слева буква и потому
#: кодом это быть не может, отдаёт клиенту последний знак кода — и следующий кусок, начавшись
#: посреди кода, разбирается не так, как в непотоковом пути (найдено property-тестом
#: 18.09.2026 на «XzPAY4P5LAD»). Удержать лишний знак стоит одного кадра, а неверный разбор —
#: текста клиента, поэтому здесь только поверхность.
_PREFIX_FAMILIES: tuple[re.Pattern, ...] = (
    re.compile(r"z(?:[PTEDAIC][A-Z2-7]{0,8})?", re.IGNORECASE),
    re.compile(r"\[(?:\[(?:[PTEDAIC]-?[A-Z2-7]{0,12})?(?:\]{0,2})?)?"),
    re.compile("\u27e6(?:[PTEDAIC]-?[A-Z2-7]{0,12})?(?:\u27e7)?"),
    re.compile(r"\\[\\A-Za-z0-9-]{0,25}"),
    re.compile(r"[PTEDAIC]-?[A-Z2-7]{0,12}"),
)

#: Длина самой длинной поверхности кода: экранированная легаси-форма (\\u27e6P-XXXXXXXXXXXX\\u27e7).
MAX_SURFACE_CHARS = 26


def token_prefix_length(text: str) -> int:
    """Return the longest tail of a text that any continuation could turn into a code.

    # START_CONTRACT: token_prefix_length
    #   PURPOSE: Дать потоку формальный ответ на вопрос «можно ли отдать этот знак клиенту».
    #   INPUTS: { text: str - буфер потока }
    #   OUTPUTS: { int - длина опасного хвоста, 0 когда позиция подтверждена }
    #   SIDE_EFFECTS: none
    #   LINKS: M-STREAM-RELAY, M-DETOKENIZER, V-M-STREAM-RELAY
    # END_CONTRACT: token_prefix_length

    Хвост опасен ровно тогда, когда он сам является началом кода: ``z``, ``zP``, ``[``,
    ``[[P-``, ``\\u27e6``, ``P-XXXXXXXXXXXX``. Длина считается по самой длинной такой части,
    поэтому разрез не попадает внутрь недостроенного кода (у компактного кода обрамления нет,
    и старая эвристика по скобкам рубила его пополам).
    """
    if not text:
        return 0
    limit = min(len(text), MAX_SURFACE_CHARS)
    for length in range(limit, 0, -1):
        tail = text[len(text) - length :]
        for pattern in _PREFIX_FAMILIES:
            if pattern.fullmatch(tail):
                return length
    return 0
# END_BLOCK_TOKEN_PREFIX


def iter_token_values(text: str) -> Iterable[str]:
    """Yield every distinct canonical identifier found in a text block, in order."""
    seen: set[str] = set()
    for _, _, _, full in find_tokens(text):
        if full not in seen:
            seen.add(full)
            yield full


# START_BLOCK_VALUE_OCCURRENCES
# Предикат «это то же значение» живёт здесь ровно потому, что им пользуются ТРИ места:
# токенизатор (что заменять), заслон (что считать остатком) и починка (что доводить до
# конца). Пока критериев было три, они расходились: токенизатор сравнивал точное
# написание, заслон — вхождение по соседям, и значение уходило кодом в одном написании,
# оставаясь в исходящем запросе в другом (инцидент 20.09.2026: «заслон нашёл 617 значений,
# 307 ушло провайдеру»). Один критерий на всех — условие того, что «нашёл» и «заменил»
# говорят об одном и том же.

#: Буква (не цифра, не подчёркивание): граница слова, как её видит проверка вхождения.
BOUNDARY_CLASS = r"[^\W\d_]"


def flexible_pattern(text: str) -> str:
    """Собрать шаблон значения, устойчивый к пробелам и неразрывным пробелам.

    # START_CONTRACT: flexible_pattern
    #   PURPOSE: Найти значение там, где оно записано чуть иначе по пробелам, не теряя границ слова.
    #   INPUTS: { text: str - значение или его фрагмент }
    #   OUTPUTS: { str - исходник регулярного выражения }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKEN-GEN, M-TOKENIZER, M-VALIDATOR, V-M-TOKENIZER
    # END_CONTRACT: flexible_pattern

    Значения приходят из CRM неровно: двойные пробелы, неразрывный пробел, пробел перед
    запятой. Точное совпадение строки на таком тексте промахивается, и остаток остался бы
    незаменённым — то есть запрос ушёл бы в блокировку на ровном месте.
    """
    parts = [
        re.escape(part)
        for part in re.split(r"\s+", re.sub(r"\s+", " ", text or "").strip())
        if part
    ]
    if not parts:
        return ""
    return r"[\s\u00a0]+".join(parts)


def word_bounded(pattern: str) -> str:
    """Ограничить шаблон границами слова (не часть другого слова).

    # START_CONTRACT: word_bounded
    #   PURPOSE: Не заменить часть другого слова.
    #   INPUTS: { pattern: str - исходник шаблона }
    #   OUTPUTS: { str - исходник шаблона с границами }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKEN-GEN, M-TOKENIZER, M-VALIDATOR, V-M-TOKENIZER
    # END_CONTRACT: word_bounded
    """
    return rf"(?<!{BOUNDARY_CLASS}){pattern}(?!{BOUNDARY_CLASS})"


def iter_value_occurrences(text: str, value: str) -> Iterator[tuple[int, int]]:
    """Yield (начало, конец) каждого вхождения значения в текст, в порядке появления.

    # START_CONTRACT: iter_value_occurrences
    #   PURPOSE: Судить значение по написанию, а не по позиции: та же запись в другом регистре — то же значение.
    #   INPUTS: { text: str - блок текста, value: str - наблюдённое значение }
    #   OUTPUTS: { Iterator[tuple[int, int]] - границы вхождений }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKEN-GEN, M-TOKENIZER, M-VALIDATOR, V-M-TOKENIZER
    # END_CONTRACT: iter_value_occurrences

    Регистр не важен: «Иванов» и «ИВАНОВ» — одна персона, и уйти провайдеру должно одно
    значение целиком, а не то написание, которое первым попалось детектору. Позиция для
    этого критерия не годится: после первой замены смещения сдвигаются.
    """
    pattern = flexible_pattern(value)
    if not pattern or not text:
        return
    for match in re.finditer(word_bounded(pattern), text, re.IGNORECASE):
        yield match.start(), match.end()


def same_value_text(observed: str, token: str) -> bool:
    """Совпадает ли выданный код с самим значением (по нормализованному написанию).

    # START_CONTRACT: same_value_text
    #   PURPOSE: Не принять «замену» за замену, если фабрика кодов вернула само значение.
    #   INPUTS: { observed: str - найденный текст, token: str - выданный код }
    #   OUTPUTS: { bool - True, когда менять нечего }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKEN-GEN, M-TOKENIZER, M-VALIDATOR
    # END_CONTRACT: same_value_text
    """
    normalize = lambda s: re.sub(r"\s+", " ", s or "").strip().lower()
    return normalize(observed) == normalize(token)


def replace_value_occurrences(
    text: str,
    value: str,
    replacement: str,
) -> tuple[str, int]:
    """Заменить значением кода все вхождения значения в строке.

    # START_CONTRACT: replace_value_occurrences
    #   PURPOSE: Довести замену до конца: остаток, который видит заслон, должен уйти кодом целиком.
    #   INPUTS: { text: str - текущая строка, value: str - наблюдённое значение, replacement: str - выданный код }
    #   OUTPUTS: { tuple[str, int] - строка с кодами и число замен }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKEN-GEN, M-TOKENIZER, M-VALIDATOR, V-M-TOKENIZER
    # END_CONTRACT: replace_value_occurrences

    Дефект 20.09.2026: прежняя замена убирала ровно одно написание (у токенизатора — точное,
    у починки — попадавшее в окно после соседа). Значение в другом регистре оставалось в
    исходящем тексте, и запрос либо уходил провайдеру с данными, либо падал в блокировку.
    Теперь заменяются все вхождения значения (``iter_value_occurrences``) в любом регистре —
    и токенизатором, и починкой, одним и тем же кодом.

    Потолок на число замен — вхождения, посчитанные до правки: фабрика кодов, вернувшая само
    значение, иначе крутила бы цикл вечно.
    """
    if not text or not replacement:
        return text, 0
    limit = sum(1 for _ in iter_value_occurrences(text, value))
    if not limit:
        return text, 0
    result = text
    done = 0
    while done < limit:
        found = None
        for start, end in iter_value_occurrences(result, value):
            if same_value_text(result[start:end], replacement):
                # Код совпал со значением: это не замена. Такой кандидат пропускаем, но
                # остальные менять не мешаем — иначе запрос ушёл бы в отказ из-за одного
                # совпадения кода со значением.
                continue
            found = (start, end)
            break
        if found is None:
            break
        start, end = found
        result = result[:start] + replacement + result[end:]
        done += 1
    return result, done
# END_BLOCK_VALUE_OCCURRENCES
