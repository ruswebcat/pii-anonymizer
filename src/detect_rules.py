# FILE: src/detect_rules.py
# VERSION: 1.4.0
# START_MODULE_CONTRACT
#   PURPOSE: Find PII by format and context (phones, e-mail, documents, addresses, birth dates, client identifiers, российские идентификаторы) and by table column headers.
#   SCOPE: regex detection per class with normalization, Russian identifier rules from M-DETECT-RU-PII, context-gated birth dates, delimiter-aware tabular detection, overlap resolution.
#   DEPENDS: M-NORM, M-DETECT-RU-PII
#   LINKS: M-DETECT-RULES, V-M-DETECT-RULES, fn-detect_rules, fn-detect_tabular, type-PiiMatch
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   PiiMatch - one detected span with class and canonical value
#   HEADER_CLASSES - CSV header keyword to class mapping
#   HEADER_CELL_MAX - предел длины ячейки строки-заголовка: подпись колонки, а не абзац
#   fn-_header_row_ok - строка похожа на шапку таблицы, а не на обычный текст
#   DATE_CONTEXT_WORDS - words that gate class D detection
#   fn-detect_rules - rule based matches inside a text block, включая российские идентификаторы
#   fn-detect_tabular - matches driven by table column headers
#   fn-merge_matches - drop overlaps, keep the most specific span
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.4.0 - шапкой таблицы считается только строка коротких подписей — абзац с перечислением полей («…ФИО, телефон, почта, адрес, дата рождения…») больше не превращает соседние строки в данные и не обезличивает слово «адрес» (161 ложная замена в одном блоке системного промпта).
#   PREVIOUS: v1.3.0 - свои адреса и телефоны ресепции приходят из настроек (own_constants, own_phone_digits): адрес и номер клуба перестали быть константами кода, сравнение номеров идёт одной свёрткой с настройками.
#   PREVIOUS: v1.2.0 - Phase-9 шаг 2: общий набор находок дополнен российскими идентификаторами (M-DETECT-RU-PII); токенизатор и заслон берут их из одного вызова.
#   PREVIOUS: v1.1.0 - Phase-7 шаг 2: у находки появилось поле identity (персона), правила его не заполняют.
#   EARLIER: v1.0.0 - Phase-1 M-DETECT-RULES: formats plus context; birth dates require context so report dates stay untouched.
# END_CHANGE_SUMMARY

"""Rule based PII detection.

Implements M-DETECT-RULES from docs/ARCHITECTURE.md. Two design decisions
matter for false positives (V-M-DETECT-RULES explicitly asserts zero false hits
on sums and report dates):

* a phone must be 11 digits starting with 7 or 8, so amounts such as 28000 and
  card prices cannot match;
* a birth date is only tokenized when the surrounding line carries a birth
  context word, otherwise reporting dates like 15.09.2026 stay open.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from src.detect_ru_pii import detect_ru_pii
from src.normalize import NormalizeError, normalize, split_birth_date
from src.own_vocabulary import digits_only, own_addresses, own_phone_digits as own_number_digits
from src.token_factory import is_valid_token

LOGGER_NAME = "RuleDetector"
LOG_MARKER = "[RuleDetector][detect_rules][BLOCK_SCAN_RULES]"

CLASS_PHONE = "T"
CLASS_EMAIL = "E"
CLASS_DOCUMENT = "I"
CLASS_ADDRESS = "A"
CLASS_BIRTH_DATE = "D"
CLASS_CLIENT = "C"
CLASS_NAME = "P"


@dataclass(frozen=True)
class PiiMatch:
    """One detected PII span.

    # START_CONTRACT: PiiMatch
    #   PURPOSE: Carry span, class and canonical value for replacement.
    #   INPUTS: { start: int, end: int, cls: str, raw: str, normalized: str }
    #   OUTPUTS: { PiiMatch - value object }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKENIZER, M-VALIDATOR
    # END_CONTRACT: PiiMatch
    """

    start: int
    end: int
    cls: str
    raw: str
    normalized: str
    open_suffix: str = ""
    #: Идентичность значения (M-NAME-IDENTITY): из неё выводится код. Пусто у правиловых
    #: находок — там идентичностью остаётся нормализованное значение, как было.
    identity: str = ""


# START_BLOCK_SCAN_RULES
PHONE_PATTERN = re.compile(
    r"(?<![\d+])(?:(?:\+7|8|7)(?:[\s\-()]*\d){10}|9\d{9})(?!\d)"
)
# Второй вариант — мобильный номер без префикса (10 цифр, начинается с 9): так телефоны
# печатаются в выгрузках и таблицах CRM. Находка 17.09.2026: приёмка по классу
# «телефон» показала, что такой номер уходил в модель открытым.
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
SNILS_PATTERN = re.compile(r"(?<!\d)\d{3}-\d{3}-\d{3}\s?\d{2}(?!\d)")
PASSPORT_PATTERN = re.compile(r"(?<!\d)\d{2}\s?\d{2}\s?№?\s?\d{6}(?!\d)")
INN_PATTERN = re.compile(r"(?<!\d)\d{12}(?!\d)")
ADDRESS_PATTERN = re.compile(
    r"(?:ул\.|улица|пр-т|проспект|б-р|бульвар|шоссе|ш\.|пер\.|переулок)\s+"
    r"[А-ЯЁA-Z][^,;|\n]{2,40}"
)
ADDRESS_TAIL_PATTERN = re.compile(r"^[,;]?\s*(?:д\.|дом|кв\.|квартира|корп\.?)\s*[\wА-Яа-яЁё\-/]{1,10}")
BIRTH_DATE_PATTERN = re.compile(r"(?<!\d)(\d{1,2})[.\-/](\d{1,2})[.\-/](\d{4})(?!\d)")
# ISO dates put the year first, so only the trailing month-day is matched: that
# is the identifying part, and the year must stay open (owner decision).
# CRM returns this order in some selections — the re-identification test
# caught birth dates surviving untokenized on 15.09.2026.
ISO_BIRTH_DATE_PATTERN = re.compile(r"(?<=\d{4}-)(\d{2})-(\d{2})(?!\d)")
CLIENT_ID_PATTERN = re.compile(
    r"(?:client_id|client\s?id|ид\s?клиента|№\s?договора|договор\s?№|№\s?карты|карта\s?№|"
    r"анкета\s?№|№\s?анкеты|номер\s?карты)"
    # A client identifier appears both as plain text (`client_id=35209`) and inside
    # JSON (`"client_id": "35209"`). The optional quotes keep both shapes detectable,
    # otherwise the same message tokenizes differently on the next turn and the
    # provider prompt cache prefix breaks (verified 15.09.2026).
    r"(?:\\?[\"'])?\s*[:№=]?\s*(?:\\?[\"'])?(\d{3,})",
    re.IGNORECASE,
)

DATE_CONTEXT_WORDS = ("г.р", "г р", "рождения", "родился", "родилась", "дата рождения", "др клиента")
# Document look-alikes: without these guards a 10-digit Unix timestamp from
# ``created_at`` was read as a passport number and the fail-closed validator
# blocked every real CRM selection (found by the A/B run on 15.09.2026).
DOCUMENT_CONTEXT_WORDS = ("паспорт", "инн", "снилс", "документ", "серия и номер", "выдан")
EPOCH_SECONDS = (1_000_000_000, 2_300_000_000)
EPOCH_MILLIS = (1_000_000_000_000, 2_300_000_000_000)

HEADER_CLASSES = {
    "фио": CLASS_NAME,
    "ф.и.о": CLASS_NAME,
    "имя": CLASS_NAME,
    "фамилия": CLASS_NAME,
    "клиент": CLASS_NAME,
    "телефон": CLASS_PHONE,
    "тел": CLASS_PHONE,
    "тел.": CLASS_PHONE,
    "phone": CLASS_PHONE,
    "мобильный": CLASS_PHONE,
    "e-mail": CLASS_EMAIL,
    "email": CLASS_EMAIL,
    "почта": CLASS_EMAIL,
    "адрес": CLASS_ADDRESS,
    "дата рождения": CLASS_BIRTH_DATE,
    "дата рожд": CLASS_BIRTH_DATE,
    "др": CLASS_BIRTH_DATE,
    "client_id": CLASS_CLIENT,
    "id клиента": CLASS_CLIENT,
    "номер договора": CLASS_CLIENT,
    "номер карты": CLASS_CLIENT,
    "№ договора": CLASS_CLIENT,
    "№ карты": CLASS_CLIENT,
}

DELIMITERS = (",", ";", "\t", "|")

#: Предел длины ячейки строки-заголовка. Имя колонки — короткая подпись, а не абзац текста;
#: самая длинная подпись в `HEADER_CLASSES` — «дата рождения» (13 знаков), а в настоящих
#: выгрузках ячейка заголовка не длиннее «Электронная почта».
#:
#: Находка 26.09.2026: строка системного промпта «Персональные данные клиентов (ФИО, телефон,
#: почта, адрес, дата рождения) приходят в коде…» принималась за строку заголовков — в ней
#: стоят «телефон», «почта», «адрес» и «дата рождения», — и в каждой следующей строке блока
#: слово «адрес» заменялось кодом класса «адрес»: 161 замена в одном блоке, где персональных
#: данных нет вовсе.
HEADER_CELL_MAX = 60


def _header_row_ok(cells: Sequence[str]) -> bool:
    """Сказать, похожа ли строка на строку заголовков таблицы, а не на абзац обычного текста.

    # START_CONTRACT: _header_row_ok
    #   PURPOSE: Не принять прозу за шапку таблицы: подпись колонки короткая, абзац — нет.
    #   INPUTS: { cells: Sequence[str] - ячейки строки, уже очищенные и приведённые к нижнему регистру }
    #   OUTPUTS: { bool - True, если все непустые ячейки короче предела подписи }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-RULES, fn-detect_tabular, V-M-DETECT-RULES
    # END_CONTRACT: _header_row_ok

    Проверка нужна только шапке: строки данных бывают любой длины, а вот имя колонки длинным
    не бывает. Без неё абзац с перечислением подписей полей превращался в таблицу и обезличивал
    соседние строки (замер 26.09.2026, блок системного промпта).
    """
    return all(len(cell) <= HEADER_CELL_MAX for cell in cells if cell)


def _line_bounds(text: str, position: int) -> tuple[int, int]:
    start = text.rfind("\n", 0, position) + 1
    end = text.find("\n", position)
    return start, len(text) if end == -1 else end


DATE_CONTEXT_WINDOW = 32


def _has_date_context(
    text: str, position: int, context: str | None, window: int = DATE_CONTEXT_WINDOW
) -> bool:
    """Return True when a birth context word sits near the date.

    # START_CONTRACT: _has_date_context
    #   PURPOSE: Gate class D so reporting dates stay open.
    #   INPUTS: { text: str, position: int - date offset, context: str | None, window: int }
    #   OUTPUTS: { bool - True when context is present }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-RULES, V-M-DETECT-RULES
    # END_CONTRACT: _has_date_context

    The window (not the whole line) matters: an agent request is one very long
    JSON line, so a line-based check made every date in the payload look like a
    birth date as soon as a single "дата рождения" key existed anywhere
    (false positive found by the dry-run rehearsal on 15.09.2026).
    """
    if window <= 0:
        haystack = (text + " " + (context or "")).lower()
        return any(word in haystack for word in DATE_CONTEXT_WORDS)
    start = max(0, position - window)
    end = min(len(text), position + window)
    haystack = (text[start:end] + " " + (context or "")).lower()
    return any(word in haystack for word in DATE_CONTEXT_WORDS)


def _safe_normalize(cls: str, raw: str) -> str | None:
    try:
        return normalize(cls, raw)
    except NormalizeError:
        return None


def _birth_date_match(text: str, start: int, raw: str) -> PiiMatch | None:
    """Build a class D match that tokenizes day and month but leaves the year open.

    # START_CONTRACT: _birth_date_match
    #   PURPOSE: Keep the separator between day-month and year outside the span.
    #   INPUTS: { text: str - source text, start: int - span start, raw: str - matched date }
    #   OUTPUTS: { PiiMatch | None - match covering only day and month }
    #   SIDE_EFFECTS: none
    #   LINKS: M-NORM, V-M-DETECT-RULES
    # END_CONTRACT: _birth_date_match
    """
    try:
        day_month, year = split_birth_date(raw)
    except NormalizeError:
        return None
    prefix = raw[: raw.rfind(year)]
    value = prefix.rstrip(".-/ ")
    if not value:
        return None
    return PiiMatch(
        start,
        start + len(value),
        CLASS_BIRTH_DATE,
        text[start : start + len(value)],
        day_month,
        open_suffix="." + year,
    )


def _document_looks_real(text: str, position: int, raw: str) -> bool:
    """Return True when a document-shaped number really is a document.

    # START_CONTRACT: _document_looks_real
    #   PURPOSE: Keep timestamps and bare long numbers out of class I.
    #   INPUTS: { text: str, position: int - match offset, raw: str - matched text }
    #   OUTPUTS: { bool - True when the match should be tokenized }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-RULES, M-VALIDATOR, V-M-DETECT-RULES
    # END_CONTRACT: _document_looks_real

    Precision matters here more than anywhere else in the detector: every class I
    match must survive the fail-closed validator, which refuses to send a request
    at all. A rule that reads ``created_at`` as a passport number therefore does
    not merely annoy — it stops the agent from working (measured 15.09.2026:
    every selection with timestamps was rejected with 403).
    """
    digits = re.sub(r"\D", "", raw)
    if _has_document_context(text, position):
        return True
    if len(digits) == 12:
        return _inn_12_checksum_ok(digits)
    if len(digits) == 10:
        number = int(digits)
        if EPOCH_SECONDS[0] <= number <= EPOCH_SECONDS[1]:
            return False
        return bool(re.search(r"[\s-]", raw))
    return bool(re.search(r"[\s-]", raw))


def _has_document_context(text: str, position: int, window: int = DATE_CONTEXT_WINDOW) -> bool:
    """Return True when a document word sits near the match."""
    start = max(0, position - window)
    window_text = text[start : position + window].lower()
    return any(word in window_text for word in DOCUMENT_CONTEXT_WORDS)


def _inn_12_checksum_ok(digits: str) -> bool:
    """Validate the two check digits of a 12-digit INN (ФНС algorithm)."""
    if len(digits) != 12 or not digits.isdigit():
        return False
    if digits in {str(EPOCH_MILLIS[0]), str(EPOCH_MILLIS[1])}:
        return False
    if EPOCH_MILLIS[0] <= int(digits) <= EPOCH_MILLIS[1]:
        return False
    weights_11 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
    weights_12 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
    check_11 = sum(int(digits[i]) * weights_11[i] for i in range(10)) % 11 % 10
    check_12 = sum(int(digits[i]) * weights_12[i] for i in range(11)) % 11 % 10
    return check_11 == int(digits[10]) and check_12 == int(digits[11])


def detect_rules(text: str, context: str | None = None) -> list[PiiMatch]:
    """Return rule based matches for a text block.

    # START_CONTRACT: detect_rules
    #   PURPOSE: Detect phone, e-mail, document, address, birth date and client id spans.
    #   INPUTS: { text: str - block to scan, context: str | None - extra nearby text }
    #   OUTPUTS: { list[PiiMatch] - matches with canonical values }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKENIZER, M-NORM, V-M-DETECT-RULES
    # END_CONTRACT: detect_rules
    """
    if not text:
        return []
    matches: list[PiiMatch] = []

    for pattern, cls in (
        (PHONE_PATTERN, CLASS_PHONE),
        (EMAIL_PATTERN, CLASS_EMAIL),
        (SNILS_PATTERN, CLASS_DOCUMENT),
        (INN_PATTERN, CLASS_DOCUMENT),
        (PASSPORT_PATTERN, CLASS_DOCUMENT),
    ):
        for found in pattern.finditer(text):
            raw = found.group(0)
            if cls == CLASS_DOCUMENT and not _document_looks_real(text, found.start(), raw):
                continue
            value = _safe_normalize(cls, raw)
            if value is None:
                continue
            matches.append(PiiMatch(found.start(), found.end(), cls, raw, value))

    for found in ADDRESS_PATTERN.finditer(text):
        start, end = found.start(), found.end()
        while True:
            tail = ADDRESS_TAIL_PATTERN.match(text[end : end + 20])
            if not tail:
                break
            end += tail.end()
        raw = text[start:end]
        value = _safe_normalize(CLASS_ADDRESS, raw)
        if value is None:
            continue
        matches.append(PiiMatch(start, end, CLASS_ADDRESS, raw, value))

    for found in BIRTH_DATE_PATTERN.finditer(text):
        if not _has_date_context(text, found.start(), context):
            continue
        match = _birth_date_match(text, found.start(), found.group(0))
        if match is not None:
            matches.append(match)

    for found in ISO_BIRTH_DATE_PATTERN.finditer(text):
        if not _has_date_context(text, found.start(), context):
            continue
        month, day = int(found.group(1)), int(found.group(2))
        if not (1 <= day <= 31 and 1 <= month <= 12):
            continue
        raw = found.group(0)
        # The canonical day-month key is built directly: class D is normalized
        # through split_birth_date, and ``normalize("D", ...)`` is unsupported by
        # design. The year sits *before* the span here, so nothing is appended
        # after the token — unlike the dotted form, where the year follows it.
        matches.append(
            PiiMatch(
                found.start(),
                found.end(),
                CLASS_BIRTH_DATE,
                raw,
                f"{day:02d}.{month:02d}",
            )
        )

    for found in CLIENT_ID_PATTERN.finditer(text):
        digits = found.group(1)
        value = _safe_normalize(CLASS_CLIENT, digits)
        if value is None:
            continue
        matches.append(
            PiiMatch(found.start(1), found.end(1), CLASS_CLIENT, digits, value)
        )

    # Российские идентификаторы (M-DETECT-RU-PII): форма плюс контрольная сумма, а где суммы
    # нет — слово-признак рядом. Подключение стоит здесь, а не в токенизаторе отдельно, потому
    # что этот же вызов делает остаточный заслон: разойдись наборы находок — заслон счёл бы
    # остаточными ПД то, что токенизатор осознанно оставил, и запрос упал бы с 403 (находка
    # 18.09.2026). Один источник находок — одно решение о судьбе запроса.
    for cls_ru, _ru_value, ru_start, ru_end, _rule in detect_ru_pii(text):
        raw = text[ru_start:ru_end]
        value = _safe_normalize(cls_ru, raw)
        if value is None:
            continue
        matches.append(PiiMatch(ru_start, ru_end, cls_ru, raw, value))

    return merge_matches(matches)


def _pick_delimiter(text: str) -> str:
    best, best_count = ",", 0
    for delimiter in DELIMITERS:
        count = text.count(delimiter)
        if count > best_count:
            best, best_count = delimiter, count
    return best


# START_BLOCK_VALUE_LIKE
# Разметка — не значение. Находка 18.09.2026 (живой блок на Mattermost): разделитель
# markdown-таблицы `---` стоит в той же колонке, что и данные, и принимался за значение
# класса «ФИО». Токенизатор его не заменял (заменять нечего), а заслон видел «значение
# осталось в тексте» и блокировал каждый такой запрос. Значением считается только то,
# в чём есть буква или цифра: пунктир, рамки и прочая разметка выпадают.
VALUE_LIKE = re.compile(r"[^\W_]", re.UNICODE)


def _is_value_like(raw: str) -> bool:
    """Return True when a cell holds a value rather than table markup.

    # START_CONTRACT: _is_value_like
    #   PURPOSE: Keep markup out of detection so the gate does not block on it.
    #   INPUTS: { raw: str - cell content }
    #   OUTPUTS: { bool - True when the cell has at least one letter or digit }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-RULES, M-TOKENIZER, M-VALIDATOR, V-M-DETECT-RULES
    # END_CONTRACT: _is_value_like
    """
    return bool(VALUE_LIKE.search(raw))
# END_BLOCK_VALUE_LIKE


def detect_tabular(text: str) -> list[PiiMatch]:
    """Detect PII inside table rows using the header row as the class map.

    # START_CONTRACT: detect_tabular
    #   PURPOSE: Force tokenization of values in columns named ФИО, Телефон and similar,
    #            which is how agent-pasted CRM exports are handled.
    #   INPUTS: { text: str - table text }
    #   OUTPUTS: { list[PiiMatch] - matches for mapped columns }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKENIZER, V-M-DETECT-RULES
    # END_CONTRACT: detect_tabular
    """
    if not text or "\n" not in text:
        return []
    delimiter = _pick_delimiter(text)
    lines = text.split("\n")
    offset = 0
    header_index = -1
    column_map: dict[int, str] = {}
    for index, line in enumerate(lines):
        cells = [cell.strip().strip('"').lower() for cell in line.split(delimiter)]
        mapped = {
            position: HEADER_CLASSES[cell]
            for position, cell in enumerate(cells)
            if cell in HEADER_CLASSES
        }
        if mapped and len(cells) >= 2 and _header_row_ok(cells):
            header_index = index
            column_map = mapped
            break
    if header_index < 0:
        return []

    matches: list[PiiMatch] = []
    for line in lines[:header_index]:
        offset += len(line) + 1
    header_line = lines[header_index]
    offset += len(header_line) + 1

    for line in lines[header_index + 1 :]:
        if not line.strip():
            offset += len(line) + 1
            continue
        cursor = 0
        for position, raw_cell in enumerate(line.split(delimiter)):
            cell_start = offset + cursor
            cell_end = cell_start + len(raw_cell)
            cursor += len(raw_cell) + len(delimiter)
            cls = column_map.get(position)
            if cls is None:
                continue
            raw = raw_cell.strip().strip('"')
            if not raw or raw.startswith("\u27e6") or is_valid_token(raw):
                continue
            if not _is_value_like(raw):
                continue
            if cls == CLASS_BIRTH_DATE:
                match = _birth_date_match(text, cell_start, raw)
                if match is not None:
                    matches.append(match)
                continue
            value = _safe_normalize(cls, raw)
            if value is None:
                continue
            matches.append(PiiMatch(cell_start, cell_end, cls, raw, value))
        offset += len(line) + 1
    return merge_matches(matches)


# START_BLOCK_OWN_CONSTANTS
#   fn-own_constants - свои адреса оператора из настроек
#   fn-own_phone_digits - телефоны ресепции оператора из настроек
# Собственные адреса оператора (адреса клубов). Это не данные клиентов, но они попадают
# в словарь законно: часть карточек заведена на адрес клуба. Находка 16.09.2026: единственная
# ложная замена на реальном словаре была именно такой.
#
# В коде адресов НЕТ: их задаёт оператор в настройках (``src/own_vocabulary.py``,
# ``config.example.yaml``), потому что адрес — свойство организации, а не алгоритма.
# Пустое значение безопасно: правила просто не отбрасывают ничего сверх обычного.
def own_constants() -> frozenset[str]:
    """Return the operator's own addresses, taken from configuration.

    # START_CONTRACT: own_constants
    #   PURPOSE: Держать адреса оператора вне класса персон, не зашивая их в код.
    #   INPUTS: none
    #   OUTPUTS: { frozenset[str] - нормализованные адреса из настроек }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-RULES, M-OWN-VOCABULARY, V-M-DETECT-RULES
    # END_CONTRACT: own_constants
    """
    return own_addresses()


# Собственные номера оператора (телефоны ресепции). Это не данные клиента, но они законно
# попадают в словарь: часть карточек заведена с номером клуба. Находка 17.09.2026: приёмка
# по классу «телефон» показала ложную замену — номер клуба в тексте превращался в код.
# Сравнение идёт по цифрам, поэтому формат записи не важен.
def own_phone_digits() -> frozenset[str]:
    """Return the digit forms of the operator's own switchboards, taken from configuration.

    # START_CONTRACT: own_phone_digits
    #   PURPOSE: Не заменять номер своего клуба, не зашивая его в код.
    #   INPUTS: none
    #   OUTPUTS: { frozenset[str] - цифры номеров из настроек, 8-форма приведена к 7-форме }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-RULES, M-OWN-VOCABULARY, V-M-DETECT-RULES
    # END_CONTRACT: own_phone_digits
    """
    return own_number_digits()
# END_BLOCK_OWN_CONSTANTS


KNOWN_NUMBER_PATTERN = re.compile(r"(?<![\d])(\d{7,12})(?![\d])")


def detect_known_numbers(text: str, lookup: object) -> list[PiiMatch]:
    """Return matches for known client and document numbers found in free text.

    # START_CONTRACT: detect_known_numbers
    #   PURPOSE: Cover client card numbers and documents outside table rows.
    #   INPUTS: { text: str, lookup: object - callable(value, cls) -> bool }
    #   OUTPUTS: { list[PiiMatch] - matches for known numbers }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-RULES, M-TOKENIZER
    # END_CONTRACT: detect_known_numbers

    Находка 17.09.2026 (приёмка по классам ПД): номер карты клиента в обычном тексте
    («карта 100200300») уходил в модель открытым — распознавание смотрело только строки
    таблиц. Берём одиночные числа от семи цифр: цены и сроки короче, поэтому суммы в
    обычных текстах под это правило не попадают, а известные номера из словаря —
    попадают и заменяются.
    """
    matches: list[PiiMatch] = []
    if not callable(lookup):
        return matches
    for found in KNOWN_NUMBER_PATTERN.finditer(text or ""):
        raw = found.group(1)
        cls = None
        for candidate_cls in (CLASS_CLIENT, CLASS_DOCUMENT):
            try:
                if lookup(raw, candidate_cls):
                    cls = candidate_cls
                    break
            except Exception:  # noqa: BLE001 - a failing lookup must not stop detection
                continue
        if cls is None:
            continue
        matches.append(PiiMatch(found.start(), found.end(), cls, raw, raw))
    return matches


def merge_matches(matches: list[PiiMatch]) -> list[PiiMatch]:
    """Return non-overlapping matches, preferring the longest span.

    # START_CONTRACT: merge_matches
    #   PURPOSE: Resolve overlapping detections deterministically.
    #   INPUTS: { matches: list[PiiMatch] - raw detections }
    #   OUTPUTS: { list[PiiMatch] - sorted, non-overlapping matches }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKENIZER, V-M-TOKENIZER
    # END_CONTRACT: merge_matches
    """
    ordered = sorted(matches, key=lambda m: (m.start, -(m.end - m.start), m.cls))
    accepted: list[PiiMatch] = []
    for candidate in ordered:
        if candidate.end <= candidate.start:
            continue
        # Свои константы (адреса клубов, бренд) не персональные данные, даже если
        # попали в словарь из карточек клиентов: клиенты записаны на адрес клуба.
        if _is_own_constant(candidate):
            continue
        if any(candidate.start < kept.end and kept.start < candidate.end for kept in accepted):
            continue
        accepted.append(candidate)
    return sorted(accepted, key=lambda m: m.start)


def _is_own_constant(match: PiiMatch) -> bool:
    """Return True when a finding is one of the network's own constants.

    # START_CONTRACT: _is_own_constant
    #   PURPOSE: Keep club addresses and brand strings out of anonymization.
    #   INPUTS: { match: PiiMatch - candidate finding }
    #   OUTPUTS: { bool - True when the finding is our own constant }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-RULES, V-M-DETECT-RULES
    # END_CONTRACT: _is_own_constant

    Находка 16.09.2026: в прогоне на реальном словаре единственная ложная замена —
    «б-р Садовая 3а», адрес клуба. Значение попало в словарь законно: часть карточек
    клиентов заведена на адрес клуба. Но это не данные человека.
    """
    probe = (match.normalized or match.raw or "").strip().lower()
    if not probe:
        return False
    if match.cls == CLASS_PHONE:
        # Свёртка та же, что у настроек: 8-форма и +7-форма одного номера совпадают.
        digits = digits_only(probe)
        if digits in own_phone_digits():
            return True
    if probe in own_constants():
        return True
    collapsed = re.sub(r"\s+", " ", probe)
    return collapsed in own_constants()
# END_BLOCK_SCAN_RULES
