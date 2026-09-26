# FILE: src/dict_export.py
# VERSION: 2.2.0
# START_MODULE_CONTRACT
#   PURPOSE: Build the known-value dictionary straight from CRM so the proxy can match client names, phones and identifiers that no rule would recognize.
#   SCOPE: paginated API reads through an injectable fetcher, field-to-class extraction, family folding of case forms, atomic permission-hardened write, CLI entry for the scheduled job.
#   DEPENDS: M-CONFIG, M-NAME-FORMS, M-DETECT-NAME, M-CLIENT-LAYER
#   LINKS: M-DICT-EXPORT, V-M-DICT-EXPORT, fn-main, fn-build_dictionary
#   ROLE: SCRIPT
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   FIELD_CLASSES - API field name to PII class mapping
#   DECLINED_CLASSES - классы, которым нужен блок формо-дигестов
#   fn-extract_values - pull PII values out of API records
#   fn-build_dictionary - read all pages and assemble the dictionary
#   fn-to_keyed_digests - schema 3: отпечатки значений и их падежных форм
#   fn-_family_roots - схлопнуть падежные формы в одну персону: значение → основа семьи
#   fn-_spelling_keys - ключи нормализации написания (как записано и со сложенной «ё»)
#   fn-_add_form_digest - добавить отпечаток написания со ссылкой на основу семьи
#   fn-_form_digests - отпечатки форм со ссылкой на отпечаток основы семьи
#   fn-_form_keys - ключи нормализации значения и форм (обычный и со сложенной «ё»)
#   fn-_generated_spellings - формы значения тем же генератором, что в распознавании
#   fn-noise_kind - признак шума в поле имени (инициал, время, техзнаки, обычное слово)
#   fn-write_dictionary_atomic - write 0600 file via temp plus replace
#   fn-crm_fetcher - real HTTP fetcher for the CRM API
#   fn-main - CLI entry used by the scheduled job
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.4.0 - служебная лексика и лексика оператора отсекаются одной общей точкой (is_own_lexicon_word): выгрузка и заслон не могут разойтись в оценке.
#   LAST_CHANGE: v2.2.0 - Phase-16 M-DICT-HYGIENE: в класс «имена» больше не попадают значения, которые рантайм именем не считает и опознать формой нельзя (инициалы, время, технические знаки, обычные слова морфологии) — счётчики dropped_noise_* в отчёте выгрузки; открытый список фамилий служит предохранителем от потери редких настоящих значений.
#   PREVIOUS: v2.1.0 - Phase-14: формы схлопываются в основу семьи (падеж не становится персоной), поэтому написание, совпавшее с падежом другого значения, больше не получает собственный код; счётчики семей печатаются в отчёте выгрузки.
#   PREVIOUS: v2.0.0 - Phase-8: выгрузка schema 3 несёт отпечатки падежных форм (M-NAME-FORMS), поэтому код остаётся один на персону во всех падежах даже на хешированном словаре; неоднозначные формы отбрасываются, чтение schema 1/2 сохранено.
#   EARLIER: v1.0.0 - Phase-2 M-DICT-EXPORT: local read-only export, no LLM, runs as a plain script.
# END_CHANGE_SUMMARY

"""Known-value dictionary export.

Implements M-DICT-EXPORT from docs/ARCHITECTURE.md. The dictionary is the
strongest detection layer, so it is fed from the source of truth — CRM —
instead of being maintained by hand. The write is atomic (temp file plus
``os.replace``) and the file is chmod 0600, because it contains personal data:
the proxy must never observe a half-written dictionary, and nobody else on the
host may read it.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

# The job is started as a file (deploy/dict-export.sh, cron), so the repository
# root is not on sys.path by default; without this the module imports fail with
# "No module named 'src'" (hit on 15.09.2026).
if __package__ in (None, ""):  # pragma: no cover - import bootstrap
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.client_layer import NAME_KINDS
from src.dictionary import SCHEMA_FORMS, value_digest
from src.detect_name import is_own_lexicon_value, is_own_lexicon_word, is_person_name, morphology_reads_common_word
from src.name_forms import name_forms, normalize_name
from src.name_layer import LayerError, load_name_layer
from src.normalize import NormalizeError, normalize, split_birth_date

LOGGER_NAME = "DictionaryExportScript"
LOG_MARKER = "[DictionaryExportScript][main][BLOCK_WRITE_DICTIONARY]"

DEFAULT_BASE_URL = "https://crm.example.com/api/v2"
DEFAULT_CLUB = "crm-demo"
PAGE_SIZE = 100

# Field names observed in CRM API v2 client records; anything unknown is
# ignored on purpose, so a schema change degrades the dictionary instead of
# corrupting it.
FIELD_CLASSES: dict[str, str] = {
    "fio": "P",
    "name": "P",
    "full_name": "P",
    "surname": "P",
    "last_name": "P",
    "first_name": "P",
    "middle_name": "P",
    "patronymic": "P",
    "phone": "T",
    "mobile_phone": "T",
    "phone_number": "T",
    "email": "E",
    "birthday": "D",
    "birth_date": "D",
    "address": "A",
    "snils": "I",
    "passport": "I",
    "card": "C",
}

# Phone and e-mail live inside the nested ``contacts`` list, where the kind of a
# value is carried by ``contact_type`` rather than by the field name (verified
# against the live API on 15.09.2026: keys are client_id, contact,
# contact_type, comment, priority ...).
CONTACT_TYPE_CLASSES: dict[str, str] = {
    "phone": "T",
    "mobile": "T",
    "mobile_phone": "T",
    "whatsapp": "T",
    "telegram": "T",
    "viber": "T",
    "email": "E",
    "e-mail": "E",
    "mail": "E",
}

# Nested objects worth walking. Club objects are deliberately excluded: a fitness
# club address or switchboard number is not a person's data, and indexing it
# would only add noise to the dictionary.
RECURSE_FIELDS = frozenset({"contacts", "manager"})

#: Классы, значения которых склоняются, поэтому им нужен блок формо-дигестов (Phase-8).
DECLINED_CLASSES = frozenset({"P"})

#: Форма, которую вообще имеет смысл искать в тексте: слово без точек и пробелов.
_WORD_SHAPE = re.compile(r"^[А-Яа-яЁё][А-Яа-яЁё\-]*$")
_CYRILLIC = re.compile(r"[А-Яа-яЁё]")


class ExportError(RuntimeError):
    """Export failure with a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# START_BLOCK_WRITE_DICTIONARY
# START_BLOCK_EXPORT_HYGIENE
PHONE_SHAPE = re.compile(r"^[+]?[78]?[\s\-()]*\d[\d\s\-()]{6,18}$")
JUNK_MARKERS = frozenset({"???", "?", "-", "--", "|", "н/д", "нет", "нет данных", "0", "б/н", "х"})
EMAIL_SHAPE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-zА-Яа-я]{2,}$")
DATE_SHAPE = re.compile(
    # Год в дате обязателен четырьмя знаками: иначе «1.2.3» стало бы датой, а это мусор.
    r"^\d{1,2}[.\-/]\d{1,2}[.\-/]\d{4}$|^\d{4}-\d{2}-\d{2}$"
)


def shape_class(value: str) -> str | None:
    """Return the class a value really belongs to, judging by its shape.

    # START_CONTRACT: shape_class
    #   PURPOSE: Keep mis-filed data in the dictionary without keeping it in the wrong class.
    #   INPUTS: { value: str - candidate value taken from a name field }
    #   OUTPUTS: { str | None - class letter when the shape decides, else None }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT-EXPORT, V-M-DICT-EXPORT
    # END_CONTRACT: shape_class

    Measured 16.09.2026: reception typed phone numbers into the surname field
    («79000000007»). Such a value must move to the phone class, not be deleted —
    it is a real client value that simply sits in the wrong field.
    """
    text = value.strip()
    if EMAIL_SHAPE.match(text):
        return "E"
    if DATE_SHAPE.match(text):
        return "D"
    digits = re.sub(r"\D", "", text)
    if PHONE_SHAPE.match(text) and 10 <= len(digits) <= 12:
        return "T"
    if digits and digits == re.sub(r"[\s\-()+]", "", text) and len(digits) >= 5:
        return "C"
    return None


#: Время суток в поле имени не является персональными данными, поэтому в словарь не идёт.
TIME_SHAPE = re.compile(r"^\d{1,2}[:.\-]\d{2}$")
#: Знаки, которых в написании имени не бывает: значение с ними — техническая строка.
#: Скобки входят сюда намеренно: телефон со скобками опознаётся формой раньше и уходит в класс T.
TECHNICAL_CHARS = frozenset("_?*#|\\/<>[]{}=~^`\"'()")
#: Ниже этого числа букв и цифр значение в тексте как отдельное слово не опознать.
MIN_NAME_CHARS = 3


def noise_kind(value: str) -> str | None:
    """Вернуть признак шума, если значение в поле имени именем быть не может.

    # START_CONTRACT: noise_kind
    #   PURPOSE: Отделить в выгрузке шум (инициалы, время, техзнаки, обычные слова) от значений клиента, которые просто записаны непривычно.
    #   INPUTS: { value: str - значение из поля имени }
    #   OUTPUTS: { str | None - "short" | "technical" | "time" | "digit_lead" | "common_word" | None }
    #   SIDE_EFFECTS: лениво строит морфологический анализатор через M-DETECT-NAME
    #   LINKS: M-DICT-EXPORT, V-M-DICT-EXPORT, M-DETECT-NAME, fn-shape_class
    # END_CONTRACT: noise_kind

    Замер 20.09.2026 (4 000 записей живой выгрузки): из 7 642 значений класса «имена» 369
    (4,8%) рантайм именем не считает, и формой их не опознать — «Н.», «06:30», «?L…»,
    «V_…», «по…». Пользы в словаре они не несут, а ложные находки в заслоне создают,
    поэтому отбрасываются со счётчиком, а не остаются «на всякий случай».

    Признак ставится только там, где это доказуемо тем же критерием, что и в рантайме
    (`is_person_name` не признал значение именем, `morphology_reads_common_word` читает
    обычное слово): непривычное, но настоящее значение клиента остаётся в словаре —
    первая версия чистки (17.09.2026) выбросила 12,9% настоящих значений, и обезличивание
    падало до 73%.
    """
    text = value.strip()
    if sum(1 for ch in text if ch.isalnum()) < MIN_NAME_CHARS:
        return "short"
    if any(ch in TECHNICAL_CHARS for ch in text):
        return "technical"
    if TIME_SHAPE.match(text):
        return "time"
    if text[:1].isdigit():
        return "digit_lead"
    if " " not in text and morphology_reads_common_word(text):
        return "common_word"
    return None


def _layer_confirms(layer: Any, value: str) -> bool:
    """Считать значение настоящим, если его знает открытый список фамилий.

    # START_CONTRACT: _layer_confirms
    #   PURPOSE: Предохранитель от потери редких настоящих значений при чистке.
    #   INPUTS: { layer: NameLayer | None - открытый список, value: str - значение }
    #   OUTPUTS: { bool - True, когда список знает значение в любом классе }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CLIENT-LAYER, M-DICT-EXPORT, V-M-DICT-HYGIENE
    # END_CONTRACT: _layer_confirms
    """
    if layer is None:
        return False
    try:
        return bool(layer.contains(value)) or bool(layer.contains(value, "P"))
    except Exception:  # noqa: BLE001 - сбой списка не повод терять значение
        return False
# END_BLOCK_EXPORT_HYGIENE


def extract_values(
    records: Sequence[Mapping[str, Any]],
    stats: dict[str, int] | None = None,
    layer: Any = None,
) -> dict[str, list[str]]:
    """Group PII values from API records by class.

    # START_CONTRACT: extract_values
    #   PURPOSE: Turn raw API records into the dictionary shape.
    #   INPUTS: { records: Sequence[Mapping[str, Any]] - API items }
    #   OUTPUTS: { dict[str, list[str]] - class to values }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT, V-M-DICT-EXPORT
    # END_CONTRACT: extract_values

    The walk follows the real DTO shape: contacts are a list of objects where
    ``contact`` holds the value and ``contact_type`` its kind, while the staff
    object (``manager``) holds its own name and contacts. Anything unmapped is
    ignored on purpose, so a schema change shrinks the dictionary instead of
    corrupting it.
    """
    collected: dict[str, set[str]] = {}
    for record in records:
        if not isinstance(record, Mapping):
            continue
        _collect(record, collected, depth=0, stats=stats, layer=layer)
        # The primary key does not carry a PII field name, so it is taken explicitly.
        identifier = record.get("id")
        if isinstance(identifier, (int, str)) and str(identifier).strip():
            collected.setdefault("C", set()).add(str(identifier).strip())
    return {cls: sorted(values) for cls, values in collected.items()}


def _collect(
    node: Any,
    collected: dict[str, set[str]],
    depth: int = 0,
    stats: dict[str, int] | None = None,
    layer: Any = None,
) -> None:
    """Walk a record fragment and index every mapped PII value.

    # START_CONTRACT: _collect
    #   PURPOSE: Handle nested contact and staff objects without a schema library.
    #   INPUTS: { node: Any - record fragment, collected: dict[str, set[str]] - accumulator, depth: int - recursion guard, stats: dict | None - счётчики чистки, layer: NameLayer | None - открытый список }
    #   OUTPUTS: { None }
    #   SIDE_EFFECTS: mutates the accumulator
    #   LINKS: M-DICT-EXPORT, V-M-DICT-EXPORT, fn-noise_kind
    # END_CONTRACT: _collect
    """
    if depth > 2:
        return
    if isinstance(node, Mapping):
        contact_type = str(node.get("contact_type") or "").strip().lower()
        contact_value = node.get("contact")
        if contact_type and isinstance(contact_value, str) and contact_value.strip():
            cls = CONTACT_TYPE_CLASSES.get(contact_type)
            if cls:
                collected.setdefault(cls, set()).add(contact_value.strip())
        for field_name, value in node.items():
            name = str(field_name).strip().lower()
            cls = FIELD_CLASSES.get(name)
            if cls and isinstance(value, (str, int)) and not isinstance(value, bool):
                text = str(value).strip()
                if text and len(text) <= 200:
                    target = _classify_name_field(text, stats, layer) if cls == "P" else cls
                    if target is None:
                        continue
                    collected.setdefault(target, set()).add(text)
            elif isinstance(value, (Mapping, list, tuple)) and name in RECURSE_FIELDS:
                _collect(value, collected, depth + 1, stats, layer)
    elif isinstance(node, (list, tuple)):
        for item in node:
            _collect(item, collected, depth + 1, stats, layer)


def _classify_name_field(
    text: str, stats: dict[str, int] | None, layer: Any = None
) -> str | None:
    """Return the class a name-field value really belongs to, or None when it is junk.

    # START_CONTRACT: _classify_name_field
    #   PURPOSE: Keep the dictionary free of service records and mis-filed data while losing no real value.
    #   INPUTS: { text: str - value from a name field, stats: dict | None - counters, layer: NameLayer | None - открытый список как предохранитель }
    #   OUTPUTS: { str | None - class letter to store under, None when the value is dropped }
    #   SIDE_EFFECTS: mutates the counters
    #   LINKS: M-DICT-EXPORT, V-M-DICT-EXPORT, fn-shape_class, fn-noise_kind
    # END_CONTRACT: _classify_name_field

    Measured 16.09.2026 (4 000 records, 24 118 class-P values, 59.5% not names):
      - the shape says phone, e-mail, date or client number — reclassified, never dropped:
        «79000000007» in the surname field is a real client value in the wrong field;
      - our own vocabulary (brand, clubs, service words) — dropped;
      - anything else that is not a name («CRM», «База», «Клиентов», «|», «-») — dropped.
    Measured 20.09.2026: of 7 642 remaining class-P values 369 (4.8%) were still not names
    and had no shape to be reclassified by («Н.», «06:30», «?L…», «V_…») — Phase-16 drops
    them by `noise_kind`, unless the open surname list confirms the value.
    Dropped values are counted, never stored: the numbers belong in the report, the
    contents do not belong anywhere.
    """
    lowered = text.lower()
    if is_own_lexicon_value(lowered) or any(is_own_lexicon_word(word) for word in lowered.split()):
        if stats is not None:
            stats["dropped_own_vocabulary"] = stats.get("dropped_own_vocabulary", 0) + 1
        return None
    if lowered in JUNK_MARKERS or not any(ch.isalnum() for ch in text):
        if stats is not None:
            stats["dropped_junk_marker"] = stats.get("dropped_junk_marker", 0) + 1
        return None
    if not is_person_name(text):
        shaped = shape_class(text)
        if shaped is not None:
            if stats is not None:
                stats[f"reclassified_to_{shaped}"] = stats.get(f"reclassified_to_{shaped}", 0) + 1
            return shaped
        # Шум в поле имени отбрасывается со счётчиком, но только там, где признак шума
        # доказуем, а открытый список фамилий значение не подтверждает (Phase-16).
        noise = noise_kind(text)
        if noise is not None and not _layer_confirms(layer, text):
            if stats is not None:
                stats[f"dropped_noise_{noise}"] = stats.get(f"dropped_noise_{noise}", 0) + 1
            return None
    # Всё остальное остаётся в классе «имена»: это значения из карточки клиента, пусть и
    # непривычной формы («Stubnick», «Тестовочка»). Убирать их нельзя — это данные клиента, а
    # точность обеспечивают заслоны на рантайме. Замер 17.09.2026: первая версия чистки
    # выбросила 12,9% таких значений, и обезличивание падало до 73%.
    return "P"


def fetch_pages(
    fetcher: Callable[[str], Mapping[str, Any]],
    path: str,
    page_size: int = PAGE_SIZE,
    max_pages: int = 600,
) -> list[Mapping[str, Any]]:
    """Read every page of a list endpoint through the injected fetcher.

    # START_CONTRACT: fetch_pages
    #   PURPOSE: Walk pagination without hard-coding a page limit into the caller.
    #   INPUTS: { fetcher: Callable, path: str, page_size: int, max_pages: int }
    #   OUTPUTS: { list[Mapping[str, Any]] - all items }
    #   SIDE_EFFECTS: performs HTTP calls through the fetcher
    #   LINKS: V-M-DICT-EXPORT
    # END_CONTRACT: fetch_pages
    """
    items: list[Mapping[str, Any]] = []
    for page in range(1, max_pages + 1):
        separator = "&" if "?" in path else "?"
        payload = fetcher(f"{path}{separator}page={page}&page_size={page_size}")
        rows = payload.get("items") if isinstance(payload, Mapping) else None
        if rows is None:
            rows = payload if isinstance(payload, list) else []
        if not rows:
            break
        items.extend(rows)
        if len(rows) < page_size:
            break
    return items


def build_dictionary(
    fetcher: Callable[[str], Mapping[str, Any]],
    path: str = "/client",
    max_pages: int = 600,
    stats: dict[str, int] | None = None,
    layer: Any = None,
) -> dict[str, list[str]]:
    """Read the client list and assemble the dictionary.

    # START_CONTRACT: build_dictionary
    #   PURPOSE: One call produces everything the proxy needs to reload.
    #   INPUTS: { fetcher: Callable, path: str, max_pages: int, stats: dict | None - счётчики чистки, layer: NameLayer | None - открытый список как предохранитель }
    #   OUTPUTS: { dict[str, list[str]] - class to values }
    #   SIDE_EFFECTS: performs HTTP calls through the fetcher
    #   LINKS: M-DICT, V-M-DICT-EXPORT, fn-noise_kind
    # END_CONTRACT: build_dictionary
    """
    records = fetch_pages(fetcher, path, max_pages=max_pages)
    return extract_values(records, stats=stats, layer=layer)


def to_keyed_digests(
    data: Mapping[str, list[str]], key: bytes, stats: dict[str, int] | None = None
) -> dict[str, Any]:
    """Convert a dictionary into keyed digests plus the digests of its case forms (schema 3).

    # START_CONTRACT: to_keyed_digests
    #   PURPOSE: Keep the file from being a readable copy of personal data while letting the proxy keep one code per person in every case.
    #   INPUTS: { data: Mapping[str, list[str]] - raw dictionary, key: bytes - secret, stats: dict[str, int] | None - счётчики семей }
    #   OUTPUTS: { dict - schema 3 payload with digests and form digests }
    #   SIDE_EFFECTS: генерирует падежные формы через M-NAME-FORMS, считает семьи основ
    #   LINKS: M-DICT, M-DICT-EXPORT, M-NAME-IDENTITY, V-M-DICT-EXPORT, Phase-14
    # END_CONTRACT: to_keyed_digests

    Why this is possible at all: matching is a membership test. The tokenizer
    already holds the value it is testing (it came from the text being
    anonymized), so the dictionary file never needs the plaintext — only a
    comparable digest. Digesting also keeps the file small.

    Зачем формы (Phase-8): хешированный словарь не может сгенерировать формы сам — значения
    он не видит. Без блока ``forms`` склонённое написание разрешалось основой открытого списка
    или не разрешалось вовсе, и один клиент получал несколько кодов (замер 19.09.2026:
    PhCons 0,875, RepRate 0,966 в контуре продакшена).

    Зачем семьи основ (Phase-14): одно и то же написание бывает и падежом одного значения, и
    записью в карточке другого («Иванова» — и фамилия клиентки, и родительный от «Иванов»).
    Тогда и падеж получал свой код, и персона — второй: на настоящем справочнике так вели себя
    15 значений из 40 (PhCons 0,625, планка ровно 1,0). Выгрузка схлопывает такие написания в
    основу семьи, поэтому падеж всегда указывает на персону, а не на написание.
    """
    digests: dict[str, list[str]] = {}
    normalized_values: dict[str, list[str]] = {}
    for cls, values in sorted(data.items()):
        bucket = set()
        normalized_bucket: list[str] = []
        for value in values:
            try:
                if cls == "D":
                    # Birth dates are tokenized as day-month with the year left
                    # open (owner decision), so the dictionary must digest the
                    # same day-month key — otherwise the entries never match and
                    # the whole class is dead weight in the file (spotted when the
                    # first digest export dropped class D entirely, 15.09.2026).
                    normalized, _year = split_birth_date(str(value))
                else:
                    normalized = normalize(cls, str(value))
            except NormalizeError:
                continue
            digest = value_digest(key, cls, normalized)
            if digest in bucket:
                continue
            bucket.add(digest)
            normalized_bucket.append(normalized)
        if bucket:
            digests[cls] = sorted(bucket)
            normalized_values[cls] = normalized_bucket
    forms = _form_digests(normalized_values, digests, key, stats=stats)
    payload: dict[str, Any] = {
        "schema": SCHEMA_FORMS,
        "generated_by": "M-DICT-EXPORT",
        "values": sum(len(bucket) for bucket in digests.values()),
        "digests": digests,
    }
    if forms:
        payload["forms"] = forms
    return payload


def _spelling_keys(spelling: str, cls: str) -> list[str]:
    """Вернуть ключи нормализации написания: как записано и со сложенной «ё».

    # START_CONTRACT: _spelling_keys
    #   PURPOSE: Одна персона при любом написании: рантайм ищет форму тем ключом, который получился из текста.
    #   INPUTS: { spelling: str - написание, cls: str - класс }
    #   OUTPUTS: { list[str] - ключи нормализации без повторов }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT-EXPORT, M-NAME-FORMS, V-M-DICT-EXPORT
    # END_CONTRACT: _spelling_keys
    """
    keys: list[str] = []
    for candidate in (_safe_normalize(cls, spelling), normalize_name(spelling)):
        if candidate and candidate not in keys:
            keys.append(candidate)
    return keys


def _family_roots(
    values: Sequence[str], cls: str, stats: dict[str, int] | None = None
) -> dict[str, str]:
    """Отобразить значение на основу его семьи падежных форм.

    # START_CONTRACT: _family_roots
    #   PURPOSE: Схлопнуть падежные формы в одну персону раньше, чем будет назначен код.
    #   INPUTS: { values: Sequence[str] - нормализованные значения класса, cls: str - класс, stats: dict[str, int] | None - счётчики }
    #   OUTPUTS: { dict[str, str] - значение → написание основы семьи }
    #   SIDE_EFFECTS: читает таблицы склонений, увеличивает счётчики
    #   LINKS: M-NAME-FORMS, M-DICT-EXPORT, M-NAME-IDENTITY, V-M-DICT-EXPORT
    # END_CONTRACT: _family_roots

    Правило: написание, порождённое как падеж другого написания, — это падеж, а не персона
    (решение владельца 18.09.2026 «код присваивается персоне, а не падежной форме»). Первый
    шаг — строгое свидетельство: значение-форма порождено генератором форм от значения-основы,
    и основа ровно одна. Несколько основ — не угадываем, значение остаётся собой.
    Второй шаг закрывает случай, когда в справочнике лежит только падежная запись («Мещерина»),
    а беспадежной основы карточек нет вовсе: её находит обратный ход, и она становится
    написанием основы семьи — тогда «Мещерин», «Мещерина», «Мещерину» получают один код.
    """
    folded: dict[str, str] = {}
    for value in values:
        key = normalize_name(value)
        if key:
            folded.setdefault(key, value)
    folded_values = set(folded)
    parents: dict[str, set[str]] = {}
    for key in folded_values:
        for kind in NAME_KINDS:
            try:
                generated = name_forms(key, kind)
            except Exception:  # noqa: BLE001 - нет таблиц — семьи не строятся, выгрузка не падает
                continue
            for form in generated:
                candidate = normalize_name(form)
                if candidate and candidate != key and candidate in folded_values:
                    parents.setdefault(candidate, set()).add(key)
    root_of: dict[str, str] = {}
    for key in sorted(folded_values):
        seen = {key}
        current = key
        while True:
            chain = parents.get(current) or set()
            if not chain:
                break
            if len(chain) > 1 or next(iter(chain)) in seen:
                # Две основы или кольцо — персону не угадываем.
                if stats is not None:
                    stats["form_roots_ambiguous"] = stats.get("form_roots_ambiguous", 0) + 1
                current = key
                break
            parent = next(iter(chain))
            seen.add(parent)
            current = parent
        root_of[key] = current
    # Шаг 2 — не нужен: беспадежную основу, которой нет среди значений («Мещерин» при записи
    # «Мещерина»), рантайм находит сам — спрашивая у словаря формы найденной основы
    # (M-NAME-IDENTITY, fn-dictionary_anchor). Выгрузке здесь хватает строгого свидетельства
    # «значение порождено значением»: широкий перебор основ менял бы код персон, к падежам
    # которых он отношения не имеет (находка 19.09.2026: «Скрытница» уезжала в основу «Турт»).
    if stats is not None:
        stats["form_families"] = len(set(root_of.values()))
        stats["form_roots_without_value"] = sum(
            1 for root in set(root_of.values()) if root not in folded_values
        )
        stats["form_values_folded"] = sum(1 for key in root_of if root_of[key] != key)
    out: dict[str, str] = {}
    for key, root in root_of.items():
        # Ключ ответа — сложенное написание (ё приведена к е), а значение — написание основы:
        # отпечаток основы считается по написанию значения, когда оно есть среди значений,
        # тогда у основы и её падежей ровно один отпечаток, а не два из-за «ё».
        out[key] = folded.get(root, root)
    return out


def _form_digests(
    normalized_values: Mapping[str, list[str]],
    digests: Mapping[str, list[str]],
    key: bytes,
    stats: dict[str, int] | None = None,
) -> dict[str, dict[str, str]]:
    """Собрать отпечатки падежных форм со ссылкой на отпечаток основы семьи.

    # START_CONTRACT: _form_digests
    #   PURPOSE: Дать прокси возможность связать падеж с персоной, не читая ни одного значения.
    #   INPUTS: { normalized_values: Mapping[str, list[str]], digests: Mapping[str, list[str]], key: bytes, stats: dict[str, int] | None - счётчики семей }
    #   OUTPUTS: { dict[str, dict[str, str]] - класс -> {отпечаток написания: отпечаток основы} }
    #   SIDE_EFFECTS: читает таблицы склонений (M-NAME-FORMS), считает семьи основ
    #   LINKS: M-DICT-EXPORT, M-NAME-FORMS, M-NAME-IDENTITY, V-M-DICT-EXPORT
    # END_CONTRACT: _form_digests

    Ссылка идёт на **основу семьи**: и падеж значения, и написание, совпавшее с падежом другого
    значения, указывают на одну персону. Написание, порождённое двумя разными основами, в блок
    не попадает — персону не угадываем. Написание, совпавшее с самой основой, тоже не попадает:
    его закрывает точный отпечаток, если основа есть среди значений, а если её там нет — оно
    попадает как якорь основы (иначе «Мещерин» не нашёл бы свою семью).
    """
    forms: dict[str, dict[str, str]] = {}
    for cls, values in sorted(normalized_values.items()):
        if cls not in DECLINED_CLASSES:
            continue
        roots = _family_roots(values, cls, stats=stats)
        pairs: dict[str, str] = {}
        ambiguous: set[str] = set()
        roots_seen: set[str] = set()
        for value in values:
            root = roots.get(normalize_name(value), value)
            root_digest = value_digest(key, cls, root)
            roots_seen.add(root)
            if root != value:
                # Само написание значения — падеж основы семьи: падеж, а не персона.
                for spelling_key in _spelling_keys(value, cls):
                    _add_form_digest(pairs, ambiguous, spelling_key, root_digest, key, cls)
            for candidate in _form_keys(value, cls):
                if candidate == root:
                    continue
                _add_form_digest(pairs, ambiguous, candidate, root_digest, key, cls)
        for root in sorted(roots_seen):
            if root in values:
                continue
            # Основы нет среди значений: её написание (якорь на саму себя) и её формы получают
            # один и тот же отпечаток, иначе падежи, порождённые самой основой (мужские формы),
            # остались бы без персоны, а написание основы — со своим кодом.
            anchor_digest = value_digest(key, cls, root)
            for spelling_key in _spelling_keys(root, cls):
                _add_form_digest(pairs, ambiguous, spelling_key, anchor_digest, key, cls, allow_self=True)
            for candidate in _form_keys(root, cls):
                if candidate == root:
                    continue
                _add_form_digest(pairs, ambiguous, candidate, anchor_digest, key, cls)
        if stats is not None:
            stats["form_digests_ambiguous"] = stats.get("form_digests_ambiguous", 0) + len(ambiguous)
        if pairs:
            forms[cls] = pairs
    return forms


def _add_form_digest(
    pairs: dict[str, str],
    ambiguous: set[str],
    spelling_key: str,
    base_digest: str,
    key: bytes,
    cls: str,
    allow_self: bool = False,
) -> None:
    """Добавить отпечаток написания со ссылкой на основу, не угадывая при столкновении основ.

    # START_CONTRACT: _add_form_digest
    #   PURPOSE: Одна форма — одна основа; две основы на одно написание означают отказ, а не выбор.
    #   INPUTS: { pairs: dict[str, str] - накопитель, ambiguous: set[str] - отброшенные, spelling_key: str - ключ написания, base_digest: str - отпечаток основы, key: bytes, cls: str, allow_self: bool - разрешить якорь основы на саму себя }
    #   OUTPUTS: { None }
    #   SIDE_EFFECTS: меняет накопитель и список отброшенных
    #   LINKS: M-DICT-EXPORT, V-M-DICT-EXPORT
    # END_CONTRACT: _add_form_digest

    ``allow_self`` нужен якорю основы: у основы, которой нет среди значений, собственное
    написание обязано получить свой же отпечаток — иначе «Мещерин» не нашёл бы свою семью,
    а его падежи нашли бы (находка 19.09.2026, прогон на настоящем справочнике).
    """
    if not spelling_key:
        return
    form_digest = value_digest(key, cls, spelling_key)
    if form_digest in ambiguous:
        return
    if form_digest == base_digest and not allow_self:
        return
    existing = pairs.get(form_digest)
    if existing is None:
        pairs[form_digest] = base_digest
    elif existing != base_digest:
        # Одно написание у двух основ — персону не угадываем.
        pairs.pop(form_digest, None)
        ambiguous.add(form_digest)


def _form_keys(value: str, cls: str) -> list[str]:
    """Вернуть ключи нормализации значения и его форм: обычный и со сложенной «ё».

    # START_CONTRACT: _form_keys
    #   PURPOSE: Одна персона при любом написании: «Печёнов», «Печенов» и падежи обоих дают один отпечаток.
    #   INPUTS: { value: str - нормализованное значение, cls: str - класс }
    #   OUTPUTS: { list[str] - ключи нормализации без повторов }
    #   SIDE_EFFECTS: читает таблицы склонений
    #   LINKS: M-NAME-FORMS, M-DICT-EXPORT, M-NAME-IDENTITY, V-M-DICT-EXPORT
    # END_CONTRACT: _form_keys

    Два написания одного ключа — одна персона (решение Phase-7: «ё» и «е» не различают людей).
    Без второго ключа «Печёнов» и «Печёновой» в контуре продакшена получали разные коды:
    выгрузка считала формы со сложенной «ё», а рантайм искал написание как оно записано
    (замер 19.09.2026: остаток PhCons 0,90 держался ровно на четырёх значениях с «ё»).
    """
    keys: list[str] = []
    for spelling in [value, *_generated_spellings(value)]:
        for candidate in (_safe_normalize(cls, spelling), normalize_name(spelling)):
            if not candidate or candidate == value:
                continue
            # Форма обязана оставаться словом: генератор изредка выдаёт артефакт вида
            # «бонч.-бруевича», которого в тексте не бывает.
            if not _WORD_SHAPE.match(candidate):
                continue
            if candidate not in keys:
                keys.append(candidate)
    return keys


def _safe_normalize(cls: str, value: str) -> str:
    """Нормализовать значение класса или вернуть пустую строку, если класс его не принимает."""
    try:
        return normalize(cls, value)
    except NormalizeError:
        return ""


def _generated_spellings(value: str) -> list[str]:
    """Вернуть формы значения, как их порождает генератор, без повторов.

    # START_CONTRACT: _generated_spellings
    #   PURPOSE: Одна точка генерации форм для выгрузки, чтобы файл и распознавание считали падежи одинаково.
    #   INPUTS: { value: str - нормализованное значение }
    #   OUTPUTS: { list[str] - формы в написании генератора без исходного значения }
    #   SIDE_EFFECTS: читает таблицы склонений
    #   LINKS: M-NAME-FORMS, M-DICT-EXPORT
    # END_CONTRACT: _generated_spellings

    Латиница остаётся собой: таблицы склонений кириллические, и выдуманные формы латинского
    значения дали бы ложные срабатывания (решение из M-NAME-IDENTITY).
    """
    if not _CYRILLIC.search(value):
        return []
    forms: dict[str, None] = {}
    for kind in NAME_KINDS:
        for form in name_forms(value, kind):
            candidate = str(form).strip().lower()
            if not candidate or candidate == value:
                continue
            forms.setdefault(candidate, None)
    return list(forms)


def write_dictionary_atomic(path: str, data: Mapping[str, list[str]]) -> str:
    """Write the dictionary atomically with owner-only permissions.

    # START_CONTRACT: write_dictionary_atomic
    #   PURPOSE: Never expose a partially written dictionary.
    #   INPUTS: { path: str - target file, data: Mapping[str, list[str]] - dictionary }
    #   OUTPUTS: { str - written path }
    #   SIDE_EFFECTS: writes and renames a file
    #   LINKS: M-DICT, V-M-DICT-EXPORT
    # END_CONTRACT: write_dictionary_atomic
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    handle, temp_path = tempfile.mkstemp(dir=directory, prefix=".dict-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, sort_keys=True)
        os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(temp_path, path)
    except Exception:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise
    return path


def crm_fetcher(base_url: str, key: str, club: str) -> Callable[[str], Mapping[str, Any]]:
    """Build the real HTTP fetcher for the CRM API.

    # START_CONTRACT: crm_fetcher
    #   PURPOSE: Read-only client listing with the network kept inside one place.
    #   INPUTS: { base_url: str, key: str, club: str }
    #   OUTPUTS: { Callable[[str], Mapping[str, Any]] - fetcher }
    #   SIDE_EFFECTS: performs HTTP GET calls
    #   LINKS: V-M-DICT-EXPORT
    # END_CONTRACT: crm_fetcher
    """

    def fetcher(path: str) -> Mapping[str, Any]:
        request = urllib.request.Request(
            base_url.rstrip("/") + path,
            headers={
                "Authorization": f"Bearer {key}",
                "club": club,
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise ExportError("EXPORT_API_ERROR", f"CRM returned {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise ExportError("EXPORT_API_ERROR", f"CRM unreachable: {exc.reason}") from exc

    return fetcher


def load_env(path: str) -> dict[str, str]:
    """Read a simple KEY=VALUE env file."""
    values: dict[str, str] = {}
    if not os.path.isfile(path):
        return values
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            values[name.strip()] = value.strip().strip('"').strip("'")
    return values


def main(
    argv: list[str] | None = None,
    fetcher: Callable[[str], Mapping[str, Any]] | None = None,
    env_values: Mapping[str, str] | None = None,
) -> int:
    """Export the dictionary to the configured path.

    # START_CONTRACT: main
    #   PURPOSE: Scheduled entry point (no LLM, zero tokens).
    #   INPUTS: { argv: list[str] | None - CLI arguments, fetcher: Callable | None - injected HTTP reader, env_values: Mapping | None - injected environment }
    #   OUTPUTS: { int - exit code }
    #   SIDE_EFFECTS: reads the API, writes the dictionary file
    #   LINKS: M-DICT, V-M-DICT-EXPORT
    # END_CONTRACT: main

    The fetcher and the environment are injectable so the export can be verified
    end to end without touching the network: an ambient CRM_API_KEY in the
    process environment used to make the unit test reach the real API
    (found on 15.09.2026 while writing tests/test_dict_export.py).
    """
    parser = argparse.ArgumentParser(description="Export the PII dictionary from CRM")
    parser.add_argument("--env-file", default="~/.config/pii-proxy/agent.env")
    parser.add_argument("--out", default="/var/lib/pii-proxy/pii_dict.json")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--club", default=DEFAULT_CLUB)
    parser.add_argument("--max-pages", type=int, default=600)
    parser.add_argument("--preview", action="store_true", help="print counts, write nothing")
    parser.add_argument(
        "--key-file",
        default="/var/lib/pii-proxy/token.key",
        help="secret used to digest values; without it the export is written in readable form",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="write readable values (diagnostics only: the file then contains personal data)",
    )
    parser.add_argument(
        "--name-layer",
        default="",
        help=(
            "открытый список фамилий (предохранитель чистки): значение, которое он знает, "
            "не отбрасывается как шум"
        ),
    )
    args = parser.parse_args(argv)

    env = dict(env_values) if env_values is not None else load_env(args.env_file)
    if env_values is None:
        key = env.get("CRM_API_KEY") or os.environ.get("CRM_API_KEY") or ""
    else:
        key = env.get("CRM_API_KEY") or ""
    if not key and not args.preview:
        print("EXPORT_MISSING_KEY: CRM_API_KEY not found", file=sys.stderr)
        return 2

    active_fetcher = fetcher or crm_fetcher(args.base_url, key, args.club)
    layer = None
    if args.name_layer:
        try:
            layer = load_name_layer(args.name_layer)
        except LayerError as exc:
            print(f"NAME_LAYER_UNAVAILABLE: {exc.code}", file=sys.stderr)
    stats: dict[str, int] = {}
    try:
        data = build_dictionary(active_fetcher, max_pages=args.max_pages, stats=stats, layer=layer)
    except ExportError as exc:
        print(f"{exc.code}: {exc.message}", file=sys.stderr)
        return 3

    counts = {cls: len(values) for cls, values in sorted(data.items())}
    total = sum(counts.values())
    hygiene = ", ".join(f"{key}={value}" for key, value in sorted(stats.items())) or "нет отброшенных"
    if args.preview:
        mode = "raw" if args.raw else "digests"
        print(f"preview: {total} values {counts} (mode={mode})")
        print(f"чистка: {hygiene}")
        return 0

    key = b""
    if not args.raw:
        try:
            with open(args.key_file, "rb") as handle:
                key = handle.read()
        except OSError:
            print(
                f"EXPORT_MISSING_KEY: cannot read {args.key_file}; "
                "pass --key-file or --raw explicitly",
                file=sys.stderr,
            )
            return 2
        if len(key) < 32:
            print("EXPORT_SHORT_KEY: token key is shorter than 32 bytes", file=sys.stderr)
            return 2
        payload: Any = to_keyed_digests(data, key, stats=stats)
        write_dictionary_atomic(args.out, payload)
        form_count = sum(len(pairs) for pairs in (payload.get("forms") or {}).values())
        print(
            f"written: {args.out}, values={total}, classes={counts}, "
            f"mode=digests schema={payload['schema']} (readable values absent), "
            f"form_digests={form_count}"
        )
        families = ", ".join(
            f"{name}={value}" for name, value in sorted(stats.items()) if name.startswith("form_")
        )
        print(f"семьи основ: {families or 'нет данных'}")
        print(f"чистка: {hygiene}")
        return 0

    write_dictionary_atomic(args.out, data)
    print(f"written: {args.out}, values={total}, classes={counts}, mode=raw")
    print(f"чистка: {hygiene}")
    return 0
# END_BLOCK_WRITE_DICTIONARY


if __name__ == "__main__":  # pragma: no cover - module entry
    raise SystemExit(main())
