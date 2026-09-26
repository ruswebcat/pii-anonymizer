# FILE: src/client_layer.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Build the thin client layer from CRM name fields only: classify each value by form, keep what is really a person's value, drop service records and placeholders, and keep only values absent from the open name list.
#   SCOPE: field classification by form (phone in a surname field becomes class T), placeholder and service-object rejection, normalization, deduplication, diff against the open list, counters without values.
#   DEPENDS: M-DICT, M-NAME-FORMS
#   LINKS: M-DICT, V-M-DICT, fn-classify_field, fn-build_client_layer, fn-diff_against_open
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   SERVICE_OBJECTS - служебные сущности, которые не люди (общая часть)
#   fn-service_objects - служебные сущности: общая часть плюс названия из настроек оператора
#   PLACEHOLDERS - маркеры-заглушки вместо значения
#   fn-classify_field - класс и очищенное значение для поля карточки
#   fn-build_client_layer - слой из записей: {класс: значения} плюс счётчики
#   fn-diff_against_open - оставить только то, чего нет в открытом списке
#   fn-build_forms_index - предгенерация форм значений: форма в значение, неоднозначные формы не разрешаются угадыванием
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.2.0 - названия своей системы учёта добавляются к служебным записям из настроек (service_objects): в коде остаётся только общая часть списка.
#   LAST_CHANGE: v1.1.0 - Phase-7 шаг 1: индекс форм клиентского слоя (форма в значение) для распознавания склонённых ФИО и присвоения кода персоне.
#   PREVIOUS: v1.0.0 - Phase-12 шаг 3: клиентский слой строится по форме значения, служебные записи отбрасываются счётчиком.
# END_CHANGE_SUMMARY

"""Client layer for the anonymization proxy (M-DICT).

Implements step 3 of Phase-12 from docs/ARCHITECTURE.md.

Почему так: в клиентском словаре 59,5% значений класса «имена» — не имена. Источники мусора
известны (замер по 4 000 карточек): служебный объект `manager` («CRM», «База», «Admin»),
кривые записи рецепции (телефон в поле фамилии, «Тестовочка»), маркеры-заглушки («|», «-»,
«нет данных»). Поэтому слой строится **только из полей ФИО** и каждое значение проходит
разбор по форме: телефон переклассифицируется, а не выбрасывается; служебные записи и
заглушки отбрасываются и считаются счётчиком, а не содержимым.

Судья чистки — покрытие данных клиента, а не число удалённых строк: прошлая версия
выглядела успехом (−21% в классе имён), а уронила обезличение с 99,9% до 73%.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

from src.name_forms import name_forms, normalize_name
from src.own_vocabulary import service_object_names

LOGGER_NAME = "ClientLayer"
LOG_MARKER = "[ClientLayer][build][BLOCK_BUILD_LAYER]"

CLASS_NAME = "P"
CLASS_PHONE = "T"
CLASS_EMAIL = "E"
CLASS_BIRTH = "D"
CLASS_ADDRESS = "A"
CLASS_CARD = "C"
CLASS_DOCUMENT = "I"

#: Виды значений, формы которых имеет смысл генерировать: поля анкеты ФИО.
NAME_KINDS = ("lastname", "firstname", "patronymic")

#: Латиница: таблицы склонений — кириллические, поэтому латинское значение остаётся
#: своей идентичностью (точное совпадение), а формы для него не выдумываются.
_LATIN_WORD = re.compile(r"^[a-z][a-z'\-]+$")
_CYRILLIC = re.compile(r"[А-Яа-яЁё]")

#: Поля карточки, из которых вообще берём значения.
NAME_FIELDS = ("surname", "name", "patronymic")

#: Общая часть служебных записей: это не люди, в слой имён они не попадают. Названия
#: конкретной системы учёта оператор задаёт в настройках — они добавляются
#: :func:`service_objects` (см. ``src/own_vocabulary.py``).
SERVICE_OBJECTS = frozenset(
    {
        "crm", "база", "база клиентов", "общая база клиентов", "системы", "система",
        "admin", "администратор", "клиентов", "клиент", "менеджер",
        "не указан", "не указано", "без менеджера",
    }
)


def service_objects() -> frozenset[str]:
    """Return service records that are never people: the general part plus configuration.

    # START_CONTRACT: service_objects
    #   PURPOSE: Отличать служебную запись системы учёта от значения клиента, не зашивая
    #            название системы в код.
    #   INPUTS: none
    #   OUTPUTS: { frozenset[str] - общая часть плюс названия из настроек }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT, M-OWN-VOCABULARY, V-M-DICT
    # END_CONTRACT: service_objects
    """
    return SERVICE_OBJECTS | service_object_names()

#: Маркеры-заглушки: вместо значения в поле стоит разметка.
PLACEHOLDERS = frozenset({"-", "--", "---", ".", "..", "|", "/", "\\", "?", "??", "???", "n/a", "нет"})

_PHONE = re.compile(r"^[+]?[\d][\d\s()\-]{8,}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-zА-Яа-я]{2,}$")
_DIGITS = re.compile(r"\d{7,}")
_WORD = re.compile(r"[^\W_]", re.UNICODE)


def classify_field(value: str) -> tuple[str | None, str, str]:
    """Classify one field value by its form.

    # START_CONTRACT: classify_field
    #   PURPOSE: Отделить значение клиента от служебной записи и заглушки.
    #   INPUTS: { value: str - значение поля карточки }
    #   OUTPUTS: { (cls | None, cleaned, reason) - класс, очищенное значение, причина отказа }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT, M-NAME-FORMS, V-M-DICT
    # END_CONTRACT: classify_field
    """
    text = str(value or "").strip()
    if not text:
        return None, "", "empty"
    lowered = text.lower().strip(" .,;:!?")
    if lowered in PLACEHOLDERS or not _WORD.search(text):
        return None, "", "placeholder"
    if lowered in service_objects():
        return None, "", "service_object"
    # Значение без единой буквы, но с семью и более цифрами — это телефон или номер карты,
    # то есть данные клиента, ошибочно записанные в поле ФИО. Переклассифицируем, не выбрасываем.
    if not re.search(r"[A-Za-zА-Яа-я]", text) and len(re.sub(r"\D", "", text)) >= 7:
        return CLASS_PHONE, text, ""
    if _EMAIL.match(text):
        return CLASS_EMAIL, text, ""
    cleaned = normalize_name(text)
    if len(cleaned) < 2:
        return None, "", "too_short"
    return CLASS_NAME, cleaned, ""


def build_client_layer(records: Iterable[Mapping[str, object]]) -> tuple[dict[str, list[str]], dict[str, int]]:
    """Build the client layer from cards, using the name fields only.

    # START_CONTRACT: build_client_layer
    #   PURPOSE: Слой значений клиента и честные счётчики отброшенного.
    #   INPUTS: { records: Iterable[Mapping] - карточки с полями surname, name, patronymic }
    #   OUTPUTS: { (слой {класс: значения}, счётчики) - счётчики без значений }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT, V-M-DICT
    # END_CONTRACT: build_client_layer
    """
    layer: dict[str, list[str]] = {}
    seen: dict[str, set[str]] = {}
    counters: dict[str, int] = {"records": 0, "kept": 0}
    for record in records:
        counters["records"] += 1
        for field in NAME_FIELDS:
            value = record.get(field)
            if value is None:
                continue
            cls, cleaned, reason = classify_field(str(value))
            if cls is None:
                counters[f"dropped_{reason or 'unknown'}"] = counters.get(f"dropped_{reason or 'unknown'}", 0) + 1
                continue
            if cls != CLASS_NAME:
                counters[f"reclassified_to_{cls}"] = counters.get(f"reclassified_to_{cls}", 0) + 1
            bucket = seen.setdefault(cls, set())
            if cleaned in bucket:
                continue
            bucket.add(cleaned)
            layer.setdefault(cls, []).append(cleaned)
            counters["kept"] += 1
    for values in layer.values():
        values.sort()
    return layer, counters


def build_forms_index(
    values: Iterable[str],
    kinds: tuple[str, ...] = NAME_KINDS,
) -> tuple[dict[str, str], dict[str, str], dict[str, int]]:
    """Предгенерировать формы значений клиентского слоя: форма → значение.

    # START_CONTRACT: build_forms_index
    #   PURPOSE: Дать распознаванию индекс «падежная форма → значение клиента», чтобы склонённое ФИО находилось и сразу относилось к своей персоне.
    #   INPUTS: { values: Iterable[str] - значения клиентского слоя, kinds: tuple[str, ...] - виды полей ФИО }
    #   OUTPUTS: { (exact, forms, counters) - точные написания, формы и счётчики без значений }
    #   SIDE_EFFECTS: читает таблицы склонений (кэшируются в модуле форм)
    #   LINKS: M-DICT, M-NAME-FORMS, M-NAME-IDENTITY, V-M-NAME-IDENTITY
    # END_CONTRACT: build_forms_index

    Два словаря, а не один, потому что идентичность разрешается по порядку: сначала точное
    значение клиентского справочника, и только потом форма, из которой оно сгенерировано
    (решение владельца 18.09.2026 — «точное значение важнее основы»). Неоднозначная форма
    (её порождают несколько значений) в индекс не попадает: угадывать персону нельзя, и
    поверхностное написание остаётся своей идентичностью.

    Латиница остаётся точным совпадением: таблицы склонений кириллические, и выдуманные
    формы латинского значения дали бы ложные срабатывания.
    """
    exact: dict[str, str] = {}
    forms: dict[str, str] = {}
    ambiguous: set[str] = set()
    counters: dict[str, int] = {"values": 0, "forms": 0, "ambiguous": 0, "latin_exact_only": 0}
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        counters["values"] += 1
        key = normalize_name(text) or text.lower()
        # Два написания одного ключа («Печёнов» и «Печенов») после нормализации — одна
        # персона: точным значением остаётся первое написание, второй код не заводится.
        exact.setdefault(key, text)
        generated: list[str] = []
        if _CYRILLIC.search(text):
            for kind in kinds:
                generated.extend(name_forms(text, kind))
        else:
            counters["latin_exact_only"] += 1
        for form in generated:
            candidate = normalize_name(form)
            if not candidate or candidate == key:
                continue
            counters["forms"] += 1
            existing = forms.get(candidate)
            if existing is None:
                forms[candidate] = text
            elif existing != text:
                ambiguous.add(candidate)
    for candidate in ambiguous:
        forms.pop(candidate, None)
    counters["ambiguous"] = len(ambiguous)
    return exact, forms, counters


def diff_against_open(layer: Mapping[str, list[str]], open_values: Iterable[str]) -> tuple[dict[str, list[str]], dict[str, int]]:
    """Keep only values the open list does not know.

    # START_CONTRACT: diff_against_open
    #   PURPOSE: В клиентском слое остаётся только то, чего нет в открытом справочнике.
    #   INPUTS: { layer: Mapping[str, list[str]] - слой, open_values: Iterable[str] - значения открытого списка }
    #   OUTPUTS: { (слой, счётчики) - сколько оставлено и сколько закрыто открытым списком }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT, M-NAME-LAYER, V-M-DICT
    # END_CONTRACT: diff_against_open
    """
    known = {normalize_name(value) for value in open_values if value}
    out: dict[str, list[str]] = {}
    counters = {"total": 0, "kept": 0, "covered_by_open": 0}
    for cls, values in layer.items():
        for value in values:
            counters["total"] += 1
            key = normalize_name(value)
            if key in known:
                counters["covered_by_open"] += 1
                continue
            out.setdefault(cls, []).append(value)
            counters["kept"] += 1
    return out, counters
