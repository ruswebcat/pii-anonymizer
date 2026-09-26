# FILE: src/tokenizer.py
# VERSION: 1.4.0
# START_MODULE_CONTRACT
#   PURPOSE: Replace every personal-data value in an OpenAI-compatible request with deterministic tokens, covering system text, message history, tool results and tool-call arguments.
#   SCOPE: recursive payload walk, JSON-embedded string handling, detection order dictionary then rules then NER, overlap resolution, binding persistence, per-class statistics.
#   DEPENDS: M-TOKEN-GEN, M-MAP-STORE, M-DETECT-RULES, M-DETECT-NAME, M-CACHE, M-AUDIT
#   LINKS: M-TOKENIZER, V-M-TOKENIZER, fn-tokenize_payload, fn-tokenize_text
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   TokenizeError - tokenization failure with a stable code
#   PayloadTokenizer - full payload anonymizer
#   fn-tokenize_text - anonymize one text block
#   fn-_bindings_tag - отпечаток связей «код → персона» для кэшированной записи
#   fn-_cache_bindings_intact - проверка кодов кэшированной записи на попадании
#   fn-_cache_block - запись обезличенного блока в кэш вместе с отпечатком связей
#   fn-tokenize_payload - anonymize every string in a request payload
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.4.0 - блоки с находками кэшируются (решение 26.09.2026), потому что в живом диалоге почти каждый блок несёт код, и запрет на их запись оставлял секунды на месте. Вместо запрета — ответственность: запись хранит отпечаток связей «код → персона», на попадании каждый код обязан всё ещё разрешаться в то же значение, иначе запись считается устаревшей. Ключ кэша несёт подпись справочника, поэтому смена справочника делает недействительным весь кэш.
#   PREVIOUS: v1.3.0 - Phase-15 шаг 6 (дефект-фикс 20.09.2026): второй проход сравнивает значение по написанию, а не по точному совпадению строки. Причина найдена замером: прибор показывал 617 найденных заслоном значений и 307 ушедших провайдеру, и 305 из 402 оставшихся вхождений — то же значение в другом регистре («Иванов» заменён, «ИВАНОВ» ушёл). Теперь заменяются все вхождения значения в любом регистре тем же кодом (общий предикат M-TOKEN-GEN).
#   PREVIOUS: v1.2.0 - Phase-15 шаг 2: выдача кода вынесена в публичный вызов issue_identifier — второй проход заслона берёт обозначения из той же фабрики, что и первый, и детерминированность кодов сохраняется.
#   PREVIOUS: v1.1.0 - Phase-7 шаг 4: код выводится из идентичности значения (персоны), занятость проверяется по идентичности, наблюдённые формы пишутся в справочник.
# END_CHANGE_SUMMARY

"""Payload tokenizer.

Implements M-TOKENIZER from docs/ARCHITECTURE.md. Two properties matter for
the security guarantee:

* the walk covers *every* string in the payload, because the upstream API is
  stateless and each request re-sends the whole history (risk-2 in the plan);
* strings that themselves contain JSON (tool-call arguments, tool results) are
  parsed, walked and re-serialized, so replacing a numeric identifier cannot
  break the structure of the arguments.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any, Callable

from src.audit import AuditEvent, AuditJournal
from src.detect_name import NameDetector
from src.detect_rules import PiiMatch, detect_known_numbers, detect_rules, detect_tabular, merge_matches
from src.map_store import MapStoreError, TokenMapStore
from src.name_identity import matches_identity
from src.normalize import NormalizeError, normalize, split_birth_date
from src.token_factory import (
    candidate_tokens,
    find_tokens,
    is_valid_token,
    iter_value_occurrences,
    replace_value_occurrences,
)

LOGGER_NAME = "PayloadTokenizer"
LOG_MARKER = "[PayloadTokenizer][tokenize_payload][BLOCK_TOKENIZE_PAYLOAD]"
CLASS_LETTERS = ("P", "T", "E", "D", "A", "I", "C")
#: Метка «код не разрешается» в отпечатке связей кэшированной записи. Отличается от
#: пустой идентичности записи, созданной до Phase-7: пустая идентичность — норма
#: (сравнение тогда идёт по значению), а неразрешимый код — не норма.
CACHE_UNRESOLVED_CODE = "\x00no-binding"

# Provider payloads carry identifiers under well known JSON keys. A bare number
# under one of these keys is PII too (a client id combined with club, date and
# amount re-identifies a person), so the value is tokenized even though no
# regex would fire on it.
PII_KEY_CLASSES = {
    "client_id": "C",
    "clientid": "C",
    "клиент_id": "C",
    "id_клиента": "C",
    "contract_id": "C",
    "договор_id": "C",
    "phone": "T",
    "телефон": "T",
    "mobile": "T",
    "email": "E",
    "e-mail": "E",
    "почта": "E",
    "fio": "P",
    "фио": "P",
    "фамилия": "P",
    "имя": "P",
    "birth_date": "D",
    "birthdate": "D",
    "дата_рождения": "D",
    "др": "D",
    "address": "A",
    "адрес": "A",
}

# Person-name keys need a different treatment from the keys above: "name" also
# names tools and functions, and anonymizing those would break tool calls. So a
# value under such a key is tokenized only when it actually looks like a human
# name, and never inside a tools/function block.
PERSON_NAME_KEYS = frozenset(
    {
        "name",
        "first_name",
        "given_name",
        "middle_name",
        "patronymic",
        "отчество",
        "surname",
        "last_name",
        "family_name",
        "full_name",
        "имя_клиента",
    }
)
TECHNICAL_NAME_VALUES = frozenset(
    {
        "assistant",
        "system",
        "user",
        "tool",
        "function",
        "content",
        "role",
        "model",
        "text",
        "json",
        "null",
        "true",
        "false",
        "ok",
        "error",
        "status",
        "success",
        "data",
        "items",
        "index",
        "message",
        "type",
        "value",
        "key",
    }
)
TOOL_CONTEXT_KEYS = frozenset({"function", "tools", "tool_calls", "tool_call"})
CONTACT_TYPE_CLASSES = {
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
NAME_SHAPE = re.compile(r"^[A-Za-zА-Яа-яЁё][A-Za-zА-Яа-яЁё'\- ]{1,39}$")
WORD_IN_VALUE = re.compile(r"[A-Za-zА-Яа-яЁё]{3,}")


def _fallback_canonical(cls: str, value: str) -> str | None:
    """Return a safe canonical form for a value whose format was unexpected.

    # START_CONTRACT: _fallback_canonical
    #   PURPOSE: Keep an oddly formatted value from leaving the perimeter openly.
    #   INPUTS: { cls: str - class letter, value: str - raw value }
    #   OUTPUTS: { str | None - canonical form, or None when the value is unusable }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKEN-GEN, V-M-TOKENIZER
    # END_CONTRACT: _fallback_canonical
    """
    text = (value or "").strip()
    if not text:
        return None
    if cls in {"T", "I", "C"}:
        digits = re.sub(r"\D", "", text)
        return digits if len(digits) >= 4 else None
    collapsed = re.sub(r"\s+", " ", text).lower()
    return collapsed[:200] if collapsed else None


def _contact_class(node: Mapping[str, Any]) -> str | None:
    """Return the PII class implied by a contact object's own ``contact_type``.

    # START_CONTRACT: _contact_class
    #   PURPOSE: Read the data kind from the sibling field when the key is generic.
    #   INPUTS: { node: Mapping[str, Any] - candidate object }
    #   OUTPUTS: { str | None - class letter }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKENIZER, V-M-TOKENIZER
    # END_CONTRACT: _contact_class
    """
    if "contact" not in node:
        return None
    kind = node.get("contact_type")
    if not isinstance(kind, str):
        return None
    return CONTACT_TYPE_CLASSES.get(kind.strip().lower())


def _looks_like_person_name(value: Any) -> bool:
    """Return True when a value under a person-name key is plausibly a name.

    # START_CONTRACT: _looks_like_person_name
    #   PURPOSE: Tokenize real names (including Latin script) without touching tool names.
    #   INPUTS: { value: Any - field value }
    #   OUTPUTS: { bool - True when the value looks like a human name }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKENIZER, V-M-TOKENIZER
    # END_CONTRACT: _looks_like_person_name

    Latin-script names are the reason this exists: CRM holds records whose
    ``name`` is "Testa" while the detectors only know Cyrillic shapes, so those
    values survived openly (found by the re-identification run on 15.09.2026).

    A long word is enough rather than an exact shape, because the data itself is
    untidy: the last surviving value in that run was a Latin surname followed by
    question marks, and "looks slightly odd" is not a reason to leave a client's
    surname in a request. Snake_case, digits and known technical words are still
    excluded, so a tool or role name never turns into personal data.
    """
    if not isinstance(value, str):
        return False
    text = value.strip()
    if len(text) < 2 or len(text) > 60 or "_" in text:
        return False
    if any(char.isdigit() for char in text):
        return False
    if text.lower() in TECHNICAL_NAME_VALUES:
        return False
    if text.isupper() and len(text) <= 4:
        # Short all-caps values are codes, not people.
        return False
    return NAME_SHAPE.match(text) is not None or WORD_IN_VALUE.search(text) is not None


class TokenizeError(RuntimeError):
    """Tokenization failure with a stable code.

    # START_CONTRACT: TokenizeError
    #   PURPOSE: Convert store or detection failures into a router-level block.
    #   INPUTS: { code: str - stable code, message: str - detail }
    #   OUTPUTS: { TokenizeError - exception instance }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKENIZER, M-ROUTER, V-M-TOKENIZER
    # END_CONTRACT: TokenizeError
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# START_BLOCK_TOKENIZE_PAYLOAD
class PayloadTokenizer:
    """Anonymize an entire request payload.

    # START_CONTRACT: PayloadTokenizer
    #   PURPOSE: Own detection order and replacement for every payload string.
    #   INPUTS: { token_key: bytes, store: TokenMapStore, name_detector: NameDetector, ner: Any | None, cache: Any | None, audit: AuditJournal | None }
    #   OUTPUTS: { PayloadTokenizer - ready tokenizer }
    #   SIDE_EFFECTS: writes bindings into the correspondence table, appends audit events
    #   LINKS: M-TOKEN-GEN, M-MAP-STORE, M-DETECT-RULES, M-DETECT-NAME, V-M-TOKENIZER
    # END_CONTRACT: PayloadTokenizer
    """

    def __init__(
        self,
        token_key: bytes,
        store: TokenMapStore,
        name_detector: NameDetector | None = None,
        ner: Any | None = None,
        cache: Any | None = None,
        audit: AuditJournal | None = None,
        use_rules: bool = True,
    ) -> None:
        self._key = token_key
        self._store = store
        self._names = name_detector or NameDetector()
        self._ner = ner
        self._cache = cache
        # Подпись справочника: строка «путь|время правки|размер» от NameDetector.dictionary_signature.
        # Тип — Any, как у заслона: подпись приходит динамически через getattr, и её источник
        # может быть подменён заглушкой (см. tests/test_validator_pair_cache.py).
        self._dictionary_marker: Any = None
        self._audit = audit
        self._use_rules = use_rules

    def detect(self, text: str) -> list[PiiMatch]:
        """Collect every match for a text block in a deterministic order.

        # START_CONTRACT: detect
        #   PURPOSE: Run tabular, rule and name detection and resolve overlaps.
        #   INPUTS: { text: str - block to scan }
        #   OUTPUTS: { list[PiiMatch] - non-overlapping matches }
        #   SIDE_EFFECTS: may query the optional NER model
        #   LINKS: M-DETECT-RULES, M-DETECT-NAME, M-NER
        # END_CONTRACT: detect
        """
        found: list[PiiMatch] = []
        found.extend(detect_tabular(text))
        if self._use_rules:
            found.extend(detect_rules(text))
        found.extend(detect_known_numbers(text, getattr(self._names, "lookup_known", None)))
        found.extend(self._names.detect_names(text))
        if self._ner is not None:
            found.extend(self._ner.detect_names(text))
        return merge_matches(found)

    def _bindings_tag(self, text: str) -> str | None:
        """Отпечаток связей «код → персона» для обезличенного текста.

        # START_CONTRACT: _bindings_tag
        #   PURPOSE: Запомнить, под какими связями построена кэшированная запись, чтобы на попадании отличить живой код от устаревшего.
        #   INPUTS: { text: str - обезличенный текст блока }
        #   OUTPUTS: { str | None - отпечаток, или None когда справочник не читается }
        #   SIDE_EFFECTS: читает справочник соответствия
        #   LINKS: M-CACHE, M-MAP-STORE, V-M-CACHE
        # END_CONTRACT: _bindings_tag

        В отпечаток входят сами коды и отпечаток персоны, за которой код закреплён
        (хеш под ключом кодов), — значений в кэше не появляется. Код, которого в
        справочнике больше нет, помечается отдельной меткой: это и есть «код
        перестал разрешаться». Кодов в блоке немного, поэтому проверка дешёвая.
        """
        marks: list[str] = []
        for token in sorted({item[3] for item in find_tokens(text)}):
            try:
                identity = self._store.load_identity(token)
            except Exception:  # noqa: BLE001 - сбой чтения справочника не повод доверять записи
                return None
            marker = CACHE_UNRESOLVED_CODE if identity is None else identity
            digest = hashlib.sha256(self._key + marker.encode("utf-8")).hexdigest()
            marks.append(f"{token}:{digest[:16]}")
        return hashlib.sha256("|".join(marks).encode("utf-8")).hexdigest()

    def _cache_bindings_intact(self, value: str, tag: str) -> bool:
        """Проверить, что коды кэшированной записи всё ещё разрешаются в те же значения.

        # START_CONTRACT: _cache_bindings_intact
        #   PURPOSE: Не отдавать запись, коды которой перестали разрешаться или сменили значение.
        #   INPUTS: { value: str - кэшированный текст, tag: str - записанный отпечаток связей }
        #   OUTPUTS: { bool - True когда запись можно отдавать }
        #   SIDE_EFFECTS: читает справочник соответствия
        #   LINKS: M-CACHE, M-MAP-STORE, V-M-CACHE
        # END_CONTRACT: _cache_bindings_intact
        """
        if not tag:
            return False
        current = self._bindings_tag(value)
        return current is not None and current == tag

    def _cache_block(self, text: str, result: str) -> str:
        """Положить обезличенный блок в кэш вместе с отпечатком его связей.

        # START_CONTRACT: _cache_block
        #   PURPOSE: Кэшировать и блок с находками, не теряя проверяемость записи.
        #   INPUTS: { text: str - исходный блок, result: str - обезличенный блок }
        #   OUTPUTS: { str - result }
        #   SIDE_EFFECTS: пишет запись в кэш
        #   LINKS: M-CACHE, V-M-CACHE
        # END_CONTRACT: _cache_block

        Блок без находок уходит в кэш без отпечатка: его текст не изменился, своих
        связей у записи нет и проверять нечего — это прежнее поведение. У блока с
        находками отпечаток обязателен: именно он отличает живой код от устаревшего,
        когда справочник перезагрузят, связь исчезнет или код сменят.
        """
        if self._cache is None:
            return result
        tag = ""
        if result != text:
            tag = self._bindings_tag(result) or ""
        self._cache.put(text, result, tag)
        return result

    def _dictionary_changed(self) -> bool:
        """Return True when the dictionary file changed since the last check.

        # START_CONTRACT: _dictionary_changed
        #   PURPOSE: Drop stale cached anonymization after a dictionary reload or replacement.
        #   INPUTS: { none }
        #   OUTPUTS: { bool - True when the signature changed }
        #   SIDE_EFFECTS: remembers the last seen signature, reads file metadata once
        #   LINKS: M-CACHE, M-DICT
        # END_CONTRACT: _dictionary_changed

        Подпись несёт и путь справочника, и состояние файла (время правки, размер), и стоит
        один `os.stat`: на неизменном справочнике проверка не делает лишней работы.
        """
        current = getattr(self._names, "dictionary_signature", None)
        if not callable(current):
            return False
        try:
            signature = current()
        except Exception:  # noqa: BLE001 - a broken dictionary must not stop tokenization
            return False
        if signature is None:
            return False
        if getattr(self, "_dictionary_marker", None) is None:
            self._dictionary_marker = signature
            return False
        if signature != self._dictionary_marker:
            self._dictionary_marker = signature
            return True
        return False

    def tokenize_text(self, text: str, session_id: str = "", stats: dict[str, int] | None = None) -> str:
        """Anonymize one text block and return the replaced text.

        # START_CONTRACT: tokenize_text
        #   PURPOSE: Replace all detected values with tokens.
        #   INPUTS: { text: str - block, session_id: str - audit correlation, stats: dict[str, int] | None - class counters }
        #   OUTPUTS: { str - text with tokens }
        #   SIDE_EFFECTS: writes bindings, updates the optional cache, appends audit events
        #   LINKS: M-TOKEN-GEN, M-MAP-STORE, V-M-TOKENIZER
        # END_CONTRACT: tokenize_text
        """
        if not text:
            return text
        if self._cache is not None:
            if self._dictionary_changed():
                # Кэш держит текст, обезличенный по прошлому словарю. После перезагрузки словаря
                # («hot reload» из выгрузки) такие записи устарели: значение, которого раньше не
                # было в списках, оставалось в исходящем запросе (находка 18.09.2026).
                self._cache.clear()
            cached = self._cache.get(text, verify=self._cache_bindings_intact)
            if cached is not None:
                if stats is not None:
                    stats["cache_hits"] = stats.get("cache_hits", 0) + 1
                return cached

        # A text block that is itself JSON must be treated exactly like a nested
        # payload string, otherwise a second pass over restored text (the next
        # conversation turn) would tokenize it differently and break the provider
        # prompt cache prefix (verified 15.09.2026).
        if self._looks_like_json(text):
            return self._tokenize_string(text, session_id, stats if stats is not None else {})

        matches = self.detect(text)
        if not matches:
            # Блок без находок: текст не менялся, отпечаток связей не нужен.
            return self._cache_block(text, text)

        result = text
        for match in sorted(matches, key=lambda m: m.start, reverse=True):
            token = self._assign_identifier(
                match.cls, match.identity or match.normalized, match.raw, stats
            )
            result = result[: match.start] + token + result[match.end :]
        # Второй проход с самопроверкой (находка 18.09.2026). Приёмка показала: при определённом
        # сочетании находок часть значений (телефоны, одно имя) оставалась в тексте, хотя
        # детектор их видел. Проверяем по ИСХОДНЫМ находкам, а не по результату: замена
        # разрушает контекст («клиентский контекст» держится на соседних словах), и повторное
        # распознавание по результату перестаёт видеть ровно те значения, ради которых проход
        # и делается. Живая находка 18.09.2026: заслон ловил шесть таких вхождений и блокировал
        # личный чат владельца в Mattermost.
        leftover: list[PiiMatch] = []
        for match in matches:
            raw = (match.raw or "").strip()
            if not raw or is_valid_token(raw):
                continue
            # Дефект 20.09.2026: проверялось точное написание («raw in result»), поэтому
            # значение уходило кодом в одном написании и оставалось в исходящем запросе в
            # другом — «Иванов» заменён, «ИВАНОВ» ушёл провайдеру. Критерий теперь тот же,
            # что у заслона: по написанию, без учёта регистра и с любыми пробелами.
            if next(iter_value_occurrences(result, raw), None) is not None:
                leftover.append(match)
        for match in sorted(leftover, key=lambda m: m.start, reverse=True):
            raw = (match.raw or "").strip()
            # Значение ищем заново: после первой замены смещения сдвинулись. Убираем все
            # его вхождения — если детектор признал значение данными, оно не должно остаться
            # в исходящем тексте ни в одном месте и ни в одном регистре, иначе запрос
            # справедливо блокируется.
            token = self._assign_identifier(
                match.cls, match.identity or match.normalized, match.raw, stats
            )
            result, _replaced = replace_value_occurrences(result, raw, token)
        if self._audit is not None and leftover:
            self._audit.append(
                AuditEvent(
                    session_id=session_id,
                    action="second_pass",
                    direction="inbound",
                    cls="-",
                    count=len(leftover),
                    channel="",
                    reason="",
                )
            )
        # Кэшируются и блоки с находками (решение 26.09.2026): без этого история, где почти
        # каждый блок несёт код, сканировалась заново на каждом запросе, и секунды оставались
        # на месте. Отказ снят не молча, а вместе с ответственностью: запись несёт отпечаток
        # связей, и на попадании каждый код обязан всё ещё разрешаться в то же значение
        # (_cache_bindings_intact); иначе запись считается устаревшей и блок обезличивается
        # заново. Ключ кэша несёт подпись справочника, поэтому его смена гасит весь кэш.
        return self._cache_block(text, result)

    def issue_identifier(
        self,
        cls: str,
        identity: str,
        raw: str,
        stats: dict[str, int] | None = None,
    ) -> str:
        """Выдать код значению тем же присвоением, что и первый проход.

        # START_CONTRACT: issue_identifier
        #   PURPOSE: Дать заслону ту же фабрику кодов: второй проход не изобретает обозначений.
        #   INPUTS: { cls: str - класс, identity: str - идентичность значения, raw: str - наблюдённая форма, stats: dict[str, int] | None - счётчики классов }
        #   OUTPUTS: { str - выданный код }
        #   SIDE_EFFECTS: пишет связку в справочник и наблюдённую форму
        #   LINKS: M-TOKEN-GEN, M-MAP-STORE, M-VALIDATOR, V-M-TOKENIZER
        # END_CONTRACT: issue_identifier

        Публичный вход существует ровно потому, что Вариант 1 (Phase-15) обязан заменять
        остаток тем же кодом, который получило бы это значение в первом проходе: то же
        значение — тот же код, иначе поехала бы не только детерминированность, но и
        байтовый префикс уже отправленных ходов (кэш провайдера).
        """
        return self._assign_identifier(cls, identity or raw, raw, stats)

    def _matches_identity(self, cls: str, value: str, identity: str) -> bool:
        """Сравнить написание с идентичностью, зная и читаемые значения, и отпечатки выгрузки.

        # START_CONTRACT: _matches_identity
        #   PURPOSE: Не завести второй код персоне, чья прежняя связка хранит значение, а новая идентичность — отпечаток (schema 3).
        #   INPUTS: { cls: str - класс, value: str - прежнее значение, identity: str - ключ идентичности }
        #   OUTPUTS: { bool - True, когда это одна персона }
        #   SIDE_EFFECTS: читает словарь через распознавание
        #   LINKS: M-NAME-IDENTITY, M-DICT, M-MAP-STORE
        # END_CONTRACT: _matches_identity
        """
        same = getattr(self._names, "identity_matches", None)
        if callable(same):
            try:
                return bool(same(cls, value, identity))
            except Exception:  # noqa: BLE001 - сбой словаря не должен ломать присвоение кода
                pass
        return matches_identity(cls, value, identity)

    def _assign_identifier(
        self,
        cls: str,
        identity: str,
        raw: str,
        stats: dict[str, int] | None = None,
        render: "Callable[[str], str] | None" = None,
    ) -> str:
        """Store the value under the first free deterministic candidate identifier.

        # START_CONTRACT: _assign_identifier
        #   PURPOSE: Give every value a stable identifier while guaranteeing that two different values never share one (Phase-4 mechanism 1) and that all case forms of one person share one code (Phase-7).
        #   INPUTS: { cls: str - class letter, identity: str - identity key of the value (person, not the case form), raw: str - observed form to store, stats: dict | None - counters, render: callable | None - builds the stored string from the candidate }
        #   OUTPUTS: { str - the assigned identifier }
        #   SIDE_EFFECTS: writes one binding into the correspondence table, appends the observed form
        #   LINKS: M-TOKEN-GEN, M-MAP-STORE, M-NAME-IDENTITY, V-M-TOKENIZER
        # END_CONTRACT: _assign_identifier

        Ключ вывода кода — идентичность значения (M-NAME-IDENTITY), поэтому «Иванов»,
        «Иванова» и «Иванову» приходят к одному кандидату. Занятость проверяется по
        идентичности, а не по написанию: иначе падежная форма считалась бы «другим
        значением» и уводила персону на второй код. Запись, созданная до Phase-7 (без
        идентичности), принимается, если её значение приводится к той же идентичности
        правилом `matches_identity`.
        """
        collisions = 0
        for candidate in candidate_tokens(cls, identity, self._key):
            try:
                stored = render(candidate) if render is not None else raw
                existing = self._store.load_identity(candidate)
                if existing is None:
                    legacy = self._store.load_value(candidate)
                    if legacy is not None and not self._matches_identity(cls, legacy, identity):
                        collisions += 1
                        continue
                    self._store.store(candidate, cls, stored, identity)
                elif existing != identity:
                    collisions += 1
                    continue
                self._store.append_form(candidate, stored)
                if stats is not None:
                    stats[cls] = stats.get(cls, 0) + 1
                    if collisions:
                        stats["collisions_resolved"] = stats.get("collisions_resolved", 0) + collisions
                return candidate
            except MapStoreError as exc:
                raise TokenizeError("TOKENIZE_STORE_FAILED", exc.message) from exc
        raise TokenizeError(
            "TOKENIZE_NO_CANDIDATE",
            f"identifier space exhausted for {cls} after {collisions} collisions",
        )

    @staticmethod
    def _replace_birth_date(
        stripped: str, day_month: str, year: str, token: str
    ) -> tuple[str, str]:
        """Replace only the day-month part of a birth date, in either order.

        # START_CONTRACT: _replace_birth_date
        #   PURPOSE: Tokenize the identifying part and keep the year open, whatever the format.
        #   INPUTS: { stripped: str, day_month: str, year: str, token: str }
        #   OUTPUTS: { tuple[str, str] - (text with the token, value for the correspondence table) }
        #   SIDE_EFFECTS: none
        #   LINKS: M-NORM, M-TOKEN-GEN, M-MAP-STORE, V-M-TOKENIZER
        # END_CONTRACT: _replace_birth_date

        Two orders exist in practice: "12.03.1985" (day first, what people type)
        and "1985-03-12" (ISO, what the API returns in some selections). The
        identifying part is the day and month in both, and in both the year must
        stay readable, so the token goes exactly where the day-month sits.
        """
        day, _, month = day_month.partition(".")
        iso_month_day = f"{month}-{day}"
        if stripped.startswith(year) and iso_month_day in stripped:
            return stripped.replace(iso_month_day, token, 1), iso_month_day
        prefix = stripped[: stripped.rfind(year)].rstrip(".-/ ") if year in stripped else stripped
        if not prefix:
            return f"{token}.{year}" if year else token, stripped
        return f"{token}{stripped[len(prefix):]}", prefix

    @staticmethod
    def _looks_like_json(text: str) -> bool:
        """Return True when the block is a JSON object or array.

        # START_CONTRACT: _looks_like_json
        #   PURPOSE: Route JSON blobs through the structure-preserving walk.
        #   INPUTS: { text: str - candidate block }
        #   OUTPUTS: { bool - True when the block parses as JSON object or array }
        #   SIDE_EFFECTS: none
        #   LINKS: M-TOKENIZER, V-M-TOKENIZER
        # END_CONTRACT: _looks_like_json
        """
        stripped = (text or "").strip()
        if len(stripped) < 3 or stripped[0] not in "{[" or stripped[-1] not in "}]":
            return False
        try:
            json.loads(stripped)
            return True
        except json.JSONDecodeError:
            return False

    def _walk(self, node: Any, session_id: str, stats: dict[str, int]) -> Any:
        """Recursively tokenize every string inside a JSON-like node.

        ``tool_context`` travels down the tree so that a "name" inside a tools or
        function block (a tool name, not a person) is never tokenized. Without
        that guard the first version of the person-key rule would have renamed
        every tool the agent can call.
        """
        return self._walk_node(node, session_id, stats, tool_context=False)

    def _walk_node(
        self,
        node: Any,
        session_id: str,
        stats: dict[str, int],
        tool_context: bool,
    ) -> Any:
        """Recursive worker for _walk with tool-context tracking."""
        if isinstance(node, str):
            return self._tokenize_string(node, session_id, stats)
        if isinstance(node, list):
            return [self._walk_node(item, session_id, stats, tool_context) for item in node]
        if isinstance(node, dict):
            walked: dict[Any, Any] = {}
            # A contact object carries its kind in a sibling field rather than in
            # the key: {"contact_type": "phone", "contact": "<16 digits>"}.
            # Without this the value slipped through every rule, because the
            # pattern only knew 11-digit phone shapes (found by the
            # re-identification run on 15.09.2026).
            contact_cls = _contact_class(node)
            for key, value in node.items():
                name = str(key).strip().lower().replace(" ", "_")
                nested_tool_context = tool_context or name in TOOL_CONTEXT_KEYS
                cls = PII_KEY_CLASSES.get(name)
                if cls is None and contact_cls is not None and name == "contact":
                    cls = contact_cls
                if cls is None and name in PERSON_NAME_KEYS and not tool_context:
                    if _looks_like_person_name(value):
                        cls = "P"
                if cls is not None:
                    walked[key] = self._force_tokenize(value, cls, stats)
                else:
                    walked[key] = self._walk_node(
                        value, session_id, stats, nested_tool_context
                    )
            return walked
        return node

    def _force_tokenize(self, value: Any, cls: str, stats: dict[str, int]) -> Any:
        """Tokenize a value that sits under a known PII key, whatever its type.

        # START_CONTRACT: _force_tokenize
        #   PURPOSE: Close the gap left by regex detection for bare identifiers.
        #   INPUTS: { value: Any - raw field value, cls: str - class implied by the key, stats: dict[str, int] }
        #   OUTPUTS: { Any - token string, or the value unchanged when it cannot be canonicalized }
        #   SIDE_EFFECTS: writes a binding into the correspondence table
        #   LINKS: M-MAP-STORE, V-M-TOKENIZER
        # END_CONTRACT: _force_tokenize
        """
        if isinstance(value, bool) or value is None:
            return value
        raw = value if isinstance(value, str) else str(value)
        stripped = raw.strip()
        if not stripped or is_valid_token(stripped):
            return value
        try:
            if cls == "D":
                day_month, year = split_birth_date(stripped)
                # The stored value embeds the identifier itself, so the walk needs a
                # renderer: candidate in, stored string out.
                holder: dict[str, str] = {}

                def _render(candidate: str) -> str:
                    replaced, stored = self._replace_birth_date(
                        stripped, day_month, year, candidate
                    )
                    holder["replaced"] = replaced
                    return stored

                token = self._assign_identifier(cls, day_month, stripped, stats, render=_render)
                replaced = holder.get("replaced")
                if replaced is None:
                    replaced = self._replace_birth_date(stripped, day_month, year, token)[0]
                return replaced
            normalized = normalize(cls, stripped)
        except NormalizeError:
            # A value sitting under a known PII key must not escape just because
            # its shape is unexpected: an operator once entered a 16-digit phone,
            # and "normalization refused it" turned into "the value left openly"
            # (found by the re-identification run on 15.09.2026). The fallback
            # canonical form keeps the binding deterministic.
            fallback = _fallback_canonical(cls, stripped)
            if fallback is None:
                return value
            return self._assign_identifier(cls, fallback, stripped, stats)
        except MapStoreError as exc:
            raise TokenizeError("TOKENIZE_STORE_FAILED", exc.message) from exc
        if cls == "P":
            # Значение под ключом ФИО подтверждено справочником — берём персону, а не
            # написание: иначе «Ивановой» под полем «фамилия» получил бы второй код.
            confirmed = getattr(self._names, "identity_for", None)
            if callable(confirmed):
                identity = confirmed(stripped)
                if identity:
                    return self._assign_identifier(cls, str(identity), stripped, stats)
        return self._assign_identifier(cls, normalized, stripped, stats)

    def _tokenize_string(self, text: str, session_id: str, stats: dict[str, int]) -> str:
        """Tokenize a string, walking it as JSON first when it clearly is JSON."""
        stripped = text.strip()
        if (
            len(stripped) > 2
            and stripped[0] in "{[" and stripped[-1] in "}]"
        ):
            try:
                inner = json.loads(stripped)
            except json.JSONDecodeError:
                return self.tokenize_text(text, session_id, stats)
            walked = self._walk(inner, session_id, stats)
            return json.dumps(walked, ensure_ascii=False)
        return self.tokenize_text(text, session_id, stats)

    def tokenize_payload(self, payload: dict, session_id: str = "") -> tuple[dict, dict[str, int]]:
        """Anonymize every string in an OpenAI-compatible payload.

        # START_CONTRACT: tokenize_payload
        #   PURPOSE: Guarantee that no PII value leaves for the model.
        #   INPUTS: { payload: dict - request body, session_id: str - audit correlation }
        #   OUTPUTS: { tuple[dict, dict[str, int]] - anonymized payload and per-class counters }
        #   SIDE_EFFECTS: writes bindings, appends audit events
        #   LINKS: M-ROUTER, M-MAP-STORE, V-M-TOKENIZER
        # END_CONTRACT: tokenize_payload
        """
        stats: dict[str, int] = {}
        anonymized = self._walk(payload, session_id, stats)
        if self._audit is not None and stats:
            # Only class counters belong in the journal: the cache counter is an
            # operational metric, and the closed-schema journal rejects anything
            # that is not a single class letter (found by tests on 15.09.2026).
            classes_only = {
                key: value for key, value in stats.items() if key in CLASS_LETTERS
            }
            self._audit.record_tokenization(session_id, classes_only)
            # Phase-4 mechanism 1: a resolved collision is evidence, not noise —
            # it proves the walk kept two values apart. Reported as its own
            # event with a whitelisted name, never as a pseudo class letter.
            collisions = stats.get("collisions_resolved", 0)
            if collisions:
                self._audit.append(
                    AuditEvent(
                        session_id=session_id,
                        action="collision_resolved",
                        direction="internal",
                        cls="-",
                        count=collisions,
                        channel="",
                        reason="",
                    )
                )
        return anonymity_cast(anonymized, payload), stats
# END_BLOCK_TOKENIZE_PAYLOAD


def anonymity_cast(anonymized: Any, original: dict) -> dict:
    """Return the anonymized payload typed as a dict for callers.

    # START_CONTRACT: anonymity_cast
    #   PURPOSE: Keep the public signature honest: a payload in, a payload out.
    #   INPUTS: { anonymized: Any - walked structure, original: dict - the request body }
    #   OUTPUTS: { dict - anonymized payload }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKENIZER
    # END_CONTRACT: anonymity_cast
    """
    if isinstance(anonymized, dict):
        return anonymized
    return original
