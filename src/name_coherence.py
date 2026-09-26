# FILE: src/name_coherence.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Держать индекс со-встречаемости частей ФИО (фамилия, имя, отчество одной карточки) в виде ключевых отпечатков и отвечать на один вопрос: «эти части встречались вместе в источнике?» — чтобы доверенная граница не склеивала имя одного человека с фамилией другого.
#   SCOPE: сбор отпечатков сочетаний из карточек, порядконезависимый ключ сочетания, загрузка файла индекса с происхождением, проверка сочетания, режимы off/audit/enforce, счётчики без значений клиентов.
#   DEPENDS: M-DICT (функция отпечатка), M-NAME-FORMS (нормализация)
#   LINKS: M-NAME-COHERENCE, V-M-NAME-COHERENCE, fn-build_combos, fn-combo_digest, fn-load_name_coherence, fn-confirm, fn-is_candidate, fn-is_part_value
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   MODES - режимы проверки: off (выключена), audit (считать и писать инцидент), enforce (не восстанавливать)
#   MODE_OFF / MODE_AUDIT / MODE_ENFORCE - имена режимов
#   COHERENCE_SCHEMA - версия файла индекса
#   MIN_PART_LENGTH - короче этого часть ФИО не участвует в проверке
#   CoherenceError - сбой индекса с машинным кодом
#   fn-combo_digest - ключ сочетания: нормализованные части, порядок не важен
#   fn-is_part_value - похоже ли одно значение на часть ФИО
#   fn-is_candidate - похожи ли части сочетания на части ФИО (одно слово, только буквы)
#   fn-build_combos - отпечатки сочетаний из карточек источника
#   class-NameCoherence - загруженный индекс сочетаний
#   fn-confirm - встречались ли части вместе в источнике
#   fn-load_name_coherence - прочитать индекс, или None когда он не настроен
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-17 шаг 2 (20.09.2026): индекс со-встречаемости как ответ на выдуманную персону в живом ответе. Токены выдаются на ОТДЕЛЬНЫЕ значения, поэтому модель может сочетать имя одного человека с фамилией другого — сочетание, которого нет ни в одной карточке, на доверенной границе не восстанавливается (решение владельца, M-NAME-COHERENCE).
# END_CHANGE_SUMMARY

"""Индекс со-встречаемости частей ФИО (M-NAME-COHERENCE).

Почему модуль существует (разбор инцидента 20.09.2026). Код выдаётся на значение, а не на
персону: «Ангелина» получает один код, «Тестовцева» — другой, «Ветрова» — третий. Модель,
которой в запросе видны коды многих людей, вправе написать в ответе код не того человека — и
доверенная граница (M-DETOKENIZER) честно восстановит чужое значение, потому что код был в
запросе. Так родилась персона «Ангелина Ветрова», которой в базе нет. Реестр при этом
исправен: коллизии кодов в нём не было (замер 20.09.2026 — 0 кодов с более чем одним
значением на 4 718 связок).

Лечит это не длина кода, а связность: пара (фамилия, имя) и тройка (фамилия, имя, отчество)
обязаны быть подтверждены источником — карточкой клиента. Индекс строится инструментом
(``tools/build_name_combos.py``) и хранит ТОЛЬКО ключевые отпечатки сочетаний: файл без
ключа бесполезен, читаемых значений в нём нет.

Ключ сочетания порядконезависим: и «Иванов Иван», и «Иван Иванов» — одна и та же пара
(в карточках поля перепутаны местами, питфолл известен с 15.09.2026).
"""

from __future__ import annotations

import gzip
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.dictionary import value_digest
from src.name_forms import normalize_name

LOGGER_NAME = "NameCoherence"
LOG_MARKER = "[NameCoherence][confirm][BLOCK_CONFIRM_COMBO]"

COHERENCE_SCHEMA = 1

#: Режимы проверки сочетаний.
MODE_OFF = "off"
MODE_AUDIT = "audit"
MODE_ENFORCE = "enforce"
MODES = (MODE_OFF, MODE_AUDIT, MODE_ENFORCE)

#: Класс отпечатков: сочетания считаются той же ключевой функцией, что и справочник.
DIGEST_CLASS = "P"

#: Сочетание — это 2 или 3 части ФИО.
MIN_COMBO_PARTS = 2
MAX_COMBO_PARTS = 3

#: Часть короче этого длиной в сочетании не участвует: «Я», «|» основой не являются.
MIN_PART_LENGTH = 2

#: Часть ФИО: одно слово из букв (кириллица или латиница), возможно с дефисом и апострофом.
PART_SHAPE = re.compile(r"^[A-Za-zА-Яа-яЁё][A-Za-zА-Яа-яЁё'\-]{0,39}$")


class CoherenceError(RuntimeError):
    """Сбой индекса сочетаний с машинным кодом.

    # START_CONTRACT: CoherenceError
    #   PURPOSE: Отличить «индекс не настроен» (норма) от «индекс испорчен» (отказ).
    #   INPUTS: { code: str - машинный код, message: str - подробность без значений }
    #   OUTPUTS: { CoherenceError - исключение }
    #   SIDE_EFFECTS: none
    #   LINKS: M-NAME-COHERENCE, V-M-NAME-COHERENCE
    # END_CONTRACT: CoherenceError
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# START_BLOCK_BUILD_COMBOS
def combo_digest(key: bytes, parts: Sequence[str]) -> str | None:
    """Вернуть ключ сочетания частей ФИО, или None когда сочетание не собрать.

    # START_CONTRACT: combo_digest
    #   PURPOSE: Один ключ на сочетание, порядок частей не важен — в карточках поля перепутаны.
    #   INPUTS: { key: bytes - ключ отпечатков, parts: Sequence[str] - части ФИО }
    #   OUTPUTS: { str | None - шестнадцатеричный отпечаток }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT, V-M-NAME-COHERENCE
    # END_CONTRACT: combo_digest
    """
    if not key or not parts:
        return None
    normalized = sorted(part for part in (normalize_name(p) for p in parts) if part)
    if len(normalized) < MIN_COMBO_PARTS or len(normalized) > MAX_COMBO_PARTS:
        return None
    if len(set(normalized)) == 1:
        # Сочетание из одной и той же части («Иванов Иванов») персоной не подтверждает.
        return None
    return value_digest(key, DIGEST_CLASS, "|".join(normalized))


def is_part_value(value: str) -> bool:
    """Сказать, похоже ли одно значение на часть ФИО (одно слово из букв, достаточной длины).

    # START_CONTRACT: is_part_value
    #   PURPOSE: Отобрать значения, которые вообще могут быть частью ФИО, до проверки сочетаний.
    #   INPUTS: { value: str - восстановленное значение }
    #   OUTPUTS: { bool - True, когда это похоже на часть ФИО }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETOKENIZER, V-M-NAME-COHERENCE
    # END_CONTRACT: is_part_value

    Условие узкое намеренно: заслон не должен мешать тексту, где рядом стоят город и тариф, а
    телефон и адрес вообще не участвуют в связности персоны.
    """
    text = (value or "").strip()
    if " " in text or len(normalize_name(text)) < MIN_PART_LENGTH:
        return False
    return PART_SHAPE.match(text) is not None


def is_candidate(parts: Sequence[str]) -> bool:
    """Сказать, похожи ли части на части одного ФИО.

    # START_CONTRACT: is_candidate
    #   PURPOSE: Проверять только то, что может быть ФИО: одно слово из букв, достаточной длины.
    #   INPUTS: { parts: Sequence[str] - соседние восстановленные значения }
    #   OUTPUTS: { bool - True, когда сочетание стоит проверять }
    #   SIDE_EFFECTS: none
    #   LINKS: V-M-NAME-COHERENCE
    # END_CONTRACT: is_candidate

    Условие намеренно узкое: проверка сочетаний — заслон на доверенной границе, и он не
    должен мешать тексту, где рядом стоят, например, город и тариф.
    """
    if len(parts) < MIN_COMBO_PARTS or len(parts) > MAX_COMBO_PARTS:
        return False
    return all(is_part_value(part) for part in parts)


def build_combos(
    records: Iterable[Sequence[str]],
    key: bytes,
) -> tuple[set[str], dict[str, int]]:
    """Собрать отпечатки сочетаний из записей источника и счётчики по числу частей.

    # START_CONTRACT: build_combos
    #   PURPOSE: Дать инструменту сборки одну функцию: карточка → отпечатки сочетаний.
    #   INPUTS: { records: Iterable[Sequence[str]] - части ФИО каждой карточки, key: bytes - ключ отпечатков }
    #   OUTPUTS: { tuple[set[str], dict[str, int]] - отпечатки и счётчики (карточек, пар, троек) }
    #   SIDE_EFFECTS: none
    #   LINKS: M-NAME-COHERENCE, V-M-NAME-COHERENCE
    # END_CONTRACT: build_combos

    Из карточки берутся все сочетания по две части и тройка целиком: этого достаточно, чтобы
    подтвердить любую пару, которую модель может составить законно.
    """
    digests: set[str] = set()
    counters = {"cards": 0, "pairs": 0, "triples": 0, "skipped": 0}
    for parts in records:
        values = [str(part).strip() for part in (parts or []) if str(part or "").strip()]
        if len(values) < MIN_COMBO_PARTS:
            counters["skipped"] += 1
            continue
        counters["cards"] += 1
        found_before = len(digests)
        for index, first in enumerate(values):
            for second in values[index + 1 :]:
                digest = combo_digest(key, [first, second])
                if digest:
                    digests.add(digest)
        triple = combo_digest(key, values[:MAX_COMBO_PARTS])
        if triple:
            digests.add(triple)
            counters["triples"] += 1
        pairs = len(digests) - found_before
        counters["pairs"] += pairs
    return digests, counters
# END_BLOCK_BUILD_COMBOS


# START_BLOCK_LOAD_COHERENCE
@dataclass(frozen=True)
class NameCoherence:
    """Загруженный индекс сочетаний частей ФИО.

    # START_CONTRACT: NameCoherence
    #   PURPOSE: Ответить на один вопрос — «эти части встречались вместе в источнике?».
    #   INPUTS: { digests: set[str] - отпечатки сочетаний, meta: Mapping[str, Any] - происхождение, path: str | None }
    #   OUTPUTS: { NameCoherence - индекс }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETOKENIZER, V-M-NAME-COHERENCE
    # END_CONTRACT: NameCoherence
    """

    digests: frozenset[str]
    meta: Mapping[str, Any] = field(default_factory=dict)
    path: str | None = None

    @property
    def size(self) -> int:
        """Вернуть число сочетаний в индексе."""
        return len(self.digests)

    def confirm(self, key: bytes, parts: Sequence[str]) -> bool:
        """Сказать, встречались ли эти части вместе в источнике.

        # START_CONTRACT: confirm
        #   PURPOSE: Подтвердить сочетание по индексу, а не по догадке.
        #   INPUTS: { key: bytes - ключ отпечатков, parts: Sequence[str] - части ФИО }
        #   OUTPUTS: { bool - True, когда сочетание есть в индексе }
        #   SIDE_EFFECTS: none
        #   LINKS: M-DETOKENIZER, V-M-NAME-COHERENCE
        # END_CONTRACT: confirm
        """
        digest = combo_digest(key, parts)
        return bool(digest) and digest in self.digests

    def snapshot(self) -> dict[str, Any]:
        """Вернуть сводку для healthz: числа и происхождение, без значений."""
        return {
            "combos": self.size,
            "source": str(self.meta.get("source", "")),
            "licence": str(self.meta.get("licence", "")),
            "built_at": str(self.meta.get("built_at", "")),
            "cards": int(self.meta.get("cards") or 0),
        }


def load_name_coherence(path: str | None) -> NameCoherence | None:
    """Прочитать файл индекса сочетаний, или вернуть None, когда он не настроен.

    # START_CONTRACT: load_name_coherence
    #   PURPOSE: Сделать проверку сочетаний включаемой настройкой, но не прощать испорченный файл.
    #   INPUTS: { path: str | None - путь к файлу индекса }
    #   OUTPUTS: { NameCoherence | None - индекс или None }
    #   SIDE_EFFECTS: читает и распаковывает файл
    #   LINKS: M-CONFIG, V-M-NAME-COHERENCE
    # END_CONTRACT: load_name_coherence

    Отличие «не настроено» от «испорчено» принципиально: пустой путь — это выключенная
    возможность (прокси работает как раньше), а нечитаемый файл по заданному пути — отказ
    (CoherenceError), иначе испорченный индекс молча отключил бы заслон.
    """
    if not path:
        return None
    target = Path(path)
    if not target.exists():
        raise CoherenceError("COHERENCE_FILE_MISSING", f"combos index not found: {path}")
    try:
        with gzip.open(target, "rt", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise CoherenceError("COHERENCE_UNREADABLE", f"{path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise CoherenceError("COHERENCE_SHAPE", "combos index root must be an object")
    if int(payload.get("schema") or 0) != COHERENCE_SCHEMA:
        raise CoherenceError("COHERENCE_SCHEMA", f"unsupported schema {payload.get('schema')!r}")
    if not payload.get("keyed"):
        raise CoherenceError(
            "COHERENCE_PLAIN", "combos index must hold keyed digests, readable values are refused"
        )
    raw = payload.get("combos")
    if not isinstance(raw, list):
        raise CoherenceError("COHERENCE_SHAPE", "combos index has no combos list")
    digests = {str(item) for item in raw if str(item).strip()}
    meta_raw = payload.get("meta")
    meta: dict[str, Any] = dict(meta_raw) if isinstance(meta_raw, dict) else {}
    return NameCoherence(digests=frozenset(digests), meta=meta, path=str(target))


def combos_payload(
    digests: Iterable[str],
    meta: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Собрать файл индекса сочетаний: отпечатки плюс происхождение.

    # START_CONTRACT: combos_payload
    #   PURPOSE: Один формат файла на инструмент сборки и на загрузчик.
    #   INPUTS: { digests: Iterable[str] - отпечатки сочетаний, meta: Mapping | None - происхождение }
    #   OUTPUTS: { dict[str, Any] - содержимое файла индекса }
    #   SIDE_EFFECTS: none
    #   LINKS: M-NAME-COHERENCE, V-M-NAME-COHERENCE
    # END_CONTRACT: combos_payload
    """
    source_meta = dict(meta or {})
    source_meta.setdefault("built_at", datetime.now(timezone.utc).isoformat())
    return {
        "schema": COHERENCE_SCHEMA,
        "keyed": True,
        "meta": source_meta,
        "combos": sorted({str(item) for item in digests if str(item).strip()}),
    }


def write_combos(path: str, payload: Mapping[str, Any]) -> int:
    """Записать индекс сочетаний атомарно, с правами 0600.

    # START_CONTRACT: write_combos
    #   PURPOSE: Не оставить рабочий индекс наполовину записанным.
    #   INPUTS: { path: str - целевой путь, payload: Mapping[str, Any] - содержимое }
    #   OUTPUTS: { int - число записанных сочетаний }
    #   SIDE_EFFECTS: пишет файл (staged → os.replace) и ставит права 0600
    #   LINKS: M-NAME-COHERENCE, V-M-NAME-COHERENCE
    # END_CONTRACT: write_combos
    """
    import os
    import tempfile

    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    descriptor, staged = tempfile.mkstemp(prefix=".combos-", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as zipped:
                zipped.write(
                    json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
                )
        os.chmod(staged, 0o600)
        os.replace(staged, path)
    except OSError as exc:
        try:
            os.unlink(staged)
        except OSError:
            pass
        raise CoherenceError("COHERENCE_WRITE_FAILED", f"cannot write {path}: {exc}") from exc
    return len(list(payload.get("combos") or []))
# END_BLOCK_LOAD_COHERENCE
