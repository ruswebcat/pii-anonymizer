# FILE: src/dict_write.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Менять хешированный справочник без риска: собрать staged-файл, проверить его прибором, сделать бэкап живого и заменить атомарно — добавлением или удалением значений.
#   SCOPE: чтение schema 3, отпечатки значений и падежных форм, удаление значений служебной лексики, слияние добавки, staged-запись с правами 0600, проверка прибором через подстановку, бэкап cp -a, атомарная замена, счётчики каждого шага.
#   DEPENDS: M-DICT, M-DICT-EXPORT, M-METRICS
#   LINKS: M-INCIDENT-TRAINER, M-DICT-HYGIENE, V-M-DICT-WRITE, Phase-16
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   DictWriteError - ошибка записи справочника с машинным кодом
#   RemoveStats - счётчики удаления значений
#   AddStats - счётчики добавления значений
#   ApplyResult - итог применения staged-файла к живому
#   fn-load_payload - прочитать справочник
#   fn-remove_values - убрать значения класса вместе с их формо-отпечатками
#   fn-add_values - добавить значения класса с отпечатками форм
#   fn-retotal - пересчитать поле values
#   fn-write_staged - записать staged-файл с правами 0600 атомарно
#   fn-check_staged - прогнать прибор на staged (подстановка прогона для тестов)
#   fn-backup_live - бэкап живого файла со штампом времени
#   fn-install_staged - атомарная замена живого файла
#   fn-apply - staged → проверка → бэкап → замена
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-16: один путь записи справочника для чистки служебной лексики и для недельного тренера. Порядок staged → проверка прибором → бэкап → замена обязателен: чистка 17.09.2026 выбросила 12,9% настоящих значений именно потому, что её никто не измерил перед заменой.
# END_CHANGE_SUMMARY

"""Запись клиентского справочника: staged, проверка, бэкап, замена (M-DICT-WRITE).

Зачем отдельный модуль. Справочник — единственная точка, где ошибка стоит дорого: если
удалить настоящее значение, оно уедет провайдеру открытым текстом, а если добавить служебное
слово, заслон начнёт ложно блокировать работу. Поэтому у любой правки справочника один и тот
же порядок, и он живёт в одном месте, а не в двух инструментах:

1. **staged** — новая версия пишется рядом с живой, права ``0600``, живая не тронута;
2. **проверка** — на staged прогоняется прибор ``tools/quality_metrics.py`` (все планки);
3. **бэкап** — живой файл копируется со штампом времени (``cp -a``, права ``0600``);
4. **замена** — атомарный ``os.replace``; служба подхватывает файл сама по смене подписи
   (mtime + размер), перезапуск не нужен.

Провал проверки не отменяет прогон: staged остаётся на диске для разбора, живой файл не
меняется. Это правило fail-closed, перенесённое на данные.

Значений в файле нет по построению: справочник хранит отпечатки (schema 3), поэтому и
удаление, и добавка работают отпечатками, а не чтением персональных данных.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.dictionary import SCHEMA_FORMS, value_digest
from src.dict_export import to_keyed_digests
from src.normalize import NormalizeError, normalize

DICT_MODE = 0o600
STAMP_FORMAT = "%Y%m%d-%H%M%S"
#: Прибор постоянных метрик — судья любой правки справочника.
METRICS_TOOL = "tools/quality_metrics.py"


class DictWriteError(RuntimeError):
    """Ошибка записи справочника: машинный код плюс пояснение.

    # START_CONTRACT: DictWriteError
    #   PURPOSE: Отличать отказ справочника от отказа логики: у отказа есть код, который видно в отчёте.
    #   INPUTS: { code: str - машинный код, message: str - пояснение }
    #   OUTPUTS: { DictWriteError - исключение }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT-WRITE, V-M-DICT-WRITE
    # END_CONTRACT: DictWriteError
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass
class RemoveStats:
    """Счётчики удаления значений из класса.

    # START_CONTRACT: RemoveStats
    #   PURPOSE: Показать, что именно снято: значения, их отпечатки и отпечатки их падежных форм.
    #   INPUTS: { requested: int - сколько значений просили убрать, removed: int - сколько снято, absent: int - сколько не найдено, form_digests: int - сколько формо-отпечатков снято вместе с ними }
    #   OUTPUTS: { RemoveStats - счётчики }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT-HYGIENE, V-M-DICT-WRITE
    # END_CONTRACT: RemoveStats
    """

    requested: int = 0
    removed: int = 0
    absent: int = 0
    form_digests: int = 0

    def to_dict(self) -> dict[str, int]:
        """Счётчики словарём для отчёта."""
        return {
            "requested": self.requested,
            "removed": self.removed,
            "absent": self.absent,
            "form_digests": self.form_digests,
        }


@dataclass
class AddStats:
    """Счётчики добавления значений в класс.

    # START_CONTRACT: AddStats
    #   PURPOSE: Отделить настоящую добавку от «уже было» и от спорных форм — иначе прирост словаря не отличить от пересчёта.
    #   INPUTS: { requested: int, added: int, already_present: int, form_digests: int, ambiguous_forms: int, rejected: int - значения, которые нормализовать не удалось }
    #   OUTPUTS: { AddStats - счётчики }
    #   SIDE_EFFECTS: none
    #   LINKS: M-INCIDENT-TRAINER, V-M-DICT-WRITE
    # END_CONTRACT: AddStats
    """

    requested: int = 0
    added: int = 0
    already_present: int = 0
    form_digests: int = 0
    ambiguous_forms: int = 0
    rejected: int = 0

    def to_dict(self) -> dict[str, int]:
        """Счётчики словарём для отчёта."""
        return {
            "requested": self.requested,
            "added": self.added,
            "already_present": self.already_present,
            "form_digests": self.form_digests,
            "ambiguous_forms": self.ambiguous_forms,
            "rejected": self.rejected,
        }


@dataclass
class ApplyResult:
    """Итог применения staged-файла к живому справочнику.

    # START_CONTRACT: ApplyResult
    #   PURPOSE: Сказать вызывающему, что произошло с живым файлом: заменён или нет, и почему.
    #   INPUTS: { applied: bool, staged_path: str, backup_path: str, live_path: str, metrics_passed: bool, reason: str, values_before: int, values_after: int }
    #   OUTPUTS: { ApplyResult - итог }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT-WRITE, V-M-DICT-WRITE
    # END_CONTRACT: ApplyResult
    """

    applied: bool = False
    staged_path: str = ""
    backup_path: str = ""
    live_path: str = ""
    metrics_passed: bool = False
    reason: str = ""
    values_before: int = 0
    values_after: int = 0
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Итог словарём для отчёта (без значений, только числа и машинные коды)."""
        return {
            "applied": self.applied,
            "staged_path": self.staged_path,
            "backup_path": self.backup_path,
            "live_path": self.live_path,
            "metrics_passed": self.metrics_passed,
            "reason": self.reason,
            "values_before": self.values_before,
            "values_after": self.values_after,
            "detail": dict(self.detail),
        }


def load_payload(path: str) -> dict[str, Any]:
    """Прочитать справочник целиком.

    # START_CONTRACT: load_payload
    #   PURPOSE: Держать чтение справочника в одном месте, чтобы правки не расходились с форматом.
    #   INPUTS: { path: str - путь к файлу справочника }
    #   OUTPUTS: { dict - payload справочника }
    #   SIDE_EFFECTS: читает файл
    #   LINKS: M-DICT, M-DICT-WRITE, V-M-DICT-WRITE
    # END_CONTRACT: load_payload
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except FileNotFoundError as exc:
        raise DictWriteError("DICT_MISSING", f"dictionary not found: {path}") from exc
    except ValueError as exc:
        raise DictWriteError("DICT_UNREADABLE", f"dictionary is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise DictWriteError("DICT_UNREADABLE", "dictionary payload is not an object")
    if int(payload.get("schema") or 0) < SCHEMA_FORMS:
        raise DictWriteError(
            "DICT_SCHEMA_UNSUPPORTED",
            f"only schema {SCHEMA_FORMS} is written; readable older schemas are not rewritten",
        )
    return payload


def _bucket(payload: Mapping[str, Any], cls: str) -> set[str]:
    """Множество отпечатков класса (живая копия, не ссылка)."""
    digests = payload.get("digests")
    if not isinstance(digests, dict):
        raise DictWriteError("DICT_UNREADABLE", "dictionary has no digests block")
    raw = digests.get(cls)
    if raw is None:
        return set()
    if not isinstance(raw, list):
        raise DictWriteError("DICT_UNREADABLE", f"digests block of class {cls} is not a list")
    return {str(item) for item in raw}


def _forms(payload: Mapping[str, Any], cls: str) -> dict[str, str]:
    """Копия карты формо-отпечатков класса."""
    forms = payload.get("forms")
    if not isinstance(forms, dict):
        return {}
    raw = forms.get(cls)
    if not isinstance(raw, dict):
        return {}
    return {str(key): str(value) for key, value in raw.items()}


def has_value(payload: Mapping[str, Any], key: bytes, cls: str, value: str) -> bool:
    """Сказать, знает ли справочник это написание — по отпечатку, без чтения содержимого.

    # START_CONTRACT: has_value
    #   PURPOSE: Дать тренеру и измерителю ответ «значение уже разрешается кодом» тем же правилом, что у рантайма.
    #   INPUTS: { payload: Mapping - справочник, key: bytes - ключ отпечатков, cls: str - класс, value: str - значение }
    #   OUTPUTS: { bool - True, когда отпечаток есть в классе или в блоке падежных форм }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT-WRITE, M-INCIDENT-TRAINER, M-DICT-HYGIENE, V-M-DICT-WRITE
    # END_CONTRACT: has_value

    Падежные формы проверяются наравне с точными отпечатками: рантайм берёт форму впереди
    точного написания (`identity_digest`), поэтому «этого написания нет в словаре» и «рантайм
    его не знает» — разные утверждения. Второе и есть настоящий вопрос: тренер не должен
    добавлять значение, которое уже получает код персоны-основы.
    """
    normalized = _normalized(cls, value)
    if normalized is None:
        return False
    digest = value_digest(key, cls, normalized)
    if digest in _bucket(payload, cls):
        return True
    return digest in _forms(payload, cls)


def remove_values(
    payload: dict[str, Any],
    key: bytes,
    cls: str,
    values: Sequence[str],
) -> tuple[dict[str, Any], RemoveStats]:
    """Убрать значения класса вместе с их формо-отпечатками.

    # START_CONTRACT: remove_values
    #   PURPOSE: Снять с класса «имена» доказанную служебную лексику, не задев ничего другого.
    #   INPUTS: { payload: dict - справочник, key: bytes - ключ отпечатков, cls: str - класс, values: Sequence[str] - служебные слова }
    #   OUTPUTS: { (dict, RemoveStats) - новый payload и счётчики }
    #   SIDE_EFFECTS: none (payload передаётся и возвращается копией)
    #   LINKS: M-DICT-HYGIENE, M-DICT-WRITE, V-M-DICT-WRITE
    # END_CONTRACT: remove_values

    Значение опознаётся отпечатком, поэтому чтения персональных данных не происходит. Вместе
    с отпечатком значения снимаются **все** формо-отпечатки, которые на него ссылались: иначе
    падежное написание снятого слова осталось бы в словаре и продолжало бы давать код.
    """
    stats = RemoveStats(requested=len(values))
    victim = set()
    for value in values:
        normalized = _normalized(cls, value)
        if normalized is None:
            stats.absent += 1
            continue
        digest = value_digest(key, cls, normalized)
        if digest in _bucket(payload, cls):
            victim.add(digest)
        else:
            stats.absent += 1
    if not victim:
        return payload, stats

    updated = json.loads(json.dumps(payload))
    remaining = _bucket(payload, cls) - victim
    digest_map = updated.setdefault("digests", {})
    digest_map[cls] = sorted(remaining)
    stats.removed = len(victim)

    forms = _forms(payload, cls)
    kept = {
        form: base for form, base in forms.items() if base not in victim and form not in victim
    }
    stats.form_digests = len(forms) - len(kept)
    if kept or "forms" in updated:
        updated.setdefault("forms", {})[cls] = kept
    retotal(updated)
    return updated, stats


def add_values(
    payload: dict[str, Any],
    key: bytes,
    cls: str,
    values: Sequence[str],
) -> tuple[dict[str, Any], AddStats]:
    """Добавить значения класса с отпечатками их падежных форм.

    # START_CONTRACT: add_values
    #   PURPOSE: Прописать в справочник подтверждённое значение так, чтобы все его падежные написания получали один код персоны.
    #   INPUTS: { payload: dict - справочник, key: bytes - ключ отпечатков, cls: str - класс, values: Sequence[str] - подтверждённые значения }
    #   OUTPUTS: { (dict, AddStats) - новый payload и счётчики }
    #   SIDE_EFFECTS: строит падежные формы через M-NAME-FORMS
    #   LINKS: M-INCIDENT-TRAINER, M-DICT-WRITE, M-DICT-EXPORT, V-M-DICT-WRITE
    # END_CONTRACT: add_values

    Формы считает тот же код, что и выгрузка (``to_keyed_digests``), — иначе добавка и полная
    выгрузка давали бы разный словарь. Спорная форма (её отпечаток уже занят другой основой или
    совпал с точным написанием другого значения) **не** добавляется и считается: пусть значение
    останется без этой формы, чем получит чужой код.
    """
    stats = AddStats(requested=len(values))
    accepted: list[str] = []
    for value in values:
        normalized = _normalized(cls, value)
        if normalized is None:
            stats.rejected += 1
            continue
        # Тот же критерий, что и у рантайма (включая блок падежных форм): иначе тренер и
        # запись справочника расходятся — «формы нет, но код она всё равно получает».
        if has_value(payload, key, cls, value):
            stats.already_present += 1
            continue
        accepted.append(value)
    if not accepted:
        return payload, stats

    addition = to_keyed_digests({cls: accepted}, key)
    new_digests = _bucket(addition, cls)
    live = _bucket(payload, cls)
    fresh = new_digests - live
    stats.added = len(fresh)

    updated = json.loads(json.dumps(payload))
    updated.setdefault("digests", {})[cls] = sorted(live | fresh)

    live_forms = _forms(payload, cls)
    new_forms = _forms(addition, cls)
    merged_forms = dict(live_forms)
    for form, base in new_forms.items():
        if base not in fresh:
            continue
        if form in live:
            # Написание совпало с точным значением другого клиента: форма спорна, оставляем как есть.
            stats.ambiguous_forms += 1
            continue
        existing = merged_forms.get(form)
        if existing is not None and existing != base:
            stats.ambiguous_forms += 1
            continue
        if existing is None:
            stats.form_digests += 1
        merged_forms[form] = base
    if merged_forms or "forms" in updated:
        updated.setdefault("forms", {})[cls] = merged_forms
    retotal(updated)
    return updated, stats


def retotal(payload: dict[str, Any]) -> int:
    """Пересчитать поле ``values`` по классам.

    # START_CONTRACT: retotal
    #   PURPOSE: Держать размер справочника честным: служба и healthz читают это число.
    #   INPUTS: { payload: dict - справочник }
    #   OUTPUTS: { int - число значений }
    #   SIDE_EFFECTS: меняет поле values
    #   LINKS: M-DICT-WRITE, V-M-DICT-WRITE
    # END_CONTRACT: retotal
    """
    digests = payload.get("digests") or {}
    total = sum(len(bucket) for bucket in digests.values() if isinstance(bucket, list))
    payload["values"] = int(total)
    return int(total)


def write_staged(payload: Mapping[str, Any], path: str) -> str:
    """Записать staged-файл справочника с правами 0600, атомарно.

    # START_CONTRACT: write_staged
    #   PURPOSE: Получить полную версию новой правки, не тронув живой файл.
    #   INPUTS: { payload: Mapping - справочник, path: str - путь staged-файла }
    #   OUTPUTS: { str - путь staged-файла }
    #   SIDE_EFFECTS: пишет файл и временный файл рядом
    #   LINKS: M-DICT-WRITE, V-M-DICT-WRITE
    # END_CONTRACT: write_staged
    """
    tmp = f"{path}.tmp"
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    try:
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, DICT_MODE)
        os.replace(tmp, path)
    except OSError as exc:
        raise DictWriteError("DICT_WRITE_FAILED", f"cannot write staged: {exc}") from exc
    _harden(path)
    return path


def check_staged(
    staged_path: str,
    key_path: str,
    runner: Callable[[Sequence[str]], tuple[int, str]] | None = None,
    layer_path: str = "",
    python: str | None = None,
) -> tuple[bool, str]:
    """Прогнать прибор постоянных метрик на staged-файле.

    # START_CONTRACT: check_staged
    #   PURPOSE: Проверять правку словаря до замены, а не после: чистка без замера уже уронила обезличивание до 73%.
    #   INPUTS: { staged_path: str, key_path: str, runner: Callable | None - подстановка прогона, layer_path: str - открытый слой для контура, python: str | None - интерпретатор }
    #   OUTPUTS: { (bool, str) - выдержаны ли планки и вывод прибора }
    #   SIDE_EFFECTS: запускает прибор (подпроцесс или подстановку)
    #   LINKS: M-METRICS, M-DICT-WRITE, V-M-DICT-WRITE
    # END_CONTRACT: check_staged

    Планки и их обоснование живут в приборе (``docs/ARCHITECTURE.md``), здесь только вызов:
    второй критерий «что считать просадкой» разошёлся бы с первым. Контур назван явно
    (``--dict-file`` — настоящий справочник), иначе зелёный синтетический прогон ничего не
    говорит о живых данных.
    """
    argv = [python or sys.executable, METRICS_TOOL, "--dict-file", staged_path, "--dict-key-file", key_path]
    if layer_path:
        argv += ["--name-layer", layer_path]
    argv.append("--quiet")
    if runner is not None:
        try:
            code, output = runner(argv)
        except Exception as exc:  # noqa: BLE001 - сбой проверки трактуется как «не выдержаны»
            return False, f"METRICS_RUNNER_FAILED:{exc.__class__.__name__}"
        return code == 0, output
    try:
        done = subprocess.run(
            argv,
            cwd=str(Path(METRICS_TOOL).resolve().parent.parent),
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DictWriteError("METRICS_UNAVAILABLE", f"cannot run quality metrics: {exc}") from exc
    output = (done.stdout or "") + (done.stderr or "")
    return done.returncode == 0, output


def backup_live(path: str, stamp: str | None = None) -> str:
    """Сделать бэкап живого справочника со штампом времени.

    # START_CONTRACT: backup_live
    #   PURPOSE: Оставить возможность отката одной командой — это условие любой правки боевого словаря.
    #   INPUTS: { path: str - живой файл, stamp: str | None - штамп времени }
    #   OUTPUTS: { str - путь бэкапа }
    #   SIDE_EFFECTS: копирует файл, ставит права 0600
    #   LINKS: M-DICT-WRITE, V-M-DICT-WRITE
    # END_CONTRACT: backup_live
    """
    marker = stamp or time.strftime(STAMP_FORMAT, time.gmtime())
    target = f"{path}.bak-{marker}"
    try:
        shutil.copy2(path, target)
    except OSError as exc:
        raise DictWriteError("DICT_BACKUP_FAILED", f"cannot back up dictionary: {exc}") from exc
    _harden(target)
    return target


def install_staged(staged_path: str, live_path: str) -> str:
    """Заменить живой справочник staged-файлом атомарно.

    # START_CONTRACT: install_staged
    #   PURPOSE: Заменить файл одним движением, чтобы служба никогда не увидела полузапись.
    #   INPUTS: { staged_path: str, live_path: str }
    #   OUTPUTS: { str - путь живого файла }
    #   SIDE_EFFECTS: переименовывает файл
    #   LINKS: M-DICT-WRITE, V-M-DICT-WRITE
    # END_CONTRACT: install_staged
    """
    try:
        os.replace(staged_path, live_path)
    except OSError as exc:
        raise DictWriteError("DICT_INSTALL_FAILED", f"cannot install staged dictionary: {exc}") from exc
    _harden(live_path)
    return live_path


def apply(
    live_path: str,
    payload: Mapping[str, Any],
    key_path: str,
    staged_path: str | None = None,
    runner: Callable[[Sequence[str]], tuple[int, str]] | None = None,
    layer_path: str = "",
    stamp: str | None = None,
    allow_backup: bool = True,
) -> ApplyResult:
    """Провести правку справочника целиком: staged → проверка → бэкап → замена.

    # START_CONTRACT: apply
    #   PURPOSE: Дать один вход для чистки и для тренера, чтобы порядок шагов нельзя было переставить.
    #   INPUTS: { live_path: str, payload: Mapping - новая версия, key_path: str, staged_path: str | None, runner: Callable | None - подстановка прибора, layer_path: str, stamp: str | None, allow_backup: bool }
    #   OUTPUTS: { ApplyResult - заменён ли живой файл и почему }
    #   SIDE_EFFECTS: пишет staged, запускает прибор, копирует бэкап, заменяет живой файл
    #   LINKS: M-DICT-WRITE, M-INCIDENT-TRAINER, M-DICT-HYGIENE, V-M-DICT-WRITE
    # END_CONTRACT: apply

    Провал проверки — не ошибка прогона, а решение «живой словарь не меняем»: staged остаётся
    на диске, бэкап не нужен, потому что замены не было. Так же ведёт себя отказ бэкапа: без
    бэкапа замены не делаем.
    """
    staged = staged_path or f"{live_path}.staged-{time.strftime('%Y%m%d', time.gmtime())}"
    result = ApplyResult(staged_path=staged, live_path=live_path)
    before = 0
    try:
        before = int(load_payload(live_path).get("values") or 0)
    except DictWriteError:
        before = 0
    result.values_before = before

    write_staged(payload, staged)
    passed, output = check_staged(staged, key_path, runner=runner, layer_path=layer_path)
    result.metrics_passed = passed
    result.values_after = int(payload.get("values") or 0)
    result.detail["metrics_tail"] = _tail(output)
    if not passed:
        result.reason = "metrics_not_passed"
        return result
    if allow_backup:
        result.backup_path = backup_live(live_path, stamp=stamp)
    install_staged(staged, live_path)
    result.applied = True
    result.reason = "applied"
    return result


def _normalized(cls: str, value: str) -> str | None:
    """Нормализовать значение для отпечатка; None, когда нормализация невозможна."""
    try:
        normalized = normalize(cls, value)
    except NormalizeError:
        return None
    return normalized or None


def _tail(text: str, limit: int = 400) -> str:
    """Хвост вывода прибора: числа и вердикт, без персональных данных."""
    body = (text or "").strip()
    return body[-limit:]


def _harden(path: str) -> None:
    """Поставить права 0600 на файл справочника."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover - filesystem dependent
        pass
