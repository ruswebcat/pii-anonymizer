# FILE: tools/incident_trainer.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Раз в неделю превращать промахи заслона в пополнение справочника: прочитать инциденты за неделю, взять значения с пометкой «из инцидента», подтвердить их морфологией и NER-моделью, добавить подтверждённое через staged → проверка → бэкап → замена, спорное отдать файлом-предложением без ПД, а отчёт — цифрами.
#   SCOPE: чтение журнала инцидентов и шифрованного справочника соответствий, подтверждение двумя независимыми источниками, жёсткий недельный лимит 50 значений, файл-предложение без ПД, отчёт числами в JSON и markdown, отправка отчёта владельцу в личку Mattermost внутренним REST-постом, режим --dry-run без единой записи.
#   DEPENDS: M-INCIDENT-JOURNAL, M-MAP-STORE, M-DICT, M-DICT-WRITE, M-DETECT-NAME, M-DETECT-NER, M-NER-TRAINER, M-METRICS, M-NAME-LAYER
#   LINKS: M-INCIDENT-TRAINER, V-M-INCIDENT-TRAINER, Phase-15, docs/ARCHITECTURE.md
#   ROLE: SCRIPT
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   DEFAULTS - пути боевого контура по умолчанию (перекрываются ключами CLI)
#   DEFAULT_LIMIT - недельный лимит добавки, 50 значений
#   TrainerError - ошибка прогона с машинным кодом
#   Candidate - значение-претендент с подтверждениями (в отчёт не попадает)
#   TrainerReport - отчёт прогона: только числа и машинные коды
#   fn-morphology_confirms - подтверждение морфологией тем же критерием, что у заслона
#   fn-ner_confirms - подтверждение NER-моделью
#   fn-split_candidates - разделить претендентов на подтверждённых и спорных со счётчиками
#   fn-sessions_in_week - знаменатель доли инцидентов по журналу аудита
#   fn-run_week - прогон недели: журнал → подтверждение → справочник → отчёт
#   fn-render_report - отчёт цифрами для владельца
#   fn-render_proposal - файл-предложение без персональных данных
#   fn-post_to_mattermost - внутренний REST-пост личным сообщением
#   fn-main - точка входа CLI
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-15 шаг 3: недельный тренер словаря по инцидентам (решение владельца 19.09.2026, docs/ARCHITECTURE.md). Ни одной языковой модели: подтверждение — морфология и NER-модель локально, отчёт — цифрами, доставка — REST-пост владельцу.
# END_CHANGE_SUMMARY

"""Недельный тренер словаря по инцидентам (M-INCIDENT-TRAINER, Phase-15 шаг 3).

Контур целиком: **промах → запись без значений → разбор → подтверждение → словарь**.

Что читает. Журнал инцидентов за неделю (файл ``incidents-YYYY-WW.jsonl``: класс, действие,
код, счётчики, правило — без значений) и шифрованный справочник соответствий: значения,
помеченные «из инцидента» (пометку ставит журнал в момент инцидента, `M-INCIDENT-JOURNAL`).

Как подтверждает. Двумя независимыми источниками, и оба локальные:

* **морфология** (`pymorphy3`) — тем же критерием, что и рантайм (`is_person_name`), чтобы
  тренер и заслон не расходились в том, что считать именем;
* **NER-модель** из ``~/.local/state/pii-proxy/ner/`` — локальный инференс ONNX;
  языковая модель в прогоне не участвует вовсе (это условие владельца: 0 токенов).

Подтверждено — попадает в справочник. Не подтверждено, подтверждено частично, превысило
лимит, относится к не-именному классу или является нашей служебной лексикой — уходит в
**спорное**: файл-предложение со счётчиками и причинами, без значений. Значение никогда не
отбрасывается молча — иначе один и тот же промах возвращался бы каждую неделю.

Чего тренер не делает. Не ослабляет fail-closed, не трогает конфиг Mattermost, не
перезапускает службу (справочник подхватывается сам по смене подписи файла), не печатает
значений и не пишет их ни в отчёт, ни в журнал, ни в файл-предложение.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # pragma: no cover - script bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from src import dict_write  # noqa: E402
from src.detect_name import is_person_name, own_lexicon_ok  # noqa: E402
from src.incident_journal import INCIDENT_SOURCE, IncidentJournal  # noqa: E402
from src.map_store import TokenMapStore  # noqa: E402
from tools.ner_trainer import PERSON_TYPES, load_ner  # noqa: E402

STATE_DIR = "/var/lib/pii-proxy"
PROFILE_ENV = "~/.config/pii-proxy/agent.env"
#: Пути боевого контура; каждый перекрывается ключом CLI (тесты не касаются живого файла).
DEFAULTS: dict[str, str] = {
    "dict": os.path.join(STATE_DIR, "pii_dict.json"),
    "dict_key": os.path.join(STATE_DIR, "dict.key"),
    "map_db": os.path.join(STATE_DIR, "pii_map.db"),
    "fernet_key": os.path.join(STATE_DIR, "fernet.key"),
    "incidents": os.path.join(STATE_DIR, "log", "incidents"),
    "audit": os.path.join(STATE_DIR, "log", "audit.jsonl"),
    "layer": os.path.join(STATE_DIR, "name_layer.json.gz"),
    "ner": os.path.join(STATE_DIR, "ner"),
    "report": os.path.join(STATE_DIR, "incident_report.json"),
    "proposal": os.path.join(STATE_DIR, "reports", "PROPOSAL-incident-dictionary.md"),
}
#: Жёсткий недельный лимит добавки (решение владельца, docs/ARCHITECTURE.md).
DEFAULT_LIMIT = 50
#: Класс «имена» — единственный, который тренер подтверждает морфологией и NER.
TRAINED_CLASS = "P"
MM_API_SUFFIX = "/api/v4"

LOGGER_NAME = "IncidentTrainer"


class TrainerError(RuntimeError):
    """Ошибка прогона тренера: машинный код плюс пояснение.

    # START_CONTRACT: TrainerError
    #   PURPOSE: Отличать «нет данных» от «сломалось»: пустой журнал ошибкой не является.
    #   INPUTS: { code: str - машинный код, message: str - пояснение }
    #   OUTPUTS: { TrainerError - исключение }
    #   SIDE_EFFECTS: none
    #   LINKS: M-INCIDENT-TRAINER, V-M-INCIDENT-TRAINER
    # END_CONTRACT: TrainerError
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Candidate:
    """Значение-претендент и его подтверждения.

    # START_CONTRACT: Candidate
    #   PURPOSE: Держать значение и подтверждения рядом в памяти прогона, не отдавая значение ни в отчёт, ни в журнал.
    #   INPUTS: { value: str - значение (только в памяти), cls: str - класс, token: str - код связки, reasons: tuple[str, ...] - подтверждения }
    #   OUTPUTS: { Candidate - претендент }
    #   SIDE_EFFECTS: none
    #   LINKS: M-INCIDENT-TRAINER, V-M-INCIDENT-TRAINER
    # END_CONTRACT: Candidate
    """

    value: str
    cls: str
    token: str = ""
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def __repr__(self) -> str:  # pragma: no cover - защита от случайной печати
        """Никогда не печатать значение: даже repr безопасен."""
        return f"Candidate(cls={self.cls!r}, value=<скрыто>, reasons={len(self.reasons)})"


@dataclass
class TrainerReport:
    """Отчёт недельного прогона: числа, классы и машинные коды.

    # START_CONTRACT: TrainerReport
    #   PURPOSE: Дать владельцу числа по контуру и ничего, кроме чисел: отчёт уходит в личку и в журнал крона.
    #   INPUTS: { поля-счётчики прогона }
    #   OUTPUTS: { TrainerReport - отчёт }
    #   SIDE_EFFECTS: none
    #   LINKS: M-INCIDENT-TRAINER, V-M-INCIDENT-TRAINER
    # END_CONTRACT: TrainerReport
    """

    week: str = ""
    week_start: str = ""
    week_end: str = ""
    dry_run: bool = False
    limit: int = DEFAULT_LIMIT
    incidents_total: int = 0
    incidents_by_class: dict[str, int] = field(default_factory=dict)
    incidents_by_action: dict[str, int] = field(default_factory=dict)
    incidents_by_channel: dict[str, int] = field(default_factory=dict)
    incidents_findings: int = 0
    incidents_replacements: int = 0
    unwritten_incidents: int = 0
    sessions_in_period: int = 0
    incident_share: float = 0.0
    incident_values_total: int = 0
    incident_value_classes: dict[str, int] = field(default_factory=dict)
    confirmed_morphology: int = 0
    confirmed_ner: int = 0
    confirmed_both: int = 0
    confirmed_total: int = 0
    already_known: int = 0
    service_lexicon: int = 0
    rejected_form: int = 0
    ner_available: bool = False
    disputed_total: int = 0
    disputed_by_reason: dict[str, int] = field(default_factory=dict)
    over_limit: int = 0
    applied: int = 0
    dictionary_values_before: int = 0
    dictionary_values_after: int = 0
    dictionary_names_before: int = 0
    dictionary_names_after: int = 0
    metrics_passed: bool = False
    apply_reason: str = ""
    staged_path: str = ""
    backup_path: str = ""
    proposal_path: str = ""
    report_path: str = ""
    delivery: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Отчёт словарём — то, что уходит в файл и в личку владельцу."""
        return {
            "week": self.week,
            "week_start": self.week_start,
            "week_end": self.week_end,
            "dry_run": self.dry_run,
            "limit": self.limit,
            "incidents": {
                "total": self.incidents_total,
                "by_class": self.incidents_by_class,
                "by_action": self.incidents_by_action,
                "by_channel": self.incidents_by_channel,
                "findings": self.incidents_findings,
                "replacements": self.incidents_replacements,
                "unwritten": self.unwritten_incidents,
                "sessions_in_period": self.sessions_in_period,
                "share": round(self.incident_share, 6),
            },
            "incident_values": {
                "total": self.incident_values_total,
                "by_class": self.incident_value_classes,
            },
            "confirmation": {
                "morphology": self.confirmed_morphology,
                "ner": self.confirmed_ner,
                "both": self.confirmed_both,
                "total": self.confirmed_total,
                "ner_available": self.ner_available,
                "already_known": self.already_known,
                "service_lexicon": self.service_lexicon,
                "rejected_form": self.rejected_form,
            },
            "disputed": {
                "total": self.disputed_total,
                "over_limit": self.over_limit,
                "by_reason": self.disputed_by_reason,
            },
            "dictionary": {
                "applied": self.applied,
                "values_before": self.dictionary_values_before,
                "values_after": self.dictionary_values_after,
                "names_before": self.dictionary_names_before,
                "names_after": self.dictionary_names_after,
                "metrics_passed": self.metrics_passed,
                "apply_reason": self.apply_reason,
                "staged_path": self.staged_path,
                "backup_path": self.backup_path,
            },
            "files": {"report": self.report_path, "proposal": self.proposal_path},
            "delivery": dict(self.delivery),
        }


def _person_label(label: str) -> bool:
    """Сказать, относится ли метка модели к человеку."""
    return label.split("-")[-1].upper() in PERSON_TYPES


def morphology_confirms(value: str) -> bool:
    """Подтвердить значение морфологией — тем же критерием, что у заслона.

    # START_CONTRACT: morphology_confirms
    #   PURPOSE: Не заводить второй критерий «это имя»: тренер обязан видеть имя так же, как заслон.
    #   INPUTS: { value: str - значение }
    #   OUTPUTS: { bool - True, когда значение может быть именем }
    #   SIDE_EFFECTS: лениво строит морфологический анализатор
    #   LINKS: M-DETECT-NAME, M-INCIDENT-TRAINER, V-M-INCIDENT-TRAINER
    # END_CONTRACT: morphology_confirms
    """
    return bool(is_person_name(value))


def ner_confirms(value: str, annotate: Callable[[Sequence[str]], list[list[tuple[int, int, str]]]] | None) -> bool:
    """Подтвердить значение NER-моделью.

    # START_CONTRACT: ner_confirms
    #   PURPOSE: Второй независимый источник: модель видит имена там, где наша морфология молчит (нерусские и редкие фамилии).
    #   INPUTS: { value: str - значение, annotate: Callable | None - разметчик модели }
    #   OUTPUTS: { bool - True, когда модель разметила значение как человека }
    #   SIDE_EFFECTS: инференс модели
    #   LINKS: M-DETECT-NER, M-NER-TRAINER, M-INCIDENT-TRAINER
    # END_CONTRACT: ner_confirms

    Модель обязана разметить **всё** значение целиком, а не кусок: иначе «Гость Иванов»
    подтверждался бы по одному слову, и в справочник уехала бы служебная лексика.
    """
    if annotate is None or not value.strip():
        return False
    try:
        spans = annotate([value])[0]
    except Exception:  # noqa: BLE001 - сбой модели не должен ломать прогон
        return False
    covered = 0
    for start, end, label in spans:
        if not _person_label(label):
            continue
        if value[start:end].strip() and start <= covered:
            covered = max(covered, end)
    return covered >= len(value.strip())


def unique_values(rows: Iterable[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    """Убрать повторы значений, сохранив порядок и первый код связки.

    # START_CONTRACT: unique_values
    #   PURPOSE: Одно значение — один претендент: повторные вхождения давали бы лишние записи в лимите.
    #   INPUTS: { rows: Iterable[tuple[str, str, str]] - (код, класс, значение) }
    #   OUTPUTS: { list[tuple[str, str, str]] - без повторов по нормализованному значению }
    #   SIDE_EFFECTS: none
    #   LINKS: M-INCIDENT-TRAINER, V-M-INCIDENT-TRAINER
    # END_CONTRACT: unique_values
    """
    seen: set[str] = set()
    out: list[tuple[str, str, str]] = []
    for token, cls, value in rows:
        text = str(value or "").strip()
        if not text:
            continue
        marker = f"{cls}:{text.casefold()}"
        if marker in seen:
            continue
        seen.add(marker)
        out.append((str(token), str(cls), text))
    return out


def split_candidates(
    rows: Sequence[tuple[str, str, str]],
    payload: Mapping[str, Any],
    key: bytes,
    annotate: Callable[[Sequence[str]], list[list[tuple[int, int, str]]]] | None,
    report: TrainerReport,
    limit: int = DEFAULT_LIMIT,
) -> tuple[list[Candidate], dict[str, int]]:
    """Разделить претендентов на подтверждённых и спорных со счётчиками.

    # START_CONTRACT: split_candidates
    #   PURPOSE: Применить все правила допуска в одном месте, чтобы ни одно спорное значение не пропало молча.
    #   INPUTS: { rows: Sequence[tuple[str, str, str]] - значения из инцидентов, payload: Mapping - справочник, key: bytes - ключ, annotate: Callable | None - разметчик NER, report: TrainerReport - счётчики, limit: int - лимит добавки }
    #   OUTPUTS: { (list[Candidate], dict[str, int]) - подтверждённые в пределах лимита и счётчики спорного по причинам }
    #   SIDE_EFFECTS: мутирует счётчики отчёта
    # END_CONTRACT: split_candidates

    Порядок правил задан дороговизной ошибки, а не удобством кода. Служебная лексика и уже
    известное значение отсеиваются **до** подтверждения: подтверждать их незачем, а попасть в
    справочник им нельзя — именно они дают ложные замены (замер 19.09.2026: 59,5% значений
    класса «имена» в выгрузке именами не являются). Дальше — подтверждение двумя источниками,
    и только потом лимит: сверх лимита значение переносится в спорное, а не отбрасывается.
    """
    accepted: list[Candidate] = []
    disputes: dict[str, int] = {}

    def dispute(reason: str) -> None:
        disputes[reason] = disputes.get(reason, 0) + 1

    for token, cls, value in rows:
        report.incident_values_total += 1
        report.incident_value_classes[cls] = report.incident_value_classes.get(cls, 0) + 1
        if cls != TRAINED_CLASS:
            dispute("class_not_trained")
            continue
        if not own_lexicon_ok(value):
            report.service_lexicon += 1
            dispute("service_lexicon")
            continue
        if dict_write.has_value(payload, key, cls, value):
            report.already_known += 1
            dispute("already_known")
            continue
        by_morph = morphology_confirms(value)
        by_ner = ner_confirms(value, annotate)
        if by_morph:
            report.confirmed_morphology += 1
        if by_ner:
            report.confirmed_ner += 1
        if by_morph and by_ner:
            report.confirmed_both += 1
        if not (by_morph and by_ner):
            reason = "ner_unavailable" if annotate is None else "unconfirmed"
            dispute(reason)
            continue
        report.confirmed_total += 1
        if len(accepted) >= max(0, limit):
            report.over_limit += 1
            dispute("over_limit")
            continue
        accepted.append(
            Candidate(value=value, cls=cls, token=token, reasons=("морфология", "NER"))
        )
    report.disputed_by_reason = disputes
    report.disputed_total = sum(disputes.values())
    return accepted, disputes


def sessions_in_week(path: str, since: float, until: float) -> int:
    """Посчитать сессии журнала аудита за промежуток — знаменатель доли инцидентов.

    # START_CONTRACT: sessions_in_week
    #   PURPOSE: Дать доле инцидентов честный знаменатель и не выдумывать счётчик, которого нет.
    #   INPUTS: { path: str - журнал аудита, since/until: float - границы недели }
    #   OUTPUTS: { int - число разных сессий за неделю }
    #   SIDE_EFFECTS: читает журнал аудита
    #   LINKS: M-AUDIT, M-INCIDENT-TRAINER, V-M-INCIDENT-TRAINER
    # END_CONTRACT: sessions_in_week

    Точного счётчика запросов журнал аудита не ведёт (запрос и обезличивание видны разными
    событиями), поэтому знаменатель — число **разных сессий** за неделю. Это ограничение
    называется в отчёте прямым текстом: доля инцидентов считается как «инциденты на сессию»,
    а не как доля запросов, и подмена одного другим запрещена.
    """
    seen: set[str] = set()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(payload, dict):
                    continue
                moment = payload.get("ts")
                if not isinstance(moment, (int, float)):
                    continue
                if not (since <= float(moment) <= until):
                    continue
                session = str(payload.get("session_id") or "")
                if session:
                    seen.add(session)
    except OSError:
        return 0
    return len(seen)


def run_week(
    week: str = "previous",
    limit: int = DEFAULT_LIMIT,
    paths: Mapping[str, str] | None = None,
    dry_run: bool = False,
    annotate: Callable[[Sequence[str]], list[list[tuple[int, int, str]]]] | None = None,
    metrics_runner: Callable[[Sequence[str]], tuple[int, str]] | None = None,
    now: float | None = None,
    layer: Any | None = None,
    journal: IncidentJournal | None = None,
    store: TokenMapStore | None = None,
    report: TrainerReport | None = None,
) -> TrainerReport:
    """Провести недельный прогон: журнал → подтверждение → справочник → отчёт.

    # START_CONTRACT: run_week
    #   PURPOSE: Собрать весь контур тренера в одной функции, чтобы CLI, тесты и крон гоняли одно и то же.
    #   INPUTS: { week: str, limit: int, paths: Mapping | None, dry_run: bool, annotate: Callable | None, metrics_runner: Callable | None, now: float | None, layer: Any | None, journal/store/report - подстановки для тестов }
    #   OUTPUTS: { TrainerReport - отчёт }
    #   SIDE_EFFECTS: читает журналы и справочники, при обычном прогоне пишет staged, бэкап, отчёт и файл-предложение
    #   LINKS: M-INCIDENT-TRAINER, M-INCIDENT-JOURNAL, M-MAP-STORE, M-DICT-WRITE, V-M-INCIDENT-TRAINER
    # END_CONTRACT: run_week

    Про пустой журнал: неделя без инцидентов — **нормальный** результат, а не ошибка. Отчёт
    приходит с нулями и словом «инцидентов нет», справочник не трогается вовсе. Отсутствие
    NER-модели — тоже не отказ: подтверждений меньше, всё неподтверждённое уходит в спорное,
    прогон завершается успешно.
    """
    report = report or TrainerReport(week=str(week), limit=int(limit), dry_run=bool(dry_run))
    resolved = dict(DEFAULTS)
    resolved.update({k: v for k, v in (paths or {}).items() if v})
    reference = float(now if now is not None else time.time())
    journal = journal or IncidentJournal(resolved["incidents"], clock=lambda: reference)
    week_key = journal.week_key(reference - 7 * 86400) if str(week).lower() in {
        "previous",
        "prev",
        "past",
    } else str(week)
    if str(week).lower() in {"current", "now", "this"}:
        week_key = journal.week_key(reference)
    report.week = week_key
    start, end = _week_bounds(week_key, reference)
    report.week_start = _iso(start)
    report.week_end = _iso(end)

    records = journal.read_week(week)
    counts = journal.counts(records)
    report.incidents_total = int(counts.get("total") or 0)
    report.incidents_by_class = _int_map(counts.get("by_class"))
    report.incidents_by_action = _int_map(counts.get("by_action"))
    report.incidents_by_channel = _int_map(counts.get("by_channel"))
    report.incidents_findings = int(counts.get("findings") or 0)
    report.incidents_replacements = int(counts.get("replacements") or 0)
    report.unwritten_incidents = int(journal.unwritten)
    report.sessions_in_period = sessions_in_week(resolved["audit"], start, end)
    report.incident_share = (
        report.incidents_total / report.sessions_in_period if report.sessions_in_period else 0.0
    )

    payload = dict_write.load_payload(resolved["dict"])
    key = _read_key(resolved["dict_key"])
    report.dictionary_values_before = int(payload.get("values") or 0)
    report.dictionary_names_before = _names_len(payload)

    annotated = annotate
    if annotated is None:
        loaded = load_ner(resolved["ner"])
        annotated = loaded
    report.ner_available = annotated is not None

    rows: list[tuple[str, str, str]] = []
    if store is not None:
        rows = store.values_by_source(INCIDENT_SOURCE, since=start, until=end)
    else:
        rows = _read_incident_values(resolved, INCIDENT_SOURCE, start, end)
    rows = unique_values(rows)

    accepted, _ = split_candidates(rows, payload, key, annotated, report, limit=limit)
    if accepted:
        updated, add_stats = dict_write.add_values(
            payload, key, TRAINED_CLASS, [item.value for item in accepted]
        )
        report.dictionary_values_after = int(updated.get("values") or 0)
        report.dictionary_names_after = _names_len(updated)
        if dry_run:
            report.apply_reason = "dry_run"
            report.applied = 0
        else:
            result = dict_write.apply(
                resolved["dict"],
                updated,
                resolved["dict_key"],
                runner=metrics_runner,
                layer_path=resolved.get("layer", ""),
            )
            report.metrics_passed = bool(result.metrics_passed)
            report.apply_reason = result.reason
            report.staged_path = result.staged_path
            report.backup_path = result.backup_path
            report.applied = int(add_stats.added) if result.applied else 0
            if result.applied:
                report.dictionary_values_after = int(result.values_after)
            else:
                report.dictionary_names_after = report.dictionary_names_before
                report.dictionary_values_after = report.dictionary_values_before
    else:
        report.dictionary_values_after = report.dictionary_values_before
        report.dictionary_names_after = report.dictionary_names_before
        report.metrics_passed = True
        report.apply_reason = "dry_run" if dry_run else "nothing_confirmed"
    return report


def _read_incident_values(
    resolved: Mapping[str, str], source: str, since: float, until: float
) -> list[tuple[str, str, str]]:
    """Прочитать значения источника из шифрованного справочника соответствий."""
    key = Path(resolved["fernet_key"]).read_bytes().strip()
    store = TokenMapStore(resolved["map_db"], key)
    try:
        return store.values_by_source(source, since=since, until=until)
    finally:
        store.close()


def _names_len(payload: Mapping[str, Any]) -> int:
    """Число значений в классе «имена»."""
    digests = payload.get("digests") or {}
    bucket = digests.get(TRAINED_CLASS) if isinstance(digests, Mapping) else None
    return len(bucket) if isinstance(bucket, list) else 0


def _week_bounds(week_key: str, reference: float) -> tuple[float, float]:
    """Границы недели YYYY-WW: понедельник 00:00 UTC и следующий понедельник."""
    try:
        year, number = str(week_key).split("-")
        monday = datetime.datetime.fromisoformat(
            f"{int(year):04d}-01-04T00:00:00+00:00"
        ) - datetime.timedelta(days=datetime.date(int(year), 1, 4).isoweekday() - 1)
        start = monday + datetime.timedelta(weeks=int(number) - 1)
    except (TypeError, ValueError):
        start = datetime.datetime.fromtimestamp(reference, datetime.timezone.utc) - datetime.timedelta(
            days=7
        )
    return start.timestamp(), (start + datetime.timedelta(days=7)).timestamp()


def _iso(moment: float) -> str:
    """Время в ISO 8601 (UTC)."""
    return datetime.datetime.fromtimestamp(moment, datetime.timezone.utc).isoformat(timespec="seconds")


def _int_map(raw: Any) -> dict[str, int]:
    """Привести счётчики по ключам к словарю чисел."""
    if not isinstance(raw, Mapping):
        return {}
    return {str(key): int(value) for key, value in raw.items()}


def render_report(report: TrainerReport) -> str:
    """Оформить недельный отчёт цифрами.

    # START_CONTRACT: render_report
    #   PURPOSE: Отдать владельцу отчёт, который читается без контекста: инциденты, подтверждения, добавка, спорное.
    #   INPUTS: { report: TrainerReport }
    #   OUTPUTS: { str - markdown }
    #   SIDE_EFFECTS: none
    #   LINKS: M-INCIDENT-TRAINER, V-M-INCIDENT-TRAINER
    # END_CONTRACT: render_report
    """
    share = (
        f"{report.incident_share:.4f} на сессию"
        if report.sessions_in_period
        else "нет данных о сессиях"
    )
    mode = "прогон без изменений (dry-run)" if report.dry_run else "боевой прогон"
    lines = [
        "## Тренер словаря по инцидентам — недельный отчёт",
        "",
        f"Неделя: **{report.week}** ({report.week_start} → {report.week_end}), режим: {mode}.",
        "",
        "### Инциденты",
        "",
        "| Показатель | Значение |",
        "|---|---|",
        f"| Инцидентов за неделю | {report.incidents_total} |",
        f"| Находок заслона | {report.incidents_findings} |",
        f"| Замен вторым проходом | {report.incidents_replacements} |",
        f"| Незаписанных инцидентов | {report.unwritten_incidents} |",
        f"| Сессий за неделю | {report.sessions_in_period} |",
        f"| Доля инцидентов | {share} |",
        f"| Классы инцидентов | {_render_map(report.incidents_by_class)} |",
        f"| Действия | {_render_map(report.incidents_by_action)} |",
        f"| Каналы | {_render_map(report.incidents_by_channel)} |",
        "",
        "### Значения из инцидентов",
        "",
        "| Показатель | Значение |",
        "|---|---|",
        f"| Значений с пометкой «из инцидента» | {report.incident_values_total} |",
        f"| По классам | {_render_map(report.incident_value_classes)} |",
        f"| Подтверждено морфологией | {report.confirmed_morphology} |",
        f"| Подтверждено NER | {report.confirmed_ner} |",
        f"| Подтверждено обоими источниками | {report.confirmed_both} |",
        f"| NER-модель доступна | {'да' if report.ner_available else 'нет'} |",
        f"| Уже было в справочнике | {report.already_known} |",
        f"| Служебная лексика (стоп-лист) | {report.service_lexicon} |",
        f"| Лимит на неделю | {report.limit} |",
        f"| Сверх лимита | {report.over_limit} |",
        "",
        "### Справочник",
        "",
        "| Показатель | До | После |",
        "|---|---|---|",
        f"| Значений всего | {report.dictionary_values_before} | {report.dictionary_values_after} |",
        f"| Значений класса «имена» | {report.dictionary_names_before} | {report.dictionary_names_after} |",
        "",
        f"| Добавлено значений | **{report.applied}** |",
        f"| Прибор на staged | {_render_metrics(report)} |",
        f"| Итог применения | {report.apply_reason} |",
        "",
        "### Спорное (без значений)",
        "",
        f"Всего спорных: **{report.disputed_total}**.",
        "",
        _render_disputes(report.disputed_by_reason),
        "",
        "Значений клиентов в отчёте нет: только числа, классы и машинные коды.",
        "",
    ]
    if report.staged_path:
        lines.append(f"staged: `{report.staged_path}`")
    if report.backup_path:
        lines.append(f"бэкап: `{report.backup_path}`")
    if report.proposal_path and not report.dry_run:
        lines.append(f"файл-предложение: `{report.proposal_path}`")
    return "\n".join(lines)


def render_proposal(report: TrainerReport) -> str:
    """Оформить файл-предложение для владельца: только счётчики и причины.

    # START_CONTRACT: render_proposal
    #   PURPOSE: Показать спорное, не показывая ни одного значения: файл лежит рядом с отчётами и может уехать куда угодно.
    #   INPUTS: { report: TrainerReport }
    #   OUTPUTS: { str - markdown без персональных данных }
    #   SIDE_EFFECTS: none
    #   LINKS: M-INCIDENT-TRAINER, V-M-INCIDENT-TRAINER
    # END_CONTRACT: render_proposal
    """
    lines = [
        "# Предложение по справочнику: значения из инцидентов без подтверждения",
        "",
        f"Неделя {report.week}. Значений клиентов в файле нет по построению: только счётчики,",
        "классы и причины. Значение не добавлено в справочник, если оно не подтверждено обоими",
        "источниками (морфология и NER-модель), либо превысило недельный лимит.",
        "",
        "| Причина | Значений | Что это значит |",
        "|---|---|---|",
    ]
    meaning = {
        "ner_unavailable": "NER-модель недоступна — подтвердить нечем",
        "unconfirmed": "второй источник не подтвердил значение",
        "over_limit": "подтверждено, но сверх недельного лимита",
        "already_known": "значение уже есть в справочнике",
        "service_lexicon": "наша служебная лексика — в справочник не идёт",
        "class_not_trained": "не класс «имена»: тренер его не подтверждает",
    }
    for reason, count in sorted(report.disputed_by_reason.items()):
        lines.append(f"| `{reason}` | {count} | {meaning.get(reason, 'разбор не описан')} |")
    if not report.disputed_by_reason:
        lines.append("| — | 0 | спорных значений нет |")
    lines += [
        "",
        "## Что предлагается решить",
        "",
        "1. Значения с причиной `unconfirmed` — кандидаты на третий источник подтверждения",
        "   (частотный словарь фамилий или ручная проверка владельцем).",
        "2. Значения с причиной `service_lexicon` — кандидаты в стоп-лист своей лексики:",
        "   их попадание в справочник даёт ложные замены.",
        "3. Значения с причиной `ner_unavailable` повторятся в следующем прогоне, когда модель",
        "   будет на месте: они не потеряны.",
        "",
    ]
    return "\n".join(lines)


def post_to_mattermost(
    text: str,
    channel: str,
    token: str,
    base_url: str,
    poster: Callable[[str, dict[str, Any], str, str], tuple[int, str]] | None = None,
) -> tuple[bool, str]:
    """Отправить отчёт владельцу личным сообщением во внутреннем контуре.

    # START_CONTRACT: post_to_mattermost
    #   PURPOSE: Доставить отчёт без языковой модели: готовый текст уходит REST-постом, как у дайджеста руководителей.
    #   INPUTS: { text: str - отчёт, channel: str - идентификатор личного канала, token: str, base_url: str, poster: Callable | None - подстановка для тестов }
    #   OUTPUTS: { (bool, str) - доставлено ли и машинный код ответа }
    #   SIDE_EFFECTS: сетевой вызов Mattermost REST
    #   LINKS: M-INCIDENT-TRAINER, V-M-INCIDENT-TRAINER
    # END_CONTRACT: post_to_mattermost

    Текст поста — тот же отчёт цифрами, что и в файле: значения клиентов в него попасть не
    могут, потому что их нет ни в отчёте, ни в счётчиках. Ошибка доставки не отменяет прогон
    (справочник уже пополнен) и не скрывается: она попадает в отчёт кодом ответа.
    """
    if not channel or not token:
        return False, "DELIVERY_NOT_CONFIGURED"
    api = _api_base(base_url)
    send = poster or _http_post
    try:
        status, body = send(f"{api}/posts", {"channel_id": channel, "message": text}, token, api)
    except (OSError, ValueError) as exc:
        return False, f"DELIVERY_FAILED:{exc.__class__.__name__}"
    if status in (200, 201):
        return True, "DELIVERED"
    return False, f"DELIVERY_HTTP_{status}" + (f":{body[:120]}" if body else "")


def main(argv: Sequence[str] | None = None) -> int:
    """Точка входа CLI недельного тренера.

    # START_CONTRACT: main
    #   PURPOSE: Сделать недельное пополнение словаря повторяемым прогоном с одним и тем же порядком шагов.
    #   INPUTS: { argv: Sequence[str] | None }
    #   OUTPUTS: { int - код выхода: 0 успех, 2 нет обязательных данных }
    #   SIDE_EFFECTS: читает журналы, пишет отчёт, файл-предложение, staged, бэкап, заменяет справочник (кроме --dry-run)
    #   LINKS: M-INCIDENT-TRAINER, V-M-INCIDENT-TRAINER
    # END_CONTRACT: main
    """
    parser = argparse.ArgumentParser(
        description="Недельный тренер словаря по инцидентам (без языковой модели)"
    )
    parser.add_argument("--week", default="previous", help="previous | current | YYYY-WW")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="лимит значений за прогон")
    parser.add_argument("--dict-file", default=DEFAULTS["dict"])
    parser.add_argument("--dict-key-file", default=DEFAULTS["dict_key"])
    parser.add_argument("--map-db", default=DEFAULTS["map_db"])
    parser.add_argument("--fernet-key-file", default=DEFAULTS["fernet_key"])
    parser.add_argument("--incident-dir", default=DEFAULTS["incidents"])
    parser.add_argument("--audit-log", default=DEFAULTS["audit"])
    parser.add_argument("--model-dir", default=DEFAULTS["ner"])
    parser.add_argument("--name-layer", default=DEFAULTS["layer"])
    parser.add_argument("--report", default=DEFAULTS["report"], help="куда записать отчёт (JSON)")
    parser.add_argument("--proposal", default=DEFAULTS["proposal"], help="файл-предложение без ПД")
    parser.add_argument("--dry-run", action="store_true", help="ничего не менять и не писать")
    parser.add_argument("--deliver-mm", action="store_true", help="отправить отчёт в личку Mattermost")
    parser.add_argument("--mm-channel", default=os.environ.get("PII_PROXY_TRAINER_MM_CHANNEL", ""))
    parser.add_argument("--mm-token", default="", help="токен бота (по умолчанию из окружения профиля)")
    parser.add_argument("--mm-base-url", default="", help="адрес Mattermost (по умолчанию из окружения)")
    parser.add_argument("--env-file", default=PROFILE_ENV, help="файл окружения профиля")
    args = parser.parse_args(list(argv) if argv is not None else None)

    paths = {
        "dict": args.dict_file,
        "dict_key": args.dict_key_file,
        "map_db": args.map_db,
        "fernet_key": args.fernet_key_file,
        "incidents": args.incident_dir,
        "audit": args.audit_log,
        "ner": args.model_dir,
        "layer": args.name_layer,
    }
    try:
        report = run_week(
            week=args.week,
            limit=args.limit,
            paths=paths,
            dry_run=args.dry_run,
        )
    except dict_write.DictWriteError as exc:
        print(f"TRAINER_DICTIONARY_ERROR {exc.code}", file=sys.stderr)
        return 2
    except (OSError, TrainerError) as exc:
        print(f"TRAINER_FAILED {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 2

    text = render_report(report)
    if not args.dry_run:
        report.report_path = _write_text(args.report, json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        report.proposal_path = _write_text(args.proposal, render_proposal(report))
    else:
        report.proposal_path = ""
        report.report_path = ""

    if args.deliver_mm and not args.dry_run:
        env = _env_values([args.env_file])
        token = args.mm_token or env.get("MATTERMOST_TOKEN", "")
        channel = args.mm_channel or env.get("PII_PROXY_TRAINER_MM_CHANNEL", "")
        base = args.mm_base_url or env.get("MATTERMOST_URL", "")
        delivered, code = post_to_mattermost(text, channel, token, base)
        report.delivery = {"delivered": delivered, "code": code, "channel_configured": bool(channel)}
        text += f"\n\nДоставка отчёта: {code}."
    print(text)
    return 0


def _http_post(url: str, body: Mapping[str, Any], token: str, base: str) -> tuple[int, str]:
    """POST в Mattermost REST; ответ — код и тело."""
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return int(response.status), response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read().decode("utf-8", "replace")


def _api_base(raw: str) -> str:
    """Привести адрес Mattermost к корню API."""
    base = (raw or "https://chat.example.com").strip().rstrip("/")
    for suffix in ("/api/v4/posts", "/api/v4"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    return base + MM_API_SUFFIX


def _env_values(paths: Iterable[str]) -> dict[str, str]:
    """Прочитать ключи окружения из файлов профиля (строки KEY=VALUE)."""
    values: dict[str, str] = {}
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    name, _, raw = line.partition("=")
                    values.setdefault(name.strip(), raw.strip().strip('"').strip("'"))
        except OSError:
            continue
    for name in ("MATTERMOST_TOKEN", "MATTERMOST_URL", "PII_PROXY_TRAINER_MM_CHANNEL"):
        if os.environ.get(name):
            values[name] = os.environ[name]
    return values


def _read_key(path: str) -> bytes:
    """Прочитать ключ отпечатков справочника."""
    try:
        key = Path(path).read_bytes().strip()
    except OSError as exc:
        raise TrainerError("DICT_KEY_UNREADABLE", str(exc)) from exc
    if not key:
        raise TrainerError("DICT_KEY_UNREADABLE", "dictionary key is empty")
    return key


def _write_text(path: str, text: str) -> str:
    """Записать текстовый артефакт отчёта, создав каталог."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return str(target)


def _render_map(raw: Mapping[str, int]) -> str:
    """Отпечатать счётчики по ключам одной строкой."""
    if not raw:
        return "—"
    return ", ".join(f"{key}: {value}" for key, value in sorted(raw.items()))


def _render_metrics(report: TrainerReport) -> str:
    """Сказать, что с прибором на staged — тремя состояниями, а не двумя."""
    if report.dry_run:
        return "не запускался (прогон без изменений)"
    if report.apply_reason == "nothing_confirmed":
        return "не требовался: добавки нет"
    return "планки выдержаны" if report.metrics_passed else "планки НЕ выдержаны"


def _render_disputes(raw: Mapping[str, int]) -> str:
    """Отпечатать спорное по причинам таблицей."""
    if not raw:
        return "Спорных значений нет: всё подтверждённое добавлено."
    lines = ["| Причина | Значений |", "|---|---|"]
    for reason, count in sorted(raw.items()):
        lines.append(f"| `{reason}` | {count} |")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
