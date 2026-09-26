# FILE: src/incident_journal.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Вести отдельный журнал инцидентов — промахов детектора на живом трафике: время, канал, класс, действие, выданный код и счётчики, без единого значения.
#   SCOPE: запись инцидента классами и числами, пометка значения «из инцидента» в шифрованном справочнике, недельная ротация файлов и срок хранения, чтение недели, счётчики по классам, действиям и каналам, счётчик незаписанных инцидентов.
#   DEPENDS: M-AUDIT, M-MAP-STORE, M-CONFIG
#   LINKS: M-INCIDENT-JOURNAL, V-M-INCIDENT-JOURNAL, fn-record, fn-read_week, fn-counts, const-ACTIONS
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   ACTIONS - машинные действия инцидента: degraded_tokenized, blocked, journal_write_failed, ambiguous_code, ambiguous_kept, name_glue
#   INCIDENT_SOURCE - пометка источника в справочнике: «из инцидента»
#   RETENTION_DAYS - срок хранения файлов журнала (180 дней: тренеру всегда есть что читать)
#   IncidentError - сбой или неверное использование журнала, с машинным кодом
#   IncidentEvent - один инцидент: классы, коды и числа
#   IncidentJournal - недельный журнал инцидентов без значений
#   fn-record - записать инцидент и пометить его значения «из инцидента»
#   fn-read_week - прочитать инциденты за неделю
#   fn-counts - счётчики по классам, действиям и каналам
#   fn-week_file - файл недели (ротация incidents-YYYY-WW.jsonl)
#   fn-purge_old - удалить файлы старше срока хранения
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.1.0 - Phase-17 (20.09.2026): три машинных действия доверенной границы — ambiguous_code (многозначный реестр), ambiguous_kept (многозначный код не восстановлен), name_glue (сочетание ФИО не подтверждено источником).
#   PREVIOUS: v1.0.0 - Phase-15 шаг 1: журнал инцидентов (M-INCIDENT-JOURNAL). Ни текстов, ни значений, ни путей и ключей — только классы, машинные коды и числа; значение уходит в шифрованный справочник с пометкой «из инцидента» и обычным TTL.
# END_CHANGE_SUMMARY

"""Журнал инцидентов (M-INCIDENT-JOURNAL).

Инцидент — запрос, в котором заслон (M-VALIDATOR) нашёл остаток персональных данных,
пропущенный детектором. Такой промах нужно разбирать: без записи нечего разбирать, без
разбора словарь не пополняется.

Схема записи закрыта ровно так же, как у журнала аудита, и по той же причине: **значению
негде лежать**. В записи есть время, канал, класс, действие, выданный код, счётчики находок
и замен, правило-источник находки. Текстов запроса и ответа, значений и их фрагментов, длин
и хешей значений, путей и ключей в журнале нет — это правило проекта, а не пожелание
(см. ``docs/ARCHITECTURE.md``, «Секретов и значений ПД в журналах нет»).

Само значение при этом не теряется: второй проход уже сохранил его в шифрованном
справочнике (M-MAP-STORE) обычным путём, а журнал помечает связку источником
«из инцидента». Недельный тренер (M-INCIDENT-TRAINER) берёт из справочника только
помеченные значения, поэтому ему не нужно видеть журнал, чтобы понять, чему учиться.

Отказ журнала защиту не отменяет: к моменту записи значение уже заменено кодом, поэтому
сбой записи утечки не даёт. Но каждый сбой считается: он попадает счётчиком незаписанных
в недельный отчёт (в журнале аудита — действием ``journal_write_failed``), а сбой **замены**
остаётся жёсткой блокировкой.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from src.audit import AuditEvent, AuditJournal
from src.token_factory import is_valid_token

LOGGER_NAME = "IncidentJournal"
LOG_MARKER = "[IncidentJournal][record][BLOCK_RECORD_INCIDENT]"

#: Машинные действия инцидента (docs/ARCHITECTURE.md, таблица действий).
#:
#: Phase-17 (20.09.2026) добавила три действия доверенной границы: ``ambiguous_code`` —
#: реестр несёт код с более чем одним значением (служба отказывается работать);
#: ``ambiguous_kept`` — многозначный код не восстановлен; ``name_glue`` — сочетание частей ФИО
#: источником не подтверждено и потому не восстановлено (выдуманная персона инцидента
#: 20.09.2026 была именно склейкой: «имя одного человека + фамилия другого»).
ACTIONS = frozenset(
    {
        "degraded_tokenized",
        "blocked",
        "journal_write_failed",
        "ambiguous_code",
        "ambiguous_kept",
        "name_glue",
    }
)

#: Пометка источника в шифрованном справочнике: по ней тренер находит свои значения.
INCIDENT_SOURCE = "из инцидента"

#: Срок хранения файлов журнала. Запас взят намеренно: тренер запускается по неделям, и
#: журнал должен пережить отпуск, болезнь и разбор инцидента задним числом.
RETENTION_DAYS = 180

FILE_PREFIX = "incidents"
CLASS_LETTERS = ("P", "T", "E", "D", "A", "I", "C")

#: Канал, правило и действие — короткие машинные строки. Всё, что длиннее, — это уже текст,
#: а тексту в журнале инцидентов не место (проверка ниже, код INCIDENT_VALUE_REQUIRED).
_MACHINE_TOKEN = re.compile(r"^[a-z0-9_\-]{0,32}$")
_CLASS = re.compile(r"^[PTEDAIC\-]$")


class IncidentError(RuntimeError):
    """Сбой журнала инцидентов или неверное его использование.

    # START_CONTRACT: IncidentError
    #   PURPOSE: Нести машинный код: INCIDENT_VALUE_REQUIRED при попытке записать текст вместо класса.
    #   INPUTS: { code: str - машинный код, message: str - подробность без значений }
    #   OUTPUTS: { IncidentError - исключение }
    #   SIDE_EFFECTS: none
    #   LINKS: M-INCIDENT-JOURNAL, V-M-INCIDENT-JOURNAL
    # END_CONTRACT: IncidentError
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class IncidentEvent:
    """Один инцидент. Ни одно поле не может нести значение.

    # START_CONTRACT: IncidentEvent
    #   PURPOSE: Описать промах детектора так, чтобы разбор был возможен без самих данных.
    #   INPUTS: { cls: str - класс значения, action: str - машинное действие, channel: str - канал, code: str - выданный код, findings/replacements: int - счётчики, rule: str - правило-источник находки, ts: float - время }
    #   OUTPUTS: { IncidentEvent - значение-объект }
    #   SIDE_EFFECTS: none
    #   LINKS: M-INCIDENT-JOURNAL, M-VALIDATOR, M-ROUTER
    # END_CONTRACT: IncidentEvent

    ``code`` — выданный код (идентификатор из фабрики кодов): псевдоним, а не значение. По нему
    оператор находит связку в шифрованном справочнике, а сам код без ключа справочника ничего
    не раскрывает. Значения, его фрагмента, длины и хеша в записи нет.
    """

    cls: str
    action: str
    channel: str = ""
    code: str = ""
    findings: int = 0
    replacements: int = 0
    rule: str = ""
    ts: float = field(default_factory=time.time)


# START_BLOCK_RECORD_INCIDENT
class IncidentJournal:
    """Недельный журнал инцидентов: классы, коды и числа.

    # START_CONTRACT: IncidentJournal
    #   PURPOSE: Записать промах детектора, пометить его значение в справочнике и отдать неделю тренеру.
    #   INPUTS: { incident_dir: str - каталог журнала, audit: AuditJournal | None - журнал аудита для счётчика незаписанных, clock: Callable[[], float] }
    #   OUTPUTS: { IncidentJournal - готовый журнал }
    #   SIDE_EFFECTS: создаёт каталог, дописывает файл недели, помечает связки в справочнике
    #   LINKS: M-AUDIT, M-MAP-STORE, M-CONFIG, V-M-INCIDENT-JOURNAL
    # END_CONTRACT: IncidentJournal

    Каталог не создаётся «во что бы то ни стало»: неудачный mkdir не мешает службе подняться.
    Сбой записи виден кодом INCIDENT_LOG_UNWRITABLE в логе и счётчиком незаписанных в отчёте.
    """

    def __init__(
        self,
        incident_dir: str,
        audit: AuditJournal | None = None,
        clock: Any = time.time,
        retention_days: int = RETENTION_DAYS,
    ) -> None:
        self._dir = incident_dir or ""
        self._audit = audit
        self._clock = clock or time.time
        self._retention_days = max(1, int(retention_days))
        self._unwritten = 0
        if self._dir:
            try:
                os.makedirs(self._dir, mode=0o700, exist_ok=True)
            except OSError:
                # Каталог может быть недоступен (права, смонтирован позже). Служба обязана
                # подняться: инцидент без записи — потеря доказательства, а не утечка.
                logging.getLogger(LOGGER_NAME).warning(
                    "%s %s", LOG_MARKER, "INCIDENT_LOG_UNWRITABLE"
                )

    @property
    def directory(self) -> str:
        """Вернуть каталог журнала."""
        return self._dir

    @property
    def unwritten(self) -> int:
        """Вернуть число незаписанных инцидентов этого процесса."""
        return self._unwritten

    @staticmethod
    def week_key(ts: float | None = None) -> str:
        """Вернуть ключ недели вида YYYY-WW по времени (UTC).

        # START_CONTRACT: week_key
        #   PURPOSE: Одна точка правды для имени файла недели.
        #   INPUTS: { ts: float | None - время, по умолчанию — сейчас }
        #   OUTPUTS: { str - ключ недели, например 2026-38 }
        #   SIDE_EFFECTS: none
        #   LINKS: fn-read_week, V-M-INCIDENT-JOURNAL
        # END_CONTRACT: week_key
        """
        moment = datetime.fromtimestamp(float(time.time() if ts is None else ts), timezone.utc)
        iso = moment.isocalendar()
        return f"{iso.year}-{iso.week:02d}"

    @staticmethod
    def week_file(incident_dir: str, week: str) -> str:
        """Вернуть путь к файлу недели (ротация incidents-YYYY-WW.jsonl)."""
        return os.path.join(incident_dir or "", f"{FILE_PREFIX}-{week}.jsonl")

    def record(
        self,
        event: IncidentEvent,
        codes: Sequence[tuple[str, str]] = (),
        store: Any | None = None,
    ) -> dict[str, Any]:
        """Записать инцидент и пометить его значения в справочнике.

        # START_CONTRACT: record
        #   PURPOSE: Оставить доказательство промаха, не записав ни одного значения.
        #   INPUTS: { event: IncidentEvent - инцидент, codes: Sequence[tuple[str, str]] - (класс, код) для пометки, store: Any | None - шифрованный справочник }
        #   OUTPUTS: { dict[str, Any] - записанная запись плюс written и marked }
        #   SIDE_EFFECTS: дописывает файл недели, помечает связки, при сбое пишет в журнал аудита
        #   LINKS: M-MAP-STORE, M-AUDIT, V-M-INCIDENT-JOURNAL
        # END_CONTRACT: record

        Порядок важен: сначала пометка значений в справочнике (тренеру нужно знать, что это
        значение из инцидента), затем запись строки. Сбой пометки не отменяет защиту, но
        инцидент считается незакрытым: он записывается действием ``journal_write_failed``.
        """
        record = self._build_record(event, codes)
        marked = 0
        mark_failed = bool(codes) and store is None
        if store is not None:
            for _cls, code in codes:
                try:
                    if store.mark_source(code, INCIDENT_SOURCE):
                        marked += 1
                    else:
                        mark_failed = True
                except Exception:  # noqa: BLE001 - сбой пометки не должен ломать запрос
                    mark_failed = True
        if mark_failed:
            # Значение не помечено — тренер его не увидит. Инцидент закрыт не полностью.
            record["action"] = "journal_write_failed"
            record["findings"] = max(int(record.get("findings") or 0), 1)
        written = self._append(record)
        if mark_failed and not written:
            self._note_unwritten()
        return {**record, "written": written, "marked": marked}

    def read_week(self, week: str = "previous", now: float | None = None) -> list[dict[str, Any]]:
        """Прочитать инциденты за неделю.

        # START_CONTRACT: read_week
        #   PURPOSE: Отдать тренеру ровно свой файл недели, без соседних.
        #   INPUTS: { week: str - previous | current | YYYY-WW, now: float | None - опорное время }
        #   OUTPUTS: { list[dict] - записи недели }
        #   SIDE_EFFECTS: читает файл журнала
        #   LINKS: M-INCIDENT-TRAINER, V-M-INCIDENT-JOURNAL
        # END_CONTRACT: read_week
        """
        reference = float(self._clock() if now is None else now)
        key = self._resolve_week(week, reference)
        path = self.week_file(self._dir, key)
        records: list[dict[str, Any]] = []
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
                    if isinstance(payload, dict):
                        records.append(payload)
        except OSError:
            return []
        return records

    def counts(self, records: Iterable[Mapping[str, Any]] | None = None) -> dict[str, Any]:
        """Собрать счётчики по классам, действиям и каналам.

        # START_CONTRACT: counts
        #   PURPOSE: Дать недельному отчёту числа: сколько инцидентов и какие.
        #   INPUTS: { records: Iterable[Mapping] | None - записи, по умолчанию — неделя «previous» }
        #   OUTPUTS: { dict - total, findings, replacements, by_class, by_action, by_channel }
        #   SIDE_EFFECTS: может читать файл недели
        #   LINKS: M-INCIDENT-TRAINER, V-M-INCIDENT-JOURNAL
        # END_CONTRACT: counts
        """
        items = list(self.read_week("previous") if records is None else records)
        by_class: dict[str, int] = {}
        by_action: dict[str, int] = {}
        by_channel: dict[str, int] = {}
        findings = 0
        replacements = 0
        for record in items:
            letter = str(record.get("class") or "-")
            by_class[letter] = by_class.get(letter, 0) + 1
            action = str(record.get("action") or "-")
            by_action[action] = by_action.get(action, 0) + 1
            channel = str(record.get("channel") or "-")
            by_channel[channel] = by_channel.get(channel, 0) + 1
            findings += int(record.get("findings") or 0)
            replacements += int(record.get("replacements") or 0)
        return {
            "total": len(items),
            "findings": findings,
            "replacements": replacements,
            "by_class": by_class,
            "by_action": by_action,
            "by_channel": by_channel,
        }

    def purge_old(self, now: float | None = None) -> int:
        """Удалить файлы журнала старше срока хранения.

        # START_CONTRACT: purge_old
        #   PURPOSE: Держать ротацию: хранение 180 дней, свежие недели не трогаются.
        #   INPUTS: { now: float | None - опорное время }
        #   OUTPUTS: { int - сколько файлов удалено }
        #   SIDE_EFFECTS: удаляет файлы в каталоге журнала
        #   LINKS: V-M-INCIDENT-JOURNAL
        # END_CONTRACT: purge_old
        """
        reference = float(self._clock() if now is None else now)
        threshold = reference - self._retention_days * 86400
        removed = 0
        try:
            names = sorted(os.listdir(self._dir))
        except OSError:
            return 0
        current = self.week_key(reference)
        for name in names:
            key = _week_of_file(name)
            if key is None or key == current:
                continue
            monday = _week_start(key)
            if monday is None or monday >= threshold:
                continue
            try:
                os.unlink(os.path.join(self._dir, name))
                removed += 1
            except OSError:  # pragma: no cover - filesystem dependent
                continue
        return removed

    def contains_any(self, needles: Iterable[str]) -> bool:
        """Ответить, встречается ли что-то из списка в файлах журнала.

        Используется тестами как доказательство «значений в журнале нет».
        """
        for name in _iter_files(self._dir):
            try:
                with open(os.path.join(self._dir, name), "r", encoding="utf-8") as handle:
                    body = handle.read()
            except OSError:  # pragma: no cover - filesystem dependent
                continue
            if any(needle and needle in body for needle in needles):
                return True
        return False

    def _resolve_week(self, week: str, reference: float) -> str:
        """Превратить «previous»/«current»/«YYYY-WW» в ключ недели."""
        text = str(week or "previous").strip().lower()
        if text in {"previous", "prev", "past"}:
            return self.week_key(reference - 7 * 86400)
        if text in {"current", "now", "this"}:
            return self.week_key(reference)
        if re.fullmatch(r"\d{4}-\d{1,2}", text):
            year, number = text.split("-")
            return f"{int(year):04d}-{int(number):02d}"
        raise IncidentError("INCIDENT_BAD_WEEK", f"unknown week selector: {week!r}")

    def _build_record(
        self, event: IncidentEvent, codes: Sequence[tuple[str, str]]
    ) -> dict[str, Any]:
        """Собрать запись строго по схеме и отвергнуть текст на месте класса."""
        cls = str(getattr(event, "cls", "") or "-").strip()
        if not _CLASS.match(cls):
            raise IncidentError(
                "INCIDENT_VALUE_REQUIRED",
                "class must be a single class letter: values and texts are not accepted",
            )
        action = str(event.action or "").strip()
        if action not in ACTIONS:
            raise IncidentError(
                "INCIDENT_VALUE_REQUIRED", f"action must be a machine code, got {action!r}"
            )
        channel = str(event.channel or "").strip().lower()
        rule = str(event.rule or "").strip().lower()
        for name, value in (("channel", channel), ("rule", rule)):
            if not _MACHINE_TOKEN.match(value):
                raise IncidentError(
                    "INCIDENT_VALUE_REQUIRED", f"{name} must be a machine code, not text"
                )
        code = str(event.code or "").strip()
        if code and not is_valid_token(code):
            raise IncidentError(
                "INCIDENT_VALUE_REQUIRED", "code must be an issued identifier, not text"
            )
        for name in ("findings", "replacements"):
            value = getattr(event, name, 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise IncidentError(
                    "INCIDENT_VALUE_REQUIRED", f"{name} must be a non-negative number"
                )
        for letter, issued in codes:
            if str(letter).strip() not in CLASS_LETTERS:
                raise IncidentError(
                    "INCIDENT_VALUE_REQUIRED", "marked class must be a class letter"
                )
            if issued and not is_valid_token(issued):
                raise IncidentError(
                    "INCIDENT_VALUE_REQUIRED", "marked code must be an issued identifier"
                )
        moment = float(event.ts)
        return {
            "ts": datetime.fromtimestamp(moment, timezone.utc).isoformat(),
            "channel": channel,
            "class": cls,
            "action": action,
            "code": code,
            "findings": int(event.findings),
            "replacements": int(event.replacements),
            "rule": rule,
        }

    def _append(self, record: Mapping[str, Any]) -> bool:
        """Дописать строку в файл недели; сбой — код INCIDENT_LOG_UNWRITABLE, а не исключение."""
        moment = record.get("ts")
        path = self.week_file(self._dir, self.week_key(_parse_iso(moment)))
        try:
            if not self._dir:
                raise OSError("incident directory is not configured")
            os.makedirs(self._dir, mode=0o700, exist_ok=True)
            descriptor = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
            try:
                os.write(
                    descriptor,
                    (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"),
                )
            finally:
                os.close(descriptor)
            os.chmod(path, 0o600)
        except OSError as exc:
            self._note_unwritten()
            logging.getLogger(LOGGER_NAME).error(
                "%s INCIDENT_LOG_UNWRITABLE (%s)", LOG_MARKER, type(exc).__name__
            )
            return False
        logging.getLogger(LOGGER_NAME).info(
            "%s action=%s class=%s channel=%s findings=%s replacements=%s",
            LOG_MARKER,
            record.get("action"),
            record.get("class"),
            record.get("channel"),
            record.get("findings"),
            record.get("replacements"),
        )
        return True

    def _note_unwritten(self) -> None:
        """Учесть незаписанный инцидент в счётчике и в журнале аудита.

        Файл инцидентов мог оказаться недоступным целиком, поэтому счётчик незаписанных
        дублируется в журнал аудита: иначе недельный отчёт о сбое не узнает. Значений здесь
        нет — только класс и число.
        """
        self._unwritten += 1
        if self._audit is None:
            return
        try:
            self._audit.append(
                AuditEvent(
                    session_id="-",
                    action="journal_write_failed",
                    direction="internal",
                    cls="-",
                    count=1,
                    channel="",
                    reason="incident_log_unwritable",
                )
            )
        except Exception:  # noqa: BLE001 - журнал аудита тоже может быть недоступен
            logging.getLogger(LOGGER_NAME).error(
                "%s INCIDENT_LOG_UNWRITABLE audit fallback failed", LOG_MARKER
            )
# END_BLOCK_RECORD_INCIDENT


def _parse_iso(moment: Any) -> float:
    """Разобрать время записи ISO 8601 в метку времени; при неудаче — текущее время."""
    if not isinstance(moment, str) or not moment:
        return time.time()
    try:
        return datetime.fromisoformat(moment).timestamp()
    except ValueError:  # pragma: no cover - defensive
        return time.time()


def _week_of_file(name: str) -> str | None:
    """Вернуть ключ недели из имени файла журнала, или None."""
    match = re.fullmatch(rf"{FILE_PREFIX}-(\d{{4}})-(\d{{1,2}})\.jsonl", name or "")
    if not match:
        return None
    return f"{int(match.group(1)):04d}-{int(match.group(2)):02d}"


def _week_start(week: str) -> float | None:
    """Вернуть метку времени начала недели (понедельник, 00:00 UTC)."""
    try:
        year, number = (int(part) for part in str(week).split("-"))
        monday = datetime.fromisocalendar(year, number, 1).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    return monday.timestamp()


def _iter_files(directory: str) -> list[str]:
    """Перечислить файлы недель в каталоге журнала."""
    try:
        return sorted(name for name in os.listdir(directory) if _week_of_file(name))
    except OSError:
        return []
