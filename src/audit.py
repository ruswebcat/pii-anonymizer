# FILE: src/audit.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Record every anonymization event without any PII value so the operator can present a compliant journal to the regulator.
#   SCOPE: append-only JSONL journal, per-class and per-action counters, block recording with a whitelisted reason code, optional alert delivery, regulator export.
#   DEPENDS: M-CONFIG
#   LINKS: M-AUDIT, V-M-AUDIT, export-audit, fn-record_block, fn-metrics_snapshot
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   ACTIONS - whitelisted action names
#   BLOCK_REASONS - whitelisted block reason codes
#   AuditEvent - one journal record without values
#   AuditJournal - append-only journal plus counters
#   fn-append - write one event
#   fn-record_block - write a blocked event
#   fn-metrics_snapshot - counters for healthz
#   fn-export_for_regulator - journal dump for inspection
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.2 - Phase-15 шаг 1: в список действий добавлены degraded_tokenized (Вариант 1) и journal_write_failed (сбой журнала инцидентов), в причины — replacement_failed и incident_log_unwritable. Журнал аудита остаётся единственным местом, где виден незаписанный инцидент.
#   PREVIOUS: v1.0.1 - Phase-9 шаг 3: в список разрешённых действий добавлено name_layer_reload (пополнение открытого словаря).
# END_CHANGE_SUMMARY

"""Anonymization journal.

Implements M-AUDIT from docs/ARCHITECTURE.md. The journal is the artifact a
regulator or prosecutor can be shown (UC-008), therefore the schema is closed:
an event carries a session id, a direction, a class letter, a count, an action
and a whitelisted reason code. Values, raw text and payload fragments have no
field to live in, which is what makes "no PII in logs" a structural property
rather than a promise.
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable

LOGGER_NAME = "AuditJournal"
LOG_MARKER = "[AuditJournal][append][BLOCK_APPEND_AUDIT]"

ACTIONS = frozenset(
    {
        "tokenized",
        "detokenized",
        "degraded_tokenized",
        "channel_blocked",
        "blocked",
        "image_blocked",
        "purge",
        "dictionary_reload",
        "name_layer_reload",
        "dry_run",
        "rarity_warning",
        "rarity_blocked",
        "cache_invalidated",
        "collision_resolved",
        "restore_skipped",
        "image_notice",
        "second_pass",
        "stream_closed",
        "stream_error",
        # Phase-15 шаг 1: инцидент — промах детектора. Значение не записано или не
        # помечено «из инцидента»: защита выполнена, но инцидент считается незакрытым
        # и попадает в недельный счётчик незаписанных.
        "journal_write_failed",
    }
)

BLOCK_REASONS = frozenset(
    {
        "residual_pii",
        "store_unavailable",
        "store_decrypt_failed",
        "validator_error",
        "images_blocked",
        "tokenizer_error",
        "unknown_route",
        "rarity_quota",
        "dictionary_reload",
        "not_in_request",
        "stream_broken",
        # Phase-15: остаток ПД найден, но заменить его не удалось — жёсткая
        # блокировка (Вариант 1 не ослабляет fail-closed).
        "replacement_failed",
        "incident_log_unwritable",
    }
)

DIRECTIONS = frozenset({"inbound", "outbound", "internal"})


class AuditError(RuntimeError):
    """Journal failure with a stable code.

    # START_CONTRACT: AuditError
    #   PURPOSE: Signal an unusable journal.
    #   INPUTS: { code: str - stable code, message: str - detail }
    #   OUTPUTS: { AuditError - exception instance }
    #   SIDE_EFFECTS: none
    #   LINKS: M-AUDIT, V-M-AUDIT
    # END_CONTRACT: AuditError
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class AuditEvent:
    """One journal record. No field may ever hold a PII value.

    # START_CONTRACT: AuditEvent
    #   PURPOSE: Describe one anonymization event in a closed schema.
    #   INPUTS: { session_id: str, action: str, direction: str, cls: str, count: int, channel: str, reason: str }
    #   OUTPUTS: { AuditEvent - value object }
    #   SIDE_EFFECTS: none
    #   LINKS: M-AUDIT, V-M-AUDIT
    # END_CONTRACT: AuditEvent
    """

    session_id: str
    action: str
    direction: str = "internal"
    cls: str = "-"
    count: int = 0
    channel: str = ""
    reason: str = ""
    ts: float = field(default_factory=time.time)


# START_BLOCK_APPEND_AUDIT
class AuditJournal:
    """Append-only anonymization journal with counters.

    # START_CONTRACT: AuditJournal
    #   PURPOSE: Own the journal file and the counters exposed by healthz.
    #   INPUTS: { log_path: str, alert_sender: Callable[[str], None] | None, clock: Callable[[], float] }
    #   OUTPUTS: { AuditJournal - usable journal }
    #   SIDE_EFFECTS: appends to the journal file, may call the alert sender
    #   LINKS: M-CONFIG, M-ROUTER, V-M-AUDIT
    # END_CONTRACT: AuditJournal
    """

    def __init__(
        self,
        log_path: str,
        alert_sender: Callable[[str], None] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._path = log_path
        self._alert = alert_sender
        self._clock = clock
        self._action_counts: Counter[str] = Counter()
        self._class_counts: Counter[str] = Counter()
        self._events: list[AuditEvent] = []
        directory = os.path.dirname(os.path.abspath(log_path))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, mode=0o700, exist_ok=True)
        try:
            with open(self._path, "a", encoding="utf-8"):
                pass
        except OSError as exc:
            raise AuditError("AUDIT_WRITE_FAILED", f"cannot open journal: {exc}") from exc

    def append(self, event: AuditEvent) -> bool:
        """Write one event after validating its closed schema.

        # START_CONTRACT: append
        #   PURPOSE: Persist an event and update counters.
        #   INPUTS: { event: AuditEvent - event to persist }
        #   OUTPUTS: { bool - True when written }
        #   SIDE_EFFECTS: appends to the journal file, may alert
        #   LINKS: M-ROUTER, V-M-AUDIT
        # END_CONTRACT: append
        """
        if event.action not in ACTIONS:
            raise AuditError("AUDIT_BAD_ACTION", f"unknown action: {event.action!r}")
        if event.direction not in DIRECTIONS:
            raise AuditError("AUDIT_BAD_DIRECTION", f"unknown direction: {event.direction!r}")
        if event.reason and event.reason not in BLOCK_REASONS:
            raise AuditError("AUDIT_BAD_REASON", f"unknown reason code: {event.reason!r}")
        if len(event.cls) > 1:
            raise AuditError("AUDIT_BAD_CLASS", "class must be a single letter")
        stamped = event
        if event.ts is None:
            stamped = AuditEvent(**{**asdict(event), "ts": self._clock()})
        record = asdict(stamped)
        try:
            with open(self._path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        except OSError as exc:
            raise AuditError("AUDIT_WRITE_FAILED", f"cannot append: {exc}") from exc
        self._events.append(stamped)
        self._action_counts[stamped.action] += 1
        if stamped.cls and stamped.cls != "-":
            self._class_counts[stamped.cls] += stamped.count or 1
        if stamped.action in {"blocked", "image_blocked", "channel_blocked"} and self._alert:
            self._alert(
                f"PII proxy: action={stamped.action} reason={stamped.reason or '-'} "
                f"channel={stamped.channel or '-'} class={stamped.cls}"
            )
        return True

    def record_tokenization(
        self, session_id: str, stats: dict[str, int], direction: str = "inbound"
    ) -> bool:
        """Record one tokenization pass as per-class events.

        # START_CONTRACT: record_tokenization
        #   PURPOSE: Turn tokenizer statistics into journal events.
        #   INPUTS: { session_id: str, stats: dict[str, int] - class to count, direction: str }
        #   OUTPUTS: { bool - True when at least one event was written }
        #   SIDE_EFFECTS: appends to the journal file
        #   LINKS: M-TOKENIZER, V-M-AUDIT
        # END_CONTRACT: record_tokenization
        """
        written = False
        for cls, count in sorted((stats or {}).items()):
            if not count:
                continue
            self.append(
                AuditEvent(
                    session_id=session_id,
                    action="tokenized",
                    direction=direction,
                    cls=cls,
                    count=int(count),
                    ts=self._clock(),
                )
            )
            written = True
        return written

    def record_block(
        self, session_id: str, reason: str, channel: str = "", cls: str = "-"
    ) -> bool:
        """Record a fail-closed block.

        # START_CONTRACT: record_block
        #   PURPOSE: Persist why a request was not sent upstream.
        #   INPUTS: { session_id: str, reason: str - whitelisted code, channel: str, cls: str }
        #   OUTPUTS: { bool - True when written }
        #   SIDE_EFFECTS: appends to the journal file, may alert
        #   LINKS: M-VALIDATOR, M-ROUTER, V-M-AUDIT
        # END_CONTRACT: record_block
        """
        action = "image_blocked" if reason == "images_blocked" else "blocked"
        return self.append(
            AuditEvent(
                session_id=session_id,
                action=action,
                direction="inbound",
                cls=cls,
                count=0,
                channel=channel,
                reason=reason,
                ts=self._clock(),
            )
        )

    def metrics_snapshot(self) -> dict[str, object]:
        """Return counters and journal size for healthz.

        # START_CONTRACT: metrics_snapshot
        #   PURPOSE: Expose non-sensitive operational counters.
        #   INPUTS: none
        #   OUTPUTS: { dict[str, object] - counters, classes, journal path and size }
        #   SIDE_EFFECTS: reads the filesystem
        #   LINKS: M-ROUTER, V-M-AUDIT
        # END_CONTRACT: metrics_snapshot
        """
        try:
            size = os.path.getsize(self._path)
        except OSError:
            size = 0
        return {
            "actions": dict(self._action_counts),
            "classes": dict(self._class_counts),
            "events": len(self._events),
            "journal_bytes": size,
        }

    def export_for_regulator(self) -> list[dict]:
        """Return the journal records for inspection (no values inside).

        # START_CONTRACT: export_for_regulator
        #   PURPOSE: Provide the artifact required by UC-008.
        #   INPUTS: none
        #   OUTPUTS: { list[dict] - journal records read from disk }
        #   SIDE_EFFECTS: reads the journal file
        #   LINKS: M-AUDIT, V-M-AUDIT
        # END_CONTRACT: export_for_regulator
        """
        records: list[dict] = []
        with open(self._path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def contains_any(self, needles: Iterable[str]) -> bool:
        """Return True when the journal file contains any of the needles.

        Used by tests to prove that values never reach the journal.
        """
        try:
            with open(self._path, "r", encoding="utf-8") as handle:
                body = handle.read()
        except OSError:
            return False
        return any(needle and needle in body for needle in needles)
# END_BLOCK_APPEND_AUDIT
