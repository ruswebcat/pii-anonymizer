# FILE: tests/test_incident_journal.py
# VERSION: 1.0.1
# START_MODULE_CONTRACT
#   PURPOSE: Проверить журнал инцидентов: запись классами и числами, отсутствие значений во всех классах, отказ текста на месте класса, сбой записи, недельная ротация и шифрованная пометка «из инцидента».
#   SCOPE: запись инцидента, поиск значения по файлу журнала, INCIDENT_VALUE_REQUIRED, INCIDENT_LOG_UNWRITABLE с незаписанным счётчиком, ротация недель, значение в шифрованном справочнике.
#   DEPENDS: M-INCIDENT-JOURNAL, M-MAP-STORE, M-AUDIT, M-ROUTER, M-TEST-HARNESS
#   LINKS: V-M-INCIDENT-JOURNAL, M-INCIDENT-JOURNAL
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   ResidualWithoutReplacement - дублёр заслона: остаток есть, замены нет (fail-closed)
#   IncidentRecordTests - запись инцидента и её поля
#   IncidentNoValueTests - значений в журнале нет ни по одному классу
#   IncidentMisuseTests - текст на месте класса отвергается машинным кодом
#   IncidentUnwritableTests - сбой записи защиту не отменяет
#   IncidentWeekTests - ротация по неделям
#   IncidentStoreTests - значение из инцидента в шифрованном справочнике
#   IncidentDegradedTests - стык с Вариантом 1: degraded_tokenized в обоих журналах, значений нет
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.2 - дефект-фикс 19.09.2026: отказ заслона по остатку ПД приходит кодом 422 (было 403 — клиент читал его как «провайдер отклонил ключ»).
#   PREVIOUS: v1.0.1 - Phase-15 шаг 2: сценарий стыка — деградация записана в журнал инцидентов и в журнал аудита, значений нет ни в одном.
#   EARLIER: v1.0.0 - Phase-15 шаг 1: журнал инцидентов (V-M-INCIDENT-JOURNAL, сценарии 1–6).
# END_CHANGE_SUMMARY

"""Тесты журнала инцидентов (Phase-15, шаг 1).

Сценарии взяты из docs/OPERATIONS.md, V-M-INCIDENT-JOURNAL. Все значения —
заглушки: настоящих персональных данных в тестах нет.
"""

import datetime
import json
import logging
import os
import stat
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.audit import AuditJournal  # noqa: E402
from src.incident_journal import (  # noqa: E402
    ACTIONS,
    INCIDENT_SOURCE,
    IncidentError,
    IncidentEvent,
    IncidentJournal,
)
from src.normalize import normalize, split_birth_date  # noqa: E402
from src.router import RouterError, build_service  # noqa: E402
from src.token_factory import make_token  # noqa: E402
from tests import harness  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()

LOGGER = logging.getLogger("IncidentJournal")

#: Путь чата — тот же, что прокидывает HTTP-обработчик (src.router.CHAT_SUFFIX).
CHAT_PATH = "/v1/chat/completions"

FIO = "Иванов Иван Иванович"
PHONE = "79000000001"
EMAIL = "client-nobody@example.ru"
BIRTH = "12.03.1985"
ADDRESS = "ул. Заводская, д. 19А, кв. 5"
CLIENT_ID = "35000"
DOCUMENT = "4509123456"
SAMPLE_BY_CLASS = {
    "P": FIO,
    "T": PHONE,
    "E": EMAIL,
    "D": BIRTH,
    "A": ADDRESS,
    "C": CLIENT_ID,
    "I": DOCUMENT,
}


def incident_dir(root: str) -> str:
    """Каталог журнала инцидентов рядом с журналом аудита."""
    return os.path.join(root, "incidents")


class ResidualWithoutReplacement:
    """Дублёр заслона: остаток есть, второго прохода (замены) нет.

    Воспроизводит промах детектора и худший его исход — замену выполнить нельзя. По
    правилу fail-closed такой запрос обязан быть остановлен, а инцидент записан
    действием ``blocked``. Дублёр намеренно «сломан»: тест обязан это заметить.
    """

    def validate_outgoing(self, payload: dict, original: dict | None = None):
        from src.validator import ValidationReason, ValidationVerdict

        return ValidationVerdict(
            clean=False, code="residual_pii", reasons=(ValidationReason(cls="P", count=1),)
        )


# START_BLOCK_TEST_INCIDENT_JOURNAL
class IncidentJournalBase(unittest.TestCase):
    """Общая обвязка: каталог, журнал аудита, шифрованный справочник."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.audit = AuditJournal(os.path.join(self.root, "audit.jsonl"))
        self.store = harness.temp_map_store(self.root)
        self.journal = IncidentJournal(incident_dir(self.root), audit=self.audit)

    def tearDown(self) -> None:
        try:
            self.store.close()
        except Exception:  # pragma: no cover - defensive
            pass
        self._tmp.cleanup()

    def token_for(self, cls: str, value: str) -> str:
        """Выдать код значению той же фабрикой, что и конвейер.

        У класса «D» отдельного нормализатора нет (в конвейере дату делит
        ``split_birth_date``): идентичность — день и месяц, год остаётся открытым.
        """
        seed = split_birth_date(value)[0] if cls == "D" else normalize(cls, value)
        return make_token(cls, seed, b"t" * 32)


class IncidentRecordTests(IncidentJournalBase):
    def test_incident_is_recorded_with_classes_and_numbers(self) -> None:
        """Сценарий 1: время, канал, класс, действие, выданный код и счётчики."""
        code = self.token_for("P", FIO)
        self.store.store(code, "P", FIO)
        event = IncidentEvent(
            cls="P",
            action="degraded_tokenized",
            channel="mattermost",
            code=code,
            findings=2,
            replacements=2,
            rule="rules",
        )
        # assertLogs выставляет уровень сам: маркер попадает в перехват без правки
        # глобального logging (тот же приём, что в тестах повторной идентификации).
        with self.assertLogs("IncidentJournal", level="INFO") as captured:
            result = self.journal.record(event, codes=[("P", code)], store=self.store)
        self.assertTrue(result["written"])
        self.assertEqual(result["marked"], 1)

        records = self.journal.read_week("current")
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(
            sorted(record),
            sorted(
                ["ts", "channel", "class", "action", "code", "findings", "replacements", "rule"]
            ),
        )
        self.assertEqual(record["class"], "P")
        self.assertEqual(record["action"], "degraded_tokenized")
        self.assertEqual(record["channel"], "mattermost")
        self.assertEqual(record["code"], code)
        self.assertEqual(record["findings"], 2)
        self.assertEqual(record["replacements"], 2)
        self.assertEqual(record["rule"], "rules")
        parsed = datetime.datetime.fromisoformat(record["ts"])
        self.assertEqual(parsed.tzinfo, datetime.timezone.utc)
        self.assertTrue(
            any(
                "[IncidentJournal][record][BLOCK_RECORD_INCIDENT]" in message
                for message in captured.output
            ),
            msg=str(captured.output),
        )
        # Действие из машинного списка, а не свободный текст.
        self.assertIn(record["action"], ACTIONS)


class IncidentNoValueTests(IncidentJournalBase):
    def test_no_value_reaches_the_journal_for_any_class(self) -> None:
        """Сценарий 2: поиск инцидентного значения по файлу журнала не даёт совпадений."""
        for cls, value in SAMPLE_BY_CLASS.items():
            code = self.token_for(cls, value)
            self.store.store(code, cls, value)
            self.journal.record(
                IncidentEvent(
                    cls=cls,
                    action="degraded_tokenized",
                    channel="mattermost",
                    code=code,
                    findings=1,
                    replacements=1,
                    rule="names",
                ),
                codes=[(cls, code)],
                store=self.store,
            )
            self.assertFalse(
                self.journal.contains_any([value]),
                msg=f"значение класса {cls} попало в файл журнала инцидентов",
            )
            self.assertFalse(
                self.journal.contains_any([value.lower(), value.split()[0]]),
                msg=f"часть значения класса {cls} попала в файл журнала инцидентов",
            )
        self.assertEqual(len(self.journal.read_week("current")), len(SAMPLE_BY_CLASS))
        # Журнал хранит ровно 0600: разбор инцидента не должен быть доступен соседям.
        for name in os.listdir(incident_dir(self.root)):
            mode = stat.S_IMODE(os.stat(os.path.join(incident_dir(self.root), name)).st_mode)
            self.assertEqual(mode & 0o077, 0, msg=f"{name} доступен группе или остальным")


class IncidentMisuseTests(IncidentJournalBase):
    def test_text_instead_of_a_class_is_rejected(self) -> None:
        """Сценарий 3: текст или значение на месте класса отвергается кодом INCIDENT_VALUE_REQUIRED."""
        cases = (
            IncidentEvent(cls=FIO, action="blocked"),
            IncidentEvent(cls="P", action="блокировка запроса"),
            IncidentEvent(cls="P", action="blocked", channel="личный чат владельца"),
            IncidentEvent(cls="P", action="blocked", rule="клиентский контекст"),
            IncidentEvent(cls="P", action="blocked", code=FIO),
        )
        for event in cases:
            with self.subTest(event=event):
                with self.assertRaises(IncidentError) as ctx:
                    self.journal.record(event)
                self.assertEqual(ctx.exception.code, "INCIDENT_VALUE_REQUIRED")
        self.assertEqual(self.journal.read_week("current"), [])


class IncidentUnwritableTests(IncidentJournalBase):
    def test_unwritable_journal_keeps_protection_and_counts_unwritten(self) -> None:
        """Сценарий 4: сбой записи не отменяет защиту, но инцидент считается незаписанным."""
        blocked_path = os.path.join(self.root, "incidents-is-a-file")
        with open(blocked_path, "w", encoding="utf-8") as handle:
            handle.write("not a directory\n")
        journal = IncidentJournal(blocked_path, audit=self.audit)
        with self.assertLogs("IncidentJournal", level="INFO") as captured:
            result = journal.record(
                IncidentEvent(cls="P", action="blocked", channel="mattermost", findings=1)
            )
        self.assertFalse(result["written"])
        self.assertEqual(journal.unwritten, 1)
        self.assertTrue(
            any("INCIDENT_LOG_UNWRITABLE" in message for message in captured.output),
            msg=str(captured.output),
        )
        # Недельный счётчик незаписанных виден в журнале аудита: файла инцидентов для него
        # может не быть вовсе.
        audit_records = self.audit.export_for_regulator()
        self.assertEqual(
            [record["action"] for record in audit_records], ["journal_write_failed"]
        )
        self.assertEqual(audit_records[0]["reason"], "incident_log_unwritable")

    def test_service_with_unwritable_journal_still_blocks_and_does_not_leak(self) -> None:
        """Сценарий 4 (сквозной): заслон нашёл остаток, но замена недоступна — блокировка.

        Дублёр заслона воспроизводит промах детектора и не умеет второго прохода: это и
        есть случай «остаток заменить не удалось», в котором Вариант 1 обязан промолчать,
        а жёсткая блокировка — сработать. Сбой самого журнала инцидентов защиту не
        отменяет: значение никуда не ушло, а инцидент попал в счётчик незаписанных.
        """
        blocked_path = os.path.join(self.root, "incidents-is-a-file")
        with open(blocked_path, "w", encoding="utf-8") as handle:
            handle.write("not a directory\n")
        config = harness.temp_config(self.root)
        upstream = harness.FakeUpstream()
        journal = IncidentJournal(blocked_path, audit=self.audit)
        service = build_service(
            config,
            store=self.store,
            upstream=upstream,
            audit=self.audit,
            validator=ResidualWithoutReplacement(),
            incident_journal=journal,
        )
        payload = {
            "model": "deepseek-flash",
            "stream": False,
            "messages": [{"role": "system", "content": f"Клиент {FIO}, телефон {PHONE}."}],
        }
        with self.assertLogs("IncidentJournal", level="INFO"):
            with self.assertRaises(RouterError) as ctx:
                service.handle_chat_completions(payload, "ds", CHAT_PATH, "mattermost")
        # Дефект 19.09.2026: отказ заслона — 422, а не 403. Клиент читал 403 как
        # «провайдер отклонил ключ» и искал причину в ключе вместо остатка ПД.
        self.assertEqual(ctx.exception.status, 422)
        self.assertEqual(ctx.exception.code, "residual_pii")
        self.assertEqual(upstream.calls, [])
        self.assertEqual(journal.unwritten, 1)
        self.assertFalse(journal.contains_any([FIO, PHONE]))
        self.assertFalse(self.audit.contains_any([FIO, PHONE]))


class IncidentDegradedTests(IncidentJournalBase):
    """Стык шагов 1 и 2 (Phase-15): деградация видна в обоих журналах, значений нет нигде."""

    def build_degraded_service(self, upstream):
        """Собрать службу с воспроизводимым промахом детектора на ФИО."""
        from src.detect_name import NameDetector
        from src.dictionary import PiiDictionary

        config = harness.temp_config(self.root)
        dictionary = PiiDictionary(config.dictionary_path, key=config.dictionary_key)
        tokenizer = harness.MissOneValueTokenizer(
            config.token_key,
            self.store,
            NameDetector(dictionary),
            audit=self.audit,
            missed=FIO,
        )
        service = build_service(
            config,
            store=self.store,
            upstream=upstream,
            audit=self.audit,
            incident_journal=self.journal,
            tokenizer=tokenizer,
        )
        return service, tokenizer

    def test_degraded_incident_reaches_both_journals_without_values(self) -> None:
        """Сценарий стыка: остаток заменён вторым проходом, инцидент записан без значений."""
        upstream = harness.EchoUpstream()
        service, tokenizer = self.build_degraded_service(upstream)
        payload = {
            "model": "deepseek-flash",
            "stream": False,
            "messages": [{"role": "system", "content": f"Клиент {FIO}, телефон {PHONE}."}],
        }
        status, body = service.handle_chat_completions(payload, "ds", CHAT_PATH, "mattermost")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(tokenizer.dropped, 1, msg="промах детектора не воспроизведён")
        self.assertIn(FIO, body["choices"][0]["message"]["content"])

        records = self.journal.read_week("current")
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["action"], "degraded_tokenized")
        self.assertEqual(record["channel"], "mattermost")
        self.assertEqual(record["class"], "P")
        self.assertEqual(record["findings"], 1)
        self.assertEqual(record["replacements"], 1)
        self.assertEqual(record["rule"], "names")
        # Выданный код — идентификатор, а не значение, и он же стоит в запросе, ушедшем наверх.
        self.assertIn(record["code"], upstream.serialized_payload())
        self.assertEqual(self.store.values_by_source(INCIDENT_SOURCE), [(record["code"], "P", FIO)])
        self.assertEqual(self.store.source_counts().get(INCIDENT_SOURCE), 1)

        audit_actions = {event["action"] for event in self.audit.export_for_regulator()}
        self.assertTrue(
            {"degraded_tokenized", "tokenized"} <= audit_actions, msg=str(sorted(audit_actions))
        )
        for needle in (FIO, PHONE, FIO.lower()):
            self.assertFalse(self.journal.contains_any([needle]), msg=needle)
            self.assertFalse(self.audit.contains_any([needle]), msg=needle)
        self.assertFalse(self.store.raw_file_contains(FIO))


class IncidentWeekTests(IncidentJournalBase):
    def test_weekly_rotation_reads_exactly_its_own_file(self) -> None:
        """Сценарий 5: чтение за неделю собирает ровно свой файл, счётчики сходятся."""
        now = datetime.datetime(2026, 9, 19, 12, 0, tzinfo=datetime.timezone.utc).timestamp()
        previous = now - 7 * 86400
        for index in range(2):
            self.journal.record(
                IncidentEvent(
                    cls="P", action="blocked", channel="mattermost", findings=1, ts=previous + index
                )
            )
        for index in range(3):
            self.journal.record(
                IncidentEvent(
                    cls="T",
                    action="degraded_tokenized",
                    channel="telegram",
                    code=self.token_for("T", PHONE),
                    findings=1,
                    replacements=1,
                    ts=now + index,
                )
            )
        current_key = IncidentJournal.week_key(now)
        previous_key = IncidentJournal.week_key(previous)
        self.assertNotEqual(current_key, previous_key)
        self.assertEqual(
            os.path.basename(IncidentJournal.week_file(self.root, current_key)),
            f"incidents-{current_key}.jsonl",
        )

        current = self.journal.read_week("current", now=now)
        previous_records = self.journal.read_week("previous", now=now)
        self.assertEqual(len(current), 3)
        self.assertEqual(len(previous_records), 2)
        self.assertEqual(self.journal.read_week(previous_key, now=now), previous_records)
        counts = self.journal.counts(previous_records)
        self.assertEqual(counts["total"], 2)
        self.assertEqual(counts["by_action"], {"blocked": 2})
        self.assertEqual(counts["by_channel"], {"mattermost": 2})
        self.assertEqual(counts["findings"], 2)
        self.assertEqual(counts["replacements"], 0)
        current_counts = self.journal.counts(current)
        self.assertEqual(current_counts["by_class"], {"T": 3})
        self.assertEqual(current_counts["replacements"], 3)


class IncidentStoreTests(IncidentJournalBase):
    def test_incident_value_is_stored_marked_and_encrypted_with_the_usual_ttl(self) -> None:
        """Сценарий 6: пометка «из инцидента», обычный TTL, читаемых значений в файле нет."""
        code = self.token_for("P", FIO)
        self.store.store(code, "P", FIO)
        self.journal.record(
            IncidentEvent(
                cls="P",
                action="degraded_tokenized",
                channel="mattermost",
                code=code,
                findings=1,
                replacements=1,
            ),
            codes=[("P", code)],
            store=self.store,
        )
        self.assertEqual(self.store.values_by_source(INCIDENT_SOURCE), [(code, "P", FIO)])
        self.assertEqual(self.store.source_counts().get(INCIDENT_SOURCE), 1)
        self.assertFalse(self.store.raw_file_contains(FIO))
        self.assertEqual(json.loads(self.store.dumps_metadata())["ttl_days"], 90)
        # TTL обычный: значение живёт 90 дней и дальше чистится вместе с остальными.
        self.assertEqual(self.store.purge_expired(now=time.time() - 86400), 0)
        self.assertEqual(self.store.purge_expired(now=time.time() + 91 * 86400), 1)
        self.assertEqual(self.store.values_by_source(INCIDENT_SOURCE), [])


if __name__ == "__main__":
    unittest.main()
# END_BLOCK_TEST_INCIDENT_JOURNAL
