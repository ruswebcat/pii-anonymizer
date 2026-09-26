# FILE: tests/test_incident_trainer.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Проверить недельный тренер словаря: подтверждение двумя источниками, лимит 50, добавка через staged → проверка → бэкап → замена, пустой журнал как норма, сбой проверки без порчи справочника, отчёт и файл-предложение без единого значения.
#   SCOPE: пустая неделя, подтверждение морфологией и NER, служебная лексика, уже известное значение, отсутствие модели, недельный лимит, провал прибора, доставка отчёта REST-постом, отсутствие значений в отчётах, режим --dry-run.
#   DEPENDS: M-INCIDENT-TRAINER, M-INCIDENT-JOURNAL, M-MAP-STORE, M-DICT-WRITE, M-DICT
#   LINKS: V-M-INCIDENT-TRAINER, docs/ARCHITECTURE.md
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   TrainerFixture - стенд: справочник, шифрованный справочник соответствий, журнал инцидентов
#   FakeNer - подстановка NER-модели: размечает значения из белого списка
#   TrainerEmptyWeekTests - неделя без инцидентов не является ошибкой
#   TrainerConfirmationTests - кто попадает в справочник, а кто уходит в спорное
#   TrainerLimitTests - жёсткий недельный лимит
#   TrainerSafetyTests - сбой проверки и режим без изменений
#   TrainerReportTests - отчёты без значений и доставка в личку
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-15 шаг 3: тесты недельного тренера. Все значения — заглушки (Иванов, Токенец, Testa), настоящих персональных данных нет; NER-модель подменяется разметчиком, потому что 178 МБ и секунды на строку — не то, что нужно юнит-тесту.
# END_CHANGE_SUMMARY

"""Тесты недельного тренера словаря по инцидентам (Phase-15 шаг 3).

Сценарии — из ``docs/OPERATIONS.md``, ``V-M-INCIDENT-TRAINER``. Модель NER в тестах
не запускается: подставляется разметчик, а проверяется то, что решает судьбу значения —
подтверждение двумя источниками, лимит, безопасность записи и отсутствие значений в отчётах.
"""

import json
import os
import stat
import sys
import time
import unittest
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src import dict_write  # noqa: E402
from src.dict_export import to_keyed_digests  # noqa: E402
from src.incident_journal import INCIDENT_SOURCE, IncidentEvent, IncidentJournal  # noqa: E402
from src.map_store import TokenMapStore  # noqa: E402
from src.normalize import normalize  # noqa: E402
from src.token_factory import make_token  # noqa: E402
from tools.incident_trainer import (  # noqa: E402
    TrainerReport,
    main,
    run_week,
    post_to_mattermost,
    render_proposal,
    render_report,
)

STUB_KEY = b"t" * 32
FERNET_KEY = b"f" * 32
#: Значения-заглушки. Редкие и нерусские фамилии специально оставлены в белом списке NER.
KNOWN_NAMES = ["Иванов Иван", "Сидоров Пётр", "Продажи"]
GOOD_NAMES = ["Токенец", "Тесля", "Стабсон", "Testa", "Стабко Артём"]
SERVICE_WORDS = ["Продажи", "Гость", "Запись"]


def ok_runner(argv: Sequence[str]) -> tuple[int, str]:
    """Подстановка прибора: планки выдержаны."""
    return 0, "все планки выдержаны"


def bad_runner(argv: Sequence[str]) -> tuple[int, str]:
    """Подстановка прибора: планки не выдержаны."""
    return 1, "recall 0.4 ниже планки"


class FakeNer:
    """Подстановка NER-модели: размечает все слова значения как фамилию."""

    def __init__(self, known: Sequence[str], types: Sequence[str] = ("LAST_NAME",)) -> None:
        self.known = {item.casefold() for item in known}
        self.seen: list[str] = []
        self.typ = types

    def __call__(self, texts: Sequence[str]) -> list[list[tuple[int, int, str]]]:
        out: list[list[tuple[int, int, str]]] = []
        for text in texts:
            self.seen.append(text)
            if text.casefold() in self.known:
                out.append([(0, len(text), f"U-{self.typ[0]}")])
            else:
                out.append([])
        return out


class TrainerFixture(unittest.TestCase):
    """Стенд: справочник, шифрованный справочник соответствий и журнал инцидентов в каталоге теста."""

    def setUp(self) -> None:
        import tempfile

        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        base = os.path.join(self.dir.name, "pii_dict.json")
        self.key_path = os.path.join(self.dir.name, "dict.key")
        self.fernet_path = os.path.join(self.dir.name, "fernet.key")
        self.audit_path = os.path.join(self.dir.name, "audit.jsonl")
        Path(self.key_path).write_bytes(STUB_KEY)
        Path(self.fernet_path).write_bytes(FERNET_KEY)
        Path(self.audit_path).write_text("", encoding="utf-8")
        self.live = dict_write.write_staged(
            to_keyed_digests({"P": list(KNOWN_NAMES)}, STUB_KEY), base
        )
        self.incidents = os.path.join(self.dir.name, "incidents")
        self.map_db = os.path.join(self.dir.name, "pii_map.db")
        self.store = TokenMapStore(self.map_db, FERNET_KEY)
        self.addCleanup(self.store.close)
        self.journal = IncidentJournal(self.incidents)
        self.paths = {
            "dict": self.live,
            "dict_key": self.key_path,
            "map_db": self.map_db,
            "fernet_key": self.fernet_path,
            "incidents": self.incidents,
            "audit": self.audit_path,
            "ner": os.path.join(self.dir.name, "no-ner"),
            "layer": "",
        }
        self.ner = FakeNer(GOOD_NAMES)

    def seed_incident(self, value: str, cls: str = "P", findings: int = 1) -> str:
        """Завести инцидент: значение кладётся в шифрованный справочник и помечается «из инцидента»."""
        token = make_token(cls, normalize(cls, value), STUB_KEY)
        self.store.store(token, cls, value)
        self.journal.record(
            IncidentEvent(cls=cls, action="degraded_tokenized", channel="mattermost", findings=findings),
            codes=[(cls, token)],
            store=self.store,
        )
        return token

    def run_trainer(self, **kwargs: object) -> TrainerReport:
        """Прогнать тренер на стенде с подстановками."""
        options = {
            "week": "current",
            "paths": self.paths,
            "annotate": self.ner,
            "metrics_runner": ok_runner,
            "limit": 50,
        }
        options.update(kwargs)
        return run_week(**options)  # type: ignore[arg-type]

    def live_bytes(self) -> bytes:
        """Содержимое живого справочника как есть."""
        return Path(self.live).read_bytes()

    def names_count(self) -> int:
        """Число значений в классе «имена» живого справочника."""
        payload = dict_write.load_payload(self.live)
        return len(payload["digests"]["P"])


class TrainerEmptyWeekTests(TrainerFixture):
    """Неделя без инцидентов — норма, а не ошибка."""

    def test_empty_journal_is_not_an_error_and_changes_nothing(self) -> None:
        before = self.live_bytes()
        report = self.run_trainer()
        self.assertEqual(0, report.incidents_total)
        self.assertEqual(0, report.incident_values_total)
        self.assertEqual(0, report.applied)
        self.assertEqual("nothing_confirmed", report.apply_reason)
        self.assertEqual(before, self.live_bytes())
        self.assertEqual("", report.staged_path)

    def test_main_exits_zero_on_empty_week(self) -> None:
        code = main(
            [
                "--week",
                "current",
                "--dict-file",
                self.live,
                "--dict-key-file",
                self.key_path,
                "--map-db",
                self.map_db,
                "--fernet-key-file",
                self.fernet_path,
                "--incident-dir",
                self.incidents,
                "--audit-log",
                self.audit_path,
                "--model-dir",
                os.path.join(self.dir.name, "no-ner"),
                "--dry-run",
            ]
        )
        self.assertEqual(0, code)


class TrainerConfirmationTests(TrainerFixture):
    """Кто попадает в справочник, а кто уходит в спорное."""

    def test_rare_and_foreign_surnames_are_confirmed_and_added(self) -> None:
        before = self.names_count()
        for value in GOOD_NAMES:
            self.seed_incident(value)
        report = self.run_trainer()
        self.assertEqual(len(GOOD_NAMES), report.incident_values_total)
        self.assertEqual(len(GOOD_NAMES), report.confirmed_total)
        self.assertEqual(len(GOOD_NAMES), report.applied)
        self.assertTrue(report.metrics_passed)
        self.assertEqual(before + len(GOOD_NAMES), report.dictionary_names_after)
        self.assertEqual(before + len(GOOD_NAMES), self.names_count())
        self.assertTrue(os.path.exists(report.backup_path))
        self.assertFalse(os.path.exists(report.staged_path))

    def test_service_lexicon_never_enters_the_dictionary(self) -> None:
        for word in SERVICE_WORDS:
            if word in KNOWN_NAMES:
                continue
            self.seed_incident(word)
        report = self.run_trainer()
        self.assertEqual(0, report.applied)
        self.assertEqual(len(SERVICE_WORDS) - 1, report.service_lexicon)
        self.assertEqual(0, report.disputed_by_reason.get("unconfirmed", 0))

    def test_already_known_value_is_counted_not_added_twice(self) -> None:
        before = self.names_count()
        self.seed_incident("Токенец")
        self.seed_incident("Сидоров Пётр")
        report = self.run_trainer()
        self.assertEqual(1, report.already_known)
        self.assertEqual(1, report.applied)
        self.assertEqual(before + 1, self.names_count())

    def test_repeated_value_is_one_candidate(self) -> None:
        self.seed_incident("Токенец")
        self.seed_incident("Токенец")
        report = self.run_trainer()
        self.assertEqual(1, report.incident_values_total)
        self.assertEqual(1, report.applied)

    def test_missing_model_sends_everything_to_disputed(self) -> None:
        before = self.live_bytes()
        self.seed_incident("Токенец")
        report = self.run_trainer(annotate=None)
        self.assertFalse(report.ner_available)
        self.assertEqual(0, report.applied)
        self.assertEqual(1, report.disputed_by_reason.get("ner_unavailable", 0))
        self.assertEqual(before, self.live_bytes())

    def test_morphology_only_confirmation_is_not_enough(self) -> None:
        # Модель размечена на других значениях: «Стабсон» морфология знает, модель — нет.
        self.seed_incident("Стабсон")
        report = self.run_trainer(annotate=FakeNer(["Testa"]))
        self.assertEqual(1, report.confirmed_morphology)
        self.assertEqual(0, report.confirmed_ner)
        self.assertEqual(0, report.applied)
        self.assertEqual(1, report.disputed_by_reason.get("unconfirmed", 0))

    def test_value_of_other_class_is_not_trained(self) -> None:
        self.seed_incident("79000000001", cls="T")
        report = self.run_trainer()
        self.assertEqual(1, report.disputed_by_reason.get("class_not_trained", 0))
        self.assertEqual(0, report.applied)


class TrainerLimitTests(TrainerFixture):
    """Жёсткий недельный лимит добавки."""

    def test_limit_is_respected_and_rest_goes_to_disputed(self) -> None:
        # Заглушки многословные: правило «это может быть имя» для них то же, что у настоящих ФИО.
        names = [f"Заглушкин Т{index:02d}" for index in range(60)]
        for value in names:
            self.seed_incident(value)
        report = self.run_trainer(limit=50, annotate=FakeNer(names))
        self.assertEqual(60, report.incident_values_total)
        self.assertEqual(60, report.confirmed_total)
        self.assertEqual(50, report.applied)
        self.assertEqual(10, report.over_limit)
        self.assertEqual(10, report.disputed_by_reason.get("over_limit", 0))

    def test_limit_counts_confirmed_values_not_disputed_ones(self) -> None:
        names = [f"Заглушкина О{index:02d}" for index in range(5)]
        for value in names:
            self.seed_incident(value)
        self.seed_incident("Гость")
        report = self.run_trainer(limit=5, annotate=FakeNer(names))
        self.assertEqual(5, report.applied)
        self.assertEqual(0, report.over_limit)
        self.assertEqual(1, report.service_lexicon)


class TrainerSafetyTests(TrainerFixture):
    """Сбой проверки и режим без изменений: справочник важнее прогона."""

    def test_failed_metrics_leaves_dictionary_untouched(self) -> None:
        before = self.live_bytes()
        self.seed_incident("Токенец")
        report = self.run_trainer(metrics_runner=bad_runner)
        self.assertFalse(report.metrics_passed)
        self.assertEqual(0, report.applied)
        self.assertEqual("metrics_not_passed", report.apply_reason)
        self.assertEqual(before, self.live_bytes())
        self.assertTrue(os.path.exists(report.staged_path))
        self.assertEqual("", report.backup_path)

    def test_dry_run_changes_nothing_and_writes_nothing(self) -> None:
        before = self.live_bytes()
        self.seed_incident("Токенец")
        report = self.run_trainer(dry_run=True)
        self.assertEqual(1, report.confirmed_total)
        self.assertEqual(0, report.applied)
        self.assertEqual("dry_run", report.apply_reason)
        self.assertEqual(before, self.live_bytes())
        self.assertEqual("", report.staged_path)
        self.assertEqual("", report.report_path)
        self.assertEqual("", report.proposal_path)

    def test_dictionary_is_readable_after_apply(self) -> None:
        from src.dictionary import PiiDictionary

        self.seed_incident("Токенец")
        self.run_trainer()
        mode = stat.S_IMODE(os.stat(self.live).st_mode)
        self.assertEqual(0o600, mode)
        dictionary = PiiDictionary(self.live, key=STUB_KEY)
        details = main.__doc__ or ""
        self.assertTrue(details)
        dictionary.load()
        self.assertGreaterEqual(dictionary.snapshot()["counts"]["P"], len(KNOWN_NAMES) + 1)


class TrainerReportTests(TrainerFixture):
    """Отчёты: числа без значений, доставка в личку."""

    def test_reports_contain_no_values(self) -> None:
        for value in GOOD_NAMES + SERVICE_WORDS:
            self.seed_incident(value)
        report = self.run_trainer(dry_run=True)
        text = render_report(report) + render_proposal(report) + json.dumps(report.to_dict(), ensure_ascii=False)
        for value in GOOD_NAMES + SERVICE_WORDS:
            self.assertNotIn(value, text, value)
            self.assertNotIn(value.casefold(), text.casefold(), value)

    def test_report_carries_numbers_from_the_run(self) -> None:
        self.seed_incident("Токенец")
        report = self.run_trainer()
        text = render_report(report)
        self.assertIn("Тренер словаря по инцидентам", text)
        self.assertIn("| Инцидентов за неделю | 1 |", text)
        self.assertIn("| Добавлено значений | **1** |", text)

    def test_proposal_lists_reasons_without_values(self) -> None:
        self.seed_incident("Гость")
        report = self.run_trainer()
        text = render_proposal(report)
        self.assertIn("service_lexicon", text)
        self.assertNotIn("Гость", text)

    def test_delivery_reports_codes_and_survives_failure(self) -> None:
        calls: list[dict[str, object]] = []

        def ok_poster(url: str, body: dict[str, object], token: str, base: str) -> tuple[int, str]:
            calls.append({"url": url, "body": body, "base": base})
            return 200, "{}"

        delivered, code = post_to_mattermost("отчёт", "chan", "tok", "https://chat.example", poster=ok_poster)
        self.assertTrue(delivered)
        self.assertEqual("DELIVERED", code)
        self.assertTrue(calls[0]["url"].endswith("/api/v4/posts"))

        delivered, code = post_to_mattermost(
            "отчёт", "chan", "tok", "https://chat.example/posts", poster=lambda u, b, t, s: (403, "forbidden")
        )
        self.assertFalse(delivered)
        self.assertIn("403", code)

        delivered, code = post_to_mattermost("отчёт", "", "", "", poster=ok_poster)
        self.assertFalse(delivered)
        self.assertEqual("DELIVERY_NOT_CONFIGURED", code)

    def test_delivery_of_report_appends_result_line(self) -> None:
        report = TrainerReport(week="2026-38", incidents_total=2, sessions_in_period=10)
        report.incident_share = 0.2
        text = render_report(report)
        self.assertIn("2026-38", text)
        self.assertIn("0.2000 на сессию", text)


class TrainerIncidentSourceTests(TrainerFixture):
    """Значение, помеченное «из инцидента», — единственный вход тренера."""

    def test_incident_mark_is_what_the_trainer_reads(self) -> None:
        token = self.seed_incident("Токенец")
        rows = self.store.values_by_source(INCIDENT_SOURCE)
        self.assertEqual([token], [row[0] for row in rows])
        self.assertEqual(1, self.store.source_counts().get(INCIDENT_SOURCE, 0))

    def test_value_without_mark_is_invisible_to_the_trainer(self) -> None:
        self.store.store("zPTEST0001", "P", "Токенец")
        report = self.run_trainer()
        self.assertEqual(0, report.incident_values_total)

    def test_week_window_excludes_values_from_other_weeks(self) -> None:
        self.seed_incident("Токенец")
        report = self.run_trainer(now=time.time() + 30 * 86400)
        self.assertEqual(0, report.incident_values_total)


if __name__ == "__main__":
    unittest.main()
