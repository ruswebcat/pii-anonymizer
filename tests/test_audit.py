# FILE: tests/test_audit.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-AUDIT contract: closed schema, counters, block recording with alerts, and proof that no PII value can reach the journal.
#   SCOPE: valid append, schema rejection, tokenization events, block events, alert callback, metrics, regulator export.
#   DEPENDS: M-AUDIT
#   LINKS: V-M-AUDIT, M-AUDIT
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   AuditTests - unittest case set for AuditJournal
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-1 M-AUDIT verification.
# END_CHANGE_SUMMARY

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.audit import AuditError, AuditEvent, AuditJournal  # noqa: E402


class AuditTests(unittest.TestCase):
    def _journal(self, tmpdir: str, alerts: list | None = None) -> AuditJournal:
        sender = alerts.append if alerts is not None else None
        return AuditJournal(os.path.join(tmpdir, "audit.jsonl"), alert_sender=sender)

    def test_valid_event_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            journal = self._journal(tmpdir)
            journal.append(AuditEvent(session_id="s1", action="tokenized", cls="P", count=3))
            records = journal.export_for_regulator()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["cls"], "P")
        self.assertEqual(records[0]["count"], 3)

    def test_unknown_action_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            journal = self._journal(tmpdir)
            with self.assertRaises(AuditError) as ctx:
                journal.append(AuditEvent(session_id="s1", action="leaked"))
        self.assertEqual(ctx.exception.code, "AUDIT_BAD_ACTION")

    def test_unknown_reason_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            journal = self._journal(tmpdir)
            with self.assertRaises(AuditError) as ctx:
                journal.append(
                    AuditEvent(session_id="s1", action="blocked", reason="Иванов Сергей")
                )
        self.assertEqual(ctx.exception.code, "AUDIT_BAD_REASON")

    def test_multi_letter_class_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            journal = self._journal(tmpdir)
            with self.assertRaises(AuditError) as ctx:
                journal.append(AuditEvent(session_id="s1", action="tokenized", cls="PP"))
        self.assertEqual(ctx.exception.code, "AUDIT_BAD_CLASS")

    def test_tokenization_stats_become_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            journal = self._journal(tmpdir)
            written = journal.record_tokenization("s1", {"P": 2, "T": 1, "C": 0})
            snapshot = journal.metrics_snapshot()
        self.assertTrue(written)
        self.assertEqual(snapshot["actions"]["tokenized"], 2)
        self.assertEqual(snapshot["classes"]["P"], 2)

    def test_block_records_reason_and_alerts(self) -> None:
        alerts: list = []
        with tempfile.TemporaryDirectory() as tmpdir:
            journal = self._journal(tmpdir, alerts)
            journal.record_block("s1", "residual_pii", channel="telegram", cls="T")
        self.assertEqual(len(alerts), 1)
        self.assertIn("residual_pii", alerts[0])
        self.assertNotIn("79000000001", alerts[0])

    def test_image_block_uses_dedicated_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            journal = self._journal(tmpdir)
            journal.record_block("s1", "images_blocked")
            records = journal.export_for_regulator()
        self.assertEqual(records[0]["action"], "image_blocked")

    def test_journal_never_contains_values(self) -> None:
        secrets = ["Иванов Иван Иванович", "79000000001", "client@example.ru"]
        with tempfile.TemporaryDirectory() as tmpdir:
            journal = self._journal(tmpdir)
            journal.record_tokenization("s1", {"P": 1, "T": 1, "E": 1})
            journal.record_block("s1", "residual_pii", cls="E")
            self.assertFalse(journal.contains_any(secrets))
            self.assertFalse(any(secret in str(journal.export_for_regulator()) for secret in secrets))

    def test_metrics_snapshot_reports_size(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            journal = self._journal(tmpdir)
            journal.record_tokenization("s1", {"T": 1})
            snapshot = journal.metrics_snapshot()
        self.assertGreater(snapshot["journal_bytes"], 0)
        self.assertEqual(snapshot["events"], 1)

    def test_unknown_direction_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            journal = self._journal(tmpdir)
            with self.assertRaises(AuditError) as ctx:
                journal.append(
                    AuditEvent(session_id="s1", action="tokenized", direction="sideways")
                )
        self.assertEqual(ctx.exception.code, "AUDIT_BAD_DIRECTION")


if __name__ == "__main__":
    unittest.main()
