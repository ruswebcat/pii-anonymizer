# FILE: tests/test_registry_integrity.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the registry invariant of M-MAP-STORE (Phase-17): a code means exactly one value and exactly one person — the service refuses to run otherwise, and the incident carries no values.
#   SCOPE: clean registry scan, forced two-values-under-one-code file, ambiguous forms with an identity resolver, fail-closed require_integrity, restore-time refusal of an ambiguous code, incident content.
#   DEPENDS: M-MAP-STORE, M-DETOKENIZER, M-INCIDENT-JOURNAL
#   LINKS: V-M-MAP-STORE, V-M-DETOKENIZER, V-M-INCIDENT-JOURNAL
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   RegistryIntegrityTests - инвариант реестра и отказ доверенной границы
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-17 (20.09.2026): регрессия на инвариант «код значит ровно одно значение», отказ службы при многозначности и запись инцидента без значений.
# END_CHANGE_SUMMARY

import base64
import json
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.fernet import Fernet  # noqa: E402

from src.audit import AuditJournal  # noqa: E402
from src.channel_policy import ChannelPolicy  # noqa: E402
from src.detokenizer import PayloadDetokenizer  # noqa: E402
from src.incident_journal import IncidentJournal  # noqa: E402
from src.map_store import MapStoreError, TokenMapStore  # noqa: E402
from src.token_factory import canonical_token, make_token  # noqa: E402

TOKEN_KEY = b"registry-integrity-token-key-32b!"
FERNET_KEY = b"f" * 32
#: Две персоны для резолвера идентичности: значения синтетические.
PERSONS = {"иванов": "pd:person-one", "петров": "pd:person-two"}


def person_of(value: str) -> str | None:
    """Резолвер персоны: узнаёт две выдуманные фамилии, остальных не называет."""
    return PERSONS.get(str(value or "").strip().lower())


def _fern_key() -> bytes:
    """Ключ шифрования справочника в том виде, в каком его строит M-MAP-STORE."""
    return base64.urlsafe_b64encode(FERNET_KEY[:32].ljust(32, b"\0"))


class RegistryIntegrityTests(unittest.TestCase):
    """Реестр обязан быть однозначным: проверка, отказ, инцидент."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "pii_map.db")
        self.store = TokenMapStore(self.db_path, fernet_key=FERNET_KEY)

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    # --- 1. чистый реестр -------------------------------------------------
    def test_clean_registry_passes_the_scan(self) -> None:
        code = make_token("P", "иванов", TOKEN_KEY)
        self.store.store(code, "P", "Иванов", "pd:person-one")
        report = self.store.scan_integrity(person_of)
        self.assertEqual(report.records, 1)
        self.assertEqual(report.codes, 1)
        self.assertEqual(report.ambiguous, 0)
        self.assertEqual(self.store.require_integrity(person_of).ambiguous, 0)

    def test_forms_of_one_person_are_not_ambiguous(self) -> None:
        code = make_token("P", "иванов", TOKEN_KEY)
        self.store.store(code, "P", "Иванов", "pd:person-one")
        self.store.append_form(code, "Иванова")
        self.store.append_form(code, "Иванову")
        report = self.store.scan_integrity(person_of)
        self.assertEqual(report.ambiguous, 0)
        self.assertEqual(report.checked_identities, 1)

    # --- 2. два значения под одним кодом ----------------------------------
    def _force_two_values_under_one_code(self, token: str) -> None:
        """Сломать реестр так, как его ломает порча файла: два значения под одним кодом.

        Схема запрещает это первичным ключом, поэтому в тесте таблица пересобирается без
        него — ровно то, что увидел бы оператор после ручной правки или слияния файлов.
        """
        self.store.close()
        connection = sqlite3.connect(self.db_path)
        fernet = Fernet(_fern_key())
        try:
            connection.execute("DROP TABLE token_map")
            connection.execute(
                "CREATE TABLE token_map (token TEXT, cls TEXT, value_enc BLOB, created_at REAL,"
                " last_used_at REAL, identity_enc BLOB, forms_enc BLOB, source TEXT)"
            )
            for value in ("Иванов", "Петров"):
                connection.execute(
                    "INSERT INTO token_map (token, cls, value_enc, created_at, last_used_at,"
                    " identity_enc, forms_enc) VALUES (?, 'P', ?, 0, 0, NULL, ?)",
                    (
                        token,
                        fernet.encrypt(value.encode("utf-8")),
                        fernet.encrypt(json.dumps([value]).encode("utf-8")),
                    ),
                )
            connection.commit()
        finally:
            connection.close()
        self.store = TokenMapStore(self.db_path, fernet_key=FERNET_KEY)

    def test_two_values_under_one_code_make_the_service_refuse(self) -> None:
        token = make_token("P", "иванов", TOKEN_KEY)
        self._force_two_values_under_one_code(token)
        report = self.store.scan_integrity(person_of)
        # Одним кодом названы и два значения, и две персоны: оба признака обязаны быть видны.
        self.assertEqual(report.value_conflicts, 1)
        self.assertEqual(report.ambiguous_codes, (token,))
        self.assertEqual(report.ambiguous, 2)
        self.assertEqual(self.store.record_ambiguity(token, person_of), 2)
        with self.assertRaises(MapStoreError) as ctx:
            self.store.require_integrity(person_of)
        self.assertEqual(ctx.exception.code, "MAP_AMBIGUOUS_CODE")

    def test_ambiguous_forms_of_two_persons_make_the_service_refuse(self) -> None:
        code = make_token("P", "иванов", TOKEN_KEY)
        self.store.store(code, "P", "Иванов", "pd:person-one")
        # Форма чужой персоны под тем же кодом: ровно тот случай, ради которого заслон есть.
        self.store.append_form(code, "Петров")
        report = self.store.scan_integrity(person_of)
        self.assertEqual(report.ambiguous_codes, (code,))
        with self.assertRaises(MapStoreError):
            self.store.require_integrity(person_of)

    def test_report_carries_codes_and_numbers_but_no_values(self) -> None:
        code = make_token("P", "иванов", TOKEN_KEY)
        self.store.store(code, "P", "Иванов", "pd:person-one")
        self.store.append_form(code, "Петров")
        report = self.store.scan_integrity(person_of)
        self.assertEqual(report.ambiguous_codes, (code,))
        rendered = json.dumps(report.to_dict(), ensure_ascii=False)
        self.assertIn('"ambiguous_codes": 1', rendered.replace(" ", " "))
        self.assertNotIn("Иванов", rendered)
        self.assertNotIn("Петров", rendered)

    # --- 3. отказ восстановления при многозначности ------------------------
    def _detokenizer(self, incidents: IncidentJournal) -> PayloadDetokenizer:
        return PayloadDetokenizer(
            self.store,
            ChannelPolicy({"local"}),
            AuditJournal(os.path.join(self.tmp.name, "audit.jsonl")),
            identity_of=person_of,
            incident=incidents,
        )

    def test_ambiguous_code_is_not_restored_and_an_incident_is_written(self) -> None:
        code = make_token("P", "иванов", TOKEN_KEY)
        self._force_two_values_under_one_code(code)
        incidents = IncidentJournal(os.path.join(self.tmp.name, "incidents"))
        detokenizer = self._detokenizer(incidents)
        text, counters = detokenizer.detokenize_text(
            f"Анкета: {code}", "local", "s-1", {canonical_token(code)}
        )
        # Значение не выдумано: код остался кодом.
        self.assertIn(code, text)
        self.assertNotIn("Иванов", text)
        self.assertEqual(counters["ambiguous"], 1)
        self.assertEqual(detokenizer.counters()["ambiguous_kept"], 1)
        records = incidents.read_week("current") or incidents.read_week("previous")
        self.assertTrue(records, "инцидент обязан быть записан")
        self.assertEqual(records[-1]["action"], "ambiguous_kept")
        self.assertEqual(records[-1]["code"], canonical_token(code))
        self.assertNotIn("Иванов", json.dumps(records, ensure_ascii=False))
        self.assertNotIn("Петров", json.dumps(records, ensure_ascii=False))

    def test_unambiguous_code_still_restores(self) -> None:
        code = make_token("P", "иванов", TOKEN_KEY)
        self.store.store(code, "P", "Иванов", "pd:person-one")
        incidents = IncidentJournal(os.path.join(self.tmp.name, "incidents"))
        detokenizer = self._detokenizer(incidents)
        text, counters = detokenizer.detokenize_text(
            f"Анкета: {code}", "local", "s-2", {canonical_token(code)}
        )
        self.assertIn("Иванов", text)
        self.assertEqual(counters["ambiguous"], 0)

    def test_ambiguous_code_in_tool_arguments_is_not_substituted(self) -> None:
        code = make_token("P", "иванов", TOKEN_KEY)
        self._force_two_values_under_one_code(code)
        incidents = IncidentJournal(os.path.join(self.tmp.name, "incidents"))
        detokenizer = self._detokenizer(incidents)
        payload = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {"function": {"name": "find", "arguments": '{"fio": "%s"}' % code}}
                        ]
                    }
                }
            ]
        }
        payload, counters = detokenizer.detokenize_tool_args(
            payload, "s-3", {canonical_token(code)}
        )
        arguments = payload["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
        self.assertIn(code, arguments)
        self.assertNotIn("Иванов", arguments)
        self.assertEqual(counters["not_in_request"], 0)
        self.assertEqual(counters.get("ambiguous", 0), 1)


class RegistryIntegrityToolTests(unittest.TestCase):
    """Инвентарь реестра: числа без значений и код возврата для прибора."""

    def _paths(self, tmp: str) -> tuple[str, str, str]:
        fernet_path = os.path.join(tmp, "fernet.key")
        token_path = os.path.join(tmp, "token.key")
        with open(fernet_path, "wb") as handle:
            handle.write(FERNET_KEY)
        with open(token_path, "wb") as handle:
            handle.write(b"t" * 32)
        return fernet_path, token_path, os.path.join(tmp, "pii_map.db")

    def test_tool_counts_codes_and_walk_steps_without_values(self) -> None:
        from tools import registry_integrity as tool

        with tempfile.TemporaryDirectory() as tmp:
            fernet_path, token_path, db_path = self._paths(tmp)
            store = TokenMapStore(db_path, fernet_key=FERNET_KEY)
            try:
                for value in ("Иванов", "Петров"):
                    code = make_token("P", value, b"t" * 32)
                    store.store(code, "P", value, "pd:" + value.lower())
            finally:
                store.close()
            code = tool.main(
                [
                    "--map-db",
                    db_path,
                    "--fernet-key-file",
                    fernet_path,
                    "--token-key-file",
                    token_path,
                    "--json",
                ]
            )
            self.assertEqual(code, 0)
            report = tool.inventory(
                TokenMapStore(db_path, fernet_key=FERNET_KEY),
                None,
                b"t" * 32,
            )
            self.assertEqual(report["records"], 2)
            self.assertEqual(report["codes"], 2)
            self.assertEqual(report["values_per_code_gt1"], 0)
            self.assertEqual(report["walk_steps"], {"0": 2})

    def test_tool_returns_two_when_a_code_carries_two_values(self) -> None:
        from tools import registry_integrity as tool

        with tempfile.TemporaryDirectory() as tmp:
            fernet_path, _token_path, db_path = self._paths(tmp)
            store = TokenMapStore(db_path, fernet_key=FERNET_KEY)
            code_token = make_token("P", "иванов", b"t" * 32)
            store.store(code_token, "P", "Иванов", "pd:one")
            store.close()
            # Порча файла: второе значение под тем же кодом (схема такого не допускает).
            connection = sqlite3.connect(db_path)
            fernet = Fernet(_fern_key())
            try:
                # Первичный ключ схемы не допускает двух строк на один код, поэтому таблица
                # пересобирается без него — так выглядит испорченный файл.
                connection.execute("DROP TABLE token_map")
                connection.execute(
                    "CREATE TABLE token_map (token TEXT, cls TEXT, value_enc BLOB,"
                    " created_at REAL, last_used_at REAL, identity_enc BLOB, forms_enc BLOB,"
                    " source TEXT)"
                )
                for value in ("Иванов", "Петров"):
                    connection.execute(
                        "INSERT INTO token_map (token, cls, value_enc, created_at, last_used_at,"
                        " identity_enc, forms_enc) VALUES (?, 'P', ?, 0, 0, NULL, ?)",
                        (
                            code_token,
                            fernet.encrypt(value.encode("utf-8")),
                            fernet.encrypt(json.dumps([value]).encode("utf-8")),
                        ),
                    )
                connection.commit()
            finally:
                connection.close()
            code = tool.main(
                ["--map-db", db_path, "--fernet-key-file", fernet_path]
            )
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
