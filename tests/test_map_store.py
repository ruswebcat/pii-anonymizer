# FILE: tests/test_map_store.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-MAP-STORE contract: bindings round-trip, values stay encrypted on disk, TTL purge works, broken keys fail loudly.
#   SCOPE: store and load, encryption at rest, counters, purge, unknown token, corrupted key.
#   DEPENDS: M-MAP-STORE
#   LINKS: V-M-MAP-STORE, M-MAP-STORE
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   MapStoreTests - unittest case set for TokenMapStore
#   new_store - helper building a store inside a temporary directory
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-1 M-MAP-STORE verification.
# END_CHANGE_SUMMARY

import os
import stat
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.map_store import MapStoreError, TokenMapStore  # noqa: E402
from src.token_factory import make_token  # noqa: E402

KEY = b"map-store-test-key-32-bytes-long!!!"


# START_BLOCK_BUILD_FIXTURES
def new_store(tmpdir: str, ttl_days: int = 90) -> TokenMapStore:
    """Build a store inside the given temporary directory."""
    return TokenMapStore(os.path.join(tmpdir, "pii_map.db"), KEY, ttl_days)
# END_BLOCK_BUILD_FIXTURES


class MapStoreTests(unittest.TestCase):
    def test_binding_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = new_store(tmpdir)
            token = make_token("P", "иванов сергей", KEY)
            store.store(token, "P", "Иванов Сергей")
            self.assertEqual(store.load_value(token), "Иванов Сергей")
            store.close()

    def test_unknown_token_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = new_store(tmpdir)
            self.assertIsNone(store.load_value("\u27e6P-AAAAAAAAAAAA\u27e7"))
            store.close()

    def test_values_are_encrypted_on_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = new_store(tmpdir)
            token = make_token("T", "79000000001", KEY)
            store.store(token, "T", "79000000001")
            self.assertFalse(store.raw_file_contains("79000000001"))
            store.close()

    def test_store_file_permissions_are_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = new_store(tmpdir)
            mode = stat.S_IMODE(os.stat(os.path.join(tmpdir, "pii_map.db")).st_mode)
            self.assertEqual(mode & 0o077, 0, msg=f"mode {oct(mode)} is too open")
            store.close()

    def test_existing_binding_is_never_overwritten(self) -> None:
        """Занятый код сохраняет своё значение: молчаливой подмены быть не должно.

        Phase-4 опирается на это свойство: обход кандидатов проверяет занятость
        кода до записи, поэтому хранилище обязано не перезаписывать значение.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            store = new_store(tmpdir)
            token = make_token("P", "иванов", KEY)
            store.store(token, "P", "Иванов")
            store.store(token, "P", "Петров")
            self.assertEqual(store.load_value(token), "Иванов")
            store.close()

    def test_counters_group_by_class(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = new_store(tmpdir)
            store.store(make_token("P", "петров", KEY), "P", "Петров")
            store.store(make_token("P", "иванов", KEY), "P", "Иванов")
            store.store(make_token("T", "79000000001", KEY), "T", "79000000001")
            self.assertEqual(store.counters(), {"P": 2, "T": 1})
            store.close()

    def test_purge_removes_expired_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = new_store(tmpdir, ttl_days=1)
            store.store(make_token("P", "старый", KEY), "P", "Старый")
            removed = store.purge_expired(now=time.time() + 3 * 86400)
            self.assertEqual(removed, 1)
            self.assertEqual(store.counters(), {})
            store.close()

    def test_purge_keeps_fresh_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = new_store(tmpdir, ttl_days=90)
            store.store(make_token("P", "свежий", KEY), "P", "Свежий")
            self.assertEqual(store.purge_expired(), 0)
            self.assertEqual(store.counters(), {"P": 1})
            store.close()

    def test_empty_key_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(MapStoreError) as ctx:
                TokenMapStore(os.path.join(tmpdir, "pii_map.db"), b"", 90)
            self.assertEqual(ctx.exception.code, "MAP_KEY_FILE_MISSING")

    def test_metadata_dump_contains_no_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = new_store(tmpdir)
            store.store(make_token("P", "иванов", KEY), "P", "Иванов Сергей")
            dump = store.dumps_metadata()
            self.assertNotIn("Иванов", dump)
            self.assertIn("\"P\": 1", dump)
            store.close()

    def test_bad_binding_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = new_store(tmpdir)
            with self.assertRaises(MapStoreError) as ctx:
                store.store("", "P", "Иванов")
            self.assertEqual(ctx.exception.code, "MAP_STORE_BAD_BINDING")
            store.close()


class IdentityBindingTests(unittest.TestCase):
    """Идентичность и наблюдённые формы в справочнике соответствия (Phase-7)."""

    def test_identity_and_observed_forms_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = new_store(tmpdir)
            token = make_token("P", "иванов", KEY)
            store.store(token, "P", "Ивановой", "иванов")
            self.assertEqual(store.load_identity(token), "иванов")
            self.assertEqual(store.load_value(token), "Ивановой")
            self.assertEqual(store.load_forms(token), ["Ивановой"])
            store.close()

    def test_forms_are_appended_in_order_without_repeats(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = new_store(tmpdir)
            token = make_token("P", "иванов", KEY)
            store.store(token, "P", "Ивановой", "иванов")
            self.assertTrue(store.append_form(token, "Иванов"))
            self.assertFalse(store.append_form(token, "Иванов"))
            self.assertEqual(store.load_forms(token), ["Ивановой", "Иванов"])
            # Значение остаётся первым наблюдённым написанием: повторная запись не подменяет.
            self.assertEqual(store.load_value(token), "Ивановой")
            store.close()

    def test_repeat_store_fills_identity_but_keeps_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = new_store(tmpdir)
            token = make_token("P", "иванов", KEY)
            store.store(token, "P", "Иванов")
            self.assertIsNone(store.load_identity(token))
            store.store(token, "P", "Ивановой", "иванов")
            self.assertEqual(store.load_identity(token), "иванов")
            self.assertEqual(store.load_value(token), "Иванов")
            store.close()

    def test_forms_list_is_capped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = new_store(tmpdir)
            token = make_token("P", "иванов", KEY)
            store.store(token, "P", "Иванов", "иванов")
            for index in range(20):
                store.append_form(token, f"Форма{index}", limit=3)
            self.assertEqual(len(store.load_forms(token)), 3)
            store.close()

    def test_row_without_identity_is_readable(self) -> None:
        """Записи, созданные до Phase-7: идентичности нет, формы — само значение."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "pii_map.db")
            store = TokenMapStore(path, KEY)
            token = make_token("P", "иванов", KEY)
            store._conn.execute(
                "INSERT INTO token_map (token, cls, value_enc, created_at, last_used_at) VALUES (?, ?, ?, ?, ?)",
                (token, "P", store._fernet.encrypt(b"\xd0\x98\xd0\xb2\xd0\xb0\xd0\xbd\xd0\xbe\xd0\xb2"), 1.0, 1.0),
            )
            store._conn.commit()
            self.assertIsNone(store.load_identity(token))
            self.assertEqual(store.load_forms(token), ["Иванов"])
            store.close()

    def test_old_schema_is_migrated_on_open(self) -> None:
        """Старый файл без новых колонок открывается и сохраняет свои записи."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "pii_map.db")
            store = TokenMapStore(path, KEY)
            token = make_token("P", "иванов", KEY)
            store.store(token, "P", "Иванов", "иванов")
            store.close()
            import sqlite3

            connection = sqlite3.connect(path)
            connection.execute("ALTER TABLE token_map RENAME TO token_map_old")
            connection.execute(
                "CREATE TABLE token_map (token TEXT PRIMARY KEY, cls TEXT NOT NULL, value_enc BLOB NOT NULL,"
                " created_at REAL NOT NULL, last_used_at REAL NOT NULL)"
            )
            connection.execute(
                "INSERT INTO token_map SELECT token, cls, value_enc, created_at, last_used_at FROM token_map_old"
            )
            connection.execute("DROP TABLE token_map_old")
            connection.commit()
            connection.close()

            reopened = TokenMapStore(path, KEY)
            self.assertEqual(reopened.load_value(token), "Иванов")
            self.assertIsNone(reopened.load_identity(token))
            self.assertEqual(reopened.load_forms(token), ["Иванов"])
            reopened.store(token, "P", "Ивановой", "иванов")
            self.assertEqual(reopened.load_identity(token), "иванов")
            reopened.close()

if __name__ == "__main__":
    unittest.main()
