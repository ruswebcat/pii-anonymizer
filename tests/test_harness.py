# FILE: tests/test_harness.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-TEST-HARNESS contract: synthetic data is deterministic and value-free, fixtures work without network or real client data.
#   SCOPE: sample determinism, CSV shape, fake upstream capture, config and store factories, log capture, dictionary writer permissions.
#   DEPENDS: M-TEST-HARNESS
#   LINKS: V-M-TEST-HARNESS, M-TEST-HARNESS
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   HarnessTests - unittest case set for the harness fixtures
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-1 M-TEST-HARNESS verification.
# END_CHANGE_SUMMARY

import logging
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import harness  # noqa: E402


class HarnessTests(unittest.TestCase):
    def test_sample_clients_is_deterministic(self) -> None:
        self.assertEqual(harness.sample_clients(10, seed=7), harness.sample_clients(10, seed=7))
        self.assertNotEqual(harness.sample_clients(10, seed=7), harness.sample_clients(10, seed=8))

    def test_sample_clients_shape(self) -> None:
        records = harness.sample_clients(3)
        self.assertEqual(len(records), 3)
        for record in records:
            self.assertIn(" ", record["fio"])
            self.assertTrue(record["phone"].startswith("79"))
            self.assertEqual(len(record["phone"]), 11)
            self.assertIn("@", record["email"])

    def test_synthetic_csv_has_russian_pii_headers(self) -> None:
        csv_text = harness.synthetic_csv(harness.sample_clients(2))
        header = csv_text.split("\n")[0]
        for expected in ("client_id", "ФИО", "Телефон", "E-mail", "Дата рождения", "Адрес"):
            self.assertIn(expected, header)
        self.assertEqual(len(csv_text.split("\n")), 3)

    def test_fake_upstream_captures_payload(self) -> None:
        upstream = harness.FakeUpstream()
        status, body = upstream.forward_json("ds", "/v1/chat/completions", {"messages": []})
        self.assertEqual(status, 200)
        self.assertIn("choices", body)
        self.assertEqual(upstream.last_payload, {"messages": []})
        self.assertIn("messages", upstream.serialized_payload())

    def test_fake_upstream_last_payload_requires_call(self) -> None:
        with self.assertRaises(AssertionError):
            _ = harness.FakeUpstream().last_payload

    def test_fake_upstream_stream_yields_configured_chunks(self) -> None:
        upstream = harness.FakeUpstream(stream_chunks=[b"data: a\n\n", b"data: b\n\n"])
        chunks = list(upstream.forward_stream("ds", "/v1/chat/completions", {"stream": True}))
        self.assertEqual(b"".join(chunks), b"data: a\n\ndata: b\n\n")

    def test_temp_config_builds_valid_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = harness.temp_config(tmpdir)
        self.assertEqual(config.host, "127.0.0.1")
        self.assertEqual(config.ttl_days, 90)
        self.assertFalse(config.ner_enabled)

    def test_temp_map_store_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = harness.temp_map_store(tmpdir)
            store.store("\u27e6P-AAAAAAAAAAAA\u27e7", "P", "Иванов Сергей")
            self.assertEqual(store.load_value("\u27e6P-AAAAAAAAAAAA\u27e7"), "Иванов Сергей")
            store.close()

    def test_write_dictionary_is_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = harness.write_dictionary(
                os.path.join(tmpdir, "pii_dict.json"), {"P": ["Иванов Сергей"]}
            )
            mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode & 0o077, 0)

    def test_log_capture_collects_messages(self) -> None:
        logger = logging.getLogger("harness-test-logger")
        logger.setLevel(logging.INFO)
        with harness.LogCapture(logger) as capture:
            logger.info("[TestHarness][sample_clients][BLOCK_BUILD_FIXTURES] built")
        self.assertTrue(capture.contains_any(["BLOCK_BUILD_FIXTURES"]))
        self.assertFalse(capture.contains_any(["Иванов"]))


if __name__ == "__main__":
    unittest.main()
