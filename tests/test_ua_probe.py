# FILE: tests/test_ua_probe.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the User-Agent probe end to end: it prints the client's actual headers, never prints the value of an access key, writes a header file the check command can read, answers streaming and plain requests, refuses a network-reachable address, and says how to check the recognition afterwards.
#   SCOPE: header report for one request, access-key value never printed (its fingerprint instead), header dump consumable by fn-parse_header_lines, healthz answer, streaming answer, refusal of a non-loopback bind, live request over loopback with a real User-Agent.
#   DEPENDS: M-CLIENT-IDENTITY
#   LINKS: V-M-CHANNEL-POLICY, tools/ua_probe.py, docs/OPERATIONS.md
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   ProbeReportTests - отчёт по одному запросу: что клиент сказал и что скрыто
#   ProbeServerTests - живой запрос по loopback: заголовки, файл снятых заголовков, ответы
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - заготовки User-Agent стали рабочими: строку снимают на своей стороне заглушкой, поэтому у прибора есть своя проверка — иначе оператор узнаёт о снятой строке только из документации.
# END_CHANGE_SUMMARY

import io
import json
import os
import sys
import tempfile
import threading
import urllib.request
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.client_identity import (  # noqa: E402
    CLIENT_KEY_HEADER,
    IDENTITY_HEADER,
    parse_header_lines,
    parse_trusted_clients,
    check_report,
    fingerprint,
)
from tools.ua_probe import build_server, describe_request, header_dump_lines  # noqa: E402

#: Выдуманный ключ доступа стенда: прибор обязан показать его отпечаток и скрыть значение.
STUB_KEY = "cursor-stub-key-0001"
CLIENTS = "cursor=ua:*cursor*;claude-code=ua:*claude-cli*"


class ProbeReportTests(unittest.TestCase):
    """Отчёт по одному запросу: что клиент сказал и что обязано остаться скрытым."""

    def test_the_user_agent_is_printed_as_it_arrived(self) -> None:
        lines = describe_request("POST", "/v1/chat/completions", {"User-Agent": "Cursor/2.0"})
        text = "\n".join(lines)
        self.assertIn("POST /v1/chat/completions", text)
        self.assertIn("User-Agent: Cursor/2.0", text)

    def test_headers_the_client_did_not_send_are_named_as_missing(self) -> None:
        text = "\n".join(describe_request("POST", "/v1/chat/completions", {"User-Agent": "X/1.0"}))
        self.assertIn("не предъявлены", text)
        self.assertIn(IDENTITY_HEADER, text)

    def test_the_access_key_value_is_never_printed(self) -> None:
        """В отчёте видно, что ключ предъявлен, и его отпечаток — но не сам ключ."""
        text = "\n".join(describe_request("POST", "/v1/chat/completions", {CLIENT_KEY_HEADER: STUB_KEY}))
        self.assertNotIn(STUB_KEY, text)
        self.assertIn(fingerprint(STUB_KEY), text)

    def test_all_headers_mode_does_not_print_a_token_either(self) -> None:
        text = "\n".join(
            describe_request(
                "POST",
                "/v1/chat/completions",
                {"User-Agent": "X/1.0", "Authorization": "Bearer " + "0" * 24},
                all_headers=True,
            )
        )
        self.assertNotIn("0" * 24, text)
        self.assertIn("Authorization: предъявлен", text)

    def test_the_header_dump_feeds_the_check_command(self) -> None:
        """Файл заголовков — вход прибора «проверить строку», а не просто текст для чтения."""
        dump = header_dump_lines(
            "POST",
            "/v1/chat/completions",
            {"User-Agent": "Cursor/2.0 (darwin arm64)", CLIENT_KEY_HEADER: STUB_KEY},
        )
        self.assertNotIn(STUB_KEY, "\n".join(dump))
        headers = parse_header_lines(dump)
        report = check_report(headers, parse_trusted_clients(CLIENTS))
        self.assertTrue(report["recognized"])
        self.assertEqual("cursor", report["channel"])


class ProbeServerTests(unittest.TestCase):
    """Живой запрос по loopback: заголовки, файл снятых заголовков и ответы заглушки."""

    def _serve(self, sink: io.StringIO, dump_path: str | None = None, all_headers: bool = False):
        server = build_server("127.0.0.1", 0, sink, dump_path=dump_path, all_headers=all_headers)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def _stop(self, server, thread) -> None:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    def test_a_non_loopback_bind_is_refused(self) -> None:
        """Заглушка, доступная из сети, перестала бы быть частью контура."""
        with self.assertRaises(ValueError) as caught:
            build_server("0.0.0.0", 0, io.StringIO())
        self.assertIn("локальный интерфейс", str(caught.exception))

    def test_a_live_request_is_reported_and_answered(self) -> None:
        sink = io.StringIO()
        server, thread = self._serve(sink)
        port = server.server_address[1]
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/v1/chat/completions",
                data=json.dumps({"model": "stub", "messages": []}).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "Cursor/2.0"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                body = json.loads(response.read().decode("utf-8"))
            self.assertIn("choices", body)
        finally:
            self._stop(server, thread)
        report = sink.getvalue()
        self.assertIn("User-Agent: Cursor/2.0", report)
        self.assertIn("python3 -m src.client_identity check", report)

    def test_the_captured_headers_land_in_the_dump_file(self) -> None:
        sink = io.StringIO()
        with tempfile.TemporaryDirectory() as tmpdir:
            dump_path = os.path.join(tmpdir, "headers.txt")
            server, thread = self._serve(sink, dump_path=dump_path)
            port = server.server_address[1]
            try:
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/v1/chat/completions",
                    data=json.dumps({"model": "stub", "messages": []}).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "claude-cli/2.1.2 (external, cli)",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=10) as response:
                    response.read()
            finally:
                self._stop(server, thread)
            with open(dump_path, "r", encoding="utf-8") as handle:
                captured = handle.read()
        self.assertIn("User-Agent: claude-cli", captured)
        self.assertIn(dump_path, sink.getvalue())

    def test_a_streaming_client_gets_a_stream_answer(self) -> None:
        """Потоковый клиент не должен падать: иначе строку заголовка снять не на чем."""
        sink = io.StringIO()
        server, thread = self._serve(sink)
        port = server.server_address[1]
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/v1/chat/completions",
                data=json.dumps({"model": "stub", "stream": True, "messages": []}).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "Codex/1.0"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                content_type = response.headers.get("Content-Type", "")
                body = response.read().decode("utf-8")
        finally:
            self._stop(server, thread)
        self.assertIn("text/event-stream", content_type)
        self.assertIn("[DONE]", body)

    def test_healthz_answers_ok(self) -> None:
        sink = io.StringIO()
        server, thread = self._serve(sink)
        port = server.server_address[1]
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=10) as response:
                health = json.loads(response.read().decode("utf-8"))
        finally:
            self._stop(server, thread)
        self.assertEqual("ok", health["status"])


if __name__ == "__main__":
    unittest.main()
