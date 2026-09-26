# FILE: tests/test_client_identity.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify M-CLIENT-IDENTITY end to end: the three recognition methods (header, key fingerprint, User-Agent) and their order, the safe behaviour for an unidentified client under both policies, and the invariant that anonymization never depends on identification.
#   SCOPE: header recognition (new and legacy header, any case), key recognition by fingerprint with refusal to downgrade to a weaker source, the User-Agent table with the Cursor / Claude Code / Codex / VS Code / JetBrains ready patterns, priority order, unknown-client policy in the policy and through the router, healthz visibility, byte-identical anonymization and cache behaviour regardless of client identification, refusal of a blocked channel and of an ambiguous key in configuration.
#   DEPENDS: M-CLIENT-IDENTITY, M-CHANNEL-POLICY, M-ROUTER, M-CONFIG, M-TEST-HARNESS
#   LINKS: V-M-CHANNEL-POLICY, docs/ARCHITECTURE.md, docs/OPERATIONS.md
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   CLIENTS_READY - таблица-заготовка для реальных клиентов (Cursor, Claude Code, Codex, VS Code, JetBrains)
#   payload_with_pii - тело запроса со значениями клиента
#   TrustedClientsParsingTests - разбор раздела настроек: перечень, компактная строка, JSON, отказы
#   ClientRecognitionTests - три способа опознания, их порядок и запрет понижения
#   CheckCliTests - прибор «проверить строку»: канал, источник, совпавший шаблон и решение
#   UnknownClientPolicyTests - обе политики для неопознанного клиента
#   IdentificationIndependenceTests - обезличивание, кэш и healthz не зависят от опознания клиента
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.1.0 - прибор «проверить строку»: опознание по готовым заголовкам и по файлу заголовков, предупреждение о шаблоне с номером версии, объяснение режима unknown_client.
#   PREVIOUS: v1.0.0 - решение владельца 26.09.2026: опознание доверенных клиентов по заголовку, отпечатку ключа доступа и User-Agent с безопасным поведением для неопознанного клиента.
# END_CHANGE_SUMMARY

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.audit import AuditJournal  # noqa: E402
from src.channel_policy import (  # noqa: E402
    CHANNEL_ALL,
    UNKNOWN_KEEP_CODES,
    UNKNOWN_RESTORE,
    ChannelPolicy,
    ChannelPolicyError,
)
from src.client_identity import (  # noqa: E402
    CHECK_COMMAND,
    CLIENT_KEY_HEADER,
    IDENTITY_HEADER,
    LEGACY_IDENTITY_HEADER,
    SOURCE_DECLARED,
    SOURCE_HEADER,
    SOURCE_KEY,
    SOURCE_NONE,
    SOURCE_USER_AGENT,
    ClientIdentityError,
    TrustedClients,
    check_report,
    format_check,
    identify_client,
    fingerprint,
    load_clients,
    main as identity_main,
    parse_header_lines,
    parse_trusted_clients,
    read_config_overlay,
    versioned_patterns,
)
from src.normalize import normalize  # noqa: E402
from src.router import build_service  # noqa: E402
from src.token_factory import make_token  # noqa: E402
from tests import harness  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: стенд включает ту же
#: демонстрационную лексику, что оператор заполняет в примере конфигурации.
use_demo_vocabulary()

FIO = "Иванов Иван Иванович"
PHONE = "79000000001"
CHAT_PATH = "/v1/chat/completions"

#: Выдуманные ключи доступа стенда и их отпечатки: в настройках лежит только отпечаток.
CURSOR_KEY = "cursor-stub-key-0001"
CODEX_KEY = "codex-stub-key-0002"
CURSOR_KEY_FINGERPRINT = fingerprint(CURSOR_KEY)
CODEX_KEY_FINGERPRINT = fingerprint(CODEX_KEY)

# START_BLOCK_READY_CLIENTS
#: Таблица-заготовка для реальных клиентов — та же, что в config.example.yaml. Оператор
#: расширяет её своими приложениями: шаблоны User-Agent подобраны по тому, как клиент
#: представляется сам, и подделываются так же легко, как заголовок (см. docs/PRIVACY.md).
#: Порядок записей и есть порядок приоритета: Cursor в своём User-Agent называет и VS Code,
#: поэтому Cursor стоит раньше VS Code.
CLIENTS_READY = [
    {"channel": "cursor", "header_value": "cursor", "user_agent": "Cursor/*", "comment": "Cursor IDE"},
    {"channel": "claude-code", "user_agent": "claude-code*", "comment": "Claude Code CLI"},
    {"channel": "codex", "user_agent": "codex*", "comment": "Codex CLI"},
    {"channel": "vscode", "user_agent": "*vscode*", "comment": "VS Code"},
    {"channel": "jetbrains", "user_agent": "JetBrains/*", "comment": "IDE семейства JetBrains"},
]


def payload_with_pii(extra: dict | None = None) -> dict:
    """Build a chat completion body carrying the client's values in the system message."""
    payload = {
        "model": "deepseek-flash",
        "stream": False,
        "messages": [
            {"role": "system", "content": f"Клиент {FIO}, телефон {PHONE}."},
            {"role": "user", "content": "Дай сводку по нему"},
        ],
    }
    if extra:
        payload.update(extra)
    return payload
# END_BLOCK_READY_CLIENTS


class TrustedClientsParsingTests(unittest.TestCase):
    """Раздел настроек «доверенные клиенты»: три вида записи и отказы на противоречии."""

    def test_absent_section_yields_an_empty_table(self) -> None:
        """Умолчание публичной сборки: доверенных клиентов нет, опознавать некого."""
        for raw in (None, "", []):
            table = parse_trusted_clients(raw)
            self.assertEqual(0, len(table))
            self.assertFalse(bool(table))
            self.assertEqual((), table.channels)

    def test_records_list_carries_the_ready_clients(self) -> None:
        table = parse_trusted_clients(CLIENTS_READY)
        self.assertEqual(5, len(table))
        self.assertEqual(
            ("claude-code", "codex", "cursor", "jetbrains", "vscode"), table.channels
        )
        self.assertEqual(
            {"header": 1, "key": 0, "user_agent": 5}, table.methods
        )

    def test_compact_string_is_understood_for_the_service_environment_file(self) -> None:
        """Компактная строка — для VariableFile systemd, где перечень записей неудобен."""
        raw = (
            f"cursor=header:cursor;"
            f"cursor=ua:Cursor/*;"
            f"codex=ua:codex*;"
            f"claude-code=key:{CURSOR_KEY_FINGERPRINT}"
        )
        table = parse_trusted_clients(raw)
        self.assertEqual(("claude-code", "codex", "cursor"), table.channels)
        self.assertEqual({"header": 1, "key": 1, "user_agent": 2}, table.methods)
        self.assertEqual("claude-code", table.by_key(CURSOR_KEY).channel)
        self.assertEqual("cursor", table.by_header_value("CURSOR").channel)

    def test_json_string_is_understood(self) -> None:
        raw = json.dumps([{"channel": "desk", "user_agent": ["Desk/*"]}])
        table = parse_trusted_clients(raw)
        self.assertEqual(("desk",), table.channels)
        self.assertEqual("desk", table.by_user_agent("Desk/1.0 (win32)").channel)

    def test_key_lives_in_the_settings_only_as_a_fingerprint(self) -> None:
        """Ключ доступа не хранится открытым: в описании для healthz его нет вовсе."""
        table = parse_trusted_clients([{"channel": "desk", "key_sha256": CURSOR_KEY_FINGERPRINT}])
        described = json.dumps(table.describe(), ensure_ascii=False)
        self.assertNotIn(CURSOR_KEY, described)
        self.assertNotIn(CURSOR_KEY_FINGERPRINT, described)
        self.assertIn("sha256", str(table.records[0].key_fingerprint))

    def test_a_short_fingerprint_is_refused(self) -> None:
        """Короткий отпечаток перебирается, поэтому служба откажется стартовать."""
        with self.assertRaises(ClientIdentityError) as caught:
            parse_trusted_clients([{"channel": "desk", "key_sha256": "ab12"}])
        self.assertEqual("CLIENT_IDENTITY_BAD_FINGERPRINT", caught.exception.code)

    def test_a_key_cannot_belong_to_two_channels(self) -> None:
        """Порядок строк настроек не имеет права решать, чей это ключ."""
        with self.assertRaises(ClientIdentityError) as caught:
            parse_trusted_clients(
                [
                    {"channel": "desk", "key_sha256": CURSOR_KEY_FINGERPRINT},
                    {"channel": "laptop", "key_sha256": CURSOR_KEY_FINGERPRINT},
                ]
            )
        self.assertEqual("CLIENT_IDENTITY_DUPLICATE_KEY", caught.exception.code)

    def test_a_channel_outside_the_perimeter_is_refused(self) -> None:
        """Внешний мессенджер не становится доверенным клиентом ни при какой настройке."""
        with self.assertRaises(ClientIdentityError) as caught:
            parse_trusted_clients([{"channel": "telegram", "user_agent": "Telegram/*"}])
        self.assertEqual("CLIENT_IDENTITY_BLOCKED_CHANNEL", caught.exception.code)

    def test_a_record_without_any_method_is_refused(self) -> None:
        with self.assertRaises(ClientIdentityError) as caught:
            parse_trusted_clients([{"channel": "desk"}])
        self.assertEqual("CLIENT_IDENTITY_BAD_ENTRY", caught.exception.code)

    def test_a_record_without_a_channel_is_refused(self) -> None:
        with self.assertRaises(ClientIdentityError) as caught:
            parse_trusted_clients([{"user_agent": "Desk/*"}])
        self.assertEqual("CLIENT_IDENTITY_BAD_ENTRY", caught.exception.code)

    def test_an_unknown_compact_method_is_refused(self) -> None:
        with self.assertRaises(ClientIdentityError) as caught:
            parse_trusted_clients("desk=magic:desk")
        self.assertEqual("CLIENT_IDENTITY_BAD_ENTRY", caught.exception.code)

    def test_one_channel_may_have_several_records_and_methods(self) -> None:
        """У одного канала бывает и ключ, и заголовок, и шаблон: записей на канал несколько."""
        table = parse_trusted_clients(
            [
                {"channel": "desk", "key_sha256": CURSOR_KEY_FINGERPRINT},
                {"channel": "desk", "key_sha256": CODEX_KEY_FINGERPRINT},
                {"channel": "desk", "user_agent": "Desk/*"},
            ]
        )
        self.assertEqual(("desk",), table.channels)
        self.assertEqual("desk", table.by_key(CURSOR_KEY).channel)
        self.assertEqual("desk", table.by_key(CODEX_KEY).channel)
        self.assertEqual("desk", table.by_user_agent("Desk/2.0").channel)


class ClientRecognitionTests(unittest.TestCase):
    """Три способа опознания и их порядок: заголовок, ключ, User-Agent."""

    def setUp(self) -> None:
        self.table = parse_trusted_clients(
            CLIENTS_READY
            + [
                {"channel": "editor", "key_sha256": CURSOR_KEY_FINGERPRINT},
                {"channel": "terminal", "key_sha256": CODEX_KEY_FINGERPRINT},
            ]
        )

    def test_header_names_the_channel(self) -> None:
        """Способ 1: X-PII-Channel — значение заголовка и есть имя канала."""
        identity = identify_client({IDENTITY_HEADER: "cursor"}, self.table)
        self.assertEqual("cursor", identity.channel)
        self.assertEqual(SOURCE_HEADER, identity.source)
        self.assertTrue(identity.recognized)

    def test_header_name_is_read_in_any_case(self) -> None:
        identity = identify_client({"x-pii-channel": "  Cursor  "}, self.table)
        self.assertEqual("cursor", identity.channel)
        self.assertEqual(SOURCE_HEADER, identity.source)

    def test_legacy_hermes_header_still_names_the_channel(self) -> None:
        """Прежний X-Hermes-Channel остаётся рабочим: настроенные клиенты не ломаются."""
        identity = identify_client({LEGACY_IDENTITY_HEADER: "mattermost"}, self.table)
        self.assertEqual("mattermost", identity.channel)
        self.assertEqual(SOURCE_HEADER, identity.source)

    def test_an_unnamed_header_channel_is_still_a_named_channel(self) -> None:
        """Канал, которого нет в таблице, всё равно назван: решение принимает политика каналов."""
        identity = identify_client({IDENTITY_HEADER: "office"}, self.table)
        self.assertEqual("office", identity.channel)
        self.assertEqual(SOURCE_HEADER, identity.source)

    def test_key_identifies_the_client_by_fingerprint(self) -> None:
        """Способ 2: ключ доступа сравнивается по отпечатку — самый надёжный из трёх."""
        identity = identify_client({CLIENT_KEY_HEADER: CURSOR_KEY}, self.table)
        self.assertEqual("editor", identity.channel)
        self.assertEqual(SOURCE_KEY, identity.source)
        self.assertIn("sha256", identity.detail)

    def test_a_presented_key_never_downgrades_to_a_weaker_source(self) -> None:
        """Предъявленный ключ без отпечатка в настройках — не опознан, а не «пусть User-Agent»."""
        identity = identify_client(
            {CLIENT_KEY_HEADER: "unknown-stub-key", "User-Agent": "Cursor/0.42"},
            self.table,
        )
        self.assertIsNone(identity.channel)
        self.assertEqual(SOURCE_NONE, identity.source)
        self.assertEqual("key_not_configured", identity.detail)

    def test_user_agent_table_recognises_the_ready_clients(self) -> None:
        """Способ 3: таблица шаблонов — заготовки для реальных клиентов."""
        expected = {
            "Cursor/0.42.3 (darwin arm64) vscode/1.90.0": "cursor",
            "claude-code/1.0.30 (external, cli)": "claude-code",
            "codex_cli_rs/0.21.0 (macos)": "codex",
            "Mozilla/5.0 (Windows NT 10.0) vscode/1.90.0 Electron/30.0.0": "vscode",
            "JetBrains/2024.1 (IntelliJ IDEA)": "jetbrains",
        }
        for user_agent, channel in expected.items():
            with self.subTest(user_agent=user_agent):
                identity = identify_client({"User-Agent": user_agent}, self.table)
                self.assertEqual(channel, identity.channel)
                self.assertEqual(SOURCE_USER_AGENT, identity.source)

    def test_an_unknown_user_agent_is_not_recognised(self) -> None:
        identity = identify_client({"User-Agent": "curl/8.5.0"}, self.table)
        self.assertIsNone(identity.channel)
        self.assertEqual(SOURCE_NONE, identity.source)

    def test_order_of_the_records_is_the_order_of_priority(self) -> None:
        """Cursor называет в User-Agent и себя, и VS Code: побеждает запись, стоящая раньше."""
        identity = identify_client(
            {"User-Agent": "Cursor/0.42 vscode/1.90.0 Electron/30.0.0"}, self.table
        )
        self.assertEqual("cursor", identity.channel)

        reversed_table = parse_trusted_clients(list(reversed(CLIENTS_READY)))
        identity = identify_client(
            {"User-Agent": "Cursor/0.42 vscode/1.90.0 Electron/30.0.0"}, reversed_table
        )
        self.assertEqual("vscode", identity.channel)

    def test_header_wins_over_key_and_user_agent(self) -> None:
        identity = identify_client(
            {
                IDENTITY_HEADER: "cursor",
                CLIENT_KEY_HEADER: CODEX_KEY,
                "User-Agent": "codex_cli_rs/0.21.0",
            },
            self.table,
        )
        self.assertEqual("cursor", identity.channel)
        self.assertEqual(SOURCE_HEADER, identity.source)

    def test_key_wins_over_user_agent(self) -> None:
        identity = identify_client(
            {CLIENT_KEY_HEADER: CURSOR_KEY, "User-Agent": "codex_cli_rs/0.21.0"}, self.table
        )
        self.assertEqual("editor", identity.channel)
        self.assertEqual(SOURCE_KEY, identity.source)

    def test_no_headers_at_all_is_not_recognised(self) -> None:
        for headers in (None, {}, {"Content-Type": "application/json"}):
            with self.subTest(headers=headers):
                identity = identify_client(headers, self.table)
                self.assertIsNone(identity.channel)
                self.assertEqual(SOURCE_NONE, identity.source)

    def test_an_empty_table_recognises_nobody(self) -> None:
        identity = identify_client(
            {
                IDENTITY_HEADER: "cursor",
                CLIENT_KEY_HEADER: CURSOR_KEY,
                "User-Agent": "Cursor/0.42",
            },
            TrustedClients(),
        )
        # Заголовок называет канал и без таблицы: таблица сужает способы, но не заголовок.
        self.assertEqual("cursor", identity.channel)
        self.assertEqual(SOURCE_HEADER, identity.source)
        self.assertIsNone(identify_client({"User-Agent": "Cursor/0.42"}, TrustedClients()).channel)


class CheckCliTests(unittest.TestCase):
    """Прибор «проверить строку»: канал, источник и решение до правки службы."""

    READY = (
        "cursor=ua:*cursor*;codex=ua:*codex*;claude-code=ua:*claude-cli*;"
        "office=header:office"
    )

    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        """Запустить прибор с перехватом печати: тест читает то же, что увидит оператор."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = identity_main(argv)
        return code, out.getvalue(), err.getvalue()

    @staticmethod
    def _notes(report: dict[str, object]) -> list[str]:
        """Вернуть предупреждения отчёта списком: отчёт для машинного чтения — словарь."""
        notes = report["notes"]
        return [str(note) for note in notes] if isinstance(notes, list) else []

    @staticmethod
    def _value(report: dict[str, object], key: str) -> str:
        """Вернуть значение поля отчёта строкой."""
        return str(report[key])

    def test_the_matched_pattern_is_named_for_a_user_agent(self) -> None:
        code, out, _err = self._run(
            ["check", "Cursor/2.0 (darwin arm64) vscode/1.9", "--trusted-clients", self.READY]
        )
        self.assertEqual(0, code)
        self.assertIn("канал:      cursor", out)
        self.assertIn(SOURCE_USER_AGENT, out)
        self.assertIn("совпало:    *cursor*", out)
        self.assertIn("detokenize", out)

    def test_the_report_says_what_would_happen_without_any_name(self) -> None:
        """Главный вопрос оператора: что получит клиент, который себя не назвал."""
        code, out, _err = self._run(["check", "--trusted-clients", self.READY])
        self.assertEqual(0, code)
        self.assertIn("канал:      не опознан", out)
        self.assertIn(f"unknown_client = {UNKNOWN_KEEP_CODES}", out)
        self.assertIn("keep — клиент не назвался ничем", out)

        code, out, _err = self._run(
            ["check", "--unknown-client", UNKNOWN_RESTORE, "--trusted-clients", self.READY]
        )
        self.assertEqual(0, code)
        self.assertIn("restore: судит список каналов", out)

    def test_a_presented_key_without_a_fingerprint_is_not_downgraded(self) -> None:
        code, out, _err = self._run(
            [
                "check",
                "--header", f"{CLIENT_KEY_HEADER}: unknown-stub-key",
                "--header", "User-Agent: Cursor/2.0",
                "--trusted-clients", self.READY,
            ]
        )
        self.assertEqual(0, code)
        self.assertIn("канал:      не опознан", out)
        self.assertIn("НЕ понижено до User-Agent", out)

    def test_a_key_that_is_in_the_table_is_reported_with_its_channel(self) -> None:
        report = check_report(
            {CLIENT_KEY_HEADER: CURSOR_KEY},
            parse_trusted_clients([{"channel": "editor", "key_sha256": CURSOR_KEY_FINGERPRINT}]),
        )
        self.assertTrue(report["recognized"])
        self.assertEqual("editor", report["channel"])
        self.assertEqual(SOURCE_KEY, report["source"])
        # В человеческом отчёте отпечаток усечён: оператору нужно узнать запись, а не весь хеш.
        self.assertIn("sha256:", format_check(report))
        self.assertNotIn(CURSOR_KEY_FINGERPRINT, format_check(report))

    def test_the_table_and_the_modes_come_from_a_config_file(self) -> None:
        """Прибор читает тот же файл настроек, что и служба, а не свою копию правил."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "config.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "trusted_clients": [{"channel": "cursor", "user_agent": "*cursor*"}],
                        "unknown_client": UNKNOWN_RESTORE,
                        "detok_channels": ["mattermost"],
                    },
                    handle,
                )
            code, out, _err = self._run(["check", "Cursor/2.0", "--config", path])
            self.assertEqual(0, code)
            self.assertIn("канал:      cursor", out)
            self.assertIn(f"unknown_client = {UNKNOWN_RESTORE}", out)
            self.assertIn("mattermost (список сужен)", out)
            overlay = read_config_overlay(path)
            self.assertEqual("mattermost", overlay["detok_channels"][0])

    def test_a_channel_outside_a_narrowed_list_is_reported_as_kept(self) -> None:
        report = check_report(
            {IDENTITY_HEADER: "office"},
            parse_trusted_clients(self.READY),
            detok_channels=["mattermost"],
        )
        self.assertEqual("office", self._value(report, "channel"))
        self.assertEqual("keep", self._value(report, "decision"))
        self.assertTrue(any("суженным" in note for note in self._notes(report)), self._notes(report))

    def test_a_channel_outside_the_perimeter_is_flagged(self) -> None:
        report = check_report({IDENTITY_HEADER: "telegram"}, parse_trusted_clients(self.READY))
        self.assertEqual("keep", self._value(report, "decision"))
        self.assertTrue(
            any("вне контура" in note for note in self._notes(report)), self._notes(report)
        )

    def test_a_pattern_with_a_version_number_is_flagged(self) -> None:
        """Шаблон с номером версии перестанет совпадать при обновлении клиента — молча."""
        clients = parse_trusted_clients("desk=ua:Desk/2.x;cursor=ua:*cursor*")
        self.assertEqual(["Desk/2.x"], versioned_patterns(clients))
        report = check_report({"User-Agent": "Desk/2.x"}, clients)
        self.assertTrue(
            any("содержит цифры" in note for note in self._notes(report)), self._notes(report)
        )

    def test_the_user_agent_can_come_from_a_file_of_headers(self) -> None:
        """Файл заголовков пишет заглушка (tools/ua_probe.py), а читает прибор."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "headers.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("# снято заглушкой\nUser-Agent: claude-cli/2.1.2 (external, cli)\n")
            code, out, _err = self._run(
                ["check", "--headers-file", path, "--trusted-clients", self.READY]
            )
            self.assertEqual(0, code)
            self.assertIn("канал:      claude-code", out)
            self.assertIn("*claude-cli*", out)

    def test_headers_can_come_from_the_standard_input(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with unittest.mock.patch("sys.stdin", io.StringIO("User-Agent: Codex/1.0\n")):
                code = identity_main(
                    ["check", "--headers-file", "-", "--trusted-clients", self.READY]
                )
        self.assertEqual(0, code)
        self.assertIn("канал:      codex", out.getvalue())

    def test_the_report_is_machine_readable_on_request(self) -> None:
        code, out, _err = self._run(
            ["check", "Cursor/2.0", "--trusted-clients", self.READY, "--json"]
        )
        self.assertEqual(0, code)
        report = json.loads(out)
        self.assertEqual("cursor", report["channel"])
        self.assertEqual(SOURCE_USER_AGENT, report["source"])
        self.assertEqual("*cursor*", report["matched"])
        self.assertEqual(UNKNOWN_KEEP_CODES, report["unknown_client"])
        self.assertEqual("detokenize", report["decision"])

    def test_the_key_command_still_prints_a_fingerprint(self) -> None:
        bare = fingerprint("stub-key-for-cli")
        for argv in (["key", "stub-key-for-cli"], ["stub-key-for-cli"]):
            with self.subTest(argv=argv):
                code, out, _err = self._run(argv)
                self.assertEqual(0, code)
                self.assertEqual(bare, out.strip())

    def test_help_lists_both_commands(self) -> None:
        code, out, _err = self._run(["--help"])
        self.assertEqual(0, code)
        self.assertIn(CHECK_COMMAND, out)
        self.assertIn("key", out)

    def test_an_empty_command_line_prints_the_usage(self) -> None:
        code, out, _err = self._run([])
        self.assertEqual(2, code)
        self.assertIn("usage:", out)

    def test_a_broken_header_line_is_refused_with_words(self) -> None:
        code, _out, err = self._run(["check", "--header", "нет двоеточия"])
        self.assertEqual(2, code)
        self.assertIn("Name: value", err)
        with self.assertRaises(ClientIdentityError):
            parse_header_lines(["нет двоеточия"])

    def test_header_lines_ignore_comments_and_blank_lines(self) -> None:
        headers = parse_header_lines(["# снято заглушкой", "", "User-Agent: Cursor/2.0"])
        self.assertEqual({"User-Agent": "Cursor/2.0"}, headers)

    def test_an_unreadable_config_file_is_explained(self) -> None:
        code, _out, err = self._run(["check", "--config", "/nonexistent/pii-proxy/config.json"])
        self.assertEqual(2, code)
        self.assertIn("config", err)

    def test_the_table_can_come_from_the_environment_form(self) -> None:
        """Компактная строка — тот же раздел, что стоит в файле окружения службы."""
        clients, where = load_clients("office=header:office;desk=ua:*desk*")
        self.assertEqual(("desk", "office"), clients.channels)
        self.assertIn("--trusted-clients", where)
        empty, note = load_clients(None, None)
        self.assertEqual(0, len(empty))
        self.assertIn("пустая", note)


class UnknownClientPolicyTests(unittest.TestCase):
    """Поведение для неизвестного клиента: умолчание безопасное, «restore» — по решению оператора."""

    def test_the_policy_default_is_the_safe_mode(self) -> None:
        policy = ChannelPolicy({CHANNEL_ALL})
        self.assertEqual(UNKNOWN_KEEP_CODES, policy.unknown_client)

    def test_an_unidentified_client_keeps_codes_under_all_channels(self) -> None:
        """Признак «любой канал» больше не отдаёт значения клиенту, который не назвался."""
        policy = ChannelPolicy({CHANNEL_ALL})
        for channel in (None, "", "   "):
            self.assertEqual("keep", policy.decide_for_client(channel), msg=repr(channel))
        # Названный канал по-прежнему пользуется правилом «любой канал».
        self.assertEqual("detokenize", policy.decide_for_client("mattermost"))

    def test_restore_returns_the_previous_behaviour(self) -> None:
        policy = ChannelPolicy({CHANNEL_ALL}, unknown_client=UNKNOWN_RESTORE)
        self.assertEqual("detokenize", policy.decide_for_client(None))
        self.assertEqual("detokenize", policy.decide_for_client("mattermost"))
        # Канал вне контура остаётся запрещённым и здесь: это граница, а не удобство.
        self.assertEqual("keep", policy.decide_for_client("telegram"))

    def test_restore_does_not_widen_a_narrowed_list(self) -> None:
        """restore возвращает прежнее поведение, а не отменяет суженный список каналов."""
        policy = ChannelPolicy({"mattermost"}, unknown_client=UNKNOWN_RESTORE)
        self.assertEqual("keep", policy.decide_for_client(None))
        self.assertEqual("detokenize", policy.decide_for_client("mattermost"))

    def test_an_unknown_mode_is_refused(self) -> None:
        with self.assertRaises(ChannelPolicyError) as caught:
            ChannelPolicy({CHANNEL_ALL}, unknown_client="maybe")
        self.assertEqual("CHANNEL_POLICY_VIOLATION", caught.exception.code)

    def test_the_channel_decision_is_unchanged_by_the_client_rule(self) -> None:
        """Прежний контракт decide_for_text сохранён: он отвечает о канале, а не о клиенте."""
        policy = ChannelPolicy({CHANNEL_ALL})
        self.assertEqual("detokenize", policy.decide_for_text(None))
        self.assertEqual("keep", policy.decide_for_text("telegram"))


class IdentificationIndependenceTests(unittest.TestCase):
    """Обезличивание не зависит от опознания клиента: в модель значения не уходят никогда."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.config = harness.temp_config(
            self._tmp.name,
            PII_PROXY_TRUSTED_CLIENTS=(
                f"desk=header:desk;desk=key:{CURSOR_KEY_FINGERPRINT};laptop=ua:Laptop/*"
            ),
        )
        self.store = harness.temp_map_store(self._tmp.name)
        self.audit = AuditJournal(os.path.join(self._tmp.name, "audit.jsonl"))
        self.upstream = harness.FakeUpstream()
        self.service = build_service(
            self.config, store=self.store, upstream=self.upstream, audit=self.audit
        )
        self.token = make_token("P", normalize("P", FIO), self.config.token_key)
        self.store.store(self.token, "P", FIO)

    def tearDown(self) -> None:
        try:
            self.store.close()
        except Exception:
            pass
        self._tmp.cleanup()

    def _ask(self, headers: dict | None) -> tuple[dict, str]:
        """Задать один и тот же вопрос с разными заголовками и вернуть тело ответа и тело запроса."""
        self.upstream.response = {
            "choices": [{"message": {"role": "assistant", "content": f"клиент {self.token}"}}]
        }
        status, body = self.service.handle_chat_completions(
            payload_with_pii(), "ds", CHAT_PATH, None, headers=headers
        )
        self.assertEqual(200, status)
        return body, self.upstream.serialized_payload()

    def test_the_client_value_never_reaches_the_model(self) -> None:
        """Ни один из четырёх путей опознания не расширяет то, что уходит провайдеру."""
        for headers in (
            {IDENTITY_HEADER: "desk"},
            {CLIENT_KEY_HEADER: CURSOR_KEY},
            {"User-Agent": "Laptop/1.0"},
            {"User-Agent": "curl/8.5.0"},
            None,
        ):
            with self.subTest(headers=headers):
                _body, serialized = self._ask(headers)
                self.assertNotIn(FIO, serialized)
                self.assertNotIn(PHONE, serialized)

    def test_anonymization_is_byte_identical_regardless_of_identification(self) -> None:
        """Опознание клиента не участвует в обезличивании и не трогает контракты кэша."""
        _identified, identified_payload = self._ask({IDENTITY_HEADER: "desk"})
        _anonymous, anonymous_payload = self._ask(None)
        self.assertEqual(identified_payload, anonymous_payload)

    def test_the_block_cache_is_not_partitioned_by_client_identification(self) -> None:
        """Тот же вопрос от другого клиента обязан попасть в кэш: иначе он перестал бы работать."""
        first, _ = self._ask({IDENTITY_HEADER: "desk"})
        second, _ = self._ask(None)
        self.assertGreaterEqual(second["pii_proxy"]["tokenized"].get("cache_hits", 0), 1)
        self.assertEqual(
            first["pii_proxy"]["tokenized"].get("cache_hits", 0),
            0,
            msg="первый запрос не может быть попаданием в кэш",
        )

    def test_a_named_client_restores_and_an_unnamed_one_keeps_codes(self) -> None:
        identified, _ = self._ask({IDENTITY_HEADER: "desk"})
        anonymous, _ = self._ask(None)
        self.assertEqual(f"клиент {FIO}", identified["choices"][0]["message"]["content"])
        self.assertEqual(f"клиент {self.token}", anonymous["choices"][0]["message"]["content"])
        self.assertEqual("desk", identified["pii_proxy"]["channel"])
        self.assertEqual("header", identified["pii_proxy"]["channel_source"])
        self.assertEqual("", anonymous["pii_proxy"]["channel"])
        self.assertEqual("none", anonymous["pii_proxy"]["channel_source"])

    def test_the_key_and_the_user_agent_both_restore(self) -> None:
        by_key, _ = self._ask({CLIENT_KEY_HEADER: CURSOR_KEY})
        by_user_agent, _ = self._ask({"User-Agent": "Laptop/1.0 (win32)"})
        self.assertEqual(f"клиент {FIO}", by_key["choices"][0]["message"]["content"])
        self.assertEqual("key", by_key["pii_proxy"]["channel_source"])
        self.assertEqual(f"клиент {FIO}", by_user_agent["choices"][0]["message"]["content"])
        self.assertEqual("user_agent", by_user_agent["pii_proxy"]["channel_source"])

    def test_the_delivery_marker_remains_the_fourth_source(self) -> None:
        """Метка Hermes продолжает работать: клиент без заголовка, но с меткой доставки."""
        self.upstream.response = {
            "choices": [{"message": {"role": "assistant", "content": f"клиент {self.token}"}}]
        }
        payload = payload_with_pii(
            {
                "messages": [
                    {
                        "role": "system",
                        "content": f"Метка канала доставки: [[delivery:mattermost]]. Клиент {FIO}.",
                    },
                    {"role": "user", "content": "Дай сводку"},
                ]
            }
        )
        _status, body = self.service.handle_chat_completions(payload, "ds", CHAT_PATH, None)
        self.assertEqual(f"клиент {FIO}", body["choices"][0]["message"]["content"])
        self.assertEqual(SOURCE_DECLARED, body["pii_proxy"]["channel_source"])

    def test_the_channel_list_still_bounds_a_named_client(self) -> None:
        """Опознание клиента не расширяет список каналов: суженный список остаётся суженным."""
        narrow = harness.temp_config(
            self._tmp.name,
            PII_PROXY_DETOK_CHANNELS="mattermost",
            PII_PROXY_TRUSTED_CLIENTS="desk=header:desk",
        )
        service = build_service(
            narrow, store=self.store, upstream=self.upstream, audit=self.audit
        )
        self.upstream.response = {
            "choices": [{"message": {"role": "assistant", "content": f"клиент {self.token}"}}]
        }
        _status, body = service.handle_chat_completions(
            payload_with_pii(), "ds", CHAT_PATH, None, headers={IDENTITY_HEADER: "desk"}
        )
        self.assertIn(self.token, body["choices"][0]["message"]["content"])

    def test_healthz_shows_the_trusted_channels_and_the_unknown_client_mode(self) -> None:
        """Наблюдаемость: владелец видит и доверенные каналы, и режим для неизвестного клиента."""
        health = self.service.health()
        self.assertEqual(["desk", "laptop"], health["trusted_clients"]["channels"])
        self.assertEqual(UNKNOWN_KEEP_CODES, health["trusted_clients"]["unknown_client"])
        self.assertEqual(
            {"header": 1, "key": 1, "user_agent": 1}, health["trusted_clients"]["methods"]
        )
        described = json.dumps(health, ensure_ascii=False)
        self.assertNotIn(CURSOR_KEY, described)
        self.assertNotIn(CURSOR_KEY_FINGERPRINT, described)

    def test_healthz_shows_the_restore_mode_when_the_operator_chose_it(self) -> None:
        permissive = harness.temp_config(
            self._tmp.name, PII_PROXY_UNKNOWN_CLIENT=UNKNOWN_RESTORE
        )
        service = build_service(
            permissive, store=self.store, upstream=self.upstream, audit=self.audit
        )
        health = service.health()
        self.assertEqual(UNKNOWN_RESTORE, health["trusted_clients"]["unknown_client"])
        self.assertEqual(0, health["trusted_clients"]["records"])
        self.assertEqual([], health["trusted_clients"]["channels"])
        self.assertEqual(0, sum(health["trusted_clients"]["methods"].values()))


if __name__ == "__main__":
    unittest.main()
