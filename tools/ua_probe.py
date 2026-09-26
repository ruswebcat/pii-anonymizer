# FILE: tools/ua_probe.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Показать, чем клиент представляется на самом деле: заглушечный локальный сервер печатает заголовки запроса (User-Agent, канал, ключ доступа) и отдаёт минимальный ответ, чтобы приложение не падало на пустом месте.
#   SCOPE: привязка только к локальному интерфейсу, печать интересных заголовков, отпечаток предъявленного ключа вместо значения, сохранение снятых заголовков в файл для прибора «проверить строку», минимальный ответ OpenAI-совместимым клиентам и потоком, остановка после первого запроса.
#   DEPENDS: M-CLIENT-IDENTITY
#   LINKS: tools/ua_probe.py, M-CLIENT-IDENTITY, docs/OPERATIONS.md, fn-describe_request, fn-header_dump_lines
#   ROLE: SCRIPT
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   LOOPBACK_HOSTS - адреса, на которых заглушке разрешено слушать
#   WATCHED_HEADERS - заголовки, которые печатаются в отчёте
#   fn-describe_request - строки отчёта по одному запросу: что клиент о себе сказал
#   fn-header_dump_lines - тот же набор заголовков в виде «Имя: значение» для прибора
#   fn-build_server - сервер-заглушка на локальном адресе
#   fn-main - разбор аргументов, запуск и остановка
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - решение владельца 26.09.2026: строку User-Agent снимают на своей стороне (заглушечный сервер), а шаблон в настройках пишут без номера версии — при обновлении клиента строка меняется, и номер в шаблоне ломает опознание молча.
# END_CHANGE_SUMMARY

"""Заглушечный сервер: снять фактическую строку User-Agent клиента.

Зачем: опознание доверенного клиента по User-Agent работает только тогда, когда шаблон в
настройках совпадает с фактической строкой приложения. Строку нельзя взять из документации
клиента — её меняют версии и сборки, — поэтому её снимают на своей стороне: клиенту указывают
адрес заглушки вместо адреса модели, а заглушка печатает то, что он прислал.

    python3 tools/ua_probe.py                       # слушает 127.0.0.1:8792
    python3 tools/ua_probe.py --once                # выйти после первого запроса
    python3 tools/ua_probe.py --dump /tmp/headers.txt

Ответ заглушки — минимальный (одно сообщение ассистента, потоком или целиком): важно не то, что
она отвечает, а то, **чем клиент себя назвал**. Слушает она только локальный интерфейс, как и
прокси: адрес, доступный из сети, перестал бы быть границей контура.

Значение ключа доступа в отчёте не печатается — печатается его отпечаток: ровно та строка,
которую владелец вписывает в раздел ``trusted_clients`` настроек.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from collections.abc import Mapping
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.client_identity import (  # noqa: E402
    CLIENT_KEY_HEADER,
    IDENTITY_HEADER,
    LEGACY_IDENTITY_HEADER,
    fingerprint,
)

#: Заглушка слушает только локальный интерфейс: адрес, доступный из сети, был бы нарушением границы.
LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")

#: Заголовки, по которым клиент себя называет или выдаёт себя: печатаются в отчёте.
WATCHED_HEADERS = (
    "User-Agent",
    IDENTITY_HEADER,
    LEGACY_IDENTITY_HEADER,
    CLIENT_KEY_HEADER,
    "originator",
    "x-app",
    "anthropic-version",
)

#: Заголовок с ключом доступа: его значение не печатается никогда, только отпечаток.
SECRET_HEADERS = (CLIENT_KEY_HEADER.lower(), "authorization", "x-api-key")

#: Заголовков, которые видит каждый запрос, но которые ничего не говорят об опознании: их печатают
#: только по флагу ``--all-headers``, иначе отчёт утонул бы в них.
NOISY_HEADERS = frozenset({"host", "connection", "accept-encoding", "content-length", "accept"})


def _find_header(headers: Mapping[str, str], name: str) -> str | None:
    """Прочитать заголовок без учёта регистра его имени."""
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            text = str(value or "").strip()
            return text or None
    return None


# START_BLOCK_DESCRIBE_REQUEST
def describe_request(
    method: str,
    path: str,
    headers: Mapping[str, str],
    all_headers: bool = False,
) -> list[str]:
    """Вернуть строки отчёта по одному запросу: что клиент о себе сказал.

    # START_CONTRACT: describe_request
    #   PURPOSE: Показать оператору фактическую строку клиента и его заголовки, не печатая значений ключей.
    #   INPUTS: { method: str - метод запроса, path: str - путь, headers: Mapping[str, str] - заголовки запроса, all_headers: bool - печатать и неинтересные заголовки }
    #   OUTPUTS: { list[str] - строки отчёта }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CLIENT-IDENTITY, docs/OPERATIONS.md
    # END_CONTRACT: describe_request

    Отпечаток ключа печатается целиком: это не секрет, а ровно то значение, которое владелец
    вписывает в настройки. Само значение ключа не печатается ни при каком флаге — журнал
    заглушки не должен становиться местом хранения ключа.
    """
    stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S%z")
    lines = [f"--- {stamp} {method} {path}"]
    if all_headers:
        shown = sorted(
            str(name) for name in headers if str(name).lower() not in NOISY_HEADERS
        )
    else:
        shown = [name for name in WATCHED_HEADERS if _find_header(headers, name)]
    for name in shown:
        value = _find_header(headers, name)
        if value is None:
            continue
        if name.lower() in SECRET_HEADERS:
            lines.append(f"  {name}: предъявлен, отпечаток {fingerprint(value)}")
            continue
        lines.append(f"  {name}: {value}")
    missing = [name for name in WATCHED_HEADERS if not _find_header(headers, name)]
    if missing:
        lines.append(f"  (не предъявлены: {', '.join(missing)})")
    return lines


def header_dump_lines(method: str, path: str, headers: Mapping[str, str], all_headers: bool = True) -> list[str]:
    """Вернуть заголовки запроса в виде «Имя: значение» — вход для прибора «проверить строку».

    # START_CONTRACT: header_dump_lines
    #   PURPOSE: Передать снятые заголовки прибору без перепечатывания руками.
    #   INPUTS: { method: str - метод, path: str - путь, headers: Mapping[str, str] - заголовки, all_headers: bool - включать неинтересные }
    #   OUTPUTS: { list[str] - строки файла: комментарий с запросом и заголовки }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CLIENT-IDENTITY, tools/ua_probe.py
    # END_CONTRACT: header_dump_lines

    Значения ключей и токенов не попадают и сюда: прибору для проверки опознания нужны только
    имена заголовков и строки, по которым клиент узнаётся.
    """
    stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S%z")
    lines = [f"# {stamp} {method} {path}"]
    for name in sorted(str(item) for item in headers):
        if str(name).lower() in NOISY_HEADERS and not all_headers:
            continue
        value = _find_header(headers, str(name))
        if value is None:
            continue
        if str(name).lower() in SECRET_HEADERS:
            lines.append(f"# {name}: предъявлен (значение не сохраняется)")
            continue
        lines.append(f"{name}: {value}")
    return lines
# END_BLOCK_DESCRIBE_REQUEST


# START_BLOCK_PROBE_SERVER
def _answer_for(path: str, payload: Mapping[str, object]) -> tuple[int, bytes, str]:
    """Собрать минимальный ответ клиенту: важно, что он сказал, а не что услышал."""
    if path.split("?")[0].rstrip("/").endswith("healthz"):
        body = {"status": "ok", "probe": "ua_probe"}
        return 200, json.dumps(body).encode("utf-8"), "application/json"
    completion = {
        "id": "probe-000",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "заглушка проверки заголовков"},
                "finish_reason": "stop",
            }
        ],
    }
    if payload.get("stream"):
        chunk = {
            "id": "probe-000",
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"role": "assistant", "content": "заглушка"}, "finish_reason": "stop"}],
        }
        frames = (
            f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
            "data: [DONE]\n\n"
        )
        return 200, frames.encode("utf-8"), "text/event-stream; charset=utf-8"
    return 200, json.dumps(completion, ensure_ascii=False).encode("utf-8"), "application/json"


def build_server(
    host: str,
    port: int,
    out,
    dump_path: str | None = None,
    all_headers: bool = False,
    once: bool = False,
) -> ThreadingHTTPServer:
    """Собрать сервер-заглушку: печатает заголовки, отвечает минимально, слушает только локальный адрес.

    # START_CONTRACT: build_server
    #   PURPOSE: Дать заглушке одну точку сборки, пригодную и для ручного снятия строки, и для теста.
    #   INPUTS: { host: str - адрес, port: int - порт (0 — любой свободный), out - поток для отчёта, dump_path: str | None - файл снятых заголовков, all_headers: bool - печатать все заголовки, once: bool - остановиться после первого запроса }
    #   OUTPUTS: { ThreadingHTTPServer - готовый к serve_forever сервер }
    #   SIDE_EFFECTS: открывает сокет на локальном адресе, пишет отчёт и файл снятых заголовков
    #   LINKS: M-CLIENT-IDENTITY, docs/OPERATIONS.md
    # END_CONTRACT: build_server
    """
    if host not in LOOPBACK_HOSTS:
        raise ValueError(
            f"заглушка слушает только локальный интерфейс: {host!r} не из {list(LOOPBACK_HOSTS)}"
        )
    lock = threading.Lock()

    class ProbeHandler(BaseHTTPRequestHandler):
        """Один запрос: напечатать заголовки, отдать минимальный ответ."""

        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
            """Молчать в стандартный журнал: отчёт заглушки печатается сама, без дат сервера."""
            return

        def _record(self, method: str, payload: Mapping[str, object]) -> None:
            headers = {str(name): str(value) for name, value in self.headers.items()}
            with lock:
                for line in describe_request(method, self.path, headers, all_headers):
                    print(line, file=out, flush=True)
                for line in self._hint(headers):
                    print(line, file=out, flush=True)
                if dump_path:
                    with open(dump_path, "a", encoding="utf-8") as handle:
                        handle.write("\n".join(header_dump_lines(method, self.path, headers)) + "\n")
            if once:
                threading.Thread(target=self.server.shutdown, daemon=True).start()

        def _hint(self, headers: Mapping[str, str]) -> list[str]:
            """Подсказать готовую команду проверки опознания по снятым заголовкам."""
            user_agent = _find_header(headers, "User-Agent") or ""
            hint = "  проверить опознание: python3 -m src.client_identity check"
            if dump_path:
                return [hint + f" --headers-file {dump_path} --trusted-clients '<таблица>'"]
            return [hint + f" --user-agent {user_agent!r} --trusted-clients '<таблица>'"]

        def _send(self, path: str, payload: Mapping[str, object]) -> None:
            status, body, content_type = _answer_for(path, payload)
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - stdlib signature
            self._record("GET", {})
            self._send(self.path, {})

        def do_POST(self) -> None:  # noqa: N802 - stdlib signature
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            raw = self.rfile.read(length) if length else b""
            try:
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except (ValueError, UnicodeDecodeError):
                payload = {}
            if not isinstance(payload, Mapping):
                payload = {}
            self._record("POST", payload)
            self._send(self.path, payload)

    server = ThreadingHTTPServer((host, port), ProbeHandler)
    server.daemon_threads = True
    return server
# END_BLOCK_PROBE_SERVER


def main(argv: list[str] | None = None) -> int:
    """Разобрать аргументы, поднять заглушку и печатать заголовки приходящих запросов.

    # START_CONTRACT: main
    #   PURPOSE: Дать оператору снять фактическую строку User-Agent своего клиента за один запуск.
    #   INPUTS: { argv: list[str] | None - аргументы командной строки }
    #   OUTPUTS: { int - код возврата }
    #   SIDE_EFFECTS: слушает локальный порт, печатает отчёт, пишет файл снятых заголовков
    #   LINKS: M-CLIENT-IDENTITY, docs/OPERATIONS.md
    # END_CONTRACT: main
    """
    parser = argparse.ArgumentParser(
        description="Заглушечный сервер: снять фактическую строку User-Agent клиента."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8792)
    parser.add_argument("--dump", default=None, metavar="ФАЙЛ", help="дописывать снятые заголовки в файл")
    parser.add_argument("--all-headers", action="store_true", help="печатать все заголовки, не только опознающие")
    parser.add_argument("--once", action="store_true", help="выйти после первого запроса")
    args = parser.parse_args(argv)

    try:
        server = build_server(
            args.host, args.port, sys.stdout, dump_path=args.dump,
            all_headers=args.all_headers, once=args.once,
        )
    except (ValueError, OSError) as exc:
        print(f"заглушка не поднялась: {exc}", file=sys.stderr)
        return 2
    host, port = server.server_address[:2]
    print(
        f"Заглушка слушает http://{host}:{port} — укажите этот адрес в клиенте как адрес модели "
        "(base_url) и повторите один запрос. Ctrl+C — остановить.",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("остановлено владельцем", file=sys.stderr)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover - служебная точка входа
    raise SystemExit(main())
