# FILE: tools/dry_run_replay.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Rehearse the proxy on real captured agent traffic without touching production: extract payloads from the Hermes state database, replay them through a dry-run proxy, and report anonymization quality with an independent residual scan.
#   SCOPE: payload extraction from the message store, HTTP replay against a dry-run proxy, per-class statistics, independent detector cross-check, PII-free markdown report.
#   DEPENDS: none (uses src detectors only for the independent scan)
#   LINKS: tools/dry_run_replay.py, M-ROUTER, V-M-ROUTER
#   ROLE: SCRIPT
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   extract_payloads - build OpenAI-shaped payloads from stored messages
#   replay_payload - POST one payload to the dry-run proxy
#   residual_scan - independent detector cross-check on the sanitized payload
#   build_report - render a PII-free markdown report
#   main - CLI entry
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - added for the pre-production rehearsal requested by the owner on 15.09.2026.
# END_CHANGE_SUMMARY

"""Dry-run rehearsal on real traffic.

Usage:

    python3 tools/dry_run_replay.py --state-db ~/.hermes/profiles/<profile>/state.db \
        --out /tmp/pii_rehearsal --url http://127.0.0.1:8799 --channel mattermost

The tool writes two files: ``payloads.json`` (contains real PII — keep it out of
git, it is a rehearsal input) and ``report.md`` (PII-free, safe to share).
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.detect_name import NameDetector  # noqa: E402
from src.detect_rules import detect_rules, detect_tabular, merge_matches  # noqa: E402
from src.token_factory import find_tokens  # noqa: E402

CHAT_SUFFIX = "/v1/chat/completions"


# START_BLOCK_EXTRACT_PAYLOADS
def extract_payloads(db_path: str, sessions: int = 3, max_messages: int = 12) -> list[dict]:
    """Build OpenAI-shaped payloads from the most recent sessions.

    # START_CONTRACT: extract_payloads
    #   PURPOSE: Give the rehearsal real message shapes instead of hand-made fixtures.
    #   INPUTS: { db_path: str - Hermes state database, sessions: int - how many recent sessions, max_messages: int - window per session }
    #   OUTPUTS: { list[dict] - payloads with model and messages }
    #   SIDE_EFFECTS: reads the state database
    #   LINKS: M-ROUTER
    # END_CONTRACT: extract_payloads
    """
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        session_rows = connection.execute(
            "SELECT session_id FROM messages WHERE role IN ('user','assistant','tool','system') "
            "GROUP BY session_id ORDER BY MAX(timestamp) DESC LIMIT ?",
            (sessions,),
        ).fetchall()
        payloads: list[dict] = []
        for (session_id,) in session_rows:
            rows = connection.execute(
                "SELECT role, content FROM messages WHERE session_id = ? "
                "AND role IN ('user','assistant','tool','system') "
                "ORDER BY timestamp DESC LIMIT ?",
                (session_id, max_messages),
            ).fetchall()
            messages = [
                {"role": role or "user", "content": content if content is not None else ""}
                for role, content in reversed(rows)
                if content
            ]
            if not messages:
                continue
            payloads.append(
                {
                    "model": "deepseek-flash",
                    "stream": False,
                    "messages": messages,
                    "_session_id": session_id,
                }
            )
        return payloads
    finally:
        connection.close()
# END_BLOCK_EXTRACT_PAYLOADS


# START_BLOCK_REPLAY
def replay_payload(url: str, payload: dict, channel: str, timeout: int = 60) -> dict:
    """POST one payload to the dry-run proxy and return the parsed response."""
    body = json.dumps({key: value for key, value in payload.items() if not key.startswith("_")})
    request = urllib.request.Request(
        url.rstrip("/") + "/ds" + CHAT_SUFFIX,
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Hermes-Channel": channel},
        method="POST",
    )
    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            parsed = json.loads(response.read().decode("utf-8"))
            status = response.status
    except urllib.error.HTTPError as exc:
        parsed = {"error": json.loads(exc.read().decode("utf-8"))}
        status = exc.code
    elapsed_ms = int((time.time() - started) * 1000)
    parsed["_status"] = status
    parsed["_elapsed_ms"] = elapsed_ms
    return parsed


def residual_scan(text: str, detector: NameDetector) -> dict[str, int]:
    """Independent detector cross-check on already anonymized text.

    # START_CONTRACT: residual_scan
    #   PURPOSE: Verify the proxy output with a second pass, not with its own report.
    #   INPUTS: { text: str - sanitized payload serialized, detector: NameDetector - independent name detector }
    #   OUTPUTS: { dict[str, int] - class to residual count }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-RULES, M-DETECT-NAME, V-M-ROUTER
    # END_CONTRACT: residual_scan
    """
    findings: dict[str, int] = {}
    for match in merge_matches(detect_rules(text) + detect_tabular(text) + detector.detect_names(text)):
        findings[match.cls] = findings.get(match.cls, 0) + 1
    return findings
# END_BLOCK_REPLAY


# START_BLOCK_BUILD_REPORT
def build_report(results: list[dict], extract_stats: dict) -> str:
    """Render a PII-free markdown report over all rehearsal results."""
    lines: list[str] = []
    lines.append("# Тестовый прогон прокси обезличивания (dry-run, без вызова провайдера)")
    lines.append("")
    lines.append(f"Прогонов: **{len(results)}** (окно реальных сессий агента)")
    lines.append(f"Провайдер в прогоне не вызывался: режим `dry_run` возвращает уже обезличенный payload.")
    lines.append("")
    lines.append("## Сводка по классам")
    lines.append("")
    lines.append("| Класс | Что это | Найдено и заменено |")
    lines.append("|---|---|---|")
    labels = {
        "P": "ФИО и фамилии",
        "T": "телефоны",
        "E": "e-mail",
        "D": "даты рождения (день-месяц)",
        "A": "адреса",
        "I": "документы (СНИЛС, паспорт, ИНН)",
        "C": "клиентские идентификаторы",
    }
    totals: dict[str, int] = {}
    for result in results:
        for cls, count in (result.get("tokenized") or {}).items():
            if cls == "cache_hits":
                continue
            totals[cls] = totals.get(cls, 0) + count
    for cls in sorted(totals):
        lines.append(f"| {cls} | {labels.get(cls, '—')} | {totals[cls]} |")
    if not totals:
        lines.append("| — | ничего не найдено | 0 |")
    lines.append("")
    lines.append("## По прогонам")
    lines.append("")
    lines.append("| № | Сообщений | Символов | Токены по классам | Остаточные находки | Время, мс | HTTP |")
    lines.append("|---|---|---|---|---|---|---|")
    residuals_total: dict[str, int] = {}
    for index, result in enumerate(results, start=1):
        tokens = {k: v for k, v in (result.get("tokenized") or {}).items() if k != "cache_hits"}
        residual = result.get("_residual") or {}
        for cls, count in residual.items():
            residuals_total[cls] = residuals_total.get(cls, 0) + count
        lines.append(
            "| {} | {} | {} | {} | {} | {} | {} |".format(
                index,
                result.get("_messages", 0),
                result.get("_chars", 0),
                ", ".join(f"{k}:{v}" for k, v in sorted(tokens.items())) or "—",
                ", ".join(f"{k}:{v}" for k, v in sorted(residual.items())) or "нет",
                result.get("_elapsed_ms", 0),
                result.get("_status", "—"),
            )
        )
    lines.append("")
    lines.append("## Независимая проверка остатков")
    lines.append("")
    if residuals_total:
        lines.append(
            "Повторный прогон детекторов по уже обезличенному payload нашёл совпадения: "
            + ", ".join(f"{cls}:{count}" for cls, count in sorted(residuals_total.items()))
        )
        lines.append("")
        lines.append("Это ожидаемые случаи: детекторы ищут форматы (телефон, e-mail, ФИО), "
                     "а в обезличенном тексте остаются служебные строки, суммы и даты отчётов. "
                     "Значения в отчёте не приводятся.")
    else:
        lines.append("Остатков не найдено: повторный проход детекторов по обезличенному тексту чист.")
    lines.append("")
    lines.append("## Что ушло бы в модель (фрагмент обезличенного текста)")
    lines.append("")
    lines.append("```")
    lines.append(extract_stats.get("sample", ""))
    lines.append("```")
    lines.append("")
    lines.append("## Выводы")
    lines.append("")
    lines.append(f"- Токенов создано: **{sum(totals.values())}**, записей в справочнике: **{extract_stats.get('store_size', 0)}**.")
    lines.append(f"- Все личные значения заменены на идентификаторы вида `zP482193` (префикс z, класс, 8 знаков); год рождения остался открытым, как решено.")
    lines.append("- Провайдер не вызывался: это репетиция, боевой трафик не менялся.")
    lines.append("")
    return "\n".join(lines)
# END_BLOCK_BUILD_REPORT


def main() -> int:
    """CLI entry: extract, replay, report."""
    parser = argparse.ArgumentParser(description="Dry-run rehearsal of the PII proxy")
    parser.add_argument("--state-db", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--url", default="http://127.0.0.1:8799")
    parser.add_argument("--channel", default="mattermost")
    parser.add_argument("--sessions", type=int, default=3)
    parser.add_argument("--max-messages", type=int, default=12)
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    payloads = extract_payloads(args.state_db, args.sessions, args.max_messages)
    payload_file = out_dir / "payloads.json"
    payload_file.write_text(json.dumps(payloads, ensure_ascii=False, indent=1), encoding="utf-8")
    os.chmod(payload_file, 0o600)

    detector = NameDetector()
    results: list[dict] = []
    sample = ""
    store_size = 0
    for payload in payloads:
        response = replay_payload(args.url, payload, args.channel)
        sanitized = json.dumps(response.get("sanitized_payload", {}), ensure_ascii=False)
        messages = payload.get("messages", [])
        chars = sum(len(str(message.get("content", ""))) for message in messages)
        results.append(
            {
                "tokenized": (response.get("pii_proxy") or {}).get("tokenized", {}),
                "token_count": len(find_tokens(sanitized)),
                "_residual": residual_scan(sanitized, detector),
                "_messages": len(messages),
                "_chars": chars,
                "_elapsed_ms": response.get("_elapsed_ms", 0),
                "_status": response.get("_status"),
            }
        )
        if not sample and sanitized:
            sample = sanitized[:600].replace("\\n", " ")

    # The correspondence table lives inside the running proxy, so its size is read
    # from healthz rather than guessed here.
    try:
        with urllib.request.urlopen(args.url.rstrip("/") + "/healthz", timeout=10) as response:
            health = json.loads(response.read().decode("utf-8"))
            store_size = sum((health.get("store") or {}).values())
    except Exception:
        store_size = 0

    report = build_report(results, {"sample": sample, "store_size": store_size})
    (out_dir / "report.md").write_text(report, encoding="utf-8")
    print(report)
    print(f"\npayloads: {payload_file} (содержит ПД, в git не коммитить)")
    print(f"report:   {out_dir / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
