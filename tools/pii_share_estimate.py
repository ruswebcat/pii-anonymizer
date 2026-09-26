# FILE: tools/pii_share_estimate.py
# VERSION: 2.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Measure what share of real agent requests carry personal data, so the blended cost of the "anonymize only where needed" plan is a fact rather than a guess.
#   SCOPE: samples turns across recent production sessions (Telegram/Mattermost, excluding the development window), rebuilds the payload the proxy would receive, runs detection with a throwaway correspondence table, reports the clean/PII split and the implied blended overhead.
#   DEPENDS: M-TOKENIZER, M-MAP-STORE, M-DICT, M-NER
#   LINKS: tools/pii_share_estimate.py, plans/2026-09-16_005838-obezlichivanie-tolko-gde-pd.md
#   ROLE: SCRIPT
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   load_turn_payloads - rebuild the payload of individual requests
#   classify - decide whether one request carries personal data
#   main - CLI entry and summary
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v2.0.0 - Sample turns of production sessions, not the newest windows: the first version measured the anonymization work itself and reported a meaningless 98.6%.
# END_CHANGE_SUMMARY

"""Measure the share of real requests that carry personal data.

The routing plan only pays off if a meaningful part of traffic has no personal
data in it. This counts that share on the agent's own history, using the same
detectors the proxy runs.

Two design notes matter for honesty of the number:

1. **Turns, not windows.** A request is one turn, not a whole session. Sampling
   the newest 20-message windows measures whatever the latest sessions happened
   to be about — in the first run, the anonymization work itself, which produced
   a meaningless 98.6%.
2. **Production sessions only.** Sessions of the development window are excluded:
   they are full of client records by design and would inflate the number.

Nothing is sent anywhere and the correspondence table is a throwaway.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.config import load_config  # noqa: E402
from src.detect_name import NameDetector  # noqa: E402
from src.detect_ner import NerDetector  # noqa: E402
from src.dictionary import PiiDictionary  # noqa: E402
from src.map_store import TokenMapStore  # noqa: E402
from src.tokenizer import PayloadTokenizer  # noqa: E402

SYSTEM_NOTE = "Ты помощник сети фитнес-клубов. Отвечай по делу."


def load_env(path: str) -> dict[str, str]:
    """Read a KEY=VALUE file."""
    values: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line and "=" in line:
            name, value = line.split("=", 1)
            values[name.strip()] = value.strip()
    return values


def load_turn_payloads(
    db_path: str,
    sources: tuple[str, ...],
    since: str,
    until: str,
    sessions: int,
    turns_per_session: int,
    window: int,
) -> tuple[list[list[dict]], int]:
    """Return payloads for sampled turns plus the number of candidate sessions."""
    since_ts = dt.datetime.fromisoformat(since).timestamp()
    until_ts = dt.datetime.fromisoformat(until).timestamp()
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    placeholders = ",".join("?" for _ in sources)
    session_ids = [
        row["id"]
        for row in connection.execute(
            f"SELECT id FROM sessions WHERE source IN ({placeholders}) "
            "AND started_at >= ? AND started_at <= ? AND message_count > 3 "
            "ORDER BY started_at DESC LIMIT ?",
            (*sources, since_ts, until_ts, sessions),
        )
    ]
    payloads: list[list[dict]] = []
    for session_id in session_ids:
        rows = connection.execute(
            "SELECT id, role, content, tool_name FROM messages "
            "WHERE session_id = ? AND active = 1 AND role IN ('user','assistant','tool') "
            "AND content IS NOT NULL AND content <> '' ORDER BY id",
            (session_id,),
        ).fetchall()
        if not rows:
            continue
        turn_indexes = [index for index, row in enumerate(rows) if row["role"] == "user"]
        if not turn_indexes:
            continue
        step = max(1, len(turn_indexes) // turns_per_session)
        sampled = turn_indexes[::step][:turns_per_session]
        for index in sampled:
            history = rows[max(0, index - window + 1) : index + 1]
            messages = [{"role": "system", "content": SYSTEM_NOTE}]
            for row in history:
                message: dict = {"role": row["role"], "content": row["content"]}
                if row["tool_name"]:
                    message["name"] = row["tool_name"]
                messages.append(message)
            payloads.append(messages)
    connection.close()
    return payloads, len(session_ids)


def classify(tokenizer: PayloadTokenizer, messages: list[dict], session: str) -> dict:
    """Return the classes found in one request and the size of the payload."""
    payload = {"model": "estimate", "messages": messages}
    try:
        _, stats = tokenizer.tokenize_payload(payload, session)
    except Exception as exc:  # noqa: BLE001 - a broken turn must not stop the run
        return {"error": str(exc), "stats": {}, "size": 0}
    return {
        "stats": {cls: count for cls, count in stats.items() if count},
        "size": len(json.dumps(messages, ensure_ascii=False)),
    }


def main(argv: list[str] | None = None) -> int:
    """Count clean and personal-data requests and print the implied cost."""
    parser = argparse.ArgumentParser(description="Share of requests carrying personal data")
    parser.add_argument("--db", default="~/.config/pii-proxy/agent.db")
    parser.add_argument("--sources", default="telegram,mattermost")
    parser.add_argument("--since", default="2026-08-01T00:00:00")
    parser.add_argument("--until", default="2026-09-15T00:00:00")
    parser.add_argument("--sessions", type=int, default=60)
    parser.add_argument("--turns-per-session", type=int, default=4)
    parser.add_argument("--window", type=int, default=20)
    parser.add_argument(
        "--env-file", default="~/.config/pii-proxy/pii-proxy.env"
    )
    parser.add_argument("--overhead", type=float, default=24.6, help="measured overhead on PII payloads, %%")
    args = parser.parse_args(argv)

    config = load_config(load_env(args.env_file))
    sources = tuple(part.strip() for part in args.sources.split(",") if part.strip())
    with tempfile.TemporaryDirectory() as tmp:
        store = TokenMapStore(str(Path(tmp) / "estimate.db"), b"e" * 32, 1)
        dictionary = PiiDictionary(config.dictionary_path, key=config.dictionary_key)
        tokenizer = PayloadTokenizer(
            config.token_key,
            store,
            NameDetector(dictionary),
            ner=NerDetector(config.ner_backend) if config.ner_enabled else None,
        )
        payloads, session_count = load_turn_payloads(
            args.db, sources, args.since, args.until, args.sessions, args.turns_per_session, args.window
        )
        clean = dirty = errors = 0
        class_totals: dict[str, int] = {}
        dirty_sizes: list[int] = []
        clean_sizes: list[int] = []
        clean_chars = 0
        dirty_chars = 0
        per_session: dict[str, list[bool]] = {}
        for index, messages in enumerate(payloads):
            result = classify(tokenizer, messages, f"estimate-{index}")
            if "error" in result:
                errors += 1
                continue
            has_pii = bool(result["stats"])
            per_session.setdefault(str(index // args.turns_per_session), []).append(has_pii)
            if has_pii:
                dirty += 1
                dirty_sizes.append(result["size"])
                dirty_chars += result["size"]
                for cls, count in result["stats"].items():
                    class_totals[cls] = class_totals.get(cls, 0) + count
            else:
                clean += 1
                clean_sizes.append(result["size"])
                clean_chars += result["size"]

    total = clean + dirty
    if not total:
        print("запросов не найдено")
        return 1
    share = 100 * dirty / total
    blended = share / 100 * args.overhead
    mixed = sum(1 for flags in per_session.values() if any(flags) and not all(flags))
    print(f"сессий: **{session_count}** | запросов проверено: **{total}** (ошибок: {errors})")
    print(f"без ПД (пойдут байт-в-байт): **{clean}** ({100 - share:.1f}%)")
    print(f"с ПД (токенизируются): **{dirty}** ({share:.1f}%)")
    print("классы ПД:", class_totals)
    if clean_sizes:
        print(f"средний размер чистого запроса: {sum(clean_sizes) // len(clean_sizes)} знаков")
    if dirty_sizes:
        print(f"средний размер запроса с ПД: {sum(dirty_sizes) // len(dirty_sizes)} знаков")
    print(f"сессий, где ПД есть не в каждом ходе: {mixed}")
    volume_total = clean_chars + dirty_chars
    volume_share = 100 * clean_chars / volume_total if volume_total else 0
    print(
        f"доля чистых запросов ПО ОБЪЁМУ (это и есть деньги): **{volume_share:.1f}%** "
        f"({clean_chars} из {volume_total} знаков)"
    )
    print(
        f"если бы платили надбавку на каждом запросе с ПД: ≈ **{blended:.1f}%** "
        f"({share:.0f}% запросов × {args.overhead:.0f}%)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
