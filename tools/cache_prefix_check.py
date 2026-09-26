# FILE: tools/cache_prefix_check.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Prove on real captured traffic that the proxy does not break provider prompt caching: the tokenized request prefix must stay byte-identical across turns, and detokenize-then-retokenize must be a fixed point.
#   SCOPE: per-session turn growth analysis, byte-prefix comparison, round-trip fixed-point simulation through the Hermes transcript, PII-free report rows.
#   DEPENDS: M-TOKENIZER, M-DETOKENIZER
#   LINKS: tools/cache_prefix_check.py, V-M-TOKENIZER, V-M-DETOKENIZER
#   ROLE: SCRIPT
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   common_prefix_bytes - length of the shared byte prefix of two strings
#   analyse_session - prefix stability over growing turn windows
#   roundtrip_fixed_point - detokenize then retokenize the stored transcript
#   build_report - PII-free report section
#   main - CLI entry
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - added on the owner request of 15.09.2026: prove prompt-cache safety before switching the agent to the proxy.
# END_CHANGE_SUMMARY

"""Prompt-cache safety check.

DeepSeek (like every major provider) caches the request on its literal byte
prefix: as long as the first N bytes of the next request are identical to the
previous one, the cached prefix is reused and the request is cheaper. A proxy
that anonymizes text can break that silently — one differently escaped token or
one reformatted JSON blob and the whole prefix is re-charged.

This tool measures the property directly on captured traffic:

1. growth check — tokenized ``messages[:k]`` must stay a byte prefix of tokenized
   ``messages[:k+1]`` for every k;
2. transcript round trip — what Hermes stores after a turn is the detokenized
   text; retokenizing it must reproduce the identical bytes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.channel_policy import ChannelPolicy  # noqa: E402
from src.detect_name import NameDetector  # noqa: E402
from src.detokenizer import PayloadDetokenizer  # noqa: E402
from src.map_store import TokenMapStore  # noqa: E402
from src.token_factory import find_tokens  # noqa: E402
from src.tokenizer import PayloadTokenizer  # noqa: E402

TOKEN_KEY = b"rehearsal-token-key-32-bytes-long"


# START_BLOCK_PREFIX_ANALYSIS
def common_prefix_bytes(first: str, second: str) -> int:
    """Return the length of the shared byte prefix of two strings."""
    limit = min(len(first), len(second))
    index = 0
    while index < limit and first[index] == second[index]:
        index += 1
    return index


def analyse_session(tokenizer: PayloadTokenizer, messages: list[dict]) -> dict:
    """Measure prefix stability while the conversation window grows.

    # START_CONTRACT: analyse_session
    #   PURPOSE: Emulate the provider cache key across consecutive turns.
    #   INPUTS: { tokenizer: PayloadTokenizer, messages: list[dict] - real history }
    #   OUTPUTS: { dict - turns checked, stable turns, changed messages, average stable share }
    #   SIDE_EFFECTS: writes bindings into the correspondence table
    #   LINKS: M-TOKENIZER, V-M-TOKENIZER
    # END_CONTRACT: analyse_session

    The provider caches the literal byte prefix of the request, so the invariant
    that matters is: every message that was already present must serialize to the
    identical bytes on the next turn. Only the freshly appended tail may differ —
    comparing whole arrays (including the closing bracket) would report a false
    break, which is exactly the bug this tool had before 15.09.2026.
    """
    previous: list[str] = []
    turns = 0
    matches = 0
    changed_messages = 0
    stable_share_sum = 0.0
    for size in range(2, len(messages) + 1):
        payload = {"model": "deepseek-flash", "stream": False, "messages": messages[:size]}
        tokenized, _ = tokenizer.tokenize_payload(payload, f"turn-{size}")
        current = [json.dumps(message, ensure_ascii=False) for message in tokenized["messages"]]
        if previous:
            turns += 1
            differing = sum(
                1 for before, after in zip(previous, current) if before != after
            )
            changed_messages += differing
            if differing == 0 and len(current) >= len(previous):
                matches += 1
            before_blob = "".join(previous)
            after_blob = "".join(current)
            stable_share_sum += common_prefix_bytes(before_blob, after_blob) / max(1, len(before_blob))
        previous = current
    return {
        "turns": turns,
        "prefix_matches": matches,
        "changed_messages": changed_messages,
        "average_stable_share": round(stable_share_sum / turns, 4) if turns else 1.0,
    }


def roundtrip_fixed_point(
    tokenizer: PayloadTokenizer, detokenizer: PayloadDetokenizer, messages: list[dict]
) -> dict:
    """Simulate the stored transcript: detokenize a turn, then retokenize it.

    # START_CONTRACT: roundtrip_fixed_point
    #   PURPOSE: Catch the failure mode where the second pass tokenizes text differently.
    #   INPUTS: { tokenizer: PayloadTokenizer, detokenizer: PayloadDetokenizer, messages: list[dict] }
    #   OUTPUTS: { dict - checked strings, mismatches, token spans }
    #   SIDE_EFFECTS: writes bindings into the correspondence table
    #   LINKS: M-DETOKENIZER, V-M-DETOKENIZER
    # END_CONTRACT: roundtrip_fixed_point

    Only assistant messages are detokenized in production: the proxy restores the
    model's own output (text for Mattermost, arguments for tool calls), while tool
    results are produced locally by Hermes and never pass through the reverse
    mapping. Simulating detokenization on a tool result would therefore test a
    code path that does not exist — and did, until 15.09.2026, produce two
    phantom "cache breaks". For every other role the invariant is different and
    stricter: re-tokenizing an already tokenized payload must be a byte-level
    no-op, which is what re-sent history relies on.
    """
    payload = {"model": "deepseek-flash", "stream": False, "messages": messages}
    tokenized, _ = tokenizer.tokenize_payload(payload, "roundtrip")
    checked = 0
    mismatches = 0
    examples: list[str] = []
    for original, message in zip(messages, tokenized["messages"]):
        content = message.get("content")
        if not isinstance(content, str) or not find_tokens(content):
            continue
        checked += 1
        if (original.get("role") or "").lower() == "assistant":
            restored, _ = detokenizer.detokenize_text(content, "mattermost", "roundtrip")
            again = tokenizer.tokenize_text(restored, "roundtrip-next")
        else:
            again = tokenizer.tokenize_text(content, "roundtrip-next")
        if again != content:
            mismatches += 1
            if len(examples) < 3:
                examples.append(_describe(again, content))
    return {"checked": checked, "mismatches": mismatches, "examples": examples}


def _describe(again: str, original: str) -> str:
    """Describe a mismatch without leaking personal data."""
    first_diff = common_prefix_bytes(again, original)
    return (
        f"расхождение с символа {first_diff}: "
        f"повторная токенизация короче на {len(original) - len(again)} симв., "
        f"токенов {len(find_tokens(again))} против {len(find_tokens(original))}"
    )
# END_BLOCK_PREFIX_ANALYSIS


# START_BLOCK_BUILD_REPORT
def build_report(sessions: list[dict]) -> str:
    """Render the prompt-cache safety section without any PII."""
    lines = ["## Проверка кэша провайдера (prompt cache)", ""]
    lines.append(
        "Провайдер кэширует запрос по литеральному байтовому префиксу. Проверка эмулирует "
        "последовательные ходы на реальной истории: каждое сообщение, которое уже было в "
        "предыдущем запросе, обязано сериализоваться в те же байты, отличаться может только "
        "добавленный хвост. Дополнительно проверяется round-trip: то, что Hermes сохранил после "
        "хода (детокенизированный текст), при повторной токенизации должно дать те же байты."
    )
    lines.append("")
    lines.append("| Сессия | Ходов | Префикс цел | Изменившихся сообщений | Средняя стабильная доля | Round-trip проверено | Расхождений |")
    lines.append("|---|---|---|---|---|---|---|")
    totals = {"turns": 0, "matches": 0, "checked": 0, "mismatches": 0}
    for index, session in enumerate(sessions, start=1):
        growth = session["growth"]
        trip = session["roundtrip"]
        totals["turns"] += growth["turns"]
        totals["matches"] += growth["prefix_matches"]
        totals["checked"] += trip["checked"]
        totals["mismatches"] += trip["mismatches"]
        lines.append(
            "| {} | {} | {} | {} | {:.2%} | {} | {} |".format(
                index,
                growth["turns"],
                growth["prefix_matches"],
                growth.get("changed_messages", 0),
                growth["average_stable_share"],
                trip["checked"],
                trip["mismatches"],
            )
        )
    lines.append("")
    verdict = "КЭШ НЕ ЛОМАЕТСЯ" if totals["matches"] == totals["turns"] and totals["mismatches"] == 0 else "ЕСТЬ РАЗРЫВЫ ПРЕФИКСА"
    lines.append(f"**Вывод: {verdict}.**")
    lines.append("")
    lines.append(
        f"Ходов проверено: {totals['turns']}, совпало префиксов: {totals['matches']}, "
        f"round-trip строк: {totals['checked']}, расхождений: {totals['mismatches']}."
    )
    examples = [example for session in sessions for example in session["roundtrip"]["examples"]]
    if examples:
        lines.append("")
        lines.append("Примеры расхождений (без значений):")
        for example in examples:
            lines.append(f"- {example}")
    lines.append("")
    return "\n".join(lines)
# END_BLOCK_BUILD_REPORT


def main() -> int:
    """CLI entry."""
    parser = argparse.ArgumentParser(description="Prompt-cache safety check")
    parser.add_argument("--payloads", required=True, help="payloads.json from dry_run_replay")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    payloads = json.loads(Path(args.payloads).read_text(encoding="utf-8"))
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    sessions: list[dict] = []
    with tempfile.TemporaryDirectory() as tmpdir:
        store = TokenMapStore(os.path.join(tmpdir, "cache_check.db"), b"c" * 32, 90)
        tokenizer = PayloadTokenizer(TOKEN_KEY, store, NameDetector())
        detokenizer = PayloadDetokenizer(store, ChannelPolicy({"mattermost"}))
        for payload in payloads:
            messages = payload.get("messages", [])
            if len(messages) < 3:
                continue
            sessions.append(
                {
                    "session": payload.get("_session_id", "?"),
                    "growth": analyse_session(tokenizer, messages),
                    "roundtrip": roundtrip_fixed_point(tokenizer, detokenizer, messages),
                }
            )
        store.close()

    report = build_report(sessions)
    (out_dir / "cache_report.md").write_text(report, encoding="utf-8")
    print(report)
    return 0 if all(session["roundtrip"]["mismatches"] == 0 for session in sessions) else 1


if __name__ == "__main__":
    sys.exit(main())
