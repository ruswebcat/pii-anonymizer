# FILE: tools/count_reliability.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Measure whether counting accuracy on a real selection changes when the same selection is anonymized: the same task is run several times through both arms and every answer is scored against ground truth computed from the data itself.
#   SCOPE: read-only CRM sample, repeated provider calls, rule-based scoring of per-manager counts, markdown verdict.
#   DEPENDS: M-DICT, M-TOKENIZER, M-ROUTER
#   LINKS: tools/count_reliability.py, V-M-REID-TEST
#   ROLE: SCRIPT
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   build_payload - the counting task over a real selection
#   ground_truth - expected per-manager counts from the data
#   score_answer - extract the count the answer claims for each manager
#   run_arm - repeat the task and collect scores
#   main - CLI entry
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Acceptance check: anonymous answers must count as accurately as direct ones.
# END_CHANGE_SUMMARY

"""Counting reliability with and without anonymization.

The owner's question was blunt: "did the maths break?" One wrong answer is not
evidence either way, so this runs the same counting task several times per arm
and scores every answer against the truth computed from the data. Only the tally
decides.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools.ab_compare import (  # noqa: E402
    MODEL,
    SYSTEM,
    build_detokenizer,
    call_direct,
    call_proxied,
    fetch_records,
    load_env,
)
from src.config import load_config  # noqa: E402

USER = (
    "Ниже выгрузка клиентов. Посчитай, сколько клиентов у каждого менеджера, "
    "и выведи результат строкой вида: «Менеджер: N клиентов». "
    "Затем одной строкой назови, у кого клиентов больше."
)


def build_payload(records: list[dict]) -> dict:
    """Build the counting task payload."""
    return {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": USER},
            {
                "role": "user",
                "content": "Выгрузка:\n" + json.dumps(records, ensure_ascii=False, indent=2),
            },
        ],
        "temperature": 0.3,
        "max_tokens": 700,
    }


def ground_truth(records: list[dict]) -> dict[str, int]:
    """Return expected counts keyed by the manager's readable label."""
    truth: dict[str, int] = {}
    for record in records:
        manager = record.get("manager") or {}
        label = " ".join(part for part in (manager.get("name"), manager.get("surname")) if part)
        if not label:
            label = "(пусто)"
        truth[label] = truth.get(label, 0) + 1
    return truth


def score_answer(answer: str, truth: dict[str, int]) -> dict:
    """Extract the count the answer claims for every manager and compare.

    # START_CONTRACT: score_answer
    #   PURPOSE: Turn a free-form answer into a checkable number per manager.
    #   INPUTS: { answer: str, truth: dict[str, int] }
    #   OUTPUTS: { dict - claimed counts, wrong labels, verdict }
    #   SIDE_EFFECTS: none
    #   LINKS: V-M-REID-TEST
    # END_CONTRACT: score_answer
    """
    claimed: dict[str, int | None] = {}
    for label, expected in truth.items():
        first, last = label.split(" ", 1) if " " in label else (label, label)
        pattern = re.compile(
            re.escape(first) + r"[^\n]{0,40}?" + r"(\d{1,3})\s*клиент", re.IGNORECASE
        )
        match = pattern.search(answer)
        if match is None and last != first:
            pattern = re.compile(re.escape(last) + r"[^\n]{0,40}?(\d{1,3})\s*клиент", re.IGNORECASE)
            match = pattern.search(answer)
        claimed[label] = int(match.group(1)) if match else None
    wrong = [label for label, value in claimed.items() if value != truth[label]]
    return {"claimed": claimed, "wrong": wrong, "correct": not wrong}


def run_arm(name: str, payload: dict, repeats: int, api_key: str, detokenizer, truth) -> dict:  # noqa: ANN001
    """Run the task repeatedly through one arm and score every answer."""
    results = []
    for index in range(repeats):
        try:
            if name == "прямой":
                summary = call_direct(payload, api_key)
            else:
                summary = call_proxied(payload, api_key, detokenizer)
        except Exception as exc:  # noqa: BLE001
            results.append({"error": str(exc)})
            print(f"  {name} #{index + 1}: ошибка {exc}", flush=True)
            continue
        score = score_answer(summary["content"], truth)
        results.append({"score": score, "content": summary["content"], "elapsed": summary["elapsed"]})
        print(
            "  %s #%d: %s | %s" % (
                name,
                index + 1,
                "верно" if score["correct"] else f"НЕВЕРНО {score['claimed']}",
                f"{summary['elapsed']} с",
            ),
            flush=True,
        )
    return {"arm": name, "results": results}


def main(argv: list[str] | None = None) -> int:
    """Run the reliability check and write a small report."""
    parser = argparse.ArgumentParser(description="Counting reliability: direct versus proxied")
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--records", type=int, default=30)
    parser.add_argument("--out", default="/tmp/ab_run/count_reliability.md")
    parser.add_argument("--env-file", default="~/.config/pii-proxy/pii-proxy.env")
    parser.add_argument("--profile-env", default="~/.config/pii-proxy/agent.env")
    args = parser.parse_args(argv)

    config = load_config(load_env(args.env_file))
    detokenizer = build_detokenizer(config)
    secrets = load_env(args.profile_env)
    api_key = secrets.get("DEEPSEEK_API_KEY", "")
    records = fetch_records(
        "https://crm.example.com/api/v2", secrets.get("CRM_API_KEY", ""), "crm-demo", args.records
    )
    truth = ground_truth(records)
    labels_masked = {("".join("*" if ch.isalpha() else ch for ch in label)): value for label, value in truth.items()}
    print("истина:", labels_masked, flush=True)
    payload = build_payload(records)

    direct = run_arm("прямой", payload, args.repeats, api_key, detokenizer, truth)
    proxied = run_arm("через прокси", payload, args.repeats, api_key, detokenizer, truth)

    def tally(arm: dict) -> tuple[int, int]:
        ok = sum(1 for item in arm["results"] if item.get("score", {}).get("correct"))
        return ok, len(arm["results"])

    direct_ok, total = tally(direct)
    proxied_ok, _ = tally(proxied)
    lines = [
        "# Точность подсчёта: напрямую против обезличенного",
        "",
        f"Задач на плечо: **{total}**, записей в выгрузке: **{len(records)}**.",
        "",
        f"Ожидаемое распределение (посчитано по данным): {labels_masked}",
        "",
        "| Плечо | Верных ответов | Неверных |",
        "|---|---|---|",
        f"| напрямую | **{direct_ok} из {total}** | {total - direct_ok} |",
        f"| через прокси | **{proxied_ok} из {total}** | {total - proxied_ok} |",
        "",
        "## Разбор неверных ответов",
        "",
    ]
    for arm in (direct, proxied):
        for index, item in enumerate(arm["results"]):
            score = item.get("score")
            if score and not score["correct"]:
                lines += [
                    f"### {arm['arm']}, попытка {index + 1}",
                    "",
                    f"Заявлено: {score['claimed']}",
                    "",
                ]
    Path(args.out).write_text("\n".join(lines), encoding="utf-8")
    Path(args.out).with_suffix(".json").write_text(
        json.dumps({"truth": truth, "direct": direct, "proxied": proxied}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"\nитог: напрямую {direct_ok}/{total}, через прокси {proxied_ok}/{total}")
    print(f"отчёт: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
