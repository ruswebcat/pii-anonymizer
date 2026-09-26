# FILE: tools/ab_compare.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Answer the owner's question "will anonymization make the model worse at my tasks?" with a blind side-by-side run: the same real tasks answered directly and through the proxy, with token, cache and latency figures.
#   SCOPE: reads a task list and a read-only CRM sample, calls the provider twice per task, detokenizes the proxied arm, writes a blind report plus a separate answer key.
#   DEPENDS: M-ROUTER, M-DETOKENIZER, M-DICT, M-TOKENIZER
#   LINKS: tools/ab_compare.py, docs/ACT.md
#   ROLE: SCRIPT
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   load_env - read a KEY=VALUE file
#   fetch_records - read a real client sample, read-only
#   aggregate_block - build a PII-free analytics block
#   build_payload - assemble the messages for one task
#   call_direct - arm A: straight to the provider
#   call_proxied - arm B: through the anonymization proxy
#   detokenize_text - restore tokens for a trusted channel
#   run_task - run both arms and collect metrics
#   main - CLI entry
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-3 acceptance: blind A/B of answer quality with and without anonymization.
# END_CHANGE_SUMMARY

"""Blind A/B comparison of answer quality: direct provider call versus proxied call."""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.config import load_config  # noqa: E402
from src.channel_policy import ChannelPolicy  # noqa: E402
from src.detokenizer import PayloadDetokenizer  # noqa: E402
from src.dict_export import crm_fetcher  # noqa: E402
from src.map_store import TokenMapStore  # noqa: E402

SYSTEM = (
    "Ты помощник сети фитнес-клубов «Пример Спорт» в Примерск. Отвечай по-русски, "
    "кратко и по делу, без канцелярита."
)
DIRECT_URL = "https://api.deepseek.com/v1/chat/completions"
PROXY_URL = "http://127.0.0.1:8791/ds/v1/chat/completions"
MODEL = "deepseek-chat"


def load_env(path: str) -> dict[str, str]:
    """Read a KEY=VALUE file, tolerating comments and blank lines."""
    values: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name.strip()] = value.strip()
    return values


def fetch_records(base_url: str, key: str, club: str, limit: int) -> list[dict]:
    """Read a real client sample, read-only."""
    fetcher = crm_fetcher(base_url, key, club)
    payload = fetcher(f"/client?page=1&page_size={limit}")
    return list((payload or {}).get("items", []))[:limit]


def aggregate_block() -> str:
    """Return a PII-free analytics block in the shape the agent normally sees."""
    rows = [
        {"клуб": "Квартальный", "продажи": 41, "выручка": 812400, "продления": 18, "прошлая_неделя": 47},
        {"клуб": "Центральный", "продажи": 63, "выручка": 1043100, "продления": 27, "прошлая_неделя": 58},
        {"клуб": "Базовый", "продажи": 88, "выручка": 986700, "продления": 31, "прошлая_неделя": 96},
    ]
    return json.dumps({"продажи_за_неделю": rows}, ensure_ascii=False, indent=2)


def build_payload(task: dict, records: list[dict]) -> dict:
    """Assemble the messages for one task."""
    messages: list[dict] = [{"role": "system", "content": SYSTEM}]
    user_text = task["user"]
    if task.get("ask_about_first") and records:
        surname = str(records[0].get("surname") or "").strip()
        user_text = user_text.replace("{surname}", surname)
    messages.append({"role": "user", "content": user_text})
    if task.get("aggregate"):
        messages.append({"role": "user", "content": "Данные:\n" + aggregate_block()})
    count = int(task.get("records") or 0)
    if count:
        sample = records[:count]
        if task.get("employee"):
            sample = [
                {
                    "name": r.get("name"),
                    "surname": r.get("surname"),
                    "patronymic": r.get("patronymic"),
                    "club": r.get("club"),
                    "должность": "тренер",
                }
                for r in sample
            ]
        messages.append(
            {
                # Plain "user" role: a bare tool message without a preceding tool
                # call is rejected by the provider with 400 (seen 15.09.2026), and
                # the point of the run is the content, not the envelope.
                "role": "user",
                "content": "Выгрузка:\n"
                + json.dumps(sample, ensure_ascii=False, indent=2),
            }
        )
    return {"model": MODEL, "messages": messages, "temperature": 0.3, "max_tokens": 900}


def _post(url: str, payload: dict, api_key: str, timeout: int = 180) -> dict:
    """POST a chat completion and return (body, elapsed seconds).

    One retry on a transport-level failure: the very first call after the proxy
    starts can fail while the dictionary and morphology are still warming up
    (seen as a 502 on 15.09.2026), and a flaky call would corrupt the comparison.
    """
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        },
        method="POST",
    )
    last_error: Exception | None = None
    for attempt in range(2):
        started = time.time()
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                parsed = json.loads(response.read().decode("utf-8"))
            return {"body": parsed, "elapsed": time.time() - started}
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code < 500 or attempt == 1:
                raise
        except Exception as exc:  # noqa: BLE001 - retry once, then report
            last_error = exc
            if attempt == 1:
                raise
        time.sleep(2)
    raise RuntimeError(f"request failed: {last_error}")


def call_direct(payload: dict, api_key: str) -> dict:
    """Arm A: the provider is called exactly as it is today."""
    result = _post(DIRECT_URL, payload, api_key)
    return _summarize(result)


def call_proxied(payload: dict, api_key: str, detokenizer: PayloadDetokenizer) -> dict:
    """Arm B: the same request, anonymized on the way out and restored on return."""
    result = _post(PROXY_URL, payload, api_key)
    summary = _summarize(result)
    content = summary["content"]
    restored, counts = detokenizer.detokenize_text(content, "mattermost")
    summary["content"] = restored
    summary["tokens_restored"] = sum(counts.values()) if isinstance(counts, dict) else 0
    return summary


def _summarize(result: dict) -> dict:
    """Extract the answer plus the provider's own accounting for one call."""
    body = result["body"]
    usage = body.get("usage") or {}
    choice = (body.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    hit = usage.get("prompt_cache_hit_tokens")
    miss = usage.get("prompt_cache_miss_tokens")
    return {
        "content": str(message.get("content") or "").strip(),
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
        "cache_hit_tokens": hit,
        "cache_miss_tokens": miss,
        "elapsed": round(result["elapsed"], 2),
    }


def run_task(task: dict, records: list[dict], api_key: str, detokenizer: PayloadDetokenizer) -> dict:
    """Run both arms for one task and return the pair plus metrics."""
    payload = build_payload(task, records)
    try:
        direct = call_direct(payload, api_key)
    except Exception as exc:  # noqa: BLE001 - a failed arm must not stop the run
        direct = {"content": f"ОШИБКА прямого вызова: {exc}", "elapsed": None}
    try:
        proxied = call_proxied(payload, api_key, detokenizer)
    except Exception as exc:  # noqa: BLE001
        proxied = {"content": f"ОШИБКА через прокси: {exc}", "elapsed": None}
    first_is_direct = random.random() < 0.5
    first, second = (direct, proxied) if first_is_direct else (proxied, direct)
    return {
        "id": task["id"],
        "title": task["title"],
        "kind": task["kind"],
        "variant_1_from": "напрямую" if first_is_direct else "через прокси",
        "variant_2_from": "через прокси" if first_is_direct else "напрямую",
        "variant_1": first,
        "variant_2": second,
        "direct": direct,
        "proxied": proxied,
    }


def build_detokenizer(config) -> PayloadDetokenizer:  # noqa: ANN001
    """Build a detokenizer writing to the same correspondence table."""
    store = TokenMapStore(config.map_db_path, config.fernet_key, config.ttl_days)
    policy = ChannelPolicy(sorted(config.detok_channels))
    return PayloadDetokenizer(store, policy)


def main(argv: list[str] | None = None) -> int:
    """Run the whole A/B and write the report and the answer key."""
    parser = argparse.ArgumentParser(description="Blind A/B: direct versus proxied answers")
    parser.add_argument("--tasks", default="/tmp/ab_tasks.json")
    parser.add_argument("--out-dir", default="/tmp/ab_run")
    parser.add_argument("--env-file", default="~/.config/pii-proxy/pii-proxy.env")
    parser.add_argument("--profile-env", default="~/.config/pii-proxy/agent.env")
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    tasks = json.loads(Path(args.tasks).read_text(encoding="utf-8"))
    config = load_config(load_env(args.env_file))
    detokenizer = build_detokenizer(config)
    secrets = load_env(args.profile_env)
    api_key = secrets.get("DEEPSEEK_API_KEY", "")
    if not api_key:
        print("AB_MISSING_KEY: DEEPSEEK_API_KEY not found", file=sys.stderr)
        return 2
    records = fetch_records(
        "https://crm.example.com/api/v2", secrets.get("CRM_API_KEY", ""), "crm-demo", 40
    )
    print(f"задач: {len(tasks)}, записей в выборке: {len(records)}", flush=True)

    results = []
    for task in tasks:
        outcome = run_task(task, records, api_key, detokenizer)
        results.append(outcome)
        print(
            "готово: %s (%s) | напрямую %s с | прокси %s с"
            % (
                task["id"],
                task["title"],
                outcome["direct"].get("elapsed"),
                outcome["proxied"].get("elapsed"),
            ),
            flush=True,
        )

    (out_dir / "results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    report = ["# Слепое сравнение анонимных ответов", ""]
    key = ["# Ключ: где какой вариант", ""]
    for item in results:
        report += [
            f"## {item['id']}. {item['title']}",
            "",
            f"*Тип задачи: {item['kind']}*",
            "",
            "**Вариант 1**",
            "",
            item["variant_1"]["content"] or "(пусто)",
            "",
            "**Вариант 2**",
            "",
            item["variant_2"]["content"] or "(пусто)",
            "",
            "---",
            "",
        ]
        key += [
            f"## {item['id']}. {item['title']}",
            "",
            f"- напрямую: {item['direct'].get('elapsed')} с, "
            f"промпт {item['direct'].get('prompt_tokens')} ток., "
            f"кэш-попадание {item['direct'].get('cache_hit_tokens')}, "
            f"кэш-промах {item['direct'].get('cache_miss_tokens')}, "
            f"ответ {item['direct'].get('completion_tokens')} ток.",
            f"- через прокси: {item['proxied'].get('elapsed')} с, "
            f"промпт {item['proxied'].get('prompt_tokens')} ток., "
            f"кэш-попадание {item['proxied'].get('cache_hit_tokens')}, "
            f"кэш-промах {item['proxied'].get('cache_miss_tokens')}, "
            f"ответ {item['proxied'].get('completion_tokens')} ток., "
            f"восстановлено значений {item['proxied'].get('tokens_restored')}",
            "",
        ]
    (out_dir / "blind_report.md").write_text("\n".join(report), encoding="utf-8")
    (out_dir / "answer_key.md").write_text("\n".join(key), encoding="utf-8")

    direct_prompt = sum(int(r["direct"].get("prompt_tokens") or 0) for r in results)
    proxied_prompt = sum(int(r["proxied"].get("prompt_tokens") or 0) for r in results)
    direct_hit = sum(int(r["direct"].get("cache_hit_tokens") or 0) for r in results)
    proxied_hit = sum(int(r["proxied"].get("cache_hit_tokens") or 0) for r in results)
    print(
        "итог: промпт напрямую %s ток. (кэш-попаданий %s) | через прокси %s ток. (кэш-попаданий %s)"
        % (direct_prompt, direct_hit, proxied_prompt, proxied_hit)
    )
    print(f"отчёт: {out_dir / 'blind_report.md'}")
    print(f"ключ: {out_dir / 'answer_key.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
