# FILE: tools/token_cost_report.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Measure what each identifier format costs in provider tokens, so the price of anonymization is a repeatable run rather than a claim in chat.
#   SCOPE: synthetic sample construction, per-format prompt token measurement through an injectable counter, comparison table rendering.
#   DEPENDS: M-TOKEN-GEN
#   LINKS: M-TOKEN-COST, V-M-TOKEN-COST, fn-measure_formats, fn-render_table
#   ROLE: SCRIPT
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   SampleValue - one synthetic value with its class
#   build_sample - deterministic synthetic sample of typical values
#   format_value - render one value in a candidate format
#   measure_formats - prompt tokens per format through a counter callable
#   render_table - markdown comparison table
#   main - CLI entry point
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-4 M-TOKEN-COST: the owner rejected the switch on cost, so the price of every candidate surface became measurable.
# END_CHANGE_SUMMARY

"""Token cost report for identifier formats.

Implements M-TOKEN-COST from docs/ARCHITECTURE.md. Measured on 16.09.2026:
raw values cost 7.33 provider tokens each, the framed twelve character token 11.60
(+58%), the compact `z`-code 8.12 (+11%). The number decides the surface, so it
has to be reproducible — this tool is that run.

The network counter is injected: tests pass a deterministic fake and never call a
provider (a lesson from a unit test that once hit the live API through an ambient
environment variable).
"""

from __future__ import annotations

import json
import os
import random
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Sequence

LOGGER_NAME = "TokenCostReport"
LOG_MARKER = "[TokenCostReport][measure_formats][BLOCK_MEASURE_FORMATS]"

PROVIDER_URL = "https://api.deepseek.com/v1/chat/completions"
PROVIDER_MODEL = "deepseek-chat"
MIN_SAMPLE = 10
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

FORMATS: tuple[str, ...] = (
    "raw",
    "framed12",
    "compact8",
    "compact6",
    "legacy_exotic",
)

_SURNAMES = ("Иванов", "Петров", "Сидоров", "Кузнецов", "Токенчук", "Попов", "Грачёв", "Камышов")
_NAMES = ("Иван", "Пётр", "Сергей", "Алексей", "Дмитрий", "Андрей", "Николай", "Михаил")
_PATRONYMICS = ("Иванович", "Петрович", "Сергеевич", "Алексеевич", "Дмитриевич", "Андреевич")


class CostReportError(RuntimeError):
    """Cost report failure with a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class SampleValue:
    """One synthetic value with its class letter."""

    cls: str
    value: str


# START_BLOCK_BUILD_SAMPLE
def build_sample(size: int = 120, seed: int = 20260916) -> list[SampleValue]:
    """Build a deterministic sample of typical values without any real data.

    # START_CONTRACT: build_sample
    #   PURPOSE: Give the measurement a fixed, reproducible and PII-free input.
    #   INPUTS: { size: int - number of values, seed: int - reproducibility seed }
    #   OUTPUTS: { list[SampleValue] - synthetic values }
    #   SIDE_EFFECTS: none
    #   LINKS: V-M-TOKEN-COST
    # END_CONTRACT: build_sample
    """
    if size < MIN_SAMPLE:
        raise CostReportError(
            "COST_SAMPLE_TOO_SMALL", f"sample of {size} is below the {MIN_SAMPLE} minimum"
        )
    rnd = random.Random(seed)
    sample: list[SampleValue] = []
    for index in range(size):
        kind = index % 3
        if kind == 0:
            value = f"{rnd.choice(_SURNAMES)} {rnd.choice(_NAMES)} {rnd.choice(_PATRONYMICS)}"
            sample.append(SampleValue("P", value))
        elif kind == 1:
            value = "79" + "".join(str(rnd.randint(0, 9)) for _ in range(9))
            sample.append(SampleValue("T", value))
        else:
            value = f"client{rnd.randint(1000, 99999)}@example.ru"
            sample.append(SampleValue("E", value))
    return sample
# END_BLOCK_BUILD_SAMPLE


# START_BLOCK_MEASURE_FORMATS
def _digest(index: int, length: int) -> str:
    """Return a stable pseudo-identifier body of the requested length."""
    rnd = random.Random(9000 + index)
    return "".join(rnd.choice(B32) for _ in range(length))


def format_value(item: SampleValue, index: int, fmt: str) -> str:
    """Render one sample value in the requested format."""
    body12 = _digest(index, 12)
    if fmt == "raw":
        return item.value
    if fmt == "framed12":
        return f"[[{item.cls}-{body12}]]"
    if fmt == "compact8":
        return f"z{item.cls}{_digest(index, 8)}"
    if fmt == "compact6":
        return f"z{item.cls}{_digest(index, 6)}"
    if fmt == "legacy_exotic":
        return f"\u27e6{item.cls}-{body12}\u27e7"
    raise CostReportError("COST_BAD_FORMAT", f"unknown format: {fmt!r}")


def measure_formats(
    sample: Sequence[SampleValue],
    counter: Callable[[str], int],
    formats: Iterable[str] = FORMATS,
) -> dict[str, int]:
    """Count prompt tokens for every format of the same sample.

    # START_CONTRACT: measure_formats
    #   PURPOSE: Produce the comparable token counts that decide the identifier surface.
    #   INPUTS: { sample: Sequence[SampleValue], counter: Callable[[str], int] - text to prompt tokens, formats: Iterable[str] }
    #   OUTPUTS: { dict[str, int] - format to prompt tokens }
    #   SIDE_EFFECTS: calls the injected counter (network in production, fake in tests)
    #   LINKS: V-M-TOKEN-COST, fn-format_value
    # END_CONTRACT: measure_formats
    """
    if len(sample) < MIN_SAMPLE:
        raise CostReportError(
            "COST_SAMPLE_TOO_SMALL", f"sample of {len(sample)} is below the {MIN_SAMPLE} minimum"
        )
    measured: dict[str, int] = {}
    for fmt in formats:
        text = "\n".join(format_value(item, index, fmt) for index, item in enumerate(sample))
        try:
            measured[fmt] = counter(text)
        except CostReportError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise CostReportError(
                "COST_PROVIDER_UNAVAILABLE", f"counter failed for {fmt}: {exc}"
            ) from exc
    return measured


def render_table(measured: Mapping[str, int], sample_size: int) -> str:
    """Render the comparison table with per-value cost and delta to raw values."""
    base = measured.get("raw")
    lines = [
        "| Формат | Токенов на значение | К сырым данным |",
        "|---|---|---|",
    ]
    for fmt in FORMATS:
        if fmt not in measured:
            continue
        per_value = measured[fmt] / sample_size
        if base:
            delta = f"{(measured[fmt] - base) / base * 100:+.1f}%"
        else:
            delta = "—"
        lines.append(f"| `{fmt}` | {per_value:.2f} | {delta} |")
    return "\n".join(lines)
# END_BLOCK_MEASURE_FORMATS


def provider_counter(text: str, api_key: str) -> int:
    """Return the provider's own prompt token count for a text block."""
    payload = {
        "model": PROVIDER_MODEL,
        "messages": [{"role": "user", "content": text}],
        "max_tokens": 1,
    }
    request = urllib.request.Request(
        PROVIDER_URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            body = json.loads(response.read().decode())
    except urllib.error.URLError as exc:
        raise CostReportError("COST_PROVIDER_UNAVAILABLE", f"provider unreachable: {exc}") from exc
    return int(body["usage"]["prompt_tokens"])


def _api_key(env_values: Mapping[str, str] | None = None) -> str:
    """Read the provider key from the given values or the profile environment."""
    if env_values is not None:
        return env_values.get("DEEPSEEK_API_KEY", "")
    env_path = os.path.expanduser("~/.config/pii-proxy/agent.env")
    if os.path.exists(env_path):
        for line in open(env_path, encoding="utf-8"):
            line = line.split("#", 1)[0].strip()
            if line.startswith("DEEPSEEK_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return os.environ.get("DEEPSEEK_API_KEY", "")


def main(argv: Sequence[str] | None = None, counter: Callable[[str], int] | None = None,
         env_values: Mapping[str, str] | None = None) -> int:
    """Run the measurement and print the table.

    # START_CONTRACT: main
    #   PURPOSE: Let the owner reproduce the price of every identifier surface.
    #   INPUTS: { argv: Sequence[str] | None - CLI arguments, counter: Callable | None - injected counter, env_values: Mapping | None - injected environment }
    #   OUTPUTS: { int - process exit code }
    #   SIDE_EFFECTS: prints a table, may call the provider
    #   LINKS: V-M-TOKEN-COST
    # END_CONTRACT: main
    """
    args = list(argv if argv is not None else sys.argv[1:])
    size = MIN_SAMPLE
    for index, arg in enumerate(args):
        if arg == "--size" and index + 1 < len(args):
            size = int(args[index + 1])
    sample = build_sample(size)
    if counter is None:
        api_key = _api_key(env_values)
        if not api_key:
            raise CostReportError("COST_PROVIDER_UNAVAILABLE", "provider key is not available")
        counter = lambda text: provider_counter(text, api_key)  # noqa: E731
    measured = measure_formats(sample, counter)
    print(f"значений в выборке: {len(sample)}")
    print(render_table(measured, len(sample)))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
