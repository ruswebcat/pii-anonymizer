# FILE: tests/test_token_cost_report.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify M-TOKEN-COST: the price table is reproducible, PII-free, counted through an injectable provider counter, and never silently empty.
#   SCOPE: sample determinism, format rendering, counter usage, table rendering, provider failure, CLI with an injected counter.
#   DEPENDS: M-TOKEN-COST, M-TOKEN-GEN
#   LINKS: V-M-TOKEN-COST, M-TOKEN-COST
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   TokenCostReportTests - unittest case set for the cost instrument
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-4 M-TOKEN-COST verification.
# END_CHANGE_SUMMARY

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from token_cost_report import (  # noqa: E402
    FORMATS,
    CostReportError,
    build_sample,
    format_value,
    main,
    measure_formats,
    render_table,
)

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()


class TokenCostReportTests(unittest.TestCase):
    def test_sample_is_deterministic_and_free_of_real_data(self) -> None:
        first = build_sample(30)
        second = build_sample(30)
        self.assertEqual(first, second)
        for item in first:
            self.assertIn(item.cls, "PTE")
            self.assertNotIn("@crm", item.value)

    def test_too_small_sample_is_rejected(self) -> None:
        with self.assertRaises(CostReportError) as ctx:
            build_sample(3)
        self.assertEqual(ctx.exception.code, "COST_SAMPLE_TOO_SMALL")

    def test_every_candidate_surface_is_rendered(self) -> None:
        item = build_sample(12)[0]
        rendered = {fmt: format_value(item, 0, fmt) for fmt in FORMATS}
        self.assertEqual(rendered["raw"], item.value)
        self.assertTrue(rendered["framed12"].startswith("[["))
        self.assertTrue(rendered["compact8"].startswith("z"))
        self.assertEqual(len(rendered["compact8"]), 10)
        self.assertEqual(len(rendered["compact6"]), 8)
        self.assertTrue(rendered["legacy_exotic"].startswith("\u27e6"))

    def test_unknown_surface_is_rejected(self) -> None:
        with self.assertRaises(CostReportError) as ctx:
            format_value(build_sample(12)[0], 0, "mystery")
        self.assertEqual(ctx.exception.code, "COST_BAD_FORMAT")

    def test_counter_is_called_once_per_surface(self) -> None:
        calls: list[str] = []

        def counter(text: str) -> int:
            calls.append(text)
            return len(text)

        sample = build_sample(12)
        measured = measure_formats(sample, counter)
        self.assertEqual(len(calls), len(FORMATS))
        self.assertEqual(set(measured), set(FORMATS))

    def test_table_shows_per_value_cost_and_delta(self) -> None:
        measured = {"raw": 880, "framed12": 1392, "compact8": 978}
        table = render_table(measured, 120)
        self.assertIn("| `raw` | 7.33 |", table)
        self.assertIn("+58.2%", table)
        self.assertIn("+11.1%", table)

    def test_provider_failure_gets_a_stable_code(self) -> None:
        def broken(text: str) -> int:
            raise RuntimeError("network down")

        with self.assertRaises(CostReportError) as ctx:
            measure_formats(build_sample(12), broken, formats=("compact8",))
        self.assertEqual(ctx.exception.code, "COST_PROVIDER_UNAVAILABLE")

    def test_main_runs_with_an_injected_counter(self) -> None:
        def counter(text: str) -> int:
            return len(text.splitlines())

        self.assertEqual(main(["--size", "30"], counter=counter), 0)


if __name__ == "__main__":
    unittest.main()
