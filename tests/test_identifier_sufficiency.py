# FILE: tests/test_identifier_sufficiency.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify M-IDENT-SUFFICIENCY: the assessment describes the identifier surface actually shipped, states its assumptions and limits, and refuses bad parameters.
#   SCOPE: figures for the code surface, growth with the table size, capacity at target, parameter rejection, report content.
#   DEPENDS: M-IDENT-SUFFICIENCY, M-TOKEN-GEN
#   LINKS: V-M-IDENT-SUFFICIENCY, M-IDENT-SUFFICIENCY
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   IdentifierSufficiencyTests - unittest case set for the sufficiency assessment
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-4 M-IDENT-SUFFICIENCY verification.
# END_CHANGE_SUMMARY

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from identifier_sufficiency import (  # noqa: E402
    SufficiencyError,
    compute_sufficiency,
    main,
    render_report,
)
from src.token_factory import CODE_LENGTH, CODE_PREFIX  # noqa: E402


class IdentifierSufficiencyTests(unittest.TestCase):
    def test_assessment_describes_the_surface_in_use(self) -> None:
        """Оценка обязана считаться для той поверхности, что стоит в коде."""
        sufficiency = compute_sufficiency()
        self.assertEqual(sufficiency.code_length, CODE_LENGTH)
        self.assertEqual(sufficiency.bits, 40)
        self.assertEqual(sufficiency.space, 32**CODE_LENGTH)

    def test_collision_probability_grows_with_the_table(self) -> None:
        small = compute_sufficiency(values_count=1_000)
        large = compute_sufficiency(values_count=500_000)
        self.assertLess(small.collision_probability, large.collision_probability)
        self.assertLess(large.collision_probability, 0.2)

    def test_accidental_hit_is_negligible_at_the_current_size(self) -> None:
        sufficiency = compute_sufficiency()
        self.assertLess(sufficiency.accidental_hit_probability, 1e-6)

    def test_capacity_at_target_is_reported(self) -> None:
        sufficiency = compute_sufficiency(values_count=10, target=0.001)
        self.assertGreater(sufficiency.safe_values_at_target, sufficiency.values_count)

    def test_bad_parameters_are_rejected(self) -> None:
        for kwargs in (
            {"values_count": 0},
            {"code_length": 0},
            {"alphabet_size": 1},
            {"target": 0},
            {"target": 1},
        ):
            with self.assertRaises(SufficiencyError, msg=str(kwargs)) as ctx:
                compute_sufficiency(**kwargs)
            self.assertEqual(ctx.exception.code, "SUFFICIENCY_BAD_PARAMS")

    def test_report_states_assumptions_and_limits(self) -> None:
        report = render_report(compute_sufficiency())
        self.assertIn("Оценка достаточности метода введения идентификаторов", report)
        self.assertIn("не является шифром", report)
        self.assertIn("разрешения коллизий", report)
        self.assertIn("только тех идентификаторов", report)
        self.assertIn(f"`{CODE_PREFIX}<", report)

    def test_report_names_the_shipped_code_length(self) -> None:
        report = render_report(compute_sufficiency())
        self.assertIn(f"длина {CODE_LENGTH} знаков", report)
        self.assertIn("40 бит", report)

    def test_main_prints_the_assessment(self) -> None:
        self.assertEqual(main(["--values", "1000"]), 0)


if __name__ == "__main__":
    unittest.main()
