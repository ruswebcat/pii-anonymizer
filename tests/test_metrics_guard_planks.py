# FILE: tests/test_metrics_guard_planks.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Prove that the Phase-17 planks of tools/quality_metrics.py can actually fail: a deliberately broken coherence guard turns glued_persons red, a corrupted registry turns ambiguous_codes red, and the intact contour keeps both at zero.
#   SCOPE: plan presence and zero values on the honest pipeline, red verdict with a guard turned off, red verdict with a forced two-values-under-one-code registry.
#   DEPENDS: M-METRICS, M-NAME-COHERENCE, M-MAP-STORE
#   LINKS: V-M-METRICS, V-M-NAME-COHERENCE, V-M-MAP-STORE
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   MetricsGuardPlankTests - планки многозначности и склейки умеют краснеть
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-17 (20.09.2026): планка, которая не умеет краснеть, ничего не доказывает — проверка обоих направлений.
# END_CHANGE_SUMMARY

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from tools import quality_metrics as qm  # noqa: E402


class MetricsGuardPlankTests(unittest.TestCase):
    """Планки Phase-17: ноль на исправном контуре и краснота на сломанном."""

    def test_honest_pipeline_keeps_the_new_planks_at_zero(self) -> None:
        sample = qm.build_client_sample(qm.MIN_SAMPLE)
        pipeline = qm.build_pipeline(sample)
        try:
            report = qm.measure(pipeline=pipeline, sample=sample)
        finally:
            pipeline.close()
        self.assertTrue(report.passed)
        self.assertEqual(report.metric("ambiguous_codes").value, 0.0)
        self.assertEqual(report.metric("glued_persons").value, 0.0)
        self.assertEqual(report.metric("false_glue_blocks").value, 0.0)
        self.assertGreater(report.metric("glued_persons").detail["attempts"], 0)
        self.assertGreater(report.metric("ambiguous_codes").detail["codes"], 0)

    def test_broken_guard_turns_glued_persons_red(self) -> None:
        """Замер с выключенным заслоном обязан показать склейки: планка не декорация."""
        sample = qm.build_client_sample(qm.MIN_SAMPLE)
        pipeline = qm.build_pipeline(sample, guard_mode=qm.MODE_OFF)
        try:
            report = qm.measure(pipeline=pipeline, sample=sample)
        finally:
            pipeline.close()
        glued = report.metric("glued_persons")
        self.assertGreater(glued.value, 0.0)
        self.assertFalse(glued.passed)
        self.assertFalse(report.passed)

    def test_registry_with_two_persons_under_one_code_turns_red(self) -> None:
        """Код, под которым стоят две персоны, обязан сделать прибор красным.

        Порча вносится через сам справочник (значение персоны и наблюдённая форма другой
        персоны под одним кодом) — ровно то состояние, которое инвариант считает недопустимым.
        """
        sample = qm.build_client_sample(qm.MIN_SAMPLE)
        pipeline = qm.build_pipeline(sample)
        store = pipeline.store
        assert store is not None
        code = qm.make_token("P", "иванов", qm.GLUE_COMBOS_KEY)
        store.store(code, "P", "Иванов", "pd:one")
        # Форма чужой персоны: код перестаёт значить ровно одно значение.
        store.append_form(code, "Печёнов")
        try:
            report = qm.measure(pipeline=pipeline, sample=sample)
        finally:
            pipeline.close()
        ambiguous = report.metric("ambiguous_codes")
        self.assertGreater(ambiguous.value, 0.0)
        self.assertFalse(ambiguous.passed)
        self.assertFalse(report.passed)


if __name__ == "__main__":
    unittest.main()
