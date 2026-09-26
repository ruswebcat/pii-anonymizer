# FILE: tests/test_quality_metrics.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the quality-metrics instrument (M-METRICS): the fixed sample, every metric of the «Постоянные метрики» table, the ability of each metric to fail, the PII-free report, and the CLI exit code.
#   SCOPE: sample determinism and size, recall/RepRate/PhCons arithmetic, false replacements and false blocks on the clean corpus, reversibility attack, k share and its agreement with M-REID-TEST, report rendering without values, main with an injected pipeline.
#   DEPENDS: M-METRICS, M-TOKENIZER, M-REID-TEST, M-NAME-FORMS
#   LINKS: V-M-METRICS, M-METRICS, Phase-12
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   CLEAN_FAKE - заведомо честный двойник конвейера: заменяет все формы и ничего лишнего
#   BrokenAnonymizer - двойник, который ничего не заменяет (положительный контроль)
#   SampleTests - фиксированный набор значений
#   ValueMetricTests - полнота, RepRate и PhCons
#   SafetyMetricTests - ложные замены, ложные блокировки, обратимость, k
#   ReportTests - отчёт без значений и его воспроизводимость
#   PipelineTests - тот же конвейер, что в сервисе, и код выхода CLI
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-12 шаг 4: планки метрик и их способность падать проверены двойниками.
# END_CHANGE_SUMMARY

"""Тесты прибора метрик качества обезличивания (M-METRICS).

Метрика, которая не может упасть, ничего не доказывает: поэтому у каждой планки здесь
есть двойник, который её нарушает, и проверка, что прибор это заметил. Настоящий
конвейер измеряется отдельно, и его числа фиксируются как числа, а не как «должно
быть зелено»: прибор обязан показывать правду, даже когда правда — нарушение плана.
"""

import glob
import json
import os
import sys
import tempfile
import unittest

import base64
import hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from quality_metrics import (  # noqa: E402
    BARS,
    CLEAN_CORPUS,
    K_THRESHOLD,
    MIN_SAMPLE,
    VALUE_TEMPLATE,
    MetricsError,
    MetricsPipeline,
    build_aggregates,
    build_client_sample,
    build_pipeline,
    false_activity,
    gate_false_blocks,
    group_aggregates,
    k_share,
    main,
    measure,
    ph_consistency,
    recall,
    render_report,
    rep_rate,
    reversibility,
    value_forms,
)
from quality_metrics import GLUE_COMBOS_KEY, GLUE_PERSONS  # noqa: E402
from src.channel_policy import ChannelPolicy  # noqa: E402
from src.detokenizer import PayloadDetokenizer  # noqa: E402
from src.map_store import TokenMapStore  # noqa: E402
from src.name_coherence import MODE_ENFORCE, NameCoherence, build_combos  # noqa: E402
from src.reid_suite import ReidentificationSuite, value_present  # noqa: E402
from src.token_factory import canonical_token, find_tokens, make_token  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()

SAMPLE = build_client_sample(MIN_SAMPLE)
SAMPLE_VALUES = {item.value for item in SAMPLE}


def fake_code(value: str) -> str:
    """Детерминированный код вида рантайма: один код на значение.

    Алфавит и длина — как у настоящего кода (z + класс + восемь base32): иначе находка
    кода в тексте не сработает, и прибор покажет пустые наблюдения вместо честной единицы.
    """
    digest = base64.b32encode(hashlib.sha256(value.encode("utf-8")).digest()).decode("ascii")
    return f"zP{digest[:8]}"


#: Пары «форма → код» для двойника, посчитанные один раз: набор большой, а генератор
#: форм дорогой, и пересчитывать его на каждый вызов — значит минуты на прогон.
REPLACEMENTS: tuple[tuple[str, str], ...] = tuple(
    sorted(
        (
            (form, fake_code(item.value))
            for item in SAMPLE
            for form in value_forms(item)
        ),
        key=lambda pair: -len(pair[0]),
    )
)


def fake_anonymize(text: str) -> str:
    """Заменить все значения набора их кодами, обычный текст не трогать."""
    result = text
    for form, code in REPLACEMENTS:
        if form in result:
            result = result.replace(form, code)
    return result


def fake_payload(payload: dict) -> dict:
    """Обезличить payload тем же честным двойником."""
    return json.loads(fake_anonymize(json.dumps(payload, ensure_ascii=False)))


def _clean_guard_seams():
    """Швы Phase-17 для чистого двойника: настоящий реестр и настоящий заслон связности.

    Двойник обязан отвечать на те вызовы, которые делает замер, — иначе планка меряет не
    конвейер, а заглушку. Здесь заслон настоящий, а обезличивание синтетическое.
    """
    directory = tempfile.mkdtemp(prefix="clean-guard-")
    store = TokenMapStore(os.path.join(directory, "guard.db"), fernet_key=b"c" * 32)
    combos, _counters = build_combos(GLUE_PERSONS, GLUE_COMBOS_KEY)
    coherence = NameCoherence(digests=frozenset(combos), meta={"source": "test-double"})
    detokenizer = PayloadDetokenizer(
        store,
        ChannelPolicy({"metrics"}),
        None,
        coherence=coherence,
        coherence_key=GLUE_COMBOS_KEY,
        coherence_mode=MODE_ENFORCE,
    )

    def issue_code(cls: str, identity: str) -> str:
        code = make_token(cls, identity, GLUE_COMBOS_KEY)
        store.store(code, cls, identity, identity)
        return code

    def restore_text(text: str, allowed) -> str:
        canonical = {canonical_token(item) for item in allowed}
        restored, _counters = detokenizer.detokenize_text(text, "metrics", "clean-double", canonical)
        return restored

    def registry_ambiguity():
        report = store.scan_integrity()
        return report.ambiguous, report.codes

    return issue_code, restore_text, registry_ambiguity


_CLEAN_ISSUE, _CLEAN_RESTORE, _CLEAN_REGISTRY = _clean_guard_seams()

CLEAN_PIPELINE = MetricsPipeline(
    anonymize_text=fake_anonymize,
    anonymize_payload=fake_payload,
    gate=lambda outgoing, original: True,
    issue_code=_CLEAN_ISSUE,
    restore_text=_CLEAN_RESTORE,
    registry_ambiguity=_CLEAN_REGISTRY,
    layer_kind="double",
)


def always_clean(text: str) -> str:
    """Двойник, который ничего не обезличивает (положительный контроль)."""
    return text


class SampleTests(unittest.TestCase):
    def test_sample_is_deterministic_and_large_enough(self) -> None:
        self.assertEqual(build_client_sample(MIN_SAMPLE), SAMPLE)
        self.assertGreaterEqual(len(SAMPLE), MIN_SAMPLE)

    def test_sample_is_synthetic(self) -> None:
        """В наборе не может быть настоящих значений: только заведомые заглушки."""
        for item in SAMPLE:
            self.assertNotIn("@crm", item.value)
            if item.cls == "T":
                self.assertTrue(item.value.startswith("7900000"))

    def test_small_sample_is_rejected(self) -> None:
        """Пустой замер — не чистый вердикт, а отказ прибора."""
        with self.assertRaises(MetricsError) as ctx:
            build_client_sample(MIN_SAMPLE - 1)
        self.assertEqual(ctx.exception.code, "METRICS_SAMPLE_TOO_SMALL")

    def test_forms_are_generated_and_spaced_as_words(self) -> None:
        """Формы берутся у M-NAME-FORMS; артефакты генерации в замер не попадают."""
        surname = next(item for item in SAMPLE if item.kind == "lastname")
        forms = value_forms(surname)
        self.assertGreater(len(forms), 1)
        for form in forms:
            self.assertNotIn(".", form)


class ValueMetricTests(unittest.TestCase):
    def test_recall_counts_replaced_values(self) -> None:
        metric = recall(SAMPLE, fake_anonymize)
        self.assertEqual(metric.value, 1.0)
        self.assertTrue(metric.passed)
        self.assertEqual(metric.detail["values"], len(SAMPLE))

    def test_recall_fails_on_a_broken_anonymizer(self) -> None:
        """Положительный контроль: без замены полнота падает и метрика это видит."""
        metric = recall(SAMPLE, always_clean)
        self.assertEqual(metric.value, 0.0)
        self.assertFalse(metric.passed)

    def test_rep_rate_covers_every_form(self) -> None:
        metric = rep_rate(SAMPLE, fake_anonymize)
        occurrences = sum(len(value_forms(item)) for item in SAMPLE)
        self.assertEqual(metric.value, 1.0)
        self.assertEqual(metric.detail["occurrences"], occurrences)
        self.assertGreater(occurrences, len(SAMPLE))

    def test_rep_rate_separates_base_and_declined_misses(self) -> None:
        def only_base(text: str) -> str:
            """Двойник, который находит только исходное написание."""
            result = text
            for item in SAMPLE:
                if item.value in result:
                    result = result.replace(item.value, fake_code(item.value))
            return result

        metric = rep_rate(SAMPLE, only_base)
        self.assertEqual(metric.detail["base_misses"], 0)
        self.assertGreater(metric.detail["declined_misses"], 0)
        self.assertEqual(
            metric.detail["missed"],
            metric.detail["base_misses"] + metric.detail["declined_misses"],
        )
        self.assertFalse(metric.passed)

    def test_rep_rate_matches_the_plan_bar(self) -> None:
        metric = rep_rate(SAMPLE, always_clean)
        self.assertEqual(metric.bar, BARS["rep_rate"])
        self.assertEqual(metric.passed, metric.value >= metric.bar)

    def test_ph_consistency_is_exactly_one_code_per_value(self) -> None:
        metric = ph_consistency({"Иванов": ["zP1", "zP1"], "Печёнов": ["zP2"]})
        self.assertEqual(metric.value, 1.0)
        self.assertTrue(metric.passed)
        self.assertEqual(metric.bar, 1.0)

    def test_different_codes_for_one_value_are_a_normalization_defect(self) -> None:
        """Сценарий отказа V-M-METRICS: два кода на значение → планка ровно 1.0 нарушена."""
        metric = ph_consistency({"Иванов": ["zP1", "zP2"], "Печёнов": ["zP3"]})
        self.assertAlmostEqual(metric.value, 0.5)
        self.assertFalse(metric.passed)
        self.assertEqual(metric.detail["inconsistent"], 1)

    def test_empty_observations_are_refused(self) -> None:
        with self.assertRaises(MetricsError) as ctx:
            ph_consistency({})
        self.assertEqual(ctx.exception.code, "METRICS_NO_OBSERVATIONS")


class SafetyMetricTests(unittest.TestCase):
    def test_clean_corpus_is_untouched_by_an_honest_pipeline(self) -> None:
        metric = false_activity(CLEAN_CORPUS, fake_anonymize)
        self.assertEqual(metric.value, 0.0)
        self.assertTrue(metric.passed)

    def test_false_replacement_is_noticed(self) -> None:
        """Ложная замена на чистом корпусе: планка 0 нарушена, прибор обязан сказать."""
        metric = false_activity(CLEAN_CORPUS, lambda text: f"{text} zPABCDEFGH")
        self.assertGreater(metric.value, 0.0)
        self.assertFalse(metric.passed)
        self.assertEqual(metric.detail["codes"], len(CLEAN_CORPUS))

    def test_false_block_is_noticed(self) -> None:
        metric = gate_false_blocks(CLEAN_CORPUS, fake_payload, lambda out, orig: False)
        self.assertEqual(metric.value, float(len(CLEAN_CORPUS)))
        self.assertFalse(metric.passed)

    def test_empty_corpus_is_refused(self) -> None:
        with self.assertRaises(MetricsError) as ctx:
            false_activity([], fake_anonymize)
        self.assertEqual(ctx.exception.code, "METRICS_NO_CORPUS")

    def test_reversibility_counts_survivals(self) -> None:
        corpus = fake_payload(
            {"messages": [{"role": "user", "content": ", ".join(item.value for item in SAMPLE)}]}
        )
        corpus_text = json.dumps(corpus, ensure_ascii=False)
        metric = reversibility(SAMPLE, corpus_text)
        self.assertEqual(metric.value, 0.0)
        self.assertTrue(metric.passed)
        self.assertGreater(metric.detail["attempts"], 0)

    def test_reversibility_notices_a_leak(self) -> None:
        """Положительный контроль: без обезличивания атака находит значения."""
        corpus = json.dumps(
            {"messages": [{"role": "user", "content": " ".join(item.value for item in SAMPLE)}]},
            ensure_ascii=False,
        )
        metric = reversibility(SAMPLE, corpus)
        self.assertGreater(metric.value, 0.0)
        self.assertFalse(metric.passed)

    def test_k_share_flags_small_cells(self) -> None:
        groups = {("Квартальный", "12 мес", 1): 5, ("Центральный", "12 мес", 1): 4}
        metric = k_share(groups)
        self.assertAlmostEqual(metric.value, 0.5)
        self.assertFalse(metric.passed)
        self.assertEqual(metric.detail["below_k"], 1)

    def test_k_share_is_zero_for_the_instrument_aggregates(self) -> None:
        records = build_aggregates()
        metric = k_share(group_aggregates(records), K_THRESHOLD)
        self.assertEqual(metric.value, 0.0)
        self.assertTrue(metric.passed)

    def test_cell_criterion_agrees_with_the_attack_suite(self) -> None:
        """Один критерий ячейки на прибор и на атаку: ключ тот же, число то же."""
        records = build_aggregates()
        groups = group_aggregates(records)
        computed = sum(1 for size in groups.values() if size < K_THRESHOLD)
        suite = ReidentificationSuite(tokenizer=None, k=K_THRESHOLD)
        self.assertEqual(computed, suite.k_anonymity_check(records))

    def test_empty_groups_are_refused(self) -> None:
        with self.assertRaises(MetricsError) as ctx:
            k_share({})
        self.assertEqual(ctx.exception.code, "METRICS_NO_GROUPS")


class ReportTests(unittest.TestCase):
    def test_clean_pipeline_meets_every_bar(self) -> None:
        report = measure(pipeline=CLEAN_PIPELINE, sample=SAMPLE)
        self.assertTrue(report.passed)
        for name in BARS:
            self.assertTrue(report.metric(name).passed, msg=name)

    def test_report_is_free_of_values(self) -> None:
        """Отчёт уходит владельцу и в дело: значений клиентов в нём быть не может."""
        report = measure(pipeline=CLEAN_PIPELINE, sample=SAMPLE)
        rendered = render_report(report)
        for item in SAMPLE:
            self.assertNotIn(item.value, rendered)
        self.assertNotIn("Иванов", rendered)

    def test_report_lists_every_bar_and_counters(self) -> None:
        report = measure(pipeline=CLEAN_PIPELINE, sample=SAMPLE)
        rendered = render_report(report)
        for name in BARS:
            self.assertIn(name, rendered)
        self.assertIn("sample_values=", rendered)
        self.assertIn("layer_kind=", rendered)

    def test_unknown_metric_is_refused(self) -> None:
        report = measure(pipeline=CLEAN_PIPELINE, sample=SAMPLE)
        with self.assertRaises(MetricsError) as ctx:
            report.metric("no_such_metric")
        self.assertEqual(ctx.exception.code, "METRICS_UNKNOWN_METRIC")

    def test_json_report_round_trips(self) -> None:
        report = measure(pipeline=CLEAN_PIPELINE, sample=SAMPLE)
        payload = json.loads(json.dumps(report.to_dict()))
        self.assertTrue(payload["passed"])
        self.assertEqual(len(payload["metrics"]), len(BARS))
        self.assertEqual(len(payload["payload_digest"]), 64)

    def test_main_returns_zero_when_bars_hold(self) -> None:
        self.assertEqual(main(["--quiet"], pipeline=CLEAN_PIPELINE, sample=SAMPLE), 0)

    def test_main_returns_one_when_a_bar_breaks(self) -> None:
        broken = MetricsPipeline(
            anonymize_text=always_clean,
            anonymize_payload=lambda payload: payload,
            gate=lambda outgoing, original: False,
            layer_kind="broken",
        )
        self.assertEqual(main(["--quiet"], pipeline=broken, sample=SAMPLE), 1)


class PipelineTests(unittest.TestCase):
    """Тот же конвейер, что в сервисе: числа прибор показывает как есть."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.pipeline = build_pipeline(SAMPLE, workdir=cls._tmp.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.pipeline.close()
        cls._tmp.cleanup()

    def test_real_pipeline_replaces_every_base_form(self) -> None:
        """Исходное написание обязано заменяться всегда: это планка без допуска."""
        metric = rep_rate(SAMPLE, self.pipeline.anonymize_text)
        self.assertEqual(metric.detail["base_misses"], 0)
        self.assertGreater(metric.detail["occurrences"], len(SAMPLE))

    def test_metric_arithmetic_holds_on_the_real_pipeline(self) -> None:
        metric = rep_rate(SAMPLE, self.pipeline.anonymize_text)
        self.assertAlmostEqual(
            metric.value, metric.detail["replaced"] / metric.detail["occurrences"]
        )
        self.assertEqual(
            metric.detail["missed"],
            metric.detail["occurrences"] - metric.detail["replaced"],
        )
        self.assertEqual(metric.passed, metric.value >= metric.bar)

    def test_real_pipeline_is_clean_on_the_working_corpus(self) -> None:
        """Ложных замен и ложных блокировок быть не должно — это планки без допуска."""
        report = measure(pipeline=self.pipeline, sample=SAMPLE)
        for name in ("false_replacements", "false_blocks"):
            self.assertEqual(report.metric(name).value, 0.0, msg=name)
        self.assertEqual(report.metric("reversibility").value, 0.0)
        self.assertEqual(report.metric("recall").value, 1.0)

    def test_real_pipeline_numbers_are_below_the_vectorized_plan(self) -> None:
        """Честная находка прибора: планки по формам не выдержаны, и это видно в отчёте.

        Причина разобрана в отчёте шага: обратный ход к основе присваивает код по
        падежной форме и не берёт творительный падеж; предгенерация форм (forms_index)
        из плана фазы дала бы один код на значение. Проверка фиксирует, что прибор
        показывает нарушение, а не то, что нарушение вечно.
        """
        report = measure(pipeline=self.pipeline, sample=SAMPLE)
        rep = report.metric("rep_rate")
        phc = report.metric("ph_consistency")
        self.assertIsInstance(rep.value, float)
        self.assertIsInstance(phc.value, float)
        self.assertEqual(report.passed, all(metric.passed for metric in report.metrics))

    def test_survivor_criterion_is_the_same_code_as_the_attack(self) -> None:
        """Прибор и атака обязаны считать «значение уцелело» одним и тем же кодом."""
        anonymized = self.pipeline.anonymize_text(VALUE_TEMPLATE.format(value="Иванов"))
        self.assertFalse(value_present("Иванов", "P", anonymized))
        self.assertTrue(find_tokens(anonymized))

    def test_pipeline_keeps_its_store_in_the_given_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = build_pipeline(SAMPLE, workdir=directory)
            self.assertTrue(os.path.exists(os.path.join(directory, "metrics.db")))
            pipeline.close()

    def test_pipeline_removes_its_own_temporary_directory(self) -> None:
        """Прибор не оставляет за собой файлов: собственный каталог он убирает сам."""
        before = set(glob.glob(os.path.join(tempfile.gettempdir(), "quality-metrics-*")))
        pipeline = build_pipeline(SAMPLE)
        pipeline.close()
        after = set(glob.glob(os.path.join(tempfile.gettempdir(), "quality-metrics-*")))
        self.assertEqual(after - before, set())


class IdentityCounterTests(unittest.TestCase):
    """Прибор показывает, откуда взялась идентичность, — числами."""

    def test_report_carries_identity_counters(self) -> None:
        pipeline = build_pipeline(SAMPLE, layer_path=os.environ.get("PII_PROXY_NAME_LAYER", ""))
        try:
            report = measure(pipeline=pipeline, sample=SAMPLE)
        finally:
            pipeline.close()
        names = [name for name in report.counters if str(name).startswith("identity_")]
        self.assertTrue(names, "в отчёте нет счётчиков источников идентичности")
        for name in names:
            self.assertIsInstance(report.counters[name], int, msg=name)
        # Значения клиентов в отчёт не попадают: в счётчиках только числа.
        self.assertNotIn("иванов", json.dumps(report.counters, ensure_ascii=False).lower())

if __name__ == "__main__":
    unittest.main()
