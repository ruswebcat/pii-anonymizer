# FILE: tests/test_name_identity.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify M-NAME-IDENTITY: the identity of a name is the person, not the case form — client exact value first, then the value a form was generated from, then an open-list base that regenerates the form, then the surface spelling; ambiguity is never guessed.
#   SCOPE: client form index, exact-value precedence, ambiguous form handling, open-list base with regeneration, stem tier for feminine forms, yo folding, shared same-value rule, counters without values, broken layer fail-open, index cap.
#   DEPENDS: M-NAME-IDENTITY, M-CLIENT-LAYER, M-NAME-FORMS
#   LINKS: V-M-NAME-IDENTITY, M-NAME-IDENTITY
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   FakeLayer - открытый список из нескольких значений
#   ClientIndexTests - индекс форм клиентского слоя
#   LayerBaseTests - основа открытого списка и её проверка порождением
#   AmbiguityTests - неоднозначность не угадывается
#   MatchesIdentityTests - одно правило «это то же значение?»
#   CounterTests - счётчики как числа, без значений клиентов
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-7 шаг 1: политика идентичности значения (решение владельца 18.09.2026).
# END_CHANGE_SUMMARY

"""Тесты идентичности значения.

Решение владельца 18.09.2026: код присваивается персоне, а не падежной форме. Эти тесты
проверяют порядок разрешения и — отдельно — что неоднозначность не разрешается угадыванием.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.name_identity import (  # noqa: E402
    SOURCE_CLIENT_EXACT,
    SOURCE_CLIENT_FORM,
    SOURCE_LAYER_BASE,
    SOURCE_SURFACE,
    MAX_CLIENT_VALUES,
    NameIdentity,
    matches_identity,
)


class FakeLayer:
    """Открытый список из нескольких значений."""

    def __init__(self, values) -> None:
        self.values = {value.lower() for value in values}

    def contains(self, value: str, cls: str | None = None) -> bool:
        return str(value).lower() in self.values


class ClientIndexTests(unittest.TestCase):
    """Клиентский слой: точное значение важнее основы, форма ведёт к своему значению."""

    def test_declined_form_resolves_to_the_client_value(self) -> None:
        """Женская запись клиента: «Терёхиной» → значение «Терёхина»."""
        resolver = NameIdentity(["Терёхина"])
        for form in ("Терёхиной", "Терёхину"):
            identity = resolver.resolve(form)
            self.assertEqual(identity.source, SOURCE_CLIENT_FORM, msg=form)
            self.assertEqual(identity.value, "терехина", msg=form)

    def test_male_value_does_not_generate_the_feminine_form(self) -> None:
        """Граница таблиц: из «Терёхин» женская форма «Терёхиной» не выводится.

        Поэтому женские записи обязаны быть в клиентском слое (или находиться по открытому
        списку): иначе «Терёхиной» получит собственный код. Граница зафиксирована тестом,
        чтобы её нельзя было принять за регресс.
        """
        resolver = NameIdentity(["Терёхин"], FakeLayer(["терехина"]))
        self.assertEqual(resolver.resolve("Терёхиной").source, SOURCE_SURFACE)
        # Найденной значение при этом остаётся: распознавание формы и идентичность —
        # разные вопросы (см. LayerBaseTests.test_feminine_form_uses_the_table_reverse_move).

    def test_nominative_is_the_exact_client_value(self) -> None:
        resolver = NameIdentity(["Терёхин"])
        identity = resolver.resolve("Терёхин")
        self.assertEqual(identity.source, SOURCE_CLIENT_EXACT)
        self.assertEqual(identity.base, "Терёхин")

    def test_exact_value_beats_a_generated_form_of_another_value(self) -> None:
        """«Иванова» — и фамилия клиентки, и родительный от «Иванов».

        Точное значение клиентского справочника важнее основы: у двух клиентов должны
        остаться разные коды, иначе две персоны слились бы в одну.
        """
        resolver = NameIdentity(["Иванов", "Иванова"])
        self.assertEqual(resolver.resolve("Иванова").source, SOURCE_CLIENT_EXACT)
        self.assertEqual(resolver.resolve("Иванова").value, "иванова")
        self.assertEqual(resolver.resolve("Иванова").base, "Иванова")
        self.assertEqual(resolver.resolve("Иванов").value, "иванов")
        # «Ивановым» порождается только «Иванов» — это его персона.
        self.assertEqual(resolver.resolve("Ивановым").value, "иванов")
        # «Иванову» порождается обоими значениями и точным не является: не угадываем,
        # написание остаётся своей идентичностью (не хуже прежнего поведения).
        self.assertEqual(resolver.resolve("Иванову").source, SOURCE_SURFACE)

    def test_all_forms_of_one_value_share_one_identity(self) -> None:
        resolver = NameIdentity(["Печёнов", "Ирина", "Иванович"])
        seen = set()
        for form in ("Печёнов", "Печёнова", "Печёнову", "Печёновым", "Печёнове"):
            seen.add(resolver.resolve(form).value)
        self.assertEqual(seen, {"печенов"})
        for form in ("Ирина", "Ирины", "Ирине", "Ирину", "Ириной"):
            self.assertEqual(resolver.resolve(form).value, "ирина", msg=form)
        for form in ("Иванович", "Ивановича", "Ивановичу"):
            self.assertEqual(resolver.resolve(form).value, "иванович", msg=form)

    def test_latin_values_stay_exact_only(self) -> None:
        """Таблицы склонений кириллические: латиница не размножается формами."""
        resolver = NameIdentity(["Terekhina"])
        self.assertEqual(resolver.resolve("Terekhina").source, SOURCE_CLIENT_EXACT)
        self.assertEqual(resolver.resolve("Terekhinoj").source, SOURCE_SURFACE)

    def test_index_is_capped_and_the_rest_is_counted(self) -> None:
        values = [f"Клиентов{index:06d}" for index in range(MAX_CLIENT_VALUES + 25)]
        resolver = NameIdentity(values)
        self.assertEqual(resolver.client_size, MAX_CLIENT_VALUES)
        self.assertEqual(resolver.counters()["client_truncated"], 25)


class LayerBaseTests(unittest.TestCase):
    """Основа открытого списка находится только там, где она порождает написание."""

    def test_genitive_finds_its_base(self) -> None:
        resolver = NameIdentity([], FakeLayer(["иванов"]))
        identity = resolver.resolve("Иванова")
        self.assertEqual(identity.source, SOURCE_LAYER_BASE)
        self.assertEqual(identity.value, "иванов")

    def test_instrumental_finds_its_base(self) -> None:
        resolver = NameIdentity([], FakeLayer(["иванов"]))
        self.assertEqual(resolver.resolve("Ивановым").value, "иванов")

    def test_base_must_regenerate_the_form(self) -> None:
        """«Иван» не становится идентичностью «Иванова»: он её не порождает."""
        resolver = NameIdentity([], FakeLayer(["иван"]))
        self.assertIsNone(resolver.layer_base("Иванова"))
        self.assertEqual(resolver.resolve("Иванова").source, SOURCE_SURFACE)

    def test_feminine_form_uses_the_table_reverse_move(self) -> None:
        """«Терёхиной» → «терехин»: генератор женских форм не даёт, обратный ход даёт."""
        resolver = NameIdentity([], FakeLayer(["терехин"]))
        identity = resolver.resolve("Терёхиной")
        self.assertEqual(identity.source, SOURCE_LAYER_BASE)
        self.assertEqual(identity.value, "терехин")

    def test_broken_layer_does_not_stop_resolution(self) -> None:
        class Broken:
            def contains(self, *_args, **_kwargs):
                raise RuntimeError("список недоступен")

        resolver = NameIdentity([], Broken())
        self.assertEqual(resolver.resolve("Терёхиной").source, SOURCE_SURFACE)

    def test_multiword_is_not_resolved_by_base(self) -> None:
        resolver = NameIdentity([], FakeLayer(["иванов"]))
        self.assertIsNone(resolver.layer_base("Иванов Иван"))
        self.assertEqual(resolver.resolve("Иванов Иван").source, SOURCE_SURFACE)


class AmbiguityTests(unittest.TestCase):
    """Неоднозначность не угадывается: поверхностное написание остаётся своей идентичностью."""

    def test_ambiguous_client_form_is_not_guessed(self) -> None:
        """«Иванову» порождается и «Иванов», и «Иванова» — форма из индекса убирается."""
        resolver = NameIdentity(["Иванов", "Иванова"])
        # Точные написания своих значений остаются за своими персонами.
        self.assertEqual(resolver.resolve("Иванов").value, "иванов")
        self.assertEqual(resolver.resolve("Иванова").value, "иванова")
        # Форма, которую порождают оба значения, не приписывается ни одному: не угадываем.
        identity = resolver.resolve("Иванову")
        self.assertEqual(identity.source, SOURCE_SURFACE)
        self.assertGreaterEqual(resolver.counters()["index_ambiguous"], 1)

    def test_strong_evidence_wins_over_a_weak_neighbour(self) -> None:
        """«Ивановым» порождается «Иванов»; «Ивановы» в списке тоже есть, но не порождает."""
        resolver = NameIdentity([], FakeLayer(["иванов", "ивановы"]))
        self.assertEqual(resolver.layer_base("Ивановым"), "иванов")

    def test_surface_fallback_keeps_the_old_behaviour(self) -> None:
        resolver = NameIdentity([])
        identity = resolver.resolve("Токенец")
        self.assertEqual(identity.source, SOURCE_SURFACE)
        self.assertEqual(identity.value, "токенец")


class FakeKeyedDictionary:
    """Словарь продакшен-вида: отвечает отпечатком персоны на известное написание."""

    def __init__(self, spellings) -> None:
        self.spellings = {str(key).lower(): value for key, value in spellings.items()}

    def identity_digest(self, value: str, cls: str | None = None) -> str | None:
        return self.spellings.get(str(value or "").strip().lower())


class DictionaryAnchorTests(unittest.TestCase):
    """Основа открытого списка подтверждается справочником (Phase-14)."""

    def test_dictionary_confirms_the_open_list_base(self) -> None:
        """«Иванову» — падеж персоны «иванов» из справочника, а не собственный код.

        Без подтверждения справочником написание получало читаемую основу («иванов») и
        второй код: замер 19.09.2026 — 12 значений из 40 на настоящем справочнике.
        """
        resolver = NameIdentity([], FakeLayer(["иванов"]))
        resolver.set_dictionary(FakeKeyedDictionary({"иванов": "pd:0000000000000001"}))
        identity = resolver.resolve("Иванову")
        self.assertEqual(identity.source, SOURCE_LAYER_BASE)
        self.assertEqual(identity.value, "pd:0000000000000001")
        self.assertGreaterEqual(resolver.counters()["layer_base_anchored"], 1)

    def test_base_without_a_dictionary_answer_keeps_its_spelling(self) -> None:
        """Справочник молчит — поведение прежнее: код берётся из читаемой основы."""
        resolver = NameIdentity([], FakeLayer(["иванов"]))
        identity = resolver.resolve("Иванову")
        self.assertEqual(identity.source, SOURCE_LAYER_BASE)
        self.assertEqual(identity.value, "иванов")

    def test_surface_base_anchors_through_the_dictionary_forms(self) -> None:
        """«Мещерин» и «Мещерина» — одна персона: справочник знает падеж, а не основу.

        Справочнике держит только падежную запись («Мещерина»), беспадежной основы карточек нет.
        Без этого правила основа получала свой код, а её падежи — код персоны (находка 19.09.2026).
        """
        resolver = NameIdentity([])
        resolver.set_dictionary(FakeKeyedDictionary({"мещерина": "pd:0000000000000002"}))
        identity = resolver.resolve("Мещерин")
        self.assertEqual(identity.source, SOURCE_SURFACE)
        self.assertEqual(identity.value, "pd:0000000000000002")
        self.assertGreaterEqual(resolver.counters()["surface_anchored"], 1)

    def test_two_forms_of_different_persons_stop_the_anchor(self) -> None:
        """Два падежа, ведущих к разным персонам, — не угадываем."""
        resolver = NameIdentity([])
        resolver.set_dictionary(
            FakeKeyedDictionary(
                {"мещерина": "pd:0000000000000002", "мещерину": "pd:0000000000000003"}
            )
        )
        identity = resolver.resolve("Мещерин")
        self.assertEqual(identity.source, SOURCE_SURFACE)
        self.assertEqual(identity.value, "мещерин")

    def test_latin_spelling_is_not_anchored_through_forms(self) -> None:
        """Латиницу выгрузка не склоняет: подтверждать её формами нечем."""
        resolver = NameIdentity([])
        resolver.set_dictionary(FakeKeyedDictionary({"kovalenko": "pd:0000000000000004"}))
        identity = resolver.resolve("Kovalenko")
        self.assertEqual(identity.value, "pd:0000000000000004")
        self.assertEqual(resolver.resolve("Kovalova").value, "kovalova")


class MatchesIdentityTests(unittest.TestCase):
    """Одно правило «это то же значение?» для присвоения кода и восстановления."""

    def test_names_fold_yo_and_case(self) -> None:
        self.assertTrue(matches_identity("P", "Печёнов", "печенов"))
        self.assertTrue(matches_identity("P", "Печёновой", "печеновой"))
        self.assertFalse(matches_identity("P", "Печёнов", "иванов"))

    def test_phones_compare_by_normalized_digits(self) -> None:
        self.assertTrue(matches_identity("T", "+7 900 111 22 33", "79001112233"))
        self.assertFalse(matches_identity("T", "79001112233", "79004445566"))

    def test_empty_values_never_match(self) -> None:
        self.assertFalse(matches_identity("P", "", "иванов"))
        self.assertFalse(matches_identity("P", "Иванов", ""))


class CounterTests(unittest.TestCase):
    """Счётчики — числа: значения клиентов наружу не идут."""

    def test_counters_are_numbers_without_values(self) -> None:
        resolver = NameIdentity(["Иванов"], FakeLayer(["иванов"]))
        resolver.resolve("Иванова")
        resolver.resolve("Иванов")
        counters = resolver.counters()
        self.assertTrue(counters, "счётчики обязаны существовать")
        for key, value in counters.items():
            self.assertIsInstance(key, str)
            self.assertIsInstance(value, int, msg=key)
        self.assertNotIn("иванов", {str(key).lower() for key in counters})
        self.assertGreaterEqual(counters[SOURCE_CLIENT_EXACT], 1)
        self.assertGreaterEqual(counters[SOURCE_CLIENT_FORM], 1)

    def test_layer_change_drops_the_base_cache(self) -> None:
        resolver = NameIdentity([], FakeLayer(["иванов"]))
        self.assertEqual(resolver.layer_base("Иванова"), "иванов")
        resolver.set_layer(FakeLayer([]))
        self.assertIsNone(resolver.layer_base("Иванова"))


if __name__ == "__main__":
    unittest.main()
