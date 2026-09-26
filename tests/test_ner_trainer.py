# FILE: tests/test_ner_trainer.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Проверить офлайн-тренера словаря: склейка подтокенов, подтверждение вторым источником, отсев уже известного открытому слою и файл-предложение без персональных данных.
#   SCOPE: merge_pieces, confirm, build_additions, render_proposal, run_corpus на подставной разметке.
#   DEPENDS: M-NER-TRAINER, M-NAME-LAYER
#   LINKS: V-M-NER-TRAINER, M-NER-TRAINER
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   MergePiecesTests - склейка подтокенов одного слова
#   ConfirmationTests - второе подтверждение находки модели
#   AdditionTests - что попадает в список добавки, а что владельцу
#   ProposalTests - файл-предложение без значений клиентов
#   CorpusRunTests - прогон корпуса на подставной разметке
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-13: модель необязательна (нет каталога — нет находок), подтверждение вторым источником обязательно, спорное уходит владельцу.
# END_CHANGE_SUMMARY

"""Тесты офлайн-тренера словаря (Phase-13).

Модель в тестах не запускается: 170 МБ и секунды на строку — не то, что нужно юнит-тесту.
Подставляется разметка, а проверяется то, что решает судьбу значения: склейка подтокенов,
подтверждение вторым источником и отсев известного.
"""

import os
import sys
import unittest
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.name_layer import NameLayer  # noqa: E402
from tools.ner_trainer import (  # noqa: E402
    ADDRESS_TYPES,
    PERSON_TYPES,
    Candidate,
    build_additions,
    confirm,
    merge_pieces,
    render_proposal,
    run_corpus,
)

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()


class MergePiecesTests(unittest.TestCase):
    """Подтокены одного слова — одно значение, разные слова — разные."""

    def test_subtokens_of_one_word_are_merged(self) -> None:
        # «Заглушкин»: модель размечает каждый подтокен и чередует виды внутри слова.
        pieces = [(7, 8, "LAST_NAME"), (8, 10, "LAST_NAME"), (10, 13, "FIRST_NAME"), (13, 16, "LAST_NAME")]
        self.assertEqual(merge_pieces(pieces), [(7, 16, "LAST_NAME")])

    def test_words_separated_by_a_space_stay_apart(self) -> None:
        pieces = [(0, 5, "LAST_NAME"), (6, 11, "FIRST_NAME")]
        self.assertEqual(merge_pieces(pieces), [(0, 5, "LAST_NAME"), (6, 11, "FIRST_NAME")])

    def test_empty_pieces_are_dropped(self) -> None:
        """Спецтокены модели дают пустой отрезок — он не значение."""
        self.assertEqual(merge_pieces([(0, 0, "FIRST_NAME"), (2, 4, "LAST_NAME")]), [(2, 4, "LAST_NAME")])

    def test_no_pieces_is_empty(self) -> None:
        self.assertEqual(merge_pieces([]), [])


class ConfirmationTests(unittest.TestCase):
    """Одно слово модели значения не решает: нужен второй источник."""

    def test_morphology_confirms_a_real_surname(self) -> None:
        self.assertIn("морфология: тег имени", confirm("Заглушкин"))

    def test_morphology_does_not_confirm_an_ordinary_word(self) -> None:
        """«Клиент» модель называет именем, а морфология — нет."""
        self.assertEqual(confirm("Клиент"), ())

    def test_rare_surname_unknown_to_morphology_needs_a_human(self) -> None:
        self.assertEqual(confirm("Тесля"), ())

    def test_presence_in_the_source_list_counts_as_confirmation(self) -> None:
        self.assertIn("есть в исходном списке", confirm("Тесля", known={"тесля"}))


class AdditionTests(unittest.TestCase):
    """В список добавки идёт только подтверждённое и только неизвестное слою."""

    def setUp(self) -> None:
        self.layer = NameLayer({"P": {"иванов"}}, {"source": "test", "licence": "n/a"})
        self.found = {
            "LAST_NAME": Counter({"Заглушкин": 2, "Тесля": 1, "Иванов": 5}),
            "STREET": Counter({"Садовая": 1}),
        }

    def test_confirmed_and_unconfirmed_are_split(self) -> None:
        confirmed, unconfirmed = build_additions(self.found, layer=self.layer)
        self.assertEqual([item.text for item in confirmed], ["Заглушкин"])
        self.assertEqual([item.text for item in unconfirmed], ["Тесля"])

    def test_values_already_in_the_layer_are_not_added(self) -> None:
        confirmed, unconfirmed = build_additions(self.found, layer=self.layer)
        texts = [item.text for item in confirmed + unconfirmed]
        self.assertNotIn("Иванов", texts, msg="известное слою значение попало в добавку")

    def test_address_values_are_not_person_candidates(self) -> None:
        """Адресные находки в добавку персон не идут: у них свои виды (улица, дом, город).

        «Садовая» — и улица, и фамилия: именно поэтому адрес отличает не морфология, а маркер,
        и разбирать адресные находки должен отдельный замер, а не список добавки персон.
        """
        confirmed, unconfirmed = build_additions(self.found, layer=self.layer)
        texts = [item.text for item in confirmed + unconfirmed]
        self.assertNotIn("Садовая", texts, msg="улица попала в кандидаты персон")

    def test_minimum_occurrences_filters_rare_findings(self) -> None:
        confirmed, _ = build_additions(self.found, layer=self.layer, minimum=2)
        self.assertEqual([item.text for item in confirmed], ["Заглушкин"])

    def test_person_types_are_three(self) -> None:
        self.assertEqual(PERSON_TYPES, ("LAST_NAME", "FIRST_NAME", "MIDDLE_NAME"))


class ProposalTests(unittest.TestCase):
    """Предложение владельцу: спорное и без персональных данных."""

    def test_proposal_lists_unconfirmed_findings(self) -> None:
        text = render_proposal(
            [Candidate(text="Тесля", label="LAST_NAME", count=3)],
            "синтетический корпус, 5 строк",
        )
        self.assertIn("Тесля", text)
        self.assertIn("не читается морфологией как имя", text)
        self.assertIn("синтетический корпус, 5 строк", text)

    def test_proposal_without_findings_is_honest(self) -> None:
        text = render_proposal([], "синтетический корпус")
        self.assertIn("спорных находок нет", text)

    def test_proposal_mentions_the_decision_to_be_taken(self) -> None:
        text = render_proposal([Candidate(text="Значение", label="LAST_NAME")], "корпус")
        self.assertIn("решить", text.lower())


class CorpusRunTests(unittest.TestCase):
    """Прогон корпуса на подставной разметке: модель заменена шпионом."""

    def test_findings_are_counted_by_type(self) -> None:
        texts = ["Анкета: Заглушкин Пётр", "Анкета: Тесля Ольга"]

        def annotate(batch: Sequence[str]) -> list[list[tuple[int, int, str]]]:
            return [
                [(8, 17, "LAST_NAME"), (18, 22, "FIRST_NAME")] if "Заглушкин" in text else [(8, 13, "LAST_NAME")]
                for text in batch
            ]

        found = run_corpus(texts, annotate, batch_size=1)
        self.assertEqual(found["LAST_NAME"]["Заглушкин"], 1)
        self.assertEqual(found["LAST_NAME"]["Тесля"], 1)
        self.assertEqual(found["FIRST_NAME"]["Пётр"], 1)

    def test_short_and_punctuated_findings_are_cleaned(self) -> None:
        """«…», обрывки короче трёх знаков и знаки препинания значениями не считаются."""

        def annotate(batch: Sequence[str]) -> list[list[tuple[int, int, str]]]:
            return [[(0, 2, "LAST_NAME"), (3, 9, "LAST_NAME")] for _ in batch]

        found = run_corpus(["яб Заглушкин"], annotate, batch_size=1)
        self.assertNotIn("яб", found.get("LAST_NAME", {}))


if __name__ == "__main__":
    unittest.main()
