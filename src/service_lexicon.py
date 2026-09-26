# FILE: src/service_lexicon.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Hold the operator's service lexicon — tariff, club and product words that its CRM leaves in the person-name field — taken from configuration, so no particular club network's tariff names sit in the code, and hand it to the dictionary-hygiene meter as data.
#   SCOPE: dependency-free value object with a neutral (empty) default, category-preserving loading from a configuration mapping, environment variables and a JSON file, merging without side effects.
#   DEPENDS: none
#   LINKS: M-SERVICE-LEXICON, M-DICT-HYGIENE, M-CONFIG, M-OWN-VOCABULARY
#   ROLE: CONFIG
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   DEFAULT_CATEGORY - категория для лексики, заданной одной строкой окружения
#   ServiceLexicon - служебная лексика оператора по категориям
#   from_mapping - собрать значение из раздела настроек без побочных действий
#   from_env - собрать значение из переменных окружения без побочных действий
#   load_json - собрать значение из файла JSON без побочных действий
#   merge - объединить несколько значений, сохранив категории
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - решение владельца 25.09.2026: клубно-тарифные служебные слова ушли из кода измерителя в настройки. Отдельный раздел, а не own_vocabulary: у своей лексики оператора и у списка слов для замера разные работы — первая запрещает замену, второй ищет шум в классе «имена», — и смешивать их значило бы менять поведение детектора правкой списка замера.
# END_CHANGE_SUMMARY

"""Служебная лексика оператора: тарифы, клубы, услуги — из настроек, а не из кода.

Зачем отдельный раздел рядом с ``own_vocabulary``. Замер 19.09.2026 показал, что 59,5% значений
класса «имена» в выгрузке карточек — служебная лексика: должности, статусы, записи системы учёта
и **названия тарифов и клубов конкретной сети**. Последние в коде публичной сборки держать нельзя:
это лексика оператора, у другого клуба тарифы называются иначе. Поэтому здесь лежит только
механизм — чтение раздела из настроек, — а значения приходят из ``config.example.yaml``
(``service_lexicon``) или из переменных окружения.

Почему не ``own_vocabulary.terms``. У этих двух списков разные работы: ``own_terms`` —
стоп-лист детектора («это слово наше, его никогда не заменять»), а служба этого модуля —
список замера («эти слова CRM оставляет в поле ФИО; посчитаем и, если нужно, снимем из
справочника»). Если сложить их в один ключ, добавление слова в список замера молча меняло бы
поведение детектора. Умолчание публичной сборки — пустая лексика: своего набора тарифов в коде
нет, и измеритель честно скажет, что сверх общих категорий замерять нечего.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Iterable, Mapping

LOGGER_NAME = "ServiceLexicon"
LOG_MARKER = "[ServiceLexicon][from_mapping][BLOCK_SERVICE_LEXICON]"

#: Одна строка окружения не знает категорий: все её слова попадают в эту.
DEFAULT_CATEGORY = "своя служебная лексика"
#: Переменные окружения: слова через запятую и необязательный путь к файлу JSON.
ENV_SERVICE_LEXICON = "PII_PROXY_SERVICE_LEXICON"
ENV_SERVICE_LEXICON_FILE = "PII_PROXY_SERVICE_LEXICON_FILE"


# START_BLOCK_SERVICE_LEXICON
@dataclass(frozen=True)
class ServiceLexicon:
    """Служебная лексика оператора по категориям.

    # START_CONTRACT: ServiceLexicon
    #   PURPOSE: Держать слова оператора, которые система учёта оставляет в поле ФИО, вместе с их категориями.
    #   INPUTS: { by_category: Mapping[str, tuple[str, ...]] - категория → слова в нижнем регистре }
    #   OUTPUTS: { ServiceLexicon - неизменяемое значение }
    #   SIDE_EFFECTS: none
    #   LINKS: M-SERVICE-LEXICON, M-DICT-HYGIENE
    # END_CONTRACT: ServiceLexicon
    """

    by_category: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def is_empty(self) -> bool:
        """Сказать, что лексики нет: пустое умолчание обязано быть видно, а не подразумеваться."""
        return not any(self.by_category.values())

    @property
    def word_count(self) -> int:
        """Сколько слов в лексике всего (число для healthz, без самих слов)."""
        return sum(len(words) for words in self.by_category.values())

    @property
    def category_count(self) -> int:
        """Сколько непустых категорий задано оператором."""
        return len([name for name, words in self.by_category.items() if words])


def _as_items(raw: object) -> Iterable[str]:
    """Развернуть строку с разделителями или последовательность в перечень значений."""
    if raw is None:
        return ()
    if isinstance(raw, str):
        return [part for part in re.split(r"[,;\n]", raw)]
    if isinstance(raw, (list, tuple, set, frozenset)):
        return [str(item) for item in raw]
    return [str(raw)]


def _normalise_words(raw: object) -> tuple[str, ...]:
    """Слова в единой форме: сжатые пробелы, нижний регистр, без повторов и пустых.

    # START_CONTRACT: _normalise_words
    #   PURPOSE: Сравнивать слово из настроек и слово из справочника в одной форме, не теряя фразы.
    #   INPUTS: { raw: object - строка, последовательность или None }
    #   OUTPUTS: { tuple[str, ...] - слова в порядке появления }
    #   SIDE_EFFECTS: none
    #   LINKS: M-SERVICE-LEXICON, M-DICT-HYGIENE
    # END_CONTRACT: _normalise_words
    """
    words: list[str] = []
    for item in _as_items(raw):
        value = " ".join(str(item).split()).strip().lower()
        if value and value not in words:
            words.append(value)
    return tuple(words)


def from_mapping(raw: object) -> ServiceLexicon:
    """Собрать лексику из раздела настроек без побочных действий.

    # START_CONTRACT: from_mapping
    #   PURPOSE: Принять раздел настроек в обоих видах: сопоставление «категория → слова» и одна строка/перечень.
    #   INPUTS: { raw: object - значение раздела service_lexicon }
    #   OUTPUTS: { ServiceLexicon - лексика из настроек, пустая если ничего не задано }
    #   SIDE_EFFECTS: none
    #   LINKS: M-SERVICE-LEXICON, M-CONFIG
    # END_CONTRACT: from_mapping
    """
    categories: dict[str, tuple[str, ...]] = {}
    if isinstance(raw, Mapping):
        for name, words in raw.items():
            label = " ".join(str(name).split()).strip()
            normalised = _normalise_words(words)
            if label and normalised:
                categories[label] = normalised
    elif raw is not None:
        normalised = _normalise_words(raw)
        if normalised:
            categories[DEFAULT_CATEGORY] = normalised
    return ServiceLexicon(by_category=categories)


def merge(*values: ServiceLexicon) -> ServiceLexicon:
    """Объединить несколько лексик, сохранив категории и порядок слов."""
    merged: dict[str, tuple[str, ...]] = {}
    for value in values:
        for name, words in value.by_category.items():
            current = list(merged.get(name, ()))
            for word in words:
                if word not in current:
                    current.append(word)
            if current:
                merged[name] = tuple(current)
    return ServiceLexicon(by_category=merged)


def load_json(path: str) -> ServiceLexicon:
    """Собрать лексику из файла JSON без побочных действий.

    # START_CONTRACT: load_json
    #   PURPOSE: Дать оператору задать лексику файлом, а не только строкой окружения.
    #   INPUTS: { path: str - файл с сопоставлением «категория → слова» или с одним перечнем }
    #   OUTPUTS: { ServiceLexicon - лексика из файла, пустая если файла нет }
    #   SIDE_EFFECTS: читает файл
    #   LINKS: M-SERVICE-LEXICON, M-CONFIG
    # END_CONTRACT: load_json
    """
    if not path or not os.path.isfile(path):
        return ServiceLexicon()
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return from_mapping(data)


def from_env(env: Mapping[str, str] | None = None) -> ServiceLexicon:
    """Собрать лексику из переменных окружения без побочных действий.

    # START_CONTRACT: from_env
    #   PURPOSE: Дать службе и приборам увидеть лексику оператора из окружения.
    #   INPUTS: { env: Mapping[str, str] | None - defaults to os.environ }
    #   OUTPUTS: { ServiceLexicon - лексика из переменных и из файла, если он задан }
    #   SIDE_EFFECTS: читает переменные окружения и, при заданном пути, файл
    #   LINKS: M-SERVICE-LEXICON, M-CONFIG
    # END_CONTRACT: from_env
    """
    source = os.environ if env is None else env
    lexicon = from_mapping(source.get(ENV_SERVICE_LEXICON) or ())
    path = source.get(ENV_SERVICE_LEXICON_FILE)
    if path:
        lexicon = merge(lexicon, load_json(path))
    return lexicon
# END_BLOCK_SERVICE_LEXICON
