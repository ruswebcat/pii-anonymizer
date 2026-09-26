# FILE: tools/dict_noise_report.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Показать по категориям, сколько служебной лексики сидит в классе «имена» клиентского справочника, не читая и не печатая значений клиентов: присутствие слова проверяется отпечатком.
#   SCOPE: категории служебной лексики как данные (общие в коде, лексика оператора из настроек), сверка слова со справочником по отпечатку, предохранитель по открытому списку фамилий, отчёт счётчиками и словами служебной лексики (не ПД).
#   DEPENDS: M-DICT, M-DICT-EXPORT, M-DETECT-NAME, M-SERVICE-LEXICON, M-OWN-VOCABULARY, M-CONFIG
#   LINKS: M-DICT-HYGIENE, V-M-DICT-HYGIENE, Phase-16
#   ROLE: SCRIPT
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   SERVICE_LEXICON - общие категории служебной лексики (данные в коде, не ПД)
#   OWN_TERMS_CATEGORY - категория для своей лексики оператора из own_vocabulary
#   CategoryReport - счётчики одной категории
#   NoiseReport - отчёт целиком
#   fn-load_digests - отпечатки класса «имена» из справочника (без расшифровки значений)
#   fn-in_dictionary - есть ли слово в классе «имена» по отпечатку
#   fn-build_lexicon - общие категории плюс лексика оператора из настроек
#   fn-load_operator_lexicon - прочитать служебную и свою лексику оператора из настроек
#   fn-scan - посчитать присутствие служебной лексики по категориям
#   fn-render_report - отчёт markdown: счётчики и слова служебной лексики
#   fn-apply_removal - снять найденную лексику из справочника
#   fn-main - точка входа CLI
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.1.0 - решение владельца 25.09.2026: клубно-тарифные слова (названия тарифов и клубов) ушли из кода в настройки. В коде остались только общие категории, не привязанные к конкретной сети; лексика оператора приходит из раздела service_lexicon, а своя лексика из own_vocabulary замеряется наравне с ней.
#   PREVIOUS: v1.0.0 - Phase-16: измеритель шума по категориям. Замер 19.09.2026 показал, что 59,5% значений класса «имена» в выгрузке именами не являются; измеритель нужен, чтобы говорить о шуме категориями и числами, а не примерами из карточек.
# END_CHANGE_SUMMARY

"""Измеритель служебной лексики в классе «имена» (M-DICT-HYGIENE, Phase-16).

Зачем отдельный инструмент. Замер 19.09.2026: 59,5% значений класса «имена» в выгрузке
карточек — не имена, а служебная лексика системы учёта («Продажи», «Гость», «Запись»,
«Анкета», «Карта», «CRM»). Часть таких значений даёт ложные замены и шум в журнале
инцидентов. Чтобы править это по числу, а не по впечатлению, нужно уметь посчитать шум
**по категориям** — на настоящем справочнике и без чтения значений клиентов.

Что в коде и что в настройках (решение владельца 25.09.2026). В коде лежат только **общие**
категории: должности, статусы, поля системы учёта, шаблоны-заглушки, обрывки служебных слов.
Они не привязаны к конкретной сети — это лексика любой карточки. **Клубно-тарифных слов**
(названия тарифов, клубов, услуг конкретной сети) в коде нет: они приходят из настроек —
раздел ``service_lexicon``, — а своя лексика организации из ``own_vocabulary`` замеряется
наравне с ними. Так другой оператор не получает в измерителе чужие тарифы, а публичная
сборка не публикует лексику одной сети.

Как это возможно без чтения значений. Справочник хранится отпечатками (schema 3,
``value_digest``); присутствие слова — это проверка «есть ли отпечаток слова в классе»,
а не чтение содержимого. Отпечаток считается тем же кодом (``M-DICT``), что и в выгрузке,
поэтому измеритель и справочник не расходятся.

Что печатается и что нет. Печатаются **счётчики по категориям** и сами слова служебной
лексики — это наша лексика, а не персональные данные (они лежат в настройках и в коде как
данные). Значений клиентов инструмент не печатает и печатать не может: на вход ему попадают
только отпечатки.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # pragma: no cover - script bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from src import own_vocabulary, service_lexicon  # noqa: E402
from src import dict_write  # noqa: E402
from src.config import read_overlay  # noqa: E402
from src.detect_name import own_lexicon_ok  # noqa: E402
from src.dictionary import value_digest  # noqa: E402
from src.normalize import NormalizeError, normalize  # noqa: E402

CLASS_NAMES = "P"
#: Категории служебной лексики, общие для любой карточки (данные в коде: это служебные слова,
#: не персональные данные). Список сознательно короткий и однозначный — слова с риском
#: «настоящая фамилия» сюда не попадают, иначе чистка снова начнёт терять данные клиентов
#: (замер 17.09.2026: чистка «как похоже на имя» выбросила 12,9% настоящих значений).
#:
#: Клубно-тарифной лексики здесь НЕТ (решение владельца 25.09.2026): названия тарифов, клубов
#: и услуг — лексика оператора, а не кода, и приходит из раздела ``service_lexicon``.
#: Категории ниже — должности, статусы, поля системы учёта, заглушки и обрывки — встречаются
#: в карточке любой организации, поэтому они и остались в коде.
SERVICE_LEXICON: dict[str, tuple[str, ...]] = {
    "служебные слова и должности": (
        "продажи",
        "продажа",
        "гость",
        "гости",
        "запись",
        "записи",
        "анкета",
        "руководитель",
        "директор",
        "менеджер",
        "администратор",
        "специалист",
        "инструктор",
        "сотрудник",
        "сотрудники",
        "персонал",
        "клиент",
        "клиентов",
        "тренер",
        "фотограф",
        "продавец",
        "оператор",
        "бухгалтер",
        "менеджер продаж",
        "отдел продаж",
    ),
    "статусы и состояния": (
        "статус",
        "активный",
        "активна",
        "заморожен",
        "заморозка",
        "отказ",
        "отказался",
        "отказалась",
        "дубль",
        "дубликат",
        "неактивный",
        "архив",
        "архивный",
        "удалён",
        "удален",
        "пробный",
        "тест",
        "тестовый",
        "новый",
        "задолженность",
        "долг",
        "оплачен",
        "неоплачен",
    ),
    "технические объекты и поля": (
        "crm",
        "итого",
        "всего",
        "комментарий",
        "примечание",
        "задача",
        "задачи",
        "отчёт",
        "отчет",
        "филиал",
        "офис",
        "зал",
        "раздевалка",
        "система",
        "системы",
        "база",
        "приложение",
        "сайт",
        "доступ",
    ),
    "шаблоны-заглушки": (
        "нет данных",
        "без имени",
        "не указано",
        "не указан",
        "не указана",
        "нет",
        "прочее",
        "другое",
        "прочерк",
        "без фамилии",
        "безымянный",
        "неизвестно",
        "неизвестный",
    ),
    "обрывки и обрубки": (
        "для",
        "на",
        "и",
        "или",
        "по",
        "из",
        "от",
        "до",
        "к",
        "с",
        "в",
        "у",
        "о",
        "при",
        "под",
        "над",
        "без",
        "но",
        "что",
        "как",
        "это",
        "его",
        "её",
        "их",
    ),
}
#: Куда попадает своя лексика оператора из ``own_vocabulary``: она замеряется наравне со
#: служебной, потому что тариф и филиал в поле ФИО — такой же шум справочника.
OWN_TERMS_CATEGORY = "своя лексика организации (own_vocabulary)"


# START_BLOCK_LEXICON_INTAKE
def _normalise_word(raw: object) -> str:
    """Слово лексики в единой форме: сжатые пробелы, нижний регистр."""
    return " ".join(str(raw).split()).strip().lower()


def build_lexicon(
    configured: Mapping[str, Sequence[str]] | None = None,
    own_terms: Iterable[str] = (),
) -> dict[str, tuple[str, ...]]:
    """Собрать лексику измерителя: общие категории в коде плюс лексика оператора из настроек.

    # START_CONTRACT: build_lexicon
    #   PURPOSE: Смешать общие категории кода с лексикой оператора, не теряя категорий и повторов.
    #   INPUTS: { configured: Mapping[str, Sequence[str]] | None - лексика из настроек по категориям, own_terms: Iterable[str] - своя лексика организации }
    #   OUTPUTS: { dict[str, tuple[str, ...]] - категории замера }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT-HYGIENE, M-SERVICE-LEXICON, M-OWN-VOCABULARY
    # END_CONTRACT: build_lexicon
    """
    lexicon: dict[str, list[str]] = {
        name: list(words) for name, words in SERVICE_LEXICON.items()
    }
    for name, words in (configured or {}).items():
        label = " ".join(str(name).split()).strip()
        if not label:
            continue
        target = lexicon.setdefault(label, [])
        for word in words:
            value = _normalise_word(word)
            if value and value not in target:
                target.append(value)
    terms = [_normalise_word(item) for item in own_terms]
    terms = [value for value in terms if value]
    if terms:
        target = lexicon.setdefault(OWN_TERMS_CATEGORY, [])
        for value in terms:
            if value not in target:
                target.append(value)
    return {name: tuple(words) for name, words in lexicon.items() if words}


def load_operator_lexicon(
    config_path: str | None = None,
    env: Mapping[str, str] | None = None,
) -> tuple[service_lexicon.ServiceLexicon, own_vocabulary.OwnVocabulary]:
    """Прочитать служебную и свою лексику оператора из настроек.

    # START_CONTRACT: load_operator_lexicon
    #   PURPOSE: Дать прибору читать те же настройки, что и служба: файл настроек и переменные окружения.
    #   INPUTS: { config_path: str | None - файл настроек, env: Mapping[str, str] | None - окружение }
    #   OUTPUTS: { (ServiceLexicon, OwnVocabulary) - лексика оператора }
    #   SIDE_EFFECTS: читает окружение и, если задан путь, файл настроек
    #   LINKS: M-SERVICE-LEXICON, M-OWN-VOCABULARY, M-CONFIG
    # END_CONTRACT: load_operator_lexicon

    Файл настроек и окружение складываются, а не перекрывают друг друга: владелец заполняет
    пример конфигурации, а окружение дополняет его значениями юнита.
    """
    source = os.environ if env is None else env
    service = service_lexicon.from_env(source)
    own = own_vocabulary.from_env(source)
    if config_path:
        overlay = read_overlay(config_path)
        if "service_lexicon" in overlay:
            service = service_lexicon.merge(
                service, service_lexicon.from_mapping(overlay["service_lexicon"])
            )
        if "own_vocabulary" in overlay:
            own = own_vocabulary.merge(
                own, own_vocabulary.from_mapping(overlay["own_vocabulary"])
            )
    return service, own
# END_BLOCK_LEXICON_INTAKE


@dataclass(frozen=True)
class CategoryReport:
    """Счётчики одной категории служебной лексики.

    # START_CONTRACT: CategoryReport
    #   PURPOSE: Держать по категории три числа: сколько слов проверено, сколько нашлось в справочнике и сколько из них проходит рантайм как имя.
    #   INPUTS: { name: str - категория, checked: int - слов проверено, present: int - слов найдено в классе «имена», escaping: int - слова, которые рантайм всё ещё считает именем }
    #   OUTPUTS: { CategoryReport - счётчики категории }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT-HYGIENE, V-M-DICT-HYGIENE
    # END_CONTRACT: CategoryReport
    """

    name: str
    checked: int = 0
    present: int = 0
    escaping: int = 0
    words: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class NoiseReport:
    """Отчёт измерителя целиком.

    # START_CONTRACT: NoiseReport
    #   PURPOSE: Собрать числа по всем категориям и состав класса, чтобы шум назывался категориями, а не примерами.
    #   INPUTS: { dictionary_path: str, class_values: int - значений в классе «имена», categories: tuple[CategoryReport, ...] }
    #   OUTPUTS: { NoiseReport - отчёт }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT-HYGIENE, V-M-DICT-HYGIENE
    # END_CONTRACT: NoiseReport
    """

    dictionary_path: str
    class_values: int = 0
    categories: tuple[CategoryReport, ...] = ()

    @property
    def present_total(self) -> int:
        """Сколько всего слов служебной лексики нашлось в классе «имена»."""
        return sum(item.present for item in self.categories)

    @property
    def checked_total(self) -> int:
        """Сколько слов служебной лексики проверено."""
        return sum(item.checked for item in self.categories)

    def to_dict(self) -> dict[str, Any]:
        """Отчёт словарём: только числа и слова служебной лексики."""
        return {
            "dictionary": self.dictionary_path,
            "class_values": self.class_values,
            "checked_total": self.checked_total,
            "present_total": self.present_total,
            "categories": [
                {
                    "name": item.name,
                    "checked": item.checked,
                    "present": item.present,
                    "escaping": item.escaping,
                    "words": list(item.words),
                }
                for item in self.categories
            ],
        }


def load_digests(path: str, key: bytes) -> tuple[set[str], int]:
    """Вернуть отпечатки класса «имена» и размер всего справочника.

    # START_CONTRACT: load_digests
    #   PURPOSE: Читать справочник как множество отпечатков: значения клиентов при этом не расшифровываются ни на шаг.
    #   INPUTS: { path: str - путь к справочнику, key: bytes - ключ отпечатков }
    #   OUTPUTS: { (set[str], int) - отпечатки класса «имена» и число записей справочника }
    #   SIDE_EFFECTS: читает файл справочника
    #   LINKS: M-DICT, M-DICT-EXPORT, V-M-DICT-HYGIENE
    # END_CONTRACT: load_digests

    Справочник schema 3 хранит словарь ``digests`` (класс → список отпечатков) и ``forms``
    (отпечатки падежных форм). Проверка присутствия значения — это проверка отпечатка в
    классе, поэтому на вход измерителю не попадает ни одного читаемого значения.
    """
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, Mapping):
        raise ValueError("dictionary payload is not an object")
    digests = payload.get("digests") or {}
    bucket = digests.get(CLASS_NAMES) if isinstance(digests, Mapping) else None
    keys = {str(item) for item in bucket} if isinstance(bucket, list) else set()
    values = int(payload.get("values") or 0)
    return keys, values


def in_dictionary(keys: Iterable[str], key: bytes, word: str) -> bool:
    """Сказать, есть ли слово в классе «имена» — по отпечатку.

    # START_CONTRACT: in_dictionary
    #   PURPOSE: Ответить «есть ли слово в справочнике», не расшифровывая ни одного значения.
    #   INPUTS: { keys: Iterable[str] - отпечатки класса, key: bytes - ключ отпечатков, word: str - служебное слово }
    #   OUTPUTS: { bool - True, если отпечаток слова есть в классе }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT, V-M-DICT-HYGIENE
    # END_CONTRACT: in_dictionary
    """
    try:
        normalized = normalize(CLASS_NAMES, word)
    except NormalizeError:
        return False
    if not normalized:
        return False
    return value_digest(key, CLASS_NAMES, normalized) in set(keys)


def scan(
    path: str,
    key: bytes,
    lexicon: Mapping[str, Sequence[str]] | None = None,
) -> NoiseReport:
    """Посчитать служебную лексику по категориям в классе «имена».

    # START_CONTRACT: scan
    #   PURPOSE: Дать числа по категориям: сколько служебных слов лежит в классе персон и сколько из них рантайм всё ещё готов заменить.
    #   INPUTS: { path: str - справочник, key: bytes - ключ, lexicon: Mapping[str, Sequence[str]] | None - категории, по умолчанию SERVICE_LEXICON }
    #   OUTPUTS: { NoiseReport - отчёт }
    #   SIDE_EFFECTS: читает файл справочника
    #   LINKS: M-DICT-HYGIENE, M-DICT, V-M-DICT-HYGIENE
    # END_CONTRACT: scan

    Три числа на категорию, и каждое отвечает на свой вопрос:

    * ``checked`` — сколько слов категории проверено (объём проверки виден, а не подразумевается);
    * ``present`` — сколько из них лежит в классе «имена» (это и есть шум справочника);
    * ``escaping`` — сколько из них **не** закрыто собственным стоп-листом, то есть рантайм
      готов их заменить (именно эта часть даёт ложные замены и шум в журнале инцидентов).

    Разница между ``present`` и ``escaping`` — прямой ответ на вопрос «хватит ли стоп-листа»:
    слово в справочнике без стоп-листа обязательно станет ложной заменой.
    """
    items = lexicon if lexicon is not None else SERVICE_LEXICON
    keys, values = load_digests(path, key)
    reports: list[CategoryReport] = []
    for name, words in items.items():
        found: list[str] = []
        escaping = 0
        for word in words:
            if not in_dictionary(keys, key, word):
                continue
            found.append(word)
            if own_lexicon_ok(word):
                escaping += 1
        reports.append(
            CategoryReport(
                name=name,
                checked=len(words),
                present=len(found),
                escaping=escaping,
                words=tuple(found),
            )
        )
    return NoiseReport(
        dictionary_path=path, class_values=len(keys) or values, categories=tuple(reports)
    )


def render_report(report: NoiseReport, show_words: bool = True) -> str:
    """Оформить отчёт markdown: счётчики и слова служебной лексики.

    # START_CONTRACT: render_report
    #   PURPOSE: Дать владельцу шум категориями и числами, а не примерами из карточек клиентов.
    #   INPUTS: { report: NoiseReport - отчёт, show_words: bool - печатать ли слова служебной лексики }
    #   OUTPUTS: { str - markdown }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT-HYGIENE, V-M-DICT-HYGIENE
    # END_CONTRACT: render_report
    """
    lines = [
        "# Служебная лексика в классе «имена» (измеритель M-DICT-HYGIENE)",
        "",
        f"Справочник: `{report.dictionary_path}`.",
        f"Значений в классе «имена»: **{report.class_values}**.",
        f"Проверено слов служебной лексики: {report.checked_total}, "
        f"найдено в классе: **{report.present_total}**.",
        "",
        "| Категория | Проверено | Найдено в классе | Из них не закрыто стоп-листом |",
        "|---|---|---|---|",
    ]
    for item in report.categories:
        lines.append(
            f"| {item.name} | {item.checked} | {item.present} | {item.escaping} |"
        )
    if show_words:
        lines += ["", "## Найденные слова по категориям", ""]
        for item in report.categories:
            if not item.present:
                continue
            lines.append(f"* **{item.name}** ({item.present}): " + ", ".join(item.words))
        if not report.present_total:
            lines.append("* служебной лексики в классе «имена» не найдено")
    lines += [
        "",
        "## Как читать числа",
        "",
        "* «Найдено в классе» — слово лежит в клиентском справочнике как имя: это и есть шум;",
        "* «не закрыто стоп-листом» — на этом слове защита держится только на других заслонах",
        "  (морфология, клиентский контекст, граница слова), а не на стоп-листе своей лексики;",
        "  слова из этой колонки обязаны попасть в стоп-лист, иначе смена заслона вернёт ложные замены;",
        "* категории тарифов, клубов и услуг приходят **из настроек** (`service_lexicon` и своя",
        "  лексика организации): в коде публичной сборки чужих тарифов нет, поэтому у этого отчёта",
        "  категории оператора свои;",
        "* значений клиентов в отчёте нет по построению: присутствие проверяется отпечатком.",
        "",
    ]
    return "\n".join(lines)


def apply_removal(
    report: NoiseReport,
    key: bytes,
    key_path: str,
    staged_path: str = "",
    runner: Any = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Снять найденную служебную лексику из класса «имена» через staged → проверка → бэкап → замена.

    # START_CONTRACT: apply_removal
    #   PURPOSE: Закрыть остаток шума в живом справочнике тем же порядком, что и любая правка словаря: сначала staged и прибор, потом замена.
    #   INPUTS: { report: NoiseReport - замер, key: bytes - ключ отпечатков, key_path: str - файл ключа, staged_path: str - куда положить staged, runner: Any - подстановка прибора, dry_run: bool - ничего не менять }
    #   OUTPUTS: { dict - числа: сколько снято, был ли заменён живой файл, где staged и бэкап }
    #   SIDE_EFFECTS: пишет staged, при обычном прогоне копирует бэкап и заменяет справочник
    #   LINKS: M-DICT-HYGIENE, M-DICT-WRITE, V-M-DICT-HYGIENE
    # END_CONTRACT: apply_removal

    Почему удаление, а не только стоп-лист: стоп-лист закрывает ложную замену, но само слово
    остаётся в классе «имена» и живёт в счётчиках healthz как имя клиента. Удаление делает
    справочник честным, а правило выгрузки (`noise_kind`, стоп-лист) не даёт слову вернуться
    при следующей выгрузке.
    """
    words = sorted({word for item in report.categories for word in item.words})
    outcome: dict[str, Any] = {"words": len(words), "removed": 0, "dry_run": bool(dry_run)}
    if not words:
        outcome["reason"] = "nothing_to_remove"
        return outcome
    payload = dict_write.load_payload(report.dictionary_path)
    updated, stats = dict_write.remove_values(payload, key, CLASS_NAMES, words)
    outcome["removed"] = stats.removed
    outcome["absent"] = stats.absent
    outcome["form_digests"] = stats.form_digests
    outcome["values_before"] = int(payload.get("values") or 0)
    outcome["values_after"] = int(updated.get("values") or 0)
    if dry_run:
        outcome["reason"] = "dry_run"
        return outcome
    result = dict_write.apply(
        report.dictionary_path,
        updated,
        key_path,
        staged_path=staged_path or f"{report.dictionary_path}.staged",
        runner=runner,
    )
    outcome["apply"] = result.to_dict()
    outcome["reason"] = result.reason
    return outcome


def main(argv: Sequence[str] | None = None) -> int:
    """Точка входа CLI измерителя.

    # START_CONTRACT: main
    #   PURPOSE: Сделать замер шума повторяемым прогоном, а не разовым разбором, и дать ту же руку для снятия остатка.
    #   INPUTS: { argv: Sequence[str] | None }
    #   OUTPUTS: { int - код выхода }
    #   SIDE_EFFECTS: читает справочник и ключ, печатает отчёт; с --apply меняет справочник через staged
    #   LINKS: M-DICT-HYGIENE, V-M-DICT-HYGIENE
    # END_CONTRACT: main
    """
    parser = argparse.ArgumentParser(
        description="Служебная лексика в классе «имена»: счётчики по категориям"
    )
    parser.add_argument("--dict-file", required=True, help="справочник (schema 3, отпечатки)")
    parser.add_argument("--dict-key-file", required=True, help="файл ключа справочника")
    parser.add_argument("--json", action="store_true", help="вывести отчёт словарём")
    parser.add_argument("--no-words", action="store_true", help="не печатать слова лексики")
    parser.add_argument(
        "--config",
        default="",
        help="файл настроек (JSON или YAML): из него берётся лексика оператора",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="снять найденную служебную лексику из справочника (staged → проверка → бэкап → замена)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    key = _read_key(args.dict_key_file)
    service, own = load_operator_lexicon(args.config or None)
    lexicon = build_lexicon(service.by_category, own.terms)
    report = scan(args.dict_file, key, lexicon)
    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(render_report(report, show_words=not args.no_words))
    if not args.apply:
        return 0

    outcome = apply_removal(report, key, args.dict_key_file, dry_run=False)
    print("")
    print("## Снятие остатка из живого справочника")
    print("")
    print(f"Слов снято: {outcome.get('removed')}, формо-отпечатков снято: {outcome.get('form_digests')}.")
    print(f"Значений всего: {outcome.get('values_before')} → {outcome.get('values_after')}.")
    applied = bool((outcome.get("apply") or {}).get("applied"))
    print(f"Живой справочник заменён: {'да' if applied else 'НЕТ'} ({outcome.get('reason')}).")
    if outcome.get("apply", {}).get("backup_path"):
        print(f"Бэкап: `{outcome['apply']['backup_path']}`")
    return 0


def _read_key(path: str) -> bytes:
    """Прочитать ключ отпечатков справочника."""
    try:
        return Path(path).read_bytes().strip()
    except OSError as exc:  # pragma: no cover - filesystem dependent
        raise SystemExit(f"DICT_KEY_UNREADABLE: {os.path.basename(path)}: {exc}") from exc


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
