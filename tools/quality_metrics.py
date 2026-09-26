# FILE: tools/quality_metrics.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Measure anonymization quality as reproducible numbers: replacement completeness over a fixed value set, RepRate over every form of a value, one code per value (PhCons), false replacements and false gate blocks on a clean corpus, reversibility attempts and the share of aggregates below k=5.
#   SCOPE: fixed synthetic client sample (>= 300 values), form expansion through M-NAME-FORMS, metrics as pure functions over injected seams, pipeline assembly for the CLI, PII-free report (numbers and counters only).
#   DEPENDS: M-TOKENIZER, M-NAME-FORMS, M-REID-TEST, M-VALIDATOR
#   LINKS: M-METRICS, V-M-METRICS, fn-recall, fn-rep_rate, fn-ph_consistency, fn-false_activity, fn-gate_false_blocks, fn-reversibility, fn-k_share
#   ROLE: SCRIPT
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   MIN_SAMPLE - минимальный размер фиксированного набора значений клиента
#   BARS - планки метрик из docs/ARCHITECTURE.md, раздел «Постоянные метрики»
#   K_THRESHOLD - порог k для агрегатов («ячейка 5»)
#   CLEAN_CORPUS - обычный рабочий текст, который обязан остаться нетронутым
#   SampleValue - значение набора: класс, вид и текст
#   MetricResult - одна метрика: число, планка, вердикт, счётчики
#   MetricsReport - отчёт целиком, без значений клиентов
#   MetricsPipeline - швы измерения: те же вызовы, что делает рантайм
#   fn-build_client_sample - фиксированный синтетический набор >= 300 значений
#   fn-value_forms - падежные формы значения по таблицам M-NAME-FORMS
#   fn-recall - доля заменённых значений набора
#   fn-rep_rate - доля заменённых вхождений с учётом всех форм значения
#   fn-ph_consistency - один код на значение; планка ровно 1.0
#   fn-false_activity - ложные замены на чистом рабочем корпусе
#   fn-gate_false_blocks - ложные блокировки заслона на том же корпусе
#   fn-reversibility - успешные восстановления без ключа; планка 0
#   fn-k_share - доля агрегатов с k меньше пяти; планка 0
#   fn-group_aggregates - группы квазидентификаторов тем же ключом, что у атаки
#   fn-measure - прогон всех метрик одним отчётом
#   fn-render_report - отчёт markdown: только числа и счётчики
#   field-identity_counters - счётчики источников идентичности (M-NAME-IDENTITY) в отчёте
#   fn-build_pipeline - собрать тот же конвейер, что в сервисе
#   fn-_dictionary_source - настоящий (хешированный) справочник или синтетический словарь набора
#   fn-main - точка входа CLI
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.2.0 - Phase-8 шаг 2: прибор умеет мерить контур продакшена — --dict-file и --dict-key-file подставляют настоящий хешированный справочник, чтобы планка «один код на персону» проверялась на том же словаре, что работает в службе.
#   PREVIOUS: v1.1.0 - Phase-7 шаг 6: отчёт несёт счётчики источников идентичности значения (числа, без значений клиентов).
#   EARLIER: v1.0.0 - Phase-12 шаг 4: постоянные метрики качества обезличивания. Планки и обоснование — docs/ARCHITECTURE.md; в приказе РКН № 140 метрик нет, критерии задаём сами и обосновываем прецедентами (EMA/Health Canada 0,09; «ячейка 5» — 0,2).
# END_CHANGE_SUMMARY

"""Постоянные метрики качества обезличивания (M-METRICS).

Implements step 4 of Phase-12 from docs/ARCHITECTURE.md.

Судья любой правки — **доля фактически заменённых данных клиента**, а не число удалённых
строк словаря: прошлая чистка выглядела успехом (−21% в классе имён), а уронила
обезличение с 99,9% до 73%. Поэтому метрики считаются кодом на фиксированном наборе, и
планки у них есть (docs/ARCHITECTURE.md):

* **только числа и счётчики** — значения клиентов не печатаются ни в отчёте, ни в журнале;
* **измеряем тем же вызовом, что рантайм** — метрика «значение уцелело» берётся из атаки
  M-REID-TEST (`value_present`), а не переписывается здесь заново: два критерия одного
  свойства расходятся и начинают врать;
* **нулевое число попыток — не успех**: пустой набор, пустой корпус и пустая группировка
  поднимают ошибку, а не дают чистый вердикт.

Внешние наборы pii-bench (Apache-2.0) и pii_benchmark (MIT) сюда не подключены: они не
проверены на совместимость разметки и не входят в зафиксированную поставку. Записи об
этом — в отчёте шага и в `docs/OPERATIONS.md` (phase-follow-up V-M-METRICS).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import tempfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.detect_name import NameDetector  # noqa: E402
from src.dict_export import to_keyed_digests  # noqa: E402
from src.dictionary import SCHEMA_DIGEST, PiiDictionary  # noqa: E402
from src.channel_policy import ChannelPolicy  # noqa: E402
from src.detokenizer import PayloadDetokenizer  # noqa: E402
from src.map_store import TokenMapStore  # noqa: E402
from src.name_forms import name_forms, normalize_name  # noqa: E402
from src.name_layer import NameLayer, load_name_layer  # noqa: E402
from src.reid_suite import (  # noqa: E402
    DEFAULT_K,
    QUASI_FIELDS,
    value_present,
)
from src.name_coherence import (  # noqa: E402
    MODE_ENFORCE,
    MODE_OFF,
    NameCoherence,
    build_combos,
    is_part_value,
)
from src.token_factory import canonical_token, find_tokens, make_token  # noqa: E402
from src.tokenizer import PayloadTokenizer  # noqa: E402
from src.validator import ResidualPiiValidator  # noqa: E402

LOGGER_NAME = "QualityMetrics"
LOG_MARKER = "[QualityMetrics][measure][BLOCK_RUN_METRICS]"

# Сессия приборов: по ней связаны записи журнала, значения в журнал не попадают.
SESSION_ID = "quality-metrics"

#: Минимальный размер фиксированного набора значений клиента (планка из плана).
MIN_SAMPLE = 300

#: Порог k для агрегатов: «ячейка 5» (EMA/Health Canada называют порог риска 0,09, k ≥ 5 даёт 0,2).
K_THRESHOLD = DEFAULT_K

#: Планки метрик. Ноль у «ложных» и «обратимости» означает «допустимо ровно ноль».
BARS: dict[str, float] = {
    "recall": 0.95,
    "rep_rate": 0.95,
    "ph_consistency": 1.0,
    "false_replacements": 0.0,
    "false_blocks": 0.0,
    "reversibility": 0.0,
    "k_share": 0.0,
    # Phase-17 (требование владельца): многозначный код и склейка персон — жёсткие планки,
    # а не «редкий случай». Нарушение планки = красный прибор, а не жалоба пользователя.
    "ambiguous_codes": 0.0,
    "glued_persons": 0.0,
    "false_glue_blocks": 0.0,
}

#: Синтетические карточки для замера заслона связности: пары внутри карточки обязаны
#: подтверждаться, пары из разных карточек — нет. Значения синтетические.
GLUE_PERSONS = (
    ("Иванов", "Иван", "Иванович"),
    ("Печёнов", "Сергей", "Сергеевич"),
    ("Скрытницов", "Максим", "Максимович"),
)

#: Ключ индекса сочетаний для замера: значения набора синтетические, секрет не нужен.
GLUE_COMBOS_KEY = b"quality-metrics-combos-key-32byte"

KIND_LASTNAME = "lastname"
KIND_FIRSTNAME = "firstname"
KIND_PATRONYMIC = "patronymic"
KIND_PLAIN = "plain"

# Синтетические словари: настоящих значений клиентов в приборе быть не может.
SURNAMES = (
    "Иванов", "Печёнов", "Заглушков", "Скрытницов", "Скрытнев",
    "Абрамов", "Пивоваров", "Грешнов", "Мещеряков", "Осипов",
    "Сахнов", "Токенец", "Тестовцев", "Терёхин", "Мещерин",
    "Дюма", "Шевченко", "Бонч-Бруевич", "Скрытниных", "Тесляков",
)
GIVEN_NAMES = (
    "Иван", "Сергей", "Ольга", "Дмитрий", "Анна",
    "Максим", "Ирина", "Пётр", "Елена", "Артём",
)
PATRONYMICS = (
    "Иванович", "Петровна", "Алексеевич", "Игоревна", "Николаевич",
    "Сергеевна", "Геннадьевич", "Олеговна", "Кузьмич", "Ильинична",
)
PHONES = tuple(f"7900000{index:04d}" for index in range(20))
EMAILS = tuple(f"client{index}@example.ru" for index in range(20))

# Чистый рабочий корпус: обычный текст, который обязан остаться нетронутым
# (бренд, термины, цены, пути, команды). Ложная замена здесь — дефект того же
# класса, что и ложная блокировка: 16.09.2026 «Для рекламы» стало «zPXXXXXXX рекламы».
CLEAN_CORPUS: tuple[str, ...] = (
    "Пример Спорт — первый фитнес Примерск",
    "клуб Квартальный, клуб Центральный, клуб Базовый, ТЦ Пример",
    "Для рекламы, На неделю, Отчёт, Задача, Ответ",
    "Клиент купил карту, клуб открыт, тренер вышел, сайт работает",
    "тариф Годовой, оплата помесячно, фитнес-тест включён",
    "годовая карта стоит 28 000 рублей, месячная 5 900",
    "карта на 12 мес, продление на 6 мес, период 2 мес",
    "путь /opt/agent/config.yaml",
    "https://example.com и https://wifi.example.com",
    "команда hermes config set model.base_url",
    "версия 1.0.0, протокол HTTP/1.1, порт 8791",
    # Заглавные деловые обороты (находка 19.09.2026): шаблон «два слова заглавными»
    # принимал их за ФИО по ОДНОМУ признаку — заглавной букве. Слова намеренно вне
    # STOPWORDS: иначе они отсекались бы списком, и замер не показывал бы дефект формы.
    "ВЫРУЧКА ПРОДАЖИ за месяц",
    "ОПЛАТА ТОПОЛЬ закрыт",
    "РАСПИСАНИЕ ЗАНЯТИЕ открыто",
    "БАЛАНС ГОСТЬ и запись",
    "НОВОСТИ КОМПАНИИ для клуба",
    "ТРЕНИРОВКА ЗАПИСЬ открыта",
    # Строка системного промпта (находка 26.09.2026): подписи полей «ФИО» и «Персональные»
    # стоят в ней рядом, и детектор имён заменял их кодами — 322 ложные находки в блоке
    # системного промпта. Строка добавлена в корпус, чтобы прибор мерил этот дефект, а не
    # только повторял, что его нет: до правки `false_replacements` здесь не равен нулю,
    # после — равен.
    "Персональные данные клиентов (ФИО, телефон, почта, адрес, дата рождения) "
    "приходят в коде и восстанавливаются доверенной границей.",
)

# Агрегаты для проверки k: клиентов в каждой ячейке не меньше пяти.
AGGREGATE_CLUBS = ("Квартальный", "Центральный", "Базовый")
AGGREGATE_CARDS = ("12 мес", "5 мес", "2 мес", "Годовой")
AGGREGATE_PER_CELL = 5

#: Переменная окружения прокси: путь к настоящему открытому слою распознавания.
LAYER_ENV = "PII_PROXY_NAME_LAYER"

#: Вид словаря прибора. `raw` — синтетический словарь набора (читаемые значения), `digests` и
#: `forms` — файл продакшен-вида из значений набора: отпечатки без формо-дигестов (схема 2) и
#: с ними (схема 3). Разница между последними двумя и есть замер Phase-8.
SAMPLE_DICT_RAW = "raw"
SAMPLE_DICT_DIGESTS = "digests"
SAMPLE_DICT_FORMS = "forms"
SAMPLE_DICT_MODES = (SAMPLE_DICT_RAW, SAMPLE_DICT_DIGESTS, SAMPLE_DICT_FORMS)

#: Ключ отпечатков для словаря, собранного из набора: не секрет, значения набора синтетические.
SAMPLE_DICT_KEY = b"quality-metrics-sample-dict-key"

#: Форма, которую вообще имеет смысл искать в тексте: слово без точек и пробелов.
WORD_SHAPE = re.compile(r"^[А-Яа-яЁё][А-Яа-яЁё-]*$")

#: Шаблон вхождения значения. Рядом стоят признаки работы с данными: без них детектор
#: справедливо не считает слово именем (защита от ложных замен), и прибор обязан её уважать,
#: иначе он мерит не тот конвейер, который работает в запросе.
VALUE_TEMPLATE = "Анкета: {value}"


class MetricsError(RuntimeError):
    """Отказ прибора: измерять нечего или вход противоречит контракту.

    # START_CONTRACT: MetricsError
    #   PURPOSE: Не дать прибору выдать чистый вердикт по пустому измерению.
    #   INPUTS: { code: str - машинный код, message: str - пояснение }
    #   OUTPUTS: { MetricsError - исключение }
    #   SIDE_EFFECTS: none
    #   LINKS: M-METRICS, V-M-METRICS
    # END_CONTRACT: MetricsError
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# START_BLOCK_BUILD_SAMPLE
@dataclass(frozen=True)
class SampleValue:
    """Одно значение фиксированного набора.

    # START_CONTRACT: SampleValue
    #   PURPOSE: Описать значение клиента так, чтобы форма порождалась по виду поля.
    #   INPUTS: { cls: str - класс ПД, value: str - синтетическое значение, kind: str - вид поля }
    #   OUTPUTS: { SampleValue - значение набора }
    #   SIDE_EFFECTS: none
    #   LINKS: M-METRICS, M-NAME-FORMS
    # END_CONTRACT: SampleValue
    """

    cls: str
    value: str
    kind: str


@dataclass(frozen=True)
class MetricResult:
    """Результат одной метрики.

    # START_CONTRACT: MetricResult
    #   PURPOSE: Отдать число, планку и счётчики так, чтобы вердикт нельзя было подделать словами.
    #   INPUTS: { name: str, value: float, bar: float | None, passed: bool, detail: Mapping[str, int] }
    #   OUTPUTS: { MetricResult - результат метрики }
    #   SIDE_EFFECTS: none
    #   LINKS: M-METRICS, V-M-METRICS
    # END_CONTRACT: MetricResult
    """

    name: str
    value: float
    bar: float | None
    passed: bool
    detail: Mapping[str, int] = field(default_factory=dict)


def build_client_sample(count: int = MIN_SAMPLE) -> tuple[SampleValue, ...]:
    """Собрать фиксированный синтетический набор значений клиента.

    # START_CONTRACT: build_client_sample
    #   PURPOSE: Дать метрикам один и тот же набор от прогона к прогону.
    #   INPUTS: { count: int - размер набора, не меньше MIN_SAMPLE }
    #   OUTPUTS: { tuple[SampleValue, ...] - значения набора }
    #   SIDE_EFFECTS: none
    #   LINKS: M-METRICS, V-M-METRICS
    # END_CONTRACT: build_client_sample

    Порядок сборки фиксирован: сначала значения по полям (как их держит клиентский
    слой), затем составные ФИО для добора до размера набора.
    """
    if count < MIN_SAMPLE:
        raise MetricsError(
            "METRICS_SAMPLE_TOO_SMALL",
            f"набор из {count} значений меньше планки {MIN_SAMPLE}",
        )
    items: list[SampleValue] = []
    items.extend(SampleValue("P", value, KIND_LASTNAME) for value in SURNAMES)
    items.extend(SampleValue("P", value, KIND_FIRSTNAME) for value in GIVEN_NAMES)
    items.extend(SampleValue("P", value, KIND_PATRONYMIC) for value in PATRONYMICS)
    items.extend(SampleValue("T", value, KIND_PLAIN) for value in PHONES)
    items.extend(SampleValue("E", value, KIND_PLAIN) for value in EMAILS)
    for surname in SURNAMES:
        for name in GIVEN_NAMES:
            for patronymic in PATRONYMICS:
                if len(items) >= count:
                    break
                items.append(SampleValue("P", f"{surname} {name} {patronymic}", KIND_LASTNAME))
            if len(items) >= count:
                break
        if len(items) >= count:
            break
    if len(items) < count:
        raise MetricsError(
            "METRICS_SAMPLE_TOO_SMALL",
            f"словарей не хватило на {count} значений",
        )
    return tuple(items[:count])


def value_forms(item: SampleValue) -> tuple[str, ...]:
    """Вернуть все формы значения: исходное написание и падежные формы.

    # START_CONTRACT: value_forms
    #   PURPOSE: Искать значение во всех формах, а не только в исходной.
    #   INPUTS: { item: SampleValue - значение набора }
    #   OUTPUTS: { tuple[str, ...] - формы без повторов, исходная первая }
    #   SIDE_EFFECTS: читает таблицы склонений через M-NAME-FORMS
    #   LINKS: M-NAME-FORMS, V-M-NAME-FORMS
    # END_CONTRACT: value_forms

    В замер попадают только словоформы (WORD_SHAPE): генератор изредка выдаёт
    артефакт вида «бонч.-бруевича», которого в тексте не бывает, и считать его
    пропуском замены — значит мерить генератор, а не обезличивание.
    """
    if item.kind == KIND_PLAIN or len(item.value.split()) != 1:
        return (item.value,)
    forms = name_forms(item.value, item.kind)
    unique: dict[str, None] = {}
    for form in forms:
        if form.strip() and WORD_SHAPE.match(form.strip()):
            unique.setdefault(form.strip(), None)
    return tuple(unique) or (item.value,)


def build_layer(
    sample: Sequence[SampleValue],
    layer_path: str | None = None,
) -> tuple[NameLayer, str]:
    """Вернуть слой распознавания и его вид: настоящий открытый список или синтетика.

    # START_CONTRACT: build_layer
    #   PURPOSE: Мерить тот же конвейер, что в сервисе: детектор смотрит в открытый слой, а не в пустоту.
    #   INPUTS: { sample: Sequence[SampleValue], layer_path: str | None - путь к слою }
    #   OUTPUTS: { tuple[NameLayer, str] - слой и вид («file» или «synthetic») }
    #   SIDE_EFFECTS: читает файл слоя, если он есть
    #   LINKS: M-NAME-LAYER, M-DETECT-NAME, V-M-METRICS
    # END_CONTRACT: build_layer

    Без слоя прибор мерил бы не тот конвейер: склонённые формы ищутся обратным ходом
    к основе именно по открытому списку, и на пустом слое любая форма выглядит пропуском.
    """
    path = layer_path or os.environ.get(LAYER_ENV, "")
    if path and os.path.isfile(path):
        layer = load_name_layer(path)
        if layer is not None and layer.size:
            return layer, "file"
    values = {
        # Ключ сравнения у обратного хода — нормализованное написание в нижнем регистре,
        # как в настоящем открытом списке; с заглавными буквами слой молча не отвечает.
        "P": {normalize_name(item.value) for item in sample if item.kind != KIND_PLAIN},
    }
    layer = NameLayer(values, {"source": "synthetic", "licence": "n/a"})
    return layer, "synthetic"


def build_dictionary(sample: Sequence[SampleValue]) -> dict[str, list[str]]:
    """Собрать словарь прибора из набора значений (клиентский слой, синтетика)."""
    layer: dict[str, list[str]] = {}
    for item in sample:
        bucket = layer.setdefault(item.cls, [])
        if item.value not in bucket:
            bucket.append(item.value)
    return layer


def build_aggregates() -> list[dict[str, object]]:
    """Собрать синтетические агрегаты: в каждой ячейке не меньше пяти клиентов.

    Сумма внутри ячейки одна и та же: если она разойдётся по клиентам, каждая запись
    станет собственной ячейкой и проверка k выродится в «все ячейки по одному человеку».
    """
    records: list[dict[str, object]] = []
    for club_index, club in enumerate(AGGREGATE_CLUBS):
        for card_index, card in enumerate(AGGREGATE_CARDS):
            amount = 28_000 + (club_index * len(AGGREGATE_CARDS) + card_index) * 1_000
            for index in range(AGGREGATE_PER_CELL):
                records.append(
                    {
                        "club": club,
                        "card": card,
                        "amount": amount,
                        "fio": f"{SURNAMES[index % len(SURNAMES)]} {GIVEN_NAMES[index % len(GIVEN_NAMES)]}",
                    }
                )
    return records
# END_BLOCK_BUILD_SAMPLE


# START_BLOCK_MEASURE_VALUES
def _verdict(name: str, value: float) -> tuple[float | None, bool]:
    """Сравнить метрику с планкой; у планки ровно ноль и ровно один — без допуска."""
    bar = BARS.get(name)
    if bar is None:
        return None, False
    return bar, value <= bar if bar == 0.0 else value >= bar


def recall(
    sample: Sequence[SampleValue],
    anonymize: Callable[[str], str],
) -> MetricResult:
    """Полнота обезличивания: доля заменённых значений набора.

    # START_CONTRACT: recall
    #   PURPOSE: Показать, что данные клиента из набора действительно заменяются.
    #   INPUTS: { sample: Sequence[SampleValue], anonymize: Callable[[str], str] - обезличивание текста }
    #   OUTPUTS: { MetricResult - доля заменённых, планка >= 0.95 }
    #   SIDE_EFFECTS: обезличивает тексты (пишет связи в справочник)
    #   LINKS: M-TOKENIZER, M-METRICS, V-M-METRICS
    # END_CONTRACT: recall
    """
    if not sample:
        raise MetricsError("METRICS_NO_SAMPLE", "набор значений пуст")
    total = 0
    replaced = 0
    for item in sample:
        total += 1
        anonymized = anonymize(VALUE_TEMPLATE.format(value=item.value))
        # Критерий тот же, что у атаки на обратимость: значение «уцелело» или нет.
        if not value_present(item.value, item.cls, anonymized):
            replaced += 1
    value = replaced / total
    bar, passed = _verdict("recall", value)
    return MetricResult(
        name="recall",
        value=value,
        bar=bar,
        passed=passed,
        detail={"values": total, "replaced": replaced, "missed": total - replaced},
    )


def rep_rate(
    sample: Sequence[SampleValue],
    anonymize: Callable[[str], str],
) -> MetricResult:
    """Доля заменённых вхождений с учётом всех форм значения.

    # START_CONTRACT: rep_rate
    #   PURPOSE: Считать пропуски по вхождениям, а не по значениям: склонённая форма — тоже утечка.
    #   INPUTS: { sample: Sequence[SampleValue], anonymize: Callable[[str], str] }
    #   OUTPUTS: { MetricResult - доля заменённых вхождений, планка >= 0.95 }
    #   SIDE_EFFECTS: обезличивает тексты
    #   LINKS: M-NAME-FORMS, M-DETECT-NAME, M-METRICS
    # END_CONTRACT: rep_rate
    """
    if not sample:
        raise MetricsError("METRICS_NO_SAMPLE", "набор значений пуст")
    occurrences = 0
    replaced = 0
    base_misses = 0
    declined_misses = 0
    for item in sample:
        for form in value_forms(item):
            occurrences += 1
            anonymized = anonymize(VALUE_TEMPLATE.format(value=form))
            if not value_present(form, item.cls, anonymized):
                replaced += 1
                continue
            # Пропуск в исходном написании и пропуск в склонённой форме — разные дефекты,
            # и владельцу важно видеть, какой именно перед ним.
            if form == item.value:
                base_misses += 1
            else:
                declined_misses += 1
    value = replaced / occurrences
    bar, passed = _verdict("rep_rate", value)
    return MetricResult(
        name="rep_rate",
        value=value,
        bar=bar,
        passed=passed,
        detail={
            "occurrences": occurrences,
            "replaced": replaced,
            "missed": occurrences - replaced,
            "base_misses": base_misses,
            "declined_misses": declined_misses,
        },
    )


def ph_consistency(observations: Mapping[str, Sequence[str]]) -> MetricResult:
    """Один код на значение во всех вхождениях; планка ровно 1.0.

    # START_CONTRACT: ph_consistency
    #   PURPOSE: Поймать дефект нормализации: одно значение получает разные коды.
    #   INPUTS: { observations: Mapping[str, Sequence[str]] - значение → замеченные коды }
    #   OUTPUTS: { MetricResult - доля значений с единственным кодом, планка ровно 1.0 }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKEN-GEN, M-NORM, M-METRICS
    # END_CONTRACT: ph_consistency

    Разные коды у одного значения ломают и промпт-кэш провайдера, и рассуждение модели
    («это тот же клиент?»). Поэтому планка не «почти один», а ровно 1.0.
    """
    if not observations:
        raise MetricsError("METRICS_NO_OBSERVATIONS", "нет наблюдений по значениям")
    total = len(observations)
    consistent = sum(1 for codes in observations.values() if len(set(codes)) == 1)
    value = consistent / total
    bar, passed = _verdict("ph_consistency", value)
    return MetricResult(
        name="ph_consistency",
        value=value,
        bar=bar,
        passed=passed,
        detail={"values": total, "consistent": consistent, "inconsistent": total - consistent},
    )
# END_BLOCK_MEASURE_VALUES


# START_BLOCK_MEASURE_SAFETY
def false_activity(
    clean_corpus: Iterable[str],
    anonymize: Callable[[str], str],
) -> MetricResult:
    """Ложные замены на чистом рабочем корпусе; планка 0.

    # START_CONTRACT: false_activity
    #   PURPOSE: Проверить, что обычный текст не превращается в коды.
    #   INPUTS: { clean_corpus: Iterable[str], anonymize: Callable[[str], str] }
    #   OUTPUTS: { MetricResult - число изменённых текстов и найденных кодов, планка 0 }
    #   SIDE_EFFECTS: обезличивает тексты
    #   LINKS: M-DETECT-NAME, M-METRICS, V-M-METRICS
    # END_CONTRACT: false_activity
    """
    texts = list(clean_corpus)
    if not texts:
        raise MetricsError("METRICS_NO_CORPUS", "чистый корпус пуст")
    changed = 0
    codes = 0
    for text in texts:
        anonymized = anonymize(text)
        if anonymized != text:
            changed += 1
        codes += len(find_tokens(anonymized))
    value = float(changed + codes)
    bar, passed = _verdict("false_replacements", value)
    return MetricResult(
        name="false_replacements",
        value=value,
        bar=bar,
        passed=passed,
        detail={"texts": len(texts), "changed": changed, "codes": codes},
    )


def gate_false_blocks(
    clean_corpus: Iterable[str],
    anonymize_payload: Callable[[dict], dict],
    gate: Callable[[dict, dict | None], bool],
) -> MetricResult:
    """Ложные блокировки заслона на чистом рабочем корпусе; планка 0.

    # START_CONTRACT: gate_false_blocks
    #   PURPOSE: Проверить, что заслон не бракует запросы, где ПД клиента нет.
    #   INPUTS: { clean_corpus: Iterable[str], anonymize_payload: Callable[[dict], dict], gate: Callable[[dict, dict | None], bool] }
    #   OUTPUTS: { MetricResult - число забракованных запросов, планка 0 }
    #   SIDE_EFFECTS: обезличивает payload'ы и вызывает заслон
    #   LINKS: M-VALIDATOR, M-ROUTER, M-METRICS
    # END_CONTRACT: gate_false_blocks

    Заслон зовём ровно так, как это делает роутер: с оригиналом запроса, иначе проверка
    идёт по другому тексту и даёт ложные вердикты (находка 18.09.2026).
    """
    texts = list(clean_corpus)
    if not texts:
        raise MetricsError("METRICS_NO_CORPUS", "чистый корпус пуст")
    blocked = 0
    for text in texts:
        payload = {"model": "quality-metrics", "messages": [{"role": "user", "content": text}]}
        anonymized = anonymize_payload(payload)
        if not gate(anonymized, payload):
            blocked += 1
    value = float(blocked)
    bar, passed = _verdict("false_blocks", value)
    return MetricResult(
        name="false_blocks",
        value=value,
        bar=bar,
        passed=passed,
        detail={"requests": len(texts), "blocked": blocked},
    )


def reversibility(
    sample: Sequence[SampleValue],
    corpus: str,
) -> MetricResult:
    """Успешные восстановления значения без ключа; планка 0.

    # START_CONTRACT: reversibility
    #   PURPOSE: Показать, что в обезличенном корпусе не уцелело ни одного значения.
    #   INPUTS: { sample: Sequence[SampleValue], corpus: str - обезличенный текст }
    #   OUTPUTS: { MetricResult - число найденных значений (успешных атак), планка 0 }
    #   SIDE_EFFECTS: none
    #   LINKS: M-REID-TEST, M-METRICS, V-M-METRICS
    # END_CONTRACT: reversibility
    """
    if not sample:
        raise MetricsError("METRICS_NO_SAMPLE", "набор значений пуст")
    if not corpus.strip():
        raise MetricsError("METRICS_NO_CORPUS", "обезличенный корпус пуст")
    attempts = 0
    successes = 0
    for item in sample:
        for form in value_forms(item):
            attempts += 1
            if value_present(form, item.cls, corpus):
                successes += 1
    value = float(successes)
    bar, passed = _verdict("reversibility", value)
    return MetricResult(
        name="reversibility",
        value=value,
        bar=bar,
        passed=passed,
        detail={"attempts": attempts, "successes": successes},
    )


def group_aggregates(records: Iterable[Mapping[str, Any]]) -> dict[tuple, int]:
    """Сгруппировать записи по квазиидентификаторам тем же ключом, что у атаки M-REID-TEST.

    # START_CONTRACT: group_aggregates
    #   PURPOSE: Держать один критерий ячейки на прибор и на атаку.
    #   INPUTS: { records: Iterable[Mapping[str, Any]] - записи с полями квазиидентификаторов }
    #   OUTPUTS: { dict[tuple, int] - ключ ячейки → число записей }
    #   SIDE_EFFECTS: none
    #   LINKS: M-REID-TEST, M-METRICS
    # END_CONTRACT: group_aggregates
    """
    groups: dict[tuple, int] = {}
    for record in records:
        key = tuple(str(record.get(field_name, "")) for field_name in QUASI_FIELDS)
        groups[key] = groups.get(key, 0) + 1
    return groups


def registry_ambiguity(ambiguous: int, codes: int) -> MetricResult:
    """Сколько кодов несут больше одного значения или больше одной персоны; планка 0.

    # START_CONTRACT: registry_ambiguity
    #   PURPOSE: Показать состояние инварианта «код значит ровно одно значение» числом.
    #   INPUTS: { ambiguous: int - число многозначных кодов, codes: int - всего кодов }
    #   OUTPUTS: { MetricResult - число, планка 0 }
    #   SIDE_EFFECTS: none
    #   LINKS: M-MAP-STORE, M-METRICS, V-M-METRICS
    # END_CONTRACT: registry_ambiguity
    """
    value = float(ambiguous)
    bar, passed = _verdict("ambiguous_codes", value)
    return MetricResult(
        name="ambiguous_codes",
        value=value,
        bar=bar,
        passed=passed,
        detail={"codes": int(codes), "ambiguous": int(ambiguous)},
    )


def person_glue_guard(
    pipeline: MetricsPipeline,
    persons: Sequence[Sequence[str]] = GLUE_PERSONS,
) -> tuple[MetricResult, MetricResult]:
    """Замер заслона связности: склейка не восстанавливается, законное ФИО восстанавливается.

    # START_CONTRACT: person_glue_guard
    #   PURPOSE: Проверить оба направления заслона: выдуманную персону не пропустить и законную не потерять.
    #   INPUTS: { pipeline: MetricsPipeline - швы конвейера, persons: Sequence[Sequence[str]] - синтетические карточки }
    #   OUTPUTS: { tuple[MetricResult, MetricResult] - (склейки, ложные отказы) }
    #   SIDE_EFFECTS: пишет связи в справочник прибора, читает их при восстановлении
    #   LINKS: M-NAME-COHERENCE, M-DETOKENIZER, M-METRICS, V-M-METRICS
    # END_CONTRACT: person_glue_guard

    Механика: каждому значению выдаётся код настоящей фабрикой, затем в текст подставляются
    два кода с пробелом между ними — так их склеивает модель. Проверяются две вещи:
    (1) пара из разных карточек НЕ восстанавливается (иначе на границе появится человек,
    которого нет); (2) пара из одной карточки восстанавливается (иначе заслон бесполезен).
    """
    codes: dict[str, str] = {}
    for parts in persons:
        for part in parts:
            if part not in codes:
                codes[part] = pipeline.issue_code("P", part)
    glued = 0
    attempts = 0
    for index, parts in enumerate(persons):
        for other in persons:
            if other is parts:
                continue
            attempts += 1
            text = f"{codes[parts[0]]} {codes[other[1]]}"
            restored = pipeline.restore_text(text, [codes[parts[0]], codes[other[1]]])
            if parts[0] in restored and other[1] in restored:
                glued += 1
    refused = 0
    checked = 0
    for parts in persons:
        checked += 1
        text = f"{codes[parts[0]]} {codes[parts[1]]}"
        restored = pipeline.restore_text(text, [codes[parts[0]], codes[parts[1]]])
        if parts[0] not in restored or parts[1] not in restored:
            refused += 1
    glued_bar, glued_passed = _verdict("glued_persons", float(glued))
    refused_bar, refused_passed = _verdict("false_glue_blocks", float(refused))
    return (
        MetricResult(
            name="glued_persons",
            value=float(glued),
            bar=glued_bar,
            passed=glued_passed,
            detail={"attempts": attempts, "cards": len(persons)},
        ),
        MetricResult(
            name="false_glue_blocks",
            value=float(refused),
            bar=refused_bar,
            passed=refused_passed,
            detail={"checked": checked},
        ),
    )


def k_share(groups: Mapping[tuple, int], k: int = K_THRESHOLD) -> MetricResult:
    """Доля агрегатов с k меньше пяти; планка 0.

    # START_CONTRACT: k_share
    #   PURPOSE: Не выпускать агрегаты, по которым выделяется один человек.
    #   INPUTS: { groups: Mapping[tuple, int] - ячейки, k: int - порог }
    #   OUTPUTS: { MetricResult - доля ячеек меньше порога, планка 0 }
    #   SIDE_EFFECTS: none
    #   LINKS: M-REID-TEST, M-METRICS
    # END_CONTRACT: k_share
    """
    if not groups:
        raise MetricsError("METRICS_NO_GROUPS", "нет ни одной ячейки агрегатов")
    below = sum(1 for size in groups.values() if size < k)
    value = below / len(groups)
    bar, passed = _verdict("k_share", value)
    return MetricResult(
        name="k_share",
        value=value,
        bar=bar,
        passed=passed,
        detail={"groups": len(groups), "below_k": below, "k": k},
    )
# END_BLOCK_MEASURE_SAFETY


# START_BLOCK_RUN_METRICS
def _noop() -> None:
    """Пустое закрытие: конвейер, переданный тестом, закрывает сам тест."""
    return None


def _noop_issue(cls: str, identity: str) -> str:
    """Выдача кода по умолчанию: детерминированная фабрика на ключе синтетического набора.

    Нужна только подстановкам в тестах: швы замера связности не должны требовать
    настоящего справочника, чтобы проверять границу.
    """
    return make_token(cls, identity, GLUE_COMBOS_KEY)


def _noop_restore(text: str, allowed: Sequence[str]) -> str:
    """Восстановление по умолчанию: ничего не восстанавливает."""
    return text


def _noop_registry() -> tuple[int, int]:
    """Реестр по умолчанию: пустой, многозначных кодов нет."""
    return 0, 0


@dataclass
class MetricsPipeline:
    """Швы измерения: те же вызовы, что делает рантайм.

    # START_CONTRACT: MetricsPipeline
    #   PURPOSE: Отделить измерение от сборки конвейера, чтобы тесты могли подставить честно сломанный конвейер.
    #   INPUTS: { anonymize_text, anonymize_payload, resolve, gate, close }
    #   OUTPUTS: { MetricsPipeline - набор швов }
    #   SIDE_EFFECTS: швы пишут связи в справочник и читают его
    #   LINKS: M-TOKENIZER, M-DETOKENIZER, M-VALIDATOR, V-M-METRICS
    # END_CONTRACT: MetricsPipeline
    """

    anonymize_text: Callable[[str], str]
    anonymize_payload: Callable[[dict], dict]
    gate: Callable[[dict, dict | None], bool]
    layer_kind: str = "synthetic"
    close: Callable[[], None] = _noop
    #: Счётчики источников идентичности значения (M-NAME-IDENTITY): числа без значений
    #: клиентов. Показывают, чем именно разрешилась персона — справочником, формой
    #: или написанием.
    identity_counters: Callable[[], dict[str, int]] = dict
    #: Выдача кода настоящей фабрикой: заслон связности проверяется на границе, а не на словаре.
    issue_code: Callable[[str, str], str] = _noop_issue
    #: Восстановление текста доверенной границей с явным списком разрешённых кодов.
    restore_text: Callable[[str, Sequence[str]], str] = _noop_restore
    #: Число многозначных кодов и всего кодов в измеренном реестре (инвариант Phase-17).
    registry_ambiguity: Callable[[], tuple[int, int]] = _noop_registry
    #: Измеренный справочник соответствия и режим заслона связности: нужны тестам, которые
    #: обязаны показать, что планка УМЕЕТ краснеть (намеренно сломанный заслон, испорченный
    #: реестр), иначе зелёная планка ничего не доказывает.
    store: Any | None = None
    guard_mode: str = MODE_ENFORCE


@dataclass(frozen=True)
class MetricsReport:
    """Отчёт прибора: метрики, счётчики и отпечаток измеренного корпуса.

    # START_CONTRACT: MetricsReport
    #   PURPOSE: Отдать владельцу числа и вердикт, без единого значения клиента.
    #   INPUTS: { metrics: tuple[MetricResult, ...], counters: Mapping[str, int], payload_digest: str }
    #   OUTPUTS: { MetricsReport - отчёт }
    #   SIDE_EFFECTS: none
    #   LINKS: M-METRICS, V-M-METRICS
    # END_CONTRACT: MetricsReport
    """

    metrics: tuple[MetricResult, ...]
    counters: Mapping[str, Any] = field(default_factory=dict)
    payload_digest: str = ""

    @property
    def passed(self) -> bool:
        """Вернуть True, только когда все планки выдержаны."""
        return all(metric.passed for metric in self.metrics)

    def metric(self, name: str) -> MetricResult:
        """Найти метрику по имени (для отчёта и тестов)."""
        for metric in self.metrics:
            if metric.name == name:
                return metric
        raise MetricsError("METRICS_UNKNOWN_METRIC", f"метрика {name!r} не считалась")

    def to_dict(self) -> dict[str, Any]:
        """Отдать отчёт словарём: числа, планки, вердикты и счётчики."""
        return {
            "passed": self.passed,
            "payload_digest": self.payload_digest,
            "counters": dict(self.counters),
            "metrics": [
                {
                    "name": metric.name,
                    "value": metric.value,
                    "bar": metric.bar,
                    "passed": metric.passed,
                    "detail": dict(metric.detail),
                }
                for metric in self.metrics
            ],
        }


def build_pipeline(
    sample: Sequence[SampleValue],
    workdir: str | None = None,
    layer_path: str | None = None,
    dictionary_path: str | None = None,
    dictionary_key_path: str | None = None,
    sample_dictionary: str = SAMPLE_DICT_RAW,
    guard_mode: str = MODE_ENFORCE,
) -> MetricsPipeline:
    """Собрать тот же конвейер, что в сервисе: словарь, слой, детектор, заслон, хранилище.

    # START_CONTRACT: build_pipeline
    #   PURPOSE: Мерить настоящий конвейер, а не упрощённую копию.
    #   INPUTS: { sample: Sequence[SampleValue], workdir: str | None - каталог для временного хранилища, layer_path: str | None - путь к открытому слою, dictionary_path: str | None - путь к настоящему справочнику, dictionary_key_path: str | None - файл ключа справочника, sample_dictionary: str - вид словаря из набора }
    #   OUTPUTS: { MetricsPipeline - швы измерения }
    #   SIDE_EFFECTS: создаёт файл хранилища во временном каталоге, читает слой и справочник
    #   LINKS: M-TOKENIZER, M-DICT, M-NAME-LAYER, M-VALIDATOR, V-M-METRICS
    # END_CONTRACT: build_pipeline

    Справочник продакшен-вида (хешированный) подставляется путём и ключом либо собирается из
    значений набора: именно на нём проверяется планка «один код на персону» (Phase-8), а
    синтетический словарь набора для этого не годится — в нём значения читаемы.
    """
    own_dir = workdir is None
    directory = workdir or tempfile.mkdtemp(prefix="quality-metrics-")
    store = TokenMapStore(os.path.join(directory, "metrics.db"), fernet_key=b"f" * 32)
    layer, layer_kind = build_layer(sample, layer_path)
    dictionary = _dictionary_source(
        sample,
        dictionary_path,
        dictionary_key_path,
        sample_dictionary=sample_dictionary,
        workdir=directory,
    )
    names = NameDetector(dictionary)
    names.register_name_layer(layer)
    token_key = os.urandom(32)
    tokenizer = PayloadTokenizer(token_key, store, names)
    validator = ResidualPiiValidator(names)
    # Заслон связности персоны (Phase-17): индекс сочетаний собирается из синтетических
    # карточек набора, поэтому замер проверяет именно границу, а не содержимое словаря.
    combos, _combo_counters = build_combos(GLUE_PERSONS, GLUE_COMBOS_KEY)
    coherence = NameCoherence(digests=frozenset(combos), meta={"source": "synthetic-sample"})
    detokenizer = PayloadDetokenizer(
        store,
        ChannelPolicy({"metrics"}),
        None,
        identity_of=getattr(names, "identity_for", None),
        coherence=coherence,
        coherence_key=GLUE_COMBOS_KEY,
        coherence_mode=guard_mode,
    )

    def anonymize_text(text: str) -> str:
        return tokenizer.tokenize_text(text, SESSION_ID)

    def anonymize_payload(payload: dict) -> dict:
        anonymized, _stats = tokenizer.tokenize_payload(payload, SESSION_ID)
        return anonymized

    def gate(outgoing: dict, original: dict | None) -> bool:
        return bool(validator.validate_outgoing(outgoing, original).clean)

    def issue_code(cls: str, identity: str) -> str:
        """Выдать код значению настоящей фабрикой конвейера."""
        return tokenizer.issue_identifier(cls, identity, identity)

    def restore_text(text: str, allowed: Sequence[str]) -> str:
        """Восстановить текст доверенной границей: только разрешённые коды, заслоны включены."""
        canonical = {canonical_token(item) for item in allowed}
        restored, _counters = detokenizer.detokenize_text(text, "metrics", "quality-metrics", canonical)
        return restored

    def registry_ambiguity() -> tuple[int, int]:
        """Считать многозначные коды измеренного реестра и всего кодов."""
        report = store.scan_integrity(getattr(names, "identity_for", None))
        return report.ambiguous, report.codes

    def close() -> None:
        store.close()
        if own_dir:
            for name in os.listdir(directory):
                try:
                    os.remove(os.path.join(directory, name))
                except OSError:  # noqa: BLE001 - временный каталог, чистим что можем
                    pass
            try:
                os.rmdir(directory)
            except OSError:  # noqa: BLE001
                pass

    return MetricsPipeline(
        anonymize_text=anonymize_text,
        anonymize_payload=anonymize_payload,
        gate=gate,
        issue_code=issue_code,
        restore_text=restore_text,
        registry_ambiguity=registry_ambiguity,
        store=store,
        guard_mode=guard_mode,
        layer_kind=layer_kind,
        close=close,
        identity_counters=names.identity_counters,
    )


def _dictionary_source(
    sample: Sequence[SampleValue],
    dictionary_path: str | None,
    dictionary_key_path: str | None,
    sample_dictionary: str = SAMPLE_DICT_RAW,
    workdir: str | None = None,
) -> Any:
    """Вернуть словарь прибора: настоящий (хешированный), из набора или синтетический.

    # START_CONTRACT: _dictionary_source
    #   PURPOSE: Мерить и синтетический контур, и контур продакшена одним прибором.
    #   INPUTS: { sample: Sequence[SampleValue], dictionary_path: str | None, dictionary_key_path: str | None, sample_dictionary: str - вид словаря из набора, workdir: str | None }
    #   OUTPUTS: { Any - словарь для NameDetector }
    #   SIDE_EFFECTS: читает файлы словаря и ключа, пишет временный файл словаря из набора
    #   LINKS: M-DICT, M-DICT-EXPORT, V-M-METRICS
    # END_CONTRACT: _dictionary_source

    Ключ обязателен вместе с путём: без него хешированный словарь не отвечает ни на один
    запрос, и прибор молча мерил бы пустой контур (нуль попыток — не успех).

    Вид «из набора» нужен для планки Phase-8: значения набора собираются в файл словаря
    продакшен-вида (отпечатки, читаемых значений нет), и видно, держит ли выгрузка один код на
    персону. ``digests`` — схема 2 (прежняя выгрузка), ``forms`` — схема 3 (формо-дигесты).
    """
    if sample_dictionary != SAMPLE_DICT_RAW:
        return _sample_dictionary(sample, sample_dictionary, workdir)
    if not dictionary_path:
        return build_dictionary(sample)
    if not dictionary_key_path:
        raise MetricsError(
            "METRICS_NO_DICT_KEY",
            "для хешированного справочника нужен файл ключа (--dict-key-file)",
        )
    try:
        with open(dictionary_key_path, "rb") as handle:
            key = handle.read()
    except OSError as exc:
        raise MetricsError("METRICS_NO_DICT_KEY", f"ключ справочника не читается: {exc}") from exc
    if len(key) < 32:
        raise MetricsError("METRICS_SHORT_DICT_KEY", "ключ справочника короче 32 байт")
    return PiiDictionary(dictionary_path, key=key)


def _sample_dictionary(
    sample: Sequence[SampleValue],
    mode: str,
    workdir: str | None,
) -> PiiDictionary:
    """Собрать словарь продакшен-вида из значений набора и вернуть его.

    # START_CONTRACT: _sample_dictionary
    #   PURPOSE: Воспроизвести контур хешированного справочника на фиксированном наборе.
    #   INPUTS: { sample: Sequence[SampleValue], mode: str - digests (схема 2) или forms (схема 3), workdir: str | None }
    #   OUTPUTS: { PiiDictionary - словарь без читаемых значений }
    #   SIDE_EFFECTS: пишет временный файл словаря
    #   LINKS: M-DICT-EXPORT, M-DICT, Phase-8, V-M-METRICS
    # END_CONTRACT: _sample_dictionary
    """
    if mode not in (SAMPLE_DICT_DIGESTS, SAMPLE_DICT_FORMS):
        raise MetricsError("METRICS_BAD_DICT_MODE", f"неизвестный вид словаря: {mode!r}")
    payload = to_keyed_digests(build_dictionary(sample), SAMPLE_DICT_KEY)
    if mode == SAMPLE_DICT_DIGESTS:
        # Прежняя выгрузка: блок форм отсутствует, схема 2. Именно на ней PhCons был 0,875.
        payload.pop("forms", None)
        payload["schema"] = SCHEMA_DIGEST
    directory = workdir or tempfile.mkdtemp(prefix="quality-metrics-dict-")
    path = os.path.join(directory, "sample_dict.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False)
    return PiiDictionary(path, key=SAMPLE_DICT_KEY)


def _observations(
    sample: Sequence[SampleValue],
    pipeline: MetricsPipeline,
) -> tuple[dict[str, list[str]], int]:
    """Собрать «значение → коды» по однословным значениям (поля анкеты).

    Составное ФИО намеренно исключено: слова ФИО обезличиваются каждое своим кодом,
    и атрибуция «какой код заменил это значение» определена только для полей анкеты —
    ровно того, из чего собран клиентский слой.
    """
    observations: dict[str, list[str]] = {}
    attempts = 0
    for item in sample:
        if item.kind == KIND_PLAIN or len(item.value.split()) != 1:
            continue
        attempts += 1
        counter: set[str] = set()
        for form in value_forms(item):
            anonymized = pipeline.anonymize_text(VALUE_TEMPLATE.format(value=form))
            for span in find_tokens(anonymized):
                counter.add(span[3])
        observations[item.value] = sorted(counter)
    return observations, attempts


def measure(
    pipeline: MetricsPipeline | None = None,
    sample: Sequence[SampleValue] | None = None,
    clean_corpus: Iterable[str] | None = None,
    aggregates: Sequence[Mapping[str, Any]] | None = None,
    k: int = K_THRESHOLD,
    layer_path: str | None = None,
    dictionary_path: str | None = None,
    dictionary_key_path: str | None = None,
    sample_dictionary: str = SAMPLE_DICT_RAW,
) -> MetricsReport:
    """Прогнать все метрики и вернуть отчёт.

    # START_CONTRACT: measure
    #   PURPOSE: Один прогон — все числа из таблицы «Постоянные метрики».
    #   INPUTS: { pipeline: MetricsPipeline | None, sample, clean_corpus, aggregates, k: int, layer_path: str | None, dictionary_path: str | None, dictionary_key_path: str | None, sample_dictionary: str }
    #   OUTPUTS: { MetricsReport - отчёт с числами и вердиктом }
    #   SIDE_EFFECTS: обезличивает набор и корпус, пишет журнал прибора
    #   LINKS: M-METRICS, V-M-METRICS
    # END_CONTRACT: measure
    """
    values = tuple(sample) if sample is not None else build_client_sample()
    texts = tuple(clean_corpus) if clean_corpus is not None else CLEAN_CORPUS
    records = tuple(aggregates) if aggregates is not None else build_aggregates()
    owns = pipeline is None
    active = pipeline or build_pipeline(
        values,
        layer_path=layer_path,
        dictionary_path=dictionary_path,
        dictionary_key_path=dictionary_key_path,
        sample_dictionary=sample_dictionary,
    )
    try:
        observations, observed_values = _observations(values, active)
        corpus = _anonymized_corpus(values, active)
        ambiguous, codes = active.registry_ambiguity()
        results = [
            recall(values, active.anonymize_text),
            rep_rate(values, active.anonymize_text),
            ph_consistency(observations),
            false_activity(texts, active.anonymize_text),
            gate_false_blocks(texts, active.anonymize_payload, active.gate),
            reversibility(values, corpus),
            k_share(group_aggregates(records), k),
            registry_ambiguity(ambiguous, codes),
            *person_glue_guard(active),
        ]
    finally:
        if owns:
            active.close()
    counters = {
        "sample_values": len(values),
        "clean_texts": len(texts),
        "aggregates": len(records),
        "observed_values": observed_values,
        "layer_kind": active.layer_kind,
        "dictionary_kind": (
            "keyed" if dictionary_path else ("sample_" + sample_dictionary)
        ),
        "attempts": sum(int(metric.detail.get("attempts", 0)) for metric in results),
    }
    # Источники идентичности (M-NAME-IDENTITY): показывают, чем разрешилась персона —
    # точным значением справочника, сгенерированной формой, основой открытого списка
    # или поверхностным написанием. Числа, ни одного значения клиента.
    for name, value in active.identity_counters().items():
        counters[f"identity_{name}"] = int(value)
    report = MetricsReport(
        metrics=tuple(results),
        counters=counters,
        # Отпечаток обезличенного корпуса: прогон воспроизводим, значения не печатаются.
        payload_digest=hashlib.sha256(corpus.encode("utf-8")).hexdigest(),
    )
    logging.getLogger(LOGGER_NAME).info(
        "%s metrics=%s passed=%s",
        LOG_MARKER,
        len(results),
        report.passed,
    )
    return report


def _anonymized_corpus(
    sample: Sequence[SampleValue],
    pipeline: MetricsPipeline,
) -> str:
    """Собрать обезличенный корпус: одна выгрузка всех значений набора.

    Корпус нужен атаке на обратимость и отпечатку прогона; наружу уходит только
    отпечаток — сам корпус содержит коды, но не значения клиентов.
    """
    payload = {
        "model": "quality-metrics",
        "messages": [
            {
                "role": "tool",
                "content": json.dumps(
                    [{"fio": item.value} for item in sample], ensure_ascii=False
                ),
            }
        ],
    }
    anonymized = pipeline.anonymize_payload(payload)
    return json.dumps(anonymized, ensure_ascii=False)


def render_report(report: MetricsReport) -> str:
    """Отдать отчёт markdown: только числа и счётчики, без значений клиентов.

    # START_CONTRACT: render_report
    #   PURPOSE: Показать владельцу числа так, чтобы отчёт можно было приложить к делу.
    #   INPUTS: { report: MetricsReport }
    #   OUTPUTS: { str - markdown отчёт }
    #   SIDE_EFFECTS: none
    #   LINKS: M-METRICS, V-M-METRICS
    # END_CONTRACT: render_report
    """
    lines = [
        "| Метрика | Значение | Планка | Итог | Счётчики |",
        "|---|---|---|---|---|",
    ]
    for metric in report.metrics:
        bar = "—" if metric.bar is None else f"{metric.bar:g}"
        detail = ", ".join(f"{key}={value}" for key, value in sorted(metric.detail.items()))
        lines.append(
            f"| `{metric.name}` | {metric.value:g} | {bar} | "
            f"{'выдержана' if metric.passed else 'нарушена'} | {detail} |"
        )
    counters = ", ".join(f"{key}={value}" for key, value in sorted(report.counters.items()))
    lines.append("")
    lines.append(f"Итог: {'все планки выдержаны' if report.passed else 'есть нарушения планов'}")
    lines.append(f"Счётчики прогона: {counters}")
    return "\n".join(lines)


def main(
    argv: Sequence[str] | None = None,
    pipeline: MetricsPipeline | None = None,
    sample: Sequence[SampleValue] | None = None,
) -> int:
    """Точка входа: прогнать метрики и напечатать отчёт.

    # START_CONTRACT: main
    #   PURPOSE: Сделать метрики повторяемым прогоном, а не утверждением в чате.
    #   INPUTS: { argv: Sequence[str] | None, pipeline: MetricsPipeline | None - подстановка для тестов, sample: Sequence[SampleValue] | None }
    #   OUTPUTS: { int - 0 при всех выдержанных планках, 1 при нарушении }
    #   SIDE_EFFECTS: печатает отчёт в stdout
    #   LINKS: M-METRICS, V-M-METRICS
    # END_CONTRACT: main
    """
    parser = argparse.ArgumentParser(description="Постоянные метрики качества обезличивания")
    parser.add_argument("--count", type=int, default=MIN_SAMPLE, help="размер набора значений")
    parser.add_argument(
        "--name-layer",
        default=os.environ.get(LAYER_ENV, ""),
        help="путь к настоящему открытому слою распознавания (по умолчанию — синтетический)",
    )
    parser.add_argument(
        "--dict-file",
        default="",
        help="путь к настоящему справочнику (хешированному); по умолчанию — синтетический словарь набора",
    )
    parser.add_argument(
        "--dict-key-file",
        default="",
        help="файл ключа справочника; обязателен вместе с --dict-file",
    )
    parser.add_argument(
        "--sample-dict",
        choices=SAMPLE_DICT_MODES,
        default=SAMPLE_DICT_RAW,
        help="словарь из значений набора: raw (читаемый), digests (схема 2), forms (схема 3, Phase-8)",
    )
    parser.add_argument("--json", action="store_true", help="вывести отчёт словарём")
    parser.add_argument("--quiet", action="store_true", help="не печатать отчёт, только код выхода")
    args = parser.parse_args(list(argv) if argv is not None else None)
    values = sample if sample is not None else build_client_sample(args.count)
    report = measure(
        pipeline=pipeline,
        sample=values,
        layer_path=args.name_layer or None,
        dictionary_path=args.dict_file or None,
        dictionary_key_path=args.dict_key_file or None,
        sample_dictionary=args.sample_dict,
    )
    if not args.quiet:
        if args.json:
            print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        else:
            print(render_report(report))
    return 0 if report.passed else 1
# END_BLOCK_RUN_METRICS


if __name__ == "__main__":
    sys.exit(main())
