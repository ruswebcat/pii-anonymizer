# FILE: src/detect_name.py
# VERSION: 1.3.2
# START_MODULE_CONTRACT
#   PURPOSE: Detect person names in free text using an exact dictionary plus surname-shape heuristics, without ever flagging clubs, cities or service words.
#   SCOPE: dictionary exact matching, full name and initials patterns, declined forms, all-caps form, stopword filtering.
#   DEPENDS: M-NORM, M-DICT
#   LINKS: M-DETECT-NAME, V-M-DETECT-NAME, fn-detect_names, fn-register_dictionary
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   STOPWORDS - words that must never be treated as names
#   SURNAME_SHAPE - surname ending pattern shared by every name regex
#   NameDetector - dictionary plus heuristic name detector
#   fn-detect_names - return name spans for a text block
#   fn-register_dictionary - bind a dictionary source for exact matches and build the client form index
#   fn-identity_for - идентичность подтверждённого значения для пути «значение под ключом ПД»
#   fn-identity_counters - счётчики источников идентичности без значений клиентов
#   PRODUCTIVE_SURNAME_ENDINGS - продуктивные фамильные окончания
#   fn-surname_is_productive - есть ли у значения продуктивное фамильное окончание
#   fn-morphology_reads_common_word - обычное слово, а не имя (общий критерий для заслона и выгрузки)
#   fn-name_features - независимые признаки имени у значения
#   fn-shape_admission_ok - хватает ли признаков значению без подтверждения справочником
#   fn-_boundary_ok - находка стоит отдельным словом, а не внутри слова
#   fn-is_own_lexicon_word - слово из общего стоп-листа или из лексики оператора
#   fn-is_own_lexicon_value - значение целиком закрыто стоп-листом своей лексики
#   fn-_own_lexicon_ok - значение не из стоп-листа своей лексики (действует на всех ветвях)
#   fn-_value_is_confirmed - фраза подтверждается целиком, а не любым своим словом
#   fn-dictionary_signature - подпись справочника (путь, время правки, размер) для кэшей
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.3.2 - подпись справочника доведена до кэшей токенизатора и заслона. Обёртка `_KnownValues` пробрасывает `path` и `file_signature()`, поэтому `NameDetector.dictionary_signature()` возвращает «путь|время правки|размер» вместо вечного None, и проверка «сменился ли справочник» снова работает без перезапуска службы.
#   PREVIOUS: v1.3.1 - служебные слова метаданных «ФИО», «Персональные» и «Персональный» стоят в стоп-листе целым словом (проверка идёт до разрешения идентичности), а подтверждение клиентским контекстом больше не выдаёт себя за подтверждение именным справочником — из блока системного промпта ушли 322 ложные находки из 323 и секунды на каждом запросе.
#   EARLIER: v1.3.0 - своя лексика организации (бренд, филиалы, тарифы, город) вынесена в настройки: в коде её нет, стоп-лист пополняется из src/own_vocabulary.py, а проверка идёт общей точкой is_own_lexicon_word на всех ветвях распознавания.
#   PREVIOUS: v1.2.2 - Phase-16 M-DICT-HYGIENE: критерий «морфология читает обычное слово» выставлен публичной точкой (morphology_reads_common_word), чтобы чистка выгрузки словаря решала тем же кодом, что и заслон; строка VERSION приведена в соответствие со сводкой.
#   PREVIOUS: v1.2.1 - Phase-9 шаг 1 follow-up (19.09.2026): ложные замены боевого прибора сведены к нулю. Стоп-лист своей лексики и граница слова действуют на всех ветвях распознавания (подтверждение справочником снимает только проверку формы), а значение из нескольких слов подтверждается целиком, а не одним своим словом.
#   PREVIOUS: v1.2.0 - Phase-9 шаг 1: судьба неподтверждённых кандидатов решается двумя-тремя признаками (заглавная буква + тег имени + продуктивное окончание) вместо одного; подтверждение словарём по-прежнему сильнее проверки формы.
#   EARLIER: v1.1.0 - Phase-7 шаг 2: детектор отдаёт идентичность значения (персону) вместе со спаном; склонённые клиентские значения находятся по индексу форм; проверка формы слова заменена разрешением основы M-NAME-IDENTITY.
#   EARLIER: v1.0.0 - Phase-1 M-DETECT-NAME: dictionary and shape heuristics; NER is added in Phase 2.
# END_CHANGE_SUMMARY

"""Name detection.

Implements M-DETECT-NAME from docs/ARCHITECTURE.md. The detector is
deliberately conservative: a capitalized word alone is never a name, only a
dictionary hit or a surname shape followed by a given name or initials counts.
V-M-DETECT-NAME asserts that club, city and service words are never labelled
with class P.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from typing import Any

from src.dictionary import CLASSES, dictionary_signature, live_file_state
from src.detect_rules import CLASS_NAME, PiiMatch, merge_matches
from src.name_forms import normalize_name
from src.name_identity import (
    SOURCE_CLIENT_DIGEST,
    SOURCE_CLIENT_EXACT,
    SOURCE_CLIENT_FORM,
    SOURCE_LAYER_BASE,
    NameIdentity,
)
from src.normalize import NormalizeError, normalize
from src.own_vocabulary import own_terms
from src.translit import matches_known_name

LOGGER_NAME = "NameDetector"
LOG_MARKER = "[NameDetector][detect_names][BLOCK_SCAN_NAMES]"

logger = logging.getLogger(LOGGER_NAME)

STOPWORDS = frozenset(
    {
        # Служебные и видовые слова, которые засорённая выгрузка приносит как «имена».
        # Своя лексика оператора — бренд, филиалы, тарифы, город, адреса и номера связи —
        # в коде НЕ живёт: она приходит из настроек (``src/own_vocabulary.py``,
        # ``config.example.yaml``) и проверяется тем же заслоном через
        # :func:`is_own_lexicon_word`.
        "фитнес",
        "фитнес-тест",
        "клуб",
        "клиент",
        "клиентов",
        "тренер",
        "администратор",
        "admin",
        "карта",
        "абонемент",
        "годовой",
        "итого",
        "всего",
        "акция",
        "тариф",
        "меню",
        "согласно",
        "приложение",
        "доступ",
        "сайт",
        "отчёт",
        "задача",
        "ответ",
        "база",
        "системы",
        "crm",
        "общая",
        # Предлоги и союзы, которые засорённая выгрузка принесла как «имена».
        "для",
        "на",
        # Обычные слова анкеты и карточки: тоже лежат в боевом справочнике клиентов
        # (замер 19.09.2026: «анкета» подтверждена выгрузкой) и персоной не являются.
        "анкета",
        # Служебные слова метаданных (замер 26.09.2026, блок системного промпта): 322 находки
        # из 323 были ложными ровно на этих словах, и все они уходили в модель кодами.
        # «ФИО» лежит в открытом списке как значение и подтверждалось им же, а «Персональные» —
        # падежная форма служебной записи «Персональный» из поля ФИО карточки, поэтому
        # приходило по формо-дигесту выгрузки. Именем не является ни то, ни другое: это
        # подписи полей, и в стоп-листе они стоят целым словом.
        "фио",
        "персональные",
        "персональный",
        # Служебная лексика карточек CRM (замер 20.09.2026, Phase-16) живёт ниже, в
        # STOPWORDS_VALUE: целым значением она закрыта, а словом внутри значения — нет, иначе
        # настоящее ФИО вроде «Тестов Тест Тестович» перестало бы обезличиваться.
    }
)

#: Слова, служебные ТОЛЬКО как само значение, но допустимые внутри ФИО.
#:
#: Зачем разделение (найдено 20.09.2026 при прогоне полного сьюта): слова выше проверяются и
#: целым значением, и словом внутри значения — так ловится «Мой Пример Спорт». Служебное слово из
#: карточки («Тест», «Гость», «Новый») так проверять нельзя: «Тестов Тест Тестович» — настоящее
#: ФИО, и правило «любое слово в стоп-листе» перестало бы его обезличивать. Это ровно тот класс
#: ошибки, на котором чистка 17.09.2026 потеряла 12,9 % значений. Поэтому такие слова
#: отбрасываются только целиком: как отдельное значение они в словаре есть (замер по отпечаткам
#: 20.09.2026), а внутри ФИО они безвредны.
STOPWORDS_VALUE = frozenset(
    {
        "продажи",
        "гость",
        "запись",
        "менеджер",
        "сотрудник",
        "фотограф",
        "бухгалтер",
        "занятия",
        "сауна",
        "тест",
        "тестовый",
        "новый",
        "без имени",
        "имени",
        "без",
        "по",
        "неизвестно",
        "неизвестный",
    }
)

# START_BLOCK_SCAN_NAMES
SURNAME_SHAPE = (
    r"[А-ЯЁ][а-яё]{1,}(?:"
    r"ский|ская|ского|скому|ским|ской|цкий|цкая|цкого|цкому|цкой|овым|иным|евой|иной|"
    r"ову|еву|ину|ова|ева|ёва|ина|ына|ого|ому|ыми|ими|ых|их|ым|ой|ая|яя|ий|ый|ов|ев|ёв|ин|ын"
    r")"
)

FULL_NAME_PATTERN = re.compile(
    r"(?<![А-Яа-яЁё])" + SURNAME_SHAPE + r"\s+[А-ЯЁ][а-яё]{2,}(?:\s+[А-ЯЁ][а-яё]{2,})?(?![А-Яа-яЁё])"
)
INITIALS_PATTERN = re.compile(
    r"(?<![А-Яа-яЁё])" + SURNAME_SHAPE + r"\s+(?:[А-ЯЁ]\.\s?){1,2}(?![А-ЯЁ]\.)"
)
UPPERCASE_PATTERN = re.compile(
    r"(?<![А-ЯЁ])[А-ЯЁ]{3,}\s+[А-ЯЁ]{2,}(?:\s+[А-ЯЁ]{3,})?(?![А-ЯЁ])"
)


class NameDetector:
    """Dictionary plus heuristic person-name detector.

    # START_CONTRACT: NameDetector
    #   PURPOSE: Produce class P matches for a text block.
    #   INPUTS: { dictionary: Any | None - source of known names }
    #   OUTPUTS: { NameDetector - ready detector }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT, M-TOKENIZER, V-M-DETECT-NAME
    # END_CONTRACT: NameDetector
    """

    def __init__(self, dictionary: Any | None = None, name_layer: Any | None = None) -> None:
        self._dictionary: Any | None = None
        self._layer: Any | None = None
        # Идентичность значения (M-NAME-IDENTITY): код присваивается персоне, а не падежной
        # форме. Резолвер держит индекс форм клиентского слоя и основу открытого списка.
        self._identity = NameIdentity()
        # Счётчик остановленных замен на неподтверждённых кандидатах (Phase-9 шаг 1):
        # замеряется числом, значений клиентов не печатает.
        self._evidence_rejected = 0
        self.register_name_layer(name_layer)
        self.register_dictionary(dictionary)

    def register_name_layer(self, name_layer: Any | None) -> None:
        """Bind the open recognition layer (Phase-10).

        # START_CONTRACT: register_name_layer
        #   PURPOSE: Recognise ordinary Russian names from open data, without a client value.
        #   INPUTS: { name_layer: Any | None - object with contains(value, cls) }
        #   OUTPUTS: { None }
        #   SIDE_EFFECTS: replaces the internal layer reference and drops the base-form cache
        #   LINKS: M-NAME-LAYER, M-NAME-IDENTITY, V-M-NAME-LAYER, M-DETECT-NAME
        # END_CONTRACT: register_name_layer
        """
        self._layer = name_layer
        self._identity.set_layer(name_layer)

    def register_dictionary(self, dictionary: Any | None) -> None:
        """Bind a dictionary source providing known person names.

        # START_CONTRACT: register_dictionary
        #   PURPOSE: Let the detector reuse the exact dictionary from M-DICT and build the client form index (M-NAME-IDENTITY).
        #   INPUTS: { dictionary: Any | None - object with values_for(cls) or a mapping }
        #   OUTPUTS: { None }
        #   SIDE_EFFECTS: replaces internal dictionary reference, builds the client form index once
        #   LINKS: M-DICT, M-NAME-IDENTITY, V-M-DICT, V-M-NAME-IDENTITY
        # END_CONTRACT: register_dictionary

        Индекс форм строится здесь, а не на пути запроса: значений тысячи, генерация дёшева,
        но платить за неё первой же реплике агента незачем.
        """
        self._dictionary = _KnownValues(dictionary) if dictionary is not None else None
        self._identity.set_client_values(self._client_values())
        # Словарь продакшен-вида (schema 3) умеет назвать персону отпечатком: без этой привязки
        # падежные формы на хешированном справочнике снова получали бы разные коды (Phase-8).
        self._identity.set_dictionary(dictionary)
        self._identity.warm()

    def _client_values(self) -> list[str]:
        """Вернуть значения клиентского слоя для индекса форм (или пустой список).

        Хешированный словарь читаемых значений не отдаёт (`values_for` возвращает пустой
        список): тогда индекс форм пуст, и разрешение опирается на открытый список. Это
        ограничение продукта, а не ошибка вызова: закрывается формо-дигестами в выгрузке
        (Phase-8).
        """
        source = self._dictionary
        if source is None:
            return []
        try:
            return [str(value) for value in source.values_for(CLASS_NAME) if str(value or "").strip()]
        except Exception:  # noqa: BLE001 - битый словарь не должен останавливать распознавание
            return []

    def identity_for(self, value: str) -> str | None:
        """Вернуть идентичность значения, подтверждённого справочником, или None.

        # START_CONTRACT: identity_for
        #   PURPOSE: Дать пути «значение под известным ключом ПД» ту же персону, что у распознавания текста.
        #   INPUTS: { value: str - значение из поля }
        #   OUTPUTS: { str | None - ключ идентичности, только когда значение подтверждено справочником }
        #   SIDE_EFFECTS: читает открытый список и индекс форм клиентского слоя
        #   LINKS: M-TOKENIZER, M-NAME-IDENTITY, V-M-NAME-IDENTITY
        # END_CONTRACT: identity_for

        None у неподтверждённого значения: тогда вызывающий оставляет прежний ключ
        (нормализованное написание), и поведение не меняется незаметно.
        """
        identity = self._identity.resolve(value)
        if identity.source in (
            SOURCE_CLIENT_EXACT,
            SOURCE_CLIENT_FORM,
            SOURCE_CLIENT_DIGEST,
            SOURCE_LAYER_BASE,
        ):
            return identity.value
        return None

    def identity_matches(self, cls: str, value: str, identity: str) -> bool:
        """Сказать, принадлежит ли написание идентичности значения (в том числе отпечатку).

        # START_CONTRACT: identity_matches
        #   PURPOSE: Дать токенизатору одно правило сравнения на переходе schema 2 → 3.
        #   INPUTS: { cls: str - класс ПД, value: str - написание, identity: str - ключ идентичности }
        #   OUTPUTS: { bool - True, когда это одна и та же персона }
        #   SIDE_EFFECTS: читает словарь
        #   LINKS: M-NAME-IDENTITY, M-TOKENIZER, M-DICT
        # END_CONTRACT: identity_matches
        """
        return self._identity.identity_matches(cls, value, identity)

    def identity_counters(self) -> dict[str, int]:
        """Вернуть счётчики источников идентичности для замеров и healthz — без значений.

        # START_CONTRACT: identity_counters
        #   PURPOSE: Показать, откуда взялись идентичности, числами: замер не должен печатать значения клиентов.
        #   INPUTS: none
        #   OUTPUTS: { dict[str, int] - счётчики по источникам и индексу форм }
        #   SIDE_EFFECTS: none
        #   LINKS: M-METRICS, M-NAME-IDENTITY, V-M-NAME-IDENTITY
        # END_CONTRACT: identity_counters
        """
        return self._identity.counters()

    def known_names(self) -> list[str]:
        """Return the known person names from the bound dictionary."""
        source = self._dictionary
        if not source:
            return []
        return [str(value) for value in source.values_for(CLASS_NAME)]

    def detect_names(self, text: str) -> list[PiiMatch]:
        """Return person-name spans for a text block.

        # START_CONTRACT: detect_names
        #   PURPOSE: Detect names by dictionary and shape, filtered against stopwords.
        #   INPUTS: { text: str - block to scan }
        #   OUTPUTS: { list[PiiMatch] - class P matches }
        #   SIDE_EFFECTS: none
        #   LINKS: M-TOKENIZER, M-DICT, V-M-DETECT-NAME
        # END_CONTRACT: detect_names

        Dictionary matching goes through *candidate extraction* rather than one
        regex per known name: the export can hold tens of thousands of clients,
        and scanning them individually per block would make every request crawl.
        Instead every capitalized word run in the text is normalized and checked
        against the dictionary index, which is O(candidates).
        """
        if not text:
            return []
        matches: list[PiiMatch] = []

        dictionary = self._dictionary
        layer = self._layer
        if dictionary is not None or layer is not None:
            for start, end in _name_candidates(text):
                candidate = text[start:end]
                value = self._safe_name(candidate)
                if value is None:
                    continue
                # Стоп-лист своей лексики проверяется ДО разрешения идентичности: он не зависит
                # ни от словарей, ни от контекста, а разрешение формы стоит времени. Замер
                # 26.09.2026: в блоке системного промпта 322 ложных кандидата платили за переход
                # к словарю на каждом запросе, и ни один из них не мог стать находкой.
                if not _own_lexicon_ok(value):
                    continue
                # Идентичность разрешается по значению, а не по написанию (M-NAME-IDENTITY):
                # «Иванова» и «Иванов» — одна персона, код у них один.
                identity = self._identity.resolve(candidate)
                exact_hit = dictionary is not None and dictionary.lookup(value, CLASS_NAME) is not None
                readable_form_hit = identity.source in (
                    SOURCE_CLIENT_EXACT,
                    SOURCE_CLIENT_FORM,
                )
                known = bool(exact_hit or readable_form_hit)
                # Подтверждение справочником отменяет проверку формы слова, но только когда
                # слово пришло из открытого списка: словарь клиентов намеренно засорён
                # обычными словами («Квартальный», «Карта», «Для»), и снятие морфологического
                # заслона для него вернуло бы ложные замены (находка тестов 19.09.2026,
                # tests/test_false_positives.py).
                layer_confirmed = False
                # Регистр берём из текста, а не из нормализованного значения: нормализация
                # приводит к нижнему регистру, а строчные кандидаты принимаются только по
                # точному совпадению со словарём клиентских значений.
                capitalized = bool(candidate[:1].isupper())
                if known and not capitalized:
                    # Строчное слово-значение («солнце») может оказаться обычным словом в
                    # тексте: принимаем его только рядом с признаками работы с данными.
                    known = _in_client_context(text, start, end)
                if not known and capitalized:
                    known = self._layer_knows_in_context(text, start, end, value)
                    layer_confirmed = known
                if not known and capitalized and identity.source == SOURCE_CLIENT_DIGEST:
                    # Падежная форма значения клиента, найденная по формо-дигесту выгрузки
                    # (Phase-8). Подтверждение словарём есть и оно сильнее проверки формы,
                    # но признаки работы с данными обязательны: обычное слово может совпасть
                    # со склонением значения клиента («рекламы» — и форма фамилии, и слово в
                    # тексте). Замер 19.09.2026 на боевом справочнике schema 3: без этого
                    # условия три чистых текста из семнадцати превращались в коды.
                    known = _in_client_context(text, start, end)
                    # layer_confirmed здесь НЕ ставится: подтвердил контекст, а не именной
                    # справочник. Иначе заслон «морфология читает обычное слово» ниже снова
                    # отключается, и служебное слово, оказавшееся падежной формой записи из
                    # грязной карточки, снова становится персоной. Замер 26.09.2026: так
                    # «Персональные» давало 161 ложную находку в одном блоке системного промпта
                    # (служебная запись «Персональный» в поле ФИО карточки дала формо-дигест),
                    # а «ФИО» рядом служило тем самым признаком клиентских данных.
                if not known and capitalized and identity.source == SOURCE_LAYER_BASE:
                    # Склонённая форма: написание в списке не лежит, а его основа — лежит.
                    # Условие то же, что у прямого попадания: рядом должны быть признаки
                    # работы с данными, иначе обычный текст снова начнёт заменяться.
                    known = _in_client_context(text, start, end)
                    layer_confirmed = known
                if not known and capitalized:
                    known = self._translit_knows(value)
                if not known:
                    continue
                # Значение подтверждено словарём, но морфология знает это слово как обычное —
                # а открытый список фамилией его не считает. Так выглядят засорённые карточки
                # («ПРОДАЖИ», «ГОСТЬ», «ЗАПИСЬ» лежат в боевом справочнике как значения класса
                # персон), и персоной такое слово не становится, хотя подтверждение словарём
                # сильнее проверки формы. Редкая фамилия («Токенец», «Скрытница») морфологии
                # неизвестна вовсе, а фамилия-омоним («Грач», «Камыш») есть в открытом списке —
                # обе проходят. Замер 19.09.2026: без этого условия чистый корпус прибора дал
                # шесть ложных замен на боевом справочнике.
                #
                # Заслон держит и падежные формы по формо-дигестам выгрузки: «Персональные»
                # читается морфологией как обычное слово и открытым списком не подтверждается,
                # поэтому находкой не становится (замер 26.09.2026).
                if (
                    identity.source
                    in (SOURCE_CLIENT_EXACT, SOURCE_CLIENT_FORM, SOURCE_CLIENT_DIGEST)
                    and not layer_confirmed
                    and len(value.split()) == 1
                    and _morphology_reads_common_word(value)
                    and not self._layer_knows_value(value)
                ):
                    continue
                # Значение из открытого списка уже подтверждено справочником и клиентским
                # контекстом — форма в этом случае не судья (решение владельца 18.09.2026:
                # подтверждают справочники, форма только помогает). Иначе редкие фамилии
                # выбрасывались: «Токенец» не проходит морфологию и терялся.
                #
                # Граница слова при этом действует ВСЕГДА, на всех ветвях: подтверждение снимает
                # только проверку формы. Раньше подтверждение открытым списком снимало заслон
                # целиком, и «Клиент» рядом с телефоном становился классом P (находка 19.09.2026,
                # боевой прибор: false_replacements 2). Стоп-лист своей лексики проверен выше —
                # до разрешения идентичности — и здесь его повторять нечего.
                if not _boundary_ok(text, start, end):
                    continue
                if not layer_confirmed and not is_person_name(value):
                    continue
                matches.append(
                    PiiMatch(start, end, CLASS_NAME, candidate, value, identity=identity.value)
                )

        for pattern in (FULL_NAME_PATTERN, INITIALS_PATTERN, UPPERCASE_PATTERN):
            for found in pattern.finditer(text):
                raw = found.group(0).strip()
                value = self._safe_name(raw)
                if value is None:
                    continue
                words = value.split()
                if is_own_lexicon_value(value) or any(is_own_lexicon_word(word) for word in words):
                    continue
                # Phase-9 шаг 1: заглавные обороты — единственный шаблон, который принимает
                # значение по ОДНОМУ признаку. ФИО-шаблоны уже несут продуктивное фамильное
                # окончание и имя рядом, поэтому их правило не касается: у «Скрытниных Пётр»
                # окончание «-ых» — форма, а не образец, и лишняя строгость теряла бы находку.
                if pattern is UPPERCASE_PATTERN and not self._shape_admission_ok(value):
                    self._evidence_rejected += 1
                    logger.debug(
                        "%s отклонён неподтверждённый заглавный оборот: %d слов, признаков %d",
                        LOG_MARKER,
                        len(words),
                        len(name_features(value)),
                    )
                    continue
                matches.append(
                    PiiMatch(
                        found.start(),
                        found.start() + len(raw),
                        CLASS_NAME,
                        raw,
                        value,
                        identity=self._identity.resolve(raw).value,
                    )
                )

        return merge_matches(
            [match for match in matches if not _in_address_context(text, match.start)]
        )

    def _layer_knows_value(self, value: str) -> bool:
        """Сказать, есть ли написание в открытом списке — без проверки контекста.

        # START_CONTRACT: _layer_knows_value
        #   PURPOSE: Отличить фамилию-омоним («Грач», «Камыш») от обычного слова из засорённой карточки.
        #   INPUTS: { value: str - нормализованное значение-кандидат }
        #   OUTPUTS: { bool - True, если список знает написание или его основу }
        #   SIDE_EFFECTS: читает открытый список и таблицы склонений (кэшируются)
        #   LINKS: M-NAME-LAYER, M-NAME-IDENTITY, M-DETECT-NAME
        # END_CONTRACT: _layer_knows_value
        """
        layer = self._layer
        if layer is None or len(value.split()) != 1:
            return False
        try:
            if layer.contains(value, CLASS_NAME):
                return True
        except Exception:  # noqa: BLE001 - битый список не должен закрывать заслон
            return False
        return self._identity.layer_base(value) is not None

    def _layer_knows_stem(self, value: str) -> bool:
        """Return True when a base of the candidate is in the open list.

        # START_CONTRACT: _layer_knows_stem
        #   PURPOSE: Найти склонённую фамилию: у «Терёхиной» основа «терехин» есть в списке, и она заново порождает это написание.
        #   INPUTS: { value: str - значение-кандидат }
        #   OUTPUTS: { bool - True, если ровно одна основа списка порождает это написание }
        #   SIDE_EFFECTS: читает открытый список и таблицы склонений (кэшируются)
        #   LINKS: M-DETECT-NAME, M-NAME-IDENTITY, V-M-DETECT-NAME
        #
        # Разрешение основы живёт в M-NAME-IDENTITY: детектор и присвоение кода обязаны
        # понимать «одна персона» одинаково, а два разных обратных хода расходятся.
        # END_CONTRACT: _layer_knows_stem
        """
        return self._identity.layer_base(value) is not None

    def _layer_knows_in_context(self, text: str, start: int, end: int, value: str) -> bool:
        """Return True when the open layer knows the value AND the context is client data.

        # START_CONTRACT: _layer_knows_in_context
        #   PURPOSE: Cover rare surnames from open lists without breaking ordinary text.
        #   INPUTS: { text: str, start/end: int - candidate span, value: str - normalized candidate }
        #   OUTPUTS: { bool - True when the layer knows it and the context is data-like }
        #   SIDE_EFFECTS: none
        #   LINKS: M-NAME-LAYER, V-M-NAME-LAYER
        # END_CONTRACT: _layer_knows_in_context

        The open list holds real surnames that are ordinary words too — «Камыш», «Грач» — so
        an unconditional layer hit mutilates normal prose (measured 17.09.2026: three false
        positives in a 23-phrase corpus). Requiring a client-data marker nearby keeps both
        properties: rare surnames in client lists are anonymized, «Камыш и солнце» is not.
        """
        layer = self._layer
        if layer is None or len(value.split()) != 1:
            return False
        try:
            if not layer.contains(value, CLASS_NAME):
                return False
        except Exception:  # noqa: BLE001 - a broken layer must not stop detection
            return False
        return _in_client_context(text, start, end)

    def _translit_knows(self, value: str) -> bool:
        """Return True when a Latin name maps onto a known Cyrillic name.

        # START_CONTRACT: _translit_knows
        #   PURPOSE: Anonymize clients written in Latin without storing a single Latin value.
        #   INPUTS: { value: str - normalized candidate }
        #   OUTPUTS: { bool - True when some Cyrillic variant is a known name }
        #   SIDE_EFFECTS: calls the layer and dictionary lookups
        #   LINKS: M-TRANSLIT, V-M-TRANSLIT, M-NAME-LAYER
        # END_CONTRACT: _translit_knows

        Measured 17.09.2026: 16.5% of clients are written in Latin and the open Cyrillic
        lists hold almost no Latin surnames, so after the layer was wired in these were
        28 of the 47 remaining misses. Rules close the gap: «Terekhina» is tried as
        «терехина/терехина/…» against the lists we already have.
        """
        if len(value.split()) != 1:
            return False
        if not re.fullmatch(r"[a-z][a-z'\-]{2,23}", value):
            return False

        def probe(candidate: str) -> bool:
            if self._layer is not None and self._layer.contains(candidate, CLASS_NAME):
                return True
            return bool(
                self._dictionary is not None
                and self._dictionary.lookup(candidate, CLASS_NAME) is not None
            )

        try:
            return matches_known_name(value, probe)
        except Exception:  # noqa: BLE001 - transliteration trouble must not stop detection
            return False

    def evidence_counters(self) -> dict[str, int]:
        """Вернуть счётчики заслона на неподтверждённых кандидатах — числами, без значений.

        # START_CONTRACT: evidence_counters
        #   PURPOSE: Показать замером, сколько замен остановила проверка признаков.
        #   INPUTS: none
        #   OUTPUTS: { dict[str, int] - счётчики заслона }
        #   SIDE_EFFECTS: none
        #   LINKS: M-DETECT-NAME, M-METRICS, V-M-DETECT-NAME
        # END_CONTRACT: evidence_counters
        """
        return {"rejected_unconfirmed": self._evidence_rejected}

    def _value_is_confirmed(self, value: str) -> bool:
        """Сказать, подтверждено ли значение хоть одним справочником.

        # START_CONTRACT: _value_is_confirmed
        #   PURPOSE: Держать правило «подтверждение словарём сильнее проверки формы» на уровне кода.
        #   INPUTS: { value: str - значение-кандидат }
        #   OUTPUTS: { bool - True, если значение подтверждено клиентским словарём, открытым списком или его основой }
        #   SIDE_EFFECTS: читает клиентский словарь, открытый список, морфологию и таблицы склонений
        #   LINKS: M-DICT, M-NAME-LAYER, M-NAME-IDENTITY, V-M-DETECT-NAME
        # END_CONTRACT: _value_is_confirmed

        Одно слово: подтверждение справочником снимает проверку формы, как и было решено
        владельцем 18.09.2026.

        Значение из нескольких слов: фразу подтверждает слово, которое справочник знает И
        которое морфология не читает обычным словом. Иначе «ОПЛАТА ТОПОЛЬ» становится ФИО
        оттого, что «тополь» лежит в списке фамилий (измерено 19.09.2026 — вторая из двух
        ложных замен боевого прибора), а «Клиент Ивановой» — оттого, что «клиент» там же.
        При этом правило не теряет того, ради чего подтверждение вводилось: редкая фамилия
        из открытого списка («Тесля», «Скрытниц») морфологии не известна вовсе, а значит
        обычным словом не читается и фразу подтверждает — ровно так же, как раньше.
        """
        words = [word.strip().lower() for word in value.split()]
        words = [word for word in words if word]
        if not words:
            return False
        if len(words) == 1:
            return self._word_is_confirmed(words[0])
        return any(self._word_confirms_phrase(word) for word in words)

    def _word_confirms_phrase(self, probe: str) -> bool:
        """Сказать, может ли слово подтвердить целую фразу.

        # START_CONTRACT: _word_confirms_phrase
        #   PURPOSE: Отделить фамилию из списка от обычного слова, случайно попавшего в список.
        #   INPUTS: { probe: str - слово в нижнем регистре }
        #   OUTPUTS: { bool - True, если справочник знает слово, а морфология не знает его как обычное }
        #   SIDE_EFFECTS: читает клиентский словарь, открытый список и морфологию (кэшируется)
        #   LINKS: M-DICT, M-NAME-LAYER, V-M-DETECT-NAME
        # END_CONTRACT: _word_confirms_phrase
        """
        if not self._word_is_confirmed(probe):
            return False
        return not _morphology_reads_common_word(probe)

    def _word_is_confirmed(self, probe: str) -> bool:
        """Сказать, подтверждено ли одно слово справочником (словарём, списком или основой).

        # START_CONTRACT: _word_is_confirmed
        #   PURPOSE: Дать подтверждению фразы ту же проверку одного слова, что была раньше.
        #   INPUTS: { probe: str - слово в нижнем регистре }
        #   OUTPUTS: { bool - True, если слово подтверждено }
        #   SIDE_EFFECTS: читает клиентский словарь, открытый список и таблицы склонений
        #   LINKS: M-DICT, M-NAME-LAYER, M-NAME-IDENTITY, V-M-DETECT-NAME
        # END_CONTRACT: _word_is_confirmed
        """
        if not probe:
            return False
        if (
            self._dictionary is not None
            and self._dictionary.lookup(probe, CLASS_NAME) is not None
        ):
            return True
        # Склонённая форма клиентского значения — тоже подтверждение: «Ивановой» под
        # своим кодом в справочнике уже стоит.
        if self._identity.resolve(probe).source in (SOURCE_CLIENT_EXACT, SOURCE_CLIENT_FORM):
            return True
        layer = self._layer
        if layer is not None:
            try:
                if layer.contains(probe, CLASS_NAME):
                    return True
            except Exception:  # noqa: BLE001 - битый список не должен закрывать заслон
                pass
            if self._identity.layer_base(probe) is not None:
                return True
        return False

    def _shape_admission_ok(self, value: str) -> bool:
        """Сказать, можно ли принять значение, пришедшее только из формы записи.

        # START_CONTRACT: _shape_admission_ok
        #   PURPOSE: Требовать два-три независимых признака там, где справочники молчат.
        #   INPUTS: { value: str - значение, найденное по форме }
        #   OUTPUTS: { bool - True, если значение подтверждено справочником или несёт два признака }
        #   SIDE_EFFECTS: читает словарь, открытый список и морфологию (всё кэшируется)
        #   LINKS: M-DETECT-NAME, M-DICT, M-NAME-LAYER, V-M-DETECT-NAME
        # END_CONTRACT: _shape_admission_ok

        Порядок проверок и есть политика: сначала справочник, и только потом форма. Так
        редкая фамилия из открытого списка («Скрытница», «Скрытниц») остаётся находкой, даже когда
        ни морфология, ни продуктивное окончание её не узнают, — именно на этом один раз
        уже был регресс (замер 19.09.2026: требование двух признаков без права словаря
        отбрасывало 12,3% значений открытого списка).
        """
        if self._value_is_confirmed(value):
            return True
        return unconfirmed_name_is_strong(value)

    def dictionary_signature(self) -> str | None:
        """Return the dictionary signature (path, mtime, size), or None when unavailable.

        # START_CONTRACT: dictionary_signature
        #   PURPOSE: Let the tokenizer and the validator notice that the dictionary was reloaded or replaced.
        #   INPUTS: { none }
        #   OUTPUTS: { str | None - подпись «путь|время правки|размер» или None, когда справочник её не отдаёт }
        #   SIDE_EFFECTS: один os.stat по файлу справочника, без чтения файла
        #   LINKS: M-DICT, M-CACHE, M-VALIDATOR
        # END_CONTRACT: dictionary_signature

        Подпись берётся у обёртки справочника: она пробрасывает `path` и `file_signature()`
        наружу (см. `_KnownValues`), поэтому «мёртвый» путь с вечным None больше не
        воспроизводится. Путь входит в подпись наравне с состоянием файла.
        """
        return dictionary_signature(self._dictionary)

    def lookup_known(self, value: str, cls: str) -> bool:
        """Return True when the client dictionary holds this value in the given class.

        # START_CONTRACT: lookup_known
        #   PURPOSE: Let the rule layer ask the dictionary about numbers and documents.
        #   INPUTS: { value: str, cls: str }
        #   OUTPUTS: { bool }
        #   SIDE_EFFECTS: none
        #   LINKS: M-DICT, M-DETECT-RULES
        # END_CONTRACT: lookup_known
        """
        dictionary = self._dictionary
        if dictionary is None or not value:
            return False
        try:
            return dictionary.lookup(value.strip().lower(), cls) is not None
        except Exception:  # noqa: BLE001 - a broken dictionary must not stop detection
            return False

    @staticmethod
    def _safe_name(raw: str) -> str | None:
        try:
            return normalize(CLASS_NAME, raw)
        except NormalizeError:
            return None

    @staticmethod
    def _standalone_name(text: str, start: int, end: int, value: str) -> bool:
        """Say whether a dictionary hit is really a person's name in this text.

        # START_CONTRACT: _standalone_name
        #   PURPOSE: Keep dictionary coverage from mutilating ordinary text and from making the validator disagree with the tokenizer.
        #   INPUTS: { text: str - scanned block, start/end: int - hit span, value: str - normalized hit }
        #   OUTPUTS: { bool - True when the hit may be replaced }
        #   SIDE_EFFECTS: loads the morphology analyser lazily on first use
        #   LINKS: M-DETECT-NAME, V-M-DETECT-NAME
        # END_CONTRACT: _standalone_name

        Measured on the live agent payload (16.09.2026): the export holds every
        distinct client value and, alongside real surnames, common words —
        «Для», «Карта», «Клиент», «Клуб», «Тренер», «Сайт», «Пример». Replacing those
        turned «Для рекламы» into «zPXXXXXXX рекламы», broke «ПримерСпорт» into a token
        plus a stray fragment, and the leftover fragment then looked like residual
        personal data to the validator, which blocked the whole request. Two guards:

        1. A hit must not sit inside a longer word: «Пример» and «Спорт» inside
           «ПримерСпорт» are parts of a word, not names.
        2. A one-word hit must be plausible as a name by morphology (surname, given
           name or patronymic); a multi-word hit is a ФИО shape and passes as is.

        Собирается из трёх частей, и это не косметика: вызывающему на ветви с
        подтверждением списком нужны только первые две (`_boundary_ok` и
        `_own_lexicon_ok`), потому что подтверждение снимает ИСКЛЮЧИТЕЛЬНО проверку формы.
        Both sides of the pipeline — the tokenizer and the validator — call this, so
        they cannot disagree about what counts as a name.
        """
        return (
            _boundary_ok(text, start, end)
            and _own_lexicon_ok(value)
            and is_person_name(value)
        )
# END_BLOCK_SCAN_NAMES


def _boundary_ok(text: str, start: int, end: int) -> bool:
    """Сказать, стоит ли находка отдельным словом, а не внутри слова.

    # START_CONTRACT: _boundary_ok
    #   PURPOSE: Не дать словарю вырезать «Пример» из «ПримерСпорт» и оставить обрывок.
    #   INPUTS: { text: str - сканируемый блок, start/end: int - границы находки }
    #   OUTPUTS: { bool - True, если по краям находки нет букв }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-NAME, V-M-DETECT-NAME
    # END_CONTRACT: _boundary_ok

    Проверка действует на всех ветвях распознавания, включая подтверждение справочником:
    обрывок слова — не значение клиента ни при каком подтверждении.
    """
    if start > 0 and text[start - 1].isalpha():
        return False
    if end < len(text) and text[end].isalpha():
        return False
    return True


def is_own_lexicon_value(value: str) -> bool:
    """Сказать, является ли значение целиком нашей служебной лексикой.

    # START_CONTRACT: is_own_lexicon_value
    #   PURPOSE: Одна точка правды для правила «это служебное слово, а не значение клиента» — проверяются оба набора: бренд и служебные слова.
    #   INPUTS: { value: str - значение или слово }
    #   OUTPUTS: { bool - True, когда значение целиком в стоп-листе своей лексики }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-NAME, M-DICT-EXPORT, M-DICT-HYGIENE, V-M-DICT-HYGIENE
    # END_CONTRACT: is_own_lexicon_value

    Разделение наборов — не косметика: `STOPWORDS` проверяются ещё и словом внутри значения
    (ловит оборот «Мой Пример Спорт»), а `STOPWORDS_VALUE` — только целиком, потому что служебное
    слово из карточки может стоять внутри настоящего ФИО («Тестов Тест Тестович»).

    Третий случай — значение из одних служебных слов («Новый Неизвестно», «Гость Запись»):
    настоящим ФИО такое быть не может, а по отдельности каждое слово проверять нельзя (см. выше).
    """
    lowered = value.strip().lower()
    if lowered in STOPWORDS or lowered in STOPWORDS_VALUE or lowered in own_terms():
        return True
    words = lowered.split()
    if len(words) > 1 and all(is_own_lexicon_word(word) or word in STOPWORDS_VALUE for word in words):
        return True
    # Оборот из нескольких слов может целиком содержать настроенную фразу оператора
    # («мой <бренд>»), даже если сами слова по отдельности заслон не ловят.
    return _contains_own_phrase(lowered)


def is_own_lexicon_word(word: str) -> bool:
    """Сказать, является ли одно слово нашей собственной лексикой.

    # START_CONTRACT: is_own_lexicon_word
    #   PURPOSE: Держать служебные слова кода и настроенную лексику оператора (бренд, филиалы,
    #            тарифы, город) вне класса персон на любой ветви распознавания.
    #   INPUTS: { word: str - одно слово значения }
    #   OUTPUTS: { bool - True, если слово в общем стоп-листе или в лексике оператора }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-NAME, M-OWN-VOCABULARY, M-DICT-EXPORT, V-M-DETECT-NAME
    # END_CONTRACT: is_own_lexicon_word
    """
    lowered = word.strip().lower()
    return lowered in STOPWORDS or lowered in own_terms()


def _contains_own_phrase(lowered: str) -> bool:
    """Return True when a configured multi-word own phrase occurs inside the value."""
    for term in own_terms():
        if " " in term and term in lowered:
            return True
    return False


def _own_lexicon_ok(value: str) -> bool:
    """Сказать, не является ли значение нашей собственной лексикой.

    # START_CONTRACT: _own_lexicon_ok
    #   PURPOSE: Держать бренд, филиалы, город и служебные слова вне класса персон на любой ветви.
    #   INPUTS: { value: str - нормализованное значение находки }
    #   OUTPUTS: { bool - True, если значение не в стоп-листе }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-NAME, M-OWN-VOCABULARY, V-M-DETECT-NAME
    # END_CONTRACT: _own_lexicon_ok

    Замер 19.09.2026: подтверждение открытым списком снимало этот заслон целиком, поэтому
    «Клиент» рядом с телефоном становился классом P — стоп-лист обязан работать и там.
    """
    lowered = value.lower()
    return not (
        is_own_lexicon_value(lowered)
        or any(is_own_lexicon_word(word) for word in lowered.split())
    )


_MORPH_ANALYSER: Any = None
_MORPH_UNAVAILABLE = False
_MORPH_CACHE: dict[str, bool] = {}
#: Кэш «морфология знает это слово как обычное, а не как имя» — отдельный словарь, потому
#: что вопрос другой: `_MORPH_CACHE` отвечает «может ли это быть имя», а этот — «известно ли
#: слово словарю как не-имя» (см. `_morphology_reads_common_word`).
_MORPH_COMMON_CACHE: dict[str, bool] = {}


ADDRESS_CONTEXT = re.compile(
    r"(?:^|[\s(])(?:ул|б-р|бр|пр|просп|пер|ш|пл|наб|д|кв|оф|г)\.?\s*$",
    re.IGNORECASE,
)

# Маркер адреса. Расширено 19.09.2026: полные слова («улица», «проспект», «бульвар», «шоссе»)
# не распознавались вовсе — только сокращения, — и в клиентском контексте «улица Садовая»
# заменялась как фамилия. Замер: наши правила защищали 5 адресов из 10, NER находил 10 из 10.
ADDRESS_MARKER = re.compile(
    r"(?:^|[\s(])(?:"
    r"улица|проспект|бульвар|переулок|шоссе|площадь|набережная|проезд|тупик|аллея|микрорайон|"
    r"ул|б-р|бр|пр|просп|пер|ш|пл|наб|д|кв|оф|г"
    r")\.?\s+",
    re.IGNORECASE,
)

#: Сколько заглавных слов допускается между маркером и находкой: «пр. Заводская 19А» —
#: два слова названия улицы, и оба должны остаться адресом, а не человеком.
ADDRESS_STREET_WORDS = 2

# Маркер адреса в пределах тридцати знаков перед находкой. Расширено 17.09.2026: адрес
# «пр. Заводская 19А» состоит из нескольких слов, и предыдущая узкая проверка
# (12 знаков) видела только слово перед находкой — «Заводская» распознавалась как фамилия.
ADDRESS_WINDOW = ADDRESS_MARKER


# Признаки клиентского контекста: только то, что действительно сопровождает данные
# клиентов (список, таблица, ФИО, телефон, номер абонемента). Общие слова вроде «карта»
# или «клуб» здесь намеренно отсутствуют: они встречаются и в обычных продающих текстах,
# и тогда «годовая карта» превращалась в код (замер 17.09.2026, три ложных срабатывания).
CLIENT_CONTEXT = re.compile(
    r"(?:фио|телефон|тел\.|моб\.|выгрузк|таблиц|csv|анкет|заявк|база данных|"
    r"\d{5,}|;|\|)",
    re.IGNORECASE,
)


def _in_client_context(text: str, start: int, end: int, radius: int = 40) -> bool:
    """Return True when a client-data marker sits near the candidate.

    # START_CONTRACT: _in_client_context
    #   PURPOSE: Let open-list surnames be replaced inside client data but not in prose.
    #   INPUTS: { text: str, start/end: int - candidate span, radius: int - window }
    #   OUTPUTS: { bool - True when a marker is nearby }
    #   SIDE_EFFECTS: none
    #   LINKS: M-NAME-LAYER, V-M-NAME-LAYER
    # END_CONTRACT: _in_client_context
    """
    window = text[max(0, start - radius) : min(len(text), end + radius)]
    return bool(CLIENT_CONTEXT.search(window))


def _in_address_context(text: str, start: int) -> bool:
    """Return True when a candidate stands inside an address.

    # START_CONTRACT: _in_address_context
    #   PURPOSE: Keep street names out of the person-name class, including full-word markers.
    #   INPUTS: { text: str - scanned block, start: int - candidate offset }
    #   OUTPUTS: { bool - True when an address marker precedes the candidate }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-NAME, V-M-DETECT-NAME
    # END_CONTRACT: _in_address_context

    Находка 16.09.2026: «б-р Садовая 3а» — адрес клуба, но «Садовая» есть в словаре как
    фамилия клиента, и морфология подтверждает фамилию. Различить помогает контекст:
    после маркера адреса («ул.», «б-р», «пр.», «пер.») слово — часть адреса, а не человек.

    Расширено 19.09.2026 по замеру (адреса клубов, персональных данных нет): полные слова
    «улица», «проспект», «бульвар», «шоссе» не распознавались, и «улица Садовая» рядом с
    телефоном заменялась как фамилия — 3 ложные замены на 4 строки. Теперь после маркера
    допускается ещё до двух заглавных слов названия улицы («проспект Заводская»), но
    любое другое слово, цифра или знак между маркером и находкой закрывают правило: иначе
    улица «съедала» бы настоящую фамилию, стоящую следом.
    """
    window = text[max(0, start - 48) : start]
    last: re.Match | None = None
    for found in ADDRESS_MARKER.finditer(window):
        last = found
    if last is None:
        return False
    tail = window[last.end() :].strip()
    if not tail:
        return True
    words = tail.split()
    if len(words) > ADDRESS_STREET_WORDS:
        return False
    return all(word[:1].isupper() for word in words)


TRANSLITERATED_NAME = re.compile(r"^[A-Z][A-Za-z'\-]{3,24}$")


def looks_like_name_value(value: str) -> bool:
    """Return True when a value may be a person's name in any spelling.

    # START_CONTRACT: looks_like_name_value
    #   PURPOSE: One shared rule for «это может быть имя?» — the recognizer, the validator and the export all use it, so they cannot disagree.
    #   INPUTS: { value: str - candidate value }
    #   OUTPUTS: { bool - True when the value may be a name }
    #   SIDE_EFFECTS: lazily loads the morphology analyser
    #   LINKS: M-DETECT-NAME, M-DICT-EXPORT, V-M-DETECT-NAME, V-M-DICT-EXPORT
    # END_CONTRACT: looks_like_name_value

    Rules, and why each exists (measured 16.09.2026):

    1. Multi-word values are ФИО shapes.
    2. A single Cyrillic word counts when morphology reads it as a surname, given name
       or patronymic — that is what keeps «Для», «Карта», «Клиент» out.
    3. A Latin word in name shape («Terekhina», «Stubson») counts: 16.5% of our clients
       are written that way and morphology cannot read them at all. Excluding them
       (the first cleaning attempt did) dropped 404 real client surnames out of the
       dictionary — a leak, not a cleanup.
    4. A Cyrillic word of four or more letters counts even when morphology does not
       recognise it (rare surnames like «Токенец»). The common words that caused the
       original damage are already excluded by the stop list, so what remains is
       client data.
    """
    if not value or not value.strip():
        return False
    text = value.strip()
    if len(text.split()) > 1:
        return True
    lowered = text.lower()
    if is_own_lexicon_value(lowered):
        return False
    # Регистр здесь намеренно не проверяется: в рантайм значение приходит уже
    # нормализованным (в нижнем регистре), а заглавную букву гарантирует извлечение
    # кандидатов. Замер 16.09.2026: требование заглавной буквы отсекало 77 настоящих
    # фамилий из выборки 400 — целый класс пропусков.
    if TRANSLITERATED_NAME.match(text) or TRANSLITERATED_NAME.match(text.capitalize()):
        return True
    if _morphology_says_name(text):
        return True
    return bool(re.fullmatch(r"[А-Яа-яЁё][А-Яа-яЁё\-]{3,24}", text))


def is_person_name(value: str) -> bool:
    """Backwards-compatible alias for looks_like_name_value."""
    return looks_like_name_value(value)


def _morphology_reads_common_word(word: str) -> bool:
    """Return True when morphology knows the word as an ordinary word, not as a name.

    # START_CONTRACT: _morphology_reads_common_word
    #   PURPOSE: Не дать обычному слову (NOUN/PREP/…) подтверждать фразу от имени справочника.
    #   INPUTS: { word: str - одно слово в нижнем регистре }
    #   OUTPUTS: { bool - True, если разбор есть, тега имени нет и слово словарю морфологии известно }
    #   SIDE_EFFECTS: лениво строит анализатор; результат кэшируется по слову
    #   LINKS: M-DETECT-NAME, V-M-DETECT-NAME
    # END_CONTRACT: _morphology_reads_common_word

    Замер 19.09.2026: «тополь» лежит в открытом списке фамилий (Тополь — настоящая фамилия)
    и читается морфологией как известное неодушевлённое существительное, поэтому «ОПЛАТА ТОПОЛЬ»
    становилось классом P. Редкая фамилия («Тесля», «Скрытниц», «Скрытница») словарю морфологии
    НЕ известна вовсе — это и есть признак, по которому список подтверждает фамилию, а не
    обычное слово (поле `is_known` разбора pymorphy3).

    Слово с тегом имени обычным не считается даже при наличии такого разбора: «камыш» — и
    существительное, и фамилия, и фразу он подтвердить вправе.

    Недоступный анализатор даёт False: отсутствие зависимости не должно молча закрывать
    подтверждение (та же политика, что у `_morphology_says_name`).
    """
    lowered = word.lower()
    cached = _MORPH_COMMON_CACHE.get(lowered)
    if cached is not None:
        return cached
    analyser = _morph_analyser()
    if analyser is None:
        return False
    verdict = False
    try:
        parses = analyser.parse(lowered)
        if parses:
            tags = [str(parse.tag) for parse in parses]
            if not any("Name" in tag or "Surn" in tag or "Patr" in tag for tag in tags):
                verdict = any(bool(getattr(parse, "is_known", False)) for parse in parses)
    except Exception:  # noqa: BLE001 - сбой анализатора не отменяет подтверждение
        verdict = False
    _MORPH_COMMON_CACHE[lowered] = verdict
    return verdict


def morphology_reads_common_word(word: str) -> bool:
    """Сказать, читает ли морфология значение обычным словом, а не именем.

    # START_CONTRACT: morphology_reads_common_word
    #   PURPOSE: Дать выгрузке словаря тот же критерий, что и заслону, без второго толкования морфологии.
    #   INPUTS: { word: str - слово или значение }
    #   OUTPUTS: { bool - True, когда разбор есть, тега имени нет и слово словарю морфологии известно }
    #   SIDE_EFFECTS: ленивая загрузка анализатора, кэш по слову
    #   LINKS: M-DETECT-NAME, M-DICT-EXPORT, V-M-DICT-HYGIENE
    # END_CONTRACT: morphology_reads_common_word

    Тонкая обёртка над внутренним критерием: чистка выгрузки (Phase-16) отбрасывает обычные
    слова из поля имени тем же кодом, что и заслон, поэтому критерий не дублируется.
    """
    return _morphology_reads_common_word(word)


def own_lexicon_ok(value: str) -> bool:
    """Сказать, что значение не является нашей собственной лексикой (бренд, клубы, служебные слова).

    # START_CONTRACT: own_lexicon_ok
    #   PURPOSE: Дать внешним инструментам (выгрузка, измеритель шума, тренер словаря) тот же стоп-лист, что и рантайму, одним кодом.
    #   INPUTS: { value: str - значение или слово }
    #   OUTPUTS: { bool - True, когда значения нет в стоп-листе своей лексики }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-NAME, M-DICT-EXPORT, M-INCIDENT-TRAINER, V-M-DICT-HYGIENE
    # END_CONTRACT: own_lexicon_ok

    Публичная обёртка над внутренним критерием: измеритель шума обязан отвечать на вопрос
    «закрыто ли слово стоп-листом» **тем же кодом**, что и заслон. Второе толкование стоп-листа
    разошлось бы с первым, и замер показывал бы не то, что делает рантайм.
    """
    return _own_lexicon_ok(value)


def _morph_analyser() -> Any:
    """Вернуть морфологический анализатор или None, если он недоступен.

    # START_CONTRACT: _morph_analyser
    #   PURPOSE: Держать одну точку ленивой загрузки pymorphy3 для всех морфологических проверок.
    #   INPUTS: none
    #   OUTPUTS: { Any - анализатор или None }
    #   SIDE_EFFECTS: импортирует pymorphy3 при первом вызове
    #   LINKS: M-DETECT-NAME, V-M-DETECT-NAME
    # END_CONTRACT: _morph_analyser
    """
    global _MORPH_ANALYSER, _MORPH_UNAVAILABLE
    if _MORPH_UNAVAILABLE:
        return None
    if _MORPH_ANALYSER is None:
        try:
            import pymorphy3
        except ImportError:  # pragma: no cover - optional dependency
            _MORPH_UNAVAILABLE = True
            return None
        _MORPH_ANALYSER = pymorphy3.MorphAnalyzer()
    return _MORPH_ANALYSER


def _morphology_says_name(word: str) -> bool:
    """Return True when morphology lets the word be a person's name.

    # START_CONTRACT: _morphology_says_name
    #   PURPOSE: Tell a surname or given name from a common word that the export happens to contain.
    #   INPUTS: { word: str - single candidate word }
    #   OUTPUTS: { bool - True when a name reading exists }
    #   SIDE_EFFECTS: lazily builds the analyser; result cached per word
    #   LINKS: M-DETECT-NAME, V-M-DETECT-NAME
    # END_CONTRACT: _morphology_says_name

    Surnames, given names and patronymics carry the Name/Surn/Patr tags; prepositions
    and ordinary nouns do not («Для» is PREP, «Карта»/«Клиент»/«Клуб»/«Тренер» are plain
    nouns). When the analyser is unavailable the answer is True — a missing dependency
    must not silently stop anonymization.
    """
    cached = _MORPH_CACHE.get(word)
    if cached is not None:
        return cached
    analyser = _morph_analyser()
    if analyser is None:
        return True
    lowered = word.lower()
    verdict = False
    try:
        for parse in analyser.parse(lowered):
            tag = str(parse.tag)
            if "Name" in tag or "Surn" in tag or "Patr" in tag:
                verdict = True
                break
    except Exception:  # noqa: BLE001 - analyser trouble must not block the pipeline
        verdict = True
    _MORPH_CACHE[word] = verdict
    return verdict


# START_BLOCK_UNCONFIRMED_EVIDENCE
#: Продуктивные фамильные окончания: по ним русская фамилия опознаётся без справочника.
PRODUCTIVE_SURNAME_ENDINGS: tuple[str, ...] = (
    "ов", "ев", "ёв", "ин", "ын", "ский", "ская", "цкий", "цкая", "енко", "ук", "юк", "ян",
)
# Падежных окончаний здесь намеренно нет («-ой», «-ым», «-ых», «-ого»): это формы уже
# известной основы, а не признак нового значения. Склонённые написания подтверждаются
# основой открытого списка (M-NAME-IDENTITY), а не формой слова.

FEATURE_CAPITAL = "заглавная"
FEATURE_MORPHOLOGY = "тег имени"
FEATURE_ENDING = "продуктивное окончание"

#: Сколько признаков нужно значению, которое не подтверждено ни одним справочником.
FEATURES_REQUIRED = 2


def surname_is_productive(value: str) -> bool:
    """Сказать, есть ли у значения продуктивное фамильное окончание.

    # START_CONTRACT: surname_is_productive
    #   PURPOSE: Дать морфологическому заслону признак, который не зависит от pymorphy3 и не гаснет на редких фамилиях.
    #   INPUTS: { value: str - слово-кандидат }
    #   OUTPUTS: { bool - True, если слово оканчивается продуктивным фамильным образцом }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-NAME, V-M-DETECT-NAME
    # END_CONTRACT: surname_is_productive

    Порог в четыре знака отсекает служебные слова, случайно оканчивающиеся на «-ов»/«-ин»
    («нов», «ин»), — они никогда не бывают фамилией целиком.
    """
    word = (value or "").strip().lower()
    if len(word) < 4:
        return False
    return word.endswith(PRODUCTIVE_SURNAME_ENDINGS)


def name_features(value: str) -> frozenset[str]:
    """Вернуть независимые признаки имени у значения: одно слово или ФИО целиком.

    # START_CONTRACT: name_features
    #   PURPOSE: Показать, на скольких основаниях значение признано именем, а не на одном.
    #   INPUTS: { value: str - значение-кандидат }
    #   OUTPUTS: { frozenset[str] - подмножество {заглавная, тег имени, продуктивное окончание} }
    #   SIDE_EFFECTS: лениво строит морфологический анализатор
    #   LINKS: M-DETECT-NAME, V-M-DETECT-NAME, M-NAME-IDENTITY
    # END_CONTRACT: name_features

    Признаки считаются по значению целиком, а не по каждому слову: в «СКРЫТНИНЫХ ПЁТР» окончание
    «-ых» — форма, а не образец, зато «Пётр» несёт тег имени, и вдвоём с заглавными буквами
    это уже два независимых основания. Именно так редкие фамилии остаются находками.

    Когда морфологический анализатор недоступен, `_morphology_says_name` отвечает True
    (отсутствие зависимости не должно молча останавливать обезличивание) — значит признак
    «тег имени» присутствует, и заслон остаётся открытым. Это осознанный отказ в сторону
    сохранения данных, а не тихая поломка.
    """
    text = (value or "").strip()
    if not text:
        return frozenset()
    words = [word for word in text.split() if word]
    if not words:
        return frozenset()
    letters = [word for word in words if word[:1].isalpha()]
    features: set[str] = set()
    if letters and all(word[:1].isupper() for word in letters):
        features.add(FEATURE_CAPITAL)
    if any(_morphology_says_name(word) for word in words):
        features.add(FEATURE_MORPHOLOGY)
    if any(surname_is_productive(word) for word in words):
        features.add(FEATURE_ENDING)
    return frozenset(features)


def unconfirmed_name_is_strong(value: str) -> bool:
    """Сказать, хватает ли признаков значению, которое не подтвердил ни один справочник.

    # START_CONTRACT: unconfirmed_name_is_strong
    #   PURPOSE: Остановить замену там, где значение держится на одном слабом признаке — заглавной букве.
    #   INPUTS: { value: str - значение-кандидат }
    #   OUTPUTS: { bool - True, если признаков не меньше FEATURES_REQUIRED }
    #   SIDE_EFFECTS: лениво строит морфологический анализатор
    #   LINKS: M-DETECT-NAME, V-M-DETECT-NAME
    # END_CONTRACT: unconfirmed_name_is_strong

    Замер 19.09.2026 на зафиксированном корпусе: шаблон «два слова заглавными» принимал за ФИО
    шесть деловых оборотов («ВЫРУЧКА ПРОДАЖИ», «ОПЛАТА ТОПОЛЬ», «РАСПИСАНИЕ ЗАНЯТИЕ», «БАЛАНС
    ГОСТЬ», «НОВОСТИ КОМПАНИИ», «ТРЕНИРОВКА ЗАПИСЬ») по одной лишь заглавной букве — 12 ложных
    замен. Здесь же положительный контроль: «ИВАНОВ ИВАН» несёт заглавные буквы и тег имени,
    «БЕРЁЗОВ ПЁТР» — ещё и продуктивное окончание.

    Эта проверка — ПОМОЩНИК, а не судья: она применяется только там, где справочник молчит.
    Подтверждение словарём сильнее проверки формы всегда (решение владельца 18.09.2026).
    """
    return len(name_features(value)) >= FEATURES_REQUIRED
# END_BLOCK_UNCONFIRMED_EVIDENCE


NAME_CANDIDATE = re.compile(
    r"(?<![А-Яа-яЁёA-Za-z])[А-ЯЁA-Z][А-Яа-яЁёA-Za-z'\-]{1,}"
    r"(?:\s+(?:[А-ЯЁA-Z][А-Яа-яЁёA-Za-z'\-]{1,}|[А-ЯЁA-Z]\.)){0,2}"
)


class _KnownValues:
    """Adapter giving one lookup interface to any dictionary source.

    # START_CONTRACT: _KnownValues
    #   PURPOSE: Accept the real M-DICT instance or a plain {class: [values]} mapping.
    #   INPUTS: { source: Any - PiiDictionary-like object or mapping }
    #   OUTPUTS: { _KnownValues - object with lookup(), values_for(), path and file_signature() }
    #   SIDE_EFFECTS: builds a normalized index lazily for plain mappings
    #   LINKS: M-DICT, V-M-DETECT-NAME, M-CACHE
    # END_CONTRACT: _KnownValues

    Обёртка не прячет подпись справочника: `path` и `file_signature()` пробрасываются к
    источнику, иначе `NameDetector.dictionary_signature()` всегда возвращал бы None, а
    кэши токенизатора и заслона молча не замечали бы смену справочника (дефект 26.09.2026).
    Обычный {class: [values]} подписи не имеет — это не ошибка: кэши просто не зависят
    от файла.
    """

    def __init__(self, source: Any) -> None:
        self._source = source
        self._index: dict[str, set[str]] | None = None

    @property
    def path(self) -> str:
        """Вернуть путь файла справочника, или пустую строку."""
        return str(getattr(self._source, "path", "") or "")

    def file_signature(self) -> tuple[float, int] | None:
        """Вернуть живое (время правки, размер) файла справочника, или None."""
        return live_file_state(self._source)

    def lookup(self, value: str, cls: str = CLASS_NAME) -> str | None:
        """Return the class of a known value, or None."""
        direct = getattr(self._source, "lookup", None)
        if callable(direct):
            return direct(value, cls)
        return cls if value in self._fallback_index().get(cls, set()) else None

    def values_for(self, cls: str = CLASS_NAME) -> list[str]:
        """Return the raw known values of one class."""
        direct = getattr(self._source, "values_for", None)
        if callable(direct):
            return list(direct(cls))
        if isinstance(self._source, Mapping):
            raw = self._source.get(cls) or self._source.get("names") or []
            return [str(value) for value in raw]
        return []

    def _fallback_index(self) -> dict[str, set[str]]:
        """Normalize a plain mapping once, on first use."""
        if self._index is None:
            index: dict[str, set[str]] = {}
            if isinstance(self._source, Mapping):
                for cls, values in self._source.items():
                    letter = str(cls).strip().upper()
                    bucket: set[str] = set()
                    for value in values if isinstance(values, (list, tuple, set)) else []:
                        try:
                            bucket.add(normalize(letter, str(value)))
                        except NormalizeError:
                            continue
                    index[letter] = bucket
            elif callable(getattr(self._source, "values_for", None)):
                # A light-weight fake that only exposes values_for() still works:
                # the index is built from whatever the source can list.
                for letter in CLASSES:
                    bucket = set()
                    for value in self._source.values_for(letter) or []:
                        try:
                            bucket.add(normalize(letter, str(value)))
                        except NormalizeError:
                            continue
                    if bucket:
                        index[letter] = bucket
            self._index = index
        return self._index


LOWERCASE_CANDIDATE = re.compile(
    r"(?<![А-Яа-яЁёA-Za-z])[а-яёa-z][а-яёa-z'\-]{3,24}(?![А-Яа-яЁёA-Za-z])"
)


def _name_candidates(text: str) -> list[tuple[int, int]]:
    """Return spans of word windows that could be a person name.

    # START_CONTRACT: _name_candidates
    #   PURPOSE: Bound dictionary matching cost by the text, not by the dictionary.
    #   INPUTS: { text: str - block to scan }
    #   OUTPUTS: { list[tuple[int, int]] - candidate spans }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT, V-M-DETECT-NAME
    # END_CONTRACT: _name_candidates

    Windows are emitted, not just the maximal capitalized run: in
    "Анкета Петруш Татьяна" the whole run is not a known name, but the inner
    window "Петруш Татьяна" is. Every window of up to three consecutive words
    inside a run is checked, which stays cheap because runs are three to five
    words long while the dictionary holds tens of thousands of entries.
    """
    spans: list[tuple[int, int]] = []
    for match in NAME_CANDIDATE.finditer(text or ""):
        words = list(_word_spans(text, match.start(), match.end()))
        for first in range(len(words)):
            for last in range(first, min(first + 3, len(words))):
                spans.append((words[first][0], words[last][1]))
    # Строчные одиночные слова: в карточках CRM имя часто записано с маленькой буквы
    # («Stubnick», «иванов»). Такие кандидаты принимаются только по точному совпадению с
    # клиентским словарём, поэтому обычный текст они не портят (см. detect_names).
    for match in LOWERCASE_CANDIDATE.finditer(text or ""):
        spans.append((match.start(), match.end()))
    return spans


def _word_spans(text: str, start: int, end: int):
    """Yield (start, end) for every word inside a slice of text."""
    index = start
    while index < end:
        if text[index].isalpha():
            word_start = index
            while index < end and (text[index].isalpha() or text[index] in "-."):
                index += 1
            yield word_start, index
        else:
            index += 1
