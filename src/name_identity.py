# FILE: src/name_identity.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Resolve the identity of a detected name — the person behind a spelling — so an anonymization code is assigned to (class, value) instead of a case form, while the forms themselves keep serving recognition.
#   SCOPE: client-layer form index consumption, exact-value precedence, open-list base with a regeneration check, dictionary confirmation of the resolved base, ambiguity policy that never guesses, per-source counters, one shared "is this the same value" rule for assignment and restoration.
#   DEPENDS: M-NAME-FORMS, M-NAME-LAYER, M-DICT
#   LINKS: M-NAME-IDENTITY, V-M-NAME-IDENTITY, fn-resolve, fn-layer_base, fn-dictionary_anchor, fn-counters, fn-matches_identity, class-NameIdentity, class-Identity
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   SOURCES - источники идентичности в порядке разрешения
#   Identity - найденная идентичность: ключ значения, основа для именительного падежа, источник
#   fn-matches_identity - одно правило «это то же значение?» для присвоения кода и восстановления
#   class-NameIdentity - разрешение идентичности по клиентскому слою, открытому списку и написанию
#   fn-resolve - порядок разрешения: точное значение, форма значения, отпечаток выгрузки, основа списка (с подтверждением словарём), написание
#   fn-layer_base - основа открытого списка, которая заново порождает написание
#   fn-dictionary_anchor - отпечаток персоны для читаемого написания: само написание или его падеж известны словарю
#   fn-anchor_through_forms - персона, к которой справочник относит формы написания (беспадежная основа)
#   fn-client_index - предгенерация форм клиентского слоя (через M-DICT)
#   fn-counters - числа по источникам без значений клиентов
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.1.0 - Phase-14: читаемая основа подтверждается справочником — словарь знает то же написание или один из его падежей, и код берётся у персоны (12 + 1 из 40 значений набора получали второй код).
#   PREVIOUS: v1.0.0 - Phase-7 шаг 1: идентичность значения вместо падежной формы (решение владельца 18.09.2026, планка PhCons 1,0).
# END_CHANGE_SUMMARY

"""Value identity for name anonymization (M-NAME-IDENTITY).

Implements step 1 of Phase-7 from docs/ARCHITECTURE.md; the decision and the
resolution order are written in docs/ARCHITECTURE.md («Решение владельца
18.09.2026»).

Почему модуль существует: код выводится из идентичности значения, а не из
поверхностного написания. Один клиент получал до пяти кодов («Иванов», «Иванова»,
«Иванову», «Ивановым», «Иванове» — по коду на падеж), из-за чего PhCons равнялся
0,125, словарь рос в 4,6 раза, а модель считала падежи разными людьми.

Порядок разрешения (он же — политика неоднозначности, покрыт тестами):

1. **точное значение клиентского справочника важнее основы**: написание само есть в
   клиентском слое — это и есть персона;
2. **значение, из которого форма сгенерирована** — индекс `форма → значение` из
   `src/client_layer.py`; форма, которую порождают несколько значений, в индексе не
   разрешается угадыванием;
3. **основа открытого списка**, которая обязана **заново породить** эту форму:
   иначе «Иван» притянул бы к себе «Иванова». Несколько подходящих основ — не угадываем.
   Найденная основа дополнительно **подтверждается справочником**: если словарь знает то же
   написание отпечатком персоны — или знает один из её падежей, — код берётся у отпечатка:
   читаемая основа и отпечаток из выгрузки называют одну и ту же фамилию, а не двух людей
   (Phase-14);
4. **поверхностное написание** — поведение до этой правки, то есть не хуже; здесь справочник
   спрашивают тем же вопросом, что и в пункте 3, иначе беспадежная основа («Мещерин») получала
   бы свой код, а её падежи («Мещерина») — код персоны из выгрузки.

Petrovich (таблицы `petrovich-rules`) склоняет значение в нужный падеж, но не умеет
определять, какой падеж нужен в новом предложении модели. Поэтому формы нужны
распознаванию, а восстановление берёт наблюдённую форму (M-DETOKENIZER). Маркер
падежа в код не добавляется: код единообразен — это детерминированность и лучший
prompt-cache провайдера.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from src.client_layer import NAME_KINDS, build_forms_index
from src.name_forms import name_forms, normalize_name, stem_candidates
from src.normalize import NormalizeError, normalize

LOGGER_NAME = "NameIdentity"
LOG_MARKER = "[NameIdentity][resolve][BLOCK_RESOLVE_IDENTITY]"

CLASS_NAME = "P"

#: Источники идентичности в порядке разрешения. `surface` — исходное поведение.
SOURCE_CLIENT_EXACT = "client_exact"
SOURCE_CLIENT_FORM = "client_form"
SOURCE_CLIENT_DIGEST = "client_digest"
SOURCE_LAYER_BASE = "layer_base"
SOURCE_SURFACE = "surface"
SOURCES = (
    SOURCE_CLIENT_EXACT,
    SOURCE_CLIENT_FORM,
    SOURCE_CLIENT_DIGEST,
    SOURCE_LAYER_BASE,
    SOURCE_SURFACE,
)

#: Префикс идентичности, которая сама является отпечатком (schema 3: словарь хранит отпечатки
#: значений и их форм, читаемых значений нет). Такой ключ — служебный: он не выводится наружу
#: как текст при восстановлении (`is_digest_identity`), но годится как ключ кода: он один и тот
#: же у всех падежей одной персоны, что и даёт PhCons ровно 1,0.
DIGEST_IDENTITY_PREFIX = "pd:"

#: Написание с кириллицей: только такие выгрузка склоняет, поэтому только у них есть формы.
_CYRILLIC = re.compile(r"[А-Яа-яЁё]")


def is_digest_identity(identity: str | None) -> bool:
    """Сказать, является ли ключ идентичности служебным отпечатком, а не значением.

    # START_CONTRACT: is_digest_identity
    #   PURPOSE: Не выпустить отпечаток в восстановленный текст: он не значение клиента.
    #   INPUTS: { identity: str | None - ключ идентичности }
    #   OUTPUTS: { bool - True, если ключ служебный }
    #   SIDE_EFFECTS: none
    #   LINKS: M-NAME-IDENTITY, M-DETOKENIZER, M-DICT-EXPORT
    # END_CONTRACT: is_digest_identity
    """
    return bool(identity) and str(identity).startswith(DIGEST_IDENTITY_PREFIX)

#: Вид значения для склонений открытого списка: слой A держит фамилии.
LAYER_KIND = "lastname"

#: Виды, формы которых проверяются при подтверждении основы справочником: фамилия, имя,
#: отчество — те же три, что генерирует выгрузка.
LAYER_KINDS = NAME_KINDS

#: Значения короче этого не считаются основой: «Ван» или «Ия» дали бы ложные основы.
MIN_BASE_LENGTH = 4

#: Сколько знаков позволено отрезать при поиске основы: падежные окончания короче.
MAX_BASE_CUT = 7

#: Потолок размера индекса форм клиентского слоя: клиентский слой — тысячи значений,
#: а «выгрузить всё» не должно превращаться в многоминутный старт. Остаток считается.
MAX_CLIENT_VALUES = 20000


def matches_identity(cls: str, value: str, identity: str) -> bool:
    """Сказать, приводится ли написание к той же идентичности.

    # START_CONTRACT: matches_identity
    #   PURPOSE: Одно правило «это то же значение?» — им пользуются и присвоение кода, и восстановление, иначе критерии расходятся.
    #   INPUTS: { cls: str - класс ПД, value: str - написание (форма, хранимое значение), identity: str - ключ идентичности }
    #   OUTPUTS: { bool - True, когда это одна и та же персона/значение }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKENIZER, M-DETOKENIZER, M-MAP-STORE, V-M-NAME-IDENTITY
    # END_CONTRACT: matches_identity
    """
    text = (value or "").strip()
    if not text or not identity:
        return False
    if text == identity:
        return True
    if cls == CLASS_NAME:
        return normalize_name(text) == identity
    try:
        return normalize(cls, text) == identity
    except NormalizeError:
        return False


@dataclass(frozen=True)
class Identity:
    """Идентичность найденного значения.

    # START_CONTRACT: Identity
    #   PURPOSE: Отделить персону от её падежа: код выводится из value, а основа нужна для именительного падежа при восстановлении.
    #   INPUTS: { value: str - ключ идентичности (нормализованное значение основы), base: str - основа в написании справочника, source: str - источник }
    #   OUTPUTS: { Identity - значение результата }
    #   SIDE_EFFECTS: none
    #   LINKS: M-NAME-IDENTITY, M-TOKENIZER, V-M-NAME-IDENTITY
    # END_CONTRACT: Identity
    """

    value: str
    base: str
    source: str


# START_BLOCK_RESOLVE_IDENTITY
class NameIdentity:
    """Разрешение идентичности: персона, а не падежная форма.

    # START_CONTRACT: NameIdentity
    #   PURPOSE: По написанию из текста вернуть значение, которому оно принадлежит.
    #   INPUTS: { client_values: Iterable[str] | None - значения клиентского слоя, layer: Any | None - открытый список с contains(value, cls) }
    #   OUTPUTS: { NameIdentity - готовый резолвер }
    #   SIDE_EFFECTS: лениво строит индекс форм клиентского слоя и читает таблицы склонений
    #   LINKS: M-DICT, M-NAME-LAYER, M-NAME-FORMS, V-M-NAME-IDENTITY
    # END_CONTRACT: NameIdentity
    """

    def __init__(
        self,
        client_values: Iterable[str] | None = None,
        layer: Any | None = None,
    ) -> None:
        self._exact: dict[str, str] | None = None
        self._forms: dict[str, str] | None = None
        self._layer = layer
        # Словарь продакшен-вида (schema 3): хранит отпечатки значений и их форм, поэтому
        # персону он называет отпечатком, а не значением. Читаемых значений по-прежнему нет.
        self._dictionary: Any | None = None
        self._index_counters: dict[str, int] = {}
        self._base_cache: dict[str, str | None] = {}
        # Кэш отпечатков для читаемых основ: справочник отвечает на одно и то же
        # написание одинаково, а вызовов на текст много (Phase-14).
        self._anchor_cache: dict[str, str | None] = {}
        self._truncated = 0
        self._values: list[str] = []
        self.set_client_values(client_values)
        self._counters: dict[str, int] = {source: 0 for source in SOURCES}
        self._counters["ambiguous_bases"] = 0
        self._counters["layer_base_anchored"] = 0
        self._counters["surface_anchored"] = 0

    def set_dictionary(self, dictionary: Any | None) -> None:
        """Привязать словарь, который умеет называть персону отпечатком (schema 3).

        # START_CONTRACT: set_dictionary
        #   PURPOSE: Дать идентичности источник, работающий на хешированном словаре.
        #   INPUTS: { dictionary: Any | None - объект с identity_digest(value, cls) }
        #   OUTPUTS: { None }
        #   SIDE_EFFECTS: заменяет ссылку на словарь и сбрасывает кэш отпечатков
        #   LINKS: M-DICT, M-NAME-IDENTITY, V-M-NAME-IDENTITY
        # END_CONTRACT: set_dictionary

        Кэш отпечатков сбрасывается вместе со сменой словаря: после горячей перезагрузки
        выгрузки прежние ответы недействительны, а держать чужие отпечатки в памяти
        незачем.
        """
        self._dictionary = dictionary
        self._anchor_cache.clear()

    # --- источник 2: клиентский слой ---------------------------------------
    def set_client_values(self, values: Iterable[str] | None) -> None:
        """Заменить значения клиентского слоя (после перезагрузки словаря).

        Индекс строится на первых `MAX_CLIENT_VALUES` значениях: значений клиентского слоя
        тысячи, и генерация форм дешёва, но выгрузка «всё, что нашли» (сотни тысяч значений)
        не должна превращаться в многоминутный старт. Остаток считается счётчиком
        `client_truncated`, а не молчаливым пропуском.
        """
        prepared = [str(value) for value in (values or []) if str(value or "").strip()]
        self._truncated = max(0, len(prepared) - MAX_CLIENT_VALUES)
        self._values = prepared[:MAX_CLIENT_VALUES]
        self._exact = None
        self._forms = None

    def set_layer(self, layer: Any | None) -> None:
        """Заменить открытый список и сбросить кэш найденных основ."""
        self._layer = layer
        self._base_cache.clear()

    def warm(self) -> int:
        """Построить индекс форм клиентского слоя заранее и вернуть его размер.

        Вызывается при привязке словаря (M-DICT): первая реплика агента не должна платить
        за генерацию форм. При хешированном словаре значений нет — индекс пуст, и это
        ожидаемое состояние, а не ошибка.
        """
        _exact, forms = self.client_index()
        return len(forms)

    @property
    def client_size(self) -> int:
        """Число значений клиентского слоя, известных резолверу."""
        return len(self._values)

    def client_index(self) -> tuple[dict[str, str], dict[str, str]]:
        """Вернуть (точные значения, индекс форм) клиентского слоя.

        # START_CONTRACT: client_index
        #   PURPOSE: Предгенерация форм на стороне распознавания — значений тысячи, это дёшево.
        #   INPUTS: none
        #   OUTPUTS: { tuple[dict[str, str], dict[str, str]] - точные написания и формы }
        #   SIDE_EFFECTS: строит индекс один раз на состав значений
        #   LINKS: M-DICT, M-NAME-FORMS, V-M-NAME-IDENTITY
        # END_CONTRACT: client_index
        """
        if self._exact is None or self._forms is None:
            exact, forms, counters = build_forms_index(self._values)
            self._exact, self._forms, self._index_counters = exact, forms, counters
        return self._exact, self._forms

    # --- источник 3: основа открытого списка --------------------------------
    def layer_base(self, candidate: str) -> str | None:
        """Вернуть основу открытого списка, которая заново порождает это написание.

        # START_CONTRACT: layer_base
        #   PURPOSE: «Ивановой» → «Иванов», но «Иванова» не притягивается к «Иван».
        #   INPUTS: { candidate: str - написание, как оно пришло из текста }
        #   OUTPUTS: { str | None - основа в написании списка, или None при неоднозначности }
        #   SIDE_EFFECTS: читает открытый список и таблицы склонений; держит кэш по написанию
        #   LINKS: M-NAME-LAYER, M-NAME-FORMS, V-M-NAME-IDENTITY
        # END_CONTRACT: layer_base

        Основа ищется перебором **префиксов написания**, а не снятием окончаний: обратный
        ход `stem_candidates` отрезает только те окончания, что записаны в правилах через
        дефис, поэтому родительный падеж («Иванова» → «Иванов») он не берёт вовсе
        (находка 19.09.2026, тест `test_stems_skip_the_dashless_endings`). Перебор
        префиксов проверяет то же свойство, что и раньше: основа обязана **заново
        породить** написание, иначе «Иван» подошёл бы к «Иванова» и полный тёзка получал
        бы код другого человека. Если подходящих основ несколько (или ни одной) —
        идентичность не угадывается, остаётся поверхностное написание.
        """
        layer = self._layer
        text = (candidate or "").strip()
        if layer is None or not text or len(text.split()) != 1:
            return None
        if text in self._base_cache:
            return self._base_cache[text]
        key = normalize_name(text)
        # Ступень 1: префиксы, которые **заново порождают** написание (сильное свидетельство).
        found: set[str] = set()
        limit = min(len(text), MAX_BASE_CUT)
        for cut in range(1, limit):
            prefix = text[: len(text) - cut]
            prefix_key = normalize_name(prefix)
            if len(prefix_key) < MIN_BASE_LENGTH:
                break
            if not self._layer_contains(prefix, prefix_key):
                continue
            try:
                regenerated = {
                    normalize_name(form) for form in name_forms(prefix_key, LAYER_KIND)
                }
            except Exception:  # noqa: BLE001 - без таблиц проверка не проходит, и это честно
                regenerated = set()
            if key in regenerated:
                found.add(prefix_key)
        if not found:
            # Ступень 2: обратный ход таблиц — правила сами называют основу («-ой» снимается
            # с «Терёхиной»). Нужна отдельной ступенью, потому что прямого порождения женских
            # форм в таблицах нет: «Терёхин» → «Терёхиной» генератор не выдаёт, а обратный
            # ход даёт. Ступень включается только когда сильных свидетельств не нашлось.
            try:
                stems = stem_candidates(text, LAYER_KIND)
            except Exception:  # noqa: BLE001 - нет таблиц не должно ломать распознавание
                stems = []
            for stem in stems:
                stem_key = normalize_name(stem)
                if not stem_key or stem_key == key or len(stem_key) < MIN_BASE_LENGTH:
                    continue
                if self._layer_contains(stem, stem_key):
                    found.add(stem_key)
        if len(found) == 1:
            result: str | None = next(iter(found))
        else:
            if len(found) > 1:
                self._counters["ambiguous_bases"] += 1
            result = None
        self._base_cache[text] = result
        return result

    def _layer_contains(self, spelling: str, folded: str) -> bool:
        """Проверить написание в открытом списке: и сложенное («ё»→«е»), и как в списке.

        Список хранит значения как есть («терехин»), а нормализация приводит «ё» к «е» —
        без второго варианта «Терёхиной» не нашлась бы вовсе.
        """
        layer = self._layer
        if layer is None:
            return False
        try:
            return bool(
                layer.contains(folded, CLASS_NAME) or layer.contains(spelling.strip().lower(), CLASS_NAME)
            )
        except Exception:  # noqa: BLE001 - битый список не останавливает разрешение
            return False

    # --- разрешение ---------------------------------------------------------
    def resolve(self, candidate: str) -> Identity:
        """Вернуть идентичность написания по зафиксированному порядку.

        # START_CONTRACT: resolve
        #   PURPOSE: Один вход для детектора: какое значение стоит за этим написанием.
        #   INPUTS: { candidate: str - написание из текста }
        #   OUTPUTS: { Identity - ключ значения, основа, источник }
        #   SIDE_EFFECTS: увеличивает счётчики источников
        #   LINKS: M-DETECT-NAME, M-TOKENIZER, V-M-NAME-IDENTITY
        # END_CONTRACT: resolve
        """
        text = (candidate or "").strip()
        key = normalize_name(text)
        if not key:
            self._counters[SOURCE_SURFACE] += 1
            return Identity(value="", base=text, source=SOURCE_SURFACE)
        exact, forms = self.client_index()
        hit = exact.get(key)
        if hit is not None:
            self._counters[SOURCE_CLIENT_EXACT] += 1
            return Identity(value=key, base=hit, source=SOURCE_CLIENT_EXACT)
        hit = forms.get(key)
        if hit is not None:
            self._counters[SOURCE_CLIENT_FORM] += 1
            return Identity(value=normalize_name(hit) or key, base=hit, source=SOURCE_CLIENT_FORM)
        # Источник 2б: формо-дигесты выгрузки (schema 3). Работает там, где читаемых значений
        # нет вовсе: «Ивановой» и «Иванов» получают один и тот же отпечаток персоны, поэтому
        # код остаётся один во всех падежах (Phase-8). Порядок сохранён: точное значение и
        # читаемая форма проверены выше и остаются впереди.
        digest_identity = self._digest_identity(text)
        if digest_identity is not None:
            self._counters[SOURCE_CLIENT_DIGEST] += 1
            return Identity(value=digest_identity, base=text, source=SOURCE_CLIENT_DIGEST)
        base = self.layer_base(text)
        if base is not None:
            # Источник 3а: основа открытого списка, которую знает клиентский справочник
            # (Phase-14). Читаемая основа и отпечаток из выгрузки — два имени одной персоны,
            # поэтому код берётся у отпечатка: иначе в контуре с хешированным словарём
            # написание, не попавшее в блок форм, получало бы второй код (замер 19.09.2026:
            # 12 из 40 значений набора, например «Иванову» и «Иванове»).
            anchored = self._dictionary_anchor(base)
            if anchored is not None:
                self._counters["layer_base_anchored"] += 1
                return Identity(value=anchored, base=base, source=SOURCE_LAYER_BASE)
            self._counters[SOURCE_LAYER_BASE] += 1
            return Identity(value=base, base=base, source=SOURCE_LAYER_BASE)
        # Источник 4: поверхностное написание. Здесь справочник тоже спрашивают: написание
        # может оказаться беспадежной основой значения, которого в справочнике нет, — тогда
        # его падежи (найденные выгрузкой) уже получили код персоны, и основа обязана получить
        # тот же (находка 19.09.2026: «Мещерин», «Мещерина» получали разные коды).
        anchored = self._dictionary_anchor(key if len(key.split()) == 1 else "")
        if anchored is not None:
            self._counters["surface_anchored"] += 1
            return Identity(value=anchored, base=text, source=SOURCE_SURFACE)
        self._counters[SOURCE_SURFACE] += 1
        return Identity(value=key, base=text, source=SOURCE_SURFACE)

    def _dictionary_anchor(self, spelling: str) -> str | None:
        """Спросить справочник, какая персона стоит за читаемой основой.

        # START_CONTRACT: _dictionary_anchor
        #   PURPOSE: Держать один код на персону там, где основа найдена открытым списком, а словарь знает ту же фамилию — саму или её падежом.
        #   INPUTS: { spelling: str - читаемая основа значения }
        #   OUTPUTS: { str | None - служебный отпечаток персоны, или None }
        #   SIDE_EFFECTS: читает словарь и таблицы склонений; держит кэш по написанию
        #   LINKS: M-DICT, M-NAME-FORMS, M-NAME-IDENTITY, V-M-NAME-IDENTITY
        # END_CONTRACT: _dictionary_anchor

        Два вопроса, оба без догадок: (1) знает ли словарь это самое написание — «иванов» из
        открытого списка и «иванов» из карточек одна и та же фамилия; (2) если не знает, знает
        ли он какой-нибудь её падеж — тогда фамилия есть в справочнике в виде падежной записи
        («Мещерина»), и код персоны уже выдан её падежам. Несколько разных падежей, ведущих к
        разным персонам, — не угадываем, написание остаётся своей идентичностью.
        """
        text = (spelling or "").strip()
        if not text:
            return None
        if text in self._anchor_cache:
            return self._anchor_cache[text]
        anchor = self._digest_identity(text)
        if anchor is None:
            anchor = self._anchor_through_forms(text)
        self._anchor_cache[text] = anchor
        return anchor

    def _anchor_through_forms(self, spelling: str) -> str | None:
        """Найти персону, к которой справочник относит формы этого написания.

        # START_CONTRACT: _anchor_through_forms
        #   PURPOSE: Довести «код на персону» до беспадежной основы, которой в справочнике нет.
        #   INPUTS: { spelling: str - читаемое написание (одно слово, кириллица) }
        #   OUTPUTS: { str | None - отпечаток персоны, ровно один на все формы }
        #   SIDE_EFFECTS: читает таблицы склонений и словарь
        #   LINKS: M-NAME-FORMS, M-DICT, M-NAME-IDENTITY, V-M-NAME-IDENTITY
        # END_CONTRACT: _anchor_through_forms

        Латиница сразу исключена: выгрузка не склоняет латинские значения, поэтому латинское
        написание формой клиента быть не может, а генерация форм на английских словах из схем
        инструментов стоила бы времени на каждом новом написании.
        """
        if len(spelling.split()) != 1 or len(normalize_name(spelling)) < MIN_BASE_LENGTH:
            return None
        if not _CYRILLIC.search(spelling):
            return None
        found: set[str] = set()
        for kind in LAYER_KINDS:
            try:
                forms = name_forms(spelling, kind)
            except Exception:  # noqa: BLE001 - без таблиц персону не подтверждаем
                return None
            for form in forms:
                candidate = normalize_name(form)
                if not candidate or candidate == normalize_name(spelling):
                    continue
                identity = self._digest_identity(candidate)
                if identity is not None:
                    found.add(identity)
            if len(found) > 1:
                return None
        return next(iter(found)) if len(found) == 1 else None

    def _digest_identity(self, candidate: str) -> str | None:
        """Спросить словарь продакшен-вида, какая персона стоит за этим написанием.

        # START_CONTRACT: _digest_identity
        #   PURPOSE: Разрешить падежную форму на хешированном словаре, не читая значений.
        #   INPUTS: { candidate: str - написание из текста }
        #   OUTPUTS: { str | None - служебный отпечаток персоны, или None }
        #   SIDE_EFFECTS: читает словарь
        #   LINKS: M-DICT, M-DICT-EXPORT, V-M-NAME-IDENTITY
        # END_CONTRACT: _digest_identity
        """
        dictionary = self._dictionary
        if dictionary is None:
            return None
        ask = getattr(dictionary, "identity_digest", None)
        if not callable(ask):
            return None
        try:
            answer = ask(candidate, CLASS_NAME)
        except Exception:  # noqa: BLE001 - битый словарь не должен ломать распознавание
            return None
        return str(answer) if answer else None

    def identity_matches(self, cls: str, value: str, identity: str) -> bool:
        """Сказать, принадлежит ли написание этой идентичности — включая идентичность-отпечаток.

        # START_CONTRACT: identity_matches
        #   PURPOSE: Одно правило «это та же персона?» и для читаемых значений, и для отпечатков выгрузки.
        #   INPUTS: { cls: str - класс, value: str - написание (прежнее значение справочника), identity: str - ключ идентичности }
        #   OUTPUTS: { bool - True, когда это одна и та же персона }
        #   SIDE_EFFECTS: читает словарь продакшен-вида
        #   LINKS: M-DICT, M-MAP-STORE, M-TOKENIZER, V-M-NAME-IDENTITY
        # END_CONTRACT: identity_matches

        Нужен на переходе schema 2 → 3: записи, созданные прежней версией, держат значение, а
        новая идентичность — отпечаток. Без этого правила такая связка выглядела бы «занятой
        другим значением», и персона получала бы второй код.
        """
        if not is_digest_identity(identity):
            return matches_identity(cls, value, identity)
        return self._digest_identity(value) == identity

    def counters(self) -> dict[str, int]:
        """Вернуть числа по источникам и по индексу — без единого значения клиента.

        # START_CONTRACT: counters
        #   PURPOSE: Показать замеру и healthz, откуда взялись идентичности, не печатая значения.
        #   INPUTS: none
        #   OUTPUTS: { dict[str, int] - счётчики источников, индекс форм, неоднозначные основы }
        #   SIDE_EFFECTS: none
        #   LINKS: M-METRICS, V-M-NAME-IDENTITY
        # END_CONTRACT: counters
        """
        out = dict(self._counters)
        out["client_truncated"] = self._truncated
        for name, value in self._index_counters.items():
            out[f"index_{name}"] = int(value)
        return out
# END_BLOCK_RESOLVE_IDENTITY
