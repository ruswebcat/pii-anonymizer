# FILE: src/name_forms.py
# VERSION: 2.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Normalize Russian name values and generate their case forms with the algorithm taken from the MIT-licensed Petrovich library, so a declined surname in the text is found by exact comparison with a generated form.
#   SCOPE: ё to е folding, case and punctuation normalisation, segment splitting by space and hyphen, exception lists, gender filter that keeps androgynous rules in both passes, table-order rule search that skips rules which keep the case unchanged, the «keep» marker returning the word unchanged, at most five forms per gender.
#   DEPENDS: M-NAME-FORMS
#   LINKS: M-NAME-FORMS, V-M-NAME-FORMS, fn-normalize_name, fn-name_forms, fn-forms_index, fn-gender_applies, class-NameForms
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   RULES_PATH - каталог с таблицами petrovich-rules
#   MAX_FORMS - потолок форм на один род
#   GENDER_ANDROGYNOUS - признак пола у правила, действующего в обоих родах
#   fn-normalize_name - ё в е, регистр, кавычки, пробелы
#   fn-name_forms - формы значения (по известному роду или по обоим)
#   fn-forms_index - предгенерация: форма → значение
#   fn-gender_applies - правило с признаком «androgynous» действует при любом поле
#   class-NameForms - таблицы и перенос алгоритма
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v2.1.0 - Phase-14: два дефекта переноса эталона — исключение с признаком «androgynous» больше не отбрасывается в женском проходе, и модификатор «сохранить» больше не дописывает точку; невозможные формы («Бонча-Бруевич», «Бонч.-Бруевич») исчезли, настоящие склонённые формы дефисных фамилий находятся (замер: rep_rate 0,991 → 1,00).
#   PREVIOUS: v2.0.0 - Phase-12 шаг 1: алгоритм перенесён из Petrovich 2.0.1 (MIT) — порядок таблицы, пропуск непопавших падежей, отрезание по числу дефисов.
# END_CHANGE_SUMMARY

"""Case forms for Russian names (M-NAME-FORMS).

Implements M-NAME-FORMS from docs/ARCHITECTURE.md, step 1 of Phase-12.
Обоснование — docs/ARCHITECTURE.md, раздел «Уточнения по результатам ресерча».

Основа алгоритма — библиотека Petrovich (Python-порт 2.0.1, **лицензия MIT**, 15 572
байта, зависимостей нет; пакет скачан и изучен без установки). Перенесены три
решающие детали, которых не было в первой попытке и из-за которых фамилии либо не
склонялись вовсе, либо превращались в обрубок основы («Терёха» вместо «Терёхин»):

  1. правила перебираются **в порядке таблицы**, и правило пропускается, если в этом
     падеже модификация «.» — то есть если оно оставляет слово без изменений;
  2. модификация применяется так: отрезается **столько знаков, сколько дефисов в
     модификации**, и дописывается модификация без дефисов («-ой» → отрезать 1 знак,
     дописать «ой»), а не всё совпавшее окончание;
  3. исключения — это **точные слова** («дюма», «ван»), а не префиксы; сравнение идёт
     по целому сегменту, поэтому «Бонч-Бруевич» разбирается на два сегмента: «Бонч»
     остаётся как есть, «Бруевич» склоняется.

Правила и таблицы — petrovich-rules (MIT, копия в src/data/petrovich-rules вместе с
LICENSE и README). Пол в таблицах обязателен: при неизвестном поле генерируются формы
обоих родов, иначе женская «Терёхиной» не найдётся.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path

LOGGER_NAME = "NameForms"
LOG_MARKER = "[NameForms][load][BLOCK_LOAD_RULES]"

RULES_PATH = Path(__file__).resolve().parent / "data" / "petrovich-rules"
RULES_FILE = "rules.json"

KEEP = "."
DASH = "-"
SEPARATORS = (DASH, " ")
MAX_FORMS = 5                     # родительный, дательный, винительный, творительный, предложный
GENDERS = ("male", "female")

#: Признак пола у правила, которое действует в обоих родах (в таблицах — исключения-несклоняемые).
GENDER_ANDROGYNOUS = "androgynous"
CASES = (0, 1, 2, 3, 4)

_WHITESPACE = re.compile(r"\s+")
_EDGES = re.compile(r"^[\"'«»()\[\].,;:]+|[\"'«»()\[\].,;:]+$")


class NameFormsError(RuntimeError):
    """Rule tables are unusable — guessing silently is not allowed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# START_BLOCK_NORMALIZE
def normalize_name(value: str) -> str:
    """Fold a value into the comparable form.

    # START_CONTRACT: normalize_name
    #   PURPOSE: Make spellings comparable: ё to е, case, quotes, punctuation, spaces.
    #   INPUTS: { value: str - значение, как оно пришло из текста или из справочника }
    #   OUTPUTS: { str - ключ сравнения: нижний регистр, ё приведена к е }
    #   SIDE_EFFECTS: none
    #   LINKS: M-NAME-FORMS, M-DETECT-NAME, V-M-NAME-FORMS
    # END_CONTRACT: normalize_name
    """
    text = str(value or "").replace("ё", "е").replace("Ё", "Е").replace("\u00a0", " ")
    text = _EDGES.sub("", text.strip())
    return _WHITESPACE.sub(" ", text).strip().lower()
# END_BLOCK_NORMALIZE


# START_BLOCK_FORMS
class NameForms:
    """Case forms for surnames, given names and patronymics.

    # START_CONTRACT: NameForms
    #   PURPOSE: Give every value a closed set of forms to match against the text.
    #   INPUTS: { rules_path: Path | None - каталог с таблицами petrovich-rules }
    #   OUTPUTS: { NameForms - загруженные таблицы }
    #   SIDE_EFFECTS: читает файл правил один раз
    #   LINKS: M-NAME-FORMS, V-M-NAME-FORMS
    # END_CONTRACT: NameForms
    """

    def __init__(self, rules_path: Path | None = None) -> None:
        self._path = Path(rules_path) if rules_path is not None else RULES_PATH
        self._tables: dict[str, dict[str, list[dict]]] = {}
        self._loaded = False

    def load(self) -> int:
        """Load the tables and return the number of suffix rules."""
        rules_file = self._path / RULES_FILE
        if not rules_file.exists():
            raise NameFormsError("rules_missing", f"нет таблиц склонений: {rules_file}")
        try:
            raw = json.loads(rules_file.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise NameFormsError("rules_unreadable", str(exc)[:120]) from exc
        tables: dict[str, dict[str, list[dict]]] = {}
        for kind, value in raw.items():
            if isinstance(value, dict):
                tables[str(kind)] = {
                    "exceptions": list(value.get("exceptions") or []),
                    "suffixes": list(value.get("suffixes") or []),
                }
        if not tables:
            raise NameFormsError("rules_empty", "таблицы правил пусты")
        self._tables = tables
        self._loaded = True
        return sum(len(group["suffixes"]) for group in tables.values())

    @property
    def kinds(self) -> list[str]:
        """Return the value kinds covered by the tables."""
        return sorted(self._tables)

    def forms(self, value: str, kind: str = "lastname", gender: str | None = None) -> list[str]:
        """Return the case forms of a value, original spelling first.

        # START_CONTRACT: forms
        #   PURPOSE: Single entry point for detection and for export-side checks.
        #   INPUTS: { value: str, kind: str - lastname, firstname, middlename, gender: str | None }
        #   OUTPUTS: { list[str] - формы без повторов; при неизвестном поле — обоих родов }
        #   SIDE_EFFECTS: лениво загружает правила
        #   LINKS: M-DETECT-NAME, M-DICT, V-M-NAME-FORMS
        # END_CONTRACT: forms
        """
        if not self._loaded:
            self.load()
        text = _WHITESPACE.sub(" ", str(value or "").strip())
        if not text:
            return []
        # При известном роде идём только этим родом (в эталоне правило пропускается, если род
        # не совпадает). Если род неизвестен — сначала прогон без фильтра (он один применяет
        # исключения и правила без признака пола), затем прогоны по каждому роду: именно они
        # дают женские формы вроде «Терёхиной», которых у мужской основы нет.
        passes: tuple[str | None, ...]
        if gender:
            passes = (gender,)
        else:
            passes = (None,) + GENDERS
        forms: list[str] = [text]
        for one_gender in passes:
            for case in CASES:
                candidate = self._inflect(text, case, kind, one_gender)
                if candidate and candidate not in forms:
                    forms.append(candidate)
        return forms

    def stems(self, value: str, kind: str = "lastname") -> list[str]:
        """Return the value and its possible stems with the case ending removed.

        # START_CONTRACT: stems
        #   PURPOSE: Обратный ход к формам: из «Терёхиной» получить основу «Терёхин».
        #   INPUTS: { value: str - значение из текста, kind: str - вид значения }
        #   OUTPUTS: { list[str] - до шести основ, исходное написание первым }
        #   SIDE_EFFECTS: лениво загружает правила
        #   LINKS: M-DETECT-NAME, M-NAME-FORMS, V-M-DETECT-NAME
        #
        # Падежные окончания берутся из модификаций таблиц: у правила они записаны с ведущим
        # дефисом («-ой», «-у», «-ым»), значит это и есть снимаемые окончания.
        # END_CONTRACT: stems
        """
        if not self._loaded:
            self.load()
        text = _WHITESPACE.sub(" ", str(value or "").strip())
        if not text:
            return []
        table = self._tables.get(kind) or self._tables.get("lastname") or {}
        endings: set[str] = set()
        for rule in table.get("suffixes", []):
            for mod in rule.get("mods") or []:
                marker = str(mod)
                if marker != KEEP and marker.count(DASH) == 1 and len(marker) <= 5:
                    endings.add(marker.replace(DASH, ""))
        lowered = normalize_name(text)
        out = [text]
        for ending in sorted(endings, key=len, reverse=True):
            if not ending or not lowered.endswith(ending):
                continue
            if len(lowered) - len(ending) < 3:
                continue
            stem = text[: len(text) - len(ending)]
            if stem and stem not in out:
                out.append(stem)
            if len(out) >= 6:
                break
        return out

    def _inflect(self, value: str, case: int, kind: str, gender: str | None) -> str:
        """Return one case form of the whole value, segment by segment."""
        segments = [part for part in re.split(r"([-\s])", value) if part]
        restored: list[str] = []
        for segment in segments:
            if segment in SEPARATORS:
                restored.append(segment)
                continue
            restored.append(self._decline(segment, case, kind, gender))
        return "".join(restored)

    def _decline(self, word: str, case: int, kind: str, gender: str | None) -> str:
        """Return one case form of a single segment (signature of the reference algorithm)."""
        table = self._tables.get(kind) or self._tables.get("lastname") or {}
        lowered = word.lower().replace("ё", "е")
        for rule in table.get("exceptions", []):
            if not _gender_applies(rule, gender):
                continue
            if lowered in [str(item).lower() for item in rule.get("test", [])]:
                return _apply_rule(rule.get("mods") or [], word, case)
        for rule in table.get("suffixes", []):
            if not _gender_applies(rule, gender):
                continue
            for chars in rule.get("test", []):
                marker = str(chars)
                if not marker or not lowered.endswith(marker.lower()):
                    continue
                # Правило, которое в этом падеже оставляет слово как есть, не подходит —
                # в эталоне оно пропускается, и поиск продолжается по таблице.
                if _mod(rule, case) == KEEP:
                    continue
                return _apply_rule(rule.get("mods") or [], word, case)
        return word
# END_BLOCK_FORMS


def _mod(rule: Mapping, case: int) -> str:
    """Return the modification of a rule for one case, or «.» when absent."""
    mods = rule.get("mods") or []
    return str(mods[case]) if case < len(mods) else KEEP


def _gender_applies(rule: Mapping, gender: str | None) -> bool:
    """Сказать, действует ли правило в этом проходе по полу.

    # START_CONTRACT: _gender_applies
    #   PURPOSE: Держать исключения-несклоняемые в обоих родах: «Бонч», «ван», «фон», «дюма» не склоняются нигде.
    #   INPUTS: { rule: Mapping - правило таблицы, gender: str | None - пол прохода }
    #   OUTPUTS: { bool - True, когда правило применяется }
    #   SIDE_EFFECTS: none
    #   LINKS: M-NAME-FORMS, M-DICT-EXPORT, V-M-NAME-FORMS
    # END_CONTRACT: _gender_applies

    В эталоне (Petrovich 2.0.1, MIT) правило с признаком «androgynous» действует при любом поле.
    Порт отбрасывал его в женском проходе, и написание «Бонч-Бруевич» получало форму
    «Бонча-Бруевича», которой в русском языке не бывает: прибор считал её пропущенным
    вхождением, а выгрузка складывала такой отпечаток в словарь (находка 19.09.2026).
    """
    if not gender:
        return True
    rule_gender = str(rule.get("gender") or "")
    return not rule_gender or rule_gender == gender or rule_gender == GENDER_ANDROGYNOUS


def _apply_rule(mods: list, name: str, case: int) -> str:
    """Apply a modification exactly as the reference library does.

    Отрезается столько знаков, сколько дефисов в модификации, и дописывается модификация
    без дефисов: «Терёхин» + «-а» → «Терёхина», «Терёхин» + «.» → «Терёхин».
    """
    if case >= len(mods):
        return name
    mod = str(mods[case])
    if mod == KEEP:
        # «Сохранить» означает, что слово не меняется. Порт дописывал сам маркер, и формы
        # выходили с точкой («Бонч.-Бруевича»): такого написания в тексте не бывает, поэтому
        # распознавание склонённых дефисных фамилий не работало (находка 19.09.2026).
        return name
    cut = mod.count(DASH)
    stem = name[: len(name) - cut] if cut else name
    return stem + mod.replace(DASH, "")


_DEFAULT: NameForms | None = None


def stem_candidates(value: str, kind: str = "lastname") -> list[str]:
    """Return possible stems of a value using the shared tables.

    # START_CONTRACT: stem_candidates
    #   PURPOSE: Готовый вызов обратного хода без ручной загрузки таблиц.
    #   INPUTS: { value: str - значение из текста, kind: str - вид значения }
    #   OUTPUTS: { list[str] - до шести основ }
    #   SIDE_EFFECTS: держит загруженные правила в модуле
    #   LINKS: M-DETECT-NAME, M-NAME-FORMS, V-M-DETECT-NAME
    # END_CONTRACT: stem_candidates
    """
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = NameForms()
    return _DEFAULT.stems(value, kind)


def name_forms(value: str, kind: str = "lastname", gender: str | None = None) -> list[str]:
    """Return the case forms of a value using the shared tables.

    # START_CONTRACT: name_forms
    #   PURPOSE: Готовый вызов без ручной загрузки таблиц.
    #   INPUTS: { value: str, kind: str, gender: str | None }
    #   OUTPUTS: { list[str] - формы значения, исходное написание первым }
    #   SIDE_EFFECTS: держит загруженные правила в модуле
    #   LINKS: M-DETECT-NAME, V-M-NAME-FORMS
    # END_CONTRACT: name_forms
    """
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = NameForms()
    return _DEFAULT.forms(value, kind, gender)


def forms_index(values: Iterable[str], kind: str = "lastname") -> dict[str, str]:
    """Map every generated form back to its source value.

    # START_CONTRACT: forms_index
    #   PURPOSE: Предгенерация: искать в тексте готовые формы, а не угадывать словоформу.
    #   INPUTS: { values: Iterable[str] - значения справочника, kind: str - вид значения }
    #   OUTPUTS: { dict[str, str] - нормализованная форма → исходное значение }
    #   SIDE_EFFECTS: читает правила
    #   LINKS: M-DETECT-NAME, M-NAME-FORMS, V-M-NAME-FORMS
    # END_CONTRACT: forms_index
    """
    index: dict[str, str] = {}
    for value in values:
        for form in name_forms(value, kind):
            index.setdefault(normalize_name(form), value)
    return index
