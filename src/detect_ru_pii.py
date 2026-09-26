# FILE: src/detect_ru_pii.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Recognize Russian personal-data identifiers by format plus control sum: СНИЛС, ИНН (10 и 12 разрядов), ОГРН, ОГРНИП, КПП, БИК, расчётный счёт, полис ОМС, водительское удостоверение, серия и номер паспорта.
#   SCOPE: Форма и контрольная сумма; там, где контрольной суммы нет — обязательное слово-признак рядом, чтобы не ловить любые цифры; отсечение обрывков длинных чисел.
#   DEPENDS: M-DETECT-RULES, M-NORM
#   LINKS: M-DETECT-RU-PII, V-M-DETECT-RU-PII, fn-detect_ru_pii, fn-snils_ok, fn-inn_ok, fn-ogrn_ok, fn-ogrnip_ok
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   CLASS_RU_DOCUMENT - класс документа РФ
#   CONTEXT_WORDS - слова-признаки, которыми подтверждается номер без контрольной суммы
#   EPOCH_GUARDED_RULES - правила, для которых метка времени не является реквизитом
#   RULES - таблица правил: имя, регулярное выражение, нужен ли контекст, проверка контрольной суммы
#   fn-snils_ok, fn-inn_ok, fn-ogrn_ok, fn-ogrnip_ok - проверки контрольных сумм
#   fn-detect_ru_pii - находки по тексту: (класс, значение, начало, конец, правило)
#   fn-iter_ru_pii - те же находки итератором
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-9 шаг 2: модуль перенесён из /tmp/ru-pii-regex и подключён к M-DETECT-RULES, то есть к общему набору находок токенизатора и заслона.
# END_CHANGE_SUMMARY

"""Российские идентификаторы персональных данных (M-DETECT-RU-PII).

Решение по ложным срабатываниям (заказчик, 18.09.2026): регулярные выражения пишем сами,
но каждое должно либо подтверждаться контрольной суммой, либо стоять рядом со словом-признаком.
Иначе «ИНН» превратится в любое 10-значное число, а страховой номер — в номер из выгрузки.

Почему контрольная сумма важнее длины: у СНИЛС, ИНН, ОГРН и ОГРНИП она есть, и она отсекает
опечатки и случайные числа почти полностью. У КПП, БИК, счёта, полиса ОМС и водительского
контрольной суммы в общем виде нет — там решает контекст.

Подключение (Phase-9 шаг 2): вызов стоит внутри ``src.detect_rules.detect_rules``, а не в
токенизаторе или заслоне по отдельности. Токенизатор и остаточный заслон обязаны видеть один
и тот же набор находок: разойдись они — заслон счёл бы остаточными ПД то, что токенизатор
осознанно не заменял, и запрос клиента упал бы с 403 (находка 18.09.2026).
"""

from __future__ import annotations

import re
from collections.abc import Iterator

LOGGER_NAME = "RuPiiDetector"
LOG_MARKER = "[RuPiiDetector][detect_ru_pii][BLOCK_SCAN_RU_PII]"

CLASS_RU_DOCUMENT = "I"

#: Слово-признак рядом с номером: без него находка не подтверждается.
CONTEXT_WORDS = (
    "паспорт", "паспорта", "паспорту", "серия", "серии", "выдан", "выдано", "выдана",
    "снилс", "страховой", "страхового", "инн", "огрн", "огрнип", "кпп", "бик",
    "счёт", "счет", "счёта", "счета", "расчётный", "расчетный", "полис", "омс",
    "удостоверение", "водительское", "выдан", "кем", "отделом", "уфмс", "мвд",
)

CONTEXT_RADIUS = 48
_DIGIT_RUN = re.compile(r"\d")

#: Диапазоны меток времени: 10-значное число внутри — это секунды Unix, а не ИНН.
#: Находка 15.09.2026 (M-DETECT-RULES): голое число из ``created_at`` читалось документом,
#: и заслон закрывал каждый запрос с выгрузкой. Здесь тот же заслон, потому что контрольные
#: разряды ИНН у метки времени иногда сходятся случайно (замер 19.09.2026: 1789502911).
EPOCH_SECONDS = (1_000_000_000, 2_300_000_000)
EPOCH_MILLIS = (1_000_000_000_000, 2_300_000_000_000)
EPOCH_GUARDED_RULES = ("инн",)


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


# START_BLOCK_CONTROL_SUMS
def snils_ok(value: str) -> bool:
    """Проверить контрольное число СНИЛС (сумма первых девяти цифр с весами, остаток по 101).

    # START_CONTRACT: snils_ok
    #   PURPOSE: Подтвердить страховой номер контрольной суммой.
    #   INPUTS: { value: str - значение с любыми разделителями }
    #   OUTPUTS: { bool - True, если контрольная сумма сходится }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-RU-PII, V-M-DETECT-RU-PII
    # END_CONTRACT: snils_ok
    """
    digits = _digits(value)
    if len(digits) != 11:
        return False
    weights = (9, 8, 7, 6, 5, 4, 3, 2, 1)
    total = sum(int(d) * w for d, w in zip(digits[:9], weights))
    control = total % 101
    if control == 100:
        control = 0
    return control == int(digits[9:])


def inn_ok(value: str) -> bool:
    """Проверить контрольные разряды ИНН из 10 и 12 цифр.

    # START_CONTRACT: inn_ok
    #   PURPOSE: Подтвердить ИНН контрольными разрядами (10 или 12 цифр).
    #   INPUTS: { value: str - значение с любыми разделителями }
    #   OUTPUTS: { bool - True, если контрольные разряды сходятся }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-RU-PII, V-M-DETECT-RU-PII
    # END_CONTRACT: inn_ok
    """
    digits = _digits(value)
    if len(digits) == 10:
        weights = (2, 4, 10, 3, 5, 9, 4, 6, 8)
        control = sum(int(d) * w for d, w in zip(digits[:9], weights)) % 11 % 10
        return control == int(digits[9])
    if len(digits) == 12:
        w1 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        w2 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        c1 = sum(int(d) * w for d, w in zip(digits[:10], w1)) % 11 % 10
        c2 = sum(int(d) * w for d, w in zip(digits[:11], w2)) % 11 % 10
        return c1 == int(digits[10]) and c2 == int(digits[11])
    return False


def ogrn_ok(value: str) -> bool:
    """Проверить контрольный разряд ОГРН (первые двенадцать цифр по модулю 11).

    # START_CONTRACT: ogrn_ok
    #   PURPOSE: Подтвердить ОГРН контрольным разрядом.
    #   INPUTS: { value: str - значение с любыми разделителями }
    #   OUTPUTS: { bool - True, если контрольный разряд сходится }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-RU-PII, V-M-DETECT-RU-PII
    # END_CONTRACT: ogrn_ok
    """
    digits = _digits(value)
    if len(digits) != 13:
        return False
    return int(digits[:12]) % 11 % 10 == int(digits[12])


def ogrnip_ok(value: str) -> bool:
    """Проверить контрольный разряд ОГРНИП (первые четырнадцать цифр по модулю 13).

    # START_CONTRACT: ogrnip_ok
    #   PURPOSE: Подтвердить ОГРНИП контрольным разрядом.
    #   INPUTS: { value: str - значение с любыми разделителями }
    #   OUTPUTS: { bool - True, если контрольный разряд сходится }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-RU-PII, V-M-DETECT-RU-PII
    # END_CONTRACT: ogrnip_ok
    """
    digits = _digits(value)
    if len(digits) != 15:
        return False
    return int(digits[:14]) % 13 % 10 == int(digits[14])
# END_BLOCK_CONTROL_SUMS


# START_BLOCK_SCAN_RU_PII
def _no_digit_neighbours(text: str, start: int, end: int) -> bool:
    """Отклонить находку, которая является обрывком более длинного числа."""
    before = text[start - 1] if start > 0 else " "
    after = text[end] if end < len(text) else " "
    return not _DIGIT_RUN.match(before) and not _DIGIT_RUN.match(after)


def _is_epoch(value: str) -> bool:
    """Сказать, является ли число меткой времени, а не реквизитом.

    # START_CONTRACT: _is_epoch
    #   PURPOSE: Не путать метку времени из выгрузки с ИНН только потому, что разряды сошлись.
    #   INPUTS: { value: str - значение с любыми разделителями }
    #   OUTPUTS: { bool - True, если число лежит в диапазоне секунд или миллисекунд Unix }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-RU-PII, M-DETECT-RULES, V-M-DETECT-RU-PII
    # END_CONTRACT: _is_epoch
    """
    digits = _digits(value)
    if not digits.isdigit():
        return False
    number = int(digits)
    if len(digits) == 10 and EPOCH_SECONDS[0] <= number <= EPOCH_SECONDS[1]:
        return True
    if len(digits) == 12 and EPOCH_MILLIS[0] <= number <= EPOCH_MILLIS[1]:
        return True
    return False


def _context_ok(text: str, start: int, end: int) -> bool:
    """Подтвердить находку словом-признаком рядом."""
    left = text[max(0, start - CONTEXT_RADIUS):start].lower()
    right = text[end:end + CONTEXT_RADIUS].lower()
    return any(word in left or word in right for word in CONTEXT_WORDS)


#: Таблица правил. Порядок важен: сначала те, у кого есть контрольная сумма и точная длина.
RULES: tuple[tuple[str, re.Pattern[str], bool, object], ...] = (
    ("снилс", re.compile(r"\d{3}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{2}"), False, snils_ok),
    ("инн", re.compile(r"\d{12}|\d{10}"), False, inn_ok),
    ("огрнип", re.compile(r"\d{15}"), False, ogrnip_ok),
    ("огрн", re.compile(r"\d{13}"), False, ogrn_ok),
    ("паспорт", re.compile(r"\d{2}\s?\d{2}\s?№?\s?\d{6}"), True, None),
    ("кпп", re.compile(r"\d{4}[\dA-ZА-Я]{2}\d{3}"), True, None),
    ("бик", re.compile(r"04\d{7}"), True, None),
    ("расчётный счёт", re.compile(r"\d{20}"), True, None),
    ("полис ОМС", re.compile(r"\d{16}"), True, None),
    ("водительское", re.compile(r"\d{2}\s?[А-Я]{2}\s?\d{6}"), True, None),
)


def detect_ru_pii(text: str) -> list[tuple[str, str, int, int, str]]:
    """Вернуть подтверждённые находки российских идентификаторов.

    # START_CONTRACT: detect_ru_pii
    #   PURPOSE: Найти СНИЛС, ИНН, ОГРН, ОГРНИП, паспорт, КПП, БИК, счёт, полис ОМС и водительское.
    #   INPUTS: { text: str - текст }
    #   OUTPUTS: { list[(класс, значение, начало, конец, правило)] - подтверждённые находки }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETECT-RULES, M-DETECT-RU-PII, M-TOKEN-GEN, M-VALIDATOR
    # END_CONTRACT: detect_ru_pii

    Судьба числа решается дважды: сначала формой и контрольной суммой, затем — и только для
    правил без суммы — словом-признаком рядом. Обрывок длинного числа отбрасывается: у
    «1408178100999100043120» нет правила «двадцать цифр», и кусок счёта клиентом не является.
    """
    found: list[tuple[str, str, int, int, str]] = []
    taken: list[tuple[int, int]] = []
    for name, pattern, need_context, checker in RULES:
        for match in pattern.finditer(text):
            start, end = match.start(), match.end()
            if any(start < t_end and t_start < end for t_start, t_end in taken):
                continue
            if not _no_digit_neighbours(text, start, end):
                continue
            value = match.group(0)
            if name in EPOCH_GUARDED_RULES and _is_epoch(value):
                continue
            if checker is not None and not checker(value):  # type: ignore[operator]
                continue
            if need_context and not _context_ok(text, start, end):
                continue
            taken.append((start, end))
            found.append((CLASS_RU_DOCUMENT, value, start, end, name))
    found.sort(key=lambda item: item[2])
    return found


def iter_ru_pii(text: str) -> Iterator[tuple[str, str, int, int, str]]:
    """Отдать те же находки итератором — для вызывающих, кому список не нужен."""
    yield from detect_ru_pii(text)
# END_BLOCK_SCAN_RU_PII
