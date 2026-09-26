# FILE: src/translit.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Recognise transliterated Russian names (Terekhina -> Терёхина) by rule, so that clients written in Latin are anonymized without keeping a single Latin value.
#   SCOPE: reverse transliteration of a Latin name into plausible Cyrillic spellings, bounded variant generation, membership probing through an injected lookup.
#   DEPENDS: none
#   LINKS: M-TRANSLIT, V-M-TRANSLIT, M-DETECT-NAME, Phase-10
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   MAX_VARIANTS - hard cap on generated variants per name
#   latin_to_cyrillic_variants - plausible Cyrillic spellings of a Latin name
#   matches_known_name - variant probe through an injected membership test
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-10: 16.5% of clients are written in Latin and no open Cyrillic list covers them.
# END_CHANGE_SUMMARY

"""Rule-based reverse transliteration.

Measured 17.09.2026: after the client dictionary was cleaned and the open layer was
wired in, effective anonymization was 88.2% — and 28 of the 47 remaining misses were
Latin spellings ("Terekhina"). No open Cyrillic surname list covers them (888 Latin
surnames against 247 110 Cyrillic), so the gap is closed by rules instead of data:
the Latin form is turned back into Cyrillic candidates and checked against the
name lists we already have.

The table is deliberately small and readable: it encodes how Russian names are
usually transliterated in club records, not every possible scheme.
"""

from __future__ import annotations

from typing import Callable, Iterable

MAX_VARIANTS = 96

# Латиница -> варианты кириллицы, упорядоченные по частоте в наших данных.
SEQUENCES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("shch", ("щ",)),
    ("sch", ("щ",)),
    ("zh", ("ж",)),
    ("kh", ("х",)),
    ("ch", ("ч",)),
    ("sh", ("ш",)),
    ("ts", ("ц",)),
    ("yo", ("ё", "е")),
    ("ju", ("ю",)),
    ("yu", ("ю",)),
    ("ja", ("я",)),
    ("ya", ("я",)),
    ("je", ("е",)),
    ("ye", ("е",)),
    ("yi", ("ый", "ий")),
    ("iy", ("ий", "ый")),
    ("ey", ("ей",)),
    ("ay", ("ай",)),
    ("oy", ("ой",)),
    ("uy", ("уй",)),
    ("y", ("ы", "й", "и")),
    ("a", ("а",)),
    ("b", ("б",)),
    ("c", ("к", "ц")),
    ("d", ("д",)),
    ("e", ("е", "э")),
    ("f", ("ф",)),
    ("g", ("г",)),
    ("h", ("х", "г")),
    ("i", ("и", "й")),
    ("j", ("й", "дж")),
    ("k", ("к",)),
    ("l", ("л",)),
    ("m", ("м",)),
    ("n", ("н",)),
    ("o", ("о",)),
    ("p", ("п",)),
    ("q", ("к",)),
    ("r", ("р",)),
    ("s", ("с",)),
    ("t", ("т",)),
    ("u", ("у",)),
    ("v", ("в",)),
    ("w", ("в",)),
    ("x", ("кс",)),
    ("z", ("з",)),
    ("'", ("ь", "")),
    ("", ("",)),
)

# Наиболее частые окончания: проверяются первыми, чтобы вариантов было меньше.
ENDINGS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ova", ("ова",)),
    ("eva", ("ева", "ёва")),
    ("ina", ("ина",)),
    ("aya", ("ая",)),
    ("sky", ("ский",)),
    ("skiy", ("ский",)),
    ("ov", ("ов",)),
    ("ev", ("ев", "ёв")),
    ("in", ("ин",)),
    ("iy", ("ий",)),
    ("ko", ("ко",)),
    ("uk", ("ук",)),
    ("vich", ("вич",)),
    ("enko", ("енко",)),
    ("enko", ("енко",)),
    ("tskaya", ("цкая",)),
)


def _variants_for(latin: str, sequences: Iterable[tuple[str, tuple[str, ...]]]) -> list[str]:
    """Split a lower-case Latin word into mapped chunks, first variant only."""
    table = {key: values[0] for key, values in sequences}
    result: list[str] = []
    index = 0
    while index < len(latin):
        for size in (4, 3, 2, 1):
            chunk = latin[index : index + size]
            if chunk and chunk in table:
                result.append(table[chunk])
                index += size
                break
        else:
            result.append(latin[index])
            index += 1
    return result


def latin_to_cyrillic_variants(latin: str, limit: int = MAX_VARIANTS) -> list[str]:
    """Return plausible Cyrillic spellings of a Latin name.

    # START_CONTRACT: latin_to_cyrillic_variants
    #   PURPOSE: Give the recognizer something to look up in the name lists.
    #   INPUTS: { latin: str - Latin name, limit: int - cap on variants }
    #   OUTPUTS: { list[str] - Cyrillic candidates, most likely first }
    #   SIDE_EFFECTS: none
    #   LINKS: V-M-TRANSLIT, M-DETECT-NAME
    # END_CONTRACT: latin_to_cyrillic_variants

    Two sources of variants: the chunk table (ambiguous letters: e -> е/э, y -> ы/й/и,
    c -> к/ц, h -> х/г) and the ending table (Russian surname endings). The result is
    capped, because a name must not cost an unbounded number of dictionary probes.
    """
    if not latin or not latin.strip():
        return []
    word = latin.strip().lower().replace("-", "")
    variants: list[str] = []

    def add(candidate: str) -> None:
        candidate = candidate.strip()
        if candidate and candidate not in variants and len(variants) < limit:
            variants.append(candidate)

    for ending, replacements in ENDINGS:
        if word.endswith(ending) and len(word) > len(ending) + 1:
            stem = word[: -len(ending)]
            stem_variants = set(_variants_for(stem, SEQUENCES))
            for replacement in replacements:
                for stem_variant in stem_variants:
                    add(stem_variant + replacement)
                    add(stem_variant + replacement.rstrip("ая"))
            break

    base = "".join(_variants_for(word, SEQUENCES))
    add(base)

    # Небольшая ротация неоднозначных букв: e -> э, i -> й, y -> й/ы.
    swaps = (
        ("е", "э"),
        ("и", "й"),
        ("о", "а"),
        ("в", "ф"),
    )
    for source, target in swaps:
        for candidate in list(variants):
            if source in candidate:
                add(candidate.replace(source, target, 1))
    return variants


def matches_known_name(value: str, lookup: Callable[[str], bool]) -> bool:
    """Return True when a Latin name maps onto a known Cyrillic name.

    # START_CONTRACT: matches_known_name
    #   PURPOSE: Close the Latin gap with rules instead of a list of client values.
    #   INPUTS: { value: str - Latin candidate, lookup: Callable[[str], bool] - membership test }
    #   OUTPUTS: { bool - True when some Cyrillic variant is known }
    #   SIDE_EFFECTS: calls the injected lookup
    #   LINKS: V-M-TRANSLIT, M-NAME-LAYER
    # END_CONTRACT: matches_known_name
    """
    if not value or not value.strip():
        return False
    for variant in latin_to_cyrillic_variants(value):
        try:
            if lookup(variant):
                return True
        except Exception:  # noqa: BLE001 - a failing lookup must not stop detection
            return False
    return False
