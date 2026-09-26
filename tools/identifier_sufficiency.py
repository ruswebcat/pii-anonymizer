# FILE: tools/identifier_sufficiency.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Compute and document the sufficiency of the identifier method (Приказ РКН 140 requires the operator to assess it): code space size, collision probability, accidental restore probability, assumptions and limits.
#   SCOPE: sufficiency arithmetic over the code space, report rendering, CLI entry.
#   DEPENDS: M-TOKEN-GEN, M-MAP-STORE
#   LINKS: M-IDENT-SUFFICIENCY, V-M-IDENT-SUFFICIENCY, fn-compute_sufficiency, fn-render_report
#   ROLE: SCRIPT
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   Sufficiency - computed sufficiency figures
#   compute_sufficiency - space, collision and accidental-hit probabilities
#   render_report - markdown report with assumptions and limits
#   main - CLI entry point
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-4 M-IDENT-SUFFICIENCY: neither РКН nor ФСТЭК norm the code length, so the operator documents the assessment; this tool is that arithmetic.
# END_CHANGE_SUMMARY

"""Sufficiency assessment for the identifier method.

Implements M-IDENT-SUFFICIENCY from docs/ARCHITECTURE.md. Приказ Роскомнадзора
№ 140 от 19.06.2025 defines the method (an identifier as «код, номер или иное
обозначение» assigned by operator algorithms), requires a key stored separately
from the data and never transferred to third parties, requires that attribution be
impossible without additional information, and requires the operator to assess the
sufficiency of the chosen method. No regulator prescribes code length or alphabet,
so the assessment is computed here and recorded in the regulation.

The identifier is not a cipher: strength comes from the separate key and the
separately stored correspondence table. Code length governs two things only —
collision probability and the chance that a made-up code accidentally matches an
issued one — and Phase-4 closes both with mechanisms (a deterministic candidate
walk, and restoring only identifiers that were present in the request).
"""

from __future__ import annotations

import math
import os
import sys
from dataclasses import dataclass
from typing import Sequence

# Bootstrap the package path: the tool is run as a script (python3 tools/x.py),
# so the repository root is not on sys.path by default.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.token_factory import CODE_LENGTH, CODE_PREFIX, CLASS_LETTERS  # noqa: E402

LOGGER_NAME = "IdentifierSufficiency"
LOG_MARKER = "[IdentifierSufficiency][compute_sufficiency][BLOCK_COMPUTE_SUFFICIENCY]"

ALPHABET_SIZE = 32
DEFAULT_TARGET = 0.001
DICTIONARY_VALUES = 150_494


class SufficiencyError(RuntimeError):
    """Sufficiency assessment failure with a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Sufficiency:
    """Computed sufficiency figures for one identifier configuration."""

    code_length: int
    bits: int
    space: int
    values_count: int
    collision_probability: float
    accidental_hit_probability: float
    safe_values_at_target: int
    target: float


# START_BLOCK_COMPUTE_SUFFICIENCY
def compute_sufficiency(
    values_count: int = DICTIONARY_VALUES,
    code_length: int = CODE_LENGTH,
    alphabet_size: int = ALPHABET_SIZE,
    target: float = DEFAULT_TARGET,
) -> Sufficiency:
    """Compute space size, collision probability and accidental hit probability.

    # START_CONTRACT: compute_sufficiency
    #   PURPOSE: Turn the identifier configuration into the numbers a regulator can read.
    #   INPUTS: { values_count: int - how many values the table holds, code_length: int, alphabet_size: int, target: float - acceptable collision probability }
    #   OUTPUTS: { Sufficiency - computed figures }
    #   SIDE_EFFECTS: none
    #   LINKS: V-M-IDENT-SUFFICIENCY
    # END_CONTRACT: compute_sufficiency
    """
    if values_count <= 0 or code_length <= 0 or alphabet_size < 2:
        raise SufficiencyError(
            "SUFFICIENCY_BAD_PARAMS",
            f"values={values_count}, length={code_length}, alphabet={alphabet_size}",
        )
    if not 0 < target < 1:
        raise SufficiencyError("SUFFICIENCY_BAD_PARAMS", f"target={target}")
    space = alphabet_size**code_length
    # Birthday bound: probability that at least one pair of values shares a code.
    collision = 1 - math.exp(-(values_count**2) / (2 * space))
    # Probability that one made-up code matches some issued code.
    hit = values_count / space
    safe_values = int(math.sqrt(2 * space * target))
    return Sufficiency(
        code_length=code_length,
        bits=int(round(math.log2(space))),
        space=space,
        values_count=values_count,
        collision_probability=collision,
        accidental_hit_probability=hit,
        safe_values_at_target=safe_values,
        target=target,
    )


def render_report(sufficiency: Sufficiency, surface: str | None = None) -> str:
    """Render the assessment for the regulation, with assumptions and limits."""
    surface = surface or f"{CODE_PREFIX}<{'|'.join(CLASS_LETTERS)}><{sufficiency.code_length} base32>"
    lines = [
        "## Оценка достаточности метода введения идентификаторов",
        "",
        f"Применяемая поверхность идентификатора: `{surface}` "
        f"(длина {sufficiency.code_length} знаков, {sufficiency.bits} бит).",
        "",
        "| Показатель | Значение |",
        "|---|---|",
        f"| Объём пространства идентификаторов | {sufficiency.space:,} |".replace(",", " "),
        f"| Вероятность совпадения двух разных значений (коллизия) | {sufficiency.collision_probability * 100:.4f}% |",
        f"| Вероятность случайного попадания в выданный идентификатор | {sufficiency.accidental_hit_probability:.2e} |",
        f"| Значений в справочнике на дату расчёта | {sufficiency.values_count:,} |".replace(",", " "),
        f"| Ёмкость при вероятности коллизии {sufficiency.target * 100:g}% | {sufficiency.safe_values_at_target:,} |".replace(",", " "),
        "",
        "### Допущения",
        "",
        f"1. Идентификатор выводится из значения ключом HMAC-SHA256 и записывается в одном регистре; "
        f"распознавание регистронезависимо, поэтому второй регистр не создаёт новых идентификаторов "
        f"и пространство не сокращается.",
        "2. Стойкость обеспечивается не длиной идентификатора, а секретным ключом (код не позволяет "
        "проверить гипотезу о значении без ключа) и хранением справочника отдельно от массива данных "
        "в зашифрованном виде — как и требует пункт 3 приказа Роскомнадзора № 140.",
        "3. Совпадение кодов разных значений исключается механизмом разрешения коллизий: при занятом "
        "коде берётся следующий детерминированный кандидат, поэтому коллизия не приводит к подмене.",
        "4. Подстановка чужого значения исключена механизмом восстановления только тех идентификаторов, "
        "которые присутствовали в запросе.",
        "",
        "### Границы применимости",
        "",
        "- Идентификатор не является шифром: он необратим только вместе с недоступностью ключа и справочника.",
        f"- Текущий справочник ({sufficiency.values_count:,} значений) уже превышает ёмкость для вероятности "
        f"коллизии {sufficiency.target * 100:g}% ({sufficiency.safe_values_at_target:,}): расчётная вероятность "
        f"совпадения составляет {sufficiency.collision_probability * 100:.2f}%, то есть совпадения происходят. "
        "Подмены при этом не возникает: занятый код обнаруживается до записи, и значение получает следующий "
        "детерминированный кандидат.",
        "- При росте справочника на порядки длину кода следует увеличить, чтобы обход кандидатов оставался "
        "коротким; механизмы подстановки при этом не меняются.",
        "- Оценка относится к методу введения идентификаторов; иные каналы передачи данных "
        "(изображения, внешние сервисы) ею не покрываются.",
    ]
    return "\n".join(lines)
# END_BLOCK_COMPUTE_SUFFICIENCY


def main(argv: Sequence[str] | None = None) -> int:
    """Print the assessment for the configuration actually used in code.

    # START_CONTRACT: main
    #   PURPOSE: Produce the assessment document for the regulation.
    #   INPUTS: { argv: Sequence[str] | None - CLI arguments (--values N) }
    #   OUTPUTS: { int - process exit code }
    #   SIDE_EFFECTS: prints the report
    #   LINKS: V-M-IDENT-SUFFICIENCY
    # END_CONTRACT: main
    """
    args = list(argv if argv is not None else sys.argv[1:])
    values = DICTIONARY_VALUES
    for index, arg in enumerate(args):
        if arg == "--values" and index + 1 < len(args):
            values = int(args[index + 1])
    sufficiency = compute_sufficiency(values_count=values)
    print(render_report(sufficiency))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
