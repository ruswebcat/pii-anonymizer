# FILE: src/normalize.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Canonicalize detected values (phone, e-mail, name, birth date, address, documents, client identifiers) so identical real-world values always produce the identical token.
#   SCOPE: per-class normalization, phone digit canonicalization to 11 digits with 7 prefix, birth date split into tokenized day-month plus open year.
#   DEPENDS: none
#   LINKS: M-NORM, V-M-NORM, fn-normalize, fn-split_birth_date, class-NormalizeError
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   CLASSES - supported PII class letters
#   NormalizeError - unsupported class or unparsable value
#   normalize - canonical form for a class and raw value
#   split_birth_date - day-month key plus open year for class D
#   digits_only - helper used by phone and document normalization
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-1 M-NORM: first implementation of the normalization contract.
# END_CHANGE_SUMMARY

"""Value normalization for deterministic tokenization.

Implements M-NORM from docs/ARCHITECTURE.md. Determinism of tokens depends
on this module: every equivalent spelling of the same value must collapse to one
canonical string, otherwise the same client yields different tokens across turns
and the upstream prompt cache stops working (see UC-004).

Owner decision of 15.09.2026: for class D the birth year stays open while day and
month are tokenized, which is why the birth date is split rather than normalized
to a single string.
"""

from __future__ import annotations

import re

LOGGER_NAME = "ValueNormalizer"
LOG_MARKER = "[ValueNormalizer][normalize][BLOCK_NORMALIZE_VALUE]"

CLASSES = ("P", "T", "E", "D", "A", "I", "C")

_NON_DIGIT = re.compile(r"\D")
_SPACES = re.compile(r"\s+")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_DATE = re.compile(r"^(\d{1,2})[.\-/](\d{1,2})[.\-/](\d{2,4})$")


class NormalizeError(ValueError):
    """Unsupported class or unparsable value.

    # START_CONTRACT: NormalizeError
    #   PURPOSE: Signal that a value cannot be canonicalized for its class.
    #   INPUTS: { code: str - stable code, message: str - detail }
    #   OUTPUTS: { NormalizeError - exception instance }
    #   SIDE_EFFECTS: none
    #   LINKS: M-NORM, V-M-NORM
    # END_CONTRACT: NormalizeError
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# START_BLOCK_NORMALIZE_VALUE
def digits_only(raw: str) -> str:
    """Return only the digit characters of a raw string.

    # START_CONTRACT: digits_only
    #   PURPOSE: Strip formatting noise from phones and document numbers.
    #   INPUTS: { raw: str - arbitrary user text }
    #   OUTPUTS: { str - digits }
    #   SIDE_EFFECTS: none
    #   LINKS: M-NORM
    # END_CONTRACT: digits_only
    """
    return _NON_DIGIT.sub("", raw or "")


def _normalize_phone(raw: str) -> str:
    digits = digits_only(raw)
    if len(digits) == 10:
        digits = "7" + digits
    if len(digits) == 11 and digits[0] == "8":
        digits = "7" + digits[1:]
    if len(digits) != 11 or digits[0] != "7":
        raise NormalizeError("NORM_BAD_PHONE", f"cannot canonicalize phone: {raw!r}")
    return digits


def _normalize_name(raw: str) -> str:
    cleaned = raw.replace(".", " ").replace(",", " ")
    cleaned = _SPACES.sub(" ", cleaned).strip().lower()
    if len(cleaned) < 2:
        raise NormalizeError("NORM_BAD_NAME", f"cannot canonicalize name: {raw!r}")
    return cleaned


def _normalize_email(raw: str) -> str:
    cleaned = (raw or "").strip().lower()
    if not _EMAIL.match(cleaned):
        raise NormalizeError("NORM_BAD_EMAIL", f"cannot canonicalize e-mail: {raw!r}")
    return cleaned


def _normalize_address(raw: str) -> str:
    cleaned = _SPACES.sub(" ", (raw or "").replace(".", " ").replace(",", " ")).strip().lower()
    if len(cleaned) < 3:
        raise NormalizeError("NORM_BAD_ADDRESS", f"cannot canonicalize address: {raw!r}")
    return cleaned


def _normalize_document(raw: str) -> str:
    digits = digits_only(raw)
    if len(digits) < 5:
        raise NormalizeError("NORM_BAD_DOCUMENT", f"cannot canonicalize document: {raw!r}")
    return digits


def _normalize_client_id(raw: str) -> str:
    cleaned = digits_only(raw)
    if not cleaned:
        raise NormalizeError("NORM_BAD_CLIENT_ID", f"cannot canonicalize client id: {raw!r}")
    return cleaned.lstrip("0") or "0"


def normalize(cls: str, raw: str) -> str:
    """Return the canonical form used both for token generation and lookups.

    # START_CONTRACT: normalize
    #   PURPOSE: Canonicalize a raw value for its PII class.
    #   INPUTS: { cls: str - one of CLASSES, raw: str - detected value }
    #   OUTPUTS: { str - canonical value }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKEN-GEN, M-TOKENIZER, V-M-NORM
    # END_CONTRACT: normalize
    """
    handler = {
        "P": _normalize_name,
        "T": _normalize_phone,
        "E": _normalize_email,
        "A": _normalize_address,
        "I": _normalize_document,
        "C": _normalize_client_id,
    }.get(cls)
    if handler is None:
        raise NormalizeError("NORM_UNSUPPORTED_CLASS", f"class {cls!r} has no normalizer")
    return handler(raw)


def split_birth_date(raw: str) -> tuple[str, str]:
    """Split a birth date into a tokenized day-month key and an open year.

    # START_CONTRACT: split_birth_date
    #   PURPOSE: Support the owner decision that the birth year stays open.
    #   INPUTS: { raw: str - date like 12.03.1985 or 1985-03-12 }
    #   OUTPUTS: { tuple[str, str] - (day-month key such as 12.03, year such as 1985) }
    #   SIDE_EFFECTS: none
    #   LINKS: M-NORM, M-DETECT-RULES, V-M-NORM
    # END_CONTRACT: split_birth_date

    Both calendar orders are accepted. CRM returns ISO dates in some
    selections, and an unsupported format silently means "not anonymized" — the
    re-identification test found exactly that on 15.09.2026.
    """
    iso = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", (raw or "").strip())
    if iso:
        year, month, day = iso.groups()
        day_i, month_i = int(day), int(month)
        if not (1 <= day_i <= 31 and 1 <= month_i <= 12):
            raise NormalizeError("NORM_BAD_DATE", f"impossible birth date: {raw!r}")
        return f"{day_i:02d}.{month_i:02d}", year
    match = _DATE.match((raw or "").strip())
    if not match:
        raise NormalizeError("NORM_BAD_DATE", f"cannot parse birth date: {raw!r}")
    day, month, year = match.groups()
    if len(year) == 2:
        year = ("19" if int(year) > 30 else "20") + year
    day_i, month_i = int(day), int(month)
    if not (1 <= day_i <= 31 and 1 <= month_i <= 12):
        raise NormalizeError("NORM_BAD_DATE", f"birth date out of range: {raw!r}")
    return f"{day_i:02d}.{month_i:02d}", year
# END_BLOCK_NORMALIZE_VALUE
