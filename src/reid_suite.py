# FILE: src/reid_suite.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Prove, on a 100-record sample, that the anonymized output cannot be tied back to a person: no value survives, the readable dictionary is gone, and the residual risk is named instead of hidden.
#   SCOPE: end-to-end sample run through the tokenizer, three independent attack checks, k-anonymity grouping, PII-free report with a payload digest.
#   DEPENDS: M-TOKENIZER, M-NORM, M-TEST-HARNESS
#   LINKS: M-REID-TEST, V-M-REID-TEST, fn-run_reid_test, fn-k_anonymity_check, type-ReidReport
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   AttackOutcome - one attack, its attempts and successes
#   ReidReport - counts, attacks, k findings, verdict, limitations
#   ReidentificationSuite - runs the sample and produces the report
#   fn-run_reid_test - main entry
#   fn-k_anonymity_check - groups smaller than the threshold
#   fn-value_present - public criterion «the value survived», used by M-METRICS
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.1.0 - Phase-12 шаг 4: критерий «значение уцелело» открыт прибору метрик (fn-value_present), чтобы атака и метрика считали одно и то же свойство одним кодом.
#   PREVIOUS: v1.0.0 - Phase-3 M-REID-TEST: the artifact behind the re-identification act required by Приказ РКН № 140.
# END_CHANGE_SUMMARY

"""Re-identification test suite.

Приказ РКН № 140 requires the operator to show that anonymized data cannot be tied
back to a person, and the honest way to show it is to attack your own output. The
suite runs a real sample through the whole pipeline and tries three things:

* **direct lookup** — does any original value survive, literally or normalized?
* **dictionary linkage** — can the stored dictionary be used without its keys to
  compute the identifier of a known client and search for it?
* **quasi-identifier singling out** — do combinations like club + card + amount
  isolate a single person?

An attack that cannot fail proves nothing, so the tests deliberately break the
tokenizer and require the suite to notice. The suite reports limitations instead of
claiming perfection: singling out and "the key holder can always reverse this" are
named as residual risks, because a regulator will ask about them anyway.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from src.normalize import NormalizeError, normalize

LOGGER_NAME = "ReidentificationSuite"
LOG_MARKER = "[ReidentificationSuite][run_reid_test][BLOCK_RUN_REID_TEST]"

DEFAULT_K = 5
SENSITIVE_FIELDS: dict[str, str] = {
    "fio": "P",
    "name": "P",
    "phone": "T",
    "email": "E",
    "address": "A",
    "birth_date": "D",
}
# Note on ``card``: in the CRM sample the field holds the *duration* of the
# card ("12 мес"), which is a quasi-identifier rather than an identifier, so it is
# handled by the k-anonymity check. Treating it as an identifier made the direct
# attack report a 100% "leak" of non-personal data (found on 15.09.2026) — an
# alarm that cries wolf is as harmful as no alarm.
QUASI_FIELDS = ("club", "card", "amount")


@dataclass(frozen=True)
class AttackOutcome:
    """Result of one attack against the anonymized output.

    # START_CONTRACT: AttackOutcome
    #   PURPOSE: State what was tried and whether it worked.
    #   INPUTS: { name: str, attempts: int, successes: int, detail: str }
    #   OUTPUTS: { AttackOutcome - value object }
    #   SIDE_EFFECTS: none
    #   LINKS: V-M-REID-TEST
    # END_CONTRACT: AttackOutcome
    """

    name: str
    attempts: int
    successes: int
    detail: str


@dataclass(frozen=True)
class ReidReport:
    """Outcome of the whole suite, safe to show a regulator.

    # START_CONTRACT: ReidReport
    #   PURPOSE: Carry counts, verdict, digest and limitations without any values.
    #   INPUTS: { records: int, k_threshold: int, attacks: tuple, groups_below_k: int, payload_digest: str, verdict: str, limitations: tuple }
    #   OUTPUTS: { ReidReport - value object }
    #   SIDE_EFFECTS: none
    #   LINKS: V-M-REID-TEST
    # END_CONTRACT: ReidReport
    """

    records: int
    k_threshold: int
    attacks: tuple[AttackOutcome, ...]
    groups_below_k: int
    payload_digest: str
    verdict: str
    limitations: tuple[str, ...]

    @property
    def successes(self) -> int:
        """Return the total number of successful attacks."""
        return sum(attack.successes for attack in self.attacks)

    def to_markdown(self) -> str:
        """Render the report without any personal data."""
        lines = [
            "# Протокол теста на обратимую идентификацию",
            "",
            f"Записей в выборке: **{self.records}**",
            f"Порог k: **{self.k_threshold}**",
            f"Отпечаток обезличенного payload: `{self.payload_digest}`",
            "",
            "| Атака | Попыток | Успехов | Комментарий |",
            "|---|---|---|---|",
        ]
        for attack in self.attacks:
            lines.append(
                f"| {attack.name} | {attack.attempts} | {attack.successes} | {attack.detail} |"
            )
        lines.extend(
            [
                "",
                f"**Вердикт: {self.verdict}** (успешных атак: {self.successes})",
                "",
                "## Ограничения метода",
                "",
            ]
        )
        lines.extend(f"- {item}" for item in self.limitations)
        lines.append("")
        return "\n".join(lines)


# START_BLOCK_RUN_REID_TEST
class ReidentificationSuite:
    """Run the sample through the pipeline and attack the result.

    # START_CONTRACT: ReidentificationSuite
    #   PURPOSE: Produce the evidence for the re-identification act.
    #   INPUTS: { tokenizer: Any - pipeline entry point, k: int - anonymity threshold, dictionary_path: str | None - exported dictionary }
    #   OUTPUTS: { ReidentificationSuite - ready suite }
    #   SIDE_EFFECTS: writes bindings into the correspondence table through the tokenizer
    #   LINKS: M-TOKENIZER, M-DICT, V-M-REID-TEST
    # END_CONTRACT: ReidentificationSuite
    """

    def __init__(self, tokenizer: Any, k: int = DEFAULT_K, dictionary_path: str | None = None) -> None:
        self._tokenizer = tokenizer
        self._k = max(1, int(k))
        self._dictionary_path = dictionary_path

    def run_reid_test(self, records: Sequence[Mapping[str, Any]]) -> ReidReport:
        """Run the sample and return the report.

        # START_CONTRACT: run_reid_test
        #   PURPOSE: Evaluate re-identification risk on a sample.
        #   INPUTS: { records: Sequence[Mapping[str, Any]] - sample with realistic fields }
        #   OUTPUTS: { ReidReport - counts, attacks, verdict, limitations }
        #   SIDE_EFFECTS: tokenizes the sample, writes bindings, logs one marker line
        #   LINKS: M-TOKENIZER, V-M-REID-TEST
        # END_CONTRACT: run_reid_test
        """
        sample = list(records)
        payload = {
            "model": "reid-suite",
            "stream": False,
            "messages": [
                {"role": "tool", "content": json.dumps(sample, ensure_ascii=False, default=str)}
            ],
        }
        anonymized, _ = self._tokenizer.tokenize_payload(payload, "reid-test")
        anonymized_text = json.dumps(anonymized, ensure_ascii=False)
        digest = hashlib.sha256(anonymized_text.encode("utf-8")).hexdigest()

        attacks = (
            self._direct_lookup_attack(sample, anonymized_text),
            self._dictionary_linkage_attack(sample, anonymized_text),
            self._singling_out_attack(sample),
        )
        groups_below_k = self.k_anonymity_check(sample)
        verdict = (
            "личность не восстановлена"
            if all(attack.successes == 0 for attack in attacks)
            else "ЕСТЬ УСПЕШНАЯ АТАКА"
        )
        report = ReidReport(
            records=len(sample),
            k_threshold=self._k,
            attacks=attacks,
            groups_below_k=groups_below_k,
            payload_digest=digest,
            verdict=verdict,
            limitations=self._limitations(sample, groups_below_k, attacks),
        )
        logging.getLogger(LOGGER_NAME).info(
            "%s records=%s successes=%s groups_below_k=%s verdict=%s",
            LOG_MARKER,
            report.records,
            report.successes,
            report.groups_below_k,
            report.verdict,
        )
        return report

    def k_anonymity_check(self, records: Sequence[Mapping[str, Any]]) -> int:
        """Count quasi-identifier groups smaller than the threshold.

        # START_CONTRACT: k_anonymity_check
        #   PURPOSE: Flag groups below k threshold.
        #   INPUTS: { records: Sequence[Mapping[str, Any]] - sample }
        #   OUTPUTS: { int - number of groups smaller than k }
        #   SIDE_EFFECTS: none
        #   LINKS: V-M-REID-TEST
        # END_CONTRACT: k_anonymity_check
        """
        groups: dict[tuple, int] = {}
        for record in records:
            key = tuple(str(record.get(field, "")) for field in QUASI_FIELDS)
            groups[key] = groups.get(key, 0) + 1
        return sum(1 for size in groups.values() if size < self._k)

    def _direct_lookup_attack(
        self, records: Sequence[Mapping[str, Any]], anonymized_text: str
    ) -> AttackOutcome:
        """Check whether any original value survived into the anonymized payload."""
        attempts = 0
        successes = 0
        for record in records:
            for field, cls in SENSITIVE_FIELDS.items():
                value = record.get(field)
                if value in (None, ""):
                    continue
                attempts += 1
                if _value_present(str(value), cls, anonymized_text):
                    successes += 1
        return AttackOutcome(
            name="Прямой поиск значений",
            attempts=attempts,
            successes=successes,
            detail="поиск исходных значений и их нормализованных форм в обезличенном тексте",
        )

    def _dictionary_linkage_attack(
        self, records: Sequence[Mapping[str, Any]], anonymized_text: str
    ) -> AttackOutcome:
        """Try to confirm a known client from the dictionary file alone."""
        if not self._dictionary_path:
            return AttackOutcome(
                name="Связывание по словарю",
                attempts=0,
                successes=0,
                detail="словарь не передан: проверка не выполнялась",
            )
        try:
            with open(self._dictionary_path, encoding="utf-8") as handle:
                blob = handle.read()
        except OSError:
            return AttackOutcome(
                name="Связывание по словарю",
                attempts=0,
                successes=0,
                detail="файл словаря недоступен",
            )
        attempts = 0
        successes = 0
        for record in records:
            for text in _linkage_candidates(record):
                attempts += 1
                # Two shapes of attack: the readable value itself, or a plain,
                # unkeyed hash of it (which is what a naive implementation stores).
                plain_digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
                if text in blob or plain_digest in blob:
                    successes += 1
                    continue
                if _contains_token_safe(text, anonymized_text):
                    successes += 1
        return AttackOutcome(
            name="Связывание по словарю",
            attempts=attempts,
            successes=successes,
            detail="поиск значений и некриптографических отпечатков в файле словаря и в payload",
        )

    def _singling_out_attack(self, records: Sequence[Mapping[str, Any]]) -> AttackOutcome:
        """Count quasi-identifier combinations that isolate exactly one record."""
        groups: dict[tuple, int] = {}
        for record in records:
            key = tuple(str(record.get(field, "")) for field in QUASI_FIELDS)
            groups[key] = groups.get(key, 0) + 1
        unique = sum(1 for size in groups.values() if size == 1)
        return AttackOutcome(
            name="Выделение по квазиидентификаторам",
            attempts=len(groups),
            # By construction this attack cannot name anyone without the
            # correspondence table, so the count stays zero while the number of
            # unique combinations is reported as a limitation instead. Reporting
            # it as a "success" would be dishonest; hiding it would be worse.
            successes=0,
            detail=(
                f"уникальных сочетаний (клуб+карта+сумма): {unique}; "
                "выделение без словаря соответствий не даёт имени, поэтому в вердикт не идёт"
            ),
        )

    def _limitations(
        self,
        records: Sequence[Mapping[str, Any]],
        groups_below_k: int,
        attacks: Iterable[AttackOutcome],
    ) -> tuple[str, ...]:
        """Name the residual risks instead of hiding them."""
        limitations = [
            f"групп меньше порога k={self._k}: {groups_below_k} — обезличивание не защищает "
            "от выделения по редким сочетаниям, это задача порога редкости (UC-012/M-ROUTER)",
            "владелец ключей и справочника соответствий может восстановить значения: "
            "схема защищает от внешнего получателя, а не от владельца контура",
            "история с обезличенными токенами остаётся у провайдера: проверяется отдельно "
            "договором и режимом хранения, а не обезличиванием",
        ]
        if not self._dictionary_path:
            limitations.append("словарь не передавался: проверка связывания по словарю не выполнена")
        return tuple(limitations)
# END_BLOCK_RUN_REID_TEST


def _linkage_candidates(record: Mapping[str, Any]) -> list[str]:
    """Return the values worth trying in the dictionary linkage attack.

    # START_CONTRACT: _linkage_candidates
    #   PURPOSE: Attack with the data that actually exists in the record.
    #   INPUTS: { record: Mapping[str, Any] - one client record }
    #   OUTPUTS: { list[str] - candidate values }
    #   SIDE_EFFECTS: none
    #   LINKS: M-REID-TEST, V-M-REID-TEST
    # END_CONTRACT: _linkage_candidates

    The first version looked only at a flat ``phone`` field, so on real CRM
    records — where phones live in the nested ``contacts`` list — the attack ran
    zero attempts and proved nothing (noticed 15.09.2026). An attack with no
    attempts is worse than no attack, because it looks like a pass.
    """
    candidates: list[str] = []
    for field in ("phone", "email", "surname", "name"):
        value = record.get(field)
        if isinstance(value, str) and _is_attack_candidate(value):
            candidates.append(value.strip())
    contacts = record.get("contacts")
    if isinstance(contacts, (list, tuple)):
        for contact in contacts:
            if not isinstance(contact, Mapping):
                continue
            kind = str(contact.get("contact_type") or "").strip().lower()
            value = contact.get("contact")
            if kind in {"phone", "mobile", "mobile_phone", "email"} and isinstance(value, str):
                if _is_attack_candidate(value):
                    candidates.append(value.strip())
    return candidates


def _is_attack_candidate(value: str) -> bool:
    """Return True when a value is worth attacking with.

    Underscored strings are excluded: the CRM's ``name`` field occasionally holds
    a technical identifier ("client_source"), which then matches a JSON *key* in
    the payload and produces a phantom success (found 15.09.2026). A real personal
    name never contains an underscore, and an attack that cries wolf makes the act
    it feeds worthless.
    """
    text = value.strip()
    if len(text) < MIN_ATTACK_LENGTH:
        return False
    return "_" not in text


def _value_present(value: str, cls: str, anonymized_text: str) -> bool:
    """Return True when a value (or its normalized form) is present in the text.

    # START_CONTRACT: _value_present
    #   PURPOSE: Make the direct attack thorough rather than naive.
    #   INPUTS: { value: str, cls: str, anonymized_text: str }
    #   OUTPUTS: { bool - True when the value survived }
    #   SIDE_EFFECTS: none
    #   LINKS: V-M-REID-TEST
    # END_CONTRACT: _value_present

    Precision matters as much as recall here. On real data the first version
    reported 47 "survivals" that were mostly noise: CRM has records whose
    ``name`` is a single character, and a one-character search matches everything
    (found 15.09.2026). Short values are therefore ignored, and Cyrillic values
    must match on word boundaries rather than inside a longer word.
    """
    if len(value.strip()) < MIN_ATTACK_LENGTH:
        return False
    if _contains_token_safe(value, anonymized_text):
        return True
    try:
        normalized = normalize(cls, value)
    except NormalizeError:
        normalized = ""
    if normalized and _contains_token_safe(normalized, anonymized_text.lower()):
        return True
    # A birth date is tokenized as day-month with the year left open on purpose,
    # so only the day-month part counts as a leak of the identifying part.
    if cls == "D":
        day_month = _birth_day_month(value)
        if day_month:
            return day_month in anonymized_text
    return False


MIN_ATTACK_LENGTH = 3

#: Публичный псевдоним для приборов (M-METRICS): метрика «значение уцелело» обязана
#: считаться тем же кодом, что и атака, иначе два критерия одного свойства расходятся.
value_present = _value_present


def _contains_token_safe(value: str, haystack: str) -> bool:
    """Return True when the value occurs not glued to neighbouring word chars."""
    pattern = (
        r"(?<![А-Яа-яЁёA-Za-z0-9])" + re.escape(value) + r"(?![А-Яа-яЁёA-Za-z0-9])"
    )
    return re.search(pattern, haystack) is not None


def _birth_day_month(value: str) -> str:
    """Return the day-month key of a birth date in either calendar order."""
    text = value.strip()
    iso = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", text)
    if iso:
        _year, month, day = iso.groups()
        return f"{month}-{day}"
    parts = text.replace("-", ".").replace("/", ".").split(".")
    if len(parts) == 3:
        try:
            return f"{int(parts[0]):02d}.{int(parts[1]):02d}"
        except ValueError:
            return ""
    return ""
