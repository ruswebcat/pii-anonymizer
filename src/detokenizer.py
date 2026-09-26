# FILE: src/detokenizer.py
# VERSION: 1.2.0
# START_MODULE_CONTRACT
#   PURPOSE: Restore real values from tokens only where policy allows: tool-call arguments always, final text only on trusted channels.
#   SCOPE: token scanning and replacement, channel-aware text handling, tool-call argument restoration, response walking, streaming detokenization with a hold buffer.
#   DEPENDS: M-MAP-STORE, M-CHANNEL-POLICY, M-AUDIT
#   LINKS: M-DETOKENIZER, V-M-DETOKENIZER, fn-detokenize_text, fn-detokenize_tool_args, class-StreamDetokenizer
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   STREAM_HOLD - characters held back while streaming so a token never splits
#   COHERENCE_GAP - предел пробела между значениями, которые считаются соседними в ФИО
#   PayloadDetokenizer - channel-aware value restoration
#   fn-detokenize_text - restore or keep tokens in one text block
#   fn-detokenize_tool_args - restore arguments before tool execution
#   fn-_ambiguity - сколько разных персон за кодом: многозначный код не восстанавливается
#   fn-_coherence_blocks - отказать значениям, сочетание которых источником не подтверждено
#   StreamDetokenizer - incremental detokenizer for SSE streams
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.3.0 - Phase-17 (20.09.2026): доверенная граница перестала быть простым перекодировщиком. (1) Многозначный код (за ним больше одной персоны) НЕ восстанавливается и пишет инцидент: выдуманный человек хуже пустого места. (2) Соседние части ФИО (пара, тройка) обязаны подтверждаться индексом со-встречаемости — иначе значения не восстанавливаются, а инцидент записывается; причиной стало то, что коды выдаются на отдельные значения и модель может склеить имя одного человека с фамилией другого. (3) Поток удерживает хвост пары, чтобы пара не разошлась по кускам: раньше граница куска была слепым пятном заслона.
#   PREVIOUS: v1.2.0 - Phase-7 шаг 5: восстановление берёт наблюдённую форму по порядку вхождений, именительный падеж как запасной; тот же счётчик в потоковом пути.
#   PREVIOUS: v1.1.0 - Phase-12 шаг 5: разрез потока считается по критерию подтверждённой позиции, который передаёт вызывающий (M-STREAM-RELAY); левый символ куска сохраняется, иначе код на стыке разбирался бы иначе, чем в непотоковом пути.
#   PREVIOUS: v1.0.0 - Phase-1 M-DETOKENIZER: Mattermost and local files only; Telegram stays tokenized and audited.
# END_CHANGE_SUMMARY

"""Channel-aware detokenization.

Implements M-DETOKENIZER from docs/ARCHITECTURE.md. The asymmetry is the
point: tool arguments must be restored or the agent cannot query CRM
(UC-002), while user-visible text is restored only for channels inside the
allowlist (UC-003). Unknown tokens are left untouched and counted, never
guessed, and no restored value is ever logged.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Collection
from typing import Any

from src.audit import AuditEvent, AuditJournal
from src.channel_policy import DECISION_DETOKENIZE, ChannelPolicy
from src.incident_journal import IncidentEvent
from src.map_store import MapStoreError, TokenMapStore
from src.name_coherence import MODE_AUDIT, MODE_ENFORCE, MODE_OFF, NameCoherence, is_part_value
from src.name_identity import is_digest_identity, matches_identity
from src.token_factory import (
    LEGACY_OPEN,
    SENTINEL_OPEN,
    TokenError,
    canonical_token,
    find_tokens,
    iter_token_values,
    parse_token,
)

# A token cut in half by a length limit: the model's answer was truncated inside the
# token, so no closing bracket ever arrives. Seen in the A/B run on 15.09.2026 —
# the reader would have been shown token debris.
TRUNCATED_TOKEN_PATTERN = re.compile(
    rf"(?:{re.escape(SENTINEL_OPEN)}|{re.escape(LEGACY_OPEN)})[A-Z]-[A-Z0-9]{{0,32}}$"
)
TRUNCATION_PLACEHOLDER = "…"

LOGGER_NAME = "PayloadDetokenizer"
LOG_MARKER = "[PayloadDetokenizer][detokenize_text][BLOCK_DETOKENIZE_TEXT]"


def collect_identifiers(*texts: str) -> frozenset[str]:
    """Return the canonical identifiers present in the given texts.

    The router builds the allowed set from the request body and from the payload
    it just anonymized, so restoration is limited to identifiers this request
    actually carried (Phase-4 mechanism 2).

    # START_CONTRACT: collect_identifiers
    #   PURPOSE: Build the allow-list that gates restoration.
    #   INPUTS: { texts: str - one or more text blocks }
    #   OUTPUTS: { frozenset[str] - canonical identifiers }
    #   SIDE_EFFECTS: none
    #   LINKS: M-ROUTER, M-DETOKENIZER, V-M-DETOKENIZER
    # END_CONTRACT: collect_identifiers
    """
    found: set[str] = set()
    for text in texts:
        if isinstance(text, str):
            found.update(iter_token_values(text))
    return frozenset(found)

#: Хвост потока, удерживаемый, чтобы код не разошёлся по кускам.
STREAM_HOLD = 32

#: Предел пробела между двумя восстановленными значениями, при котором они считаются
#: соседними частями одного ФИО: «Иванов Иван» — да, «Иванов .... Иван» — нет.
COHERENCE_GAP = 2

#: Не-пробельные знаки, которые тоже читаются как разделитель внутри ФИО (перенос не нужен).
COHERENCE_SEPARATORS = frozenset({" ", "\t", "\n", "\r", "\u00a0"})



class DetokenizeError(RuntimeError):
    """Detokenization failure with a stable code.

    # START_CONTRACT: DetokenizeError
    #   PURPOSE: Surface store failures so the router can fail closed.
    #   INPUTS: { code: str - stable code, message: str - detail }
    #   OUTPUTS: { DetokenizeError - exception instance }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETOKENIZER, M-ROUTER, V-M-DETOKENIZER
    # END_CONTRACT: DetokenizeError
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# START_BLOCK_DETOKENIZE_TEXT
class PayloadDetokenizer:
    """Restore values from tokens according to channel policy.

    # START_CONTRACT: PayloadDetokenizer
    #   PURPOSE: Own the reverse mapping and the channel decision.
    #   INPUTS: { store: TokenMapStore, policy: ChannelPolicy, audit: AuditJournal | None }
    #   OUTPUTS: { PayloadDetokenizer - ready detokenizer }
    #   SIDE_EFFECTS: reads the correspondence table, appends audit events
    #   LINKS: M-MAP-STORE, M-CHANNEL-POLICY, V-M-DETOKENIZER
    # END_CONTRACT: PayloadDetokenizer
    """

    def __init__(
        self,
        store: TokenMapStore,
        policy: ChannelPolicy,
        audit: AuditJournal | None = None,
        identity_of: Callable[[str], str | None] | None = None,
        coherence: NameCoherence | None = None,
        coherence_key: bytes | None = None,
        coherence_mode: str = MODE_OFF,
        incident: Any | None = None,
    ) -> None:
        """Собрать детокенизатор доверенной границы.

        # START_CONTRACT: PayloadDetokenizer.__init__
        #   PURPOSE: Дать границе два заслона помимо списка разрешённых кодов: многозначность кода и связность персоны.
        #   INPUTS: { store, policy, audit, identity_of - как называть персону значения, coherence - индекс сочетаний, coherence_key - ключ отпечатков, coherence_mode - off/audit/enforce, incident - журнал инцидентов }
        #   OUTPUTS: { PayloadDetokenizer }
        #   SIDE_EFFECTS: none
        #   LINKS: M-NAME-COHERENCE, M-MAP-STORE, V-M-DETOKENIZER
        # END_CONTRACT: PayloadDetokenizer.__init__

        Оба заслона включаются параметрами и по умолчанию выключены: без ``identity_of``
        многозначность не спрашивается (историческая совместимость), без индекса сочетаний
        проверка связности выключена явно (``coherence_mode=off``), а не молча.
        """
        self._store = store
        self._policy = policy
        self._audit = audit
        self._identity_of = identity_of
        self._coherence = coherence
        self._coherence_key = coherence_key
        self._coherence_mode = coherence_mode if coherence_mode in (MODE_OFF, MODE_AUDIT, MODE_ENFORCE) else MODE_OFF
        self._incident = incident
        #: Счётчики заслонов: числа, без значений. Показываются в healthz и в отчёте замера.
        self._guard_counters: dict[str, int] = {
            "ambiguous_kept": 0,
            "coherence_checked": 0,
            "coherence_blocked": 0,
            "coherence_unchecked": 0,
        }

    def counters(self) -> dict[str, int]:
        """Вернуть счётчики заслонов границы (числа без значений)."""
        return dict(self._guard_counters)

    @property
    def coherence_mode(self) -> str:
        """Вернуть режим проверки связности: off, audit или enforce."""
        return self._coherence_mode

    def _note_incident(self, cls: str, action: str, code: str, findings: int, channel: str, session_id: str) -> None:
        """Записать инцидент границы: класс, машинное действие, код и число, без значений.

        Сбой записи инцидента защиту не отменяет (значение уже не восстановлено), поэтому
        исключение наружу не идёт: журнал аудита и счётчик незаписанных увидят сбой сами.
        """
        if self._incident is None:
            return
        try:
            self._incident.record(
                IncidentEvent(
                    cls=cls,
                    action=action,
                    channel=str(channel or ""),
                    code=code,
                    findings=int(findings),
                    replacements=0,
                )
            )
        except Exception:  # noqa: BLE001 - журнал инцидентов не имеет права ломать ответ
            logging.getLogger(LOGGER_NAME).warning(
                "%s incident not recorded: %s", LOG_MARKER, action
            )

    def _ambiguity(self, token: str) -> bool:
        """Сказать, значит ли код больше одной персоны (тогда значение не восстанавливается).

        # START_CONTRACT: _ambiguity
        #   PURPOSE: Не восстанавливать по коду, который не однозначен: это и есть выдуманный человек.
        #   INPUTS: { token: str - канонический код }
        #   OUTPUTS: { bool - True, когда за кодом больше одной персоны }
        #   SIDE_EFFECTS: читает справочник
        #   LINKS: M-MAP-STORE, V-M-DETOKENIZER
        # END_CONTRACT: _ambiguity
        """
        if self._identity_of is None:
            return False
        try:
            return self._store.record_ambiguity(token, self._identity_of) > 0
        except MapStoreError as exc:
            raise DetokenizeError("DETOK_STORE_FAILED", exc.message) from exc

    def _coherence_parts(self, cls: str, token: str, replacement: str | None) -> str:
        """Вернуть хранимое значение кода — часть ФИО для проверки сочетания.

        Берётся хранимое значение, а не наблюдённая форма: падежная форма не совпала бы с
        карточкой источника, и подтверждение превратилось бы в отказ на ровном месте.
        """
        try:
            stored = self._store.load_value(token)
        except MapStoreError as exc:
            raise DetokenizeError("DETOK_STORE_FAILED", exc.message) from exc
        return str(stored or replacement or "").strip()

    def _confirmed(self, parts: list[str]) -> bool:
        """Спросить индекс со-встречаемости; в режиме audit ответ не блокирует.

        # START_CONTRACT: _confirmed
        #   PURPOSE: Один критерий «сочетание подтверждено источником» для пары и для тройки.
        #   INPUTS: { parts: list[str] - части ФИО }
        #   OUTPUTS: { bool - True, когда сочетание можно показывать }
        #   SIDE_EFFECTS: читает индекс и увеличивает счётчики
        #   LINKS: M-NAME-COHERENCE, V-M-NAME-COHERENCE
        # END_CONTRACT: _confirmed
        """
        if self._coherence is None or self._coherence_key is None:
            return True
        answer = self._coherence.confirm(self._coherence_key, parts)
        if answer:
            self._guard_counters["coherence_checked"] += 1
            return True
        if self._coherence_mode == MODE_ENFORCE:
            self._guard_counters["coherence_blocked"] += 1
            return False
        # audit: сочетание считается, инцидент пишется, но значение показывается —
        # этот режим существует ровно для того, чтобы измерить цену заслона до включения.
        self._guard_counters["coherence_unchecked"] += 1
        return True

    def _coherence_blocks(
        self,
        text: str,
        selected: list[tuple[int, int, str, str, str | None]],
        channel: str = "",
        session_id: str = "",
    ) -> set[int]:
        """Найти значения, чьё сочетание источником не подтверждено.

        # START_CONTRACT: _coherence_blocks
        #   PURPOSE: Не допустить на доверенную границу склейку из разных персон (инцидент 20.09.2026: «Ангелина Ветрова»).
        #   INPUTS: { text: str - исходный текст блока, selected: list - отобранные к восстановлению, channel/session_id - для инцидента }
        #   OUTPUTS: { set[int] - позиции в selected, которые восстанавливать нельзя }
        #   SIDE_EFFECTS: читает справочник и индекс, пишет инциденты и счётчики
        #   LINKS: M-NAME-COHERENCE, V-M-DETOKENIZER, V-M-NAME-COHERENCE
        # END_CONTRACT: _coherence_blocks

        Соседними считаются восстановленные значения класса «имена», между которыми только
        пробел (не длиннее COHERENCE_GAP знаков): «Иванов Иван» — соседи, «Иванов / Иван» —
        уже нет. Проверяются все соседние пары и, если в цепочке ровно три значения, тройка:
        карточка подтверждает и пару, и полное ФИО.
        """
        if (
            self._coherence is None
            or self._coherence_key is None
            or self._coherence_mode == MODE_OFF
        ):
            return set()
        refused: set[int] = set()
        run: list[tuple[int, str, int]] = []

        def judge(chain: list[tuple[int, str, int]]) -> None:
            if len(chain) < 2:
                return
            for index in range(len(chain) - 1):
                pair = [chain[index][1], chain[index + 1][1]]
                if not self._confirmed(pair):
                    for position, _part, _end in chain[index : index + 2]:
                        refused.add(position)
                        self._note_incident("P", "name_glue", selected[position][3], 1, channel, session_id)
            if len(chain) == 3:
                triple = [entry[1] for entry in chain]
                if not self._confirmed(triple):
                    for position, _part, _end in chain:
                        refused.add(position)
                        self._note_incident("P", "name_glue", selected[position][3], 1, channel, session_id)

        previous_end: int | None = None
        for position, (start, end, cls, token, replacement) in enumerate(selected):
            part = self._coherence_parts(cls, token, replacement) if cls == "P" else ""
            looks_like_part = cls == "P" and is_part_value(part)
            if not looks_like_part:
                judge(run)
                run = []
                previous_end = None
                continue
            adjacent = (
                previous_end is not None
                and start >= previous_end
                and start - previous_end <= COHERENCE_GAP
                and not text[previous_end:start].strip()
            )
            if not adjacent:
                judge(run)
                run = []
            run.append((position, part, end))
            previous_end = end
        judge(run)
        return refused

    def _replace(
        self,
        text: str,
        allowed: Collection[str] | None = None,
        occurrences: dict[str, int] | None = None,
        channel: str = "",
        session_id: str = "",
    ) -> tuple[str, int, int, int, dict[str, int]]:
        """Replace every known identifier, returning text, three counters and guard counters.

        ``allowed`` is the set of identifiers issued for the request. An
        identifier outside that set is never restored: a made-up or foreign code
        must not be able to inject another client's value (Phase-4 mechanism 2).
        ``None`` restores nothing, so a caller that forgets the set fails closed
        instead of silently bypassing the guard.

        Поверх списка разрешённых кодов стоят два заслона (Phase-17). (1) Многозначный код
        не восстанавливается: если за кодом больше одной персоны, восстановление выдумало бы
        человека. (2) Соседние части ФИО проверяются индексом со-встречаемости: коды выдаются
        на отдельные значения, поэтому модель может написать код чужого человека, и склейка
        «имя одного + фамилия другого» обязана быть отвергнута на доверенной границе.

        ``occurrences`` — счётчик уже отданных вхождений по коду: в потоковом пути
        очередной кусок продолжает порядок предыдущего, иначе падеж выбирался бы
        заново в каждом куске и поток расходился бы с непотоковым ответом.
        """
        replaced = 0
        unknown = 0
        skipped = 0
        ambiguous = 0
        result = text
        counters: dict[str, int] = occurrences if occurrences is not None else {}
        selected: list[tuple[int, int, str, str, str | None]] = []
        for start, end, cls, token in sorted(find_tokens(text), key=lambda item: item[0]):
            index = counters.get(token, 0)
            counters[token] = index + 1
            if allowed is None or token not in allowed:
                skipped += 1
                continue
            if self._ambiguity(token):
                # Многозначный код: значение не восстанавливаем и оставляем код как есть.
                ambiguous += 1
                self._guard_counters["ambiguous_kept"] += 1
                self._note_incident(cls, "ambiguous_kept", token, 1, channel, session_id)
                continue
            selected.append((start, end, cls, token, self._restore_form(cls, token, index)))
        refused = self._coherence_blocks(text, selected, channel, session_id)
        for position in range(len(selected) - 1, -1, -1):
            start, end, _cls, _token, replacement = selected[position]
            if position in refused or replacement is None:
                if replacement is None:
                    unknown += 1
                continue
            result = result[:start] + replacement + result[end:]
            replaced += 1
        result, truncated = _cut_truncated_token(result)
        if truncated:
            unknown += 1
        return result, replaced, unknown, skipped, {
            "ambiguous": ambiguous,
            "glued": len(refused),
        }

    def _restore_form(self, cls: str, token: str, index: int) -> str | None:
        """Выбрать написание для вхождения кода под номером index.

        # START_CONTRACT: _restore_form
        #   PURPOSE: Восстановить ту форму, в которой код встречался в запросе, а не просто «значение».
        #   INPUTS: { cls: str - класс, token: str - канонический код, index: int - номер вхождения в тексте модели }
        #   OUTPUTS: { str | None - написание для замены, None когда значение неизвестно }
        #   SIDE_EFFECTS: читает справочник соответствия
        #   LINKS: M-MAP-STORE, M-NAME-IDENTITY, V-M-DETOKENIZER, V-M-NAME-IDENTITY
        # END_CONTRACT: _restore_form

        Порядок вхождений: i-е вхождение берёт i-ю наблюдённую форму. Если столько форм
        не наблюдалось (код появился или повторился в авторском тексте модели) — отдаётся
        именительный падеж: наблюдённая форма, совпадающая с идентичностью, а при её
        отсутствии — сама идентичность. Ни одно значение не выдумывается.
        """
        try:
            forms = self._store.load_forms(token)
            identity = self._store.load_identity(token)
            value = self._store.load_value(token)
        except MapStoreError as exc:
            raise DetokenizeError("DETOK_STORE_FAILED", exc.message) from exc
        if not forms and value is None and identity is None:
            return None
        if not forms:
            forms = [value] if value else []
        if index < len(forms):
            return forms[index]
        return self._nominative_form(cls, forms, identity, value)

    @staticmethod
    def _nominative_form(
        cls: str, forms: list[str], identity: str | None, value: str | None
    ) -> str:
        """Вернуть именительный падеж значения: наблюдённую основу, иначе сам ключ.

        Ключ (значение из справочника) стоит впереди хранимого написания: если код появился
        в авторском тексте модели, а именительной формы в запросе не было, отдаётся основа
        значения — она и есть именительный падеж. Прежнее поведение сохраняется у записей
        без идентичности: там остаётся хранимое значение.

        Ключ-отпечаток (schema 3) наружу не выходит: он служебный, читаемого значения за ним
        нет, и увидеть его в тексте владелец не должен. В этом случае отдаётся наблюдённое
        написание, а при его отсутствии — первая сохранённая форма.
        """
        for form in forms:
            if identity and matches_identity(cls, form, identity):
                return form
        if identity and not is_digest_identity(identity):
            return identity
        return value or (forms[0] if forms else "")

    def detokenize_text(
        self,
        text: str,
        channel: str | None,
        session_id: str = "",
        allowed: Collection[str] | None = None,
        occurrences: dict[str, int] | None = None,
    ) -> tuple[str, dict[str, int]]:
        """Restore values in final text when the channel allows it.

        # START_CONTRACT: detokenize_text
        #   PURPOSE: Apply the channel decision to user-visible text.
        #   INPUTS: { text: str - model output, channel: str | None - transport channel, session_id: str - audit correlation, allowed: Collection | None - identifiers issued for this request, occurrences: dict[str, int] | None - счётчик вхождений (потоковый путь) }
        #   OUTPUTS: { tuple[str, dict[str, int]] - text and counters }
        #   SIDE_EFFECTS: reads the store, appends audit events
        #   LINKS: M-CHANNEL-POLICY, M-MAP-STORE, V-M-CHANNEL-POLICY, V-M-DETOKENIZER
        # END_CONTRACT: detokenize_text
        """
        if not text:
            return text, {"replaced": 0, "kept": 0, "unknown": 0, "not_in_request": 0}
        tokens = find_tokens(text)
        if self._policy.decide_for_text(channel) != DECISION_DETOKENIZE:
            if tokens and self._audit is not None:
                self._audit.append(
                    AuditEvent(
                        session_id=session_id,
                        action="channel_blocked",
                        direction="outbound",
                        cls="-",
                        count=len(tokens),
                        channel=str(channel or ""),
                        reason="",
                    )
                )
            return text, {"replaced": 0, "kept": len(tokens), "unknown": 0, "not_in_request": 0}
        restored, replaced, unknown, skipped, extra = self._replace(
            text, allowed, occurrences, str(channel or ""), session_id
        )
        if self._audit is not None and replaced:
            self._audit.append(
                AuditEvent(
                    session_id=session_id,
                    action="detokenized",
                    direction="outbound",
                    cls="-",
                    count=replaced,
                    channel=str(channel or ""),
                    reason="",
                )
            )
        return restored, {
            "replaced": replaced,
            "kept": 0,
            "unknown": unknown,
            "not_in_request": skipped,
            **extra,
        }

    def detokenize_string(
        self, text: str, session_id: str = "", allowed: Collection[str] | None = None
    ) -> str:
        """Restore every known token in a string, ignoring channel policy."""
        restored, _, _, _, _ = self._replace(text, allowed)
        return restored

    def _walk_arguments(
        self,
        node: Any,
        session_id: str,
        counters: dict[str, int],
        allowed: Collection[str] | None = None,
    ) -> Any:
        """Restore tokens inside tool arguments, walking JSON embedded strings."""
        if isinstance(node, str):
            tokens = find_tokens(node)
            if not tokens:
                return node
            exact = self._restore_exact_token(node, counters, allowed)
            if exact is not None:
                return exact
            stripped = node.strip()
            if len(stripped) > 2 and stripped[0] in "{[" and stripped[-1] in "}]":
                try:
                    inner = json.loads(stripped)
                except json.JSONDecodeError:
                    inner = None
                if inner is not None:
                    walked = self._walk_arguments(inner, session_id, counters, allowed)
                    return json.dumps(walked, ensure_ascii=False)
            restored, replaced, unknown, skipped, extra = self._replace(
                node, allowed, None, "tool_args", session_id
            )
            counters["replaced"] += replaced
            counters["unknown"] += unknown
            counters["not_in_request"] = counters.get("not_in_request", 0) + skipped
            for key, value in extra.items():
                counters[key] = counters.get(key, 0) + value
            return restored
        if isinstance(node, list):
            return [self._walk_arguments(item, session_id, counters, allowed) for item in node]
        if isinstance(node, dict):
            return {
                key: self._walk_arguments(value, session_id, counters, allowed)
                for key, value in node.items()
            }
        return node

    @staticmethod
    def _coerce(cls: str, value: str) -> Any:
        """Return the value in its original JSON type.

        # START_CONTRACT: _coerce
        #   PURPOSE: Keep tool arguments type-correct after a token replaced a number.
        #   INPUTS: { cls: str - class letter, value: str - stored text }
        #   OUTPUTS: { Any - int for numeric identifiers, str otherwise }
        #   SIDE_EFFECTS: none
        #   LINKS: M-TOKENIZER, V-M-DETOKENIZER
        # END_CONTRACT: _coerce
        """
        if cls in {"C", "T"} and value.isdigit():
            return int(value)
        return value

    def _restore_exact_token(
        self, text: str, counters: dict[str, int], allowed: Collection[str] | None = None
    ) -> Any | None:
        """Restore a string that consists of exactly one token, with type coercion.

        # START_CONTRACT: _restore_exact_token
        #   PURPOSE: Handle the common case where a whole JSON value is one token.
        #   INPUTS: { text: str - candidate string, counters: dict[str, int] - running counters }
        #   OUTPUTS: { Any | None - restored value or None when the string is not a single token }
        #   SIDE_EFFECTS: reads the correspondence table
        #   LINKS: M-MAP-STORE, V-M-DETOKENIZER
        # END_CONTRACT: _restore_exact_token
        """
        try:
            cls, _ = parse_token(text.strip())
        except TokenError:
            return None
        canonical = canonical_token(text.strip())
        if allowed is None or canonical not in allowed:
            counters["not_in_request"] = counters.get("not_in_request", 0) + 1
            return None
        if self._ambiguity(canonical):
            # Многозначный код в аргументе инструмента: значение не подставляем. Счётчик и
            # инцидент пишет общий путь (_replace): иначе одно вхождение считалось бы дважды.
            return None
        try:
            # Look up the canonical string: the surface in the text may be bare or
            # legacy, while bindings are always stored framed.
            forms = self._store.load_forms(canonical)
            value = self._store.load_value(canonical)
            identity = self._store.load_identity(canonical)
        except MapStoreError as exc:
            raise DetokenizeError("DETOK_STORE_FAILED", exc.message) from exc
        if value is None and not forms and identity is None:
            counters["unknown"] += 1
            return None
        counters["replaced"] += 1
        # Целое значение — не текст, а аргумент: падеж здесь неуместен, отдаём основу
        # (именительный падеж), иначе инструмент получил бы «Ивановой» вместо «Иванов».
        return self._coerce(cls, self._nominative_form(cls, forms, identity, value))

    def detokenize_tool_args(
        self,
        payload: dict,
        session_id: str = "",
        allowed: Collection[str] | None = None,
    ) -> tuple[dict, dict[str, int]]:
        """Restore values inside tool-call arguments before execution.

        # START_CONTRACT: detokenize_tool_args
        #   PURPOSE: Let the agent act on real client identifiers.
        #   INPUTS: { payload: dict - response body, session_id: str - audit correlation }
        #   OUTPUTS: { tuple[dict, dict[str, int]] - payload and counters }
        #   SIDE_EFFECTS: reads the store, appends audit events
        #   LINKS: M-CHANNEL-POLICY, V-M-DETOKENIZER
        # END_CONTRACT: detokenize_tool_args
        """
        counters = {"replaced": 0, "unknown": 0, "not_in_request": 0}
        for choice in payload.get("choices", []) or []:
            message = choice.get("message") or {}
            for call in message.get("tool_calls") or []:
                function = call.get("function") or {}
                if isinstance(function.get("arguments"), str):
                    tokens = find_tokens(function["arguments"])
                    if tokens:
                        function["arguments"] = self._walk_arguments(
                            function["arguments"], session_id, counters, allowed
                        )
            if message.get("function_call") and isinstance(message["function_call"].get("arguments"), str):
                tokens = find_tokens(message["function_call"]["arguments"])
                if tokens:
                    message["function_call"]["arguments"] = self._walk_arguments(
                        message["function_call"]["arguments"], session_id, counters, allowed
                    )
        if self._audit is not None and counters["replaced"]:
            self._audit.append(
                AuditEvent(
                    session_id=session_id,
                    action="detokenized",
                    direction="outbound",
                    cls="-",
                    count=counters["replaced"],
                    channel="tool_args",
                    reason="",
                )
            )
        return payload, counters

    def detokenize_response(
        self,
        payload: dict,
        channel: str | None,
        session_id: str = "",
        allowed: Collection[str] | None = None,
    ) -> tuple[dict, dict[str, int]]:
        """Restore tool arguments (always) and text (per policy) in a response.

        # START_CONTRACT: detokenize_response
        #   PURPOSE: Single entry point used by the router after upstream.
        #   INPUTS: { payload: dict - response body, channel: str | None, session_id: str, allowed: Collection | None - identifiers issued for this request }
        #   OUTPUTS: { tuple[dict, dict[str, int]] - response and counters }
        #   SIDE_EFFECTS: reads the store, appends audit events
        #   LINKS: M-ROUTER, V-M-TOKENIZER, V-M-DETOKENIZER
        # END_CONTRACT: detokenize_response
        """
        totals = {
            "replaced": 0,
            "kept": 0,
            "unknown": 0,
            "not_in_request": 0,
            "tool_args_replaced": 0,
        }
        payload, args_counters = self.detokenize_tool_args(payload, session_id, allowed)
        totals["tool_args_replaced"] = args_counters["replaced"]
        totals["not_in_request"] += args_counters.get("not_in_request", 0)
        for choice in payload.get("choices", []) or []:
            message = choice.get("message") or {}
            content = message.get("content")
            if isinstance(content, str) and find_tokens(content):
                message["content"], counters = self.detokenize_text(
                    content, channel, session_id, allowed
                )
                for key, value in counters.items():
                    totals[key] = totals.get(key, 0) + value
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        if find_tokens(part["text"]):
                            part["text"], counters = self.detokenize_text(
                                part["text"], channel, session_id, allowed
                            )
                            for key, value in counters.items():
                                totals[key] = totals.get(key, 0) + value
        return payload, totals
# END_BLOCK_DETOKENIZE_TEXT


# START_BLOCK_DETOKENIZE_STREAM
class StreamDetokenizer:
    """Incremental detokenizer that never emits a half token.

    # START_CONTRACT: StreamDetokenizer
    #   PURPOSE: Detokenize an SSE stream while holding back a tail buffer.
    #   INPUTS: { detokenizer: PayloadDetokenizer, channel: str | None, session_id: str, allowed: Collection | None, hold: int - жёсткий предел удержания, boundary: Callable[[str, int], int] - критерий подтверждённой позиции }
    #   OUTPUTS: { StreamDetokenizer - feed/flush API }
    #   SIDE_EFFECTS: reads the store through the wrapped detokenizer
    #   LINKS: M-STREAM-RELAY, M-TOKEN-GEN, M-ROUTER, V-M-UPSTREAM
    # END_CONTRACT: StreamDetokenizer

    Критерий разреза здесь не вычисляется: его задаёт вызывающий (M-STREAM-RELAY,
    ``confirmed_position``), поэтому правило подтверждённой позиции живёт в одном месте.
    Аргумент обязателен намеренно: забытый критерий обязан падать сразу, а не давать тихий
    неверный разрез, из-за которого код уедет клиенту недостроенным.
    """

    def __init__(
        self,
        detokenizer: PayloadDetokenizer,
        channel: str | None,
        session_id: str = "",
        allowed: Collection[str] | None = None,
        hold: int = STREAM_HOLD,
        *,
        boundary: Callable[[str, int], int],
    ) -> None:
        self._detokenizer = detokenizer
        self._channel = channel
        self._session_id = session_id
        # Streaming obeys the same gate as buffered responses: only identifiers
        # that were in the request may be restored mid-stream.
        self._identifiers = allowed
        self._hold = hold
        self._boundary = boundary
        self._buffer = ""
        # Последний отданный знак: по нему проверяется левый просмотр назад у кода на
        # стыке кусков, иначе «XzP…» разобралось бы иначе, чем в непотоковом пути.
        self._left = ""
        # Порядок вхождений по коду продолжается через куски: без этого падеж выбирался
        # бы заново в каждом куске, и поток разошёлся бы с непотоковым ответом.
        self._occurrences: dict[str, int] = {}
        self._decided = detokenizer._policy.decide_for_text(channel)
        self._allowed = self._decided == DECISION_DETOKENIZE

    def feed(self, chunk: str) -> str:
        """Accept a chunk and return the safe part to forward."""
        if not chunk:
            return ""
        self._buffer += chunk
        if not self._allowed:
            emitted, self._buffer = self._buffer, ""
            return self._release(emitted)
        cut = self._boundary(self._buffer, self._hold)
        emit, self._buffer = self._buffer[:cut], self._buffer[cut:]
        return self._release(emit)

    def flush(self) -> str:
        """Return whatever is still held back, detokenized."""
        if not self._buffer:
            return ""
        pending, self._buffer = self._buffer, ""
        return self._release(pending, final=True)

    def _hold_tail(self, full: str, text: str, context: str) -> int | None:
        """Сколько знаков конца куска удержать, чтобы пара ФИО не разошлась по кускам.

        # START_CONTRACT: _hold_tail
        #   PURPOSE: Не оставить стык кусков слепым пятном заслона связности.
        #   INPUTS: { full: str - левый знак плюс кусок, text: str - кусок, context: str - левый знак }
        #   OUTPUTS: { int | None - сколько знаков куска вернуть в буфер, None когда удерживать нечего }
        #   SIDE_EFFECTS: none
        #   LINKS: M-STREAM-RELAY, M-NAME-COHERENCE, V-M-STREAM-RELAY
        # END_CONTRACT: _hold_tail

        Правило простое и узкое: если кусок заканчивается значением-именем (или пробелами после
        него), это значение возвращается в буфер вместе с соседом слева — тогда в следующем
        вызове заслон увидит пару целиком. Без этого склейка прошла бы ровно на стыке кусков, а
        канал Mattermost работает потоком (инцидент 20.09.2026 шёл именно потоком). Удержание
        ограничено двумя кодами и пробелом между ними, поэтому поток не «залипает».
        """
        tokens = [item for item in find_tokens(full) if item[2] == "P"]
        if not tokens:
            return None
        last = tokens[-1]
        if full[last[1] :].strip():
            return None
        start = last[0]
        if len(tokens) >= 2:
            previous = tokens[-2]
            if not full[previous[1] : start].strip():
                start = previous[0]
        cut = start - len(context)
        # Ноль — тоже удержание: кусок целиком состоит из кода и пробела, а сосед придёт
        # следующим кадром. Отдать значение сейчас — значит отдать его без проверки пары.
        # Отрицательный разрез означает, что код начался в предыдущем куске: он уже отдан.
        return None if cut < 0 else cut

    def _release(self, text: str, final: bool = False) -> str:
        """Отдать кусок клиенту, сохранив левый контекст кода.

        # START_CONTRACT: _release
        #   PURPOSE: Не потерять левый символ на стыке кусков и не отдать наполовину восстановленное значение.
        #   INPUTS: { text: str - подтверждённый кусок }
        #   OUTPUTS: { str - кусок для клиента }
        #   SIDE_EFFECTS: читает справочник через обёрнутый детокенизатор
        #   LINKS: M-STREAM-RELAY, M-DETOKENIZER, V-M-STREAM-RELAY
        # END_CONTRACT: _release

        Левый символ предыдущего куска подставляется при детокенизации и снимается после:
        так просмотр назад у кода на стыке совпадает с непотоковым путём. Сам символ
        заменой быть не может — критерий подтверждённой позиции не пускает разрез внутрь
        кода; если это всё-таки произошло, поток закрывается ошибкой, а не отдаётся
        обрезанное значение.
        """
        if not text:
            return ""
        context, self._left = self._left, text[-1:]
        if not self._allowed:
            return text
        if not final:
            held_from = self._hold_tail(context + text, text, context)
            if held_from is not None:
                held = text[held_from:]
                text = text[:held_from]
                # Удержанное возвращается в буфер: следующий кусок соберёт пару целиком.
                self._buffer = held + self._buffer
                self._left = (context + text)[-1:]
                if not text:
                    return ""
        restored, _ = self._detokenizer.detokenize_text(
            context + text, self._channel, self._session_id, self._identifiers, self._occurrences
        )
        if context and not restored.startswith(context):
            raise DetokenizeError("STREAM_CONTEXT_LOST", "левый символ куска попал в замену")
        return restored[len(context):]
# END_BLOCK_DETOKENIZE_STREAM


# The helper lives outside the class on purpose: parking a module-level function
# between two methods silently detached detokenize_text and the stream buffer from
# the class body (caught by the type checker, 15.09.2026).
def _cut_truncated_token(text: str) -> tuple[str, bool]:
    """Replace a half-arrived token at the very end of a text.

    # START_CONTRACT: _cut_truncated_token
    #   PURPOSE: Keep a truncated answer readable instead of showing token debris.
    #   INPUTS: { text: str - restored text }
    #   OUTPUTS: { tuple[str, bool] - text, whether a cut token was found }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DETOKENIZER, V-M-DETOKENIZER
    # END_CONTRACT: _cut_truncated_token
    """
    match = TRUNCATED_TOKEN_PATTERN.search(text)
    if match is None:
        return text, False
    return text[: match.start()] + TRUNCATION_PLACEHOLDER, True
