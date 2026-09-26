# FILE: src/channel_policy.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Decide per transport channel whether final text may be detokenized, while tool-call arguments are always restored.
#   SCOPE: allowlist or all-channels text decision, unconditional tool-argument decision, hard ban on channels outside the perimeter.
#   DEPENDS: M-CONFIG
#   LINKS: M-CHANNEL-POLICY, V-M-CHANNEL-POLICY, fn-decide_for_text, fn-decide_for_tool_args
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   CHANNEL_ALL - признак «восстанавливать в любом канале»
#   DECISION_DETOKENIZE - restore real values
#   DECISION_KEEP - keep tokens in the text
#   BLOCKED_CHANNELS - channels that may never be detokenized
#   ChannelPolicy - decision maker for text and tool arguments
#   fn-decide_for_text - decision for a transport channel
#   fn-decide_for_tool_args - decision for tool arguments
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.1.0 - решение владельца 25.09.2026: умолчание публичной сборки — восстановление в ЛЮБОМ канале (признак «*»), и список каналов стал настройкой. Запрет на каналы вне контура (внешние мессенджеры) остаётся безусловным при любом умолчании: это не удобство, а граница ответственности оператора.
#   PREVIOUS: v1.0.0 - Phase-1 M-CHANNEL-POLICY: owner decision of 15.09.2026 (Mattermost only, Telegram never).
# END_CHANGE_SUMMARY

"""Channel detokenization policy.

Implements M-CHANNEL-POLICY from docs/ARCHITECTURE.md. The owner decided on
15.09.2026 that final text may be restored only inside the operator's perimeter;
on 25.09.2026 the owner set the *public build* default to every channel, because
a generic product cannot know its operator's channel names. The list of channels
is therefore configuration (``detok_channels`` / ``PII_PROXY_DETOK_CHANNELS``),
where an empty value or the explicit marker ``*`` means "any channel".

The hard rule survives the permissive default: channels that carry data out of
the perimeter (external messengers) are never detokenized and cannot be
configured as allowed. Operators who care more about privacy than convenience
must narrow the list to their own trusted channels, as docs/PRIVACY.md says.
"""

from __future__ import annotations

from collections.abc import Iterable

LOGGER_NAME = "ChannelPolicy"
LOG_MARKER = "[ChannelPolicy][decide_for_text][BLOCK_DECIDE_CHANNEL]"

#: Признак «восстанавливать в любом канале»: значение настройки ``detok_channels``.
CHANNEL_ALL = "*"

DECISION_DETOKENIZE = "detokenize"
DECISION_KEEP = "keep"

BLOCKED_CHANNELS = frozenset({"telegram", "whatsapp", "viber", "sms", "email"})


class ChannelPolicyError(ValueError):
    """Policy misuse, for example attempting to allow a blocked channel.

    # START_CONTRACT: ChannelPolicyError
    #   PURPOSE: Refuse a policy configuration that contradicts the owner decision.
    #   INPUTS: { code: str - stable code, message: str - detail }
    #   OUTPUTS: { ChannelPolicyError - exception instance }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CHANNEL-POLICY, V-M-CHANNEL-POLICY
    # END_CONTRACT: ChannelPolicyError
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# START_BLOCK_DECIDE_CHANNEL
class ChannelPolicy:
    """Decide whether a channel may receive restored values.

    # START_CONTRACT: ChannelPolicy
    #   PURPOSE: Hold the detokenization rule — an explicit allowlist or the all-channels marker — and answer per channel.
    #   INPUTS: { allowed_channels: Iterable[str] - каналы, где восстановление разрешено; «*» означает любой канал }
    #   OUTPUTS: { ChannelPolicy - ready policy }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CONFIG, M-DETOKENIZER, V-M-CHANNEL-POLICY
    # END_CONTRACT: ChannelPolicy

    Пустой список означает «ни один канал» (fail-closed), а не «любой»: «любой» задаётся
    явным признаком ``CHANNEL_ALL``. Так значение настройки видно в healthz и в журнале, и
    его нельзя получить случайно, забыв заполнить строку.
    """

    def __init__(self, allowed_channels: Iterable[str]) -> None:
        given = {str(channel).strip().lower() for channel in allowed_channels if channel}
        blocked = given & BLOCKED_CHANNELS
        if blocked:
            raise ChannelPolicyError(
                "CHANNEL_POLICY_VIOLATION",
                f"channels may never be detokenized: {sorted(blocked)}",
            )
        self._all = CHANNEL_ALL in given
        self._allowed = given - {CHANNEL_ALL}

    @property
    def allows_all_channels(self) -> bool:
        """Сказать, действует ли правило «любой канал» (без учёта каналов вне контура)."""
        return self._all

    @property
    def allowed_channels(self) -> frozenset[str]:
        """Return the allowlist as a frozen set (без признака «любой канал»)."""
        return frozenset(self._allowed)

    def is_allowed(self, channel: str | None) -> bool:
        """Return True when the channel may receive restored values.

        # START_CONTRACT: is_allowed
        #   PURPOSE: Single place where the channel decision is derived.
        #   INPUTS: { channel: str | None - transport channel name }
        #   OUTPUTS: { bool - True when allowed }
        #   SIDE_EFFECTS: none
        #   LINKS: V-M-CHANNEL-POLICY
        # END_CONTRACT: is_allowed

        Канал вне контура отвергается **первым** и при любом правиле: безусловный запрет
        важнее удобства умолчания. Неопознанный канал (``None`` или пустая строка) при
        правиле «любой канал» получает значения: публичная сборка не может знать имён каналов
        своего оператора, и владелец выбрал это умолчание 25.09.2026.
        """
        name = str(channel).strip().lower() if channel else ""
        if name in BLOCKED_CHANNELS:
            return False
        if self._all:
            return True
        if not name:
            return False
        return name in self._allowed

    def decide_for_text(self, channel: str | None) -> str:
        """Return the decision for final text on the given channel.

        # START_CONTRACT: decide_for_text
        #   PURPOSE: Keep or restore values in user-visible text.
        #   INPUTS: { channel: str | None - transport channel name }
        #   OUTPUTS: { str - DECISION_DETOKENIZE or DECISION_KEEP }
        #   SIDE_EFFECTS: none
        #   LINKS: M-DETOKENIZER, V-M-CHANNEL-POLICY
        # END_CONTRACT: decide_for_text
        """
        return DECISION_DETOKENIZE if self.is_allowed(channel) else DECISION_KEEP

    def decide_for_tool_args(self) -> str:
        """Return the decision for tool-call arguments (always restore).

        # START_CONTRACT: decide_for_tool_args
        #   PURPOSE: Let the agent query CRM with real identifiers.
        #   INPUTS: none
        #   OUTPUTS: { str - always DECISION_DETOKENIZE }
        #   SIDE_EFFECTS: none
        #   LINKS: M-DETOKENIZER, V-M-DETOKENIZER
        # END_CONTRACT: decide_for_tool_args
        """
        return DECISION_DETOKENIZE
# END_BLOCK_DECIDE_CHANNEL
