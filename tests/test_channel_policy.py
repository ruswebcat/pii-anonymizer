# FILE: tests/test_channel_policy.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-CHANNEL-POLICY contract: a named allowlist restores only the listed channels, the all-channels marker restores any channel, channels outside the perimeter are always refused, and tool arguments are always restored.
#   SCOPE: allowlist, all-channels marker, blocking of outside-the-perimeter channels, fail-closed unknown channel in allowlist mode, tool-argument decision, policy violation rejection.
#   DEPENDS: M-CHANNEL-POLICY
#   LINKS: V-M-CHANNEL-POLICY, M-CHANNEL-POLICY
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   ChannelPolicyTests - unittest case set for ChannelPolicy
#   AllChannelsPolicyTests - правило «любой канал» и безусловный запрет каналов вне контура
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.1.0 - решение владельца 25.09.2026: умолчание публичной сборки — «любой канал». Проверка держит обе стороны: правило «любой канал» восстанавливает в неопознанном канале, а канал вне контура отвергается при любом правиле.
#   PREVIOUS: v1.0.0 - Phase-1 M-CHANNEL-POLICY verification.
# END_CHANGE_SUMMARY

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.channel_policy import (  # noqa: E402
    CHANNEL_ALL,
    DECISION_DETOKENIZE,
    DECISION_KEEP,
    ChannelPolicy,
    ChannelPolicyError,
)


class ChannelPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = ChannelPolicy({"mattermost", "local"})

    def test_mattermost_is_allowed(self) -> None:
        self.assertEqual(self.policy.decide_for_text("mattermost"), DECISION_DETOKENIZE)
        self.assertTrue(self.policy.is_allowed("Mattermost"))

    def test_local_file_is_allowed(self) -> None:
        self.assertEqual(self.policy.decide_for_text("local"), DECISION_DETOKENIZE)

    def test_telegram_is_kept(self) -> None:
        self.assertEqual(self.policy.decide_for_text("telegram"), DECISION_KEEP)

    def test_unknown_channel_is_kept(self) -> None:
        for channel in ("", None, "signal", "carrier-pigeon"):
            self.assertEqual(self.policy.decide_for_text(channel), DECISION_KEEP, msg=str(channel))

    def test_tool_arguments_always_restored(self) -> None:
        self.assertEqual(self.policy.decide_for_tool_args(), DECISION_DETOKENIZE)

    def test_telegram_can_never_be_configured_as_allowed(self) -> None:
        with self.assertRaises(ChannelPolicyError) as ctx:
            ChannelPolicy({"mattermost", "telegram"})
        self.assertEqual(ctx.exception.code, "CHANNEL_POLICY_VIOLATION")

    def test_allowed_channels_property_is_frozen(self) -> None:
        allowed = self.policy.allowed_channels
        self.assertEqual(allowed, frozenset({"mattermost", "local"}))

    def test_named_list_does_not_allow_all_channels(self) -> None:
        self.assertFalse(self.policy.allows_all_channels)


class AllChannelsPolicyTests(unittest.TestCase):
    """Правило «любой канал» (умолчание публичной сборки, решение владельца 25.09.2026).

    Умолчание выбрано для обобщённого продукта, который не знает имён каналов своего оператора.
    Проверка держит и другую сторону решения: канал вне контура не становится доверенным ни при
    каком правиле — иначе умолчание отменило бы границу ответственности оператора.
    """

    def setUp(self) -> None:
        self.policy = ChannelPolicy({CHANNEL_ALL})

    def test_unknown_channel_is_restored(self) -> None:
        for channel in ("mattermost", "signal", "carrier-pigeon", "web"):
            self.assertEqual(
                self.policy.decide_for_text(channel), DECISION_DETOKENIZE, msg=str(channel)
            )

    def test_unidentified_channel_is_restored_under_the_all_channels_rule(self) -> None:
        """Обобщённый продукт не знает имён каналов: неизвестный канал получает значения."""
        for channel in (None, ""):
            self.assertEqual(self.policy.decide_for_text(channel), DECISION_DETOKENIZE)

    def test_channels_outside_the_perimeter_are_still_refused(self) -> None:
        for channel in ("telegram", "WhatsApp", "viber", "SMS", "Email"):
            self.assertEqual(
                self.policy.decide_for_text(channel), DECISION_KEEP, msg=str(channel)
            )

    def test_the_marker_can_be_combined_with_named_channels(self) -> None:
        policy = ChannelPolicy({CHANNEL_ALL, "mattermost"})
        self.assertTrue(policy.allows_all_channels)
        self.assertEqual(frozenset({"mattermost"}), policy.allowed_channels)

    def test_a_channel_outside_the_perimeter_can_never_be_added_to_the_rule(self) -> None:
        with self.assertRaises(ChannelPolicyError) as ctx:
            ChannelPolicy({CHANNEL_ALL, "telegram"})
        self.assertEqual(ctx.exception.code, "CHANNEL_POLICY_VIOLATION")

    def test_tool_arguments_are_still_always_restored(self) -> None:
        self.assertEqual(self.policy.decide_for_tool_args(), DECISION_DETOKENIZE)


if __name__ == "__main__":
    unittest.main()
