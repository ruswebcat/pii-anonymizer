# FILE: tests/test_alert_sender.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the alert senders: Telegram is preferred when a chat is configured, Mattermost is the fallback, and a delivery failure never breaks the pipeline.
#   SCOPE: sender selection, request shape (chat_id, message_thread_id, JSON body), quiet failure.
#   DEPENDS: src/router.py, src/config.py
#   LINKS: M-ROUTER, M-CONFIG, V-M-ROUTER
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   AlertSenderTests - sender selection and request feeding without network access
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-18 (23.09.2026): проверки алертов; в тестах только заглушки, ни одного настоящего значения.
# END_CHANGE_SUMMARY
"""Alerts must reach the owner and must never break the pipeline."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from types import SimpleNamespace  # noqa: E402
from typing import Any  # noqa: E402

from src.router import _make_alert_sender, _make_telegram_sender  # noqa: E402

# START_BLOCK_TEST_ALERT_SENDER
STUB_TOKEN = "stub-token-value"
STUB_CHAT = "100000001"
STUB_THREAD = "200001"


def make_config(**overrides: object) -> Any:
    """Настройки только в той части, которую читают отправители: в тестах — заглушки.

    Отправитель зависит от четырёх полей (Telegram) и трёх (Mattermost), поэтому держим
    ровно их, а не весь ProxyConfig: тест не должен требовать ключевых файлов и путей.
    """
    base: dict[str, object] = {
        "alert_url": None,
        "alert_token": None,
        "alert_channel": None,
        "alert_telegram_token": None,
        "alert_telegram_chat": None,
        "alert_telegram_thread": None,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class AlertSenderTests(unittest.TestCase):
    """Выбор канала и форма запроса — без обращения к сети."""

    def setUp(self) -> None:
        self.requests: list[dict] = []

        class StubResponse:
            status = 200

            def __enter__(self) -> "StubResponse":
                return self

            def __exit__(self, *_: object) -> bool:
                return False

        def fake_urlopen(request, timeout=None):  # noqa: ANN001 - заглушка сети
            self.requests.append(
                {
                    "url": request.full_url,
                    "method": request.method,
                    "body": json.loads((request.data or b"{}").decode("utf-8")),
                    "headers": dict(request.headers),
                }
            )
            return StubResponse()

        import src.router as router_module

        self._original = router_module.urllib.request.urlopen
        router_module.urllib.request.urlopen = fake_urlopen
        self.addCleanup(setattr, router_module.urllib.request, "urlopen", self._original)

    def test_no_channel_configured_gives_no_sender(self) -> None:
        self.assertIsNone(_make_alert_sender(make_config()))

    def test_telegram_sender_posts_to_the_configured_chat_and_topic(self) -> None:
        config = make_config(
            alert_telegram_token=STUB_TOKEN,
            alert_telegram_chat=STUB_CHAT,
            alert_telegram_thread=STUB_THREAD,
        )
        sender = _make_telegram_sender(config)
        self.assertIsNotNone(sender)
        sender("проверка алерта")  # type: ignore[misc]
        self.assertEqual(1, len(self.requests))
        sent = self.requests[0]
        self.assertEqual(f"https://api.telegram.org/bot{STUB_TOKEN}/sendMessage", sent["url"])
        self.assertEqual(STUB_CHAT, sent["body"]["chat_id"])
        self.assertEqual(int(STUB_THREAD), sent["body"]["message_thread_id"])
        self.assertIn("проверка алерта", sent["body"]["text"])

    def test_telegram_wins_over_mattermost_when_both_configured(self) -> None:
        config = make_config(
            alert_telegram_token=STUB_TOKEN,
            alert_telegram_chat=STUB_CHAT,
            alert_url="https://chat.example.test",
            alert_token="stub-mattermost",
            alert_channel="stub-channel",
        )
        sender = _make_alert_sender(config)
        sender("отказ")  # type: ignore[misc]
        self.assertIn("api.telegram.org", self.requests[0]["url"])

    def test_mattermost_is_used_when_telegram_is_not_configured(self) -> None:
        config = make_config(
            alert_url="https://chat.example.test",
            alert_token="stub-mattermost",
            alert_channel="stub-channel",
        )
        sender = _make_alert_sender(config)
        self.assertIsNotNone(sender)
        sender("отказ")  # type: ignore[misc]
        sent = self.requests[0]
        self.assertTrue(sent["url"].endswith("/api/v4/posts"))
        self.assertEqual("stub-channel", sent["body"]["channel_id"])

    def test_delivery_failure_does_not_raise(self) -> None:
        import src.router as router_module

        def exploding_urlopen(request, timeout=None):  # noqa: ANN001 - заглушка сбоя
            raise OSError("сеть недоступна")

        router_module.urllib.request.urlopen = exploding_urlopen
        sender = _make_telegram_sender(
            make_config(alert_telegram_token=STUB_TOKEN, alert_telegram_chat=STUB_CHAT)
        )
        sender("отказ")  # type: ignore[misc]  # не должно бросить исключение

    def test_thread_is_optional(self) -> None:
        sender = _make_telegram_sender(
            make_config(alert_telegram_token=STUB_TOKEN, alert_telegram_chat=STUB_CHAT)
        )
        sender("отказ")  # type: ignore[misc]
        self.assertNotIn("message_thread_id", self.requests[0]["body"])
# END_BLOCK_TEST_ALERT_SENDER


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
