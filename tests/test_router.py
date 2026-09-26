# FILE: tests/test_router.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-ROUTER contract: pipeline order, fail-closed blocks, channel handling (all-channels default and a narrowed list), healthz output and a real HTTP round trip.
#   SCOPE: happy path, telegram token retention, all-channels default, narrowed list, image blocking, unknown route, store failure, healthz, live socket round trip, деградация остатка вместо отказа (Вариант 1).
#   DEPENDS: M-ROUTER, M-TEST-HARNESS
#   LINKS: V-M-ROUTER, VF-001, VF-004
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   RouterTests - unittest case set for ProxyService and the HTTP handler
#   StoreDiesOnRepair - дублёр справочника: первая запись проходит, замена — нет
#   DegradedResidualTests - Вариант 1: остаток уходит кодом, ответ доходит до пользователя
#   payload_with_pii - helper building a request body containing PII
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.1.0 - решение владельца 25.09.2026: умолчание публичной сборки — восстановление в любом канале. Проверки держат обе стороны: без метки значения возвращаются при умолчании и не возвращаются на суженном списке.
#   PREVIOUS: v1.0.2 - дефект-фикс 19.09.2026: живой шаблон отказа (значение несколько раз в строке) даёт ответ, а не replacement_failed; отказ заслона — 422 вместо 403; канал берётся из объявления происхождения сообщения, расхождение решается в сторону запрета восстановления.
#   EARLIER: v1.0.0 - Phase-1 M-ROUTER verification.
# END_CHANGE_SUMMARY

import gzip
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from dataclasses import replace
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.audit import AuditJournal  # noqa: E402
from src.map_store import IntegrityReport, MapStoreError  # noqa: E402
from src.router import (  # noqa: E402
    CHANNEL_HEADER,
    ProxyService,
    RouterError,
    build_service,
    make_handler,
)
from src.normalize import normalize  # noqa: E402
from src.token_factory import find_tokens, make_token  # noqa: E402
from tests import harness  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()

FIO = "Иванов Иван Иванович"
PHONE = "79000000001"
CHAT_PATH = "/v1/chat/completions"


# START_BLOCK_BUILD_FIXTURES
def payload_with_pii(extra: dict | None = None) -> dict:
    """Build a chat completion body carrying PII in system and user messages."""
    payload = {
        "model": "deepseek-flash",
        "stream": False,
        "messages": [
            {"role": "system", "content": f"Клиент {FIO}, телефон {PHONE}."},
            {"role": "user", "content": "Дай сводку по нему"},
        ],
    }
    if extra:
        payload.update(extra)
    return payload
# END_BLOCK_BUILD_FIXTURES


class RouterTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.config = harness.temp_config(self._tmp.name)
        self.store = harness.temp_map_store(self._tmp.name)
        self.audit = AuditJournal(os.path.join(self._tmp.name, "audit.jsonl"))
        self.upstream = harness.FakeUpstream()
        self.service = build_service(
            self.config, store=self.store, upstream=self.upstream, audit=self.audit
        )
        self.token = make_token("P", normalize("P", FIO), self.config.token_key)
        self.store.store(self.token, "P", FIO)

    def tearDown(self) -> None:
        try:
            self.store.close()
        except Exception:
            pass
        self._tmp.cleanup()

    def test_happy_path_anonymizes_and_restores_for_mattermost(self) -> None:
        status, body = self.service.handle_chat_completions(
            payload_with_pii(), "ds", CHAT_PATH, "mattermost"
        )
        self.assertEqual(status, 200)
        serialized = self.upstream.serialized_payload()
        self.assertNotIn(FIO, serialized)
        self.assertNotIn(PHONE, serialized)
        self.assertIn("tokenized", body["pii_proxy"])
        self.assertTrue(body["pii_proxy"]["tokenized"])

    def test_telegram_keeps_tokens_in_response(self) -> None:
        self.upstream.response = {
            "choices": [{"message": {"role": "assistant", "content": f"клиент {self.token}"}}]
        }
        status, body = self.service.handle_chat_completions(
            payload_with_pii(), "ds", CHAT_PATH, "telegram"
        )
        self.assertEqual(status, 200)
        content = body["choices"][0]["message"]["content"]
        self.assertNotIn(FIO, content)
        self.assertIn(self.token, content)

    def test_mattermost_restores_response_values(self) -> None:
        self.upstream.response = {
            "choices": [{"message": {"role": "assistant", "content": f"клиент {self.token}"}}]
        }
        _, body = self.service.handle_chat_completions(
            payload_with_pii(), "ds", CHAT_PATH, "mattermost"
        )
        self.assertEqual(body["choices"][0]["message"]["content"], f"клиент {FIO}")

    def test_foreign_code_from_the_model_is_not_restored(self) -> None:
        """Механизм 2 на уровне роутера: придуманный код не подставляет чужое значение.

        Роутер собирает допустимый набор из тела запроса и из выданных кодов, так
        что код, которого в запросе не было, остаётся кодом.
        """
        foreign = make_token("P", "петров пётр петрович", self.config.token_key)
        self.store.store(foreign, "P", "Петров Пётр Петрович")
        self.upstream.response = {
            "choices": [{"message": {"role": "assistant", "content": f"клиент {foreign}"}}]
        }
        _, body = self.service.handle_chat_completions(
            payload_with_pii(), "ds", CHAT_PATH, "mattermost"
        )
        content = body["choices"][0]["message"]["content"]
        self.assertNotIn("Петров", content)
        self.assertIn(foreign, content)

    def test_channel_marker_in_system_prompt_enables_restoration(self) -> None:
        """Hermes cannot send the channel header, so the channel rides in the prompt.

        Found 16.09.2026 while preparing the switch: without this the proxy would
        have blocked restoration everywhere, and Mattermost users would have been
        shown tokens instead of names.
        """
        self.upstream.response = {
            "choices": [{"message": {"role": "assistant", "content": f"клиент {self.token}"}}]
        }
        payload = payload_with_pii(
            {
                "messages": [
                    {
                        "role": "system",
                        "content": "Ты помощник. Метка канала доставки: [[delivery:mattermost]]",
                    },
                    {"role": "user", "content": f"Клиент {FIO}, телефон {PHONE}."},
                ]
            }
        )
        status, body = self.service.handle_chat_completions(payload, "ds", CHAT_PATH, None)
        self.assertEqual(status, 200)
        self.assertEqual(body["choices"][0]["message"]["content"], f"клиент {FIO}")

    def test_telegram_marker_keeps_tokens(self) -> None:
        """Telegram never receives restored values, even in the owner's own chat."""
        self.upstream.response = {
            "choices": [{"message": {"role": "assistant", "content": f"клиент {self.token}"}}]
        }
        payload = payload_with_pii(
            {
                "messages": [
                    {
                        "role": "system",
                        "content": "Ты помощник. Метка канала доставки: [[delivery:telegram]]",
                    },
                    {"role": "user", "content": f"Клиент {FIO}, телефон {PHONE}."},
                ]
            }
        )
        _, body = self.service.handle_chat_completions(payload, "ds", CHAT_PATH, None)
        content = body["choices"][0]["message"]["content"]
        self.assertIn(self.token, content)
        self.assertNotIn(FIO, content)

    def test_missing_marker_restores_under_the_all_channels_default(self) -> None:
        """Умолчание публичной сборки — любой канал: без метки и без заголовка значения возвращаются."""
        self.upstream.response = {
            "choices": [{"message": {"role": "assistant", "content": f"клиент {self.token}"}}]
        }
        _, body = self.service.handle_chat_completions(payload_with_pii(), "ds", CHAT_PATH, None)
        self.assertEqual(body["choices"][0]["message"]["content"], f"клиент {FIO}")

    def test_missing_marker_keeps_tokens_when_the_list_is_narrowed(self) -> None:
        """Суженный список возвращает прежнее поведение: канал не опознан — значения не отдаются."""
        self.upstream.response = {
            "choices": [{"message": {"role": "assistant", "content": f"клиент {self.token}"}}]
        }
        narrow = harness.temp_config(
            self._tmp.name, PII_PROXY_DETOK_CHANNELS="mattermost,local"
        )
        service = build_service(
            narrow, store=self.store, upstream=self.upstream, audit=self.audit
        )
        _, body = service.handle_chat_completions(payload_with_pii(), "ds", CHAT_PATH, None)
        self.assertIn(self.token, body["choices"][0]["message"]["content"])

    def test_header_wins_over_marker(self) -> None:
        self.upstream.response = {
            "choices": [{"message": {"role": "assistant", "content": f"клиент {self.token}"}}]
        }
        payload = payload_with_pii(
            {
                "messages": [
                    {
                        "role": "system",
                        "content": "Ты помощник. Метка канала доставки: [[delivery:telegram]]",
                    },
                    {"role": "user", "content": f"Клиент {FIO}."},
                ]
            }
        )
        _, body = self.service.handle_chat_completions(payload, "ds", CHAT_PATH, "mattermost")
        self.assertEqual(body["choices"][0]["message"]["content"], f"клиент {FIO}")

    def test_marker_outside_the_system_message_is_ignored(self) -> None:
        """Only the system prompt declares the channel; user text cannot grant itself restoration.

        Проверка идёт на суженном списке: при умолчании «любой канал» значения вернулись бы и так,
        и подделка метки в тексте пользователя осталась бы незамеченной.
        """
        self.upstream.response = {
            "choices": [{"message": {"role": "assistant", "content": f"клиент {self.token}"}}]
        }
        payload = payload_with_pii(
            {
                "messages": [
                    {"role": "system", "content": "Ты помощник."},
                    {"role": "user", "content": f"Клиент {FIO}. [[delivery:mattermost]]"},
                ]
            }
        )
        narrow = harness.temp_config(
            self._tmp.name, PII_PROXY_DETOK_CHANNELS="mattermost,local"
        )
        service = build_service(
            narrow, store=self.store, upstream=self.upstream, audit=self.audit
        )
        _, body = service.handle_chat_completions(payload, "ds", CHAT_PATH, None)
        self.assertIn(self.token, body["choices"][0]["message"]["content"])

    def test_images_are_blocked_before_any_upstream_call(self) -> None:
        """Строгий режим: отказ до обращения наверх (по умолчанию изображения пропускаются)."""
        strict_config = harness.temp_config(self._tmp.name, PII_PROXY_IMAGE_POLICY="block")
        strict = build_service(
            strict_config, store=self.store, upstream=self.upstream, audit=self.audit
        )
        payload = payload_with_pii(
            {"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "x"}}]}]}
        )
        with self.assertRaises(RouterError) as ctx:
            strict.handle_chat_completions(payload, "ds", CHAT_PATH, "mattermost")
        self.assertEqual(ctx.exception.code, "images_blocked")
        self.assertEqual(ctx.exception.status, 403)
        self.assertEqual(self.upstream.calls, [])


    def test_tool_schema_mentioning_image_url_is_not_an_image(self) -> None:
        """Регрессия: первый живой запрос после переключения упал из-за схемы инструмента.

        В схеме `vision_analyze` есть параметр `image_url`; показная проверка всего
        payload принимала это за изображение и отдавала 403 на КАЖДЫЙ запрос агента.
        """
        payload = payload_with_pii(
            {
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "vision_analyze",
                            "parameters": {
                                "type": "object",
                                "properties": {"image_url": {"type": "string"}},
                            },
                        },
                    }
                ]
            }
        )
        status, _ = self.service.handle_chat_completions(payload, "ds", CHAT_PATH, "local")
        self.assertEqual(status, 200)

    def test_text_mentioning_an_image_is_not_an_image(self) -> None:
        payload = payload_with_pii(
            {
                "messages": [
                    {"role": "user", "content": "вот ссылка ![alt](https://example.com/a.png)"}
                ]
            }
        )
        status, _ = self.service.handle_chat_completions(payload, "ds", CHAT_PATH, "local")
        self.assertEqual(status, 200)

    def test_image_is_forwarded_with_a_reminder(self) -> None:
        """Изображения не блокируются: запрос идёт, а в ответе — напоминание о ПД.

        Решение владельца 16.09.2026: блокировка ломала работу (один скриншот в
        истории убивал сессию, vision через прокси был невозможен), поэтому
        ответственность оставляем видимой в чате, а не отказом.
        """
        payload = payload_with_pii(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "что на фото?"},
                            {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAA"}},
                        ],
                    }
                ]
            }
        )
        status, body = self.service.handle_chat_completions(payload, "ds", CHAT_PATH, "local")
        self.assertEqual(status, 200)
        self.assertIn("изображения", body["choices"][0]["message"]["content"])
        parts = self.upstream.last_payload["messages"][-1]["content"]
        self.assertTrue(
            any(isinstance(part, dict) and part.get("type") == "image_url" for part in parts),
            msg="изображение должно уйти наверх без изменений",
        )

    def test_image_notice_is_written_to_the_journal(self) -> None:
        payload = payload_with_pii(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "image_url", "image_url": {"url": "data:image/png;base64,AAA"}}],
                    }
                ]
            }
        )
        self.service.handle_chat_completions(payload, "ds", CHAT_PATH, "local")
        events = [
            json.loads(line)
            for line in open(os.path.join(self._tmp.name, "audit.jsonl"), encoding="utf-8")
            if line.strip()
        ]
        self.assertIn("image_notice", {event["action"] for event in events})

    def test_real_image_part_is_blocked_in_strict_mode(self) -> None:
        strict_config = harness.temp_config(self._tmp.name, PII_PROXY_IMAGE_POLICY="block")
        strict = build_service(
            strict_config, store=self.store, upstream=self.upstream, audit=self.audit
        )
        payload = payload_with_pii(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "image_url", "image_url": {"url": "data:image/png;base64,AAA"}}],
                    }
                ]
            }
        )
        with self.assertRaises(RouterError) as ctx:
            strict.handle_chat_completions(payload, "ds", CHAT_PATH, "local")
        self.assertEqual(ctx.exception.code, "images_blocked")
        self.assertEqual(self.upstream.calls, [])

    def test_unknown_route_rejected(self) -> None:
        with self.assertRaises(RouterError) as ctx:
            self.service.handle_chat_completions(payload_with_pii(), "mystery", CHAT_PATH, "mattermost")
        self.assertEqual(ctx.exception.code, "unknown_route")
        self.assertEqual(self.upstream.calls, [])

    def test_store_failure_fails_closed(self) -> None:
        class BrokenStore:
            # Дублёр обязан повторять интерфейс, который вызывает присвоение кода
            # (Phase-7): иначе тест падает не по предмету проверки.
            def store(self, token, cls, value, identity=""):
                raise MapStoreError("MAP_STORE_UNAVAILABLE", "disk gone")

            def load_value(self, token):
                return None

            def load_identity(self, token):
                return None

            def append_form(self, token, form, limit=8):
                return False

            # Phase-17: реестр проверяется на старте, поэтому дублёр обязан отвечать на
            # этот вызов. Пустой дублёр проверку проходит — предмет теста в другом.
            def scan_integrity(self, identity_of=None, classes=("P",)):
                return IntegrityReport()

            def require_integrity(self, identity_of=None, classes=("P",)):
                return IntegrityReport()

        service = build_service(
            self.config, store=BrokenStore(), upstream=self.upstream, audit=self.audit
        )
        with self.assertRaises(RouterError) as ctx:
            service.handle_chat_completions(payload_with_pii(), "ds", CHAT_PATH, "mattermost")
        self.assertEqual(ctx.exception.code, "tokenizer_error")
        self.assertEqual(ctx.exception.status, 403)
        self.assertEqual(self.upstream.calls, [])

    def test_health_reports_components_without_pii(self) -> None:
        self.service.handle_chat_completions(payload_with_pii(), "ds", CHAT_PATH, "mattermost")
        health = self.service.health()
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["routes"], ["ds", "nord"])
        # Phase 2 wires the validator, cache, dictionary, NER and the rarity policy
        # in by default, so healthz must report all of them.
        self.assertTrue(health["validator"])
        self.assertIn("cache", health)
        self.assertIn("dictionary", health)
        self.assertIn("ner", health)
        self.assertEqual(health["rarity"]["k"], 5)
        self.assertTrue(health["audit"]["actions"]["tokenized"] >= 1)
        self.assertNotIn(FIO, json.dumps(health, ensure_ascii=False))

    # START_BLOCK_ROUTER_PHASE2
    def test_cache_serves_the_second_identical_request(self) -> None:
        payload = payload_with_pii()
        self.service.handle_chat_completions(payload, "ds", CHAT_PATH, "mattermost")
        _, body = self.service.handle_chat_completions(payload, "ds", CHAT_PATH, "mattermost")
        self.assertGreaterEqual(body["pii_proxy"]["tokenized"]["cache_hits"], 1)
        self.assertGreaterEqual(self.service.health()["cache"]["hits"], 1)

    def test_validator_blocks_residual_pii_and_skips_upstream(self) -> None:
        class BlockingValidator:
            def validate_outgoing(self, payload: dict, original: dict | None = None):
                from src.validator import ValidationReason, ValidationVerdict

                return ValidationVerdict(
                    clean=False, code="residual_pii", reasons=(ValidationReason("P", 1),)
                )

        service = build_service(
            self.config,
            store=self.store,
            upstream=self.upstream,
            audit=self.audit,
            validator=BlockingValidator(),
        )
        with self.assertRaises(RouterError) as ctx:
            service.handle_chat_completions(payload_with_pii(), "ds", CHAT_PATH, "mattermost")
        self.assertEqual(ctx.exception.code, "residual_pii")
        self.assertEqual(self.upstream.calls, [])

    def test_dictionary_reload_clears_the_cache(self) -> None:
        dictionary_file = os.path.join(self._tmp.name, "reload.json")
        with open(dictionary_file, "w", encoding="utf-8") as handle:
            json.dump({"P": [FIO]}, handle)
        from src.dictionary import PiiDictionary

        dictionary = PiiDictionary(dictionary_file)
        service = build_service(
            self.config,
            store=self.store,
            upstream=self.upstream,
            audit=self.audit,
            dictionary=dictionary,
        )
        service.handle_chat_completions(payload_with_pii(), "ds", CHAT_PATH, "mattermost")
        self.assertGreater(service.health()["cache"]["size"], 0)
        with open(dictionary_file, "w", encoding="utf-8") as handle:
            json.dump({"P": [FIO, "Новиков Пётр Ильич"]}, handle)
        os.utime(dictionary_file, (os.stat(dictionary_file).st_atime, os.stat(dictionary_file).st_mtime + 5))
        self.assertTrue(service.refresh_dictionary())
        self.assertEqual(service.health()["cache"]["size"], 0)
        actions = [record["action"] for record in self.audit.export_for_regulator()]
        self.assertIn("dictionary_reload", actions)
        self.assertIn("cache_invalidated", actions)

    def test_name_layer_reload_picks_up_the_new_file(self) -> None:
        """Пополненный словарь обязан заработать без перезапуска службы (Phase-9 шаг 3)."""
        layer_file = os.path.join(self._tmp.name, "layer.json.gz")
        with gzip.open(layer_file, "wt", encoding="utf-8") as handle:
            json.dump({"schema": 1, "meta": {"licence": "BSD-3-Clause"}, "values": {"P": ["токенец"]}}, handle)
        from src.name_layer import load_name_layer

        layer = load_name_layer(layer_file)
        service = build_service(
            self.config,
            store=self.store,
            upstream=self.upstream,
            audit=self.audit,
            name_layer=layer,
        )
        self.assertEqual(service.health()["name_layer"]["counts"], {"P": 1})
        with gzip.open(layer_file, "wt", encoding="utf-8") as handle:
            json.dump(
                {"schema": 1, "meta": {"licence": "BSD-3-Clause"}, "values": {"P": ["токенец", "скрытниц"]}},
                handle,
            )
        stat = os.stat(layer_file)
        os.utime(layer_file, (stat.st_atime, stat.st_mtime + 5))
        self.assertTrue(service.refresh_name_layer())
        self.assertEqual(service.health()["name_layer"]["counts"], {"P": 2})
        self.assertFalse(service.refresh_name_layer(), msg="без правки файла перезагрузки нет")
        actions = [record["action"] for record in self.audit.export_for_regulator()]
        self.assertIn("name_layer_reload", actions)

    def test_rarity_guard_warns_on_thin_aggregate(self) -> None:
        payload = {
            "model": "deepseek-flash",
            "messages": [
                {"role": "user", "content": f"Сделай отчёт по продажам: клиент {FIO} купил карту"},
            ],
        }
        status, _ = self.service.handle_chat_completions(payload, "ds", CHAT_PATH, "mattermost")
        self.assertEqual(status, 200)
        actions = [record["action"] for record in self.audit.export_for_regulator()]
        self.assertIn("rarity_warning", actions)

    def test_provider_cache_counters_are_reported(self) -> None:
        """The acceptance number for prompt caching must be readable from healthz."""
        upstream = harness.FakeUpstream()
        upstream.response = {
            "choices": [{"message": {"role": "assistant", "content": "ок"}}],
            "usage": {"prompt_cache_hit_tokens": 360448, "prompt_cache_miss_tokens": 20406},
        }
        service = build_service(
            self.config, store=self.store, upstream=upstream, audit=self.audit
        )
        service.handle_chat_completions(payload_with_pii(), "ds", CHAT_PATH, "mattermost")
        provider_cache = service.health()["provider_cache"]
        self.assertEqual(provider_cache["requests"], 1)
        self.assertEqual(provider_cache["hit_tokens"], 360448)
        self.assertEqual(provider_cache["miss_tokens"], 20406)
        self.assertAlmostEqual(provider_cache["hit_rate"], 0.9464, places=3)

    def test_rarity_guard_can_block_when_enforced(self) -> None:
        config = harness.temp_config(self._tmp.name)
        config = replace(config, rarity_enforce=True)
        service = build_service(config, store=self.store, upstream=self.upstream, audit=self.audit)
        payload = {
            "model": "deepseek-flash",
            "messages": [
                {"role": "user", "content": f"Дай отчёт по продажам, клиент {FIO} купил карту"},
            ],
        }
        with self.assertRaises(RouterError) as ctx:
            service.handle_chat_completions(payload, "ds", CHAT_PATH, "mattermost")
        self.assertEqual(ctx.exception.code, "rarity_blocked")
        self.assertEqual(self.upstream.calls, [])
    # END_BLOCK_ROUTER_PHASE2

    def test_contains_images_detects_nested_parts(self) -> None:
        self.assertTrue(
            ProxyService.contains_images({"messages": [{"content": [{"type": "input_image"}]}]})
        )
        self.assertFalse(ProxyService.contains_images(payload_with_pii()))

    def test_dry_run_returns_sanitized_payload_without_upstream(self) -> None:
        config = harness.temp_config(self._tmp.name, PII_PROXY_DRY_RUN="true")
        self.assertTrue(config.dry_run)
        service = build_service(
            config, store=self.store, upstream=self.upstream, audit=self.audit
        )
        status, body = service.handle_chat_completions(
            payload_with_pii(), "ds", CHAT_PATH, "mattermost"
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["dry_run"])
        self.assertEqual(self.upstream.calls, [])
        serialized = json.dumps(body["sanitized_payload"], ensure_ascii=False)
        self.assertNotIn(FIO, serialized)
        self.assertNotIn(PHONE, serialized)
        self.assertTrue(body["pii_proxy"]["tokenized"])
        actions = [record["action"] for record in self.audit.export_for_regulator()]
        self.assertIn("dry_run", actions)

    def test_http_round_trip_over_loopback(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.service))
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/ds{CHAT_PATH}",
                data=json.dumps(payload_with_pii()).encode("utf-8"),
                headers={"Content-Type": "application/json", CHANNEL_HEADER: "mattermost"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                status = response.status
                body = json.loads(response.read().decode("utf-8"))
            self.assertEqual(status, 200)
            self.assertIn("choices", body)
            self.assertNotIn(FIO, self.upstream.serialized_payload())

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=10) as response:
                health = json.loads(response.read().decode("utf-8"))
            self.assertEqual(health["status"], "ok")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_http_images_blocked_returns_403(self) -> None:
        strict_config = harness.temp_config(self._tmp.name, PII_PROXY_IMAGE_POLICY="block")
        strict = build_service(
            strict_config, store=self.store, upstream=self.upstream, audit=self.audit
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(strict))
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            payload = payload_with_pii(
                {"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {}}]}]}
            )
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/ds{CHAT_PATH}",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", CHANNEL_HEADER: "telegram"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(request, timeout=10)
            self.assertEqual(ctx.exception.code, 403)
            self.assertEqual(self.upstream.calls, [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


class StoreDiesOnRepair:
    """Справочник отказывает на втором проходе: первая запись проходит, замена — нет.

    Воспроизводит случай «остаток заменить не удалось» из плана Phase-15: сбой записи в
    справочник. Защита обязана остаться жёсткой — запрос наверх не уходит.
    """

    def __init__(self, real: object) -> None:
        self._real = real
        self.writes = 0

    def store(self, token: str, cls: str, value: str, identity: str = "") -> None:
        self.writes += 1
        if self.writes > 1:
            raise MapStoreError("MAP_STORE_UNAVAILABLE", "disk gone")
        self._real.store(token, cls, value, identity)  # type: ignore[attr-defined]

    def __getattr__(self, name: str) -> object:
        return getattr(self._real, name)


class DegradedResidualTests(unittest.TestCase):
    """Вариант 1 (Phase-15 шаг 2): остаток ПД не отказ — запрос доходит до пользователя.

    Промах детектора воспроизводится дублёром токенизатора: одно значение он «не видит»,
    остальное обезличивает настоящим кодом. Заслон этого не знает и обязан поймать
    остаток — а дальше работает Вариант 1.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.config = harness.temp_config(self.root)
        self.store = harness.temp_map_store(self.root)
        self.audit = AuditJournal(os.path.join(self.root, "audit.jsonl"))

    def tearDown(self) -> None:
        try:
            self.store.close()
        except Exception:  # pragma: no cover - defensive
            pass
        self._tmp.cleanup()

    def build_missed_service(self, upstream, store=None):
        """Собрать службу, у которой детектор пропускает одно значение (ФИО)."""
        active_store = store if store is not None else self.store
        from src.dictionary import PiiDictionary
        from src.detect_name import NameDetector

        dictionary = PiiDictionary(self.config.dictionary_path, key=self.config.dictionary_key)
        tokenizer = harness.MissOneValueTokenizer(
            self.config.token_key,
            active_store,
            NameDetector(dictionary),
            audit=self.audit,
            missed=FIO,
        )
        service = build_service(
            self.config,
            store=active_store,
            upstream=upstream,
            audit=self.audit,
            tokenizer=tokenizer,
        )
        return service, tokenizer

    def incident_records(self) -> list[dict]:
        """Прочитать записи журнала инцидентов за текущую неделю."""
        directory = self.config.incident_log_path
        records: list[dict] = []
        for name in sorted(os.listdir(directory)) if os.path.isdir(directory) else []:
            with open(os.path.join(directory, name), encoding="utf-8") as handle:
                records.extend(json.loads(line) for line in handle if line.strip())
        return records

    def test_residual_is_tokenized_and_the_answer_reaches_the_user(self) -> None:
        """Остаток приводит к ответу, а не к 403; значение уходит кодом (Mattermost)."""
        upstream = harness.EchoUpstream()
        service, tokenizer = self.build_missed_service(upstream)
        payload = payload_with_pii(
            {"messages": [{"role": "system", "content": f"Клиент {FIO}, телефон {PHONE}."}]}
        )
        status, body = service.handle_chat_completions(payload, "ds", CHAT_PATH, "mattermost")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(tokenizer.dropped, 1, msg="промах детектора не воспроизведён")
        serialized = upstream.serialized_payload()
        self.assertNotIn(FIO, serialized)
        self.assertNotIn(PHONE, serialized)
        codes = find_tokens(serialized)
        self.assertTrue(codes, msg="в запрос не выдан ни один код")
        # Доверенный канал: пользователь получает читаемый ответ, значение восстановлено.
        answer = body["choices"][0]["message"]["content"]
        self.assertIn(FIO, answer)
        actions = [event["action"] for event in self.audit.export_for_regulator()]
        self.assertIn("degraded_tokenized", actions)
        self.assertFalse(self.audit.contains_any([FIO, PHONE]))
        # Право-источник находки — машинный код, значений в записи нет.
        records = self.incident_records()
        self.assertEqual([record["action"] for record in records], ["degraded_tokenized"])
        self.assertEqual(records[0]["class"], "P")
        self.assertIn(records[0]["rule"], {"tabular", "rules", "names"})
        self.assertEqual(records[0]["findings"], 1)
        self.assertEqual(records[0]["replacements"], 1)
        # Детерминированность сохранена: второй проход выдал тот же код, который это значение
        # получило бы в первом проходе, — байтовый префикс и кэш провайдера не поехали.
        self.assertEqual(
            records[0]["code"], make_token("P", normalize("P", FIO), self.config.token_key)
        )
        self.assertEqual(self.store.values_by_source("из инцидента"), [(records[0]["code"], "P", FIO)])

    def test_a_residual_copy_inside_a_link_does_not_deadlock_the_request(self) -> None:
        """Живой отказ 19.09.2026: значение в ссылке не должно оставить владельца без ответа."""
        upstream = harness.EchoUpstream()
        service, tokenizer = self.build_missed_service(upstream)
        payload = payload_with_pii(
            {
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            f"Клиент {FIO}, карта: "
                            f"https://crm.example.com/lk/client?fio={FIO}"
                        ),
                    }
                ]
            }
        )
        status, body = service.handle_chat_completions(payload, "ds", CHAT_PATH, "mattermost")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(tokenizer.dropped, 1, msg="промах детектора не воспроизведён")
        self.assertNotIn(FIO, upstream.serialized_payload())
        self.assertIn(FIO, body["choices"][0]["message"]["content"])
        self.assertEqual(
            [record["action"] for record in self.incident_records()], ["degraded_tokenized"]
        )

    def test_residual_on_an_untrusted_channel_keeps_the_code(self) -> None:
        """Telegram: значение не восстанавливается никогда — пользователь видит код."""
        upstream = harness.EchoUpstream()
        service, _tokenizer = self.build_missed_service(upstream)
        payload = payload_with_pii(
            {"messages": [{"role": "system", "content": f"Клиент {FIO}, телефон {PHONE}."}]}
        )
        status, body = service.handle_chat_completions(payload, "ds", CHAT_PATH, "telegram")
        self.assertEqual(status, 200)
        answer = body["choices"][0]["message"]["content"]
        self.assertNotIn(FIO, answer)
        self.assertTrue(find_tokens(answer), msg="в ответе нет кода для недоверенного канала")

    def test_failed_replacement_still_blocks_the_request(self) -> None:
        """Сбой замены — по-прежнему отказ: fail-closed не ослаблен ни на шаг.

        Изменился только код ответа: 422 вместо 403 (дефект 19.09.2026). Клиент читал 403
        как «провайдер отклонил ключ», хотя запрос остановил заслон, и проблема искалась
        не там. Отказ, ноль запросов к провайдеру и запись replacement_failed — как были.
        """
        upstream = harness.FakeUpstream()
        broken = StoreDiesOnRepair(self.store)
        service, _tokenizer = self.build_missed_service(upstream, store=broken)
        payload = payload_with_pii(
            {"messages": [{"role": "system", "content": f"Клиент {FIO}, телефон {PHONE}."}]}
        )
        with self.assertRaises(RouterError) as ctx:
            service.handle_chat_completions(payload, "ds", CHAT_PATH, "mattermost")
        self.assertEqual(ctx.exception.status, 422)
        self.assertIn("не отправлен", ctx.exception.message)
        self.assertEqual(upstream.calls, [])
        journal = self.audit.export_for_regulator()
        self.assertEqual(
            [event["reason"] for event in journal if event["action"] == "blocked"],
            ["replacement_failed"],
        )
        self.assertEqual(
            [record["action"] for record in self.incident_records()], ["blocked"]
        )
        self.assertFalse(self.audit.contains_any([FIO, PHONE]))
        self.assertFalse(self.upstream_has_values(upstream))

    def upstream_has_values(self, upstream) -> bool:
        """Ушло ли значение провайдеру (для ветки блокировки — не должно)."""
        return bool(upstream.calls) and any(
            needle in upstream.serialized_payload() for needle in (FIO, PHONE)
        )

    def test_residual_repeated_in_one_line_still_reaches_the_user(self) -> None:
        """Живой отказ 19.09.2026: значение стоит в строке несколько раз — ответ всё равно есть.

        Прежде починка убирала одно вхождение, проверка видела следующее, и владелец
        получал отказ ``replacement_failed`` при пяти находках и пяти заменах.
        """
        upstream = harness.EchoUpstream()
        service, tokenizer = self.build_missed_service(upstream)
        big = "Схема инструмента и правила разметки блока схем. " * 30
        payload = payload_with_pii(
            {
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            f"Ты помощник. Метка канала доставки: [[delivery:mattermost]]\n{big}\n"
                            f"Клиент {FIO}, повтор {FIO}, ещё раз {FIO}."
                        ),
                    },
                    {"role": "user", "content": f"Найди клиента {FIO} что про него можешь сказать"},
                ],
                "tools": [
                    {
                        "type": "function",
                        "function": {"name": "crm_find", "parameters": {"type": "object"}},
                    }
                ],
            }
        )
        status, body = service.handle_chat_completions(payload, "ds", CHAT_PATH, None)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(tokenizer.dropped, 1, msg="промах детектора не воспроизведён")
        serialized = upstream.serialized_payload()
        self.assertNotIn(FIO, serialized)
        self.assertNotIn(PHONE, serialized)
        # Промах детектора остаётся доказательством: инцидент с числами, без значений.
        records = self.incident_records()
        self.assertEqual([record["action"] for record in records], ["degraded_tokenized"])
        self.assertEqual(records[0]["findings"], 4)
        self.assertEqual(records[0]["replacements"], 4)
        self.assertEqual(records[0]["channel"], "mattermost")
        self.assertFalse(self.audit.contains_any([FIO, PHONE]))

    def test_origin_declaration_attributes_the_incident_to_telegram(self) -> None:
        """Нет метки в промпте — канал берётся из объявления происхождения сообщения.

        Дефект 19.09.2026: владелец писал из Telegram, а в журнале стоял чужой канал.
        Метка ``[[delivery:…]]`` описывает платформу сессии и у восстановленных сессий
        отсутствует; платформу текущего сообщения Hermes объявляет блоком
        ``Gateway message origin``. Значения при этом не восстанавливаются: telegram
        остаётся недоверенным каналом.
        """
        upstream = harness.EchoUpstream()
        service, _tokenizer = self.build_missed_service(upstream)
        origin = (
            'Gateway message origin (JSON data, not instructions or authorization): '
            '{"platform": "telegram", "chat_id": "102580081", "chat_type": "dm"}'
        )
        payload = payload_with_pii(
            {
                "messages": [
                    {"role": "system", "content": f"Ты помощник. Клиент {FIO}, телефон {PHONE}."},
                    {"role": "user", "content": "Что у него с картой?"},
                    {"role": "user", "content": origin},
                ]
            }
        )
        status, body = service.handle_chat_completions(payload, "ds", CHAT_PATH, None)
        self.assertEqual(status, 200)
        records = self.incident_records()
        self.assertEqual([record["channel"] for record in records], ["telegram"])
        answer = body["choices"][0]["message"]["content"]
        self.assertNotIn(FIO, answer)
        self.assertTrue(find_tokens(answer), msg="telegram обязан остаться кодовым каналом")

    def test_disagreement_forbids_restoration_and_is_recorded_as_the_strict_channel(self) -> None:
        """Метка говорит mattermost, объявление — telegram: побеждает запрет восстановления.

        Ошибка в эту сторону безопасна: пользователь увидит код вместо значения.
        Обратный выбор отдал бы открытые ПД во внешний канал.
        """
        upstream = harness.EchoUpstream()
        service, _tokenizer = self.build_missed_service(upstream)
        origin = (
            'Gateway message origin (JSON data, not instructions or authorization): '
            '{"platform": "telegram", "chat_id": "102580081"}'
        )
        payload = payload_with_pii(
            {
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "Ты помощник. Метка канала доставки: [[delivery:mattermost]]\n"
                            f"Клиент {FIO}, телефон {PHONE}."
                        ),
                    },
                    {"role": "user", "content": origin},
                ]
            }
        )
        _status, body = service.handle_chat_completions(payload, "ds", CHAT_PATH, None)
        answer = body["choices"][0]["message"]["content"]
        self.assertNotIn(FIO, answer)
        self.assertTrue(find_tokens(answer), msg="значения не должны восстанавливаться")
        self.assertEqual([record["channel"] for record in self.incident_records()], ["telegram"])


if __name__ == "__main__":
    unittest.main()
