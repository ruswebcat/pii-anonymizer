# FILE: tests/test_config.py
# VERSION: 1.2.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the M-CONFIG contract: valid environment yields a frozen config and every unsafe input aborts startup.
#   SCOPE: happy path, missing provider key, key file permissions, non-loopback bind, detokenization channels (all-channels default, explicit list, marker, refusal of channels outside the perimeter), service lexicon intake, invalid route and TTL.
#   DEPENDS: M-CONFIG
#   LINKS: V-M-CONFIG, M-CONFIG
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   ConfigTests - unittest case set for load_config
#   DetokChannelsConfigTests - каналы восстановления: умолчание «любой канал» и явный список
#   OwnVocabularyConfigTests - своя лексика организации из настроек
#   ServiceLexiconConfigTests - служебная лексика оператора из настроек
#   TrustedClientsConfigTests - доверенные клиенты и поведение для неизвестного клиента
#   make_env - helper building a valid environment with temporary key files
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.2.0 - решение владельца 26.09.2026: раздел trusted_clients (три способа опознания) и настройка unknown_client с безопасным умолчанием; проверены обе стороны настройки и отказ на противоречивой таблице.
#   PREVIOUS: v1.1.0 - решения владельца 25.09.2026: каналы восстановления читаются из настроек с умолчанием «любой канал», появился раздел service_lexicon. Добавлены проверки обеих сторон умолчания и отказа на канале вне контура.
#   PREVIOUS: v1.0.0 - Phase-1 M-CONFIG verification.
# END_CHANGE_SUMMARY

import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.channel_policy import UNKNOWN_KEEP_CODES, UNKNOWN_RESTORE  # noqa: E402
from src.client_identity import fingerprint  # noqa: E402
from src.config import ConfigError, ProxyConfig, load_config  # noqa: E402


# START_BLOCK_BUILD_FIXTURES
def make_env(tmpdir: str, **overrides) -> dict:
    """Build a valid environment mapping with real key files on disk."""
    token_key = os.path.join(tmpdir, "token.key")
    fernet_key = os.path.join(tmpdir, "fernet.key")
    dict_key = os.path.join(tmpdir, "dict.key")
    with open(token_key, "wb") as handle:
        handle.write(b"k" * 32)
    with open(fernet_key, "wb") as handle:
        handle.write(b"f" * 32)
    with open(dict_key, "wb") as handle:
        handle.write(b"d" * 32)
    for path in (token_key, fernet_key, dict_key):
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    env = {
        "DEEPSEEK_API_KEY": "ds-secret",
        "NORDROUTER_API_KEY": "nord-secret",
        "PII_PROXY_TOKEN_KEY_FILE": token_key,
        "PII_PROXY_FERNET_KEY_FILE": fernet_key,
        "PII_PROXY_DICT_KEY_FILE": dict_key,
        "PII_PROXY_MAP_DB": os.path.join(tmpdir, "pii_map.db"),
        "PII_PROXY_DICT": os.path.join(tmpdir, "pii_dict.json"),
        "PII_PROXY_AUDIT_LOG": os.path.join(tmpdir, "audit.jsonl"),
    }
    env.update(overrides)
    return env
# END_BLOCK_BUILD_FIXTURES


class ConfigTests(unittest.TestCase):
    def test_valid_environment_yields_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = load_config(make_env(tmpdir))
        self.assertIsInstance(cfg, ProxyConfig)
        self.assertEqual(cfg.host, "127.0.0.1")
        self.assertEqual(cfg.port, 8791)
        self.assertEqual(cfg.ttl_days, 90)
        self.assertEqual(cfg.routes["ds"], "https://api.deepseek.com")
        self.assertEqual(cfg.provider_keys["nord"], "nord-secret")
        # Изображения по умолчанию пропускаются с напоминанием (решение 16.09.2026).
        self.assertEqual(cfg.image_policy, "allow")
        self.assertFalse(cfg.block_images)
        # Умолчание публичной сборки — «любой канал» (решение владельца 25.09.2026).
        self.assertTrue(cfg.detok_all_channels)
        self.assertEqual(frozenset({"*"}), cfg.detok_channels)

    def test_config_is_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = load_config(make_env(tmpdir))
        with self.assertRaises(Exception):
            cfg.port = 1  # type: ignore[misc]

    def test_missing_provider_key_aborts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = make_env(tmpdir)
            del env["DEEPSEEK_API_KEY"]
            with self.assertRaises(ConfigError) as ctx:
                load_config(env)
        self.assertEqual(ctx.exception.code, "CONFIG_MISSING_KEY")

    def test_dry_run_does_not_require_provider_keys(self) -> None:
        """A rehearsing instance must start without credentials (found 15.09.2026)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env = make_env(tmpdir)
            del env["DEEPSEEK_API_KEY"]
            env["PII_PROXY_DRY_RUN"] = "true"
            config = load_config(env)
        self.assertTrue(config.dry_run)
        self.assertEqual(config.provider_keys["ds"], "")

    def test_trailing_comment_in_env_file_is_tolerated(self) -> None:
        """systemd keeps inline comments inside the value; parsing must survive it."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env = make_env(tmpdir)
            env["PII_PROXY_DRY_RUN"] = "true   # репетиция, боевой режим отдельно"
            config = load_config(env)
        self.assertTrue(config.dry_run)

    def test_missing_dictionary_key_falls_back_with_a_warning(self) -> None:
        """The fallback keeps old installs alive but must be visible."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env = make_env(tmpdir)
            del env["PII_PROXY_DICT_KEY_FILE"]
            config = load_config(env)
        self.assertEqual(config.dictionary_key, config.token_key)
        self.assertIn("dictionary_key_fallback_to_token_key", config.extra["warnings"])

    def test_dictionary_key_is_separate_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = make_env(tmpdir)
            config = load_config(env)
        self.assertNotEqual(config.dictionary_key, config.token_key)

    def test_world_readable_key_file_aborts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = make_env(tmpdir)
            os.chmod(env["PII_PROXY_TOKEN_KEY_FILE"], 0o644)
            with self.assertRaises(ConfigError) as ctx:
                load_config(env)
        self.assertEqual(ctx.exception.code, "CONFIG_KEY_FILE_PERMISSIONS")

    def test_missing_key_file_aborts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = make_env(tmpdir)
            env["PII_PROXY_FERNET_KEY_FILE"] = os.path.join(tmpdir, "absent.key")
            with self.assertRaises(ConfigError) as ctx:
                load_config(env)
        self.assertEqual(ctx.exception.code, "CONFIG_KEY_FILE_MISSING")

    def test_non_loopback_bind_aborts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = make_env(tmpdir, PII_PROXY_HOST="0.0.0.0")
            with self.assertRaises(ConfigError) as ctx:
                load_config(env)
        self.assertEqual(ctx.exception.code, "CONFIG_NON_LOCAL_BIND")

    def test_telegram_never_allowed_as_detokenization_channel(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = make_env(tmpdir, PII_PROXY_DETOK_CHANNELS="mattermost,telegram")
            with self.assertRaises(ConfigError) as ctx:
                load_config(env)
        self.assertEqual(ctx.exception.code, "CONFIG_CHANNEL_POLICY_VIOLATION")

    def test_non_https_route_aborts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            overlay = os.path.join(tmpdir, "overlay.json")
            with open(overlay, "w", encoding="utf-8") as handle:
                handle.write('{"routes": {"ds": "http://insecure.example/v1"}}')
            with self.assertRaises(ConfigError) as ctx:
                load_config(make_env(tmpdir), config_path=overlay)
        self.assertEqual(ctx.exception.code, "CONFIG_INVALID_ROUTE")

    def test_invalid_ttl_aborts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = make_env(tmpdir, PII_PROXY_TTL_DAYS="0")
            with self.assertRaises(ConfigError) as ctx:
                load_config(env)
        self.assertEqual(ctx.exception.code, "CONFIG_INVALID_TTL")

    def test_overlay_can_add_route_with_own_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            overlay = os.path.join(tmpdir, "overlay.json")
            with open(overlay, "w", encoding="utf-8") as handle:
                handle.write(
                    '{"routes": {"ds": "https://api.deepseek.com/v1", '
                    '"local": "https://llm.example.com/v1"}}'
                )
            env = make_env(tmpdir, LOCAL_API_KEY="local-secret")
            cfg = load_config(env, config_path=overlay)
        self.assertEqual(cfg.provider_keys["local"], "local-secret")


class OwnVocabularyConfigTests(unittest.TestCase):
    """Своя лексика организации приходит из настроек: в коде её нет.

    Проверка держит главное обещание публичной сборки — другой оператор заполняет пример
    конфигурации и получает работающий контур, не правя исходники.
    """

    def test_absent_configuration_leaves_the_lexicon_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = load_config(make_env(tmpdir))
        self.assertTrue(cfg.own_vocabulary.is_empty())
        self.assertEqual(frozenset(), cfg.own_vocabulary.terms)

    def test_lexicon_comes_from_the_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = load_config(
                make_env(
                    tmpdir,
                    PII_PROXY_OWN_TERMS="Пример Спорт,Примерск",
                    PII_PROXY_OWN_ADDRESSES="б-р Садовая 3а",
                    PII_PROXY_OWN_PHONES="+7 (8481) 000-011",
                    PII_PROXY_OWN_SERVICE_OBJECTS="CRM",
                )
            )
        self.assertIn("пример спорт", cfg.own_vocabulary.terms)
        self.assertIn("примерск", cfg.own_vocabulary.terms)
        self.assertIn("б-р садовая 3а", cfg.own_vocabulary.addresses)
        # Номер свернулся к 7-форме: сравнение идёт по цифрам, формат записи не важен.
        self.assertEqual(frozenset({"78481000011"}), cfg.own_vocabulary.phones)
        self.assertIn("crm", cfg.own_vocabulary.service_objects)

    def test_lexicon_comes_from_a_json_overlay(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            overlay = os.path.join(tmpdir, "config.json")
            with open(overlay, "w", encoding="utf-8") as handle:
                json.dump(
                    {"own_vocabulary": {"terms": ["Пример Спорт"], "phones": ["79001110011"]}},
                    handle,
                    ensure_ascii=False,
                )
            cfg = load_config(make_env(tmpdir), config_path=overlay)
        self.assertIn("пример спорт", cfg.own_vocabulary.terms)
        self.assertEqual(frozenset({"79001110011"}), cfg.own_vocabulary.phones)

    def test_yaml_overlay_loads_when_the_parser_is_available(self) -> None:
        """Пример настроек с комментариями — YAML; он читается, когда разборщик установлен."""
        try:
            import yaml  # type: ignore[import-not-found]  # noqa: F401
        except ImportError:  # pragma: no cover - окружение без PyYAML
            self.skipTest("PyYAML не установлен")
        with tempfile.TemporaryDirectory() as tmpdir:
            overlay = os.path.join(tmpdir, "config.yaml")
            with open(overlay, "w", encoding="utf-8") as handle:
                handle.write(
                    "own_vocabulary:\n"
                    "  terms: ['Пример Спорт']\n"
                    "  addresses: ['б-р Садовая 3а']\n"
                    "port: 8792\n"
                )
            cfg = load_config(make_env(tmpdir), config_path=overlay)
        self.assertIn("пример спорт", cfg.own_vocabulary.terms)
        self.assertEqual(8792, cfg.port)

    def test_missing_config_file_is_named_as_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ConfigError) as caught:
                load_config(make_env(tmpdir), config_path=os.path.join(tmpdir, "absent.yaml"))
        self.assertEqual("CONFIG_MISSING_KEY", caught.exception.code)


class DetokChannelsConfigTests(unittest.TestCase):
    """Каналы восстановления — настройка с умолчанием «любой канал» (решение владельца 25.09.2026).

    Проверяются обе стороны решения: при умолчании значение восстанавливается в любом канале, а
    при явном списке — только в перечисленных. Канал вне контура отвергается на старте при любом
    значении настройки.
    """

    def _policy(self, cfg):  # noqa: ANN001 - стенд
        from src.channel_policy import ChannelPolicy

        return ChannelPolicy(cfg.detok_channels)

    def test_absent_setting_restores_in_every_channel(self) -> None:
        """Умолчание публичной сборки: список не задан — значения получает любой канал."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = load_config(make_env(tmpdir))
        self.assertTrue(cfg.detok_all_channels)
        policy = self._policy(cfg)
        for channel in ("mattermost", "signal", "carrier-pigeon", "", None):
            self.assertEqual(
                "detokenize", policy.decide_for_text(channel), msg=str(channel)
            )

    def test_explicit_list_restores_only_the_listed_channels(self) -> None:
        """Явный список сужает восстановление до перечисленных каналов."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = load_config(make_env(tmpdir, PII_PROXY_DETOK_CHANNELS="mattermost,local"))
        self.assertFalse(cfg.detok_all_channels)
        self.assertEqual(frozenset({"mattermost", "local"}), cfg.detok_channels)
        policy = self._policy(cfg)
        self.assertEqual("detokenize", policy.decide_for_text("mattermost"))
        self.assertEqual("keep", policy.decide_for_text("signal"))
        self.assertEqual("keep", policy.decide_for_text(None))

    def test_the_marker_means_every_channel(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = load_config(make_env(tmpdir, PII_PROXY_DETOK_CHANNELS="*"))
        self.assertTrue(cfg.detok_all_channels)
        self.assertEqual("detokenize", self._policy(cfg).decide_for_text("signal"))

    def test_the_overlay_list_is_read_as_a_list(self) -> None:
        """Список из файла настроек читается как список, а не как строка с кавычками."""
        with tempfile.TemporaryDirectory() as tmpdir:
            overlay = os.path.join(tmpdir, "config.json")
            with open(overlay, "w", encoding="utf-8") as handle:
                json.dump({"detok_channels": ["mattermost", "local"]}, handle)
            cfg = load_config(make_env(tmpdir), config_path=overlay)
        self.assertEqual(frozenset({"mattermost", "local"}), cfg.detok_channels)

    def test_channel_outside_the_perimeter_is_refused_with_the_default(self) -> None:
        """Умолчание «любой канал» не отменяет запрета каналов вне контура."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for value in ("telegram", "whatsapp", "*,telegram"):
                with self.subTest(value=value):
                    with self.assertRaises(ConfigError) as ctx:
                        load_config(make_env(tmpdir, PII_PROXY_DETOK_CHANNELS=value))
                    self.assertEqual(ctx.exception.code, "CONFIG_CHANNEL_POLICY_VIOLATION")


class ServiceLexiconConfigTests(unittest.TestCase):
    """Служебная лексика оператора приходит из настроек: клубно-тарифных слов в коде нет."""

    def test_absent_configuration_leaves_the_service_lexicon_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = load_config(make_env(tmpdir))
        self.assertTrue(cfg.service_lexicon.is_empty())
        self.assertEqual(0, cfg.service_lexicon.word_count)

    def test_lexicon_comes_from_the_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = load_config(
                make_env(tmpdir, PII_PROXY_SERVICE_LEXICON="Годовой,групповые занятия")
            )
        self.assertEqual(2, cfg.service_lexicon.word_count)
        self.assertIn("годовой", cfg.service_lexicon.by_category["своя служебная лексика"])

    def test_lexicon_comes_from_a_yaml_overlay_with_categories(self) -> None:
        try:
            import yaml  # type: ignore[import-not-found]  # noqa: F401
        except ImportError:  # pragma: no cover - окружение без PyYAML
            self.skipTest("PyYAML не установлен")
        with tempfile.TemporaryDirectory() as tmpdir:
            overlay = os.path.join(tmpdir, "config.yaml")
            with open(overlay, "w", encoding="utf-8") as handle:
                handle.write(
                    "service_lexicon:\n"
                    "  \"тарифы и клубы\": ['Годовой', 'Базовый']\n"
                    "  \"услуги\": ['пробное занятие']\n"
                )
            cfg = load_config(make_env(tmpdir), config_path=overlay)
        self.assertEqual(2, cfg.service_lexicon.category_count)
        self.assertEqual(3, cfg.service_lexicon.word_count)
        self.assertIn("базовый", cfg.service_lexicon.by_category["тарифы и клубы"])


class TrustedClientsConfigTests(unittest.TestCase):
    """Доверенные клиенты и поведение для неизвестного клиента приходят из настроек."""

    def test_absent_section_leaves_the_table_empty_and_the_safe_mode(self) -> None:
        """Умолчание публичной сборки: опознавать некого, неопознанный клиент получает коды."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = load_config(make_env(tmpdir))
        self.assertEqual(0, len(cfg.trusted_clients))
        self.assertEqual(UNKNOWN_KEEP_CODES, cfg.unknown_client)

    def test_the_compact_environment_value_is_understood(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = load_config(
                make_env(
                    tmpdir,
                    PII_PROXY_TRUSTED_CLIENTS="desk=header:desk;laptop=ua:Laptop/*;desk=ua:Desk/*",
                )
            )
        self.assertEqual(("desk", "laptop"), cfg.trusted_clients.channels)
        self.assertEqual({"header": 1, "key": 0, "user_agent": 2}, cfg.trusted_clients.methods)

    def test_a_json_environment_value_is_understood(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = load_config(
                make_env(
                    tmpdir,
                    PII_PROXY_TRUSTED_CLIENTS=json.dumps(
                        [{"channel": "desk", "key_sha256": fingerprint("desk-stub-key")}]
                    ),
                )
            )
        self.assertEqual(("desk",), cfg.trusted_clients.channels)

    def test_the_overlay_section_is_read_as_a_list_of_records(self) -> None:
        """Основной способ настройки: перечень записей рядом с пояснением оператора."""
        with tempfile.TemporaryDirectory() as tmpdir:
            overlay = os.path.join(tmpdir, "config.json")
            with open(overlay, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "trusted_clients": [
                            {"channel": "cursor", "header_value": "cursor", "comment": "IDE"},
                            {
                                "channel": "codex",
                                "key_sha256": fingerprint("codex-stub-key"),
                                "user_agent": "*codex*",
                            },
                        ],
                        "unknown_client": UNKNOWN_RESTORE,
                    },
                    handle,
                )
            cfg = load_config(make_env(tmpdir), config_path=overlay)
        self.assertEqual(("codex", "cursor"), cfg.trusted_clients.channels)
        self.assertEqual(UNKNOWN_RESTORE, cfg.unknown_client)
        # Список каналов файл не задавал: умолчание осталось прежним.
        self.assertTrue(cfg.detok_all_channels)

    def test_a_channel_outside_the_perimeter_is_refused_at_startup(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ConfigError) as ctx:
                load_config(
                    make_env(
                        tmpdir,
                        PII_PROXY_TRUSTED_CLIENTS="telegram=ua:Telegram/*",
                    )
                )
        self.assertEqual("CLIENT_IDENTITY_BLOCKED_CHANNEL", ctx.exception.code)

    def test_a_broken_fingerprint_is_refused_at_startup(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ConfigError) as ctx:
                load_config(
                    make_env(tmpdir, PII_PROXY_TRUSTED_CLIENTS="desk=key:not-a-fingerprint")
                )
        self.assertEqual("CLIENT_IDENTITY_BAD_FINGERPRINT", ctx.exception.code)

    def test_one_key_cannot_belong_to_two_channels(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ConfigError) as ctx:
                load_config(
                    make_env(
                        tmpdir,
                        PII_PROXY_TRUSTED_CLIENTS=(
                            f"desk=key:{fingerprint('shared-stub-key')};"
                            f"laptop=key:{fingerprint('shared-stub-key')}"
                        ),
                    )
                )
        self.assertEqual("CLIENT_IDENTITY_DUPLICATE_KEY", ctx.exception.code)

    def test_an_unknown_client_mode_is_refused_at_startup(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ConfigError) as ctx:
                load_config(make_env(tmpdir, PII_PROXY_UNKNOWN_CLIENT="maybe"))
        self.assertEqual("CONFIG_INVALID_UNKNOWN_CLIENT", ctx.exception.code)


if __name__ == "__main__":
    unittest.main()
