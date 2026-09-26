# FILE: tests/test_stream_mode_config.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the streaming-mode switch that keeps the JSON path alive: default auto, explicit json_only, and a hard failure on an unknown value.
#   SCOPE: default value, environment parsing, normalisation, rejection of unknown values and of values carrying an inline comment.
#   DEPENDS: M-CONFIG
#   LINKS: V-M-CONFIG, Phase-11
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   make_env - valid environment with temporary key files
#   StreamModeTests - stream_mode parsing and validation
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.1.0 - Phase-11 шаг 1: два пути, JSON сохраняется.
# END_CHANGE_SUMMARY

import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import ConfigError, load_config  # noqa: E402


def make_env(tmpdir: str, **overrides: str) -> dict:
    """Build a valid environment mapping with real key files on disk."""
    keys = {}
    for name, filler in (("token", b"k"), ("fernet", b"f"), ("dict", b"d")):
        path = os.path.join(tmpdir, f"{name}.key")
        with open(path, "wb") as handle:
            handle.write(filler * 32)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        keys[name] = path
    env = {
        "DEEPSEEK_API_KEY": "ds-secret",
        "NORDROUTER_API_KEY": "nord-secret",
        "PII_PROXY_TOKEN_KEY_FILE": keys["token"],
        "PII_PROXY_FERNET_KEY_FILE": keys["fernet"],
        "PII_PROXY_DICT_KEY_FILE": keys["dict"],
        "PII_PROXY_MAP_DB": os.path.join(tmpdir, "pii_map.db"),
        "PII_PROXY_DICT": os.path.join(tmpdir, "pii_dict.json"),
        "PII_PROXY_AUDIT_LOG": os.path.join(tmpdir, "audit.jsonl"),
    }
    env.update(overrides)
    return env


class StreamModeTests(unittest.TestCase):
    def test_default_is_auto(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = load_config(make_env(tmpdir))
        self.assertEqual(config.stream_mode, "auto")

    def test_json_only_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = load_config(make_env(tmpdir, PII_PROXY_STREAM_MODE="json_only"))
        self.assertEqual(config.stream_mode, "json_only")

    def test_value_is_normalised(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = load_config(make_env(tmpdir, PII_PROXY_STREAM_MODE="  JSON_ONLY  "))
        self.assertEqual(config.stream_mode, "json_only")

    def test_unknown_value_stops_the_start(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ConfigError) as ctx:
                load_config(make_env(tmpdir, PII_PROXY_STREAM_MODE="always"))
        self.assertEqual(ctx.exception.code, "CONFIG_INVALID_STREAM_MODE")

    def test_inline_comment_does_not_flip_the_value(self) -> None:
        """systemd EnvironmentFile не понимает инлайновые комментарии: значение приходит целиком."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ConfigError):
                load_config(make_env(tmpdir, PII_PROXY_STREAM_MODE="json_only  # выключить поток"))

    def test_auto_is_the_documented_default_for_other_clients(self) -> None:
        """Клиент без потока идёт непотоковым путём — режим auto ничего не меняет."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = load_config(make_env(tmpdir, PII_PROXY_STREAM_MODE="auto"))
        self.assertEqual(config.stream_mode, "auto")


if __name__ == "__main__":
    unittest.main()
