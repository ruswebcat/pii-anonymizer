# FILE: tests/test_name_layer.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the open recognition layer and its detector integration: ordinary Russian names are recognised without any client value, the layer is optional, and a broken layer never stops detection.
#   SCOPE: loading (absent, broken, valid), membership lookups, provenance, detector integration, config wiring.
#   DEPENDS: M-NAME-LAYER, M-DETECT-NAME, M-CONFIG
#   LINKS: V-M-NAME-LAYER, M-NAME-LAYER, Phase-10
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   make_layer_file - write a small layer fixture
#   NameLayerTests - loading and lookups
#   LayerDetectorTests - recognition through the layer
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-10 verification.
# END_CHANGE_SUMMARY

import gzip
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.detect_name import NameDetector  # noqa: E402
from src.name_layer import LayerError, load_name_layer  # noqa: E402

FIXTURE = {
    "schema": 1,
    "meta": {"source": "https://example.test/names", "licence": "BSD-3-Clause", "built_at": "2026-09-17T00:00:00+00:00"},
    "values": {"P": ["Токенец", "Заглушкин", "Марат", "Ильдарович"]},
}


def make_layer_file(directory: str, payload: dict | None = None) -> str:
    """Write a layer fixture and return its path."""
    path = os.path.join(directory, "name_layer.json.gz")
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(payload if payload is not None else FIXTURE, handle, ensure_ascii=False)
    return path


class NameLayerTests(unittest.TestCase):
    def test_absent_layer_is_not_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(load_name_layer(None))
            self.assertIsNone(load_name_layer(os.path.join(tmp, "missing.json.gz")))

    def test_layer_lookup_is_case_insensitive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            layer = load_name_layer(make_layer_file(tmp))
        assert layer is not None
        for value in ("Токенец", "токенец", "ТОКЕНЕЦ"):
            self.assertTrue(layer.contains(value, "P"), msg=value)
        self.assertFalse(layer.contains("Телевизор", "P"))

    def test_layer_reports_provenance_and_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            layer = load_name_layer(make_layer_file(tmp))
        assert layer is not None
        snapshot = layer.snapshot()
        self.assertEqual(snapshot["counts"], {"P": 4})
        self.assertEqual(snapshot["licence"], "BSD-3-Clause")
        self.assertIn("example.test", snapshot["source"])

    def test_unsupported_schema_is_refused(self) -> None:
        broken = dict(FIXTURE)
        broken["schema"] = 99
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(LayerError) as ctx:
                load_name_layer(make_layer_file(tmp, broken))
        self.assertEqual(ctx.exception.code, "LAYER_SCHEMA")

    def test_unreadable_file_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "broken.json.gz")
            with open(path, "wb") as handle:
                handle.write(b"not gzip at all")
            with self.assertRaises(LayerError) as ctx:
                load_name_layer(path)
        self.assertEqual(ctx.exception.code, "LAYER_UNREADABLE")


class LayerDetectorTests(unittest.TestCase):
    """Открытый слой в деле: он подтверждает транслитерацию, а не одиночные слова.

    Решение 17.09.2026: одиночные кириллические слова решает клиентский словарь, иначе
    слой тянет за собой обычные слова, которые являются фамилиями («Камыш», «Грач»), и
    портит нормальный текст. Слой закрывает латиницу: «Terekhina» проверяется своими
    кириллическими вариантами против открытых списков.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        layer_payload = {
            "schema": 1,
            "meta": {"source": "https://example.test/names", "licence": "BSD-3-Clause"},
            "values": {"P": ["терехина", "терехина", "токенец", "заглушкин", "марат"]},
        }
        self.layer = load_name_layer(make_layer_file(self._tmp.name, layer_payload))
        assert self.layer is not None
        self.detector = NameDetector(None, self.layer)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_latin_name_is_confirmed_through_the_layer(self) -> None:
        matches = self.detector.detect_names("клиент Terekhina купил карту")
        self.assertTrue(matches, msg="латиница обязана подтверждаться слоем через транслитерацию")
        self.assertTrue(any("Terekhina" in match.raw for match in matches))

    def test_all_caps_and_lowercase_latin_is_confirmed(self) -> None:
        for text in ("TEREKHINA", "Terekhina"):
            with self.subTest(text=text):
                self.assertTrue(
                    self.detector.detect_names(f"клиент {text} купил карту"),
                    msg=f"не распознано: {text}",
                )

    def test_unknown_latin_name_is_not_detected(self) -> None:
        self.assertEqual(self.detector.detect_names("клиент Zzzzzz купил карту"), [])

    def test_rare_surname_in_client_context_is_detected(self) -> None:
        """Редкая фамилия из открытого списка распознаётся, когда рядом идут данные клиента."""
        matches = self.detector.detect_names("клиент Токенец, телефон 79 1234 5678")
        self.assertTrue(matches, msg="фамилия из слоя в клиентском контексте обязана распознаваться")

    def test_rare_surname_outside_client_context_is_left_alone(self) -> None:
        self.assertEqual(self.detector.detect_names("Токенец и общество"), [])

    def test_common_word_is_not_stopped_by_the_layer_alone(self) -> None:
        """Обычное слово, которое есть в открытых списках как фамилия, не заменяется."""
        layer_payload = {
            "schema": 1,
            "meta": {"source": "https://example.test/names", "licence": "BSD-3-Clause"},
            "values": {"P": ["камыш", "грач"]},
        }
        with tempfile.TemporaryDirectory() as tmp:
            layer = load_name_layer(make_layer_file(tmp, layer_payload))
        assert layer is not None
        detector = NameDetector(None, layer)
        self.assertEqual(detector.detect_names("Камыш растёт у берега"), [])
        self.assertEqual(detector.detect_names("Грач прилетел весной"), [])

    def test_detector_works_without_any_dictionary(self) -> None:
        """Слой самодостаточен для латиницы: клиентского словаря в тесте нет."""
        self.assertIsNone(self.detector._dictionary)
        self.assertTrue(self.detector.detect_names("клиент Terekhina"))
        self.assertEqual(self.detector.detect_names("Stubova пришла в клуб"), [])

    def test_broken_layer_does_not_stop_detection(self) -> None:
        class BrokenLayer:
            def contains(self, value: str, cls: str | None = None) -> bool:
                raise RuntimeError("layer failed")

        detector = NameDetector(None, BrokenLayer())
        self.assertEqual(detector.detect_names("клиент Terekhina"), [])


class ReloadTests(unittest.TestCase):
    """Пополненный слой перечитывается без перезапуска службы (Phase-9 шаг 3)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = make_layer_file(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _touch_forward(self) -> None:
        stat = os.stat(self.path)
        os.utime(self.path, (stat.st_atime, stat.st_mtime + 5))

    def test_unchanged_file_is_not_reloaded(self) -> None:
        layer = load_name_layer(self.path)
        assert layer is not None
        self.assertFalse(layer.reload_if_changed(), msg="без правки файла перезагрузки быть не должно")

    def test_new_values_are_picked_up(self) -> None:
        layer = load_name_layer(self.path)
        assert layer is not None
        self.assertFalse(layer.contains("Скрытниц", "P"))
        payload = {
            "schema": 1,
            "meta": {"source": "https://example.test/names", "licence": "BSD-3-Clause"},
            "values": {"P": FIXTURE["values"]["P"] + ["Скрытниц"]},
        }
        make_layer_file(self._tmp.name, payload)
        self._touch_forward()
        self.assertTrue(layer.reload_if_changed())
        self.assertEqual(layer.size, 5)
        self.assertTrue(layer.contains("Скрытниц", "P"))
        self.assertFalse(layer.reload_if_changed(), msg="повторная проверка без правки — False")

    def test_values_are_replaced_inside_the_same_object(self) -> None:
        """Детектор держит ссылку на слой: подмена объекта оставила бы его со старым словарём."""
        layer = load_name_layer(self.path)
        assert layer is not None
        detector = NameDetector(None, name_layer=layer)
        self.assertEqual(detector.detect_names("ТЕСЛЯ СКРЫТНИЦ"), [])
        make_layer_file(
            self._tmp.name,
            {"schema": 1, "meta": {"licence": "BSD-3-Clause"}, "values": {"P": ["тесля"]}},
        )
        self._touch_forward()
        self.assertTrue(layer.reload_if_changed())
        self.assertTrue(
            detector.detect_names("ТЕСЛЯ СКРЫТНИЦ"),
            msg="детектор обязан видеть пополненный слой через ту же ссылку",
        )

    def test_layer_without_a_file_is_never_reloaded(self) -> None:
        from src.name_layer import NameLayer

        layer = NameLayer({"P": {"иванов"}}, {"source": "synthetic"})
        self.assertIsNone(layer.file_signature())
        self.assertFalse(layer.reload_if_changed())

    def test_broken_file_keeps_the_previous_values(self) -> None:
        """Битый файл не должен обнулять слой: обезличивание продолжает работать по прежнему."""
        layer = load_name_layer(self.path)
        assert layer is not None
        with open(self.path, "wb") as handle:
            handle.write(b"not a gzip at all")
        self._touch_forward()
        self.assertFalse(layer.reload_if_changed())
        self.assertTrue(layer.contains("Токенец", "P"))


if __name__ == "__main__":
    unittest.main()
