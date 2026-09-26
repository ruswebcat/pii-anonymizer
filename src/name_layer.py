# FILE: src/name_layer.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Provide the open-source recognition layer (суффиксы, имена, отчества из открытых списков) so that ordinary Russian names are recognised without storing a single client value.
#   SCOPE: loading a compact layer file with its licence and provenance, membership lookups by class, size reporting, hot reload when the file changed.
#   DEPENDS: M-CONFIG
#   LINKS: M-NAME-LAYER, V-M-NAME-LAYER, Phase-10, Phase-9
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   LayerError - layer failure with a stable code
#   NameLayer - loaded open layer with per-class membership
#   fn-load_name_layer - read the layer file, or return None when absent
#   fn-file_signature - сигнатура файла слоя: время правки и размер
#   fn-reload_if_changed - перечитать слой после пополнения словаря, не меняя объект
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.1.0 - Phase-9 шаг 3: слой помнит свой файл и перечитывается по изменению; значения заменяются внутри того же объекта, поэтому детектор и заслон видят пополнение без перезапуска службы.
#   PREVIOUS: v1.0.0 - Phase-10: recognition moves to open data (слой A), the private layer becomes thin.
# END_CHANGE_SUMMARY

"""Open recognition layer.

Why this exists (measured 16.09.2026): the dictionary built from client cards covered
only 63% of surnames and carried 59.5% values that were not names at all. Recognition
should come from the language — открытые списки фамилий, имён и отчеств — and the
private layer should hold only what the language cannot give: nicknames, odd
spellings, values sitting in the wrong field.

The layer file is built by ``tools/build_name_layer.py`` from an open dataset and
carries its own provenance (source, licence, checksum, build date) so that the
licence travels with the data.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

LOGGER_NAME = "NameLayer"
LOG_MARKER = "[NameLayer][load_name_layer][BLOCK_LOAD_NAME_LAYER]"

SCHEMA = 1
CLASSES = ("P", "T", "E", "D", "A", "I", "C")


class LayerError(RuntimeError):
    """Layer failure with a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# START_BLOCK_LOAD_NAME_LAYER
class NameLayer:
    """Loaded open layer: per-class value sets with their provenance."""

    def __init__(self, values: dict[str, set[str]], meta: dict[str, Any], path: str | None = None) -> None:
        self._values = values
        self._meta = meta
        self._sizes = {cls: len(items) for cls, items in values.items()}
        # Путь хранится, чтобы слой можно было перечитать после пополнения словаря
        # (Phase-9 шаг 3): без него новая сборка ждала бы перезапуска службы.
        self._path = path
        # Сигнатуру запоминаем сразу: иначе первый же запрос после старта счёл бы файл изменившимся.
        self._signature = self.file_signature()

    @property
    def size(self) -> int:
        """Return the number of values across all classes."""
        return sum(self._sizes.values())

    @property
    def counts(self) -> dict[str, int]:
        """Return per-class value counts."""
        return dict(self._sizes)

    @property
    def meta(self) -> dict[str, Any]:
        """Return provenance (source, licence, checksum, build date)."""
        return dict(self._meta)

    @property
    def path(self) -> str | None:
        """Return the layer file path, when the layer came from a file."""
        return self._path

    def file_signature(self) -> tuple[float, int] | None:
        """Вернуть сигнатуру файла слоя (время правки, размер) или None.

        # START_CONTRACT: file_signature
        #   PURPOSE: Заметить пополнение словаря, не читая файл на каждом запросе.
        #   INPUTS: none
        #   OUTPUTS: { tuple[float, int] | None - сигнатура или None, если слой не из файла }
        #   SIDE_EFFECTS: читает метаданные файла
        #   LINKS: M-NAME-LAYER, M-ROUTER, V-M-NAME-LAYER
        # END_CONTRACT: file_signature
        """
        if not self._path:
            return None
        try:
            stat = Path(self._path).stat()
        except OSError:
            return None
        return stat.st_mtime, stat.st_size

    def reload_if_changed(self) -> bool:
        """Перечитать слой, если файл изменился, и вернуть True при перезагрузке.

        # START_CONTRACT: reload_if_changed
        #   PURPOSE: Новый словарь должен работать без перезапуска службы.
        #   INPUTS: none
        #   OUTPUTS: { bool - True, если значения слоя заменены }
        #   SIDE_EFFECTS: читает и разбирает файл слоя; заменяет значения и происхождение
        #   LINKS: M-NAME-LAYER, M-ROUTER, V-M-NAME-LAYER
        # END_CONTRACT: reload_if_changed

        Значения заменяются ВНУТРИ того же объекта: детектор, резолвер идентичности и заслон
        держат ссылку на него, и подмена объекта оставила бы их со старым словарём.
        """
        signature = self.file_signature()
        if signature is None or signature == self._signature:
            return False
        try:
            fresh = load_name_layer(self._path)
        except LayerError:
            # Битый файл не должен обнулять слой: прежние значения продолжают работать,
            # а обезличивание не имеет права замолчать из-за неудачной выгрузки.
            return False
        if fresh is None or not fresh.size:
            return False
        self._values = fresh._values  # noqa: SLF001 - тот же класс, доступ намеренный
        self._meta = fresh._meta
        self._sizes = fresh._sizes
        self._signature = fresh._signature
        return True

    def contains(self, value: str, cls: str | None = None) -> bool:
        """Return True when the value is a known name of the given class.

        # START_CONTRACT: contains
        #   PURPOSE: Answer the only question the layer is asked — «это известная фамилия/имя/отчество?».
        #   INPUTS: { value: str - candidate, cls: str | None - class letter, None checks every class }
        #   OUTPUTS: { bool - membership }
        #   SIDE_EFFECTS: none
        #   LINKS: V-M-NAME-LAYER, M-DETECT-NAME
        # END_CONTRACT: contains
        """
        if not value:
            return False
        probe = value.strip().lower()
        if not probe:
            return False
        if cls is not None:
            return probe in self._values.get(cls, frozenset())
        return any(probe in items for items in self._values.values())

    def snapshot(self) -> dict[str, Any]:
        """Return a health-friendly summary without any values."""
        return {"counts": self.counts, "source": self._meta.get("source", ""), "licence": self._meta.get("licence", ""), "built_at": self._meta.get("built_at", "")}


def load_name_layer(path: str | None) -> NameLayer | None:
    """Load the layer file, or return None when no layer is configured.

    # START_CONTRACT: load_name_layer
    #   PURPOSE: Make the open layer optional: without it the proxy behaves exactly as before.
    #   INPUTS: { path: str | None - layer file path }
    #   OUTPUTS: { NameLayer | None - loaded layer }
    #   SIDE_EFFECTS: reads and decompresses the file
    #   LINKS: V-M-NAME-LAYER, M-CONFIG
    # END_CONTRACT: load_name_layer
    """
    if not path:
        return None
    target = Path(path)
    if not target.exists():
        return None
    try:
        with gzip.open(target, "rt", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise LayerError("LAYER_UNREADABLE", f"{path}: {exc}") from exc
    if int(payload.get("schema") or 0) != SCHEMA:
        raise LayerError("LAYER_SCHEMA", f"unsupported schema {payload.get('schema')!r}")
    raw = payload.get("values")
    if not isinstance(raw, dict):
        raise LayerError("LAYER_SHAPE", "layer has no values block")
    values: dict[str, set[str]] = {}
    for cls, items in raw.items():
        if not isinstance(items, list):
            raise LayerError("LAYER_SHAPE", f"class {cls} is not a list")
        values[str(cls)] = {str(item).strip().lower() for item in items if str(item).strip()}
    meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
    return NameLayer(values, meta, str(target))
# END_BLOCK_LOAD_NAME_LAYER
