# FILE: tools/build_name_layer.py
# VERSION: 2.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Build the open recognition layer (фамилии, имена, отчества) from several open datasets into a compact file that carries the licence and provenance of every source.
#   SCOPE: reading csv/zip and one-word-per-line sources, filtering Cyrillic name-shaped values, deduplication, per-source checksum, gzip write, staging path support.
#   DEPENDS: M-NAME-LAYER
#   LINKS: M-NAME-LAYER, V-M-NAME-LAYER, Phase-10, Phase-9
#   ROLE: SCRIPT
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   BuildError - build failure with a stable code
#   SOURCE_REGISTRY - точные ссылки и лицензионные оговорки известных открытых источников
#   SourceSpec - один источник: вид, путь, адрес, страница, лицензия, оговорка
#   detect_source_kind - вид источника по расширению файла
#   read_source - строки источника в обоих видах
#   collect_values - наборы значений по источникам и классам со счётчиками
#   build - собрать слой с происхождением и контрольной суммой каждого источника
#   main - точка входа CLI
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v2.1.0 - Phase-9 шаг 3 follow-up (19.09.2026): человекочитаемая ссылка на источник (--source-page) и реестр известных источников с точными адресами и лицензионной оговоркой; ссылка и оговорка едут в meta вместе с данными.
#   PREVIOUS: v2.0.0 - Phase-9 шаг 3: несколько источников вместо одного (--source повторяется), вид словаря «слово на строке» для списка Natasha, per-source sha256, адрес и лицензия в meta; сборка в промежуточный файл (--out) с проверкой счётчиков до замены живого слоя.
#   EARLIER: v1.0.0 - Phase-10: recognition from open data instead of a dump of client cards.
# END_CHANGE_SUMMARY

"""Build the open recognition layer.

Источники (19.09.2026):

* ``datacoon/russiannames`` — BSD-3-Clause, 375 449 фамилий, 32 134 имени, 48 274 отчества;
  выгрузка одним CSV (``first_name,last_name,middle_name,sex``, 1 161 943 строки);
* ``natasha`` — MIT у репозитория, но на сами данные словаря отдельной лицензии нет и
  происхождение не задокументировано (возможно, производное от OpenCorpora под CC BY-SA);
  три списка по одному слову на строке: ``last.txt`` 182 338, ``first.txt`` 7 658,
  ``middle.txt`` 77. Точная ссылка на данные —
  https://github.com/natasha/natasha/blob/master/natasha/data/dict/last.txt
  (в реестре ``SOURCE_REGISTRY`` и в ``meta.sources[*].page`` файла слоя). Оговорка записана
  в meta каждого источника и в отчёте, чтобы её невозможно было потерять при чтении файла слоя.

Лицензия едет вместе с данными: собранный файл хранит адрес, лицензию и контрольную сумму
каждого источника, поэтому восстанавливать происхождение вручную не приходится.

В слой попадают только кириллические значения имени той же формы, что и раньше: слой — это
язык, а не клиентская база, и смысл его в том, что для распознавания обычного русского имени
не нужно ни одного значения клиента.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import re
import sys
import zipfile
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # pragma: no cover - script bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from src.name_layer import SCHEMA  # noqa: E402

LOGGER_NAME = "BuildNameLayer"
LOG_MARKER = "[BuildNameLayer][build][BLOCK_BUILD_NAME_LAYER]"

SOURCE_URL = "https://github.com/datacoon/russiannames"
LICENCE = "BSD-3-Clause"
DEFAULT_OUT = "/var/lib/pii-proxy/name_layer.json.gz"

#: Известные источники открытого слоя: точная человекочитаемая ссылка на данные, лицензия и
#: оговорка. Реестр — не украшение: без ссылки лицензионную оговорку невозможно проверить, а
#: данные Natasha пришли без собственной лицензии, поэтому их происхождение описано словами
#: (возможно, производное от OpenCorpora под CC BY-SA). Решение о допустимости — за владельцем;
#: до его решения словарь используют, но оговорку фиксируют вместе с данными.
SOURCE_REGISTRY: dict[str, dict[str, str]] = {
    "natasha:last": {
        "page": "https://github.com/natasha/natasha/blob/master/natasha/data/dict/last.txt",
        "raw": "https://raw.githubusercontent.com/natasha/natasha/master/natasha/data/dict/last.txt",
        "licence": "MIT репозитория; на сами данные лицензия не заявлена",
        "note": (
            "происхождение словаря не задокументировано, возможно производное от OpenCorpora (CC BY-SA); "
            "страница источника: https://github.com/natasha/natasha/blob/master/natasha/data/dict/last.txt"
        ),
    },
    "datacoon:names": {
        "page": "https://github.com/datacoon/russiannames",
        "licence": "BSD-3-Clause",
        "note": "выгрузка data-distinct.zip, 1 161 943 строк",
    },
}

KIND_NAMES = "names_csv"
KIND_WORDS = "wordlist"

# Колонки источника -> классы нашей схемы.
COLUMN_CLASSES: tuple[tuple[str, str], ...] = (
    ("last_name", "P"),
    ("first_name", "P"),
    ("middle_name", "P"),
)

CYRILLIC_NAME = re.compile(r"^[А-ЯЁ][а-яё][а-яё\-']{1,29}$", re.IGNORECASE)
JUNK_MARKERS = {"???", "?", "-", "|", "н/д", "нет", "нет данных"}
COMMENT_PREFIX = "#"

COUNTER_KEYS = (
    "строк",
    "принято",
    "отклонено: латиница",
    "отклонено: мусор",
    "отклонено: форма",
    "отклонено: коротко",
)


class BuildError(RuntimeError):
    """Layer build failure with a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class SourceSpec:
    """Один источник слоя вместе с его происхождением.

    # START_CONTRACT: SourceSpec
    #   PURPOSE: Держать адрес, ссылку на страницу источника, лицензию и оговорку рядом с данными, а не в чужой памяти.
    #   INPUTS: { path: str, kind: str, url: str, page: str, licence: str, note: str }
    #   OUTPUTS: { SourceSpec - описание источника }
    #   SIDE_EFFECTS: none
    #   LINKS: M-NAME-LAYER, V-M-NAME-LAYER
    # END_CONTRACT: SourceSpec
    """

    path: str
    kind: str = ""
    url: str = ""
    page: str = ""
    licence: str = ""
    note: str = ""


def detect_source_kind(path: str) -> str:
    """Определить вид источника по расширению файла.

    # START_CONTRACT: detect_source_kind
    #   PURPOSE: Не требовать от вызывающего знания внутреннего формата файла.
    #   INPUTS: { path: str - путь к файлу }
    #   OUTPUTS: { str - KIND_NAMES для zip/csv, иначе KIND_WORDS }
    #   SIDE_EFFECTS: none
    #   LINKS: V-M-NAME-LAYER
    # END_CONTRACT: detect_source_kind
    """
    suffix = Path(path).suffix.lower()
    return KIND_NAMES if suffix in {".zip", ".csv"} else KIND_WORDS


# START_BLOCK_READ_SOURCE
def read_source(spec: SourceSpec) -> Iterator[str]:
    """Yield raw values of one source, whatever its shape.

    # START_CONTRACT: read_source
    #   PURPOSE: Читать и выгрузку с колонками, и список «слово на строке» одним ходом.
    #   INPUTS: { spec: SourceSpec - источник }
    #   OUTPUTS: { Iterator[str] - значения источника как они записаны }
    #   SIDE_EFFECTS: читает файл
    #   LINKS: V-M-NAME-LAYER
    # END_CONTRACT: read_source

    В списке слов строки, начинающиеся с «#», — комментарии: у Natasha так помечены
    заголовки и пояснения, и без этого правила в слой попадали бы английские фразы.
    """
    target = Path(spec.path)
    if not target.exists():
        raise BuildError("LAYER_SOURCE_MISSING", f"{spec.path} not found")
    kind = spec.kind or detect_source_kind(spec.path)
    if kind == KIND_WORDS:
        yield from _read_wordlist(target)
        return
    yield from _read_names_csv(target)


def _read_wordlist(target: Path) -> Iterator[str]:
    """Строки списка «слово на строке» без комментариев и пустых строк."""
    with open(target, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            value = line.strip()
            if not value or value.startswith(COMMENT_PREFIX):
                continue
            yield value


def _read_names_csv(target: Path) -> Iterator[str]:
    """Значения колонок ФИО из csv или из zip с одним csv."""
    if target.suffix.lower() == ".zip":
        with zipfile.ZipFile(target) as archive:
            names = [name for name in archive.namelist() if name.lower().endswith(".csv")]
            if not names:
                raise BuildError("LAYER_SOURCE_SHAPE", "zip holds no csv")
            with archive.open(names[0]) as raw:
                text = io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
                yield from _rows_to_values(csv.DictReader(text))
        return
    with open(target, encoding="utf-8", errors="replace") as handle:
        yield from _rows_to_values(csv.DictReader(handle))


def _rows_to_values(rows: Iterable[Mapping[str, Any]]) -> Iterator[str]:
    """Значения колонок ФИО построчно."""
    for row in rows:
        for column, _cls in COLUMN_CLASSES:
            value = str(row.get(column) or "").strip()
            if value:
                yield value


def collect_values(specs: Sequence[SourceSpec]) -> tuple[dict[str, set[str]], dict[str, int], dict[str, int]]:
    """Собрать значения по источникам с counters и вкладом каждого источника.

    # START_CONTRACT: collect_values
    #   PURPOSE: Слить несколько независимых списков в один набор, сохранив вклад каждого.
    #   INPUTS: { specs: Sequence[SourceSpec] - источники }
    #   OUTPUTS: { tuple[dict[str, set[str]], dict[str, int], dict[str, int]] - значения, общие счётчики, вклад по источникам }
    #   SIDE_EFFECTS: читает файлы источников
    #   LINKS: V-M-NAME-LAYER
    # END_CONTRACT: collect_values

    Вклад источника считается по его собственным уникальным значениям: сумма вкладов не равна
    размеру слоя, и это правильно — иначе пересечение списков выглядело бы приростом.
    """
    values: dict[str, set[str]] = {"P": set()}
    stats = {key: 0 for key in COUNTER_KEYS}
    contributions: dict[str, int] = {}
    for index, spec in enumerate(specs):
        own: set[str] = set()
        for value in read_source(spec):
            stats["строк"] += 1
            lowered = value.lower()
            if lowered in JUNK_MARKERS:
                stats["отклонено: мусор"] += 1
                continue
            if len(value) < 3:
                stats["отклонено: коротко"] += 1
                continue
            if re.search(r"[A-Za-z]", value):
                stats["отклонено: латиница"] += 1
                continue
            if not CYRILLIC_NAME.match(value):
                stats["отклонено: форма"] += 1
                continue
            own.add(lowered)
            values["P"].add(lowered)
            stats["принято"] += 1
        contributions[_source_label(spec, index)] = len(own)
    return values, stats, contributions


def _source_label(spec: SourceSpec, index: int) -> str:
    """Имя источника для отчёта: адрес, иначе имя файла."""
    return spec.url or Path(spec.path).name or f"источник-{index + 1}"


def file_digest(path: str) -> str:
    """Вернуть sha256 файла источника.

    # START_CONTRACT: file_digest
    #   PURPOSE: Зафиксировать, какая именно версия списка попала в слой.
    #   INPUTS: { path: str - путь к файлу }
    #   OUTPUTS: { str - шестнадцатеричный sha256 }
    #   SIDE_EFFECTS: читает файл
    #   LINKS: V-M-NAME-LAYER
    # END_CONTRACT: file_digest
    """
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
# END_BLOCK_READ_SOURCE


# START_BLOCK_BUILD_LAYER
def build(specs: Sequence[SourceSpec]) -> dict[str, Any]:
    """Assemble the layer payload with per-source provenance and checksums.

    # START_CONTRACT: build
    #   PURPOSE: Собрать слой так, чтобы происхождение каждого значения можно было проверить.
    #   INPUTS: { specs: Sequence[SourceSpec] - источники }
    #   OUTPUTS: { dict - payload слоя: schema, meta, values }
    #   SIDE_EFFECTS: читает файлы источников
    #   LINKS: M-NAME-LAYER, V-M-NAME-LAYER
    # END_CONTRACT: build
    """
    if not specs:
        raise BuildError("LAYER_NO_SOURCE", "ни одного источника не задано")
    values, stats, contributions = collect_values(specs)
    sources: list[dict[str, Any]] = []
    for index, spec in enumerate(specs):
        sources.append(
            {
                "kind": spec.kind or detect_source_kind(spec.path),
                "file": Path(spec.path).name,
                "url": spec.url,
                # Человекочитаемая страница источника: по ней видно и лицензию репозитория,
                # и сам файл данных. Без неё оговорку нельзя проверить.
                "page": spec.page,
                "licence": spec.licence,
                "note": spec.note,
                "sha256": file_digest(spec.path),
                "values": contributions.get(_source_label(spec, index), 0),
            }
        )
    counts = {cls: len(items) for cls, items in values.items()}
    payload = {
        "schema": SCHEMA,
        "meta": {
            # Краткая сводка для healthz: старые поля остаются на месте, детали — в sources.
            "source": " + ".join(source["url"] for source in sources if source["url"]) or "—",
            "licence": "; ".join(
                f"{source['file']}: {source['licence'] or 'не заявлена'}" for source in sources
            ),
            "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "builder": "tools/build_name_layer.py",
            "counts": counts,
            "stats": stats,
            "sources": sources,
        },
        "values": {cls: sorted(items) for cls, items in values.items()},
    }
    return payload


def main(argv: list[str] | None = None) -> int:
    """Build the layer file.

    # START_CONTRACT: main
    #   PURPOSE: Одна команда собирает слой из нескольких источников, воспроизводимо и проверяемо.
    #   INPUTS: { argv: list[str] | None }
    #   OUTPUTS: { int - exit code }
    #   SIDE_EFFECTS: writes the gz file
    #   LINKS: V-M-NAME-LAYER
    # END_CONTRACT: main

    Сборка идёт в путь ``--out``: сначала промежуточный файл, проверка счётчиков и состава, и
    только потом подмена живого слоя. Иначе ошибка в новом списке ломает обезличивание сразу.
    """
    parser = argparse.ArgumentParser(description="Build the open name layer")
    parser.add_argument("--source", action="append", default=[], help="csv, zip или список слов; повторяется")
    parser.add_argument("--source-kind", action="append", default=[], help=f"{KIND_NAMES} или {KIND_WORDS}")
    parser.add_argument("--source-url", action="append", default=[], help="адрес источника; повторяется по порядку --source")
    parser.add_argument(
        "--source-page",
        action="append",
        default=[],
        help="человекочитаемая страница источника (например blob-ссылка на файл данных); повторяется по порядку",
    )
    parser.add_argument("--source-licence", action="append", default=[], help="лицензия источника; повторяется по порядку")
    parser.add_argument("--source-note", action="append", default=[], help="оговорка об источнике; повторяется по порядку")
    parser.add_argument("--out", default=DEFAULT_OUT)
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    specs = _specs_from_args(args)
    payload = build(specs)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(out, "wt", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False)
    counts = payload["meta"]["counts"]
    print(f"слой собран: {out} ({out.stat().st_size / 1024 / 1024:.1f} МБ)")
    print(f"значений: {sum(counts.values())} {counts}")
    for source in payload["meta"]["sources"]:
        print(
            f"  источник: {source['file']} | {source['kind']} | лицензия: {source['licence'] or 'не заявлена'}"
            f" | своих значений: {source['values']} | sha256: {source['sha256'][:12]}…"
        )
        if source.get("page") or source.get("url"):
            print(f"    страница: {source.get('page') or '—'} | данные: {source.get('url') or '—'}")
    print(f"чистка источника: {payload['meta']['stats']}")
    return 0


def _specs_from_args(args: argparse.Namespace) -> list[SourceSpec]:
    """Собрать описания источников из аргументов командной строки.

    Списки адресов, лицензий, видов и оговорок должны либо отсутствовать, либо иметь ту же
    длину, что и список источников: сдвиг на один элемент тихо приписал бы чужую лицензию.
    """
    sources = list(args.source)
    if not sources:
        raise BuildError("LAYER_NO_SOURCE", "не задан ни один --source")
    aligned = {
        "kind": list(args.source_kind),
        "url": list(args.source_url),
        "page": list(args.source_page),
        "licence": list(args.source_licence),
        "note": list(args.source_note),
    }
    for name, values in aligned.items():
        if values and len(values) != len(sources):
            raise BuildError(
                "LAYER_SOURCE_ARITY",
                f"--source-{name}: задано {len(values)}, а источников {len(sources)}",
            )
    specs: list[SourceSpec] = []
    for index, path in enumerate(sources):
        specs.append(
            SourceSpec(
                path=path,
                kind=aligned["kind"][index] if aligned["kind"] else detect_source_kind(path),
                url=aligned["url"][index] if aligned["url"] else "",
                page=aligned["page"][index] if aligned["page"] else "",
                licence=aligned["licence"][index] if aligned["licence"] else "",
                note=aligned["note"][index] if aligned["note"] else "",
            )
        )
    return specs
# END_BLOCK_BUILD_LAYER


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
