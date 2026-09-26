# FILE: tools/build_name_combos.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Собрать индекс со-встречаемости частей ФИО (M-NAME-COHERENCE) из карточек клиентов: пары и тройки одной карточки в виде ключевых отпечатков, без единого читаемого значения.
#   SCOPE: пагинация клиентов CRM, извлечение полей ФИО, отпечатки сочетаний, происхождение в метаданных, staged-запись 0600, счётчики прогона.
#   DEPENDS: M-NAME-COHERENCE, M-DICT (ключ отпечатков)
#   LINKS: M-NAME-COHERENCE, V-M-NAME-COHERENCE, fn-cards_from_api, fn-main
#   ROLE: TOOL
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   FIELD_NAMES - поля карточки, из которых собираются части ФИО
#   CRM_BASE - корень боевого API CRM v2
#   fn-cards_from_api - страницы клиентов → части ФИО по карточке
#   fn-main - точка входа: собрать индекс и записать файл
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-17 (20.09.2026): инструмент сборки индекса со-встречаемости. Индекс нужен заслону связности: код выдаётся на отдельное значение, поэтому доверенная граница обязана проверить, что пара или тройка ФИО встречается в одной карточке. Инструмент пишет только отпечатки — читаемых значений клиентов в файле нет.
# END_CHANGE_SUMMARY

"""Инструмент сборки индекса со-встречаемости частей ФИО.

Запуск (боевой контур, ключ CRM из окружения профиля):

    python3 tools/build_name_combos.py --out ~/.local/state/pii-proxy/pii_combos.json.gz \\
        --key-file ~/.local/state/pii-proxy/dict.key

Файл индекса — только отпечатки сочетаний: без ключа ``dict.key`` он не подтверждает ничего,
а читаемых значений в нём нет по построению (та же логика, что у справочника распознавания).

Сеть нужна только боевому запуску; тесты подставляют ``fetcher`` и работают без сети.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.name_coherence import build_combos, combos_payload, write_combos  # noqa: E402

LOGGER_NAME = "BuildNameCombos"

#: Поля карточки CRM, из которых собираются части ФИО. Порядок не важен: ключ сочетания
#: порядконезависим, потому что в карточках поля регулярно перепутаны местами.
FIELD_NAMES = ("surname", "name", "patronymic")

#: Корень боевого API CRM v2 (схема — api_v2, данные — api/v2).
CRM_BASE = "https://crm.example.com/api/v2"

DEFAULT_PAGE_SIZE = 100


def _http_fetcher(token: str, club: str = "crm-demo", timeout: int = 30) -> Callable[[str], Mapping[str, Any]]:
    """Собрать чтение страниц CRM с ключом из окружения профиля.

    # START_CONTRACT: _http_fetcher
    #   PURPOSE: Отделить сеть от логики сборки: тесты подставляют своё чтение.
    #   INPUTS: { token: str - ключ API, club: str - домен клуба, timeout: int - таймаут }
    #   OUTPUTS: { Callable[[str], Mapping] - чтение страницы по URL }
    #   SIDE_EFFECTS: выполняет HTTP-запросы при вызове
    #   LINKS: V-M-NAME-COHERENCE
    # END_CONTRACT: _http_fetcher
    """

    def fetch(url: str) -> Mapping[str, Any]:
        request = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}", "club": club},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - адрес задан константой
            return json.loads(response.read().decode("utf-8"))

    return fetch


# START_BLOCK_BUILD_COMBOS_TOOL
def cards_from_api(
    fetcher: Callable[[str], Mapping[str, Any]],
    base: str = CRM_BASE,
    page_size: int = DEFAULT_PAGE_SIZE,
    limit: int | None = None,
) -> Iterator[tuple[str, ...]]:
    """Пройти страницы клиентов и выдать по карточке её части ФИО.

    # START_CONTRACT: cards_from_api
    #   PURPOSE: Дать сборщику только части ФИО, не таща в память карточки целиком.
    #   INPUTS: { fetcher: Callable[[str], Mapping] - чтение страницы, base: str - корень API, page_size: int, limit: int | None - предел числа карточек }
    #   OUTPUTS: { Iterator[tuple[str, ...]] - части ФИО каждой карточки }
    #   SIDE_EFFECTS: выполняет сетевые запросы через fetcher
    #   LINKS: M-NAME-COHERENCE, V-M-NAME-COHERENCE
    # END_CONTRACT: cards_from_api

    Значения не сохраняются и не печатаются: функция отдаёт их вызывающему коду, который
    обязан положить их только в отпечатки.
    """
    size = max(1, min(int(page_size), 100))
    page = 1
    seen = 0
    while True:
        payload = fetcher(f"{base}/client?page={page}&page_size={size}")
        items = payload.get("items") if isinstance(payload, Mapping) else None
        if not isinstance(items, list) or not items:
            return
        for item in items:
            if not isinstance(item, Mapping):
                continue
            parts = tuple(
                str(item.get(field) or "").strip() for field in FIELD_NAMES if str(item.get(field) or "").strip()
            )
            seen += 1
            yield parts
            if limit is not None and seen >= int(limit):
                return
        if len(items) < size:
            return
        page += 1


# END_BLOCK_BUILD_COMBOS_TOOL


def _read_key(path: str) -> bytes:
    """Прочитать ключ отпечатков, отвергая файл, доступный группе или прочим."""
    if not path:
        raise ValueError("key file path is empty")
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o077:
        raise PermissionError(f"key file {path} must be 0600, mode {oct(mode)}")
    with open(path, "rb") as handle:
        return handle.read().strip()


def main(
    argv: Sequence[str] | None = None,
    fetcher: Callable[[str], Mapping[str, Any]] | None = None,
    env_values: Mapping[str, str] | None = None,
) -> int:
    """Собрать индекс сочетаний и записать файл.

    # START_CONTRACT: main
    #   PURPOSE: Сделать сборку повторяемым прогоном с числами на выходе, а не ручной выгрузкой.
    #   INPUTS: { argv: Sequence[str] | None, fetcher: Callable | None - подстановка для тестов, env_values: Mapping | None - окружение }
    #   OUTPUTS: { int - 0 при успехе }
    #   SIDE_EFFECTS: выполняет сетевые запросы, пишет файл индекса
    #   LINKS: M-NAME-COHERENCE, V-M-NAME-COHERENCE
    # END_CONTRACT: main
    """
    env = dict(os.environ if env_values is None else env_values)
    parser = argparse.ArgumentParser(description="Индекс со-встречаемости частей ФИО")
    parser.add_argument("--out", required=True, help="путь к файлу индекса")
    parser.add_argument("--key-file", default="", help="файл ключа отпечатков (dict.key)")
    parser.add_argument("--token", default="", help="ключ CRM (по умолчанию — CRM_API_KEY)")
    parser.add_argument("--club", default="crm-demo", help="домен клуба CRM")
    parser.add_argument("--base", default=CRM_BASE, help="корень API v2")
    parser.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE)
    parser.add_argument("--limit", type=int, default=0, help="предел числа карточек (0 — все)")
    parser.add_argument("--source", default="CRM API v2: GET /client (поля ФИО карточек)")
    parser.add_argument("--licence", default="данные оператора; файл хранит только ключевые отпечатки")
    args = parser.parse_args(list(argv) if argv is not None else None)

    key_path = args.key_file or env.get("PII_PROXY_DICT_KEY_FILE", "")
    key = _read_key(key_path)
    token = args.token or env.get("CRM_API_KEY", "")
    reader = fetcher
    if reader is None:
        if not token:
            print("CRM_TOKEN_MISSING: нет ключа CRM (--token или CRM_API_KEY)")
            return 2
        reader = _http_fetcher(token, args.club)

    digests: set[str] = set()
    counters = {"cards": 0, "pairs": 0, "triples": 0, "skipped": 0}
    for parts in cards_from_api(reader, base=args.base, page_size=args.page_size, limit=args.limit or None):
        found, chunk = build_combos([parts], key)
        digests.update(found)
        for name, value in chunk.items():
            counters[name] = counters.get(name, 0) + int(value)

    payload = combos_payload(
        digests,
        {
            "source": args.source,
            "licence": args.licence,
            "cards": counters["cards"],
        },
    )
    written = write_combos(args.out, payload)
    # Наружу — только числа: ни значений, ни их частей.
    print(
        f"[{LOGGER_NAME}] cards={counters['cards']} pairs={counters['pairs']} "
        f"triples={counters['triples']} skipped={counters['skipped']} combos={written} out={args.out}"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - точка входа
    raise SystemExit(main())
