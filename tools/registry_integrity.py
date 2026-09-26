# FILE: tools/registry_integrity.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Прочитать шифрованный справочник соответствия и назвать цифрами состояние инварианта реестра: сколько кодов несут больше одного значения или больше одной персоны, сколько кодов выдано обходом кандидатов (коллизии) и сколько кодов всего — без единого значения клиента на выходе.
#   SCOPE: чтение справочника по ключу, разрешение персон справочником распознавания, обход кандидатов фабрики кодов, счётчики по классам, JSON-отчёт, код возврата для прибора.
#   DEPENDS: M-MAP-STORE, M-NAME-IDENTITY, M-TOKEN-GEN
#   LINKS: M-REGISTRY-GUARD, V-M-MAP-STORE, fn-inventory, fn-main
#   ROLE: TOOL
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   fn-read_bytes - чтение ключа
#   fn-person_resolver - резолвер персоны тем же словарём, что у службы
#   fn-inventory - инвентарь реестра: числа и коды, без значений
#   fn-main - точка входа: инвентарь + код возврата
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-17 (20.09.2026): инвентарь реестра как инструмент разбора (инцидент выдуманной персоны потребовал числа, а не рассуждения): «сколько кодов значат больше одного значения». Значения клиентов не выводятся — только счётчики, коды-псевдонимы и хеши.
# END_CHANGE_SUMMARY

"""Инвентарь реестра соответствия (M-REGISTRY-GUARD).

Запуск:

    python3 tools/registry_integrity.py \\
        --map-db ~/.local/state/pii-proxy/pii_map.db \\
        --fernet-key-file ~/.local/state/pii-proxy/fernet.key \\
        --dict-file ~/.local/state/pii-proxy/pii_dict.json \\
        --dict-key-file ~/.local/state/pii-proxy/dict.key \\
        --token-key-file ~/.local/state/pii-proxy/token.key

Что печатает: размер реестра, распределение кодов по классам, число кодов, несущих больше
одного значения или больше одной персоны (инвариант Phase-17), и число кодов, выданных
обходом кандидатов (след коллизии). Ни одного значения клиента, ни его фрагмента и длины —
за это отвечает сам справочник (M-MAP-STORE): он расшифровывает значения только внутри
процесса и наружу их не отдаёт.

Код возврата: 0 — реестр однозначен, 2 — найдены многозначные коды (прибор красный),
1 — реестр недоступен.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.detect_name import NameDetector  # noqa: E402
from src.dictionary import PiiDictionary  # noqa: E402
from src.map_store import MapStoreError, TokenMapStore  # noqa: E402
from src.token_factory import candidate_tokens  # noqa: E402

LOGGER_NAME = "RegistryIntegrity"


def read_bytes(path: str) -> bytes:
    """Прочитать ключевой файл.

    # START_CONTRACT: read_bytes
    #   PURPOSE: Дать инструменту ключи в том же виде, что у службы.
    #   INPUTS: { path: str - путь к файлу }
    #   OUTPUTS: { bytes - содержимое без завершающего перевода строки }
    #   SIDE_EFFECTS: читает файл
    #   LINKS: M-MAP-STORE, V-M-MAP-STORE
    # END_CONTRACT: read_bytes
    """
    if not path or not os.path.isfile(path):
        raise FileNotFoundError(path or "(пустой путь)")
    with open(path, "rb") as handle:
        return handle.read().strip()


def person_resolver(dictionary_path: str = "", dictionary_key: bytes | None = None) -> Callable[[str], str | None]:
    """Собрать резолвер персоны тем же кодом, что работает в службе.

    # START_CONTRACT: person_resolver
    #   PURPOSE: Считать многозначность тем же критерием, что у заслона восстановления.
    #   INPUTS: { dictionary_path: str, dictionary_key: bytes | None }
    #   OUTPUTS: { Callable[[str], str | None] - имя персоны для значения, или None }
    #   SIDE_EFFECTS: читает справочник распознавания
    #   LINKS: M-NAME-IDENTITY, M-DETECT-NAME, V-M-NAME-IDENTITY
    # END_CONTRACT: person_resolver

    Без словаря персону назвать нечем: тогда в отчёте честно ноль проверенных персон, а
    значения под одним кодом всё равно видны счётчиком конфликтов.
    """
    if not dictionary_path:
        return lambda _value: None
    names = NameDetector(PiiDictionary(dictionary_path, key=dictionary_key))
    resolver = getattr(names, "identity_for", None)
    if not callable(resolver):
        return lambda _value: None

    def ask(value: str) -> str | None:
        answer = resolver(value)
        return str(answer) if answer else None

    return ask


# START_BLOCK_INVENTORY
def inventory(
    store: TokenMapStore,
    identity_of: Callable[[str], str | None] | None = None,
    token_key: bytes | None = None,
    show_codes: bool = False,
) -> dict[str, Any]:
    """Посчитать состояние реестра: числа и коды, без значений.

    # START_CONTRACT: inventory
    #   PURPOSE: Ответить цифрами на вопрос «сколько кодов несут больше одного значения».
    #   INPUTS: { store: TokenMapStore, identity_of: Callable | None, token_key: bytes | None - ключ фабрики кодов для замера обхода, show_codes: bool - печатать ли коды }
    #   OUTPUTS: { dict[str, Any] - отчёт с числами и (по запросу) кодами }
    #   SIDE_EFFECTS: читает справочник и расшифровывает значения внутри процесса
    #   LINKS: M-MAP-STORE, V-M-MAP-STORE
    # END_CONTRACT: inventory
    """
    report = store.scan_integrity(identity_of)
    answer: dict[str, Any] = {
        "records": report.records,
        "codes": report.codes,
        "values_per_code_gt1": report.value_conflicts,
        "codes_with_more_than_one_person": len(report.ambiguous_codes),
        "checked_identities": report.checked_identities,
        "classes": dict(report.classes),
        "walk_steps": {},
    }
    if token_key:
        steps: dict[str, int] = {}
        for record in store.binding_records(identity_of):
            token, cls, identity = record
            if not identity:
                continue
            position = 0
            for index, candidate in enumerate(candidate_tokens(cls, identity, token_key)):
                if candidate == token:
                    position = index
                    break
            steps[str(position)] = steps.get(str(position), 0) + 1
        answer["walk_steps"] = steps
        answer["codes_after_collision"] = sum(
            count for step, count in steps.items() if step not in {"0"}
        )
    if show_codes:
        answer["ambiguous_codes"] = list(report.ambiguous_codes)
    return answer
# END_BLOCK_INVENTORY


def main(argv: Sequence[str] | None = None) -> int:
    """Точка входа: инвентарь реестра и код возврата для прибора/крона.

    # START_CONTRACT: main
    #   PURPOSE: Дать оператору одну команду вместо рассуждения о состоянии реестра.
    #   INPUTS: { argv: Sequence[str] | None - аргументы }
    #   OUTPUTS: { int - 0 однозначен, 2 многозначные коды, 1 реестр недоступен }
    #   SIDE_EFFECTS: читает файлы, печатает отчёт
    #   LINKS: M-REGISTRY-GUARD, V-M-MAP-STORE
    # END_CONTRACT: main
    """
    parser = argparse.ArgumentParser(description="Инвентарь реестра соответствия (без значений)")
    parser.add_argument("--map-db", required=True, help="файл справочника соответствия")
    parser.add_argument("--fernet-key-file", required=True, help="ключ шифрования справочника")
    parser.add_argument("--dict-file", default="", help="файл справочника распознавания")
    parser.add_argument("--dict-key-file", default="", help="ключ отпечатков справочника")
    parser.add_argument("--token-key-file", default="", help="ключ фабрики кодов (замер обхода)")
    parser.add_argument("--show-codes", action="store_true", help="печатать коды-псевдонимы")
    parser.add_argument("--json", action="store_true", help="вывести отчёт словарём")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        fernet_key = read_bytes(args.fernet_key_file)
        dict_key = read_bytes(args.dict_key_file) if args.dict_key_file else None
        token_key = read_bytes(args.token_key_file) if args.token_key_file else None
        store = TokenMapStore(args.map_db, fernet_key=fernet_key)
    except (OSError, MapStoreError) as exc:
        print(f"[{LOGGER_NAME}] MAP_STORE_UNAVAILABLE: {exc}")
        return 1
    try:
        report = inventory(
            store,
            person_resolver(args.dict_file, dict_key),
            token_key,
            show_codes=args.show_codes,
        )
    except MapStoreError as exc:
        print(f"[{LOGGER_NAME}] {exc.code}")
        return 1
    finally:
        store.close()
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(
            f"[{LOGGER_NAME}] records={report['records']} codes={report['codes']} "
            f"values_per_code_gt1={report['values_per_code_gt1']} "
            f"codes_with_more_than_one_person={report['codes_with_more_than_one_person']} "
            f"checked_identities={report['checked_identities']} "
            f"walk_steps={report['walk_steps']} classes={report['classes']}"
        )
    return 2 if report["values_per_code_gt1"] or report["codes_with_more_than_one_person"] else 0


if __name__ == "__main__":  # pragma: no cover - точка входа
    raise SystemExit(main())
