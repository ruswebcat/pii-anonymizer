# FILE: tests/test_outgoing_no_leak.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Инвариант «в исходящем запросе нет ни одного значения, найденного заслоном» — тем же предикатом, что у рантайма, с корректным вычетом служебных блоков, и с контролем самого инварианта.
#   SCOPE: значения заслона в исходном и в исходящем запросе, вычет блока tools и ключей JSON, разбор по регистровым формам, намеренно сломанный двойник (инвариант обязан его поймать), известная граница «значение ключом JSON».
#   DEPENDS: M-ROUTER, M-VALIDATOR, M-TOKENIZER, M-TOKEN-GEN, M-TEST-HARNESS
#   LINKS: V-M-VALIDATOR, V-M-TOKENIZER, M-VALIDATOR, инцидент 20.09.2026
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   FIO / SURNAME / PHONE - глушки вместо данных клиентов
#   DICTIONARY - словарь глушек для распознавания
#   gate_values - значения, найденные заслоном в исходных сообщениях
#   outgoing_texts - значения строк исходящего запроса (ключи JSON не в счёт)
#   leaked_values - значения, оставшиеся в тексте исходящего запроса
#   OutgoingLeakInvariantTests - инвариант на сквозном пути и на уровне блока
#   JsonKeyBoundaryTests - документированная граница: значение ключом JSON не правится
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - дефект-фикс 20.09.2026 (красный флаг прибора: 617 найдено, 307 ушло): значение уходило кодом в одном написании и оставалось в исходящем запросе в другом. Тест фиксирует инвариант и обязан падать на сломанном двойнике — иначе зелёный тест ничего не доказывает.
# END_CHANGE_SUMMARY

"""Инвариант против утечки найденного заслоном значения в исходящий запрос.

Зачем отдельный класс проверки. Прибор 20.09.2026 показал: заслон нашёл 617 значений, 307 из
них ушли провайдеру — при этом сьют был зелёный, потому что ни один тест не смотрел на
исходящий запрос глазами заслона. Инвариант ниже смотрит именно так: берёт значения,
найденные заслоном в исходном запросе, и требует, чтобы ни одно из них не осталось в тексте
исходящего.

Две тонкости, без которых проверка была бы самообманом:

* **тот же предикат, что у рантайма.** Наличие значения считается вызовами
  ``flexible_pattern`` / ``word_bounded`` из M-TOKEN-GEN — тем же кодом, которым пользуется
  токенизатор и починка. Свой «похожий» предикат разошёлся бы с рантаймом и врал бы;
* **вычет служебных блоков — с числами.** Проверяются значения строк сообщений: блок
  ``tools`` (статические схемы инструментов) и ключи JSON-блоков исключены, и оба вычета
  считаются, чтобы «ноль утечек» не оказался нулём проверок.

Положительный контроль обязателен: намеренно испорченный исходящий запрос обязан быть
пойман. Инвариант, который не умеет падать, не проверяет ничего.
"""

import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.audit import AuditJournal  # noqa: E402
from src.router import build_service  # noqa: E402
from src.token_factory import flexible_pattern, find_tokens, word_bounded  # noqa: E402
from src.validator import _iter_strings, _normalize_space  # noqa: E402
from tests import harness  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()

FIO = "Иванов Иван Иванович"
SURNAME = "Иванов"
PHONE = "79000000001"
CHAT_PATH = "/v1/chat/completions"

DICTIONARY = {"P": [FIO, SURNAME], "T": [PHONE]}


# START_BLOCK_INVARIANT_HELPERS
def gate_values(gate, payload: dict) -> set[tuple[str, str]]:
    """Значения, найденные заслоном в сообщениях исходного запроса.

    # START_CONTRACT: gate_values
    #   PURPOSE: Взять набор значений ровно тем вызовом, которым его берёт прибор приёмки и заслон.
    #   INPUTS: { gate: ResidualPiiValidator, payload: dict - исходный запрос }
    #   OUTPUTS: { set[tuple[str, str]] - (класс, значение) }
    #   SIDE_EFFECTS: none
    #   LINKS: M-VALIDATOR, V-M-VALIDATOR
    # END_CONTRACT: gate_values
    """
    found: set[tuple[str, str]] = set()
    for text in _iter_strings(payload.get("messages", [])):
        if not text.strip():
            continue
        for _rule, match in gate._channel_matches(text):
            value = _normalize_space(match.raw).strip()
            if value:
                found.add((match.cls, value))
    return found


def outgoing_texts(payload: dict, root: str = "$", include_tools: bool = False):
    """Yield (путь, текст) для значений строк исходящего запроса.

    # START_CONTRACT: outgoing_texts
    #   PURPOSE: Проверять ровно те блоки, которые правит токенизатор (значения `_walk`), а не сериализованный JSON.
    #   INPUTS: { payload: dict, root: str - префикс пути, include_tools: bool - включать ли статические схемы }
    #   OUTPUTS: { Iterator[tuple[str, str]] - путь и текст }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKENIZER, V-M-TOKENIZER
    # END_CONTRACT: outgoing_texts

    Ключи JSON не возвращаются: обход ``_walk`` правит значения, а ключ — это схема. Сериализация
    JSON не годится как единица проверки: кавычки, запятые и имена ключей дают ложные совпадения.
    """
    if isinstance(payload, dict):
        for key, value in payload.items():
            path = f"{root}.{key}"
            if key == "tools" and not include_tools:
                continue
            yield from outgoing_texts(value, path, include_tools)
    elif isinstance(payload, (list, tuple)):
        for index, item in enumerate(payload):
            yield from outgoing_texts(item, f"{root}[{index}]", include_tools)
    elif isinstance(payload, str):
        yield root, payload


def leaked_values(found, outgoing: dict, include_tools: bool = False) -> list[tuple[str, str, str]]:
    """Значения из ``found``, оставшиеся в тексте исходящего запроса.

    # START_CONTRACT: leaked_values
    #   PURPOSE: Дать инварианту числовой ответ: что именно утекло и в каком блоке.
    #   INPUTS: { found: set[tuple[str, str]], outgoing: dict - исходящий запрос, include_tools: bool }
    #   OUTPUTS: { list[tuple[str, str, str]] - (класс, значение, путь блока) }
    #   SIDE_EFFECTS: none
    #   LINKS: M-VALIDATOR, M-TOKENIZER, V-M-VALIDATOR
    # END_CONTRACT: leaked_values

    Критерий тот же, что у рантайма: значение ищется по написанию, без учёта регистра, с любыми
    пробелами и границами слова. Именно поэтому «Иванов» и «ИВАНОВ» — одна утечка, а не две разные
    записи (дефект 20.09.2026).
    """
    leaks: list[tuple[str, str, str]] = []
    texts = list(outgoing_texts(outgoing, include_tools=include_tools))
    for cls, value in sorted(found):
        pattern = flexible_pattern(value)
        if not pattern:
            continue
        probe = re.compile(word_bounded(pattern), re.IGNORECASE)
        for path, text in texts:
            if text and probe.search(text):
                leaks.append((cls, value, path))
                break
    return leaks


def json_key_matches(payload: dict, found) -> int:
    """Сколько найденных заслоном значений стоит КЛЮЧОМ внутри JSON-блока строки.

    # START_CONTRACT: json_key_matches
    #   PURPOSE: Отделить «значение осталось в тексте» от «слово совпало с ключом схемы».
    #   INPUTS: { payload: dict - исходящий запрос, found: set[tuple[str, str]] }
    #   OUTPUTS: { int - число совпадений с ключами }
    #   SIDE_EFFECTS: none
    #   LINKS: M-TOKENIZER, V-M-TOKENIZER
    # END_CONTRACT: json_key_matches
    """
    hits = 0
    for _path, text in outgoing_texts(payload, include_tools=True):
        stripped = (text or "").strip()
        if len(stripped) < 3 or stripped[0] not in "{[" or stripped[-1] not in "}]":
            continue
        try:
            inner = json.loads(stripped)
        except ValueError:
            continue
        keys = set()
        stack = [inner]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for key, value in node.items():
                    if isinstance(key, str):
                        keys.add(_normalize_space(key).strip().lower())
                    stack.append(value)
            elif isinstance(node, list):
                stack.extend(node)
        hits += sum(1 for _cls, value in found if value.lower() in keys)
    return hits
# END_BLOCK_INVARIANT_HELPERS


# START_BLOCK_INVARIANT_TESTS
class OutgoingLeakInvariantTests(unittest.TestCase):
    """Инвариант: найденное заслоном значение не остаётся в тексте исходящего запроса."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        harness.write_dictionary(os.path.join(self.root, "pii_dict.json"), DICTIONARY)
        self.config = harness.temp_config(self.root)
        self.store = harness.temp_map_store(self.root)
        self.audit = AuditJournal(os.path.join(self.root, "audit.jsonl"))
        self.upstream = harness.FakeUpstream()
        self.service = build_service(
            self.config, store=self.store, upstream=self.upstream, audit=self.audit
        )

    def tearDown(self) -> None:
        try:
            self.store.close()
        except Exception:  # pragma: no cover - defensive
            pass
        self._tmp.cleanup()

    def build_payload(self) -> dict:
        """Запрос с одним и тем же значением в разных написаниях и в разных блоках."""
        block = json.dumps(
            {"ФИО": FIO, "телефон": PHONE, "заметка": f"позвонить {SURNAME} и {SURNAME.lower()}"},
            ensure_ascii=False,
        )
        return {
            "model": "deepseek-flash",
            "stream": False,
            "messages": [
                {"role": "system", "content": f"Канал mattermost. Клиент {FIO}, телефон {PHONE}."},
                {"role": "user", "content": f"Сводка по {SURNAME.upper()} и по {SURNAME.lower()}."},
                {
                    "role": "assistant",
                    "content": f"Клиент {SURNAME}, карта: https://crm.example.com/lk?fio={SURNAME}",
                },
                {"role": "tool", "content": block},
            ],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "terminal",
                        "parameters": {"type": "object", "properties": {}},
                    },
                }
            ],
        }

    def incident_actions(self) -> list[str]:
        directory = self.config.incident_log_path
        actions: list[str] = []
        for name in sorted(os.listdir(directory)) if os.path.isdir(directory) else []:
            with open(os.path.join(directory, name), encoding="utf-8") as handle:
                actions.extend(json.loads(line)["action"] for line in handle if line.strip())
        return actions

    def test_no_gate_value_remains_in_the_outgoing_request(self) -> None:
        """Все найденные заслоном значения уходят кодом — включая другие написания того же значения."""
        payload = self.build_payload()
        found = gate_values(self.service._validator, payload)
        status, _body = self.service.handle_chat_completions(payload, "ds", CHAT_PATH, "mattermost")
        self.assertEqual(status, 200)
        self.assertTrue(self.upstream.calls, msg="запрос не дошёл до провайдера — проверять нечего")
        self.assertGreaterEqual(len(found), 3, msg="заслон не нашёл значений — инвариант пуст")

        leaks = leaked_values(found, self.upstream.last_payload)
        self.assertEqual(leaks, [], msg=f"в исходящем запросе остались значения заслона: {leaks}")
        # Причина исправлена, а не залатана починкой: заслону нечего заменять вторым проходом.
        self.assertEqual(self.incident_actions(), [])

    def test_the_invariant_catches_a_leak(self) -> None:
        """Контроль инварианта: намеренно испорченный исходящий запрос обязан быть пойман."""
        payload = self.build_payload()
        found = gate_values(self.service._validator, payload)
        self.service.handle_chat_completions(payload, "ds", CHAT_PATH, "mattermost")
        broken = json.loads(json.dumps(self.upstream.last_payload))
        # Двойник заслон обманывает так, как это делал настоящий дефект: значение осталось
        # в другом написании, чем то, которым оно было заменено.
        broken["messages"][1]["content"] += f" уточнение по {SURNAME.upper()}"
        leaks = leaked_values(found, broken)
        self.assertTrue(leaks, msg="инвариант не поймал подложенную утечку")
        self.assertTrue(
            any(value.lower() == SURNAME.lower() for _cls, value, _path in leaks),
            msg="инвариант поймал не то значение, ради которого написан",
        )

    def test_one_value_in_three_case_forms_leaves_as_one_code(self) -> None:
        """Регистровые формы — одно значение: наверх уходит один код, а не значение."""
        text = f"Клиент {SURNAME}, он же {SURNAME.lower()}, в базе как {SURNAME.upper()}."
        result = self.service._tokenizer.tokenize_text(text)
        probe = re.compile(word_bounded(flexible_pattern(SURNAME)), re.IGNORECASE)
        self.assertEqual(probe.findall(result), [], msg="значение осталось в другом написании")
        self.assertEqual(len({span[3] for span in find_tokens(result)}), 1, msg="на одно значение не один код")

    def test_a_value_inside_a_json_block_is_anonymized(self) -> None:
        """Значение внутри JSON-блока правится так же, как в обычной строке."""
        block = json.dumps({"заметка": f"{SURNAME} и {SURNAME.upper()}"}, ensure_ascii=False)
        result = self.service._tokenizer.tokenize_text(block)
        probe = re.compile(word_bounded(flexible_pattern(SURNAME)), re.IGNORECASE)
        self.assertEqual(probe.findall(result), [])
        self.assertTrue(find_tokens(result), msg="в блоке не выдан код")


class JsonKeyBoundaryTests(unittest.TestCase):
    """Граница обхода и её закрытие заслоном: значение КЛЮЧОМ JSON-блока.

    Обход токенизатора (``_walk``) правит значения, а ключ оставляет: ключ — часть структуры,
    и замена ключа может свести два ключа в один при падежных формах одного человека. Поэтому
    значение ключом ловит не обход, а заслон (он читает текст строки целиком) — и уводит его
    кодом вторым проходом. Тест фиксирует обе половины, чтобы граница была видна в сьюте, а не
    в прозе: если починка перестанет срабатывать, значение ключом уйдёт провайдеру открытым.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        harness.write_dictionary(os.path.join(self.root, "pii_dict.json"), DICTIONARY)
        self.config = harness.temp_config(self.root)
        self.store = harness.temp_map_store(self.root)
        self.audit = AuditJournal(os.path.join(self.root, "audit.jsonl"))
        self.upstream = harness.FakeUpstream()
        self.service = build_service(
            self.config, store=self.store, upstream=self.upstream, audit=self.audit
        )

    def tearDown(self) -> None:
        try:
            self.store.close()
        except Exception:  # pragma: no cover - defensive
            pass
        self._tmp.cleanup()

    def build_payload(self) -> dict:
        """Сообщение-инструмент, где значение стоит ключом JSON-блока."""
        return {
            "model": "deepseek-flash",
            "stream": False,
            "messages": [
                {"role": "tool", "content": json.dumps({SURNAME: 3, "итого": 3}, ensure_ascii=False)}
            ],
        }

    def incident_actions(self) -> list[str]:
        directory = self.config.incident_log_path
        actions: list[str] = []
        for name in sorted(os.listdir(directory)) if os.path.isdir(directory) else []:
            with open(os.path.join(directory, name), encoding="utf-8") as handle:
                actions.extend(json.loads(line)["action"] for line in handle if line.strip())
        return actions

    def test_the_walk_alone_leaves_a_json_key_in_place(self) -> None:
        """Документированная граница: обход правит значения, ключ остаётся структурой."""
        anonymized, _stats = self.service._tokenizer.tokenize_payload(self.build_payload(), "keys")
        text = anonymized["messages"][0]["content"]
        restored = json.loads(text)
        self.assertIn(SURNAME, restored, msg="граница обхода изменилась — тест надо переписать")
        self.assertEqual(restored[SURNAME], 3, msg="значение-число не осталось числом")

    def test_the_gate_catches_the_key_and_the_repair_replaces_it(self) -> None:
        """Заслон читает строку целиком: значение ключом уходит кодом, запрос доходит."""
        payload = self.build_payload()
        found = gate_values(self.service._validator, payload)
        status, _body = self.service.handle_chat_completions(payload, "ds", CHAT_PATH, "mattermost")
        self.assertEqual(status, 200)
        self.assertTrue(found, msg="заслон не нашёл значение — проверять нечего")
        outgoing = self.upstream.last_payload
        self.assertEqual(json_key_matches(outgoing, found), 0, msg="значение осталось ключом")
        self.assertEqual(leaked_values(found, outgoing), [])
        self.assertIn("degraded_tokenized", self.incident_actions())
# END_BLOCK_INVARIANT_TESTS


if __name__ == "__main__":
    unittest.main()
