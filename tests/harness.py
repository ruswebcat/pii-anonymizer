# FILE: tests/harness.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Provide deterministic synthetic PII fixtures, an in-memory upstream double and isolated stores so no test needs the network or real client data.
#   SCOPE: synthetic client generator, CSV builder, fake upstream, temporary store and config factories, log capture helper.
#   DEPENDS: M-CONFIG, M-MAP-STORE, M-AUDIT
#   LINKS: M-TEST-HARNESS, V-M-TEST-HARNESS, fn-fake_upstream, fn-sample_clients, fn-temp_map_store
#   ROLE: TEST
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   SAMPLE_SURNAMES / SAMPLE_NAMES / SAMPLE_STREETS - synthetic vocabularies
#   FakeUpstream - upstream double capturing the last payload
#   EchoUpstream - провайдер-эхо: отвечает тем, что получил (проверка «ответ доходит»)
#   MissOneValueTokenizer - токенизатор с воспроизводимым промахом детектора (Вариант 1)
#   fn-sample_clients - deterministic synthetic client records
#   fn-synthetic_csv - CSV text with Russian PII column headers
#   fn-temp_config - config built on temporary key files
#   fn-temp_map_store - isolated encrypted store
#   fn-capture_logs - capture logger records to assert "no PII in logs"
#   fn-use_demo_vocabulary - включить демонстрационную лексику организации
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.2.0 - демонстрационная лексика организации (use_demo_vocabulary) и её установка в конфигурации стенда: своя лексика приходит из настроек и в тестах.
#   LAST_CHANGE: v1.1.0 - Phase-15 шаг 2: два дублёра для проверки Варианта 1 — эхо-провайдер и токенизатор с воспроизводимым промахом детектора.
#   PREVIOUS: v1.0.0 - Phase-1 M-TEST-HARNESS: fixtures for the whole Phase-1 wave.
# END_CHANGE_SUMMARY

"""Synthetic test fixtures.

Implements M-TEST-HARNESS from docs/ARCHITECTURE.md. Every value produced
here is invented: real client names, phones and e-mails must never enter the
repository, and docs/OPERATIONS.md forbids network access in tests.
"""

from __future__ import annotations

import json
import logging
import os
import random
import stat
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Iterator

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import ProxyConfig, load_config  # noqa: E402
from src.map_store import TokenMapStore  # noqa: E402
from src import own_vocabulary  # noqa: E402
from src.tokenizer import PayloadTokenizer  # noqa: E402

LOGGER_NAME = "TestHarness"
LOG_MARKER = "[TestHarness][sample_clients][BLOCK_BUILD_FIXTURES]"

# START_BLOCK_BUILD_FIXTURES
SAMPLE_SURNAMES = (
    "Иванов", "Печёнова", "Заглушков", "Скрытницова", "Скрытнев",
    "Абрамова", "Пивоваров", "Грешнова", "Мещеряков", "Осипова",
)
SAMPLE_SURNAMES_IN_DECLINE = (
    "Иванова", "Печёновой", "Заглушкову", "Скрытницовой", "Скрытнева",
)
SAMPLE_NAMES = ("Сергей", "Ольга", "Дмитрий", "Анна", "Максим", "Ирина")
SAMPLE_PATRONYMICS = (
    "Геннадьевич", "Петровна", "Алексеевич", "Игоревна", "Николаевич", "Сергеевна",
)
SAMPLE_STREETS = (
    "ул. Заводская, д. 19А, кв. 5",
    "б-р Садовая, д. 3А",
    "ул. Лесная, д. 12, кв. 3",
    "ул. Мира, д. 85, кв. 3",
)
SAMPLE_CLUBS = ("Квартальный", "Центральный", "Базовый")
SAMPLE_CARDS = ("12 мес", "5 мес", "2 мес", "Годовой")

#: Демонстрационная лексика организации: выдуманные бренд, филиалы, тарифы, город, свои
#: адреса и номера ресепции. Она показывает главное свойство публичной сборки — своя
#: лексика приходит из настроек, а не из кода, — и включается теми же вызовами, что и
#: боевой контур (``deploy/pii-proxy.env.example``, ``config.example.yaml``).
DEMO_OWN_VOCABULARY: dict[str, str] = {
    "terms": "пример спорт,примерспорт,пример,спорт,примерск,северный,центральный,базовый,квартальный,годовой",
    "addresses": "б-р садовая 3а,пр. заводская 19а,садовая 12",
    "phones": "79001110011,78481000011",
    "service_objects": "crm,admin crm,менеджер crm",
}


# START_BLOCK_DEMO_VOCABULARY
def use_demo_vocabulary() -> None:
    """Install the demo lexicon the way the configuration loader installs the real one.

    # START_CONTRACT: use_demo_vocabulary
    #   PURPOSE: Включить демонстрационную лексику организации в тесте или приборе.
    #   INPUTS: none
    #   OUTPUTS: { None }
    #   SIDE_EFFECTS: заменяет реестр своей лексики
    #   LINKS: M-OWN-VOCABULARY, M-CONFIG, V-M-REPO-HYGIENE
    # END_CONTRACT: use_demo_vocabulary
    """
    own_vocabulary.configure(**DEMO_OWN_VOCABULARY)


def clear_vocabulary() -> None:
    """Return the own-vocabulary registry to the neutral (empty) default."""
    own_vocabulary.reset()
# END_BLOCK_DEMO_VOCABULARY


@dataclass
class FakeUpstream:
    """Upstream double that records the payload it was asked to send.

    # START_CONTRACT: FakeUpstream
    #   PURPOSE: Prove what would have reached the model without any network call.
    #   INPUTS: { response: dict - canned response body, stream_chunks: list[bytes] - canned SSE chunks }
    #   OUTPUTS: { FakeUpstream - double with captured payload }
    #   SIDE_EFFECTS: none
    #   LINKS: M-UPSTREAM, V-M-UPSTREAM
    # END_CONTRACT: FakeUpstream
    """

    response: dict = field(
        default_factory=lambda: {
            "id": "chatcmpl-test",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}],
        }
    )
    stream_chunks: list[bytes] = field(default_factory=list)
    calls: list[dict] = field(default_factory=list)

    def forward_json(
        self, route: str, path: str, payload: dict, timeout: int | None = None
    ) -> tuple[int, dict]:
        self.calls.append({"route": route, "path": path, "payload": payload, "timeout": timeout})
        return 200, json.loads(json.dumps(self.response))

    def forward_stream(
        self, route: str, path: str, payload: dict, timeout: int | None = None
    ) -> Iterator[bytes]:
        self.calls.append({"route": route, "path": path, "payload": payload, "timeout": timeout})
        for chunk in self.stream_chunks:
            yield chunk

    @property
    def last_payload(self) -> dict:
        if not self.calls:
            raise AssertionError("upstream received no request")
        return self.calls[-1]["payload"]

    def serialized_payload(self) -> str:
        return json.dumps(self.last_payload, ensure_ascii=False)


class EchoUpstream(FakeUpstream):
    """Провайдер-эхо: отвечает тем, что получил в системном сообщении.

    # START_CONTRACT: EchoUpstream
    #   PURPOSE: Проверить обещание Варианта 1 «пользователь всегда получает ответ» без сети.
    #   INPUTS: { наследуется от FakeUpstream }
    #   OUTPUTS: { EchoUpstream - дублёр }
    #   SIDE_EFFECTS: none
    #   LINKS: M-UPSTREAM, M-ROUTER, V-M-ROUTER
    # END_CONTRACT: EchoUpstream

    Если бы остаток не был заменён кодом, эхо вернуло бы значение открытым текстом — и тест
    это увидел бы в ответе. Так проверяются сразу обе половины: запрос ушёл обезличенным и
    ответ на доверенном канале читается человеком.
    """

    def forward_json(
        self, route: str, path: str, payload: dict, timeout: int | None = None
    ) -> tuple[int, dict]:
        """Записать вызов и вернуть эхо системного сообщения."""
        self.calls.append({"route": route, "path": path, "payload": payload, "timeout": timeout})
        messages = payload.get("messages") or [{}]
        content = messages[0].get("content") if isinstance(messages[0], dict) else ""
        return 200, {
            "id": "chatcmpl-echo",
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": content or ""}}
            ],
        }


class MissOneValueTokenizer(PayloadTokenizer):
    """Токенизатор с воспроизводимым промахом: одно значение детектор не видит.

    # START_CONTRACT: MissOneValueTokenizer
    #   PURPOSE: Воспроизвести инцидент — промах детектора, из-за которого в исходящем запросе остаётся значение.
    #   INPUTS: { наследуется от PayloadTokenizer, missed: str - значение, которое детектор «пропускает» }
    #   OUTPUTS: { MissOneValueTokenizer - дублёр }
    #   SIDE_EFFECTS: правит payload тем же путём, что настоящий токенизатор
    #   LINKS: M-TOKENIZER, M-VALIDATOR, V-M-ROUTER, V-M-VALIDATOR
    # END_CONTRACT: MissOneValueTokenizer

    Дублёр намеренно «сломан» в одном месте: остальное обезличивает настоящий токенизатор,
    поэтому проверяется именно поведение заслона и Варианта 1, а не исправность конвейера.
    Заслон такой подмены не видит — он судит по своей второй проверке, и это и есть предмет
    проверки: промах обязан стать инцидентом, а не отказом пользователю.
    """

    def __init__(self, *args: object, missed: str = "", **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.missed = (missed or "").strip().lower()
        self.dropped = 0

    def detect(self, text: str):  # type: ignore[override]
        """Вернуть находки, выбросив ровно то значение, ради которого тест и написан."""
        matches = super().detect(text)
        kept = [match for match in matches if match.raw.strip().lower() != self.missed]
        self.dropped += len(matches) - len(kept)
        return kept


def sample_clients(count: int = 100, seed: int = 42) -> list[dict]:
    """Build a deterministic list of synthetic client records.

    # START_CONTRACT: sample_clients
    #   PURPOSE: Feed tokenizer and reidentification tests with realistic shapes.
    #   INPUTS: { count: int - number of records, seed: int - deterministic seed }
    #   OUTPUTS: { list[dict] - synthetic records with PII-shaped fields }
    #   SIDE_EFFECTS: none
    #   LINKS: M-REID-TEST, V-M-DETECT-RULES
    # END_CONTRACT: sample_clients
    """
    rng = random.Random(seed)
    records: list[dict] = []
    for index in range(count):
        surname = SAMPLE_SURNAMES[index % len(SAMPLE_SURNAMES)]
        name = SAMPLE_NAMES[index % len(SAMPLE_NAMES)]
        patronymic = SAMPLE_PATRONYMICS[index % len(SAMPLE_PATRONYMICS)]
        records.append(
            {
                "client_id": 35000 + index,
                "fio": f"{surname} {name} {patronymic}",
                "phone": "79" + f"{rng.randrange(10**8, 10**9):09d}",
                "email": f"client{index}@example.ru",
                "birth_date": f"{rng.randrange(1, 29):02d}.{rng.randrange(1, 13):02d}.{rng.randrange(1970, 2005)}",
                "address": SAMPLE_STREETS[index % len(SAMPLE_STREETS)],
                "club": SAMPLE_CLUBS[index % len(SAMPLE_CLUBS)],
                "card": SAMPLE_CARDS[index % len(SAMPLE_CARDS)],
                "amount": 28000 + index,
            }
        )
    return records


def synthetic_csv(records: list[dict]) -> str:
    """Render synthetic records as a CSV block with Russian PII headers."""
    lines = ["client_id,ФИО,Телефон,E-mail,Дата рождения,Адрес,Клуб,Карта,Сумма"]
    for record in records:
        lines.append(
            ",".join(
                str(record[key])
                for key in (
                    "client_id",
                    "fio",
                    "phone",
                    "email",
                    "birth_date",
                    "address",
                    "club",
                    "card",
                    "amount",
                )
            )
        )
    return "\n".join(lines)


def temp_config(tmpdir: str, **overrides) -> ProxyConfig:
    """Build a validated config on top of temporary key files."""
    token_key = os.path.join(tmpdir, "token.key")
    fernet_key = os.path.join(tmpdir, "fernet.key")
    dict_key = os.path.join(tmpdir, "dict.key")
    with open(token_key, "wb") as handle:
        handle.write(b"t" * 32)
    with open(fernet_key, "wb") as handle:
        handle.write(b"f" * 32)
    with open(dict_key, "wb") as handle:
        handle.write(b"d" * 32)
    for path in (token_key, fernet_key, dict_key):
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    env = {
        "DEEPSEEK_API_KEY": "ds-test",
        "NORDROUTER_API_KEY": "nord-test",
        "PII_PROXY_TOKEN_KEY_FILE": token_key,
        "PII_PROXY_FERNET_KEY_FILE": fernet_key,
        "PII_PROXY_DICT_KEY_FILE": dict_key,
        "PII_PROXY_MAP_DB": os.path.join(tmpdir, "pii_map.db"),
        "PII_PROXY_DICT": os.path.join(tmpdir, "pii_dict.json"),
        "PII_PROXY_AUDIT_LOG": os.path.join(tmpdir, "audit.jsonl"),
        "PII_PROXY_NER_ENABLED": "false",
        # Своя лексика организации — из настроек, как в боевом контуре: конфигурация стенда
        # несёт ту же демонстрационную лексику, иначе сборка службы обнулила бы её.
        "PII_PROXY_OWN_TERMS": DEMO_OWN_VOCABULARY["terms"],
        "PII_PROXY_OWN_ADDRESSES": DEMO_OWN_VOCABULARY["addresses"],
        "PII_PROXY_OWN_PHONES": DEMO_OWN_VOCABULARY["phones"],
        "PII_PROXY_OWN_SERVICE_OBJECTS": DEMO_OWN_VOCABULARY["service_objects"],
    }
    env.update({key: str(value) for key, value in overrides.items()})
    return load_config(env)


def temp_map_store(tmpdir: str, ttl_days: int = 90) -> TokenMapStore:
    """Build an isolated encrypted store inside a temporary directory."""
    return TokenMapStore(os.path.join(tmpdir, "pii_map.db"), b"s" * 32, ttl_days)


def write_dictionary(path: str, entries: dict[str, list[str]]) -> str:
    """Write a dictionary file with 0600 permissions and return its path."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(entries, handle, ensure_ascii=False)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return path


class LogCapture:
    """Context manager capturing log records from one or more loggers."""

    def __init__(self, *loggers: logging.Logger) -> None:
        self._loggers = loggers
        self._handler = logging.Handler()
        self._handler.emit = self._collect  # type: ignore[method-assign]
        self.records: list[logging.LogRecord] = []
        self.messages: list[str] = []

    def _collect(self, record: logging.LogRecord) -> None:
        self.records.append(record)
        self.messages.append(record.getMessage())

    def __enter__(self) -> "LogCapture":
        for logger in self._loggers:
            logger.addHandler(self._handler)
        return self

    def __exit__(self, *exc_info) -> None:
        for logger in self._loggers:
            logger.removeHandler(self._handler)

    def contains_any(self, needles: list[str]) -> bool:
        body = "\n".join(self.messages)
        return any(needle and needle in body for needle in needles)


def temp_dir() -> tempfile.TemporaryDirectory:
    """Return a temporary directory context manager for use in tests."""
    return tempfile.TemporaryDirectory()
# END_BLOCK_BUILD_FIXTURES
