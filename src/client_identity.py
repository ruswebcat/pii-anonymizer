# FILE: src/client_identity.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Опознать клиента запроса (имя доверенного канала) по трём источникам по порядку — явный заголовок, отпечаток ключа доступа, шаблон User-Agent — и честно признать, когда не опознан ни один.
#   SCOPE: разбор раздела настроек trusted_clients (список записей, компактная строка, JSON), отпечаток ключа без хранения самого ключа, сопоставление шаблонов User-Agent, порядок источников и запрет на понижение надёжности, описание набора для healthz без значений.
#   DEPENDS: M-CHANNEL-POLICY
#   LINKS: M-CLIENT-IDENTITY, M-CONFIG, M-CHANNEL-POLICY, V-M-CHANNEL-POLICY, fn-identify_client, fn-parse_trusted_clients, fn-fingerprint
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   IDENTITY_HEADER - заголовок, значение которого прямо называет канал
#   LEGACY_IDENTITY_HEADER - прежний заголовок канала (совместимость)
#   CLIENT_KEY_HEADER - заголовок с ключом доступа клиента
#   SOURCE_HEADER / SOURCE_KEY / SOURCE_USER_AGENT / SOURCE_DECLARED / SOURCE_NONE - каким источником опознан клиент
#   METHODS - три способа опознания, задаваемые в настройках
#   ClientIdentityError - отказ разбора настроек с устойчивым кодом
#   TrustedClient - одна запись раздела trusted_clients
#   TrustedClients - набор записей с поиском по ключу, заголовку и User-Agent
#   ClientIdentity - итог опознания: канал и источник
#   fn-fingerprint - необратимый отпечаток ключа доступа
#   fn-normalize_channel - имя канала в каноническом виде
#   fn-parse_trusted_clients - разобрать раздел настроек
#   fn-identify_client - опознать клиента запроса
#   fn-main - печать отпечатка ключа для настроек
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - решение владельца 26.09.2026: сторонние ИИ-приложения (Cursor, Claude Code, Codex и прочие) не шлют меток Hermes, поэтому канал опознаётся по явному заголовку, по отпечатку ключа доступа и по шаблону User-Agent; неопознанный клиент получает решение настройки «поведение для неизвестного клиента».
# END_CHANGE_SUMMARY

"""Опознание клиента запроса.

Реализует M-CLIENT-IDENTITY из docs/ARCHITECTURE.md. До появления этого модуля канал брался
только из метки доставки Hermes в системном промпте (``src/router.py``). Сторонние IDE такой
метки не шлют, поэтому появился третий способ опознания — по самому клиенту.

Порядок источников (сверху вниз), и он же порядок доверия:

1. **Явный заголовок** (``X-PII-Channel``, прежний ``X-Hermes-Channel``) — значение заголовка
   называет канал. Самый простой способ и самый слабый: заголовок подделывается кем угодно,
   кто может поставить запрос на прокси.
2. **Ключ доступа клиента** (``X-PII-Client-Key``) — ключ сравнивается **по отпечатку**: в
   настройках лежит ``sha256:…``, сам ключ в файле не хранится. Это единственный способ, который
   нельзя подделать, не зная ключа, поэтому он и назван самым надёжным.
3. **User-Agent** — шаблон (glob) сопоставляется с заголовком целиком, без учёта регистра:
   заготовки для Cursor, Claude Code, Codex, VS Code и JetBrains есть в config.example.yaml,
   таблица расширяется оператором. Подделывается так же легко, как заголовок.

Если клиент назвал ключ, а отпечатка в настройках нет — опознание **не понижается** до шаблона
User-Agent: предъявленный и не совпавший ключ это либо сменившийся ключ оператора, либо чужой
запрос, и в обоих случаях значения восстанавливать нечем. Такой запрос считается неопознанным и
получает решение настройки «поведение для неизвестного клиента».
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from src.channel_policy import BLOCKED_CHANNELS

LOGGER_NAME = "ClientIdentity"
LOG_MARKER = "[ClientIdentity][identify_client][BLOCK_IDENTIFY_CLIENT]"

#: Заголовок, значение которого прямо называет канал клиента.
IDENTITY_HEADER = "X-PII-Channel"
#: Прежний заголовок канала: остаётся рабочим, чтобы уже настроенные клиенты не сломались.
LEGACY_IDENTITY_HEADER = "X-Hermes-Channel"
#: Заголовок с ключом доступа клиента. Ключ сравнивается по отпечатку и нигде не сохраняется.
CLIENT_KEY_HEADER = "X-PII-Client-Key"

#: Источники опознания: видно и в ответе healthz, и в журнале инцидентов — по чему именно судили.
SOURCE_HEADER = "header"
SOURCE_KEY = "key"
SOURCE_USER_AGENT = "user_agent"
#: Канал объявлен внутри запроса (метка доставки Hermes). Источник не наш, но опознание есть,
#: и политика каналов судит такой запрос как любой другой названный канал.
SOURCE_DECLARED = "declared"
SOURCE_NONE = "none"

#: Три способа, которые оператор задаёт в настройках.
METHODS = (SOURCE_HEADER, SOURCE_KEY, SOURCE_USER_AGENT)

#: Приставка отпечатка: в настройках ключ лежит в виде ``sha256:<hex>``.
FINGERPRINT_PREFIX = "sha256:"
#: Минимальная длина шестнадцатеричной части отпечатка: короткий отпечаток перебирается.
MIN_FINGERPRINT_HEX = 32

_CHANNEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")

#: Поля записи раздела trusted_clients в настройках.
_HEADER_KEYS = ("header_value", "header")
_KEY_KEYS = ("key_sha256", "key_fingerprint", "key")
_USER_AGENT_KEYS = ("user_agent", "user_agent_patterns", "ua")


class ClientIdentityError(ValueError):
    """Отказ разбора раздела trusted_clients, с устойчивым кодом.

    # START_CONTRACT: ClientIdentityError
    #   PURPOSE: Назвать неправильную настройку опознания клиента до старта службы.
    #   INPUTS: { code: str - устойчивый код, message: str - пояснение }
    #   OUTPUTS: { ClientIdentityError - исключение }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CLIENT-IDENTITY, M-CONFIG, V-M-CHANNEL-POLICY
    # END_CONTRACT: ClientIdentityError
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# START_BLOCK_FINGERPRINT
def fingerprint(secret: str) -> str:
    """Вернуть отпечаток ключа доступа для настроек: «sha256:<hex>».

    # START_CONTRACT: fingerprint
    #   PURPOSE: Сравнивать ключи клиентов, не храня сами ключи ни в настройках, ни в дереве.
    #   INPUTS: { secret: str - ключ доступа }
    #   OUTPUTS: { str - отпечаток с приставкой алгоритма }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CLIENT-IDENTITY, V-M-CHANNEL-POLICY
    # END_CONTRACT: fingerprint

    Сам ключ в настройках и в репозитории не лежит: файл настроек читает человек, и открытый
    ключ там — такая же утечка, как значение клиента. Владелец получает отпечаток командой
    ``python3 -m src.client_identity <ключ>`` и вписывает его в раздел ``trusted_clients``.
    """
    return FINGERPRINT_PREFIX + hashlib.sha256(str(secret).encode("utf-8")).hexdigest()


def normalize_channel(channel: object) -> str:
    """Привести имя канала к каноническому виду: строчные буквы без пробелов по краям.

    # START_CONTRACT: normalize_channel
    #   PURPOSE: Одно написание имени канала и в настройках, и в решении политики.
    #   INPUTS: { channel: object - имя канала }
    #   OUTPUTS: { str - каноническое имя или пустая строка }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CHANNEL-POLICY, M-CLIENT-IDENTITY
    # END_CONTRACT: normalize_channel
    """
    return str(channel or "").strip().lower()


def _parse_fingerprint(raw: object, channel: str) -> str:
    """Проверить отпечаток ключа из настроек и вернуть его в каноническом виде."""
    text = str(raw or "").strip().lower()
    if not text:
        raise ClientIdentityError(
            "CLIENT_IDENTITY_BAD_FINGERPRINT",
            f"client {channel!r}: key fingerprint is empty",
        )
    if text.startswith(FINGERPRINT_PREFIX):
        text = text[len(FINGERPRINT_PREFIX) :]
    if len(text) < MIN_FINGERPRINT_HEX or not _HEX_RE.match(text):
        raise ClientIdentityError(
            "CLIENT_IDENTITY_BAD_FINGERPRINT",
            f"client {channel!r}: key fingerprint must be hexadecimal, at least "
            f"{MIN_FINGERPRINT_HEX} characters (see tools: python3 -m src.client_identity <key>)",
        )
    return FINGERPRINT_PREFIX + text
# END_BLOCK_FINGERPRINT


# START_BLOCK_TRUSTED_CLIENTS
@dataclass(frozen=True)
class TrustedClient:
    """Одна запись раздела доверенных клиентов.

    # START_CONTRACT: TrustedClient
    #   PURPOSE: Связать имя канала со способами, которыми этот клиент себя объявляет.
    #   INPUTS: { channel: str - имя канала, header_value: str | None - значение заголовка, key_fingerprint: str | None - отпечаток ключа, user_agent_patterns: tuple[str, ...] - шаблоны User-Agent, comment: str - пояснение оператора }
    #   OUTPUTS: { TrustedClient - запись }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CLIENT-IDENTITY, M-CONFIG, V-M-CHANNEL-POLICY
    # END_CONTRACT: TrustedClient

    Записей на один канал бывает несколько: клиент может объявлять себя и ключом, и шаблоном
    User-Agent, а у двух приложений одного вендора — ключи разные, а канал один. Комментарий
    хранится для владельца: в healthz он не выводится, значения оператора туда не попадают.
    """

    channel: str
    header_value: str | None = None
    key_fingerprint: str | None = None
    user_agent_patterns: tuple[str, ...] = ()
    comment: str = ""

    @property
    def methods(self) -> frozenset[str]:
        """Return the recognition methods this record actually uses."""
        used = set()
        if self.header_value:
            used.add(SOURCE_HEADER)
        if self.key_fingerprint:
            used.add(SOURCE_KEY)
        if self.user_agent_patterns:
            used.add(SOURCE_USER_AGENT)
        return frozenset(used)

    def to_dict(self) -> dict[str, object]:
        """Return the record without the comment: настройки владельца в наблюдаемость не уходят.

        # START_CONTRACT: to_dict
        #   PURPOSE: Показать запись в healthz, не публикуя пояснения оператора.
        #   INPUTS: none
        #   OUTPUTS: { dict[str, object] - канал, способы, признак наличия отпечатка }
        #   SIDE_EFFECTS: none
        #   LINKS: M-CLIENT-IDENTITY, M-ROUTER
        # END_CONTRACT: to_dict
        """
        return {
            "channel": self.channel,
            "methods": sorted(self.methods),
            "has_key": bool(self.key_fingerprint),
            "user_agent_patterns": len(self.user_agent_patterns),
        }


@dataclass(frozen=True)
class TrustedClients:
    """Набор доверенных клиентов с поиском по каждому способу опознания.

    # START_CONTRACT: TrustedClients
    #   PURPOSE: Держать таблицу опознания и отвечать на три вопроса: чей это заголовок, чей это ключ, чей это User-Agent.
    #   INPUTS: { records: tuple[TrustedClient, ...] - записи настроек }
    #   OUTPUTS: { TrustedClients - неизменяемый набор }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CLIENT-IDENTITY, M-CONFIG, V-M-CHANNEL-POLICY
    # END_CONTRACT: TrustedClients
    """

    records: tuple[TrustedClient, ...] = field(default_factory=tuple)

    def __bool__(self) -> bool:
        return bool(self.records)

    def __len__(self) -> int:
        return len(self.records)

    def __iter__(self):
        return iter(self.records)

    @property
    def channels(self) -> tuple[str, ...]:
        """Return the channel names, sorted and deduplicated."""
        return tuple(sorted({record.channel for record in self.records}))

    @property
    def methods(self) -> dict[str, int]:
        """Return how many records use each recognition method."""
        counts = {method: 0 for method in METHODS}
        for record in self.records:
            for method in record.methods:
                counts[method] += 1
        return counts

    def by_header_value(self, value: str | None) -> TrustedClient | None:
        """Return the client whose header value is exactly this one."""
        wanted = normalize_channel(value)
        if not wanted:
            return None
        for record in self.records:
            if record.header_value and normalize_channel(record.header_value) == wanted:
                return record
        return None

    def by_key(self, presented: str) -> TrustedClient | None:
        """Return the client whose key fingerprint matches the presented key.

        # START_CONTRACT: by_key
        #   PURPOSE: Сравнить ключ клиента с отпечатками настроек, не сохраняя сам ключ.
        #   INPUTS: { presented: str - предъявленный ключ }
        #   OUTPUTS: { TrustedClient | None - чей это ключ }
        #   SIDE_EFFECTS: none
        #   LINKS: M-CLIENT-IDENTITY, V-M-CHANNEL-POLICY
        # END_CONTRACT: by_key

        Сравнение идёт постоянным по времени `hmac.compare_digest`: обычное ``==`` по строке
        выдаёт разные времена на совпавших префиксах и позволяет подобрать отпечаток по времени
        ответа. Отпечаток — не секрет, но и подсказывать его нечем.
        """
        if not presented:
            return None
        computed = fingerprint(presented)
        for record in self.records:
            if record.key_fingerprint and hmac.compare_digest(
                computed, record.key_fingerprint
            ):
                return record
        return None

    def by_user_agent(self, user_agent: str | None) -> TrustedClient | None:
        """Return the client whose User-Agent pattern matches this header.

        Шаблоны сопоставляются без учёта регистра и покрывают заголовок целиком
        (``fnmatch``): ``*cursor*`` поймает «vscode/1.9 … Cursor/0.4x», ``cursor/*`` — только
        строку, начинающуюся с «cursor/». Порядок записей в настройках и есть порядок приоритета.
        """
        text = str(user_agent or "").strip().lower()
        if not text:
            return None
        for record in self.records:
            for pattern in record.user_agent_patterns:
                if fnmatch.fnmatch(text, pattern.strip().lower()):
                    return record
        return None

    def describe(self) -> dict[str, object]:
        """Return the table for healthz: каналы и способы, без пояснений и без значений.

        # START_CONTRACT: describe
        #   PURPOSE: Дать владельцу увидеть режим опознания одним взглядом.
        #   INPUTS: none
        #   OUTPUTS: { dict[str, object] - число записей, каналы, счётчики способов, записи }
        #   SIDE_EFFECTS: none
        #   LINKS: M-CLIENT-IDENTITY, M-ROUTER
        # END_CONTRACT: describe
        """
        return {
            "records": len(self.records),
            "channels": list(self.channels),
            "methods": self.methods,
            "entries": [record.to_dict() for record in self.records],
        }


def _split_patterns(raw: object) -> tuple[str, ...]:
    """Прочитать шаблоны User-Agent: строка с запятыми или перечень."""
    if raw is None:
        return ()
    if isinstance(raw, str):
        parts = raw.split(",")
    elif isinstance(raw, (list, tuple, set, frozenset)):
        parts = [str(item) for item in raw]
    else:
        raise ClientIdentityError(
            "CLIENT_IDENTITY_BAD_ENTRY",
            "user_agent must be a string or a list of strings",
        )
    return tuple(part.strip() for part in parts if part.strip())


def _record_from_mapping(entry: Mapping[str, object], index: int) -> TrustedClient:
    """Собрать одну запись из отображения файла настроек."""
    if "channel" not in entry:
        raise ClientIdentityError(
            "CLIENT_IDENTITY_BAD_ENTRY",
            f"trusted_clients[{index}]: field 'channel' is required",
        )
    channel = normalize_channel(entry.get("channel"))
    if not _CHANNEL_RE.match(channel):
        raise ClientIdentityError(
            "CLIENT_IDENTITY_BAD_CHANNEL",
            f"trusted_clients[{index}]: channel name {channel!r} must be latin letters, "
            "digits, dots, dashes or underscores",
        )
    header_value = None
    for key in _HEADER_KEYS:
        if key in entry and str(entry.get(key) or "").strip():
            header_value = normalize_channel(entry.get(key))
            break
    key_fingerprint = None
    for key in _KEY_KEYS:
        if key in entry and str(entry.get(key) or "").strip():
            key_fingerprint = _parse_fingerprint(entry.get(key), channel)
            break
    patterns = ()
    for key in _USER_AGENT_KEYS:
        if key in entry and entry.get(key):
            patterns = _split_patterns(entry.get(key))
            break
    if not (header_value or key_fingerprint or patterns):
        raise ClientIdentityError(
            "CLIENT_IDENTITY_BAD_ENTRY",
            f"trusted_clients[{index}] (channel {channel!r}): no recognition method — "
            "set 'header_value', 'key_sha256' or 'user_agent'",
        )
    return TrustedClient(
        channel=channel,
        header_value=header_value,
        key_fingerprint=key_fingerprint,
        user_agent_patterns=patterns,
        comment=str(entry.get("comment") or "").strip(),
    )


#: Способы в компактной строке настроек: ``cursor=header:cursor;codex=ua:*codex*``.
_COMPACT_METHODS = {
    "header": "header_value",
    "key": "key_sha256",
    "ua": "user_agent",
    "user_agent": "user_agent",
}


def _records_from_compact(raw: str) -> list[dict[str, object]]:
    """Разобрать компактную строку настроек: ``канал=способ:значение`` через точку с запятой."""
    entries: list[dict[str, object]] = []
    for chunk in raw.split(";"):
        piece = chunk.strip()
        if not piece:
            continue
        if "=" not in piece or ":" not in piece:
            raise ClientIdentityError(
                "CLIENT_IDENTITY_BAD_ENTRY",
                f"trusted_clients entry {piece!r} must look like 'channel=method:value' "
                "(methods: header, key, ua)",
            )
        channel, _, rest = piece.partition("=")
        method, _, value = rest.partition(":")
        field_name = _COMPACT_METHODS.get(method.strip().lower())
        if field_name is None:
            raise ClientIdentityError(
                "CLIENT_IDENTITY_BAD_ENTRY",
                f"trusted_clients entry {piece!r}: unknown method {method.strip()!r} "
                f"(known: {', '.join(sorted(_COMPACT_METHODS))})",
            )
        entries.append({"channel": channel.strip(), field_name: value.strip()})
    return entries


def parse_trusted_clients(raw: object) -> TrustedClients:
    """Разобрать раздел настроек «доверенные клиенты» в таблицу опознания.

    # START_CONTRACT: parse_trusted_clients
    #   PURPOSE: Принять раздел настроек в трёх видах и отвергнуть противоречивую таблицу.
    #   INPUTS: { raw: object - None, перечень отображений, компактная строка или JSON-строка }
    #   OUTPUTS: { TrustedClients - таблица опознания }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CONFIG, M-CLIENT-IDENTITY, V-M-CHANNEL-POLICY
    # END_CONTRACT: parse_trusted_clients

    Три вида одного раздела: перечень записей в файле настроек (основной способ — рядом с каждой
    записью можно написать пояснение), компактная строка для файла переменных systemd
    (``cursor=header:cursor;codex=ua:*codex*``) и та же компактная строка в виде JSON-перечня.
    Один и тот же отпечаток ключа не может принадлежать двум каналам: восстановление не имеет
    права зависеть от порядка строк в настройках.
    """
    if raw is None or raw == "" or raw == []:
        return TrustedClients()
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return TrustedClients()
        if text.startswith(("[", "{")):
            try:
                raw = json.loads(text)
            except ValueError as exc:
                raise ClientIdentityError(
                    "CLIENT_IDENTITY_BAD_ENTRY",
                    f"trusted_clients looks like JSON but does not parse: {exc}",
                ) from exc
        else:
            raw = _records_from_compact(text)
    if isinstance(raw, Mapping):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        raise ClientIdentityError(
            "CLIENT_IDENTITY_BAD_ENTRY",
            "trusted_clients must be a list of records or a compact string",
        )
    records: list[TrustedClient] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            raise ClientIdentityError(
                "CLIENT_IDENTITY_BAD_ENTRY",
                f"trusted_clients[{index}]: record must be a mapping",
            )
        records.append(_record_from_mapping(entry, index))
    seen_keys: dict[str, str] = {}
    for record in records:
        if record.channel in BLOCKED_CHANNELS:
            raise ClientIdentityError(
                "CLIENT_IDENTITY_BLOCKED_CHANNEL",
                f"channel {record.channel!r} carries data outside the perimeter and can never "
                "be a trusted client channel",
            )
        if not record.key_fingerprint:
            continue
        owner = seen_keys.get(record.key_fingerprint)
        if owner is not None and owner != record.channel:
            raise ClientIdentityError(
                "CLIENT_IDENTITY_DUPLICATE_KEY",
                f"key fingerprint is assigned to both {owner!r} and {record.channel!r}: "
                "restoration must not depend on the order of the configuration records",
            )
        seen_keys[record.key_fingerprint] = record.channel
    unique: list[TrustedClient] = []
    for record in records:
        if record not in unique:
            unique.append(record)
    return TrustedClients(records=tuple(unique))
# END_BLOCK_TRUSTED_CLIENTS


# START_BLOCK_IDENTIFY_CLIENT
@dataclass(frozen=True)
class ClientIdentity:
    """Итог опознания клиента: имя канала и источник, которым оно получено.

    # START_CONTRACT: ClientIdentity
    #   PURPOSE: Отделить опознанный клиент от неопознанного, сохранив причину решения.
    #   INPUTS: { channel: str | None - канал, source: str - источник, detail: str - что именно совпало }
    #   OUTPUTS: { ClientIdentity - итог }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CLIENT-IDENTITY, M-CHANNEL-POLICY
    # END_CONTRACT: ClientIdentity

    ``detail`` — короткая метка для журнала: имя канала, отпечаток ключа или шаблон. Значений
    клиента и самого ключа в ней не бывает.
    """

    channel: str | None = None
    source: str = SOURCE_NONE
    detail: str = ""

    @property
    def recognized(self) -> bool:
        """Say whether the client was recognized at all."""
        return bool(self.channel)


def _header(headers: Mapping[str, str] | None, name: str) -> str | None:
    """Прочитать заголовок без учёта регистра его имени."""
    if not headers:
        return None
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            text = str(value or "").strip()
            return text or None
    return None


def identify_client(
    headers: Mapping[str, str] | None,
    clients: TrustedClients,
    declared: str | None = None,
) -> ClientIdentity:
    """Опознать клиента запроса по трём источникам в порядке доверия.

    # START_CONTRACT: identify_client
    #   PURPOSE: Единственная точка, где решается, чей это запрос и как клиент назвался.
    #   INPUTS: { headers: Mapping[str, str] | None - заголовки запроса, clients: TrustedClients - таблица настроек, declared: str | None - канал, названный заголовком вызывающего }
    #   OUTPUTS: { ClientIdentity - канал и источник либо признак «не опознан» }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CHANNEL-POLICY, M-ROUTER, V-M-CHANNEL-POLICY
    # END_CONTRACT: identify_client

    Порядок источников — часть решения владельца: заголовок (самый простой), ключ (самый
    надёжный из трёх, потому что его нельзя предъявить, не зная), User-Agent (расширяемая
    таблица заготовок). Не опознан — решение принимает настройка «поведение для неизвестного
    клиента», а не этот модуль.
    """
    # 1. Явный заголовок: сначала новый, затем прежний — уже настроенные клиенты не ломаются.
    named = declared or _header(headers, IDENTITY_HEADER) or _header(headers, LEGACY_IDENTITY_HEADER)
    if named:
        channel = normalize_channel(named)
        if channel:
            record = clients.by_header_value(channel)
            return ClientIdentity(
                channel=record.channel if record else channel,
                source=SOURCE_HEADER,
                detail=channel,
            )

    # 2. Ключ доступа: предъявленный ключ, не совпавший с таблицей, понижения не получает.
    presented = _header(headers, CLIENT_KEY_HEADER)
    if presented:
        record = clients.by_key(presented)
        if record is not None:
            return ClientIdentity(
                channel=record.channel, source=SOURCE_KEY, detail=fingerprint(presented)
            )
        return ClientIdentity(channel=None, source=SOURCE_NONE, detail="key_not_configured")

    # 3. User-Agent: шаблон из настроек, сопоставление без учёта регистра.
    user_agent = _header(headers, "User-Agent")
    if user_agent:
        record = clients.by_user_agent(user_agent)
        if record is not None:
            return ClientIdentity(
                channel=record.channel, source=SOURCE_USER_AGENT, detail=record.channel
            )
    return ClientIdentity(channel=None, source=SOURCE_NONE, detail="")


def declared_identity(channel: str | None) -> ClientIdentity:
    """Назвать канал, объявленный внутри запроса меткой доставки (путь Hermes).

    # START_CONTRACT: declared_identity
    #   PURPOSE: Сохранить прежний способ опознания канала и подписать его своим источником.
    #   INPUTS: { channel: str | None - канал из метки доставки }
    #   OUTPUTS: { ClientIdentity - опознание или признак «не опознан» }
    #   SIDE_EFFECTS: none
    #   LINKS: M-ROUTER, M-CHANNEL-POLICY
    # END_CONTRACT: declared_identity
    """
    name = normalize_channel(channel)
    if not name:
        return ClientIdentity(channel=None, source=SOURCE_NONE, detail="")
    return ClientIdentity(channel=name, source=SOURCE_DECLARED, detail=name)
# END_BLOCK_IDENTIFY_CLIENT


def main(argv: Sequence[str] | None = None) -> int:
    """Напечатать отпечаток ключа — то, что владелец вписывает в trusted_clients.

    # START_CONTRACT: main
    #   PURPOSE: Дать владельцу получить отпечаток ключа, не оставляя ключ в настройках.
    #   INPUTS: { argv: Sequence[str] | None - аргументы командной строки }
    #   OUTPUTS: { int - код возврата }
    #   SIDE_EFFECTS: читает аргументы и печатает отпечаток
    #   LINKS: M-CLIENT-IDENTITY, docs/OPERATIONS.md
    # END_CONTRACT: main

    Запуск: ``python3 -m src.client_identity <ключ>``. В командной строке ключ виден в истории
    оболочки, поэтому в эксплуатации он читается из файла: ``python3 -m src.client_identity
    "$(cat /etc/pii-proxy/client-keys/cursor)"``.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or args[0] in {"-h", "--help"}:
        print("usage: python3 -m src.client_identity <key>")
        return 0 if args[:1] in (["-h"], ["--help"]) else 2
    print(fingerprint(args[0]))
    return 0


if __name__ == "__main__":  # pragma: no cover - служебная точка входа
    raise SystemExit(main())
