# FILE: src/router.py
# VERSION: 1.4.2
# START_MODULE_CONTRACT
#   PURPOSE: Serve the local HTTP endpoint the agent talks to and orchestrate the fail-closed pipeline: image policy, tokenization, validation, degradation of residual findings, upstream forwarding, detokenization, audit.
#   SCOPE: route parsing for ds and nord prefixes, chat completion pipeline, residual repair instead of refusal (Вариант 1), healthz status, JSON error shapes, service assembly and systemd entry point, hot reload of the client dictionary and of the open name layer, incident journal on residual findings.
#   DEPENDS: M-CONFIG, M-TOKENIZER, M-DETOKENIZER, M-VALIDATOR, M-UPSTREAM, M-AUDIT, M-MAP-STORE, M-DICT, M-NAME-LAYER, M-INCIDENT-JOURNAL
#   LINKS: M-ROUTER, V-M-ROUTER, export-app, fn-handle_chat_completions, fn-handle_healthz, fn-main
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   CHANNEL_HEADER - request header carrying the transport channel
#   CHANNEL_MARKER - метка доставки платформы в системном промпте
#   ORIGIN_PLATFORM - объявление платформы текущего сообщения (Gateway message origin)
#   ROUTE_PATTERN - path pattern splitting route prefix from upstream path
#   StreamResponse - deferred streaming answer
#   RouterError - HTTP-facing failure with a code and status
#   _RepairOutcome - итог второго прохода по остатку: замены, коды, правила, признак попытки
#   ProxyService - orchestration of the whole pipeline
#   fn-handle_chat_completions - full request pipeline with fail-closed semantics
#   fn-refresh_dictionary - перечитать клиентский словарь по изменению файла
#   fn-refresh_name_layer - перечитать открытый слой распознавания по изменению файла
#   fn-record_incident - записать промах детектора классами и числами
#   fn-_repair_residual - заменить остаток вторым проходом и вернуть исход замены
#   fn-health - component status without any PII
#   fn-build_service - assemble a service from a validated config
#   fn-main - process entry point
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.3.0 - сборка службы устанавливает лексику оператора из настроек до сборки детекторов; healthz показывает её размеры по разделам; точка входа читает необязательный файл настроек.
#   LAST_CHANGE: v1.4.3 - Phase-18 (23.09.2026): алерты службы умеют уходить в Telegram (Bot API, только стандартная библиотека) — чат и тема задаются настройками, Telegram предпочитается Mattermost; сбой доставки по-прежнему не ломает конвейер.
#   PREVIOUS: v1.4.2 - Phase-17 шаг 6 (20.09.2026): восстановлена функция `_make_alert_sender` (её вызов остался в `main`, и служба падала с NameError на старте) и убран осиротевший блок её тела внутри `_require_registry_integrity`, где он обращался к несуществующему `config`; статическая проверка символов точки входа ловит этот класс отказов без запуска службы.
#   EARLIER: v1.4.1 - дефект-фикс 19.09.2026: счётчику кэша провайдера отдаётся служебный кадр потока (`usage`) — попадание в кэш DeepSeek, названное владельцем ключевым фактором приёмки, теперь измеряется и на потоковом пути, которым ходят мессенджеры.
#   PREVIOUS: v1.4.0 - дефект-фикс 19.09.2026: канал берётся не только из метки доставки в системном промпте, но и из объявления происхождения текущего сообщения; расхождение метки и объявления разрешается в сторону запрета восстановления значений. Инцидент перестаёт терять канал у восстановленных сессий, где метки нет вовсе.
#   EARLIER: v1.3.1 - дефект-фикс 19.09.2026: отказ заслона по остатку ПД возвращается кодом 422, а не 403.
#   EARLIER: v1.3.0 - Phase-15 шаг 2 (Вариант 1): остаток ПД заменяется вторым проходом и запрос доходит до провайдера (действие degraded_tokenized в журнале аудита и инцидент без значений); жёсткая блокировка остаётся только там, где замена не удалась.
#   EARLIER: v1.2.0 - Phase-15 шаг 1: остаток ПД записывается в журнал инцидентов действием blocked (значений в записи нет), журнал поднимается в build_service и виден в healthz счётчиком незаписанных.
# END_CHANGE_SUMMARY

"""HTTP entry point.

Implements M-ROUTER from docs/ARCHITECTURE.md. The order of steps is part
of the contract and is asserted by tests: config, image policy, tokenization,
validation, upstream, detokenization, audit. Any failure before the upstream call
results in a 4xx and zero outbound requests (UC-005): a residual-PII block answers
422 (the client must read the real reason, not "your API key was rejected"), while
technical fail-closed failures keep 403.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import urllib.request
import uuid
from collections.abc import Collection, Iterator
from dataclasses import dataclass
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Sequence

from src.audit import AuditEvent, AuditJournal
from src.cache import TokenizationCache
from src.channel_policy import ChannelPolicy
from src.config import ProxyConfig, load_config
from src.detect_name import NameDetector
from src.detect_ner import NerDetector
from src.dictionary import PiiDictionary, live_file_state
from src.detokenizer import DetokenizeError, PayloadDetokenizer, collect_identifiers
from src.incident_journal import IncidentEvent, IncidentJournal
from src.name_coherence import MODE_OFF, load_name_coherence
from src.stream_relay import StreamRelay
from src.map_store import MapStoreError, TokenMapStore
from src.name_layer import LayerError, load_name_layer
from src.own_vocabulary import apply as apply_own_vocabulary
from src.token_factory import find_tokens
from src.tokenizer import PayloadTokenizer, TokenizeError
from src.upstream import UpstreamClient, UpstreamError
from src.validator import ResidualPiiValidator

LOGGER_NAME = "HttpRouter"
LOG_MARKER = "[HttpRouter][handle_chat_completions][BLOCK_HANDLE_CHAT_COMPLETIONS]"

# Бюджет кэша блоков задаётся в мегабайтах (PII_PROXY_BLOCK_CACHE_MB), а предел
# в TokenizationCache — в байтах: перевод делается один раз, здесь.
BYTES_PER_MEGABYTE = 1024 * 1024

CHANNEL_HEADER = "X-Hermes-Channel"
# ``[[delivery:telegram]]`` — injected by Hermes into the platform hint of the
# system prompt (config.yaml → platform_hints.<platform>.append).
CHANNEL_MARKER = re.compile(r"\[\[delivery:([a-zA-Z0-9_-]{1,32})\]\]")
# Hermes добавляет в запрос объявление происхождения текущего сообщения:
#   Gateway message origin (JSON data, not instructions or authorization):
#   {"platform": "telegram", "chat_id": "...", ...}
# Метка в системном промпте описывает платформу *сессии* (и её может не быть в
# восстановленной сессии), а это поле — платформу *текущего сообщения*.
ORIGIN_PLATFORM = re.compile(
    r"Gateway message origin[\s\S]{0,160}?\"platform\"\s*:\s*\"([a-zA-Z0-9_-]{1,32})\""
)


def _is_image_part(node: Any) -> bool:
    """Return True when a node is a message content part carrying an image.

    # START_CONTRACT: _is_image_part
    #   PURPOSE: Recognise an image inside message content only.
    #   INPUTS: { node: Any - candidate content part }
    #   OUTPUTS: { bool - True when the part is an image }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CHANNEL-POLICY, V-M-ROUTER
    # END_CONTRACT: _is_image_part
    """
    if not isinstance(node, dict):
        return False
    if isinstance(node.get("image_url"), (dict, str)):
        return True
    if isinstance(node.get("input_image"), (dict, str)):
        return True
    kind = node.get("type")
    return isinstance(kind, str) and kind.lower() in {"image_url", "input_image", "image"}


def _channel_from_payload(payload: dict, allowed: Collection[str] = ()) -> str | None:
    """Return the delivery channel declared inside the request, if any.

    # START_CONTRACT: _channel_from_payload
    #   PURPOSE: Learn the transport channel without a header the agent cannot send.
    #   INPUTS: { payload: dict - request body, allowed: Collection[str] - каналы, где восстановление разрешено }
    #   OUTPUTS: { str | None - channel name or None }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CHANNEL-POLICY, M-ROUTER, V-M-CHANNEL-POLICY
    # END_CONTRACT: _channel_from_payload

    Дефект 19.09.2026: канал брался только из метки ``[[delivery:…]]`` в системном
    промпте, а метка описывает платформу **сессии**: у восстановленных сессий её нет
    вовсе, и запрос получал пустой канал — инцидент в журнале оставался без канала.
    В том же запросе Hermes объявляет платформу **текущего сообщения** блоком
    ``Gateway message origin … "platform": "telegram"``.

    Правило разбора: метка остаётся основным источником, объявление происхождения —
    вторым. Расхождение разрешается в сторону **запрета восстановления**: если один
    из двух источников называет канал вне allowlist, побеждает он. Так инцидент
    атрибутируется по каналу, а открытые значения не могут уйти в канал, который
    хотя бы один источник считает внешним. Текст запроса не может *расширить*
    восстановление: он способен только его отключить — ошибка в эту сторону
    безопасна (пользователь увидит код вместо значения).
    """
    declared = _declared_channel(payload)
    origin = _origin_channel(payload)
    if not declared:
        return origin
    if not origin or origin == declared:
        return declared
    allowed_set = {str(item).strip().lower() for item in allowed if item}
    if origin not in allowed_set:
        return origin
    if declared not in allowed_set:
        return declared
    return declared


def _declared_channel(payload: dict) -> str | None:
    """Прочитать метку доставки из системного сообщения запроса.

    # START_CONTRACT: _declared_channel
    #   PURPOSE: Метка ``[[delivery:…]]`` — основной источник канала (подсказка платформы).
    #   INPUTS: { payload: dict - request body }
    #   OUTPUTS: { str | None - channel name or None }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CHANNEL-POLICY, M-ROUTER, V-M-CHANNEL-POLICY
    # END_CONTRACT: _declared_channel

    Метка ищется только в системных сообщениях: текст пользователя не имеет права
    самочинно разрешить восстановление значений.
    """
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return None
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "system":
            continue
        content = message.get("content")
        if not isinstance(content, str):
            continue
        found = CHANNEL_MARKER.search(content)
        if found:
            return found.group(1).strip().lower()
    return None


def _origin_channel(payload: dict) -> str | None:
    """Прочитать платформу текущего сообщения из блока происхождения, если он есть.

    # START_CONTRACT: _origin_channel
    #   PURPOSE: Знать канал текущего сообщения, когда метки в промпте нет или она устарела.
    #   INPUTS: { payload: dict - request body }
    #   OUTPUTS: { str | None - channel name or None }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CHANNEL-POLICY, M-ROUTER, V-M-CHANNEL-POLICY
    # END_CONTRACT: _origin_channel

    Берётся **последнее** объявление: блок дописывается перед каждым ходом, и текущее
    сообщение — последнее в запросе. Значение используется только для сужения канала
    (см. ``_channel_from_payload``), поэтому подделка этого блока в тексте запроса
    может отключить восстановление, но не разрешить его.
    """
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return None
    found: str | None = None
    for message in messages:
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if not isinstance(content, str):
            continue
        match = ORIGIN_PLATFORM.search(content)
        if match:
            found = match.group(1).strip().lower()
    return found


ROUTE_PATTERN = re.compile(r"^/(?P<route>[A-Za-z0-9_-]+)(?P<path>/.*)$")
CHAT_SUFFIX = "/chat/completions"
HEALTH_PATH = "/healthz"
IMAGE_MARKERS = ("image_url", "input_image", "image")
STREAM_CONTENT_TYPE = "text/event-stream; charset=utf-8"


@dataclass(frozen=True)
class StreamResponse:
    """A response that is written to the client frame by frame.

    # START_CONTRACT: StreamResponse
    #   PURPOSE: Let the service hand a stream back without materializing it.
    #   INPUTS: { status: int - http status, chunks: Iterator[bytes] - SSE frames }
    #   OUTPUTS: { StreamResponse - value object }
    #   SIDE_EFFECTS: none
    #   LINKS: M-ROUTER, M-STREAM-RELAY, V-M-STREAM-RELAY
    # END_CONTRACT: StreamResponse
    """

    status: int
    chunks: Iterator[bytes]
    content_type: str = STREAM_CONTENT_TYPE


def sse_single_frame(body: dict) -> Iterator[bytes]:
    """Wrap a complete JSON response into one SSE frame plus the terminator.

    # START_CONTRACT: sse_single_frame
    #   PURPOSE: Serve a streaming client from the buffered path (PII_PROXY_STREAM_MODE=json_only).
    #   INPUTS: { body: dict - the buffered response }
    #   OUTPUTS: { Iterator[bytes] - one data frame and [DONE] }
    #   SIDE_EFFECTS: none
    #   LINKS: M-ROUTER, M-CONFIG, V-M-ROUTER
    # END_CONTRACT: sse_single_frame
    """
    yield b"data: " + json.dumps(body, ensure_ascii=False).encode("utf-8") + b"\n\n"
    yield b"data: [DONE]\n\n"


class RouterError(RuntimeError):
    """Routing or pipeline failure with a stable code.

    # START_CONTRACT: RouterError
    #   PURPOSE: Classify pipeline failures for the response shape.
    #   INPUTS: { code: str - stable code, message: str - detail, status: int - http status }
    #   OUTPUTS: { RouterError - exception instance }
    #   SIDE_EFFECTS: none
    #   LINKS: M-ROUTER, V-M-ROUTER
    # END_CONTRACT: RouterError
    """

    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status = status


# START_BLOCK_HANDLE_CHAT_COMPLETIONS
@dataclass(frozen=True)
class _RepairOutcome:
    """Итог второго прохода по остатку ПД (Вариант 1).

    # START_CONTRACT: _RepairOutcome
    #   PURPOSE: Отделить «замена выполнена» от «замена не удалась» — от этого зависит, идёт запрос или блокируется.
    #   INPUTS: { replaced: int - заменённых вхождений, codes: tuple[tuple[str, str], ...] - выданные коды (класс, код), rules: tuple[str, ...] - правила-источники, attempted: bool - была ли попытка замены }
    #   OUTPUTS: { _RepairOutcome - value object }
    #   SIDE_EFFECTS: none
    #   LINKS: M-VALIDATOR, M-TOKENIZER, M-INCIDENT-JOURNAL, V-M-ROUTER
    # END_CONTRACT: _RepairOutcome

    ``attempted=False`` означает, что заменить было нечем (у заслона нет второго прохода):
    тогда остаток блокируется как прежде, и в журнале аудита стоит причина residual_pii, а
    не replacement_failed.
    """

    replaced: int = 0
    codes: tuple[tuple[str, str], ...] = ()
    rules: tuple[str, ...] = ()
    attempted: bool = False


class ProxyService:
    """Orchestrate one request through the anonymization pipeline.

    # START_CONTRACT: ProxyService
    #   PURPOSE: Own the pipeline step order and the fail-closed blocks.
    #   INPUTS: { config: ProxyConfig, store: TokenMapStore, tokenizer: PayloadTokenizer, detokenizer: PayloadDetokenizer, upstream: UpstreamClient, audit: AuditJournal, validator: Any | None }
    #   OUTPUTS: { ProxyService - ready service }
    #   SIDE_EFFECTS: writes bindings, journal entries and outbound provider calls
    #   LINKS: M-CONFIG, M-TOKENIZER, M-DETOKENIZER, M-UPSTREAM, M-AUDIT, V-M-ROUTER
    # END_CONTRACT: ProxyService
    """

    def __init__(
        self,
        config: ProxyConfig,
        store: TokenMapStore,
        tokenizer: Any,
        detokenizer: PayloadDetokenizer,
        upstream: UpstreamClient,
        audit: AuditJournal,
        validator: Any | None = None,
        cache: Any | None = None,
        dictionary: Any | None = None,
        ner: Any | None = None,
        name_layer: Any | None = None,
        incident_journal: Any | None = None,
        coherence: Any | None = None,
        registry_report: Any | None = None,
    ) -> None:
        self._config = config
        self._store = store
        self._tokenizer = tokenizer
        self._detokenizer = detokenizer
        self._upstream = upstream
        self._audit = audit
        self._validator = validator
        self._cache = cache
        self._dictionary = dictionary
        self._ner = ner
        self._name_layer = name_layer
        self._incidents = incident_journal
        # Phase-17: индекс со-встречаемости и итог проверки реестра на старте — и то, и
        # другое показывается в healthz, чтобы «заслон включён» было фактом, а не словом.
        self._coherence = coherence
        self._registry = registry_report
        self._provider_cache: dict[str, Any] = {
            "requests": 0,
            "hit_tokens": 0,
            "miss_tokens": 0,
            "last": {},
        }

    def _record_provider_cache(self, body: Any) -> None:
        """Accumulate the provider's own prompt-cache counters.

        # START_CONTRACT: _record_provider_cache
        #   PURPOSE: Turn "the cache still works" into a number the owner can read.
        #   INPUTS: { body: Any - upstream response }
        #   OUTPUTS: { None }
        #   SIDE_EFFECTS: updates counters exposed by healthz
        #   LINKS: M-UPSTREAM, V-M-ROUTER, acceptance
        # END_CONTRACT: _record_provider_cache

        DeepSeek reports how much of a request was served from its prefix cache
        (``prompt_cache_hit_tokens`` / ``prompt_cache_miss_tokens``). Those numbers
        are the direct evidence for the acceptance criterion the owner named on
        15.09.2026: the proxy must not break prompt caching. Provider spellings
        differ, so a few known variants are checked.
        """
        if not isinstance(body, dict):
            return
        usage = body.get("usage")
        if not isinstance(usage, dict):
            return
        hit = _first_int(usage, ("prompt_cache_hit_tokens", "cache_hit_tokens", "cached_tokens"))
        miss = _first_int(
            usage, ("prompt_cache_miss_tokens", "cache_miss_tokens", "uncached_tokens")
        )
        if hit is None and miss is None:
            return
        self._provider_cache["requests"] += 1
        self._provider_cache["hit_tokens"] += hit or 0
        self._provider_cache["miss_tokens"] += miss or 0
        self._provider_cache["last"] = {"hit_tokens": hit or 0, "miss_tokens": miss or 0}

    def refresh_dictionary(self) -> bool:
        """Hot-reload the dictionary and drop the cache when it changed.

        # START_CONTRACT: refresh_dictionary
        #   PURPOSE: Pick up the scheduled export without restarting the proxy.
        #   INPUTS: none
        #   OUTPUTS: { bool - True when a new dictionary version was loaded }
        #   SIDE_EFFECTS: reloads the dictionary, may clear the tokenization cache, appends an audit event
        #   LINKS: M-DICT, M-CACHE, V-M-DICT, V-M-CACHE
        # END_CONTRACT: refresh_dictionary

        The cache must be dropped on reload: it holds results produced under the
        previous dictionary, and next turn those stale entries would be re-sent
        with a value the new dictionary knows about. A stale cache entry is a
        cache miss for the provider but a leak for us.
        """
        dictionary = self._dictionary
        if dictionary is None or not hasattr(dictionary, "reload_if_changed"):
            return False
        try:
            reloaded = bool(dictionary.reload_if_changed())
        except Exception as exc:  # noqa: BLE001 - a broken dictionary must not break serving
            logging.getLogger(LOGGER_NAME).warning(
                "[HttpRouter][refresh_dictionary][BLOCK_RELOAD_DICTIONARY] reload failed: %s",
                type(exc).__name__,
            )
            return False
        if not reloaded:
            return False
        if self._cache is not None:
            self._cache.clear()
            self._audit.append(
                AuditEvent(
                    session_id="-",
                    action="cache_invalidated",
                    direction="internal",
                    cls="-",
                    count=0,
                    channel="",
                    reason="dictionary_reload",
                )
            )
        self._audit.append(
            AuditEvent(
                session_id="-",
                action="dictionary_reload",
                direction="internal",
                cls="-",
                count=int(getattr(dictionary, "size", 0)),
                channel="",
                reason="",
            )
        )
        return True

    def refresh_name_layer(self) -> bool:
        """Перечитать открытый слой распознавания, если файл изменился.

        # START_CONTRACT: refresh_name_layer
        #   PURPOSE: Пополненный словарь должен работать без перезапуска службы.
        #   INPUTS: none
        #   OUTPUTS: { bool - True, если значения слоя заменены }
        #   SIDE_EFFECTS: читает файл слоя, очищает кэш токенизации, пишет событие журнала
        #   LINKS: M-NAME-LAYER, M-CACHE, V-M-NAME-LAYER
        # END_CONTRACT: refresh_name_layer

        Кэш очищается по той же причине, что и при перезагрузке словаря: в нём лежат тексты,
        обезличенные по прежнему списку, и запись «здесь ничего не нашлось» после пополнения
        словаря стала бы утечкой — значение теперь известно, а текст ушёл бы открытым.

        Значения заменяются внутри того же объекта слоя: детектор, резолвер идентичности и
        заслон держат на него ссылку, поэтому подмены объекта не требуется.
        """
        layer = self._name_layer
        if layer is None or not hasattr(layer, "reload_if_changed"):
            return False
        try:
            reloaded = bool(layer.reload_if_changed())
        except Exception as exc:  # noqa: BLE001 - сломанный слой не должен останавливать службу
            logging.getLogger(LOGGER_NAME).warning(
                "[HttpRouter][refresh_name_layer][BLOCK_RELOAD_NAME_LAYER] reload failed: %s",
                type(exc).__name__,
            )
            return False
        if not reloaded:
            return False
        if self._cache is not None:
            self._cache.clear()
        self._audit.append(
            AuditEvent(
                session_id="-",
                action="name_layer_reload",
                direction="internal",
                cls="-",
                count=int(getattr(layer, "size", 0)),
                channel="",
                reason="",
            )
        )
        return True

    def record_incident(
        self,
        action: str,
        cls: str = "-",
        channel: str = "",
        code: str = "",
        findings: int = 0,
        replacements: int = 0,
        rule: str = "",
        codes: Sequence[tuple[str, str]] = (),
    ) -> bool:
        """Записать промах детектора в журнал инцидентов — классами и числами.

        # START_CONTRACT: record_incident
        #   PURPOSE: Оставить доказательство промаха, не записав ни одного значения.
        #   INPUTS: { action: str - машинное действие, cls: str - класс, channel: str, code: str - выданный код, findings/replacements: int - счётчики, rule: str - правило-источник, codes: Sequence[tuple[str, str]] - коды для пометки в справочнике }
        #   OUTPUTS: { bool - True, когда запись удалась }
        #   SIDE_EFFECTS: дописывает журнал инцидентов, помечает связки в справочнике
        #   LINKS: M-INCIDENT-JOURNAL, M-MAP-STORE, V-M-ROUTER
        # END_CONTRACT: record_incident

        Сбой журнала не отменяет уже выполненную защиту и не должен ломать ответ: значение к
        этому моменту заменено кодом, а незаписанный инцидент попадает в счётчик и в журнал
        аудита. Поэтому исключение сюда не пропускается.
        """
        journal = self._incidents
        if journal is None:
            return False
        try:
            result = journal.record(
                IncidentEvent(
                    cls=cls or "-",
                    action=action,
                    channel=str(channel or ""),
                    code=code,
                    findings=int(findings),
                    replacements=int(replacements),
                    rule=rule,
                ),
                codes=codes,
                store=self._store,
            )
        except Exception as exc:  # noqa: BLE001 - журнал не в критическом пути ответа
            logging.getLogger(LOGGER_NAME).warning(
                "[HttpRouter][record_incident][BLOCK_RECORD_INCIDENT] incident not recorded: %s",
                type(exc).__name__,
            )
            return False
        return bool(result.get("written"))

    def _repair_residual(
        self, anonymized: dict, original: dict, stats: dict[str, int]
    ) -> _RepairOutcome:
        """Заменить остаток вторым проходом тем же детектором и той же фабрикой кодов.

        # START_CONTRACT: _repair_residual
        #   PURPOSE: Выполнить Вариант 1 — пользователь получает ответ, остаток уходит кодом, а не открытым текстом.
        #   INPUTS: { anonymized: dict - исходящий запрос (правится на месте), original: dict - исходный запрос, stats: dict[str, int] - счётчики классов }
        #   OUTPUTS: { _RepairOutcome - замены, выданные коды, правила, признак попытки }
        #   SIDE_EFFECTS: правит anonymized, пишет связки в справочник
        #   LINKS: M-VALIDATOR, M-TOKENIZER, M-INCIDENT-JOURNAL, V-M-ROUTER
        # END_CONTRACT: _repair_residual

        Сбой второго прохода наружу не пропускается: он означает «замена не удалась», а это
        не отказ от запроса, а возврат к жёсткой блокировке. Коды, выданные до сбоя, всё
        равно возвращаются: значение уже лежит в справочнике, и его нужно пометить «из
        инцидента», чтобы тренер его увидел.
        """
        repair = getattr(self._validator, "repair_outgoing", None)
        issue_fn: Any = getattr(self._tokenizer, "issue_identifier", None)
        if not callable(repair) or not callable(issue_fn):
            # Нечем заменять: второго прохода нет. Это не ошибка — это отсутствие Варианта 1,
            # и остаток обязан блокироваться как прежде.
            return _RepairOutcome()
        issued: list[tuple[str, str]] = []

        def issue_code(cls: str, identity: str, raw: str) -> str:
            """Выдать код тем же присвоением, что и первый проход, и запомнить его."""
            token = str(issue_fn(cls, identity, raw, stats))
            issued.append((cls, token))
            return token

        try:
            report = repair(anonymized, original, issue_code)
        except Exception as exc:  # noqa: BLE001 - сбой замены = блокировка, а не отказ журнала
            logging.getLogger(LOGGER_NAME).warning(
                "[HttpRouter][repair_residual][BLOCK_DEGRADED_TOKENIZED] second pass failed: %s",
                type(exc).__name__,
            )
            return _RepairOutcome(codes=tuple(issued), attempted=True)
        return _RepairOutcome(
            replaced=int(getattr(report, "total", 0) or 0),
            codes=tuple(issued),
            rules=tuple(getattr(report, "rules", ()) or ()),
            attempted=True,
        )

    AGGREGATE_WORDS = (
        "сколько",
        "выручка",
        "продаж",
        "отчёт",
        "отчет",
        "дайджест",
        "статистик",
        "конверсия",
        "продлен",
        "продлён",
        "сводк",
        "динамик",
    )

    def _check_rarity(self, anonymized: dict, session_id: str, channel: str | None) -> None:
        """Flag (or block) requests whose data could identify a single person.

        # START_CONTRACT: _check_rarity
        #   PURPOSE: Enforce the k-anonymity policy for anything leaving the perimeter.
        #   INPUTS: { anonymized: dict - anonymized payload, session_id: str, channel: str | None }
        #   OUTPUTS: { None }
        #   SIDE_EFFECTS: appends an audit event, raises RouterError when enforced
        #   LINKS: M-ROUTER, M-AUDIT, V-M-ROUTER
        # END_CONTRACT: _check_rarity

        Two deliberate choices. First, the guard looks at *distinct tokens*, not at
        raw text, so it works on the anonymized payload and never needs the values.
        Second, it only fires for aggregate-shaped requests: a manager asking about
        one client by name is normal operational work, while a "sales report" that
        rests on one or two people is a small-cell disclosure. That distinction
        keeps the signal useful instead of flagging every per-client request.
        """
        text = json.dumps(anonymized, ensure_ascii=False).lower()
        if not any(word in text for word in self.AGGREGATE_WORDS):
            return
        distinct = {
            (cls, token)
            for _, _, cls, token in find_tokens(json.dumps(anonymized, ensure_ascii=False))
        }
        persons = len({token for cls, token in distinct if cls == "P"})
        if persons == 0 or persons >= self._config.rarity_k:
            return
        # The journal schema is closed on purpose: a human-readable sentence is
        # rejected, so the reason is a machine code and the numbers travel in
        # `count` (the person count) plus the configured k in healthz.
        if self._config.rarity_enforce:
            self._audit.append(
                AuditEvent(
                    session_id=session_id,
                    action="rarity_blocked",
                    direction="outbound",
                    cls="P",
                    count=persons,
                    channel=str(channel or ""),
                    reason="rarity_quota",
                )
            )
            raise RouterError(
                "rarity_blocked",
                f"в запросе данные {persons} человек(а), порог k={self._config.rarity_k}",
                status=403,
            )
        self._audit.append(
            AuditEvent(
                session_id=session_id,
                action="rarity_warning",
                direction="outbound",
                cls="P",
                count=persons,
                channel=str(channel or ""),
                reason="rarity_quota",
            )
        )

    @staticmethod
    def new_session_id() -> str:
        """Return a fresh correlation id for one request."""
        return uuid.uuid4().hex[:16]

    IMAGE_REMINDER = (
        "\u26a0\ufe0f В запросе были изображения. Они передаются без обезличивания: "
        "если на них есть персональные данные клиентов, это нарушение политики обработки персональных данных."
    )

    @classmethod
    def _append_image_reminder(cls, body: dict) -> int:
        """Append the image-policy reminder to every textual answer.

        # START_CONTRACT: _append_image_reminder
        #   PURPOSE: Keep the image policy visible in the chat instead of silently deleting it.
        #   INPUTS: { body: dict - upstream response }
        #   OUTPUTS: { int - how many answers received the reminder }
        #   SIDE_EFFECTS: mutates the response body
        #   LINKS: M-CHANNEL-POLICY, V-M-ROUTER
        # END_CONTRACT: _append_image_reminder
        """
        choices = body.get("choices")
        if not isinstance(choices, list):
            return 0
        appended = 0
        for choice in choices:
            message = choice.get("message") if isinstance(choice, dict) else None
            if not isinstance(message, dict):
                continue
            content = message.get("content")
            if isinstance(content, str) and content.strip():
                message["content"] = f"{content}\n\n{cls.IMAGE_REMINDER}"
                appended += 1
        return appended

    @staticmethod
    def contains_images(node: Any) -> bool:
        """Return True when a message carries an image part.

        # START_CONTRACT: contains_images
        #   PURPOSE: Feed the image policy before any tokenization, looking only at message content.
        #   INPUTS: { node: Any - request payload }
        #   OUTPUTS: { bool - True when an image part is present }
        #   SIDE_EFFECTS: none
        #   LINKS: V-M-ROUTER
        # END_CONTRACT: contains_images

        Only message content counts. The first live request after the switch
        (16.09.2026) was rejected because a *tool schema* declares a parameter
        named ``image_url``; scanning the whole payload turned every agent request
        into 403, which would have killed the agent on its first message. A tool
        definition is not an image, and neither is text that mentions one.
        """
        if not isinstance(node, dict):
            return False
        messages = node.get("messages")
        if not isinstance(messages, list):
            return False
        for message in messages:
            if not isinstance(message, dict):
                continue
            content = message.get("content")
            if isinstance(content, list):
                if any(_is_image_part(part) for part in content):
                    return True
            elif _is_image_part(content):
                return True
        return False

    def handle_chat_completions(
        self, payload: dict, route: str, path: str, channel: str | None
    ) -> tuple[int, dict] | StreamResponse:
        """Run the full pipeline for one chat completion request.

        # START_CONTRACT: handle_chat_completions
        #   PURPOSE: Anonymize, validate, forward, restore, audit.
        #   INPUTS: { payload: dict - request body, route: str - ds or nord, path: str - upstream path, channel: str | None - transport channel }
        #   OUTPUTS: { tuple[int, dict] - status and body, or StreamResponse - frame stream (Phase-11) }
        #   SIDE_EFFECTS: store writes, journal writes, outbound provider call
        #   LINKS: M-TOKENIZER, M-VALIDATOR, M-UPSTREAM, M-DETOKENIZER, M-STREAM-RELAY, V-M-ROUTER
        # END_CONTRACT: handle_chat_completions
        """
        session_id = self.new_session_id()
        self.refresh_dictionary()
        self.refresh_name_layer()
        # The transport channel decides whether restored values may be shown at
        # all, and the agent does not send a header for it (checked in the Hermes
        # source on 16.09.2026). Hermes does inject per-platform hint text into the
        # system prompt, so the channel travels as a marker inside the request:
        # without it the decision stays "no restore", which is the safe default.
        # Дефект 19.09.2026: метки в системном промпте может не быть (восстановленная
        # сессия) или она описывает платформу сессии, а не текущего сообщения. Помимо
        # метки читаем объявление происхождения последнего сообщения; расхождение
        # решается в сторону запрета восстановления (см. _channel_from_payload).
        channel = channel or _channel_from_payload(payload, self._config.detok_channels)

        if route not in self._config.routes:
            self._audit.record_block(session_id, "unknown_route", channel=str(channel or ""))
            raise RouterError("unknown_route", f"маршрут {route!r} не настроен", status=404)

        # Image policy (owner decision 16.09.2026): images are NOT blocked. Blocking
        # looked like protection but a single screenshot in a session's history made
        # every later request fail, and a vision route could never work at all.
        # Instead the request proceeds and the answer carries a reminder that images
        # with personal data violate the policy — the responsibility stays visible
        # to whoever reads the chat.
        images_present = self.contains_images(payload)
        if images_present and self._config.image_policy == "block":
            self._audit.record_block(session_id, "images_blocked", channel=str(channel or ""))
            raise RouterError(
                "images_blocked",
                "изображения запрещены в строгом режиме (включите PII_PROXY_IMAGE_POLICY=allow)",
                status=403,
            )

        try:
            anonymized, stats = self._tokenizer.tokenize_payload(payload, session_id)
        except TokenizeError as exc:
            self._audit.record_block(session_id, "tokenizer_error", channel=str(channel or ""))
            raise RouterError("tokenizer_error", exc.message, status=403) from exc
        except MapStoreError as exc:
            self._audit.record_block(session_id, "store_unavailable", channel=str(channel or ""))
            raise RouterError("store_unavailable", exc.message, status=403) from exc

        if self._validator is not None:
            verdict = self._validator.validate_outgoing(anonymized, payload)
            if not verdict.clean:
                findings = sum(int(reason.count or 0) for reason in verdict.reasons)
                if os.environ.get("PII_PROXY_DEBUG_FINDINGS", "").strip().lower() in {"1", "true", "yes"}:
                    # Диагностика включена вручную: печатаем классы, счётчики и
                    # маскированные образцы (значений в логе нет). Журнал остаётся
                    # закрытым — разбор идёт в лог службы, а не в журнал.
                    logging.getLogger(LOGGER_NAME).warning(
                        "[ProxyService][residual_pii][BLOCK_RESIDUAL_PII] %s",
                        "; ".join(
                            f"{reason.cls}×{reason.count} {list(reason.samples)}"
                            for reason in verdict.reasons
                        ),
                    )
                # Phase-15, Вариант 1 (решение владельца 19.09.2026): остаток больше не
                # отказ. Второй проход тем же детектором и той же фабрикой кодов заменяет
                # найденные вхождения, запрос уходит провайдеру, а промах детектора
                # остаётся доказательством — в журнале инцидентов и в журнале аудита.
                outcome = self._repair_residual(anonymized, payload, stats)
                first_cls = outcome.codes[0][0] if outcome.codes else (
                    verdict.reasons[0].cls if verdict.reasons else "-"
                )
                if outcome.replaced:
                    # Судит результат тот же заслон, а не сама починка: если после замены
                    # что-то осталось, запрос блокируется, как и раньше.
                    verdict = self._validator.validate_outgoing(anonymized, payload)
                if outcome.replaced and verdict.clean:
                    self._audit.append(
                        AuditEvent(
                            session_id=session_id,
                            action="degraded_tokenized",
                            direction="inbound",
                            cls=first_cls,
                            count=outcome.replaced,
                            channel=str(channel or ""),
                            reason="",
                        )
                    )
                    self.record_incident(
                        action="degraded_tokenized",
                        cls=first_cls,
                        channel=str(channel or ""),
                        code=outcome.codes[0][1] if outcome.codes else "",
                        findings=findings,
                        replacements=outcome.replaced,
                        rule=outcome.rules[0] if outcome.rules else "",
                        codes=outcome.codes,
                    )
                else:
                    # Жёсткая блокировка: заменить остаток не удалось (сбой справочника,
                    # исчерпание кодов, вхождение не нашлось). Fail-closed не ослабляется
                    # ни на шаг — открытым остаток не уходит.
                    #
                    # Дефект 19.09.2026: ответ 403 клиент читал как «провайдер отклонил
                    # ключ» (Hermes показывает так любой 403) и искал проблему в ключе,
                    # хотя запрос остановил наш заслон. Теперь это 422 — «тело запроса
                    # не принято», и в чате видно настоящую причину. Fail-closed не
                    # меняется: запрос по-прежнему не уходит провайдеру.
                    reason = "replacement_failed" if outcome.attempted else "residual_pii"
                    self._audit.record_block(
                        session_id, reason, channel=str(channel or ""), cls=first_cls
                    )
                    self.record_incident(
                        action="blocked",
                        cls=first_cls,
                        channel=str(channel or ""),
                        findings=findings,
                        replacements=outcome.replaced,
                    )
                    raise RouterError(
                        "residual_pii",
                        "в исходящем запросе остались персональные данные — запрос не отправлен",
                        status=422,
                    )

        self._check_rarity(anonymized, session_id, channel)

        # Phase-11 (решение владельца 18.09.2026): два пути. Поток нужен мессенджерам,
        # непотоковый JSON остаётся для инструментов, скриптов и других моделей.
        streaming_requested = bool(payload.get("stream"))
        if streaming_requested and self._config.stream_mode == "json_only":
            # Обходной путь: обмен с провайдером идёт как раньше, а клиент получает
            # ответ одним кадром SSE, чтобы не сломать потокового клиента.
            anonymized.pop("stream", None)

        if self._config.dry_run:
            self._audit.append(
                AuditEvent(
                    session_id=session_id,
                    action="dry_run",
                    direction="inbound",
                    cls="-",
                    count=sum(
                        value for key, value in stats.items() if key in {"P", "T", "E", "D", "A", "I", "C"}
                    ),
                    channel=str(channel or ""),
                    reason="",
                )
            )
            dry_body = {
                "dry_run": True,
                "sanitized_payload": anonymized,
                "pii_proxy": {"session_id": session_id, "tokenized": stats, "upstream": "skipped"},
            }
            if streaming_requested:
                # Репетиция тоже умеет поток: один кадр с тем же телом и терминатор.
                return StreamResponse(status=200, chunks=sse_single_frame(dry_body))
            return 200, dry_body

        if streaming_requested and self._config.stream_mode == "auto":
            return StreamResponse(
                status=200,
                chunks=self._stream_chunks(
                    route, path, anonymized, payload, channel, session_id, images_present
                ),
            )

        try:
            status, body = self._upstream.forward_json(route, path, anonymized)
            self._record_provider_cache(body)
        except UpstreamError as exc:
            raise RouterError(exc.code.lower(), exc.message, status=exc.status) from exc

        try:
            # Mechanism 2 (Phase-4): restoration is limited to identifiers that were
            # actually present in this request — the incoming history plus the
            # identifiers issued while anonymizing it.
            allowed = collect_identifiers(
                json.dumps(payload, ensure_ascii=False),
                json.dumps(anonymized, ensure_ascii=False),
            )
            body, detok_stats = self._detokenizer.detokenize_response(
                body, channel, session_id, allowed
            )
        except DetokenizeError as exc:
            raise RouterError("store_unavailable", exc.message, status=403) from exc

        body.setdefault("pii_proxy", {})
        if images_present and self._config.image_policy == "allow":
            notified = self._append_image_reminder(body)
            self._audit.append(
                AuditEvent(
                    session_id=session_id,
                    action="image_notice",
                    direction="outbound",
                    cls="-",
                    count=notified,
                    channel=str(channel or ""),
                    reason="",
                )
            )
        if isinstance(body["pii_proxy"], dict):
            body["pii_proxy"].update(
                {
                    "session_id": session_id,
                    "tokenized": stats,
                    "detokenized": detok_stats,
                }
            )
        if streaming_requested and self._config.stream_mode == "json_only":
            # Клиент просил поток, но режим выбран непотоковый: отдаём тот же
            # восстановленный ответ одним кадром SSE — так клиент не сломается.
            return StreamResponse(status=int(status), chunks=sse_single_frame(body))
        return int(status), body

    def _stream_chunks(
        self,
        route: str,
        path: str,
        anonymized: dict,
        payload: dict,
        channel: str | None,
        session_id: str,
        images_present: bool,
    ) -> Iterator[bytes]:
        """Yield client frames for one streaming request.

        # START_CONTRACT: _stream_chunks
        #   PURPOSE: Run the streaming path end to end without materializing the answer.
        #   INPUTS: { route: str, path: str, anonymized: dict, payload: dict, channel: str | None, session_id: str, images_present: bool }
        #   OUTPUTS: { Iterator[bytes] - SSE frames for the client }
        #   SIDE_EFFECTS: outbound provider call, store reads, journal writes
        #   LINKS: M-STREAM-RELAY, M-UPSTREAM, M-DETOKENIZER, V-M-STREAM-RELAY
        # END_CONTRACT: _stream_chunks

        Fail-closed: к этому моменту заголовки ответа уже отданы, поэтому сбой
        внутри потока закрывается кадром ошибки и записью stream_error — статус
        ответа изменить нельзя, и частичный ответ наружу не выпускается.
        """
        try:
            allowed = collect_identifiers(
                json.dumps(payload, ensure_ascii=False),
                json.dumps(anonymized, ensure_ascii=False),
            )
        except Exception:  # pragma: no cover - defensive
            # Без набора идентификаторов восстановление невозможно: пустой список
            # безопаснее полного, потому что ничего чужого не покажет.
            allowed = frozenset()

        relay = StreamRelay(
            self._detokenizer,
            self._audit,
            channel,
            session_id,
            allowed,
            # Кэш провайдера считается и на потоковом пути: мессенджеры ходят именно им,
            # а попадание в кэш DeepSeek владелец назвал ключевым фактором приёмки.
            on_usage=self._record_provider_cache,
        )

        if images_present and self._config.image_policy == "allow":
            # Напоминание о политике изображений уходит первым кадром, как и в
            # непотоковом ответе, где оно дописывается к тексту.
            self._audit.append(
                AuditEvent(
                    session_id=session_id,
                    action="image_notice",
                    direction="outbound",
                    cls="-",
                    count=1,
                    channel=str(channel or ""),
                    reason="",
                )
            )
            yield b"data: " + json.dumps(
                {
                    "choices": [
                        {"index": 0, "delta": {"role": "assistant", "content": self.IMAGE_REMINDER}}
                    ]
                },
                ensure_ascii=False,
            ).encode("utf-8") + b"\n\n"

        try:
            chunks = self._upstream.forward_stream(route, path, anonymized)
        except UpstreamError as exc:
            self._audit.record_block(
                session_id, "stream_broken", channel=str(channel or ""), cls="-"
            )
            logging.getLogger(LOGGER_NAME).error(
                "[ProxyService][_stream_chunks][BLOCK_STREAM_CHUNKS] upstream failure: %s",
                exc.code,
            )
            yield b'data: {"error":{"code":"' + exc.code.lower().encode("utf-8")
            yield b'"}}\n\n'
            yield b"data: [DONE]\n\n"
            return

        yield from relay.relay(chunks)

    def health(self) -> dict:
        """Return component status without any PII.

        # START_CONTRACT: health
        #   PURPOSE: Give the operator a one-glance readiness view.
        #   INPUTS: none
        #   OUTPUTS: { dict - status, store counters, audit metrics, policy flags }
        #   SIDE_EFFECTS: reads store counters and metrics
        #   LINKS: V-M-ROUTER, fn-handle_healthz
        # END_CONTRACT: health
        """
        try:
            counters = self._store.counters()
        except MapStoreError as exc:
            return {"status": "degraded", "store_error": exc.code}
        return {
            "status": "ok",
            "bind": f"{self._config.host}:{self._config.port}",
            "routes": sorted(self._config.routes),
            "block_images": self._config.block_images,
            "image_policy": self._config.image_policy,
            "detok_channels": sorted(self._config.detok_channels),
            # Признак «любой канал» читается отдельно: значение настройки видно, а не
            # выводится из отсутствия списка каналов.
            "detok_all_channels": self._config.detok_all_channels,
            "ner_enabled": self._config.ner_enabled,
            "name_layer": (
                self._name_layer.snapshot()
                if self._name_layer is not None and hasattr(self._name_layer, "snapshot")
                else None
            ),
            "validator": self._validator is not None,
            "store": counters,
            "audit": self._audit.metrics_snapshot(),
            "cache": self._cache.stats() if self._cache is not None else {},
            "dictionary": (
                self._dictionary.snapshot()
                if self._dictionary is not None and hasattr(self._dictionary, "snapshot")
                else {}
            ),
            "ner": (
                self._ner.ner_status()
                if self._ner is not None and hasattr(self._ner, "ner_status")
                else {"available": False, "backend": "disabled"}
            ),
            "rarity": {"k": self._config.rarity_k, "enforce": self._config.rarity_enforce},
            # Своя лексика организации: видно, принята ли она из настроек. Показываются только
            # числа по разделам — сами значения оператора в healthz не попадают.
            "own_vocabulary": {
                "terms": len(self._config.own_vocabulary.terms),
                "addresses": len(self._config.own_vocabulary.addresses),
                "phones": len(self._config.own_vocabulary.phones),
                "service_objects": len(self._config.own_vocabulary.service_objects),
            },
            # Служебная лексика оператора: только числа — сами слова в healthz не попадают.
            "service_lexicon": {
                "categories": self._config.service_lexicon.category_count,
                "words": self._config.service_lexicon.word_count,
            },
            "provider_cache": self._provider_cache_snapshot(),
            # Phase-15: журнал инцидентов виден счётчиком незаписанных. Значений и путей
            # в healthz нет — только числа и признак того, что журнал подключён.
            "incident_journal": {
                "enabled": self._incidents is not None,
                "unwritten": int(getattr(self._incidents, "unwritten", 0)),
            },
            # Phase-17: два инварианта доверенной границы видны цифрами. Реестр — состояние
            # «код значит ровно одно значение»; связность — подтверждается ли сочетание ФИО
            # источником и сколько склеек заслон остановил.
            "registry": self._registry_report(),
            "coherence": self._coherence_snapshot(),
        }

    def _provider_cache_snapshot(self) -> dict[str, Any]:
        """Return the provider prompt-cache counters with a hit rate.

        # START_CONTRACT: _provider_cache_snapshot
        #   PURPOSE: One place to read the acceptance number for prompt caching.
        #   INPUTS: none
        #   OUTPUTS: { dict - requests, tokens, hit rate }
        #   SIDE_EFFECTS: none
        #   LINKS: M-ROUTER, acceptance
        # END_CONTRACT: _provider_cache_snapshot
        """
        snapshot = dict(self._provider_cache)
        total = snapshot.get("hit_tokens", 0) + snapshot.get("miss_tokens", 0)
        snapshot["hit_rate"] = round(snapshot.get("hit_tokens", 0) / total, 4) if total else None
        return snapshot

    def _registry_report(self) -> dict[str, Any]:
        """Отдать итог проверки реестра: числа и коды без значений.

        # START_CONTRACT: _registry_report
        #   PURPOSE: Показать состояние инварианта «код значит ровно одно значение».
        #   INPUTS: none
        #   OUTPUTS: { dict[str, Any] - отчёт проверки, снятый при сборке службы }
        #   SIDE_EFFECTS: none
        #   LINKS: M-MAP-STORE, V-M-ROUTER
        # END_CONTRACT: _registry_report
        """
        report = self._registry
        if report is None or not hasattr(report, "to_dict"):
            return {"checked": False}
        return {"checked": True, **report.to_dict()}

    def _coherence_snapshot(self) -> dict[str, Any]:
        """Отдать состояние заслона связности персоны: режим, индекс и счётчики.

        # START_CONTRACT: _coherence_snapshot
        #   PURPOSE: Показать, включён ли заслон и сколько значений он остановил.
        #   INPUTS: none
        #   OUTPUTS: { dict[str, Any] - режим, индекс и счётчики }
        #   SIDE_EFFECTS: none
        #   LINKS: M-NAME-COHERENCE, M-DETOKENIZER, V-M-ROUTER
        # END_CONTRACT: _coherence_snapshot
        """
        index = self._coherence
        counters = {}
        getter = getattr(self._detokenizer, "counters", None)
        if callable(getter):
            try:
                counters = dict(getter())
            except Exception:  # noqa: BLE001 - healthz не должен падать из-за счётчиков
                counters = {}
        return {
            "mode": str(getattr(self._detokenizer, "coherence_mode", MODE_OFF)),
            "index": index.snapshot() if index is not None and hasattr(index, "snapshot") else None,
            "counters": counters,
        }

    def close(self) -> None:
        """Release the store connection."""
        self._store.close()
# END_BLOCK_HANDLE_CHAT_COMPLETIONS


# START_BLOCK_HTTP_HANDLER
class ProxyRequestHandler(BaseHTTPRequestHandler):
    """Minimal JSON HTTP handler for the proxy.

    # START_CONTRACT: ProxyRequestHandler
    #   PURPOSE: Parse requests, dispatch to ProxyService, shape JSON responses.
    #   INPUTS: { service: ProxyService - bound service }
    #   OUTPUTS: { ProxyRequestHandler - handler class }
    #   SIDE_EFFECTS: writes HTTP responses
    #   LINKS: M-ROUTER, V-M-ROUTER
    # END_CONTRACT: ProxyRequestHandler
    """

    protocol_version = "HTTP/1.1"
    service: ProxyService

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        """Route stdlib access logs through the structured logger, never the body."""
        logging.getLogger(LOGGER_NAME).debug(
            "[HttpRouter][handler][BLOCK_HANDLE_REQUEST] %s", format % args
        )

    def _respond(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _respond_stream(self, response: StreamResponse) -> None:
        """Write a response frame by frame with chunked transfer encoding.

        # START_CONTRACT: _respond_stream
        #   PURPOSE: Deliver an SSE answer without buffering it.
        #   INPUTS: { response: StreamResponse - status and frame iterator }
        #   OUTPUTS: none
        #   SIDE_EFFECTS: writes HTTP chunks to the socket
        #   LINKS: M-ROUTER, M-STREAM-RELAY, V-M-STREAM-RELAY
        # END_CONTRACT: _respond_stream
        """
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        try:
            for chunk in response.chunks:
                if not chunk:
                    continue
                self.wfile.write(b"%x\r\n" % len(chunk) + chunk + b"\r\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            # Клиент закрыл соединение: остаток ответа отправлять некому.
            logging.getLogger(LOGGER_NAME).info(
                "[HttpRouter][_respond_stream][BLOCK_RESPOND_STREAM] client closed the stream"
            )
            return
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def do_GET(self) -> None:  # noqa: N802 - stdlib signature
        if self.path.split("?")[0] == HEALTH_PATH:
            self._respond(200, self.service.health())
            return
        self._respond(404, {"error": {"code": "unknown_route", "message": self.path}})

    def do_POST(self) -> None:  # noqa: N802 - stdlib signature
        match = ROUTE_PATTERN.match(self.path.split("?")[0])
        if not match:
            self._respond(404, {"error": {"code": "unknown_route", "message": self.path}})
            return
        route = match.group("route").lower()
        path = match.group("path")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._respond(400, {"error": {"code": "bad_content_length", "message": "invalid header"}})
            return
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError):
            self._respond(400, {"error": {"code": "bad_json", "message": "request body is not JSON"}})
            return
        channel = self.headers.get(CHANNEL_HEADER) or self.headers.get(CHANNEL_HEADER.lower())
        try:
            result = self.service.handle_chat_completions(payload, route, path, channel)
        except RouterError as exc:
            self._respond(exc.status, {"error": {"code": exc.code, "message": exc.message}})
            return
        except Exception as exc:  # pragma: no cover - defensive
            logging.getLogger(LOGGER_NAME).error(
                "[HttpRouter][handle_chat_completions][BLOCK_HANDLE_CHAT_COMPLETIONS] unexpected failure: %s",
                type(exc).__name__,
            )
            self._respond(502, {"error": {"code": "upstream_bad_gateway", "message": "proxy failure"}})
            return
        if isinstance(result, StreamResponse):
            # Phase-11: поток отдаётся кадрами, заголовки уходят до первого кадра.
            self._respond_stream(result)
            return
        status, body = result
        self._respond(status, body)


def _first_int(source: dict, keys: tuple[str, ...]) -> int | None:
    """Return the first present integer among several provider spellings.

    # START_CONTRACT: _first_int
    #   PURPOSE: Read prompt-cache counters without pinning one provider's naming.
    #   INPUTS: { source: dict - usage object, keys: tuple[str, ...] - candidate names }
    #   OUTPUTS: { int | None - value or None }
    #   SIDE_EFFECTS: none
    #   LINKS: M-ROUTER, acceptance
    # END_CONTRACT: _first_int
    """
    for key in keys:
        value = source.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            return int(value)
    return None


def make_handler(service: ProxyService) -> type[ProxyRequestHandler]:
    """Bind a service instance to a handler subclass.

    # START_CONTRACT: make_handler
    #   PURPOSE: Keep the stdlib server construction with an injected service.
    #   INPUTS: { service: ProxyService - service to bind }
    #   OUTPUTS: { type[ProxyRequestHandler] - handler class with service bound }
    #   SIDE_EFFECTS: none
    #   LINKS: fn-main, V-M-ROUTER
    # END_CONTRACT: make_handler
    """
    return type("BoundProxyRequestHandler", (ProxyRequestHandler,), {"service": service})
# END_BLOCK_HTTP_HANDLER


# START_BLOCK_BUILD_SERVICE
def _dictionary_cache_signature(
    config: ProxyConfig, dictionary: Any
) -> tuple[str, Callable[[], Any] | None]:
    """Собрать подпись справочника для ключа кэша блоков.

    # START_CONTRACT: _dictionary_cache_signature
    #   PURPOSE: Одна точка, где решается, что именно делает кэш блоков недействительным.
    #   INPUTS: { config: ProxyConfig, dictionary: Any }
    #   OUTPUTS: { tuple[str, Callable | None] - статическая часть подписи и источник живого состояния файла }
    #   SIDE_EFFECTS: читает настройки
    #   LINKS: M-CACHE, M-DICT, M-ROUTER
    # END_CONTRACT: _dictionary_cache_signature

    В подпись входят путь справочника и отпечаток ключа справочника (сам ключ в
    подписи не хранится), а живое состояние файла — время правки и размер — берётся
    у самого справочника при каждом обращении к кэшу. Версию схемы ключа добавляет
    сам кэш, поэтому забыть её на этой стороне нельзя.

    Источник — справочник, а не обёртка детектора имён: детектор держит над справочником
    адаптер `_KnownValues`, и подпись у него своя (`NameDetector.dictionary_signature()`,
    путь + состояние файла). Живое состояние берётся общим помощником `live_file_state`
    (M-DICT), чтобы кэш блоков и кэши токенизатора/заслона судили о смене файла одним кодом.
    """
    path = str(getattr(dictionary, "path", "") or "")
    key = getattr(config, "dictionary_key", b"") or b""
    fingerprint = hashlib.sha256(bytes(key)).hexdigest()[:16]
    source = (
        partial(live_file_state, dictionary)
        if callable(getattr(dictionary, "file_signature", None))
        else None
    )
    return f"{path}|{fingerprint}", source


def build_service(
    config: ProxyConfig,
    store: TokenMapStore | None = None,
    dictionary: Any | None = None,
    upstream: UpstreamClient | None = None,
    audit: AuditJournal | None = None,
    validator: Any | None = None,
    alert_sender: Callable[[str], None] | None = None,
    cache: Any | None = None,
    ner: Any | None = None,
    name_layer: Any | None = None,
    incident_journal: Any | None = None,
    tokenizer: Any | None = None,
) -> ProxyService:
    """Assemble a fully wired proxy service from a validated configuration.

    # START_CONTRACT: build_service
    #   PURPOSE: Single place where modules are joined, used by main and by tests.
    #   INPUTS: { config: ProxyConfig, store: TokenMapStore | None, dictionary: Any | None, upstream: UpstreamClient | None, audit: AuditJournal | None, validator: Any | None, alert_sender: Callable | None, tokenizer: Any | None - шов для проверки промаха детектора }
    #   OUTPUTS: { ProxyService - ready service }
    #   SIDE_EFFECTS: opens the store and the journal, may issue outbound calls later
    #   LINKS: M-CONFIG, M-TOKENIZER, M-DETOKENIZER, M-UPSTREAM, M-AUDIT, M-DICT, M-INCIDENT-JOURNAL
    # END_CONTRACT: build_service
    """
    # Своя лексика оператора устанавливается ДО сборки детекторов: детектор, правила и
    # выгрузка читают её вживую, и порядок здесь — часть контракта.
    apply_own_vocabulary(config.own_vocabulary)
    active_store = store or TokenMapStore(config.map_db_path, config.fernet_key, config.ttl_days)
    active_audit = audit or AuditJournal(config.audit_log_path, alert_sender=alert_sender)
    # Журнал инцидентов поднимается на том же журнале аудита: сбой записи инцидента должен
    # быть виден счётчиком незаписанных в недельном отчёте, а не молчанием.
    active_incidents = (
        incident_journal
        if incident_journal is not None
        else IncidentJournal(config.incident_log_path, audit=active_audit)
    )
    policy = ChannelPolicy(config.detok_channels)
    active_dictionary = (
        dictionary
        if dictionary is not None
        else PiiDictionary(config.dictionary_path, key=config.dictionary_key)
    )
    names = NameDetector(active_dictionary)
    active_layer = name_layer if name_layer is not None else load_name_layer(config.name_layer_path)
    if active_layer is not None:
        names.register_name_layer(active_layer)
    active_ner = ner if ner is not None else (
        NerDetector(config.ner_backend) if config.ner_enabled else None
    )
    # Два предела сразу (M-CACHE): по числу записей и по объёму в байтах. Объём —
    # единственная мера, которой живёт живой диалог (сотни сообщений на сотни
    # килобайт), поэтому бюджет берётся из PII_PROXY_BLOCK_CACHE_MB, а
    # PII_PROXY_BLOCK_CACHE=false выключает кэш целиком.
    # Подпись справочника — часть ключа: смена справочника (правка файла, замена
    # пути или ключа выгрузки) делает недействительным весь кэш сразу, а не только
    # по факту перезагрузки, которую кто-то должен был заметить.
    cache_signature, cache_signature_source = _dictionary_cache_signature(
        config, active_dictionary
    )
    active_cache = cache if cache is not None else TokenizationCache(
        config.cache_size if config.block_cache_enabled else 0,
        max_bytes=config.block_cache_limit_mb * BYTES_PER_MEGABYTE,
        signature=cache_signature,
        signature_source=cache_signature_source,
    )
    active_tokenizer = (
        tokenizer
        if tokenizer is not None
        else PayloadTokenizer(
            config.token_key,
            active_store,
            names,
            ner=active_ner,
            cache=active_cache,
            audit=active_audit,
        )
    )
    # Индекс со-встречаемости частей ФИО (Phase-17): без него заслон связности выключен,
    # и это видно в healthz; испорченный файл по заданному пути — отказ (CoherenceError).
    active_coherence = load_name_coherence(config.name_combos_path)
    detokenizer = PayloadDetokenizer(
        active_store,
        policy,
        active_audit,
        identity_of=getattr(names, "identity_for", None),
        coherence=active_coherence,
        coherence_key=config.dictionary_key if active_coherence is not None else None,
        coherence_mode=config.coherence_mode,
        incident=active_incidents,
    )
    # Проверка целостности реестра на старте (Phase-17, требование владельца): код обязан
    # значить ровно одно значение. Многозначность — не «редкий случай», а состояние, в
    # котором службе работать нельзя: восстановление по такому коду выдумало бы человека.
    registry_report = _require_registry_integrity(active_store, names, active_incidents)
    active_upstream = upstream or UpstreamClient(config)
    active_validator = validator if validator is not None else ResidualPiiValidator(names)
    return ProxyService(
        config=config,
        store=active_store,
        tokenizer=active_tokenizer,
        detokenizer=detokenizer,
        upstream=active_upstream,
        audit=active_audit,
        validator=active_validator,
        cache=active_cache,
        dictionary=active_dictionary,
        ner=active_ner,
        name_layer=active_layer,
        incident_journal=active_incidents,
        coherence=active_coherence,
        registry_report=registry_report,
    )


def _require_registry_integrity(
    store: TokenMapStore,
    names: Any,
    incidents: Any,
) -> Any:
    """Проверить реестр на старте и отказать службе при многозначном коде.

    # START_CONTRACT: _require_registry_integrity
    #   PURPOSE: Превратить инвариант реестра в отказ службы, а не в строчку в отчёте.
    #   INPUTS: { store: TokenMapStore, names: Any - распознавание (резолвер персоны), incidents: Any - журнал инцидентов }
    #   OUTPUTS: { IntegrityReport - отчёт при чистом реестре }
    #   SIDE_EFFECTS: читает справочник, пишет инцидент при отказе
    #   LINKS: M-MAP-STORE, M-INCIDENT-JOURNAL, V-M-ROUTER
    # END_CONTRACT: _require_registry_integrity

    Значений в инциденте нет — только класс, действие, число кодов и один код-псевдоним:
    разбор идёт по справочнику, а не по журналу.
    """
    identity_of = getattr(names, "identity_for", None)
    try:
        return store.require_integrity(identity_of)
    except MapStoreError as exc:
        report = None
        try:
            report = store.scan_integrity(identity_of)
        except MapStoreError:
            report = None
        ambiguous = len(getattr(report, "ambiguous_codes", ()) or ())
        code = ""
        codes = getattr(report, "ambiguous_codes", ()) or ()
        if codes:
            code = str(codes[0])
        if incidents is not None:
            try:
                incidents.record(
                    IncidentEvent(
                        cls="P",
                        action="ambiguous_code",
                        channel="startup",
                        code=code,
                        findings=ambiguous or 1,
                    )
                )
            except Exception:  # noqa: BLE001 - отказ важнее сбоя журнала
                pass
        logging.getLogger(LOGGER_NAME).error(
            "[HttpRouter][build_service][BLOCK_BUILD_SERVICE] %s ambiguous=%s",
            exc.code,
            ambiguous,
        )
        raise


def _make_telegram_sender(config: ProxyConfig) -> Callable[[str], None] | None:
    """Build a Telegram alert sender (Bot API, standard library) when a chat is configured.

    # START_CONTRACT: _make_telegram_sender
    #   PURPOSE: Присылать отказы службы владельцу в Telegram, когда чат задан, — без сторонних библиотек.
    #   INPUTS: { config: ProxyConfig - alert_telegram_token, alert_telegram_chat, alert_telegram_thread }
    #   OUTPUTS: { Callable[[str], None] | None - отправитель или None, когда канал не настроен }
    #   SIDE_EFFECTS: HTTP-запрос при вызове отправителя; сбой доставки только пишется в журнал
    #   LINKS: M-CONFIG, M-AUDIT, M-ROUTER, V-M-ROUTER
    # END_CONTRACT: _make_telegram_sender

    Сообщение уходит в чат и, если задан, в тему (`message_thread_id`) — так отказы попадают
    туда, где владелец их читает, а не в общий поток. Недоставка не ломает конвейер: отказ
    фиксируется журналом и без алерта.
    """
    token = (config.alert_telegram_token or "").strip()
    chat = (config.alert_telegram_chat or "").strip()
    if not (token and chat):
        return None
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    thread = (config.alert_telegram_thread or "").strip()

    def sender(message: str) -> None:
        body: dict[str, Any] = {"chat_id": chat, "text": message}
        if thread:
            body["message_thread_id"] = int(thread) if thread.isdigit() else thread
        request = urllib.request.Request(
            url,
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10):
                pass
        except Exception as exc:  # pragma: no cover - alerting must never break the pipeline
            logging.getLogger(LOGGER_NAME).warning(
                "[HttpRouter][alert][BLOCK_HANDLE_CHAT_COMPLETIONS] telegram alert delivery failed: %s",
                type(exc).__name__,
            )

    return sender


def _make_alert_sender(config: ProxyConfig) -> Callable[[str], None] | None:
    """Build an alert sender: Telegram when its chat is configured, otherwise Mattermost."""
    telegram = _make_telegram_sender(config)
    if telegram is not None:
        return telegram
    if not (config.alert_url and config.alert_token and config.alert_channel):
        return None
    url = config.alert_url.rstrip("/") + "/api/v4/posts"
    token = config.alert_token
    channel = config.alert_channel

    def sender(message: str) -> None:
        body = json.dumps({"channel_id": channel, "message": message}, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10):
                pass
        except Exception as exc:  # pragma: no cover - alerting must never break the pipeline
            logging.getLogger(LOGGER_NAME).warning(
                "[HttpRouter][alert][BLOCK_HANDLE_CHAT_COMPLETIONS] alert delivery failed: %s",
                type(exc).__name__,
            )

    return sender


def purge_loop(service: ProxyService, interval_seconds: int = 86400) -> threading.Thread:
    """Start a background thread purging expired bindings.

    # START_CONTRACT: purge_loop
    #   PURPOSE: Honour the TTL without a separate cron dependency.
    #   INPUTS: { service: ProxyService, interval_seconds: int }
    #   OUTPUTS: { threading.Thread - started daemon thread }
    #   SIDE_EFFECTS: deletes expired bindings on schedule
    #   LINKS: M-MAP-STORE, V-M-MAP-STORE
    # END_CONTRACT: purge_loop
    """

    def worker() -> None:  # pragma: no cover - timing dependent
        while True:
            try:
                service._store.purge_expired()  # noqa: SLF001 - internal maintenance loop
            except MapStoreError:
                logging.getLogger(LOGGER_NAME).warning(
                    "[HttpRouter][purge][BLOCK_HANDLE_CHAT_COMPLETIONS] purge failed"
                )
            threading.Event().wait(interval_seconds)

    thread = threading.Thread(target=worker, name="pii-proxy-purge", daemon=True)
    thread.start()
    return thread


def main(argv: list[str] | None = None) -> int:
    """Process entry point for the systemd unit.

    # START_CONTRACT: main
    #   PURPOSE: Load config, assemble the service and serve forever.
    #   INPUTS: { argv: list[str] | None - unused, kept for testability }
    #   OUTPUTS: { int - exit code }
    #   SIDE_EFFECTS: binds a socket and serves requests
    #   LINKS: M-CONFIG, M-ROUTER, V-M-ROUTER
    # END_CONTRACT: main
    """
    # Необязательный файл настроек: путь приходит переменной окружения, и без него работают
    # умолчания и переменные — публичная сборка запускается до заполнения примера.
    config = load_config(config_path=os.environ.get("PII_PROXY_CONFIG") or None)
    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    service = build_service(config, alert_sender=_make_alert_sender(config))
    if config.cache_size:
        purge_loop(service)
    handler = make_handler(service)
    server = ThreadingHTTPServer((config.host, config.port), handler)
    logging.getLogger(LOGGER_NAME).info(
        "[HttpRouter][main][BLOCK_HANDLE_CHAT_COMPLETIONS] listening on %s:%s routes=%s channels=%s",
        config.host,
        config.port,
        sorted(config.routes),
        "all" if config.detok_all_channels else sorted(config.detok_channels),
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - operator action
        pass
    finally:
        server.server_close()
        service.close()
    return 0


if __name__ == "__main__":  # pragma: no cover - module entry
    raise SystemExit(main())
# END_BLOCK_BUILD_SERVICE
