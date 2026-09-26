# FILE: src/config.py
# VERSION: 1.3.0
# START_MODULE_CONTRACT
#   PURPOSE: Load, validate and freeze proxy configuration (routes, provider keys, token and mapping keys, policy flags, operator's own lexicon, operator's service lexicon, detokenization channels) and refuse to start on unsafe input.
#   SCOPE: environment parsing, optional JSON config file overlay, key material loading with permission checks, loopback bind enforcement, policy defaults, detokenization channel list with the all-channels default, own-vocabulary (brand, branches, tariffs, addresses, switchboard numbers) intake, service-lexicon (tariffs, clubs, services) intake.
#   DEPENDS: none
#   LINKS: M-CONFIG, V-M-CONFIG, fn-load_config, type-ProxyConfig, class-ConfigError
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   DEFAULT_ROUTES - upstream route table for the ds and nord prefixes
#   ALL_CHANNEL_WORDS - слова настройки, означающие «восстанавливать в любом канале»
#   ConfigError - configuration failure carrying a stable code
#   ProxyConfig - immutable validated configuration
#   load_config - read environment and optional file, validate, return ProxyConfig
#   _read_overlay - необязательный файл настроек: JSON всегда, YAML при установленном PyYAML
#   read_overlay - открытая обёртка над _read_overlay для приборов
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.3.0 - решения владельца 25.09.2026: каналы восстановления стали настройкой с умолчанием «любой канал» (пустое значение или «*»), а служебная лексика оператора (тарифы, клубы, услуги) приходит из нового раздела service_lexicon. Запрет на каналы вне контура остался отказом на старте.
#   PREVIOUS: v1.2.0 - своя лексика оператора и необязательный файл настроек: PII_PROXY_OWN_* и PII_PROXY_CONFIG, разбор JSON и YAML с явной ошибкой при отсутствии разборщика.
#   PREVIOUS: v1.0.1 - Phase-15 шаг 1: PII_PROXY_INCIDENT_LOG задаёт каталог журнала инцидентов (по умолчанию рядом с журналом аудита).
#   PREVIOUS: v1.0.0 - Phase-1 M-CONFIG: first implementation of the configuration contract.
# END_CHANGE_SUMMARY

"""Configuration for the PII anonymization proxy.

Implements the M-CONFIG contract from docs/ARCHITECTURE.md. Fail-closed
policy starts here: an unsafe configuration (missing provider key, non-loopback
bind address, key file readable by group or others, non-HTTPS route, a
detokenization channel outside the perimeter) aborts startup instead of
degrading into a silently open proxy.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from typing import Mapping

from src.channel_policy import BLOCKED_CHANNELS, CHANNEL_ALL
from src.own_vocabulary import OwnVocabulary, from_env as own_from_env, from_mapping as own_from_mapping, merge as merge_own
from src.service_lexicon import (
    ServiceLexicon,
    from_env as service_from_env,
    from_mapping as service_from_mapping,
    merge as merge_service,
)

LOGGER_NAME = "ProxyConfig"
LOG_MARKER = "[ProxyConfig][load_config][BLOCK_VALIDATE_CONFIG]"

DEFAULT_ROUTES = {
    "ds": "https://api.deepseek.com",
    "nord": "https://nordrouter.com",
}

LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")

#: Слова настройки, означающие «восстанавливать в любом канале». Пустое значение обрабатывается
#: отдельно и означает то же самое — это умолчание публичной сборки (решение владельца 25.09.2026).
ALL_CHANNEL_WORDS = frozenset({"*", "all", "any", "все", "любой"})

REQUIRED_PROVIDER_KEYS = {
    "ds": "DEEPSEEK_API_KEY",
    "nord": "NORDROUTER_API_KEY",
}


class ConfigError(RuntimeError):
    """Configuration failure with a stable code.

    # START_CONTRACT: ConfigError
    #   PURPOSE: Carry a machine-checkable failure code for configuration problems.
    #   INPUTS: { code: str - stable code, message: str - human readable detail }
    #   OUTPUTS: { ConfigError - exception instance }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CONFIG, V-M-CONFIG
    # END_CONTRACT: ConfigError
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ProxyConfig:
    """Validated immutable proxy configuration.

    # START_CONTRACT: ProxyConfig
    #   PURPOSE: Hold every value the proxy needs, already validated.
    #   INPUTS: { routes: Mapping[str, str], provider_keys: Mapping[str, str], token_key: bytes, fernet_key: bytes, ... }
    #   OUTPUTS: { ProxyConfig - frozen value object }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CONFIG, M-TOKEN-GEN, M-MAP-STORE
    # END_CONTRACT: ProxyConfig
    """

    routes: Mapping[str, str]
    provider_keys: Mapping[str, str]
    token_key: bytes
    fernet_key: bytes
    dictionary_key: bytes
    map_db_path: str
    dictionary_path: str
    ttl_days: int
    detok_channels: frozenset[str]
    block_images: bool
    image_policy: str
    name_layer_path: str
    stream_mode: str
    host: str
    port: int
    audit_log_path: str
    cache_size: int
    # Второй предел того же кэша — по объёму (МБ), рядом с пределом по числу записей:
    # живой диалог меряется байтами, а записи ничего о памяти не говорят.
    block_cache_enabled: bool = True
    block_cache_limit_mb: int = 64
    incident_log_path: str = ""
    alert_url: str | None = None
    alert_token: str | None = None
    alert_channel: str | None = None
    alert_telegram_token: str | None = None
    alert_telegram_chat: str | None = None
    alert_telegram_thread: str | None = None
    ner_enabled: bool = False
    ner_backend: str = "auto"
    dry_run: bool = False
    rarity_k: int = 5
    rarity_enforce: bool = False
    request_timeout: int = 120
    log_level: str = "INFO"
    extra: Mapping[str, str] = field(default_factory=dict)
    # Phase-17: индекс со-встречаемости частей ФИО и режим проверки связности персоны.
    # Поля с умолчаниями — в конце: dataclass не разрешает значение по умолчанию раньше
    # обязательного поля.
    name_combos_path: str = ""
    coherence_mode: str = "off"
    # Своя лексика оператора (бренд, филиалы, тарифы, город, свои адреса и номера связи).
    # В коде её нет: пустое значение — безопасное умолчание публичной сборки.
    own_vocabulary: OwnVocabulary = field(default_factory=OwnVocabulary)
    # Служебная лексика оператора (тарифы, клубы, услуги, которые система учёта оставляет в поле
    # ФИО). В коде её нет: пустое умолчание — другой клуб заполняет свои слова в примере настроек.
    service_lexicon: ServiceLexicon = field(default_factory=ServiceLexicon)

    @property
    def detok_all_channels(self) -> bool:
        """Сказать, что восстановление разрешено в любом канале (умолчание публичной сборки).

        Отдельный признак, а не «пустое множество»: значение настройки должно читаться
        в healthz и в документации, а не выводиться из отсутствия списка.
        """
        return CHANNEL_ALL in self.detok_channels


# START_BLOCK_READ_KEY_FILE
def _read_key_file(path: str, *, min_bytes: int = 16) -> bytes:
    """Read secret key material, rejecting files readable by group or others.

    # START_CONTRACT: _read_key_file
    #   PURPOSE: Load key bytes while enforcing 0600-style permissions.
    #   INPUTS: { path: str - key file path, min_bytes: int - minimal acceptable key length }
    #   OUTPUTS: { bytes - key material without trailing newline }
    #   SIDE_EFFECTS: reads the filesystem
    #   LINKS: V-M-CONFIG
    # END_CONTRACT: _read_key_file
    """
    if not path:
        raise ConfigError("CONFIG_MISSING_KEY", "key file path is empty")
    if not os.path.isfile(path):
        raise ConfigError("CONFIG_KEY_FILE_MISSING", f"key file not found: {path}")
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        raise ConfigError(
            "CONFIG_KEY_FILE_PERMISSIONS",
            f"key file {path} must not be readable by group or others (mode {oct(mode)})",
        )
    with open(path, "rb") as handle:
        material = handle.read().strip()
    if len(material) < min_bytes:
        raise ConfigError(
            "CONFIG_KEY_TOO_SHORT",
            f"key file {path} holds {len(material)} bytes, at least {min_bytes} required",
        )
    return material
# END_BLOCK_READ_KEY_FILE


# START_BLOCK_VALIDATE_CONFIG
def _validate_routes(routes: Mapping[str, str]) -> dict[str, str]:
    """Validate route table: every upstream must be HTTPS and non-empty."""
    if not routes:
        raise ConfigError("CONFIG_INVALID_ROUTE", "no upstream routes configured")
    validated: dict[str, str] = {}
    for prefix, url in routes.items():
        if not prefix or "/" in prefix:
            raise ConfigError("CONFIG_INVALID_ROUTE", f"bad route prefix: {prefix!r}")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise ConfigError(
                "CONFIG_INVALID_ROUTE",
                f"route {prefix!r} must be an https URL, got {url!r}",
            )
        validated[prefix] = url.rstrip("/")
    return validated


def _validate_bind(host: str, port: int) -> tuple[str, int]:
    """Validate bind address: loopback only, port inside the privileged range."""
    if host not in LOOPBACK_HOSTS:
        raise ConfigError(
            "CONFIG_NON_LOCAL_BIND",
            f"proxy must bind to loopback, got {host!r}",
        )
    if not (1024 <= port <= 65535):
        raise ConfigError("CONFIG_INVALID_PORT", f"port {port} out of range")
    return host, port


def _parse_bool(raw: object, default: bool) -> bool:
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return default
    # Environment files are written by humans: systemd does not support inline
    # comments after a value, so a trailing remark would otherwise arrive as part
    # of the value and silently turn "true" into "not true" (hit while verifying
    # the deployment on 15.09.2026).
    text = str(raw).split("#", 1)[0].strip().lower()
    text = text.split()[0] if text.split() else ""
    if not text:
        return default
    return text in {"1", "true", "yes", "on"}


def _parse_channels(raw: object) -> frozenset[str]:
    """Прочитать список каналов, где восстанавливаются значения.

    # START_CONTRACT: _parse_channels
    #   PURPOSE: Дать владельцу умолчание «любой канал» и возможность сузить список до своих каналов.
    #   INPUTS: { raw: object - None, строка с разделителями или перечень из файла настроек }
    #   OUTPUTS: { frozenset[str] - каналы; признак CHANNEL_ALL означает «любой канал» }
    #   SIDE_EFFECTS: none
    #   LINKS: M-CONFIG, M-CHANNEL-POLICY, V-M-CONFIG
    # END_CONTRACT: _parse_channels

    Пустое значение и явный признак (``*``, ``all``, ``все``) означают одно и то же —
    восстановление в любом канале; это умолчание публичной сборки. Признак не «съедает»
    перечисленные рядом каналы: ``*,telegram`` остаётся видимым и отвергается проверкой
    каналов вне контура, а не проходит незамеченным.
    """
    if raw is None:
        return frozenset({CHANNEL_ALL})
    if isinstance(raw, (list, tuple, set, frozenset)):
        parts = [str(item).strip().lower() for item in raw]
    else:
        parts = [part.strip().lower() for part in str(raw).split(",")]
    parts = [part for part in parts if part]
    if not parts:
        return frozenset({CHANNEL_ALL})
    explicit = [part for part in parts if part not in ALL_CHANNEL_WORDS]
    if len(explicit) != len(parts):
        return frozenset({CHANNEL_ALL, *explicit})
    return frozenset(explicit)


# START_BLOCK_READ_OVERLAY
def _read_overlay(config_path: str | None) -> dict:
    """Read the optional configuration overlay from a JSON or YAML file.

    # START_CONTRACT: _read_overlay
    #   PURPOSE: Дать оператору пример настроек с комментариями, не добавляя обязательную зависимость.
    #   INPUTS: { config_path: str | None - путь к файлу настроек }
    #   OUTPUTS: { dict - разобранный файл или пустой словарь, если путь не задан }
    #   SIDE_EFFECTS: читает файл
    #   LINKS: M-CONFIG, V-M-CONFIG
    # END_CONTRACT: _read_overlay

    Формат выбирается по расширению и наличию разборщика: JSON разбирается всегда (stdlib), YAML —
    когда установлен PyYAML. Отсутствие YAML-разборщика называется прямо, а не приводит к запуску
    службы с пустыми настройками: молчаливая подмена конфигурации здесь опаснее отказа.
    """
    if not config_path:
        return {}
    if not os.path.isfile(config_path):
        raise ConfigError("CONFIG_MISSING_KEY", f"config file not found: {config_path}")
    with open(config_path, "r", encoding="utf-8") as handle:
        text = handle.read()
    if config_path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ConfigError(
                "CONFIG_YAML_UNAVAILABLE",
                "config file is YAML but PyYAML is not installed; "
                "install it or keep the overlay in JSON",
            ) from exc
        loaded = yaml.safe_load(text)
    else:
        loaded = json.loads(text)
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ConfigError("CONFIG_INVALID_OVERLAY", "config file must hold a mapping at the top level")
    return loaded
# END_BLOCK_READ_OVERLAY


def read_overlay(config_path: str | None) -> dict:
    """Открытая обёртка над чтением файла настроек — для приборов, а не только для службы.

    # START_CONTRACT: read_overlay
    #   PURPOSE: Дать приборам (измеритель шума справочника) читать те же настройки, что и служба, одним кодом.
    #   INPUTS: { config_path: str | None - путь к файлу настроек }
    #   OUTPUTS: { dict - разобранный файл или пустой словарь }
    #   SIDE_EFFECTS: читает файл
    #   LINKS: M-CONFIG, M-DICT-HYGIENE
    # END_CONTRACT: read_overlay
    """
    return _read_overlay(config_path)


def load_config(
    env: Mapping[str, str] | None = None,
    config_path: str | None = None,
) -> ProxyConfig:
    """Read environment (plus an optional JSON overlay) and validate it.

    # START_CONTRACT: load_config
    #   PURPOSE: Produce a validated ProxyConfig or raise ConfigError.
    #   INPUTS: { env: Mapping[str, str] | None - defaults to os.environ, config_path: str | None - optional JSON overlay }
    #   OUTPUTS: { ProxyConfig - frozen validated configuration }
    #   SIDE_EFFECTS: reads environment and filesystem, no logging of secret values
    #   LINKS: V-M-CONFIG, M-TOKEN-GEN, M-MAP-STORE
    # END_CONTRACT: load_config
    """
    source = dict(os.environ if env is None else env)
    overlay: dict = _read_overlay(config_path)

    route_map: dict[str, str] = dict(overlay.get("routes") or DEFAULT_ROUTES)
    routes = _validate_routes({str(k): str(v) for k, v in route_map.items()})

    # The rehearsal switch is read before the provider keys, because in dry-run
    # mode no provider is ever called, so requiring credentials would make an
    # installed-but-not-yet-switched instance crash-loop (found while verifying
    # the deployment on 15.09.2026).
    dry_run = _parse_bool(overlay.get("dry_run", source.get("PII_PROXY_DRY_RUN")) or "", False)

    provider_keys: dict[str, str] = {}
    for prefix in routes:
        env_name = REQUIRED_PROVIDER_KEYS.get(prefix, f"{prefix.upper()}_API_KEY")
        value = source.get(env_name) or os.environ.get(env_name)
        if not value:
            if dry_run:
                provider_keys[prefix] = ""
                continue
            raise ConfigError("CONFIG_MISSING_KEY", f"provider key {env_name} is not set")
        provider_keys[prefix] = value

    token_key_path = str(
        overlay.get("token_key_file")
        or source.get("PII_PROXY_TOKEN_KEY_FILE")
        or ""
    )
    dictionary_key_path = str(source.get("PII_PROXY_DICT_KEY_FILE") or "")
    fernet_key_path = str(
        overlay.get("fernet_key_file")
        or source.get("PII_PROXY_FERNET_KEY_FILE")
        or ""
    )
    token_key = _read_key_file(token_key_path, min_bytes=32)
    fernet_key = _read_key_file(fernet_key_path, min_bytes=32)

    # The dictionary is digested with its own secret. Sharing the token key would
    # turn the dictionary file into a linkage tool: anyone holding it could compute
    # the token of a known client and find that token in a request, without ever
    # touching the correspondence table. Falling back to the token key keeps old
    # installations working, but the fallback is reported as a warning.
    warnings: list[str] = []
    if dictionary_key_path:
        dictionary_key = _read_key_file(dictionary_key_path, min_bytes=32)
    else:
        dictionary_key = token_key
        warnings.append("dictionary_key_fallback_to_token_key")

    host, port = _validate_bind(
        str(overlay.get("host") or source.get("PII_PROXY_HOST") or "127.0.0.1"),
        int(str(overlay.get("port") or source.get("PII_PROXY_PORT") or 8791)),
    )

    ttl_days = int(str(overlay.get("ttl_days") or source.get("PII_PROXY_TTL_DAYS") or 90))
    if ttl_days <= 0:
        raise ConfigError("CONFIG_INVALID_TTL", f"ttl_days must be positive, got {ttl_days}")

    cache_size = int(
        str(overlay.get("cache_size") or source.get("PII_PROXY_CACHE_SIZE") or 512)
    )
    if cache_size < 0:
        raise ConfigError("CONFIG_INVALID_CACHE", "cache_size must not be negative")

    # Кэш блоков: полный выключатель и бюджет по объёму. Предел по числу записей остаётся
    # (cache_size), но объём берётся из отдельной настройки — это то, что ограничивает память.
    block_cache_enabled = _parse_bool(
        overlay.get("block_cache_enabled", source.get("PII_PROXY_BLOCK_CACHE")),
        default=True,
    )
    block_cache_limit_mb = int(
        str(overlay.get("block_cache_limit_mb") or source.get("PII_PROXY_BLOCK_CACHE_MB") or 64)
    )
    if block_cache_limit_mb < 1:
        raise ConfigError("CONFIG_INVALID_CACHE", "block cache size must be positive")

    detok_channels = _parse_channels(
        overlay["detok_channels"] if "detok_channels" in overlay
        else source.get("PII_PROXY_DETOK_CHANNELS")
    )
    # Каналы вне контура не становятся доверенными ни при каком умолчании: это отказ на старте,
    # а не молчаливое сужение списка. Пустое умолчание — «любой канал» (решение владельца 25.09.2026).
    outside = detok_channels & BLOCKED_CHANNELS
    if outside:
        raise ConfigError(
            "CONFIG_CHANNEL_POLICY_VIOLATION",
            "channels outside the perimeter must never be detokenization channels: "
            f"{sorted(outside)} (owner decision 15.09.2026)",
        )

    block_images = _parse_bool(
        overlay.get("block_images", source.get("PII_PROXY_BLOCK_IMAGES")) or "", True
    )
    # Image policy (16.09.2026, owner decision). Blocking was wrong twice over: a
    # single screenshot in a session's history made every later request fail, and a
    # vision route could never work. Images are now forwarded and the answer carries
    # a reminder that images with personal data violate the policy.
    #   allow - forward images, append the reminder to the answer (default)
    #   block - refuse the request with 403 (strict mode, off by default)
    image_policy = str(
        overlay.get("image_policy", source.get("PII_PROXY_IMAGE_POLICY")) or ""
    ).strip().lower()
    if not image_policy:
        # Legacy switch only: an explicitly set PII_PROXY_BLOCK_IMAGES=true still
        # means strict mode, but the old *default* (true) is deliberately NOT
        # carried forward — that default blocked every request from a session that
        # had ever touched an image.
        legacy = overlay.get("block_images", source.get("PII_PROXY_BLOCK_IMAGES"))
        strict = legacy is not None and _parse_bool(str(legacy), False)
        image_policy = "block" if strict else "allow"
    if image_policy not in {"allow", "block"}:
        raise ConfigError(
            "CONFIG_INVALID_IMAGE_POLICY",
            f"image policy must be allow or block, got {image_policy!r}",
        )
    block_images = image_policy == "block"
    # Потоковый режим (Phase-11, решение владельца 18.09.2026). Гермес шлёт stream=true,
    # и непотоковый прокси отвечал 502; но не все клиенты и модели работают потоком,
    # поэтому JSON-путь сохраняется.
    #   auto      - идти тем путём, который запросил клиент (по умолчанию)
    #   json_only - всегда непотоковый обмен; поток отдаётся одним кадром с [DONE]
    stream_mode = str(
        overlay.get("stream_mode", source.get("PII_PROXY_STREAM_MODE")) or "auto"
    ).strip().lower()
    if stream_mode not in {"auto", "json_only"}:
        raise ConfigError(
            "CONFIG_INVALID_STREAM_MODE",
            f"stream mode must be auto or json_only, got {stream_mode!r}",
        )
    # Открытый слой распознавания (Phase-10): фамилии, имена и отчества из открытых
    # списков. Пустое значение выключает слой — прокси работает как раньше.
    name_layer_path = str(
        overlay.get("name_layer", source.get("PII_PROXY_NAME_LAYER")) or ""
    ).strip()
    # Индекс со-встречаемости частей ФИО (Phase-17): подтверждает, что пара или тройка
    # (фамилия, имя, отчество) встречались вместе в карточке клиента. Нужен доверенной
    # границе, чтобы модель не склеила имя одного человека с фамилией другого.
    name_combos_path = str(
        overlay.get("name_combos", source.get("PII_PROXY_NAME_COMBOS")) or ""
    ).strip()
    # Режим проверки связности: off (выключена), audit (считать и писать инцидент),
    # enforce (не восстанавливать). Если индекс настроен, по умолчанию enforce: выдуманная
    # персона хуже пустого места. Без индекса режим остаётся off — выключенная возможность
    # видна в healthz, а не подразумевается.
    coherence_mode = str(
        overlay.get("coherence_mode", source.get("PII_PROXY_COHERENCE_MODE")) or ""
    ).strip().lower()
    if not coherence_mode:
        coherence_mode = "enforce" if name_combos_path else "off"
    if coherence_mode not in {"off", "audit", "enforce"}:
        raise ConfigError(
            "CONFIG_INVALID_COHERENCE_MODE",
            f"coherence mode must be off, audit or enforce, got {coherence_mode!r}",
        )
    if coherence_mode != "off" and not name_combos_path:
        raise ConfigError(
            "CONFIG_COHERENCE_WITHOUT_INDEX",
            f"coherence mode {coherence_mode!r} requires the combos index path",
        )
    ner_enabled = _parse_bool(
        overlay.get("ner_enabled", source.get("PII_PROXY_NER_ENABLED")) or "", False
    )
    dry_run = _parse_bool(overlay.get("dry_run", source.get("PII_PROXY_DRY_RUN")) or "", False)
    ner_backend = str(
        overlay.get("ner_backend", source.get("PII_PROXY_NER_BACKEND")) or "auto"
    ).strip()
    rarity_k = int(str(source.get("PII_PROXY_RARITY_K") or 5))
    rarity_enforce = _parse_bool(
        overlay.get("rarity_enforce", source.get("PII_PROXY_RARITY_ENFORCE")) or "", False
    )
    # Своя лексика оператора: бренд, филиалы, тарифы, город, свои адреса и телефоны ресепции,
    # названия своей системы учёта. Лежит в настройках, а не в коде: другой клуб заполняет
    # свои значения, ничего не правя в исходниках. Ни переменные, ни файл не обязательны —
    # пустая лексика безопасна (просто нечего отбрасывать сверх общей части).
    own_vocabulary = own_from_env(source)
    if "own_vocabulary" in overlay and isinstance(overlay["own_vocabulary"], Mapping):
        own_vocabulary = merge_own(own_vocabulary, own_from_mapping(overlay["own_vocabulary"]))
    # Служебная лексика оператора: тарифы, названия клубов и услуги, которые система учёта
    # оставляет в поле ФИО. По ней измеритель (M-DICT-HYGIENE) считает шум справочника и,
    # если нужно, снимает его. В коде её нет — другой оператор заполняет свои слова.
    service_lexicon = service_from_env(source)
    if "service_lexicon" in overlay:
        service_lexicon = merge_service(
            service_lexicon, service_from_mapping(overlay["service_lexicon"])
        )

    audit_log_path = str(
        overlay.get("audit_log_path")
        or source.get("PII_PROXY_AUDIT_LOG")
        or "/var/log/pii-proxy/audit.jsonl"
    )
    # Phase-15: журнал инцидентов лежит рядом с журналом аудита (ротация по неделям,
    # файлы incidents-YYYY-WW.jsonl внутри каталога). Каталог задаётся отдельно, чтобы
    # боевой контур мог держать инциденты на другом разделе, но по умолчанию —
    # соседний каталог: тогда оба журнала попадают в одну резервную копию.
    incident_log_path = str(
        overlay.get("incident_log_path")
        or source.get("PII_PROXY_INCIDENT_LOG")
        or os.path.join(os.path.dirname(audit_log_path) or ".", "incidents")
    )

    return ProxyConfig(
        routes=routes,
        provider_keys=provider_keys,
        token_key=token_key,
        fernet_key=fernet_key,
        dictionary_key=dictionary_key,
        extra={"warnings": ",".join(warnings)} if warnings else {},
        map_db_path=str(
            overlay.get("map_db_path")
            or source.get("PII_PROXY_MAP_DB")
            or "/var/lib/pii-proxy/pii_map.db"
        ),
        dictionary_path=str(
            overlay.get("dictionary_path")
            or source.get("PII_PROXY_DICT")
            or "/var/lib/pii-proxy/pii_dict.json"
        ),
        ttl_days=ttl_days,
        detok_channels=detok_channels,
        block_images=block_images,
        image_policy=image_policy,
        own_vocabulary=own_vocabulary,
        service_lexicon=service_lexicon,
        name_layer_path=name_layer_path,
        name_combos_path=name_combos_path,
        coherence_mode=coherence_mode,
        stream_mode=stream_mode,
        host=host,
        port=port,
        audit_log_path=audit_log_path,
        incident_log_path=incident_log_path,
        cache_size=cache_size,
        block_cache_enabled=block_cache_enabled,
        block_cache_limit_mb=block_cache_limit_mb,
        alert_url=source.get("MATTERMOST_URL"),
        alert_token=source.get("MATTERMOST_TOKEN"),
        alert_channel=source.get("MATTERMOST_ALERT_CHANNEL"),
        alert_telegram_token=source.get("PII_PROXY_ALERT_TELEGRAM_TOKEN"),
        alert_telegram_chat=source.get("PII_PROXY_ALERT_TELEGRAM_CHAT"),
        alert_telegram_thread=source.get("PII_PROXY_ALERT_TELEGRAM_THREAD"),
        ner_enabled=ner_enabled,
        ner_backend=ner_backend,
        dry_run=dry_run,
        rarity_k=rarity_k,
        rarity_enforce=rarity_enforce,
        request_timeout=int(str(source.get("PII_PROXY_REQUEST_TIMEOUT") or 120)),
        log_level=str(source.get("PII_PROXY_LOG_LEVEL") or "INFO").upper(),
    )
# END_BLOCK_VALIDATE_CONFIG
