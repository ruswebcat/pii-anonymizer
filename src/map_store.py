# FILE: src/map_store.py
# VERSION: 1.1.0
# START_MODULE_CONTRACT
#   PURPOSE: Persist the token-to-value correspondence table locally with encryption and TTL, and read values back only for authorized detokenization.
#   SCOPE: encrypted binding storage, single binding lookup, expiry purge, per-class counters, file permission hardening.
#   DEPENDS: M-CONFIG
#   LINKS: M-MAP-STORE, V-M-MAP-STORE, export-store, fn-load_value, fn-purge_expired
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   MapStoreError - store failure with a stable code
#   IntegrityReport - отчёт проверки реестра: числа и коды без значений
#   TokenMapStore - encrypted SQLite correspondence table
#   fn-scan_integrity - код → ровно одно значение и ровно одна персона
#   fn-require_integrity - проверка реестра с отказом при многозначном коде
#   fn-binding_records - список кодов, классов и персон без значений
#   fn-record_ambiguity - сколько разных персон называет один код
#   fn-store - persist one binding
#   fn-load_value - decrypt and return the value for a token
#   fn-load_identity - идентичность значения: по ней сравниваются записи
#   fn-append_form - дописать наблюдённую форму в порядке вхождения
#   fn-load_forms - наблюдённые формы кода для согласования падежа
#   fn-mark_source - пометить связку источником (например «из инцидента»)
#   fn-values_by_source - значения одного источника за промежуток времени
#   fn-source_counts - сколько связок помечено каждым источником
#   fn-purge_expired - delete bindings older than the TTL
#   fn-counters - per-class binding counts
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.3.0 - Phase-17 шаг 1 (20.09.2026): проверка целостности реестра (M-REGISTRY-GUARD) — код → ровно одно значение и ровно одна персона; отказ MAP_AMBIGUOUS_CODE при многозначности, ответ record_ambiguity для заслона восстановления. Причина: разбор инцидента 20.09.2026 (выдуманная персона в живом ответе) потребовал инварианта, а не наблюдения.
#   PREVIOUS: v1.2.0 - Phase-15 шаг 1: колонка source у связки и чтение значений по пометке «из инцидента» — тренеру нужно знать, какие значения пришли из промахов детектора, не перебирая весь справочник.
#   PREVIOUS: v1.1.0 - Phase-7 шаг 3: запись хранит идентичность значения и список наблюдённых форм; старые файлы читаются без миграции данных.
# END_CHANGE_SUMMARY

"""Encrypted token-to-value correspondence table.

Implements M-MAP-STORE from docs/ARCHITECTURE.md. RKN order 140 method 1
("introduction of identifiers") requires the correspondence table to be kept
apart from the working PII arrays, which is why this file is a separate SQLite
database with its own key and its own TTL purge.

The table is the only place where raw values live, so nothing from this module
may ever be logged: only class letters and counts.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import stat
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

LOGGER_NAME = "TokenMapStore"
LOG_MARKER = "[TokenMapStore][store][BLOCK_STORE_BINDING]"

SCHEMA = """
CREATE TABLE IF NOT EXISTS token_map (
    token TEXT PRIMARY KEY,
    cls TEXT NOT NULL,
    value_enc BLOB NOT NULL,
    created_at REAL NOT NULL,
    last_used_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_token_map_cls ON token_map (cls);
"""

# Phase-7 (19.09.2026): код присваивается персоне, а не падежной форме, поэтому к записи
# добавляются идентичность значения (по ней сравниваются записи) и список наблюдённых форм
# (из них выбирается форма при восстановлении). Старые файлы читаются без миграции данных:
# у них обе колонки пусты, а роль списка форм играет само значение.
COLUMNS_SCHEMA = (
    "identity_enc BLOB",
    "forms_enc BLOB",
    # Phase-15: источник связки. Пометка «из инцидента» (значение пришло из промаха
    # детектора) нужна недельному тренеру словаря: он берёт только такие значения.
    # Класс и пометка — машинные строки, значений в них нет.
    "source TEXT",
)

#: Предел удержания наблюдённых форм на один код: список нужен для согласования падежа,
#: а не как копия текста агента.
MAX_OBSERVED_FORMS = 8

#: Предел кэша ответов «сколько персон за кодом»: проверка нужна на каждом восстановлении,
#: а справочник на коротком ответе возвращает десятки кодов. Кэш чистится при любой записи,
#: поэтому ответ не может устареть: форма, дописанная позже, меняет вердикт.
AMBIGUITY_CACHE_LIMIT = 4096


@dataclass(frozen=True)
class IntegrityReport:
    """Итог проверки целостности реестра: числа и коды, без единого значения.

    # START_CONTRACT: IntegrityReport
    #   PURPOSE: Отдать счётчики проверки реестра так, чтобы их можно было показать и записать в инцидент.
    #   INPUTS: { codes: int, records: int, ambiguous_codes: tuple[str, ...], value_conflicts: int, checked_identities: int }
    #   OUTPUTS: { IntegrityReport - отчёт }
    #   SIDE_EFFECTS: none
    #   LINKS: M-MAP-STORE, M-REGISTRY-GUARD, V-M-MAP-STORE
    # END_CONTRACT: IntegrityReport

    ``ambiguous_codes`` — коды, за которыми стоит больше одной персоны: состояние, которого
    быть не должно. В отчёте только коды (псевдонимы, они и так лежат в журналах), значения
    не выводятся ни в каком виде.
    """

    codes: int = 0
    records: int = 0
    ambiguous_codes: tuple[str, ...] = ()
    value_conflicts: int = 0
    checked_identities: int = 0
    classes: Mapping[str, int] = field(default_factory=dict)

    @property
    def ambiguous(self) -> int:
        """Число кодов, несущих больше одного значения или больше одной персоны."""
        return len(self.ambiguous_codes) + self.value_conflicts

    def to_dict(self) -> dict[str, Any]:
        """Отдать отчёт словарём: только числа и коды."""
        return {
            "codes": self.codes,
            "records": self.records,
            "ambiguous_codes": len(self.ambiguous_codes),
            "value_conflicts": self.value_conflicts,
            "checked_identities": self.checked_identities,
            "classes": dict(self.classes),
        }


class MapStoreError(RuntimeError):
    """Store failure with a stable code.

    # START_CONTRACT: MapStoreError
    #   PURPOSE: Signal an unusable store so the router can fail closed.
    #   INPUTS: { code: str - stable code, message: str - detail }
    #   OUTPUTS: { MapStoreError - exception instance }
    #   SIDE_EFFECTS: none
    #   LINKS: M-MAP-STORE, M-ROUTER, V-M-MAP-STORE
    # END_CONTRACT: MapStoreError
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Binding:
    """One stored correspondence record without its value.

    # START_CONTRACT: Binding
    #   PURPOSE: Describe a stored binding for counters and tests.
    #   INPUTS: { token: str, cls: str, created_at: float, last_used_at: float }
    #   OUTPUTS: { Binding - value object }
    #   SIDE_EFFECTS: none
    #   LINKS: M-MAP-STORE
    # END_CONTRACT: Binding
    """

    token: str
    cls: str
    created_at: float
    last_used_at: float


# START_BLOCK_STORE_BINDING
class TokenMapStore:
    """Encrypted SQLite correspondence table between tokens and PII values.

    # START_CONTRACT: TokenMapStore
    #   PURPOSE: Own the encrypted correspondence table and its lifecycle.
    #   INPUTS: { db_path: str, fernet_key: bytes, ttl_days: int }
    #   OUTPUTS: { TokenMapStore - usable store }
    #   SIDE_EFFECTS: creates and modifies the SQLite file on disk
    #   LINKS: M-CONFIG, M-TOKENIZER, M-DETOKENIZER, V-M-MAP-STORE
    # END_CONTRACT: TokenMapStore
    """

    def __init__(self, db_path: str, fernet_key: bytes, ttl_days: int = 90) -> None:
        if not fernet_key:
            raise MapStoreError("MAP_KEY_FILE_MISSING", "fernet key material is empty")
        try:
            self._fernet = Fernet(self._normalize_key(fernet_key))
        except (ValueError, TypeError) as exc:
            raise MapStoreError("MAP_KEY_FILE_MISSING", f"unusable fernet key: {exc}") from exc
        self._db_path = db_path
        self._ttl_seconds = max(1, int(ttl_days)) * 86400
        self._ambiguity_cache: dict[str, int] = {}
        directory = os.path.dirname(os.path.abspath(db_path))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, mode=0o700, exist_ok=True)
        try:
            self._conn = sqlite3.connect(db_path, check_same_thread=False)
            self._conn.executescript(SCHEMA)
            self._migrate_columns()
            self._conn.commit()
        except sqlite3.Error as exc:
            raise MapStoreError("MAP_STORE_UNAVAILABLE", f"cannot open store: {exc}") from exc
        self._harden_permissions()

    def _migrate_columns(self) -> None:
        """Дописать новые колонки в существующий файл (повторный запуск — без изменений).

        `CREATE TABLE IF NOT EXISTS` не трогает уже созданную таблицу, поэтому колонки
        добавляются по одной и «уже есть» — нормальный исход, а не ошибка.
        """
        for column in COLUMNS_SCHEMA:
            try:
                self._conn.execute(f"ALTER TABLE token_map ADD COLUMN {column}")
            except sqlite3.OperationalError as exc:
                if "duplicate column" not in str(exc).lower():
                    raise

    @staticmethod
    def _normalize_key(raw: bytes) -> bytes:
        """Accept either a raw 32-byte key or a base64 urlsafe Fernet key."""
        if len(raw) == 44:
            try:
                base64.urlsafe_b64decode(raw)
                return raw
            except Exception:  # pragma: no cover - defensive branch
                pass
        return base64.urlsafe_b64encode(raw[:32].ljust(32, b"\0"))

    def _harden_permissions(self) -> None:
        try:
            os.chmod(self._db_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:  # pragma: no cover - filesystem dependent
            pass

    # START_BLOCK_STORE_BINDING
    def store(self, token: str, cls: str, value: str, identity: str = "") -> None:
        """Persist one token-to-value binding.

        # START_CONTRACT: store
        #   PURPOSE: Keep the encrypted value for later detokenization, plus the identity that decides which person the code belongs to.
        #   INPUTS: { token: str - token string, cls: str - class letter, value: str - observed form to store, identity: str - identity key of the value }
        #   OUTPUTS: { None }
        #   SIDE_EFFECTS: writes the SQLite file
        #   LINKS: M-TOKENIZER, M-NAME-IDENTITY, V-M-MAP-STORE
        # END_CONTRACT: store

        Повторная запись того же кода ничего не перезаписывает: значение остаётся первым
        наблюдённым написанием, а идентичность дозаполняется, если её не было (записи,
        созданные до Phase-7). Так старая связь продолжает работать и становится сравнимой
        по персоне.
        """
        if not token or value is None:
            raise MapStoreError("MAP_STORE_BAD_BINDING", "token and value are required")
        now = time.time()
        payload = self._fernet.encrypt(value.encode("utf-8"))
        identity_payload = self._fernet.encrypt(identity.encode("utf-8")) if identity else None
        forms_payload = self._fernet.encrypt(json.dumps([value], ensure_ascii=False).encode("utf-8"))
        try:
            self._conn.execute(
                "INSERT INTO token_map (token, cls, value_enc, created_at, last_used_at, identity_enc, forms_enc) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(token) DO UPDATE SET "
                "last_used_at = excluded.last_used_at, "
                "identity_enc = COALESCE(token_map.identity_enc, excluded.identity_enc)",
                (token, cls, payload, now, now, identity_payload, forms_payload),
            )
            self._conn.commit()
            # Новая связка и новая форма меняют вердикт «сколько персон за кодом».
            self._ambiguity_cache.clear()
        except sqlite3.Error as exc:
            raise MapStoreError("MAP_STORE_UNAVAILABLE", f"cannot store binding: {exc}") from exc

    def append_form(self, token: str, form: str, limit: int = MAX_OBSERVED_FORMS) -> bool:
        """Дописать наблюдённую форму в список форм кода.

        # START_CONTRACT: append_form
        #   PURPOSE: Собрать формы, в которых значение встретилось в запросе, — по ним восстанавливается падеж.
        #   INPUTS: { token: str - код, form: str - наблюдённое написание, limit: int - предел удержания }
        #   OUTPUTS: { bool - True, если форма добавлена }
        #   SIDE_EFFECTS: перезаписывает зашифрованный список форм
        #   LINKS: M-TOKENIZER, M-DETOKENIZER, V-M-MAP-STORE
        # END_CONTRACT: append_form

        Хранится ограниченное число форм (предел удержания): список нужен для согласования
        падежа, а не как копия текста. Повтор той же формы ничего не меняет.
        """
        text = (form or "").strip()
        if not token or not text:
            return False
        try:
            row = self._conn.execute(
                "SELECT forms_enc, value_enc FROM token_map WHERE token = ?", (token,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise MapStoreError("MAP_STORE_UNAVAILABLE", f"cannot read forms: {exc}") from exc
        if row is None:
            return False
        forms = self._decode_forms(row[0], row[1])
        if text in forms:
            return False
        if len(forms) >= max(1, int(limit)):
            return False
        forms.append(text)
        payload = self._fernet.encrypt(json.dumps(forms, ensure_ascii=False).encode("utf-8"))
        try:
            self._conn.execute(
                "UPDATE token_map SET forms_enc = ? WHERE token = ?", (payload, token)
            )
            self._conn.commit()
            self._ambiguity_cache.clear()
        except sqlite3.Error as exc:
            raise MapStoreError("MAP_STORE_UNAVAILABLE", f"cannot store forms: {exc}") from exc
        return True

    def load_identity(self, token: str) -> str | None:
        """Вернуть идентичность значения для кода, или None.

        # START_CONTRACT: load_identity
        #   PURPOSE: Сравнивать записи по персоне, а не по падежной форме.
        #   INPUTS: { token: str - код }
        #   OUTPUTS: { str | None - ключ идентичности }
        #   SIDE_EFFECTS: читает SQLite
        #   LINKS: M-TOKENIZER, V-M-NAME-IDENTITY
        # END_CONTRACT: load_identity

        None у записей, созданных до Phase-7: токенизатор тогда сравнивает их по значению
        тем же правилом `matches_identity` и, если это та же персона, дозаписывает
        идентичность.
        """
        try:
            row = self._conn.execute(
                "SELECT identity_enc FROM token_map WHERE token = ?", (token,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise MapStoreError("MAP_STORE_UNAVAILABLE", f"cannot read identity: {exc}") from exc
        if row is None or row[0] is None:
            return None
        try:
            return self._fernet.decrypt(row[0]).decode("utf-8")
        except InvalidToken as exc:
            raise MapStoreError("MAP_DECRYPT_FAILED", f"cannot decrypt identity {token}") from exc

    def load_forms(self, token: str) -> list[str]:
        """Вернуть наблюдённые формы кода в порядке вхождения.

        # START_CONTRACT: load_forms
        #   PURPOSE: Восстановление берёт ту форму, в которой код встречался в запросе.
        #   INPUTS: { token: str - код }
        #   OUTPUTS: { list[str] - формы без повторов, первая — хранимое значение }
        #   SIDE_EFFECTS: читает SQLite
        #   LINKS: M-DETOKENIZER, V-M-DETOKENIZER
        # END_CONTRACT: load_forms

        Записи до Phase-7 списка форм не имеют: тогда список — это само хранимое значение,
        то есть поведение прежней версии.
        """
        try:
            row = self._conn.execute(
                "SELECT forms_enc, value_enc FROM token_map WHERE token = ?", (token,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise MapStoreError("MAP_STORE_UNAVAILABLE", f"cannot read forms: {exc}") from exc
        if row is None:
            return []
        forms = self._decode_forms(row[0], row[1])
        return forms

    def mark_source(self, token: str, source: str) -> bool:
        """Пометить связку источником происхождения значения.

        # START_CONTRACT: mark_source
        #   PURPOSE: Отделить значения из инцидентов от обычных: тренер берёт только помеченные.
        #   INPUTS: { token: str - код связки, source: str - пометка источника («из инцидента») }
        #   OUTPUTS: { bool - True, если связка найдена и помечена }
        #   SIDE_EFFECTS: обновляет строку SQLite
        #   LINKS: M-INCIDENT-JOURNAL, M-INCIDENT-TRAINER, V-M-MAP-STORE
        # END_CONTRACT: mark_source

        Пометка не является персональными данными: это машинная строка-источник. TTL и
        порядок удаления помеченных связок не меняются — значение из инцидента живёт
        обычный срок и чистится вместе с остальными.
        """
        text = (source or "").strip()
        if not token or not text:
            return False
        try:
            cursor = self._conn.execute(
                "UPDATE token_map SET source = ? WHERE token = ?", (text, token)
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise MapStoreError("MAP_STORE_UNAVAILABLE", f"cannot mark source: {exc}") from exc
        return int(cursor.rowcount or 0) > 0

    def values_by_source(
        self,
        source: str,
        since: float | None = None,
        until: float | None = None,
        limit: int | None = None,
    ) -> list[tuple[str, str, str]]:
        """Вернуть связки одного источника за промежуток: (код, класс, значение).

        # START_CONTRACT: values_by_source
        #   PURPOSE: Дать тренеру ровно те значения, которые пришли из инцидентов за неделю.
        #   INPUTS: { source: str - пометка, since/until: float | None - границы по времени создания, limit: int | None - предел }
        #   OUTPUTS: { list[tuple[str, str, str]] - код, класс и расшифрованное значение }
        #   SIDE_EFFECTS: читает SQLite и расшифровывает значения
        #   LINKS: M-INCIDENT-TRAINER, M-MAP-STORE, V-M-MAP-STORE
        # END_CONTRACT: values_by_source

        Значения расшифровываются для вызывающего кода и никогда не печатаются: этот вызов
        существует для локального недельного тренера, а не для журналов и логов (правило
        проекта «значений в журналах нет»). Фильтр по времени создания отделяет неделю
        отчёта от всего, что накопилось в справочнике раньше.
        """
        query = "SELECT token, cls, value_enc FROM token_map WHERE source = ?"
        params: list[object] = [source]
        if since is not None:
            query += " AND created_at >= ?"
            params.append(float(since))
        if until is not None:
            query += " AND created_at <= ?"
            params.append(float(until))
        query += " ORDER BY created_at"
        if limit is not None:
            query += " LIMIT ?"
            params.append(max(0, int(limit)))
        try:
            rows = self._conn.execute(query, tuple(params)).fetchall()
        except sqlite3.Error as exc:
            raise MapStoreError("MAP_STORE_UNAVAILABLE", f"cannot read source: {exc}") from exc
        return [
            (str(row[0]), str(row[1]), self._decode_value(row[2]))
            for row in rows
            if row[2] is not None
        ]

    def source_counts(self) -> dict[str, int]:
        """Сколько связок помечено каждым источником (числа, без значений).

        # START_CONTRACT: source_counts
        #   PURPOSE: Показать недельному отчёту и healthz объём инцидентных значений.
        #   INPUTS: none
        #   OUTPUTS: { dict[str, int] - пометка источника или «-» к количеству }
        #   SIDE_EFFECTS: читает SQLite
        #   LINKS: M-INCIDENT-JOURNAL, M-MAP-STORE, V-M-MAP-STORE
        # END_CONTRACT: source_counts
        """
        try:
            rows = self._conn.execute(
                "SELECT COALESCE(source, '-'), COUNT(*) FROM token_map GROUP BY 1"
            ).fetchall()
        except sqlite3.Error as exc:
            raise MapStoreError("MAP_STORE_UNAVAILABLE", f"cannot count sources: {exc}") from exc
        return {str(name): int(count) for name, count in rows}

    def _decode_forms(self, forms_payload: bytes | None, value_payload: bytes | None) -> list[str]:
        """Расшифровать список форм, при отсутствии — собрать его из значения."""
        if forms_payload is None:
            value = self._decode_value(value_payload) if value_payload is not None else None
            return [value] if value else []
        try:
            raw = json.loads(self._fernet.decrypt(forms_payload).decode("utf-8"))
        except (InvalidToken, ValueError) as exc:
            raise MapStoreError("MAP_DECRYPT_FAILED", "cannot decrypt forms") from exc
        if not isinstance(raw, list):
            return []
        return [str(item) for item in raw if str(item or "").strip()]

    def _decode_value(self, payload: bytes) -> str:
        """Расшифровать одно хранимое значение."""
        try:
            return self._fernet.decrypt(payload).decode("utf-8")
        except InvalidToken as exc:
            raise MapStoreError("MAP_DECRYPT_FAILED", "cannot decrypt binding") from exc
    # END_BLOCK_STORE_BINDING

    # START_BLOCK_REGISTRY_INTEGRITY
    def scan_integrity(
        self,
        identity_of: Callable[[str], str | None] | None = None,
        classes: tuple[str, ...] = ("P",),
    ) -> IntegrityReport:
        """Проверить целостность реестра: код → ровно одно значение, код → ровно одна персона.

        # START_CONTRACT: scan_integrity
        #   PURPOSE: Считать состояние реестра, в котором «два разных значения под одним кодом» — недопустимое, а не редкое.
        #   INPUTS: { identity_of: Callable[[str], str | None] | None - как называть персону значения, classes: tuple[str, ...] - классы, где смотрят персон }
        #   OUTPUTS: { IntegrityReport - числа и коды без значений }
        #   SIDE_EFFECTS: читает SQLite и расшифровывает значения внутри процесса
        #   LINKS: M-MAP-STORE, M-DETOKENIZER, M-ROUTER, V-M-MAP-STORE
        # END_CONTRACT: scan_integrity

        Что именно проверяется. (1) Под одним кодом должно лежать ровно одно хранимое значение:
        схема этого требует, и нарушение — признак испорченного файла, а не «редкого случая».
        (2) Все наблюдённые формы кода обязаны называть одну персону: если формы кода
        разрешаются в разные личности, код многозначен, и восстановление по нему может выдать
        чужого человека. Значения наружу не выходят: отчёт несёт числа и коды.

        Проверка персон идёт через переданный ``identity_of`` — тот же резолвер, что у
        токенизатора (M-NAME-IDENTITY). Пока значения нет в справочнике, персона не
        называется, и форма в счёт не идёт: догадка здесь запрещена.
        """
        try:
            rows = self._conn.execute(
                "SELECT token, cls, value_enc, identity_enc, forms_enc FROM token_map"
            ).fetchall()
        except sqlite3.Error as exc:
            raise MapStoreError("MAP_STORE_UNAVAILABLE", f"cannot scan registry: {exc}") from exc
        values_per_code: dict[str, set[bytes]] = {}
        people_per_code: dict[str, set[str]] = {}
        classes_count: dict[str, int] = {}
        for token, cls, value_enc, _identity_enc, forms_enc in rows:
            letter = str(cls)
            classes_count[letter] = classes_count.get(letter, 0) + 1
            values_per_code.setdefault(str(token), set()).add(value_enc)
            if identity_of is None or letter not in classes:
                continue
            people = people_per_code.setdefault(str(token), set())
            for form in self._decode_forms(forms_enc, value_enc):
                person = identity_of(form)
                if person:
                    people.add(str(person))
        conflicts = sum(1 for payloads in values_per_code.values() if len(payloads) > 1)
        ambiguous = tuple(
            sorted(token for token, people in people_per_code.items() if len(people) > 1)
        )
        return IntegrityReport(
            codes=len(values_per_code),
            records=len(rows),
            ambiguous_codes=ambiguous,
            value_conflicts=conflicts,
            checked_identities=sum(len(people) for people in people_per_code.values()),
            classes=classes_count,
        )

    def require_integrity(
        self,
        identity_of: Callable[[str], str | None] | None = None,
        classes: tuple[str, ...] = ("P",),
    ) -> IntegrityReport:
        """Проверить реестр и отказать, если найдён многозначный код.

        # START_CONTRACT: require_integrity
        #   PURPOSE: Не пустить службу в работу с реестром, где код значит больше одного значения.
        #   INPUTS: { identity_of: Callable[[str], str | None] | None, classes: tuple[str, ...] }
        #   OUTPUTS: { IntegrityReport - отчёт при чистом реестре }
        #   SIDE_EFFECTS: читает SQLite
        #   LINKS: M-ROUTER, V-M-MAP-STORE
        # END_CONTRACT: require_integrity

        Отказ, а не предупреждение: восстановление по многозначному коду выдумывает человека,
        а выдуманная персона хуже пустого места. Значений в сообщении нет — только число кодов.
        """
        report = self.scan_integrity(identity_of, classes)
        if report.ambiguous:
            raise MapStoreError(
                "MAP_AMBIGUOUS_CODE",
                f"registry holds {report.ambiguous} ambiguous codes "
                f"(records={report.records}, codes={report.codes})",
            )
        return report

    def binding_records(
        self,
        identity_of: Callable[[str], str | None] | None = None,
    ) -> list[tuple[str, str, str]]:
        """Вернуть (код, класс, идентичность) каждой связки — без хранимых значений.

        # START_CONTRACT: binding_records
        #   PURPOSE: Дать приборам список связок, не выпуская ни одного значения наружу.
        #   INPUTS: { identity_of: Callable[[str], str | None] | None - чем назвать персону у старых записей }
        #   OUTPUTS: { list[tuple[str, str, str]] - код, класс, идентичность (может быть пустой) }
        #   SIDE_EFFECTS: читает SQLite и расшифровывает значения внутри процесса
        #   LINKS: M-REGISTRY-GUARD, M-MAP-STORE, V-M-MAP-STORE
        # END_CONTRACT: binding_records

        Идентичность у записей до Phase-7 пуста: для них персона спрашивается у ``identity_of``,
        чтобы инвентарь мерил обход кандидатов так же, как это делает присвоение кода.
        """
        try:
            rows = self._conn.execute(
                "SELECT token, cls, identity_enc, value_enc FROM token_map"
            ).fetchall()
        except sqlite3.Error as exc:
            raise MapStoreError("MAP_STORE_UNAVAILABLE", f"cannot read bindings: {exc}") from exc
        answer: list[tuple[str, str, str]] = []
        for token, cls, identity_enc, value_enc in rows:
            identity = ""
            if identity_enc is not None:
                try:
                    identity = self._fernet.decrypt(identity_enc).decode("utf-8")
                except InvalidToken:
                    identity = ""
            if not identity and identity_of is not None and value_enc is not None:
                person = identity_of(self._decode_value(value_enc))
                identity = str(person or "")
            answer.append((str(token), str(cls), identity))
        return answer

    def record_ambiguity(
        self,
        token: str,
        identity_of: Callable[[str], str | None] | None,
    ) -> int:
        """Сколько разных персон называет один код (0 или 1 — норма).

        # START_CONTRACT: record_ambiguity
        #   PURPOSE: Дать заслону ответ на месте: восстанавливать ли значение по этому коду.
        #   INPUTS: { token: str - код, identity_of: Callable[[str], str | None] | None - как называть персону }
        #   OUTPUTS: { int - число разных персон за кодом }
        #   SIDE_EFFECTS: читает SQLite; кэширует ответ до ближайшей записи в справочник
        #   LINKS: M-DETOKENIZER, V-M-DETOKENIZER
        # END_CONTRACT: record_ambiguity
        """
        if identity_of is None or not token:
            return 0
        if token in self._ambiguity_cache:
            return self._ambiguity_cache[token]
        try:
            counted = self._conn.execute(
                "SELECT COUNT(*), COUNT(DISTINCT value_enc) FROM token_map WHERE token = ?",
                (token,),
            ).fetchone()
            row = self._conn.execute(
                "SELECT forms_enc, value_enc FROM token_map WHERE token = ?", (token,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise MapStoreError("MAP_STORE_UNAVAILABLE", f"cannot read record: {exc}") from exc
        answer = 0
        rows_under_code = int(counted[0] or 0) if counted else 0
        values_under_code = int(counted[1] or 0) if counted else 0
        if rows_under_code > 1 or values_under_code > 1:
            # Испорченный файл: под одним кодом больше одной записи или больше одного значения.
            answer = max(values_under_code, rows_under_code)
        elif row is not None:
            people: set[str] = set()
            for form in self._decode_forms(row[0], row[1]):
                person = identity_of(form)
                if person:
                    people.add(str(person))
            answer = len(people) if len(people) > 1 else 0
        if len(self._ambiguity_cache) >= AMBIGUITY_CACHE_LIMIT:
            self._ambiguity_cache.clear()
        self._ambiguity_cache[token] = answer
        return answer
    # END_BLOCK_REGISTRY_INTEGRITY

    def load_value(self, token: str) -> str | None:
        """Return the decrypted value for a token, or None when unknown.

        # START_CONTRACT: load_value
        #   PURPOSE: Restore one value for detokenization.
        #   INPUTS: { token: str - token string }
        #   OUTPUTS: { str | None - decrypted value }
        #   SIDE_EFFECTS: updates last_used_at, reads the SQLite file
        #   LINKS: M-DETOKENIZER, V-M-DETOKENIZER
        # END_CONTRACT: load_value
        """
        try:
            row = self._conn.execute(
                "SELECT value_enc FROM token_map WHERE token = ?", (token,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise MapStoreError("MAP_STORE_UNAVAILABLE", f"cannot read binding: {exc}") from exc
        if row is None:
            return None
        try:
            value = self._fernet.decrypt(row[0]).decode("utf-8")
        except InvalidToken as exc:
            raise MapStoreError("MAP_DECRYPT_FAILED", f"cannot decrypt binding {token}") from exc
        try:
            self._conn.execute(
                "UPDATE token_map SET last_used_at = ? WHERE token = ?", (time.time(), token)
            )
            self._conn.commit()
        except sqlite3.Error:  # pragma: no cover - non critical
            pass
        return value

    def purge_expired(self, now: float | None = None) -> int:
        """Delete bindings older than the TTL and return the number removed.

        # START_CONTRACT: purge_expired
        #   PURPOSE: Honour the 90-day TTL decided by the owner on 15.09.2026.
        #   INPUTS: { now: float | None - reference timestamp }
        #   OUTPUTS: { int - removed rows }
        #   SIDE_EFFECTS: deletes rows from the SQLite file
        #   LINKS: M-CONFIG, V-M-MAP-STORE
        # END_CONTRACT: purge_expired
        """
        reference = time.time() if now is None else now
        threshold = reference - self._ttl_seconds
        try:
            cursor = self._conn.execute(
                "DELETE FROM token_map WHERE last_used_at < ?", (threshold,)
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise MapStoreError("MAP_STORE_UNAVAILABLE", f"cannot purge: {exc}") from exc
        return int(cursor.rowcount or 0)

    def counters(self) -> dict[str, int]:
        """Return the number of live bindings per class.

        # START_CONTRACT: counters
        #   PURPOSE: Feed healthz and the audit journal without exposing values.
        #   INPUTS: none
        #   OUTPUTS: { dict[str, int] - class letter to count }
        #   SIDE_EFFECTS: reads the SQLite file
        #   LINKS: M-AUDIT, M-ROUTER
        # END_CONTRACT: counters
        """
        try:
            rows = self._conn.execute(
                "SELECT cls, COUNT(*) FROM token_map GROUP BY cls"
            ).fetchall()
        except sqlite3.Error as exc:
            raise MapStoreError("MAP_STORE_UNAVAILABLE", f"cannot count: {exc}") from exc
        return {str(cls): int(count) for cls, count in rows}

    def get_binding(self, token: str) -> Binding | None:
        """Return binding metadata without decrypting the value."""
        try:
            row = self._conn.execute(
                "SELECT token, cls, created_at, last_used_at FROM token_map WHERE token = ?",
                (token,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise MapStoreError("MAP_STORE_UNAVAILABLE", f"cannot read metadata: {exc}") from exc
        if row is None:
            return None
        return Binding(token=row[0], cls=row[1], created_at=row[2], last_used_at=row[3])

    def raw_file_contains(self, needle: str) -> bool:
        """Check whether the raw database bytes contain a needle.

        Only used by tests to prove that values are stored encrypted.
        """
        with open(self._db_path, "rb") as handle:
            blob = handle.read()
        return needle.encode("utf-8") in blob

    def close(self) -> None:
        """Close the underlying connection."""
        try:
            self._conn.close()
        except sqlite3.Error:  # pragma: no cover - defensive
            pass

    def dumps_metadata(self) -> str:
        """Return a JSON summary that contains no values, for healthz."""
        return json.dumps({"counters": self.counters(), "ttl_days": self._ttl_seconds // 86400})
# END_BLOCK_STORE_BINDING
