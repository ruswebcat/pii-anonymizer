# FILE: src/dictionary.py
# VERSION: 1.2.0
# START_MODULE_CONTRACT
#   PURPOSE: Hold the exact list of known personal-data values (clients, staff, phones, identifiers) so the tokenizer catches values that no rule would recognize, and refresh it without restarting the proxy.
#   SCOPE: JSON dictionary loading with permission checks, normalized lookup index, hot reload by mtime and size, per-class counts, graceful empty state.
#   DEPENDS: M-CONFIG, M-NORM
#   LINKS: M-DICT, V-M-DICT, export-dictionary, fn-lookup, fn-reload_if_changed
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   PiiDictionary - known-value dictionary with hot reload
#   fn-load - read the dictionary file
#   fn-reload_if_changed - pick up a new file version
#   fn-values_for - raw values of one class
#   fn-lookup - exact normalized match to a class
#   fn-identity_digest - отпечаток персоны-основы: падежная форма впереди точного написания
#   fn-snapshot - per-class counts without values
#   fn-live_file_state - живое (время правки, размер) справочника одной точкой
#   fn-dictionary_signature - подпись «путь + время правки + размер» для кэшей
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.2.0 - живое состояние файла справочника и его подпись вынесены в общие помощники (live_file_state, dictionary_signature), чтобы кэш токенизатора, кэш пар заслона и ключ кэша блоков судили о смене справочника одним кодом, а не каждый по-своему.
#   PREVIOUS: v1.1.0 - Phase-14: в хешированном словаре блок формо-дигестов проверяется впереди точных отпечатков, поэтому написание, признанное выгрузкой падежной формой, получает код персоны-основы, а не собственный.
#   EARLIER: v1.0.0 - Phase-2 M-DICT: exact matching layer feeding the name detector and the tokenizer.
# END_CHANGE_SUMMARY

"""Known-value dictionary.

Implements M-DICT from docs/ARCHITECTURE.md. A dictionary hit is the most
reliable detection there is, which is why the export script (M-DICT-EXPORT) pulls
it straight from CRM. Two deliberate properties:

* a missing file is not an error — the proxy starts with an empty dictionary and
  keeps working on rules and heuristics alone (V-M-DICT scenario 3);
* the file is read whole and swapped atomically, so a half-written export can
  never be observed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from src.name_identity import DIGEST_IDENTITY_PREFIX
from src.normalize import NormalizeError, normalize

LOGGER_NAME = "PiiDictionary"
LOG_MARKER = "[PiiDictionary][reload][BLOCK_RELOAD_DICTIONARY]"

CLASSES = ("P", "T", "E", "D", "A", "I", "C")

# Schema 2 stores keyed digests instead of readable values. Matching only ever
# needs membership, because the raw value being tested is already in the text the
# tokenizer is working on — so the dictionary has no reason to hold a readable
# copy of 150k personal values on disk (raised by the owner on 15.09.2026).
#
# Schema 3 adds the digests of the *case forms* of each value (Phase-8). A keyed
# dictionary cannot generate forms for itself: it never sees the value. Without
# this block a declined spelling resolved to the open list's base — or to nothing —
# so one client got several codes (measured 19.09.2026: PhCons 0,875, RepRate 0,966
# in the production contour). With it the form points at its value's digest, and
# the code stays one per person in every case.
#
# Phase-14 (19.09.2026) extends that block to *families*: a spelling that is a case
# form of another spelling belongs to the family base, even when another client's
# card happens to hold exactly that spelling. The block therefore wins over the
# exact digests in :meth:`PiiDictionary.identity_digest` — a case form is not a person
# of its own. Raison d'être, measured on the live reference: 15 of 40 sampled values
# got several codes, 12 of them because a dropped (ambiguous) form fell back to the
# open list's readable base, 3 because a form coincided with another client's card
# value.
SCHEMA_DIGEST = 2
SCHEMA_FORMS = 3
DIGEST_LENGTH = 16


def value_digest(key: bytes, cls: str, normalized_value: str) -> str:
    """Return the keyed digest used for dictionary membership.

    # START_CONTRACT: value_digest
    #   PURPOSE: Make the dictionary file useless without the key.
    #   INPUTS: { key: bytes - secret, cls: str - class letter, normalized_value: str - normalized value }
    #   OUTPUTS: { str - hex digest }
    #   SIDE_EFFECTS: none
    #   LINKS: M-DICT, M-DICT-EXPORT, V-M-DICT
    # END_CONTRACT: value_digest

    Plain SHA-256 would be reversible by enumeration: there are only so many
    plausible Russian surnames, so an attacker holding the file could confirm any
    guess. Keying the digest removes that offline oracle.
    """
    message = f"{cls}:{normalized_value}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()[:DIGEST_LENGTH]


class DictionaryError(RuntimeError):
    """Dictionary failure with a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass
class _Snapshot:
    """Internal view of one dictionary version."""

    raw: dict[str, list[str]] = field(default_factory=dict)
    normalized: dict[str, dict[str, str]] = field(default_factory=dict)
    digests: dict[str, set[str]] = field(default_factory=dict)
    #: schema 3: класс -> {отпечаток падежной формы: отпечаток значения}
    form_bases: dict[str, dict[str, str]] = field(default_factory=dict)
    keyed: bool = False
    mtime: float = 0.0
    size: int = 0
    version: int = 0


# START_BLOCK_RELOAD_DICTIONARY
class PiiDictionary:
    """Known-value dictionary with hot reload.

    # START_CONTRACT: PiiDictionary
    #   PURPOSE: Provide exact matches for known PII values.
    #   INPUTS: { path: str - dictionary file, loader: Callable[[str], Mapping] | None - injectable reader }
    #   OUTPUTS: { PiiDictionary - ready dictionary }
    #   SIDE_EFFECTS: reads the file on load and on reload
    #   LINKS: M-DICT-EXPORT, M-DETECT-NAME, M-TOKENIZER, V-M-DICT
    # END_CONTRACT: PiiDictionary
    """

    def __init__(
        self,
        path: str,
        loader: Callable[[str], Mapping[str, Any]] | None = None,
        key: bytes | None = None,
    ) -> None:
        self._path = path
        self._loader = loader or self._read_file
        self._key = key
        self._state = _Snapshot()
        self._warnings: list[str] = []
        self.load()

    @staticmethod
    def _read_file(path: str) -> Mapping[str, Any]:
        """Read and parse the dictionary file."""
        if not os.path.isfile(path):
            return {}
        mode = stat.S_IMODE(os.stat(path).st_mode)
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def load(self) -> int:
        """(Re)load the dictionary and return the number of indexed values.

        # START_CONTRACT: load
        #   PURPOSE: Build the raw and normalized indexes.
        #   INPUTS: none
        #   OUTPUTS: { int - number of values }
        #   SIDE_EFFECTS: reads the dictionary file
        #   LINKS: V-M-DICT
        # END_CONTRACT: load
        """
        try:
            payload = self._loader(self._path)
        except FileNotFoundError:
            payload = {}
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            self._warnings.append(f"dictionary unreadable: {type(exc).__name__}")
            payload = {}
        if not isinstance(payload, Mapping):
            self._warnings.append("dictionary root must be an object")
            payload = {}

        # Schema 2: the file carries keyed digests, so matching is a membership
        # test and the file itself is not a readable copy of anyone's data.
        # Schema 3 adds the digests of the case forms of each value on top of that.
        if int(payload.get("schema") or 0) in (SCHEMA_DIGEST, SCHEMA_FORMS):
            digests: dict[str, set[str]] = {}
            form_bases: dict[str, dict[str, str]] = {}
            counter = 0
            source = payload.get("digests")
            for cls, values in (source or {}).items():
                letter = str(cls).strip().upper()
                if letter not in CLASSES or not isinstance(values, (list, tuple, set)):
                    continue
                bucket = {str(value).strip().lower() for value in values if str(value).strip()}
                if bucket:
                    digests[letter] = bucket
                    counter += len(bucket)
            # Блок форм необязателен: файл schema 2 его не несёт, и это нормальное состояние,
            # а не ошибка — словарь продолжает работать по точным отпечаткам.
            raw_forms = payload.get("forms")
            if isinstance(raw_forms, Mapping):
                for cls, pairs in raw_forms.items():
                    letter = str(cls).strip().upper()
                    if letter not in CLASSES or not isinstance(pairs, Mapping):
                        continue
                    bucket_forms: dict[str, str] = {}
                    for form, base in pairs.items():
                        form_digest = str(form).strip().lower()
                        base_digest = str(base).strip().lower()
                        if form_digest and base_digest:
                            bucket_forms[form_digest] = base_digest
                    if bucket_forms:
                        form_bases[letter] = bucket_forms
            if self._key is None:
                self._warnings.append("dictionary is keyed but no key was provided")
            stat_info = self._stat()
            self._state = _Snapshot(
                digests=digests,
                form_bases=form_bases,
                keyed=True,
                mtime=stat_info[0],
                size=stat_info[1],
                version=self._state.version + 1,
            )
            return counter

        raw: dict[str, list[str]] = {}
        normalized: dict[str, dict[str, str]] = {}
        counter = 0
        for cls, values in payload.items():
            letter = str(cls).strip().upper()
            if letter not in CLASSES or not isinstance(values, (list, tuple, set)):
                continue
            raw_values: list[str] = []
            index: dict[str, str] = {}
            for value in values:
                text = str(value).strip()
                if not text:
                    continue
                raw_values.append(text)
                counter += 1
                try:
                    index[normalize(letter, text)] = text
                except NormalizeError:
                    continue
            # A class with no usable values is left out entirely, so the snapshot
            # counts describe real coverage instead of listing empty buckets.
            if raw_values:
                raw[letter] = raw_values
                normalized[letter] = index

        stat_info = self._stat()
        self._state = _Snapshot(
            raw=raw,
            normalized=normalized,
            keyed=False,
            mtime=stat_info[0],
            size=stat_info[1],
            version=self._state.version + 1,
        )
        return counter

    def _stat(self) -> tuple[float, int]:
        """Return (mtime, size) of the dictionary file, or zeros when absent."""
        try:
            info = os.stat(self._path)
        except OSError:
            return 0.0, 0
        return info.st_mtime, info.st_size

    def file_signature(self) -> tuple[float, int]:
        """Return (mtime, size) so callers can notice a dictionary reload.

        # START_CONTRACT: file_signature
        #   PURPOSE: Let the tokenizer drop cached results when the dictionary changed.
        #   INPUTS: { none }
        #   OUTPUTS: { tuple[float, int] - mtime and size, zeros when absent }
        #   SIDE_EFFECTS: none
        #   LINKS: M-CACHE, M-DICTIONARY
        # END_CONTRACT: file_signature
        """
        return self._stat()

    def reload_if_changed(self) -> bool:
        """Reload when the file changed on disk; return True when reloaded.

        # START_CONTRACT: reload_if_changed
        #   PURPOSE: Pick up the export produced by the scheduled script.
        #   INPUTS: none
        #   OUTPUTS: { bool - True when a new version was loaded }
        #   SIDE_EFFECTS: reads the dictionary file
        #   LINKS: M-DICT-EXPORT, V-M-DICT
        # END_CONTRACT: reload_if_changed
        """
        try:
            stat_info = os.stat(self._path)
        except OSError:
            if self._state.version and self._state.size:
                self.load()
                return True
            return False
        if (stat_info.st_mtime, stat_info.st_size) == (self._state.mtime, self._state.size):
            return False
        self.load()
        return True

    def values_for(self, cls: str) -> list[str]:
        """Return the raw values of one class.

        # START_CONTRACT: values_for
        #   PURPOSE: Feed the name detector with exact client names.
        #   INPUTS: { cls: str - class letter }
        #   OUTPUTS: { list[str] - raw values }
        #   SIDE_EFFECTS: none
        #   LINKS: M-DETECT-NAME, V-M-DETECT-NAME
        # END_CONTRACT: values_for

        A keyed dictionary stores no readable values, so this returns an empty
        list: detection uses :meth:`lookup`, which needs membership only. Callers
        that want a human-readable list (diagnostics, one-off scripts) must work
        with an unkeyed export.
        """
        if self._state.keyed:
            return []
        return list(self._state.raw.get(str(cls).strip().upper(), []))

    def lookup(self, value: str, cls: str | None = None) -> str | None:
        """Return the class of a known value, or None.

        # START_CONTRACT: lookup
        #   PURPOSE: Exact match against the known-value index.
        #   INPUTS: { value: str - candidate, cls: str | None - restrict to one class }
        #   OUTPUTS: { str | None - class letter }
        #   SIDE_EFFECTS: none
        #   LINKS: M-TOKENIZER, V-M-DICT
        # END_CONTRACT: lookup
        """
        if self._state.keyed:
            if self._key is None:
                return None
            candidates = [cls] if cls else CLASSES
            for letter in candidates:
                if not letter:
                    continue
                letter = str(letter).strip().upper()
                bucket = self._state.digests.get(letter)
                if not bucket:
                    continue
                for probe in _probe_normalized(letter, value):
                    if value_digest(self._key, letter, probe) in bucket:
                        return letter
            return None
        candidates = [cls] if cls else list(self._state.normalized)
        for letter in candidates:
            if not letter:
                continue
            letter = str(letter).strip().upper()
            index = self._state.normalized.get(letter) or {}
            for probe in _probe_forms(value):
                if probe in index:
                    return letter
        return None

    def identity_digest(self, value: str, cls: str | None = None) -> str | None:
        """Вернуть служебный отпечаток персоны для написания, или None.

        # START_CONTRACT: identity_digest
        #   PURPOSE: Дать распознаванию персону на хешированном словаре: код должен быть один во всех падежах.
        #   INPUTS: { value: str - написание из текста, cls: str | None - класс (по умолчанию «имена») }
        #   OUTPUTS: { str | None - «pd:<отпечаток значения>» или None, когда написания в справочнике нет }
        #   SIDE_EFFECTS: none
        #   LINKS: M-DICT, M-DICT-EXPORT, M-NAME-IDENTITY, V-M-DICT
        # END_CONTRACT: identity_digest

        Порядок: **падежная форма впереди точного написания**. В блоке `forms` лежат написания,
        которые выгрузка признала формами основы семьи (Phase-14): и падеж значения, и написание,
        совпавшее с падежом другого значения. Такое написание — падеж, а не персона, поэтому код
        берётся у основы семьи; иначе один клиент получал бы два кода, а падеж — свой собственный
        (решение владельца 18.09.2026 «код присваивается персоне, а не падежной форме»).
        Точный отпечаток из блока `digests` отвечает за написание, которое формой не является, —
        там и живёт персона. Возвращается отпечаток, а не значение: файл читаемых значений не
        хранит, и это не ограничение, а свойство.
        """
        if not self._state.keyed or self._key is None:
            return None
        letter = str(cls).strip().upper() if cls else "P"
        if letter not in CLASSES:
            return None
        probes = _probe_normalized(letter, value)
        if not probes:
            return None
        probe = probes[0]
        digest = value_digest(self._key, letter, probe)
        pairs = self._state.form_bases.get(letter)
        if pairs:
            # Отпечаток самой формы ищем по её написанию; в блоке форм лежат отпечатки форм,
            # порождённых основами семей, поэтому совпадение означает «это падеж персоны-основы».
            base = pairs.get(digest)
            if base:
                return DIGEST_IDENTITY_PREFIX + base
        exact = self._state.digests.get(letter)
        if exact and digest in exact:
            return DIGEST_IDENTITY_PREFIX + digest
        return None

    def snapshot(self) -> dict[str, Any]:
        """Return per-class counts, version and warnings — never values.

        # START_CONTRACT: snapshot
        #   PURPOSE: Observable state for healthz and the audit journal.
        #   INPUTS: none
        #   OUTPUTS: { dict - counts, version, warnings }
        #   SIDE_EFFECTS: none
        #   LINKS: M-AUDIT, V-M-DICT
        # END_CONTRACT: snapshot
        """
        return {
            "counts": (
                {letter: len(values) for letter, values in self._state.digests.items()}
                if self._state.keyed
                else {letter: len(values) for letter, values in self._state.raw.items()}
            ),
            "keyed": self._state.keyed,
            # Число падежных форм в выгрузке (schema 3): показатель того, что словарь может
            # держать одну персону во всех падежах. Значений не печатает.
            "form_digests": sum(len(pairs) for pairs in self._state.form_bases.values()),
            "version": self._state.version,
            "warnings": list(self._warnings),
        }

    @property
    def size(self) -> int:
        """Return the total number of indexed values."""
        if self._state.keyed:
            return sum(len(bucket) for bucket in self._state.digests.values())
        return sum(len(values) for values in self._state.raw.values())

    @property
    def path(self) -> str:
        """Return the dictionary file path."""
        return self._path


def _probe_forms(value: str) -> list[str]:
    """Return candidate normalized forms of a raw value."""
    forms: list[str] = []
    for letter in ("P", "T", "E", "C", "I", "A"):
        forms.extend(_probe_normalized(letter, value))
    return forms


def _probe_normalized(letter: str, value: str) -> list[str]:
    """Return the normalized form of a value for one class, or an empty list."""
    try:
        return [normalize(letter, value)]
    except NormalizeError:
        return []
# END_BLOCK_RELOAD_DICTIONARY


# START_BLOCK_DICT_SIGNATURE
def live_file_state(source: Any) -> tuple[float, int] | None:
    """Вернуть живое (время правки, размер) файла справочника, или None.

    # START_CONTRACT: live_file_state
    #   PURPOSE: Одна точка, где состояние файла справочника спрашивается у источника, а не читается здесь.
    #   INPUTS: { source: Any - объект со свойством file_signature() -> (mtime, size) }
    #   OUTPUTS: { tuple[float, int] | None - состояние файла или None, если источник его не отдаёт }
    #   SIDE_EFFECTS: один os.stat внутри file_signature источника; файл не читается
    #   LINKS: M-DICT, M-CACHE, M-DETECT-NAME
    # END_CONTRACT: live_file_state

    Никакого чтения файла: подпись обязана стоить один `os.stat` на вызов, иначе проверка
    «сменился ли справочник» на каждом блоке станет дороже самой обезлички.
    """
    signature = getattr(source, "file_signature", None)
    if not callable(signature):
        return None
    try:
        value = signature()
    except Exception:  # noqa: BLE001 - сбойный справочник не должен останавливать работу
        return None
    if isinstance(value, tuple) and len(value) == 2:
        return float(value[0]), int(value[1])
    return None


def dictionary_signature(dictionary: Any) -> str | None:
    """Вернуть подпись справочника «путь + время правки + размер», или None.

    # START_CONTRACT: dictionary_signature
    #   PURPOSE: Дать кэшам одну сравнимую подпись справочника, в которую входит и путь файла.
    #   INPUTS: { dictionary: Any - объект справочника со свойствами path и file_signature() }
    #   OUTPUTS: { str | None - подпись или None, когда источник её не отдаёт }
    #   SIDE_EFFECTS: один os.stat внутри file_signature источника
    #   LINKS: M-DICT, M-CACHE, M-DETECT-NAME, M-VALIDATOR
    # END_CONTRACT: dictionary_signature

    Путь входит наравне с состоянием файла: замена справочника другим файлом (например
    свежим экспортом рядом) должна гасить кэш даже при совпавших времени и размере.
    """
    state = live_file_state(dictionary)
    if state is None:
        return None
    path = str(getattr(dictionary, "path", "") or "")
    return f"{path}|{state[0]}|{state[1]}"
# END_BLOCK_DICT_SIGNATURE
