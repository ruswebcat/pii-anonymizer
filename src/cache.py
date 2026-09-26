# FILE: src/cache.py
# VERSION: 1.2.0
# START_MODULE_CONTRACT
#   PURPOSE: Avoid re-scanning unchanged text blocks (typically hundreds of kilobytes of re-sent history) by caching tokenization results keyed by content hash, dictionary signature and key scheme version.
#   SCOPE: bounded LRU cache with two independent bounds (entry count and total bytes), key = content hash + dictionary signature + schema version, hit-time check that every code still resolves, hit and miss counters, guarantee that raw values are never stored.
#   DEPENDS: M-CONFIG
#   LINKS: M-CACHE, V-M-CACHE, export-cache, fn-stats
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   CACHE_KEY_SCHEMA - version of the key layout; bump it when the key changes
#   TokenizationCache - LRU cache over block hashes, dictionary signature and code tags
#   fn-get - return the cached tokenized block after checking its codes
#   fn-put - store a tokenized block together with the tag of its bindings
#   fn-_evict - drop least recently used entries until both bounds hold
#   fn-stats - hits, misses, stale, size, bytes, evictions for healthz
#   fn-clear - drop every entry
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.2.0 - блоки с находками тоже кэшируются, но под ответственной подписью. Ключ получил подпись справочника (путь, время правки, размер, отпечаток ключа) и версию схемы ключа, поэтому смена справочника делает недействительным весь кэш сразу, а не только по факту перезагрузки. Запись обезличенного блока сопровождается отпечатком связей «код → персона»: на попадании каждый код обязан всё ещё разрешаться в то же значение, иначе запись считается устаревшей и блок обезличивается заново.
#   EARLIER: v1.1.0 - M-CACHE gets a byte budget next to the entry count. The entry count alone made a long dialog thrash: hundreds of small blocks filled the cap while a single large one was evicted, so history was re-scanned. The volume of a live dialog is measured in bytes, and the bound must be expressed in the same unit.
#   EARLIER: v1.0.0 - Phase-2 M-CACHE: performance layer that must not weaken the tokenizer's determinism.
# END_CHANGE_SUMMARY

"""Tokenization cache.

Implements M-CACHE from docs/ARCHITECTURE.md. The agent re-sends the whole
conversation on every request, so the same blocks are tokenized again and again.
The cache stores the sha256 of the input, the already tokenized text and a tag
describing the bindings that text was built from, which means it cannot leak
values: plaintext never enters the cache, and the tokenized text contains codes,
not data.

Two bounds are held at once, and the least recently used entry goes first as long
as *either* of them is violated:

* ``max_entries`` — the historical bound. It counts blocks, and a live dialog of
  hundreds of messages is nothing like a thousand blocks of one byte each: a
  hundred-block cache can hold ten kilobytes or ten megabytes, so the entry count
  alone says nothing about memory.
* ``max_bytes`` — the byte budget (``PII_PROXY_BLOCK_CACHE_MB``, 64 MB by
  default). It is what makes the cache retain a whole re-sent history instead of
  evicting its head, and it is the bound that actually limits memory.

Blocks *with* findings are cached too (decision of 26.09.2026), because in a real
dialog almost every block carries a code and refusing to cache them left the
seconds in place. Two guarantees make that safe:

* the key carries the **dictionary signature** (path, mtime, size, key
  fingerprint) and the **schema version** (``CACHE_KEY_SCHEMA``): a reloaded or
  replaced dictionary invalidates the whole cache at once, because every key
  changes;
* an entry only counts as a hit while every code inside it **still resolves to
  the same value**. The tokenizer hands ``get`` a ``verify`` predicate and a tag
  recorded next to the value; on a mismatch the entry is dropped and the block is
  anonymized afresh.
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from typing import Callable

LOGGER_NAME = "TokenizationCache"
LOG_MARKER = "[TokenizationCache][lookup][BLOCK_CACHE_LOOKUP]"

#: Версия схемы ключа: первая версия, в которой ключ несёт подпись справочника.
#: Меняется, когда меняется состав ключа: старые записи после такого изменения
#: обязаны стать промахами, а не «почти попаданиями».
CACHE_KEY_SCHEMA = 1


class CacheError(RuntimeError):
    """Cache misuse or failure with a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# START_BLOCK_CACHE_LOOKUP
class TokenizationCache:
    """Bounded LRU cache from block hash to tokenized block.

    # START_CONTRACT: TokenizationCache
    #   PURPOSE: Keep repeated tokenization cheap without storing values, and without serving a block whose codes went stale.
    #   INPUTS: { max_entries: int - entry budget, 0 disables the cache; max_bytes: int | None - byte budget over stored values, None or 0 keeps the entries-only behaviour; signature: str - static part of the dictionary signature (path and key fingerprint); signature_source: Callable | None - returns the live (mtime, size) of the dictionary file }
    #   OUTPUTS: { TokenizationCache - ready cache }
    #   SIDE_EFFECTS: holds bounded memory only
    #   LINKS: M-TOKENIZER, M-CONFIG, V-M-CACHE
    # END_CONTRACT: TokenizationCache
    """

    def __init__(
        self,
        max_entries: int = 512,
        max_bytes: int | None = None,
        signature: str = "",
        signature_source: Callable[[], object] | None = None,
    ) -> None:
        if max_entries < 0:
            raise CacheError("CACHE_BAD_SIZE", "max_entries must not be negative")
        if max_bytes is not None and max_bytes < 0:
            raise CacheError("CACHE_BAD_SIZE", "max_bytes must not be negative")
        self._max_entries = int(max_entries)
        # A budget of zero is the same as "no byte budget": healthz cannot tell a
        # disabled cache from an unbounded one otherwise, and both mean the same
        # for eviction.
        self._max_bytes = int(max_bytes) if max_bytes else None
        self._signature_prefix = str(signature or "")
        self._signature_source = signature_source if callable(signature_source) else None
        self._signature = self._compose_signature()
        # Значение записи и отпечаток связей, по которым оно построено. Отпечаток
        # хранится рядом с текстом: на попадании его пересчитывают по справочнику и
        # сравнивают, поэтому запись с кодами, переставшими разрешаться, не отдаётся.
        self._entries: OrderedDict[str, tuple[str, str]] = OrderedDict()
        self._bytes = 0
        self._hits = 0
        self._misses = 0
        self._stale = 0
        self._signature_changes = 0
        self._evictions = 0

    @staticmethod
    def key_for(text: str, signature: str = "") -> str:
        """Return the cache key for a text block.

        # START_CONTRACT: key_for
        #   PURPOSE: Hash the block together with the dictionary signature and the schema version, so plaintext is never held as a key and a stale dictionary cannot serve old entries.
        #   INPUTS: { text: str - block; signature: str - dictionary signature }
        #   OUTPUTS: { str - hex digest }
        #   SIDE_EFFECTS: none
        #   LINKS: V-M-CACHE
        # END_CONTRACT: key_for
        """
        material = f"v{CACHE_KEY_SCHEMA}\x00{signature}\x00{text}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _compose_signature(self) -> str:
        """Return the signature string that goes into every key.

        # START_CONTRACT: _compose_signature
        #   PURPOSE: Put the schema version, the dictionary identity and its live file state into one string.
        #   INPUTS: none
        #   OUTPUTS: { str - signature }
        #   SIDE_EFFECTS: reads the dictionary file metadata when a source is set
        #   LINKS: M-CACHE, M-DICT
        # END_CONTRACT: _compose_signature
        """
        live = None
        if self._signature_source is not None:
            try:
                live = self._signature_source()
            except Exception:  # noqa: BLE001 - a broken dictionary must not stop serving
                live = None
        return f"v{CACHE_KEY_SCHEMA}|{self._signature_prefix}|{live}"

    def _refresh_signature(self) -> bool:
        """Recompute the signature and drop everything when it changed.

        # START_CONTRACT: _refresh_signature
        #   PURPOSE: Инвалидировать кэш целиком при смене справочника, а не по факту чужого вызова.
        #   INPUTS: none
        #   OUTPUTS: { bool - True когда подпись изменилась и записи сброшены }
        #   SIDE_EFFECTS: reads file metadata, may drop every entry
        #   LINKS: M-CACHE, M-DICT
        # END_CONTRACT: _refresh_signature
        """
        if self._signature_source is None:
            return False
        current = self._compose_signature()
        if current == self._signature:
            return False
        self._signature = current
        self._signature_changes += 1
        self.clear()
        return True

    @property
    def signature(self) -> str:
        """Return the signature every key is currently built from."""
        return self._signature

    @staticmethod
    def _value_bytes(entry: tuple[str, str]) -> int:
        """Return the memory a stored entry occupies, in UTF-8 bytes.

        # START_CONTRACT: _value_bytes
        #   PURPOSE: Count the bound in the unit the budget is expressed in.
        #   INPUTS: { entry: tuple[str, str] - stored tokenized block and its tag }
        #   OUTPUTS: { int - byte length }
        #   SIDE_EFFECTS: none
        #   LINKS: V-M-CACHE
        # END_CONTRACT: _value_bytes
        """
        value, tag = entry
        return len(value.encode("utf-8")) + len(tag.encode("utf-8"))

    @property
    def enabled(self) -> bool:
        """Return True when the cache is active."""
        return self._max_entries > 0

    def get(
        self,
        text: str,
        verify: Callable[[str, str], bool] | None = None,
    ) -> str | None:
        """Return the cached tokenized block, or None on a miss.

        # START_CONTRACT: get
        #   PURPOSE: Serve repeated blocks without re-running detectors, but never serve a block whose codes no longer resolve.
        #   INPUTS: { text: str - block; verify: Callable[[str, str], bool] | None - проверка (значение, отпечаток) для блока, в котором были находки }
        #   OUTPUTS: { str | None - tokenized block }
        #   SIDE_EFFECTS: updates recency order and counters, may drop a stale entry
        #   LINKS: M-TOKENIZER, V-M-CACHE
        # END_CONTRACT: get

        ``verify`` is called only for a block whose stored text differs from the
        input — that is exactly the block in which something was replaced. A
        clean block stores its own input, so it carries no binding of ours to
        re-check and keeps the old, cheaper path.
        """
        if not self.enabled:
            return None
        self._refresh_signature()
        key = self.key_for(text, self._signature)
        entry = self._entries.get(key)
        if entry is None:
            self._misses += 1
            return None
        value, tag = entry
        if value != text and verify is not None and not verify(value, tag):
            # Запись сделана под прежним состоянием справочника: код перестал
            # разрешаться (или разрешается в другое значение). Отдать её — значит
            # вернуть устаревший код в исходящий запрос, поэтому это промах.
            self._drop(key)
            self._stale += 1
            self._misses += 1
            return None
        self._entries.move_to_end(key)
        self._hits += 1
        return value

    def put(self, text: str, tokenized: str, tag: str = "") -> None:
        """Store a tokenized block, evicting the least recently used entries.

        # START_CONTRACT: put
        #   PURPOSE: Fill the cache with bounded memory, together with the tag of the bindings the result was built from.
        #   INPUTS: { text: str - original block, tokenized: str - result, tag: str - отпечаток связей «код → персона», пустой для блока без находок }
        #   OUTPUTS: { None }
        #   SIDE_EFFECTS: evicts the oldest entries while either bound is violated
        #   LINKS: M-TOKENIZER, V-M-CACHE
        # END_CONTRACT: put

        A block that alone exceeds the byte budget is stored and evicted by the
        same call: the bound is a ceiling on what the process holds, so it wins
        over the wish to keep the block. Oversized single blocks are a
        configuration signal, not a reason to exceed the budget.
        """
        if not self.enabled:
            return
        self._refresh_signature()
        key = self.key_for(text, self._signature)
        entry = (tokenized, str(tag or ""))
        if key in self._entries:
            # Rewriting an entry must not count its bytes twice.
            self._bytes -= self._value_bytes(self._entries[key])
        self._entries[key] = entry
        self._entries.move_to_end(key)
        self._bytes += self._value_bytes(entry)
        self._evict()

    def _drop(self, key: str) -> None:
        """Remove one entry and correct the byte total."""
        dropped = self._entries.pop(key, None)
        if dropped is not None:
            self._bytes -= self._value_bytes(dropped)

    def _evict(self) -> None:
        """Drop least recently used entries until both bounds hold.

        # START_CONTRACT: _evict
        #   PURPOSE: Hold the entry count and the byte budget at once.
        #   INPUTS: { none }
        #   OUTPUTS: { None }
        #   SIDE_EFFECTS: removes entries, updates byte total and the eviction counter
        #   LINKS: V-M-CACHE, fn-stats
        # END_CONTRACT: _evict
        """
        while self._entries and (
            len(self._entries) > self._max_entries
            or (self._max_bytes is not None and self._bytes > self._max_bytes)
        ):
            _, evicted = self._entries.popitem(last=False)
            self._bytes -= self._value_bytes(evicted)
            self._evictions += 1

    def stats(self) -> dict[str, int | str]:
        """Return counters for healthz.

        # START_CONTRACT: stats
        #   PURPOSE: Make cache effectiveness observable.
        #   INPUTS: none
        #   OUTPUTS: { dict[str, int | str] - hits, misses, stale, signature_changes, size, max_entries, entries, bytes, evictions, limit_bytes, signature }
        #   SIDE_EFFECTS: none
        #   LINKS: M-ROUTER, V-M-CACHE
        # END_CONTRACT: stats

        ``size`` and ``entries`` are the same number under two names: the first is
        kept because healthz readers know it, the second because the byte budget
        makes it read as "how many blocks fit", ``bytes`` is what those entries
        hold, and ``limit_bytes`` is 0 when the byte budget is off. ``stale``
        counts entries that were dropped for retired codes, ``signature`` is a
        short fingerprint of the dictionary signature in the key (not the
        signature itself: healthz carries no paths beyond what it always did).
        """
        entries = len(self._entries)
        return {
            "hits": self._hits,
            "misses": self._misses,
            "stale": self._stale,
            "signature_changes": self._signature_changes,
            "size": entries,
            "max_entries": self._max_entries,
            "entries": entries,
            "bytes": self._bytes,
            "evictions": self._evictions,
            "limit_bytes": self._max_bytes if self._max_bytes is not None else 0,
            "signature": hashlib.sha256(self._signature.encode("utf-8")).hexdigest()[:12],
        }

    def clear(self) -> None:
        """Drop every cached entry."""
        self._entries.clear()
        self._bytes = 0

    def contains_any(self, needles: list[str]) -> bool:
        """Return True when a value appears in the cached keys or values.

        Used by tests to prove that raw values never enter the cache.
        """
        blob = "".join(self._entries)
        for value, tag in self._entries.values():
            blob += value + tag
        return any(needle and needle in blob for needle in needles)
# END_BLOCK_CACHE_LOOKUP
