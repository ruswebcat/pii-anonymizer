# FILE: src/detect_ner.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Add free-text name detection on top of rules and the dictionary, with pluggable local backends and silent degradation when no backend is installed.
#   SCOPE: lazy backend loading, morphology backend over pymorphy when available, optional neural backend, no-op fallback, status reporting for healthz.
#   DEPENDS: M-CONFIG
#   LINKS: M-NER, V-M-NER, fn-detect_ner, fn-ner_status
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   NerDetector - free-text name detector with pluggable backends
#   fn-detect_ner - name spans from the active backend
#   fn-ner_status - availability and backend identity, no data
#   fn-load_backend - lazy backend discovery
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.1.0 - Phase-19 (23.09.2026): кэш морфологических разборов по отпечатку слова. Профиль на реальном запросе MM показал 131 672 разбора слов за один запрос (около 80 % времени обработки) — повторяющиеся слова больше не разбираются заново; значения текста в кэше не хранятся.
#   PREVIOUS: v1.0.0 - Phase-2 M-NER: the host has 2 GB RAM, so the backend is lazy and optional; heavy neural stacks are not installed.
# END_CHANGE_SUMMARY

"""Free-text name detection.

Implements M-NER from docs/ARCHITECTURE.md. The owner asked for NER on
15.09.2026 ("место много не занимает"), but the realistic constraint is the host:
2 GB RAM total. Therefore the module is a shell with pluggable backends:

* ``morphology`` — uses ``pymorphy3``/``pymorphy2`` word tags (pure Python, tens
  of megabytes) to recognize declined surnames and patronymics that shape
  heuristics miss;
* ``neural`` — used only when a neural NER package is already present (not
  installed here; a torch-based stack would not fit the host);
* ``none`` — no backend: the detector reports unavailable and returns nothing,
  which must never break the pipeline (V-M-NER scenario 2).

Nothing is imported at module import time; the backend is discovered on first
use, so startup stays fast and memory stays free until text actually needs it.
"""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict
from typing import Any, Callable

from src.detect_name import is_own_lexicon_value
from src.detect_rules import CLASS_NAME, PiiMatch, merge_matches
from src.normalize import NormalizeError, normalize

LOGGER_NAME = "NerDetector"
LOG_MARKER = "[NerDetector][detect_ner][BLOCK_LAZY_LOAD_MODEL]"

NAME_TAGS = ("Name", "Surn", "Patr", "имя", "фам", "отч")


class NerError(RuntimeError):
    """NER failure with a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# START_BLOCK_LAZY_LOAD_MODEL
class NerDetector:
    """Optional free-text name detector.

    # START_CONTRACT: NerDetector
    #   PURPOSE: Add recalled names that rules and dictionary miss.
    #   INPUTS: { backend: str - "auto", "morphology", "neural" or "none", backend_factory: Callable | None - injectable backend for tests }
    #   OUTPUTS: { NerDetector - ready detector, possibly unavailable }
    #   SIDE_EFFECTS: imports a backend lazily on first use
    #   LINKS: M-TOKENIZER, M-CONFIG, V-M-NER
    # END_CONTRACT: NerDetector
    """

    def __init__(
        self,
        backend: str = "auto",
        backend_factory: Callable[[], Any] | None = None,
    ) -> None:
        self._requested = backend
        self._factory = backend_factory
        self._backend: Any | None = None
        self._backend_name = "none"
        self._loaded = False
        self._errors: list[str] = []

    def load_backend(self) -> str:
        """Discover and initialize the backend once; return its name.

        # START_CONTRACT: load_backend
        #   PURPOSE: Keep imports off the startup path.
        #   INPUTS: none
        #   OUTPUTS: { str - backend name }
        #   SIDE_EFFECTS: imports a third-party module when present
        #   LINKS: V-M-NER
        # END_CONTRACT: load_backend
        """
        if self._loaded:
            return self._backend_name
        self._loaded = True
        if self._requested == "none":
            self._backend_name = "none"
            return self._backend_name
        if self._factory is not None:
            self._backend = self._factory()
            self._backend_name = getattr(self._backend, "name", "custom")
            return self._backend_name
        if self._requested in ("auto", "morphology"):
            morph = _MorphologyBackend.try_create()
            if morph is not None:
                self._backend = morph
                self._backend_name = "morphology"
                return self._backend_name
        if self._requested in ("auto", "neural"):
            neural = _NeuralBackend.try_create()
            if neural is not None:
                self._backend = neural
                self._backend_name = "neural"
                return self._backend_name
        self._errors.append("no NER backend available")
        self._backend_name = "none"
        return self._backend_name

    @property
    def available(self) -> bool:
        """Return True when a backend is usable.

        # START_CONTRACT: available
        #   PURPOSE: Report degraded mode honestly.
        #   INPUTS: none
        #   OUTPUTS: { bool - True when a backend is loaded }
        #   SIDE_EFFECTS: triggers lazy loading once
        #   LINKS: M-ROUTER, V-M-NER
        # END_CONTRACT: available
        """
        return self.load_backend() != "none" and self._backend is not None

    def detect_names(self, text: str) -> list[PiiMatch]:
        """Return free-text name spans, or nothing when unavailable.

        # START_CONTRACT: detect_names
        #   PURPOSE: Feed the tokenizer with recalled names.
        #   INPUTS: { text: str - block to scan }
        #   OUTPUTS: { list[PiiMatch] - class P matches }
        #   SIDE_EFFECTS: may load the backend on first call
        #   LINKS: M-TOKENIZER, V-M-NER
        # END_CONTRACT: detect_names
        """
        if not text or not self.available:
            return []
        try:
            matches = self._backend.detect(text)
        except Exception as exc:  # noqa: BLE001 - a broken backend must never break the pipeline
            self._errors.append(f"backend failure: {type(exc).__name__}")
            self._backend = None
            self._backend_name = "none"
            return []
        cleaned: list[PiiMatch] = []
        for match in matches:
            value = _safe_name(match.get("text", ""))
            if value is None:
                continue
            # A morphological or neural backend happily tags club and city names,
            # so the stopword filter from the shape detector applies here too: целым значением
            # проверяются оба набора, словом внутри значения — только брендовый (см. M-DETECT-NAME).
            if is_own_lexicon_value(value):
                continue
            cleaned.append(
                PiiMatch(
                    int(match["start"]),
                    int(match["end"]),
                    CLASS_NAME,
                    match.get("text", ""),
                    value,
                )
            )
        return merge_matches(cleaned)

    def ner_status(self) -> dict[str, Any]:
        """Return availability and backend identity for healthz.

        # START_CONTRACT: ner_status
        #   PURPOSE: Make degradation visible without leaking text.
        #   INPUTS: none
        #   OUTPUTS: { dict - available, backend, errors }
        #   SIDE_EFFECTS: triggers lazy loading once
        #   LINKS: M-ROUTER, V-M-NER
        # END_CONTRACT: ner_status
        """
        self.load_backend()
        return {
            "available": self.available,
            "backend": self._backend_name,
            "errors": list(self._errors),
        }


def _safe_name(raw: str) -> str | None:
    """Normalize a candidate name, returning None when it is unusable."""
    try:
        return normalize(CLASS_NAME, raw)
    except NormalizeError:
        return None


class _MorphologyBackend:
    """Backend built on pymorphy word tags (pure Python, light).

    # START_CONTRACT: _MorphologyBackend
    #   PURPOSE: Recognize declined names via grammatical tags.
    #   INPUTS: { morph: Any - pymorphy module or compatible object }
    #   OUTPUTS: { _MorphologyBackend - backend with detect() }
    #   SIDE_EFFECTS: none
    #   LINKS: V-M-NER
    # END_CONTRACT: _MorphologyBackend
    """

    name = "morphology"

    def __init__(self, morph: Any) -> None:
        self._morph = morph

    @classmethod
    def try_create(cls) -> "_MorphologyBackend | None":
        """Return a backend when pymorphy is importable, else None."""
        for module_name in ("pymorphy3", "pymorphy2"):
            try:
                module = __import__(module_name)
            except ImportError:
                continue
            return cls(module.MorphAnalyzer())
        return None

    def detect(self, text: str) -> list[dict[str, Any]]:
        """Return spans of word pairs whose tags look like a person name."""
        words = list(_iter_words(text))
        found: list[dict[str, Any]] = []
        index = 0
        while index < len(words):
            start, end, token_text = words[index]
            tag_names = _tag_names(self._morph, token_text)
            if not _looks_like_name_token(tag_names):
                index += 1
                continue
            pair_end = end
            if index + 1 < len(words):
                next_start, next_end, next_text = words[index + 1]
                if next_start == end + 1 and _looks_like_name_token(
                    _tag_names(self._morph, next_text)
                ):
                    pair_end = next_end
                    found.append({"start": start, "end": pair_end, "text": text[start:pair_end]})
                    index += 2
                    continue
            found.append({"start": start, "end": pair_end, "text": text[start:pair_end]})
            index += 1
        return found


class _NeuralBackend:
    """Backend for an already installed neural NER package (absent here)."""

    name = "neural"

    @classmethod
    def try_create(cls) -> "_NeuralBackend | None":
        try:
            import natasha  # noqa: F401 - availability probe only
        except ImportError:
            return None
        return cls()

    def detect(self, text: str) -> list[dict[str, Any]]:  # pragma: no cover - not installed
        from natasha import Doc, Segmenter, MorphVocab, NewsEmbedding, NewsNERTagger  # noqa: PLC0415

        doc = Doc(text)
        doc.segment(Segmenter())
        doc.tag_ner(NewsNERTagger(NewsEmbedding()))
        return [
            {"start": span.start, "end": span.stop, "text": text[span.start : span.stop]}
            for span in doc.spans
            if span.type == "PER"
        ]


def _iter_words(text: str):
    """Yield (start, end, word) for Cyrillic/Latin word runs."""
    index = 0
    length = len(text)
    while index < length:
        if text[index].isalpha():
            start = index
            while index < length and (text[index].isalpha() or text[index] in "-'"):
                index += 1
            yield start, index, text[start:index]
        else:
            index += 1


# START_BLOCK_TAG_CACHE
#: Разбор слова — самый дорогой шаг в обработке (обход DAWG внутри морфологии), а слова в
#: истории чата и в описаниях инструментов повторяются тысячи раз. Кэш держит теги граммем
#: по отпечатку слова: значения текста в памяти не задерживаются, сами слова не хранятся.
_TAG_CACHE_LIMIT = 50_000
_TAG_CACHE: "OrderedDict[str, tuple[str, ...]]" = OrderedDict()
_TAG_CACHE_LOCK = threading.Lock()
_TAG_CACHE_STATS = {"hits": 0, "misses": 0}


def tag_cache_stats() -> dict[str, int]:
    """Вернуть счётчики кэша разборов: попадания, промахи, размер (без значений текста)."""
    with _TAG_CACHE_LOCK:
        return {
            "hits": _TAG_CACHE_STATS["hits"],
            "misses": _TAG_CACHE_STATS["misses"],
            "size": len(_TAG_CACHE),
        }


def clear_tag_cache() -> None:
    """Сбросить кэш разборов вместе со счётчиками: нужен тестам и смене бэкенда."""
    with _TAG_CACHE_LOCK:
        _TAG_CACHE.clear()
        _TAG_CACHE_STATS["hits"] = 0
        _TAG_CACHE_STATS["misses"] = 0
# END_BLOCK_TAG_CACHE


def _tag_names(morph: Any, word: str) -> tuple[str, ...]:
    """Return grammatical tag names for a word, cached by the digest of that word.

    # START_CONTRACT: _tag_names
    #   PURPOSE: Держать разбор слова дешёвым: морфология — это обход DAWG, а слова в истории чата повторяются тысячи раз.
    #   INPUTS: { morph: Any - анализатор, word: str - слово из текста }
    #   OUTPUTS: { tuple[str, ...] - имена граммем первого разбора, пустой кортеж при сбое }
    #   SIDE_EFFECTS: пишет в кэш по отпечатку слова; сами слова в кэше не хранятся
    #   LINKS: M-NER, M-TOKENIZER, V-M-NER, Phase-19
    # END_CONTRACT: _tag_names

    Замер 23.09.2026 (профиль на реальном запросе MM: 357 сообщений, 520 КБ): разбор слов занял
    основную часть времени — 131 672 вызова морфологии за один запрос, около 80% времени
    обработки. Ключ кэша — отпечаток слова, поэтому значения текста в памяти не задерживаются.
    """
    digest = hashlib.sha1(word.encode("utf-8", "replace")).hexdigest()
    with _TAG_CACHE_LOCK:
        cached = _TAG_CACHE.get(digest)
        if cached is not None:
            _TAG_CACHE.move_to_end(digest)
            _TAG_CACHE_STATS["hits"] += 1
            return cached
    try:
        parsed = morph.parse(word)
    except Exception:  # noqa: BLE001 - backend quirks must not propagate
        parsed = ()
    tags: tuple[str, ...] = ()
    if parsed:
        tags = tuple(str(getattr(parsed[0].tag, "grammemes", ())).split(","))
    with _TAG_CACHE_LOCK:
        _TAG_CACHE[digest] = tags
        if len(_TAG_CACHE) > _TAG_CACHE_LIMIT:
            _TAG_CACHE.popitem(last=False)
        _TAG_CACHE_STATS["misses"] += 1
    return tags


def _looks_like_name_token(tag_names: tuple[str, ...]) -> bool:
    """Return True when any grammeme marks the token as part of a person name."""
    joined = " ".join(tag_names)
    return any(tag in joined for tag in NAME_TAGS)
# END_BLOCK_LAZY_LOAD_MODEL
