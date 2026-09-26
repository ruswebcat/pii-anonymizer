# FILE: tools/ner_trainer.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Использовать NER-модель как офлайн-тренера словаря: найти подтверждённые значения, которых нет в открытом слое, собрать их в список добавки и отдельно оформить то, что требует решения человека.
#   SCOPE: чтение корпуса, инференс ONNX-модели (int8) через onnxruntime+tokenizers, разбор BIO-разметки, кандидаты классов «человек» и «адрес», подтверждение вторым источником (морфология, исходные списки), список добавки, файл-предложение без ПД.
#   DEPENDS: M-NAME-LAYER, M-DETECT-NAME, M-NAME-FORMS
#   LINKS: M-NER-TRAINER, V-M-NER-TRAINER, Phase-13, M-NAME-LAYER
#   ROLE: SCRIPT
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   MODEL_DIR - каталог скачанной модели (model_int8.onnx + tokenizer.json)
#   PERSON_LABEL - метка персоны в разметке модели
#   ADDRESS_LABEL - метка места (адрес)
#   Candidate - найденное значение: текст, метка, число вхождений
#   fn-load_ner - загрузить модель; None, если её нет (модуль остаётся необязательным)
#   fn-label_spans - разметка отрезков текста по меткам модели
#   fn-merge_pieces - склейка подтокенов одного слова в одно значение
#   fn-run_corpus - прогон корпуса: находки по видам
#   fn-confirm - подтвердить значение вторым источником
#   fn-build_additions - подтверждённые значения и то, что требует решения человека
#   fn-render_proposal - файл-предложение для владельца: без значений клиентов
#   fn-main - точка входа CLI
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-13: NER как офлайн-тренер словаря (решение владельца 19.09.2026: модель уже скачана, ничего не устанавливается). Находки попадают в открытый слой только после подтверждения вторым источником; неподтверждённое уходит файлом-предложением.
# END_CHANGE_SUMMARY

"""NER как офлайн-тренер словаря (M-NER-TRAINER).

Идея: модель NER видит имена там, где наши списки молчат (редкие и нерусские фамилии), но её
слово не может быть последним — модель ошибается на обычной речи. Поэтому находка модели
становится **кандидатом**, кандидат подтверждается **вторым источником** (морфология называет
слово именем или оно есть в исходных открытых списках), и только подтверждённое попадает в
открытый слой штатным сборщиком (``tools/build_name_layer.py --source``). Всё, что подтвердить
не удалось, уходит владельцу файлом-предложением без персональных данных.

Модель необязательна: нет каталога — нет находок, и это не ошибка (как у NER в рантайме).
Значений клиентов этот инструмент не читает: корпус — открытые списки, адреса клубов и
синтетические строки.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # pragma: no cover - script bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from src.detect_name import FEATURE_MORPHOLOGY, name_features  # noqa: E402
from src.name_forms import normalize_name  # noqa: E402

MODEL_DIR = "/tmp/ner-test"
#: Модель размечена подробно (U/L/B/I-{FIRST_NAME,LAST_NAME,MIDDLE_NAME,STREET,…}) и выдаёт
#: префикс U у каждого подтокена, поэтому вид берётся из второй половины метки, а отрезки
#: склеиваются по смежности: подтокены одного слова идут встык, слова разделены пробелом.
PERSON_TYPES = ("LAST_NAME", "FIRST_NAME", "MIDDLE_NAME")
ADDRESS_TYPES = ("STREET", "HOUSE", "CITY", "REGION", "DISTRICT", "COUNTRY")
PERSON_LABEL = ",".join(PERSON_TYPES)
ADDRESS_LABEL = ",".join(ADDRESS_TYPES)
MAX_LENGTH = 512

LOGGER_NAME = "NerTrainer"


@dataclass(frozen=True)
class Candidate:
    """Найденное моделью значение.

    # START_CONTRACT: Candidate
    #   PURPOSE: Держать находку и её подтверждение рядом, чтобы решение было видно построчно.
    #   INPUTS: { text: str - значение, label: str - метка модели, count: int - число вхождений, sources: tuple[str, ...] - чем подтверждено }
    #   OUTPUTS: { Candidate - находка }
    #   SIDE_EFFECTS: none
    #   LINKS: M-NER-TRAINER, V-M-NER-TRAINER
    # END_CONTRACT: Candidate
    """

    text: str
    label: str
    count: int = 1
    sources: tuple[str, ...] = field(default_factory=tuple)


def load_ner(model_dir: str = MODEL_DIR) -> Callable[[Sequence[str]], list[list[tuple[int, int, str]]]] | None:
    """Загрузить ONNX-модель и вернуть функцию разметки, или None.

    # START_CONTRACT: load_ner
    #   PURPOSE: Сделать модель необязательной: её отсутствие не должно ломать инструмент.
    #   INPUTS: { model_dir: str - каталог с model_int8.onnx и tokenizer.json }
    #   OUTPUTS: { Callable | None - разметка списка текстов }
    #   SIDE_EFFECTS: читает файлы модели, занимает память под сессию onnxruntime
    #   LINKS: M-NER-TRAINER, V-M-NER-TRAINER
    # END_CONTRACT: load_ner

    Пик памяти int8-модели — около 385 МБ (замер 19.09.2026), медиана 19–26 мс на строку.
    Ничего не устанавливается: onnxruntime и tokenizers уже есть в окружении, модель скачана.
    """
    directory = Path(model_dir or "")
    model_file = directory / "model_int8.onnx"
    tokenizer_file = directory / "tokenizer.json"
    if not model_file.is_file() or not tokenizer_file.is_file():
        return None
    try:
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer
    except ImportError:  # pragma: no cover - окружение без модели
        return None

    options = ort.SessionOptions()
    options.intra_op_num_threads = 2
    session = ort.InferenceSession(str(model_file), sess_options=options, providers=["CPUExecutionProvider"])
    tokenizer = Tokenizer.from_file(str(tokenizer_file))
    tokenizer.enable_truncation(max_length=MAX_LENGTH)
    inputs = {item.name for item in session.get_inputs()}
    labels = _read_labels(directory)

    def annotate(texts: Sequence[str]) -> list[list[tuple[int, int, str]]]:
        return [
            label_spans(text, tokenizer, session, inputs, labels, np)
            for text in texts
        ]

    return annotate


def _read_labels(directory: Path) -> list[str]:
    """Прочитать список меток модели из config.json (id2label), иначе — стандартный порядок BIO."""
    try:
        payload = json.loads((directory / "config.json").read_text(encoding="utf-8"))
        mapping = payload.get("id2label") or {}
        if mapping:
            return [str(mapping[key]) for key in sorted(mapping, key=lambda item: int(item))]
    except (OSError, ValueError):
        pass
    return ["O", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-LOC", "I-LOC", "B-MISC", "I-MISC"]


def label_spans(
    text: str,
    tokenizer: Any,
    session: Any,
    inputs: set[str],
    labels: Sequence[str],
    np: Any,
) -> list[tuple[int, int, str]]:
    """Вернуть отрезки текста с метками модели (BIO → диапазоны символов).

    # START_CONTRACT: label_spans
    #   PURPOSE: Превратить токенную разметку в отрезки исходного текста.
    #   INPUTS: { text: str, tokenizer/session/inputs/labels/np - окружение модели }
    #   OUTPUTS: { list[tuple[int, int, str]] - (начало, конец, метка без BIO-префикса) }
    #   SIDE_EFFECTS: выполняет инференс модели
    #   LINKS: M-NER-TRAINER, V-M-NER-TRAINER
    # END_CONTRACT: label_spans
    """
    encoding = tokenizer.encode(text)
    ids = encoding.ids
    if not ids:
        return []
    names = sorted(inputs)
    feed: dict[str, Any] = {}
    if "input_ids" in names:
        feed["input_ids"] = np.array([ids], dtype=np.int64)
    else:
        feed[names[0]] = np.array([ids], dtype=np.int64)
    if "attention_mask" in names:
        feed["attention_mask"] = np.array([encoding.attention_mask], dtype=np.int64)
    if "token_type_ids" in names:
        feed["token_type_ids"] = np.array([encoding.type_ids], dtype=np.int64)
    logits = session.run(None, feed)[0][0]
    predicted = [int(max(range(len(row)), key=lambda index: row[index])) for row in logits]

    spans: list[list[int | str]] = []
    for prediction, offsets in zip(predicted, encoding.offsets):
        name = labels[prediction] if prediction < len(labels) else "O"
        _prefix, _, entity = name.partition("-")
        start, end = offsets
        if not entity or end <= start:
            continue
        spans.append([start, end, entity])
    return merge_pieces([(int(s), int(e), str(t)) for s, e, t in spans])


def merge_pieces(pieces: Sequence[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """Склеить подтокены одного слова в одно значение.

    # START_CONTRACT: merge_pieces
    #   PURPOSE: Модель размечает слово по подтокенам и чередует внутри него виды — значение должно получиться целым.
    #   INPUTS: { pieces: Sequence[tuple[int, int, str]] - куски разметки по порядку }
    #   OUTPUTS: { list[tuple[int, int, str]] - значения: (начало, конец, вид) }
    #   SIDE_EFFECTS: none
    #   LINKS: M-NER-TRAINER, V-M-NER-TRAINER
    # END_CONTRACT: merge_pieces

    Смежность — единственный признак границы: подтокены одного слова идут встык, а разные
    слова разделены пробелом. Без склейки «Заглушкин» распадался на «уз», «ева», «нов», а
    «Абрамян» — на «бра» и «мян», и такие обрывки морфология подтверждала как фамилии.
    """
    merged: list[list[int | str]] = []
    for start, end, entity in pieces:
        if end <= start or not entity:
            continue
        if merged and merged[-1][1] == start:
            merged[-1][1] = end
        else:
            merged.append([start, end, entity])
    return [(int(item[0]), int(item[1]), str(item[2])) for item in merged]


def run_corpus(
    texts: Iterable[str],
    annotate: Callable[[Sequence[str]], list[list[tuple[int, int, str]]]],
    batch_size: int = 16,
) -> dict[str, Counter]:
    """Прогнать корпус и собрать находки по меткам.

    # START_CONTRACT: run_corpus
    #   PURPOSE: Один проход по корпусу вместо ручных вызовов модели на каждой строке.
    #   INPUTS: { texts: Iterable[str], annotate: Callable - разметка, batch_size: int }
    #   OUTPUTS: { dict[str, Counter] - метка → счётчик значений }
    #   SIDE_EFFECTS: выполняет инференс; печатает прогресс в stderr
    #   LINKS: M-NER-TRAINER, V-M-NER-TRAINER
    # END_CONTRACT: run_corpus
    """
    found: dict[str, Counter] = {}
    batch: list[str] = []
    total = 0
    started = time.perf_counter()
    for text in texts:
        batch.append(text)
        if len(batch) < batch_size:
            continue
        total += _consume(batch, annotate, found)
        batch = []
        if total and total % 320 < batch_size:
            print(f"  … строк {total}, {time.perf_counter() - started:.0f} с", file=sys.stderr)
    if batch:
        total += _consume(batch, annotate, found)
    print(f"корпус: {total} строк за {time.perf_counter() - started:.0f} с", file=sys.stderr)
    return found


def _consume(
    batch: Sequence[str],
    annotate: Callable[[Sequence[str]], list[list[tuple[int, int, str]]]],
    found: dict[str, Counter],
) -> int:
    """Разметить пачку строк и добавить значения в счётчики."""
    for text, spans in zip(batch, annotate(list(batch))):
        for start, end, label in spans:
            value = text[start:end].strip(" \t\n,.:;()«»\"'")
            if len(value) < 3:
                continue
            found.setdefault(label, Counter())[value] += 1
    return len(batch)


def confirm(value: str, known: Collection[str] | None = None) -> tuple[str, ...]:
    """Подтвердить значение вторым источником и вернуть список подтверждений.

    # START_CONTRACT: confirm
    #   PURPOSE: Не пускать в словарь ни одного значения на одном слове модели.
    #   INPUTS: { value: str - найденное значение, known: Collection[str] | None - исходные открытые списки }
    #   OUTPUTS: { tuple[str, ...] - подтверждения: имя по морфологии, значение есть в списке }
    #   SIDE_EFFECTS: лениво строит морфологический анализатор
    #   LINKS: M-DETECT-NAME, M-NER-TRAINER, V-M-NER-TRAINER
    # END_CONTRACT: confirm

    Морфология — независимый источник: pymorphy3 ничего не знает о модели NER и о наших
    списках. Значение, которое анализатор читает как фамилию, имя или отчество, подтверждено
    дважды. Пустые подтверждения означают «решение за человеком».
    """
    reasons: list[str] = []
    if FEATURE_MORPHOLOGY in name_features(value):
        reasons.append("морфология: тег имени")
    if known:
        key = normalize_name(value)
        if key and key in known:
            reasons.append("есть в исходном списке")
    return tuple(reasons)


def build_additions(
    found: Mapping[str, Counter],
    known: Mapping[str, Any] | None = None,
    layer: Any | None = None,
    labels: Sequence[str] = PERSON_TYPES,
    minimum: int = 1,
) -> tuple[list[Candidate], list[Candidate]]:
    """Разделить находки на подтверждённые и требующие решения человека.

    # START_CONTRACT: build_additions
    #   PURPOSE: Отдать сборщику словаря только подтверждённое, а спорное — владельцу.
    #   INPUTS: { found: Mapping[str, Counter], known: Mapping | None, layer: Any | None - открытый слой, labels: Sequence[str] - виды значений, minimum: int - минимум вхождений }
    #   OUTPUTS: { (confirmed, unconfirmed) - два списка кандидатов }
    #   SIDE_EFFECTS: читает открытый слой
    #   LINKS: M-NER-TRAINER, M-NAME-LAYER, V-M-NER-TRAINER
    # END_CONTRACT: build_additions

    Из находок выкидывается уже известное открытому слою: добавлять в словарь то, что там есть,
    нечего, и такой «прирост» только запутал бы замер состава.
    """
    confirmed: list[Candidate] = []
    unconfirmed: list[Candidate] = []
    for label in labels:
        for value, count in sorted((found.get(label) or Counter()).items()):
            if count < minimum:
                continue
            if layer is not None and _in_layer(value, layer):
                continue
            reasons = confirm(value, known)
            candidate = Candidate(text=value, label=label, count=count, sources=reasons)
            (confirmed if reasons else unconfirmed).append(candidate)
    return confirmed, unconfirmed


def _in_layer(value: str, layer: Any) -> bool:
    """Проверить написание в открытом слое, не ломая прогон битым слоем."""
    try:
        return bool(layer.contains(value, "P"))
    except Exception:  # noqa: BLE001 - битый слой не должен останавливать обучение словаря
        return False


def render_proposal(unconfirmed: Sequence[Candidate], corpus_note: str) -> str:
    """Оформить файл-предложение для владельца: находки без подтверждения, без ПД.

    # START_CONTRACT: render_proposal
    #   PURPOSE: Показать владельцу спорное честно и так, чтобы это можно было проверить.
    #   INPUTS: { unconfirmed: Sequence[Candidate], corpus_note: str - из какого корпуса находки }
    #   OUTPUTS: { str - markdown предложение }
    #   SIDE_EFFECTS: none
    #   LINKS: M-NER-TRAINER, V-M-NER-TRAINER
    # END_CONTRACT: render_proposal
    """
    lines = [
        "# Предложение по словарю: находки NER без подтверждения",
        "",
        f"Корпус: {corpus_note}.",
        "Значений клиентов в файле нет: находки получены на открытых списках, адресах клубов и",
        "синтетических строках. Каждая строка — то, что модель назвала именем, но второй источник",
        "(морфология pymorphy3, исходный открытый список) не подтвердил.",
        "",
        "| Значение | Метка | Вхождений | Почему требует решения |",
        "|---|---|---|---|",
    ]
    for candidate in sorted(unconfirmed, key=lambda item: (-item.count, item.text)):
        lines.append(
            f"| {candidate.text} | {candidate.label} | {candidate.count} | "
            "не читается морфологией как имя и нет в исходном списке |"
        )
    if not unconfirmed:
        lines.append("| — | — | — | спорных находок нет |")
    lines += [
        "",
        "## Что предлагается решить",
        "",
        "1. Добавлять ли такие значения в открытый слой как фамилии (риск: модель путает с",
        "   названиями организаций, клубов и улиц).",
        "2. Нужен ли третий источник подтверждения (например, частотный словарь русских фамилий",
        "   или ручная проверка владельцем).",
        "",
        "Пока решения нет, эти значения **не** попадают ни в слой, ни в словарь карточек.",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Прогнать корпус и собрать список добавки и файл-предложение.

    # START_CONTRACT: main
    #   PURPOSE: Сделать обучение словаря повторяемым прогоном, а не ручным разбором.
    #   INPUTS: { argv: list[str] | None }
    #   OUTPUTS: { int - код выхода }
    #   SIDE_EFFECTS: читает корпус и слой, пишет список добавки и предложение
    #   LINKS: M-NER-TRAINER, V-M-NER-TRAINER
    # END_CONTRACT: main
    """
    parser = argparse.ArgumentParser(description="NER как офлайн-тренер словаря")
    parser.add_argument("--corpus", required=True, help="файл корпуса: одна строка — один текст")
    parser.add_argument("--model-dir", default=MODEL_DIR)
    parser.add_argument("--layer", default="", help="путь к открытому слою (для отсева известного)")
    parser.add_argument("--out-additions", default="", help="куда записать подтверждённые значения")
    parser.add_argument("--out-proposal", default="", help="куда записать файл-предложение")
    parser.add_argument("--label", default=PERSON_LABEL, help="виды значений через запятую (LAST_NAME,FIRST_NAME,…)")
    parser.add_argument("--minimum", type=int, default=1)
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    texts = [line.strip() for line in Path(args.corpus).read_text(encoding="utf-8").splitlines() if line.strip()]
    annotate = load_ner(args.model_dir)
    if annotate is None:
        print("NER_MODEL_UNAVAILABLE: модель не найдена, прогон невозможен", file=sys.stderr)
        return 2
    if not texts:
        print("NER_EMPTY_CORPUS: корпус пуст", file=sys.stderr)
        return 2

    found = run_corpus(texts, annotate)
    layer = None
    if args.layer:
        from src.name_layer import load_name_layer

        layer = load_name_layer(args.layer)
    labels = [item.strip().upper() for item in args.label.split(",") if item.strip()]
    confirmed, unconfirmed = build_additions(
        found, layer=layer, labels=labels, minimum=args.minimum
    )
    for label, counter in sorted(found.items()):
        print(f"  находки {label}: {len(counter)} значений, {sum(counter.values())} вхождений")
    print(f"подтверждено: {len(confirmed)}, требует решения человека: {len(unconfirmed)}")
    if args.out_additions:
        Path(args.out_additions).write_text(
            "\n".join(sorted({candidate.text for candidate in confirmed})) + "\n", encoding="utf-8"
        )
        print(f"список добавки: {args.out_additions} ({len(confirmed)} значений)")
    if args.out_proposal:
        Path(args.out_proposal).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out_proposal).write_text(
            render_proposal(unconfirmed, f"{args.corpus}, {len(texts)} строк, модель {args.model_dir}"),
            encoding="utf-8",
        )
        print(f"предложение: {args.out_proposal}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
