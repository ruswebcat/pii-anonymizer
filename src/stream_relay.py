# FILE: src/stream_relay.py
# VERSION: 1.2.0
# START_MODULE_CONTRACT
#   PURPOSE: Turn the provider's SSE stream into the client's SSE stream, restoring values only on a trusted channel and never letting a value of a client leave.
#   SCOPE: SSE frame splitting across chunk boundaries, confirmed-position criterion for the cut (no continuation can still form a code), hard hold limit, delta text detokenization with the hold buffer, tool-call argument accumulation restored before the finish frame, keep-alive and comment frames passed through, fail-closed on a broken stream or store failure.
#   DEPENDS: M-UPSTREAM, M-DETOKENIZER, M-TOKEN-GEN, M-AUDIT, M-CONFIG
#   LINKS: M-STREAM-RELAY, V-M-STREAM-RELAY, fn-iter_frames, fn-confirmed_position, class-StreamRelay
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   DONE_FRAME - the terminal SSE frame "data: [DONE]"
#   ERROR_FRAME - the frame that closes a broken stream
#   MAX_HOLD_CHARS - жёсткий предел удержания буфера потока
#   StreamRelayError - stream failure with a stable code
#   fn-iter_frames - split raw chunks into SSE frames
#   fn-confirmed_position - подтверждённая позиция разреза: ни одно продолжение не даст код
#   class-StreamRelay - frame-in, frame-out relay with restoration
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.2.1 - дефект-фикс 19.09.2026: служебный кадр потока (`usage`) отдаётся не только клиенту, но и счётчику кэша провайдера — иначе ключевой фактор приёмки (попадание в кэш DeepSeek) не виден на потоковом пути, которым ходят мессенджеры.
#   PREVIOUS: v1.2.0 - Phase-12 шаг 5: критерий подтверждённой позиции вместо эвристики по обрамлению, жёсткий предел удержания 128 знаков. Критерий и property-тест заимствованы у veilstream (Apache-2.0), предел удержания — у piighost (MIT).
# END_CHANGE_SUMMARY
#
# Компактный код (`z<class><8 base32>`) не имеет обрамления, поэтому старый разрез по
# обрамляющим скобкам мог разрубить его пополам: клиент получал недостроенный код вместо
# значения. Формальный критерий ниже отвечает на вопрос «можно ли отдать этот знак» по
# самой поверхности кода, а не по догадке (veilstream, Apache-2.0).

"""Streaming relay (M-STREAM-RELAY).

Implements M-STREAM-RELAY from docs/ARCHITECTURE.md and docs/ARCHITECTURE.md.

Границы восстановления те же, что в непотоковом пути (решение владельца): текст
восстанавливается только на доверенном канале (Mattermost, локальные файлы),
аргументы инструментов — всегда, потому что их исполняет агент, а не человек.

Инварианты модуля:
  1. ни одно значение клиента не уходит в модель и не появляется в исходящем
     потоке: релей разбирает уже обезличенный поток и восстанавливает ровно те
     идентификаторы, что были в запросе;
  2. разрез потока проходит только по подтверждённой позиции — там, где ни одно
     продолжение не может дать код (критерий `confirmed_position`, veilstream
     Apache-2.0), а удержание ограничено жёстким пределом MAX_HOLD_CHARS
     (piighost, MIT). Поэтому поток обязан дать ровно тот же текст, что
     непотоковый путь при любом разбиении на чанки;
  3. аргументы инструментов уходят клиенту **до** кадра с finish_reason, иначе
     агент исполнит инструмент с пустыми аргументами;
  4. сбой разбора, обрыв потока, ошибка справочника → поток клиенту закрывается
     событием ошибки и записью stream_error: частично обработанный ответ наружу
     не выпускается.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Collection, Iterable, Iterator

from src.audit import BLOCK_REASONS, AuditEvent, AuditJournal
from src.detokenizer import DetokenizeError, PayloadDetokenizer, StreamDetokenizer
from src.token_factory import token_prefix_length

LOGGER_NAME = "StreamRelay"
LOG_MARKER = "[StreamRelay][relay_stream][BLOCK_RELAY_STREAM]"

#: Жёсткий предел удержания (piighost, MIT): буфер потока не растёт бесконечно, даже если
#: провайдер пришлёт длинную последовательность, похожую на начало кода. Сама поверхность кода
#: короче (MAX_SURFACE_CHARS = 26), поэтому в обычной работе предел не наступает.
MAX_HOLD_CHARS = 128

#: Коды сбоя потока → коды журнала. Журнал — закрытая схема: неизвестный код он отвергает
#: исключением, а исключение вместо кадра ошибки ломает fail-closed (найдено property-тестом
#: 18.09.2026: «DETOK_STORE_FAILED» и «STREAM_CONTEXT_LOST» в журнал не входили).
JOURNAL_REASON_MAP = {
    "DETOK_STORE_FAILED": "store_unavailable",
    "STREAM_CONTEXT_LOST": "stream_broken",
}
JOURNAL_DEFAULT_REASON = "stream_broken"

DONE_FRAME = b"data: [DONE]\n\n"
ERROR_FRAME = (
    b'data: {"error":{"code":"stream_broken",'
    b'"message":"\xd0\xbf\xd0\xbe\xd1\x82\xd0\xbe\xd0\xba \xd0\xbe\xd0\xb1\xd0\xbe\xd1\x80\xd0\xb2\xd0\xb0\xd0\xbd"}}\n\n'
)


class StreamRelayError(RuntimeError):
    """Stream failure with a stable code.

    # START_CONTRACT: StreamRelayError
    #   PURPOSE: Give the router a stable classification for a failed stream.
    #   INPUTS: { code: str - stable code, message: str - detail }
    #   OUTPUTS: { StreamRelayError - exception instance }
    #   SIDE_EFFECTS: none
    #   LINKS: M-STREAM-RELAY, M-ROUTER, V-M-STREAM-RELAY
    # END_CONTRACT: StreamRelayError
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# START_BLOCK_ITER_FRAMES
def iter_frames(chunks: Iterable[bytes]) -> Iterator[bytes]:
    """Yield complete SSE frames from arbitrarily split chunks.

    # START_CONTRACT: iter_frames
    #   PURPOSE: Hide chunk boundaries so a frame (and therefore a code) is never cut.
    #   INPUTS: { chunks: Iterable[bytes] - raw bytes from the provider }
    #   OUTPUTS: { Iterator[bytes] - one complete frame per item, terminator included }
    #   SIDE_EFFECTS: none
    #   LINKS: M-STREAM-RELAY, V-M-STREAM-RELAY
    # END_CONTRACT: iter_frames
    """
    pending = b""
    for chunk in chunks:
        if not chunk:
            continue
        pending += chunk
        while True:
            # Кадр SSE заканчивается пустой строкой: \n\n либо \r\n\r\n.
            plain = pending.find(b"\n\n")
            crlf = pending.find(b"\r\n\r\n")
            if plain == -1 and crlf == -1:
                break
            if plain != -1 and (crlf == -1 or plain < crlf):
                yield pending[: plain + 2]
                pending = pending[plain + 2 :]
            else:
                yield pending[: crlf + 4]
                pending = pending[crlf + 4 :]
    if pending:
        # Хвост без терминатора отдаём как есть, иначе кадр потеряется молча.
        yield pending
# END_BLOCK_ITER_FRAMES


# START_BLOCK_CONFIRMED_POSITION
def confirmed_position(pending: str, limit: int = MAX_HOLD_CHARS) -> int:
    """Return the cut position: everything before it is confirmed, nothing can make it a code.

    # START_CONTRACT: confirmed_position
    #   PURPOSE: Отдавать клиенту только то, что никакое продолжение не превратит в код.
    #   INPUTS: { pending: str - буфер потока, limit: int - жёсткий предел удержания }
    #   OUTPUTS: { int - длина подтверждённого префикса буфера }
    #   SIDE_EFFECTS: none
    #   LINKS: M-STREAM-RELAY, M-TOKEN-GEN, M-DETOKENIZER, V-M-STREAM-RELAY
    # END_CONTRACT: confirmed_position

    Criteria, borrowed from veilstream (Apache-2.0): a position is confirmed when no
    continuation could still form a code there. Formally, the prefix ``pending[:cut]`` is
    confirmed when no suffix of it is the beginning of a code surface, and no code starts
    inside it and would end outside it. The rule for «beginning of a code» lives in
    M-TOKEN-GEN (``token_prefix_length``) beside ``find_tokens``, so the stream does not carry
    a second, drifting copy of the surfaces — and it deliberately ignores the look-behind of
    a code: a cut that «knows» the letter on the left makes it impossible for the next chunk
    to see that letter at all, and the chunk then parses differently from the buffered path
    (found by the property test, 18.09.2026).

    ``limit`` is the hard hold limit (piighost, MIT): the buffer never keeps more than that
    many characters, even if the text looks like an endless code prefix. In normal work the
    surface itself bounds the tail (26 characters), so the limit never binds — and if it ever
    does, the run degrades loudly rather than growing without bound.
    """
    tail = token_prefix_length(pending)
    if tail > limit:
        tail = limit
    return len(pending) - tail
# END_BLOCK_CONFIRMED_POSITION


# START_BLOCK_RELAY_STREAM
class StreamRelay:
    """Relay provider frames to the client, restoring values on trusted channels.

    # START_CONTRACT: StreamRelay
    #   PURPOSE: Rebuild an SSE stream for the client without leaking a value of a client.
    #   INPUTS: { detokenizer: PayloadDetokenizer, audit: AuditJournal, channel: str | None, session_id: str, allowed: Collection[str] | None }
    #   OUTPUTS: { StreamRelay - relay instance }
    #   SIDE_EFFECTS: reads the store through the detokenizer, appends to the journal
    #   LINKS: M-DETOKENIZER, M-AUDIT, M-ROUTER, V-M-STREAM-RELAY
    # END_CONTRACT: StreamRelay
    """

    def __init__(
        self,
        detokenizer: PayloadDetokenizer,
        audit: AuditJournal,
        channel: str | None,
        session_id: str,
        allowed: Collection[str] | None = None,
        on_usage: Callable[[dict], None] | None = None,
    ) -> None:
        self._detokenizer = detokenizer
        self._audit = audit
        self._channel = channel
        self._session_id = session_id
        self._allowed = allowed
        # Служебный кадр `usage` уходит клиенту как есть, но он же — единственное место, где
        # на потоковом пути видно попадание в кэш провайдера. Без этого вызова ключевой
        # фактор приёмки (кэш DeepSeek) не измеряется на каналах-мессенджерах, которые ходят
        # потоком (живой разбор 19.09.2026: в healthz три запроса и ни одного попадания).
        self._on_usage = on_usage
        # Буфер удержания живёт в M-DETOKENIZER, критерий разреза — здесь: вызывающий
        # передаёт его явно, чтобы правило подтверждённой позиции было одно на проект.
        self._text = StreamDetokenizer(
            detokenizer,
            channel,
            session_id,
            allowed,
            hold=MAX_HOLD_CHARS,
            boundary=confirmed_position,
        )
        self._tool_args: dict[int, str] = {}
        self._tool_names: dict[int, str] = {}
        self._restored = 0
        self._broken = False

    @property
    def restored(self) -> int:
        """Return how many values were restored on the way out."""
        return self._restored

    def relay(self, chunks: Iterable[bytes]) -> Iterator[bytes]:
        """Yield client frames for provider frames.

        # START_CONTRACT: relay
        #   PURPOSE: Single entry point used by the router for the streaming path.
        #   INPUTS: { chunks: Iterable[bytes] - provider stream }
        #   OUTPUTS: { Iterator[bytes] - client stream, error frame on failure }
        #   SIDE_EFFECTS: journal writes, store reads
        #   LINKS: M-UPSTREAM, M-STREAM-RELAY, V-M-STREAM-RELAY
        # END_CONTRACT: relay
        """
        failure: Exception | None = None
        try:
            for frame in iter_frames(chunks):
                yield from self._relay_frame(frame)
            # Провайдер может закрыть поток без [DONE]: тогда хвост и аргументы
            # инструментов досылаем сами, иначе ответ придёт обрезанным.
            yield from self._flush_tools()
            tail = self._text.flush()
            if tail:
                yield self._frame_from_delta({"role": "assistant", "content": tail})
        except (DetokenizeError, StreamRelayError) as exc:
            self._broken = True
            failure = exc
            self._record_failure(getattr(exc, "code", "stream_broken"))
            yield ERROR_FRAME
            yield DONE_FRAME
        finally:
            self._audit.append(
                AuditEvent(
                    session_id=self._session_id,
                    action="stream_error" if self._broken else "stream_closed",
                    direction="outbound",
                    cls="-",
                    count=self._restored,
                    channel=str(self._channel or ""),
                    reason="",
                )
            )
        if failure is not None:
            # Поток закрыт событием ошибки: исключение наружу не пробрасываем,
            # иначе обработчик попытается отправить второй ответ.
            return

    def _relay_frame(self, frame: bytes) -> Iterator[bytes]:
        """Pass one frame through, restoring text and tool-call arguments."""
        text = frame.decode("utf-8", errors="replace")
        stripped = text.strip()
        if not stripped.startswith("data:"):
            # Комментарии и keep-alive проходят без изменений.
            yield frame
            return
        payload_text = stripped[len("data:") :].strip()
        if payload_text == "[DONE]":
            yield from self._flush_tools()
            tail = self._text.flush()
            if tail:
                yield self._frame_from_delta({"role": "assistant", "content": tail})
            yield DONE_FRAME
            return
        try:
            event = json.loads(payload_text)
        except ValueError:
            # Неразобранный кадр не выпускаем: пропустить — потерять часть ответа,
            # отдать как есть — потерять контроль над восстановлением.
            raise StreamRelayError("stream_broken", "кадр потока не разобран") from None
        if not isinstance(event, dict):
            raise StreamRelayError("stream_broken", "событие потока не объект")
        yield from self._rewrite(event)

    def _rewrite(self, event: dict) -> Iterator[bytes]:
        """Restore one parsed event and re-serialize it."""
        usage = event.get("usage")
        if isinstance(usage, dict) and self._on_usage is not None:
            # Метрика кэша провайдера считается тем же кодом, что и на непотоковом пути:
            # событие отдаётся счётчику, клиенту кадр уходит без изменений.
            self._on_usage(event)
        choices = event.get("choices")
        if not isinstance(choices, list) or not choices:
            # Кадры со служебной информацией (например, usage) отдаём как есть.
            yield self._frame(event)
            return
        finishing = False
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta") or choice.get("message")
            if isinstance(delta, dict):
                self._restore_text(delta)
                self._accumulate_tools(delta)
            if choice.get("finish_reason"):
                finishing = True
        if finishing:
            # Аргументы инструментов должны дойти до кадра завершения.
            yield from self._flush_tools()
        yield self._frame(event)

    def _restore_text(self, delta: dict) -> None:
        """Restore values in the text parts of a delta."""
        for field in ("content", "reasoning_content"):
            value = delta.get(field)
            if not isinstance(value, str) or not value:
                continue
            restored = self._text.feed(value)
            # Пустое значение оставляем пустым: восстановленный текст уходит
            # отдельным кадром, когда перестанет быть половиной кода.
            delta[field] = restored or ""

    def _accumulate_tools(self, delta: dict) -> None:
        """Accumulate tool-call argument fragments.

        Аргументы приходят частями и исполняются агентом, а не человеком, поэтому
        восстанавливаются всегда — независимо от канала. Копим до конца: половина
        аргумента к исполнению не годится, а код может быть разрезан между частями.
        """
        calls = delta.get("tool_calls")
        if not isinstance(calls, list):
            return
        for call in calls:
            if not isinstance(call, dict):
                continue
            function = call.get("function")
            if not isinstance(function, dict):
                continue
            index = call.get("index")
            if not isinstance(index, int):
                index = 0
            name = function.get("name")
            if isinstance(name, str) and name:
                self._tool_names[index] = name
            arguments = function.get("arguments")
            if isinstance(arguments, str):
                if arguments:
                    self._tool_args[index] = self._tool_args.get(index, "") + arguments
                # Фрагмент клиенту не отдаём: восстановленные аргументы уйдут
                # одним кадром до кадра завершения.
                function["arguments"] = ""

    def _flush_tools(self) -> Iterator[bytes]:
        """Yield one frame per tool call with its arguments restored."""
        if not self._tool_args:
            return
        for index in sorted(self._tool_args):
            wrapper = {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {"function": {"arguments": self._tool_args[index]}}
                            ]
                        }
                    }
                ]
            }
            restored_payload, stats = self._detokenizer.detokenize_tool_args(
                wrapper, self._session_id, self._allowed
            )
            restored = (
                restored_payload["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
            )
            self._restored += sum(int(value) for value in stats.values())
            call = {
                "index": index,
                "type": "function",
                "function": {"name": self._tool_names.get(index, ""), "arguments": restored},
            }
            event = {"choices": [{"index": 0, "delta": {"tool_calls": [call]}}]}
            yield self._frame(event)
        self._tool_args.clear()
        self._tool_names.clear()

    @staticmethod
    def _frame(event: dict) -> bytes:
        """Serialize one event as an SSE frame."""
        return b"data: " + json.dumps(event, ensure_ascii=False).encode("utf-8") + b"\n\n"

    def _frame_from_delta(self, delta: dict) -> bytes:
        """Build one SSE frame from a plain delta."""
        return self._frame({"choices": [{"index": 0, "delta": delta}]})

    def _record_failure(self, reason: str) -> None:
        """Record a fail-closed stream failure (machine code only)."""
        self._audit.record_block(
            self._session_id,
            _journal_reason(reason),
            channel=str(self._channel or ""),
            cls="-",
        )
# END_BLOCK_RELAY_STREAM


def _journal_reason(code: str) -> str:
    """Перевести код сбоя в код журнала: схема журнала закрытая, чужих строк он не принимает."""
    mapped = JOURNAL_REASON_MAP.get(code, code)
    return mapped if mapped in BLOCK_REASONS else JOURNAL_DEFAULT_REASON
