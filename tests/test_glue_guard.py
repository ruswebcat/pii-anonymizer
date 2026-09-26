# FILE: tests/test_glue_guard.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Verify the trusted-boundary gate of Phase-17: adjacent name values are restored only when the source confirms the pair or triple, so a glued «given name of one person + surname of another» never reaches the reader (the fabricated person of 20.09.2026), in the buffered path, in tool arguments and in the stream.
#   SCOPE: enforced refusals of glued pairs and triples, legitimate restorations, adjacency rule, non-name neighbours, audit mode, incident content, stream parity across chunk boundaries, off mode.
#   DEPENDS: M-DETOKENIZER, M-NAME-COHERENCE, M-INCIDENT-JOURNAL, M-MAP-STORE
#   LINKS: V-M-DETOKENIZER, V-M-NAME-COHERENCE, V-M-STREAM-RELAY
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   GlueGuardTests - заслон связности персоны: пара, тройка, поток, режимы
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - Phase-17 (20.09.2026): регрессия на выдуманную персону — склейка имени одного человека с фамилией другого не восстанавливается, а законное ФИО восстанавливается.
# END_CHANGE_SUMMARY

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.audit import AuditJournal  # noqa: E402
from src.channel_policy import ChannelPolicy  # noqa: E402
from src.detokenizer import PayloadDetokenizer, StreamDetokenizer  # noqa: E402
from src.incident_journal import IncidentJournal  # noqa: E402
from src.map_store import TokenMapStore  # noqa: E402
from src.name_coherence import MODE_AUDIT, MODE_ENFORCE, MODE_OFF, NameCoherence, build_combos  # noqa: E402
from src.stream_relay import confirmed_position  # noqa: E402
from src.token_factory import canonical_token, find_tokens, make_token  # noqa: E402

TOKEN_KEY = b"glue-guard-token-key-32-bytes!!"
DICT_KEY = b"glue-guard-dict-key-32-bytes!!!"
#: Синтетические персоны: значения выдуманы, настоящих клиентов в тестах нет.
PERSONS = (
    ("Иванов", "Иван", "Иванович"),
    ("Печёнов", "Сергей", "Сергеевич"),
)


class GlueGuardTests(unittest.TestCase):
    """Связность персоны: подтверждённое сочетание показывается, склейка — нет."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TokenMapStore(os.path.join(self.tmp.name, "pii_map.db"), fernet_key=b"f" * 32)
        self.codes: dict[str, str] = {}
        for parts in PERSONS:
            for part in parts:
                code = make_token("P", part, TOKEN_KEY)
                self.codes[part] = code
                self.store.store(code, "P", part, "pd:" + part.lower())
        digests, _ = build_combos(PERSONS, DICT_KEY)
        self.index = NameCoherence(digests=frozenset(digests), meta={"source": "test"})
        self.incidents = IncidentJournal(os.path.join(self.tmp.name, "incidents"))
        self.audit = AuditJournal(os.path.join(self.tmp.name, "audit.jsonl"))

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def _detokenizer(self, mode: str = MODE_ENFORCE) -> PayloadDetokenizer:
        return PayloadDetokenizer(
            self.store,
            ChannelPolicy({"local"}),
            self.audit,
            coherence=self.index,
            coherence_key=DICT_KEY,
            coherence_mode=mode,
            incident=self.incidents,
        )

    def _restore(self, text: str, detokenizer: PayloadDetokenizer) -> tuple[str, dict]:
        codes = {canonical_token(span[3]) for span in find_tokens(text)}
        return detokenizer.detokenize_text(text, "local", "s-glue", codes)

    def _incidents(self) -> list[dict]:
        records = self.incidents.read_week("current") or self.incidents.read_week("previous")
        return records

    # --- 1. законные сочетания --------------------------------------------
    def test_confirmed_pair_is_restored(self) -> None:
        text = f"Анкета: {self.codes['Иванов']} {self.codes['Иван']}"
        restored, counters = self._restore(text, self._detokenizer())
        self.assertIn("Иванов", restored)
        self.assertIn("Иван", restored)
        self.assertEqual(counters["glued"], 0)
        self.assertEqual(self._detokenizer().counters()["coherence_checked"], 0)

    def test_confirmed_triple_is_restored(self) -> None:
        text = " ".join(
            [self.codes["Печёнов"], self.codes["Сергей"], self.codes["Сергеевич"]]
        )
        restored, counters = self._restore(text, self._detokenizer())
        self.assertIn("Печёнов", restored)
        self.assertIn("Сергеевич", restored)
        self.assertEqual(counters["glued"], 0)

    def test_lone_value_is_restored_without_a_neighbour(self) -> None:
        restored, counters = self._restore(f"Клиент: {self.codes['Иванов']}", self._detokenizer())
        self.assertIn("Иванов", restored)
        self.assertEqual(counters["glued"], 0)

    # --- 2. склейка: выдуманная персона -----------------------------------
    def test_glued_pair_is_not_restored_and_is_recorded(self) -> None:
        # Ровно форма инцидента 20.09.2026: имя одной персоны плюс фамилия другой.
        text = f"Анкета 684: {self.codes['Иван']} {self.codes['Печёнов']}"
        detokenizer = self._detokenizer()
        restored, counters = self._restore(text, detokenizer)
        self.assertNotIn("Иван", restored)
        self.assertNotIn("Печёнов", restored)
        self.assertIn(canonical_token(self.codes["Иван"]), restored)
        self.assertEqual(counters["glued"], 2)
        self.assertEqual(detokenizer.counters()["coherence_blocked"], 1)
        records = self._incidents()
        self.assertTrue(records)
        self.assertEqual(records[-1]["action"], "name_glue")
        self.assertEqual(records[-1]["class"], "P")
        rendered = json.dumps(records, ensure_ascii=False)
        for value in ("Иван", "Печёнов"):
            self.assertNotIn(value, rendered)

    def test_confirmed_pair_inside_a_longer_text_still_restores(self) -> None:
        text = (
            f"Отчёт: {self.codes['Иванов']} {self.codes['Иван']} закрыт, "
            f"а {self.codes['Печёнов']} {self.codes['Сергей']} открыт"
        )
        restored, counters = self._restore(text, self._detokenizer())
        self.assertIn("Иванов", restored)
        self.assertIn("Сергей", restored)
        self.assertEqual(counters["glued"], 0)

    def test_glued_triple_is_refused_as_a_whole(self) -> None:
        text = " ".join(
            [self.codes["Иванов"], self.codes["Иван"], self.codes["Сергеевич"]]
        )
        restored, counters = self._restore(text, self._detokenizer())
        self.assertNotIn("Иванович", restored)
        self.assertNotIn("Сергеевич", restored)
        self.assertEqual(counters["glued"], 3)

    def test_values_separated_by_a_pause_are_not_neighbours(self) -> None:
        # Разделитель «, » означает, что это не части одного ФИО: заслон их не трогает.
        text = f"{self.codes['Иван']}, {self.codes['Печёнов']}"
        restored, counters = self._restore(text, self._detokenizer())
        self.assertIn("Иван", restored)
        self.assertIn("Печёнов", restored)
        self.assertEqual(counters["glued"], 0)

    def test_phone_next_to_a_name_is_untouched(self) -> None:
        phone_code = make_token("T", "79000000001", TOKEN_KEY)
        self.store.store(phone_code, "T", "79000000001", "")
        text = f"{self.codes['Иван']} {phone_code}"
        restored, counters = self._restore(text, self._detokenizer())
        self.assertIn("Иван", restored)
        self.assertIn("79000000001", restored)
        self.assertEqual(counters["glued"], 0)

    # --- 3. режимы --------------------------------------------------------
    def test_audit_mode_counts_without_blocking(self) -> None:
        text = f"{self.codes['Иван']} {self.codes['Печёнов']}"
        detokenizer = self._detokenizer(MODE_AUDIT)
        restored, counters = self._restore(text, detokenizer)
        self.assertIn("Иван", restored)
        self.assertIn("Печёнов", restored)
        self.assertEqual(counters["glued"], 0)
        self.assertGreaterEqual(detokenizer.counters()["coherence_unchecked"], 1)

    def test_off_mode_does_not_check(self) -> None:
        text = f"{self.codes['Иван']} {self.codes['Печёнов']}"
        detokenizer = self._detokenizer(MODE_OFF)
        restored, _counters = self._restore(text, detokenizer)
        self.assertIn("Иван", restored)
        self.assertEqual(detokenizer.counters()["coherence_blocked"], 0)
        self.assertFalse(self._incidents())

    # --- 4. аргументы инструментов ----------------------------------------
    def test_glued_pair_in_tool_arguments_is_not_substituted(self) -> None:
        payload = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "search",
                                    "arguments": '{"fio": "%s %s"}'
                                    % (self.codes["Иван"], self.codes["Печёнов"]),
                                }
                            }
                        ]
                    }
                }
            ]
        }
        detokenizer = self._detokenizer()
        allowed = {
            canonical_token(self.codes["Иван"]),
            canonical_token(self.codes["Печёнов"]),
        }
        payload, counters = detokenizer.detokenize_tool_args(payload, "s-tool", allowed)
        arguments = payload["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
        self.assertNotIn("Иван", arguments)
        self.assertNotIn("Печёнов", arguments)
        self.assertGreaterEqual(counters.get("glued", 0), 1)

    # --- 5. поток: стык кусков не слепое пятно ----------------------------
    def _stream(self, detokenizer: PayloadDetokenizer, chunks: list[str]) -> str:
        stream = StreamDetokenizer(
            detokenizer,
            "local",
            "s-stream",
            allowed=None,
            boundary=lambda text, hold: confirmed_position(text, hold),
        )
        out = []
        for chunk in chunks:
            # список разрешённых кодов собирается по всему ответу, как у потока целиком
            stream._identifiers = None  # noqa: SLF001 - проверка самого удержания
            stream._identifiers = {  # noqa: SLF001
                canonical_token(span[3])
                for chunk_text in chunks
                for span in find_tokens(chunk_text)
            }
            out.append(stream.feed(chunk))
        out.append(stream.flush())
        return "".join(out)

    def test_stream_keeps_a_glued_pair_apart(self) -> None:
        glued = f"{self.codes['Иван']} {self.codes['Печёнов']}"
        detokenizer = self._detokenizer()
        # Пара разрезана по стыку кусков: значение и его сосед приходят разными кадрами.
        chunks = [self.codes["Иван"] + " ", self.codes["Печёнов"]]
        streamed = self._stream(detokenizer, chunks)
        self.assertNotIn("Иван", streamed)
        self.assertNotIn("Печёнов", streamed)
        self.assertIn(canonical_token(self.codes["Иван"]), streamed)

    def test_stream_restores_a_confirmed_pair(self) -> None:
        detokenizer = self._detokenizer()
        chunks = [self.codes["Иванов"] + " ", self.codes["Иван"]]
        streamed = self._stream(detokenizer, chunks)
        self.assertIn("Иванов", streamed)
        self.assertIn("Иван", streamed)


if __name__ == "__main__":
    unittest.main()
