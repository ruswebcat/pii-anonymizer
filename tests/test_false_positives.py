# FILE: tests/test_false_positives.py
# VERSION: 1.3.0
# START_MODULE_CONTRACT
#   PURPOSE: Guard against false positives — ordinary operational text (brand, city, business terms, prices, dates, paths, commands) must survive anonymization untouched, and a mixed sentence must lose exactly the personal value and nothing else.
#   SCOPE: false-positive corpus with an adversarial dictionary, expected-replacement counts, positive control.
#   DEPENDS: M-TOKENIZER, M-DETECT-NAME, M-DICT
#   LINKS: V-M-DETECT-NAME, V-M-TOKENIZER, M-TOKENIZER
#   ROLE: TEST
#   MAP_MODE: LOCALS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   FALSE_POSITIVE_CORPUS - ordinary text that must never be replaced
#   FalsePositiveTests - the suite itself
#   MixedTextTests - exactly-one-replacement checks and the positive control
#   OwnVocabularyNearDataTests - стоп-лист своей лексики, обычные слова и подтверждение фразы целиком
#   SystemPromptServiceWordsTests - служебные подписи промпта («ФИО», «Персональные») персоной не становятся, редкие фамилии остаются
#   AddressMarkerTests - адрес клуба при полном и сокращённом написании маркера
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.3.0 - класс SystemPromptServiceWordsTests. Блок системного промпта давал 322 ложные находки из 323 («Персональные» и «ФИО»), они уходили модели кодами и стоили секунд на каждом запросе; положительный контроль — редкие фамилии («Тесля», «Скрытница») и падеж «Камыша» остаются находками.
#   PREVIOUS: v1.2.0 - Phase-9 follow-up 19.09.2026: заслон открытого списка снимал стоп-лист своей лексики («Клиент» → класс P), фраза подтверждалась одним словом («ОПЛАТА ТОПОЛЬ»), маркер адреса знал только сокращения; добавлены классы OwnVocabularyNearDataTests и AddressMarkerTests.
#   PREVIOUS: v1.1.0 - Phase-9 follow-up 19.09.2026: заслон открытого списка снимал стоп-лист своей лексики («Клиент» → класс P), а фраза подтверждалась одним словом («ОПЛАТА ТОПОЛЬ»); добавлен класс OwnVocabularyNearDataTests.
#   PREVIOUS: v1.0.0 - Phase-4 follow-up: false positives became their own test class after «Для рекламы» turned into «zPXXXXXXX рекламы» on the live agent payload (16.09.2026).
# END_CHANGE_SUMMARY

"""False-positive suite.

Why this class exists: on 16.09.2026 the first live agent request was blocked and
the anonymized text came back mutilated — «Для рекламы» had become
«zPXXXXXXX рекламы» and «ПримерСпорт» had been split into a code plus a stray
fragment. The cause was not the tokenizer's logic but the dictionary: it contained
ordinary words («Для», «Карта», «Клиент», «Клуб», «Тренер», «Сайт», «Пример») and,
measured on 4 000 CRM records, 59.5% of its class-P values are not person
names at all. Checking *what must not change* is a different test than checking
what must change — hence this module.

The dictionary used here is deliberately adversarial: it holds the junk words that
were actually found, so the guards have to hold even then.
"""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.detect_name import NameDetector  # noqa: E402
from src.dict_export import to_keyed_digests  # noqa: E402
from src.dictionary import PiiDictionary  # noqa: E402
from src.map_store import TokenMapStore  # noqa: E402
from src.name_layer import NameLayer  # noqa: E402
from src.token_factory import find_tokens  # noqa: E402
from src.tokenizer import PayloadTokenizer  # noqa: E402

from tests.harness import use_demo_vocabulary  # noqa: E402

#: Своя лексика организации приходит из настроек, а не из кода: тест включает ту же
#: демонстрационную лексику, которую оператор заполняет в примере конфигурации.
use_demo_vocabulary()

KEY = b"false-positive-suite-key-32-bytes!!"

# Словарь, каким он был на самом деле: фамилии клиентов вперемешку с обычными словами
# и служебными записями, которые завели в CRM.
ADVERSARIAL_DICTIONARY = {
    "P": [
        "Для", "На", "Пример", "Спорт", "Примерск", "Квартальный", "Центральный", "Базовый",
        "Пример", "Клиент", "Карта", "Клуб", "Тренер", "Сайт", "Доступ", "Отчёт",
        "Задача", "Ответ", "Годовой", "CRM", "База", "Системы", "Admin", "Клиентов",
        "Общая", "Администратор", "Иванов Иван Иванович", "Иванов", "Сахнов Артём",
    ],
    "A": ["пр. Заводская 19А", "б-р Садовая 3а"],
}

# Текст не должен меняться вообще.
FALSE_POSITIVE_CORPUS: tuple[tuple[str, str], ...] = (
    ("бренд", "Пример Спорт — первый фитнес Примерск"),
    ("бренд без пробела", "папка _ПримерСпорт общие"),
    ("клубы", "клуб Квартальный, клуб Центральный, клуб Базовый, ТЦ Пример"),
    ("служебные слова", "Для рекламы, На неделю, Отчёт, Задача, Ответ"),
    ("бизнес-термины", "Клиент купил карту, клуб открыт, тренер вышел, сайт работает"),
    ("тариф", "тариф Годовой, оплата помесячно, фитнес-тест включён"),
    ("цены", "годовая карта стоит 28 000 рублей, месячная 5 900"),
    ("суммы и счётчики", "выручка 1 234 567 рублей за период, 150 494 значения в словаре"),
    ("длительности", "карта на 12 мес, продление на 6 мес, период 2 мес"),
    ("пути", "путь /opt/agent/config.yaml"),
    ("ссылки", "https://example.com и https://wifi.example.com"),
    ("команды", "команда hermes config set model.base_url"),
    ("ключи конфигурации", "ключи model.base_url, model.default, platform_hints"),
    ("версии", "версия 1.0.0, протокол HTTP/1.1, порт 8791"),
    ("адрес клуба", "клуб по адресу пр. Заводская 19А — это адрес клуба, не клиента"),
    ("служебные объекты CRM", "сущности CRM, База, Системы, Admin в выгрузке"),
)


class FalsePositiveTests(unittest.TestCase):
    """Обычный текст обязан остаться нетронутым."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = TokenMapStore(os.path.join(self._tmp.name, "fp.db"), fernet_key=b"f" * 32)
        self.tokenizer = PayloadTokenizer(
            KEY, self.store, NameDetector(ADVERSARIAL_DICTIONARY)
        )

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def _tokens_in(self, text: str) -> list[tuple[str, str]]:
        payload = {"messages": [{"role": "user", "content": text}]}
        anonymized, _stats = self.tokenizer.tokenize_payload(payload, "fp")
        serialized = json.dumps(anonymized, ensure_ascii=False)
        return [(span[2], span[3]) for span in find_tokens(serialized)]

    def test_ordinary_text_is_never_replaced(self) -> None:
        for label, text in FALSE_POSITIVE_CORPUS:
            with self.subTest(label=label):
                self.assertEqual(self._tokens_in(text), [], msg=f"ложное срабатывание: {text}")

    def test_camel_case_brand_is_not_split(self) -> None:
        for text in ("_ПримерСпорт общие", "ПримерСпорт", "Мой Пример Спорт"):
            with self.subTest(text=text):
                self.assertEqual(self._tokens_in(text), [], msg=text)


class MixedTextTests(unittest.TestCase):
    """В смешанном тексте заменяется только персональное значение."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = TokenMapStore(os.path.join(self._tmp.name, "mix.db"), fernet_key=b"f" * 32)
        self.tokenizer = PayloadTokenizer(
            KEY, self.store, NameDetector(ADVERSARIAL_DICTIONARY)
        )

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def _anonymize(self, text: str) -> str:
        payload = {"messages": [{"role": "user", "content": text}]}
        anonymized, _stats = self.tokenizer.tokenize_payload(payload, "mix")
        return anonymized["messages"][0]["content"]

    def test_only_the_person_is_replaced(self) -> None:
        text = "Клиент Иванов Иван Иванович купил карту Квартальный в Примерск, оплата 28 000"
        result = self._anonymize(text)
        self.assertNotIn("Иванов", result)
        for survivor in ("карту", "Квартальный", "Примерск", "28 000", "Клиент"):
            self.assertIn(survivor, result, msg=f"потерян обычный фрагмент: {survivor}")

    def test_positive_control_a_real_name_is_replaced(self) -> None:
        """Контроль: если обезличивание сломается, этот модуль обязан упасть."""
        result = self._anonymize("клиент Иванов Иван Иванович")
        self.assertNotIn("Иванов", result)
        self.assertTrue(find_tokens(result), msg="ФИО обязано быть заменено")

    def test_service_records_are_not_treated_as_people(self) -> None:
        text = "в выгрузке есть сущности CRM, База, Системы, Admin, Клиентов"
        result = self._anonymize(text)
        for survivor in ("CRM", "База", "Системы", "Admin", "Клиентов"):
            self.assertIn(survivor, result, msg=f"служебная запись заменена: {survivor}")

    def test_markdown_table_separator_is_not_a_value(self) -> None:
        """Находка 18.09.2026: `---` в колонке «ФИО» принимался за значение и блокировал запрос.

        Разделитель markdown-таблицы стоит в тех же колонках, что и данные. Токенизатор
        его не заменял (заменять нечего), а заслон видел «значение осталось в тексте» —
        и каждый запрос с таблицей в истории чата падал с 403.
        """
        text = (
            "| ФИО | Телефон |\n"
            "|---|---|\n"
            "| Иванов Иван Иванович | +79000000001 |\n"
        )
        result = self._anonymize(text)
        self.assertIn("---", result, msg="разделитель таблицы не должен заменяться")
        self.assertIn("|", result, msg="рамка таблицы не должна заменяться")
        # Положительный контроль: данные в той же таблице обязаны заменяться.
        self.assertNotIn("Иванов Иван Иванович", result, msg="ФИО в строке таблицы обязано быть заменено")

    def test_table_without_data_changes_nothing(self) -> None:
        text = "| ФИО | Телефон |\n|---|---|\n| | |\n"
        self.assertEqual(self._anonymize(text), text)


class OwnVocabularyNearDataTests(unittest.TestCase):
    """Стоп-лист своей лексики и граница слова действуют на всех ветвях детектора.

    Находка 19.09.2026 (боевой прибор, `false_replacements = 2`, контур настоящего открытого
    слоя): стоп-лист проверялся только в ветви клиентского словаря. Слово, подтверждённое
    ОТКРЫТЫМ списком, шло мимо проверки, и «Клиент» рядом с телефоном становился классом P.
    Второй случай того же корня: фраза подтверждалась ОДНИМ своим словом — «ОПЛАТА ТОПОЛЬ»
    попадала в класс P, потому что «тополь» есть в списке фамилий.

    Оба теста падали до правки: первый возвращал два класса P вместо одного, второй —
    одну замену вместо нуля.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = TokenMapStore(os.path.join(self._tmp.name, "ctx.db"), fernet_key=b"f" * 32)

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def _payload_text(self, detector: NameDetector, text: str) -> str:
        tokenizer = PayloadTokenizer(KEY, self.store, detector)
        payload = {"messages": [{"role": "user", "content": text}]}
        anonymized, _stats = tokenizer.tokenize_payload(payload, "ctx")
        return anonymized["messages"][0]["content"]

    def test_client_word_next_to_client_data_stays(self) -> None:
        """«Клиент» — наша лексика, и близость телефона этого не меняет.

        Слово подтверждено открытым списком («клиент» там лежит как фамилия) и стоит в
        клиентском контексте, но в класс P попадать не должно: замена съедала обычное слово
        анкеты и делала текст нечитаемым.
        """
        layer = NameLayer({"P": {"клиент", "иванов"}}, {"source": "test", "licence": "n/a"})
        # Клиентского словаря здесь достаточно одного значения: проверяем именно ветвь
        # открытого списка. В настоящей выгрузке «клиент» не лежит — она отбрасывает свою
        # лексику, — поэтому слово держится только слоем и клиентским контекстом.
        detector = NameDetector({"P": ["Иванов"]}, name_layer=layer)
        text = "Клиент Ивановой, телефон 79001112233"
        matches = detector.detect_names(text)
        detected = [text[span.start:span.end] for span in matches]
        self.assertNotIn("Клиент", detected, msg=f"служебное слово стало персоной: {detected}")
        self.assertTrue(matches, msg="положительный контроль: «Ивановой» обязана находиться")
        result = self._payload_text(detector, text)
        self.assertIn("Клиент", result, msg="обычное слово заменено вместе с данными")

    def test_uppercase_phrase_is_not_confirmed_by_a_common_word(self) -> None:
        """Обычное слово из открытого списка фразу не подтверждает.

        «ТОПОЛЬ» есть в списке фамилий (Тополь — настоящая фамилия), но морфология знает это
        слово как обычное неодушевлённое существительное, и «ОПЛАТА» рядом — не имя вовсе.
        Раньше одного такого подтверждения хватало, чтобы весь оборот стал классом P
        (19.09.2026, боевой прибор: ложная замена).
        """
        layer = NameLayer({"P": {"тополь"}}, {"source": "test", "licence": "n/a"})
        detector = NameDetector(name_layer=layer)
        text = "ОПЛАТА ТОПОЛЬ закрыт"
        self.assertEqual(detector.detect_names(text), [], msg="оборот принят за ФИО")
        self.assertEqual(self._payload_text(detector, text), text)

    def test_phrase_is_confirmed_by_a_rare_surname_from_the_open_list(self) -> None:
        """Положительный контроль: редкая фамилия фразу подтверждает, как и раньше.

        «Тесля» и «Скрытниц» словарю морфологии неизвестны вовсе — именно поэтому их держит
        открытый список. Правило «обычное слово фразу не подтверждает» не должно выбросить
        такие значения, иначе лечение ложной замены стало бы новой слепой зоной.
        """
        layer = NameLayer({"P": {"тесля", "скрытница"}}, {"source": "test", "licence": "n/a"})
        detector = NameDetector(name_layer=layer)
        self.assertTrue(detector._word_confirms_phrase("тесля"), msg="редкая фамилия не подтверждает")
        self.assertFalse(detector._word_confirms_phrase("тополь"), msg="обычное слово подтверждает фразу")
        matches = detector.detect_names("ТЕСЛЯ СКРЫТНИЦА")
        self.assertTrue(matches, msg="подтверждённая фраза потеряна")

    def test_common_word_from_a_dirty_card_is_not_a_person(self) -> None:
        """Обычное слово из засорённой карточки персоной не становится.

        Найдено на боевом справочнике schema 3 (19.09.2026): «Продажи», «Гость», «Запись»
        лежат в нём как значения класса персон (так их завели в карточках) и проходили
        проверку «кириллица от четырёх букв». Положительный контроль рядом — редкая фамилия
        «Скрытница», которую морфология не читает вовсе: она обязана остаться находкой.
        """
        detector = NameDetector({"P": ["Продажи", "Скрытница"]})
        for text in ("ВЫРУЧКА ПРОДАЖИ за месяц", "ПРОДАЖИ закрыты"):
            with self.subTest(text=text):
                self.assertEqual(detector.detect_names(text), [], msg=f"ложная находка: {text}")
        self.assertTrue(
            detector.detect_names("Скрытница пришла"),
            msg="редкая фамилия из справочника потеряна",
        )

    def test_surname_homonym_is_kept_when_the_open_list_knows_it(self) -> None:
        """Фамилия-омоним («Грач») остаётся находкой: её знает открытый список."""
        layer = NameLayer({"P": {"грач"}}, {"source": "test", "licence": "n/a"})
        detector = NameDetector({"P": ["Грач"]}, name_layer=layer)
        self.assertTrue(detector.detect_names("Грач Иванов"), msg="фамилия-омоним потеряна")

    def test_a_common_word_is_not_enough_for_the_phrase(self) -> None:
        """Обычное слово из клиентского справочника фразу не подтверждает.

        Боевая выгрузка держит в классе персон и обычные слова («Анкета», «Карта», «Клиент» —
        они лежат в поле ФИО карточки), поэтому подтверждением значения такое слово быть не
        может. Само слово при этом остаётся подтверждённым — иначе был бы потерян настоящий
        клиент, чьё значение совпало с обычным словом.
        """
        detector = NameDetector({"P": ["Карта", "Иванов"]})
        self.assertTrue(detector._word_is_confirmed("карта"), msg="слово из справочника не подтвердилось")
        self.assertFalse(detector._word_confirms_phrase("карта"), msg="обычное слово подтвердило фразу")
        self.assertTrue(detector._word_confirms_phrase("иванов"), msg="фамилия не подтвердила фразу")

    def test_ordinary_form_word_from_the_client_dictionary_is_not_a_person(self) -> None:
        """Обычное слово анкеты, попавшее в справочник клиентов, персоной не становится.

        Замер 19.09.2026 на боевом справочнике: «анкета» подтверждена выгрузкой (значение
        лежит в поле ФИО карточки) и проходила морфологический заслон по правилу «кириллица
        от четырёх букв», которое держит редкие фамилии. Держит её только стоп-лист.
        """
        detector = NameDetector({"P": ["Анкета", "Иванов"]})
        detected = [m.raw for m in detector.detect_names("Анкета: Иванов")]
        self.assertNotIn("Анкета", detected, msg=f"слово анкеты стало персоной: {detected}")
        self.assertIn("Иванов", detected, msg="положительный контроль: значение клиента потеряно")


class SystemPromptServiceWordsTests(unittest.TestCase):
    """Служебные подписи системного промпта персоной не становятся (замер 26.09.2026).

    Разбор блока системного промпта (161 повтор промпта агента) дал 323 находки, из них
    322 — ложные, ровно на двух словах: «Персональные» (161) и «ФИО» (161). Оба уходили
    модели кодами, то есть портили текст, и оба стоили секунд на каждом запросе: блок с
    находками кэшируется иначе, чем чистый.

    Корни разные, и оба закрыты штатными механизмами:

    * «ФИО» — подпись поля, но в открытом списке имён лежит значение «фио», поэтому
      ветвь открытого списка подтверждала его и заменяла как фамилию;
    * «Персональные» — падежная форма служебной записи «Персональный», заведённой в поле
      ФИО карточки: выгрузка даёт на это слово формо-дигест персоны, он разрешался, а роль
      «признака клиентских данных» играло само слово «ФИО» рядом. Подтверждение контекстом
      выдавало себя за подтверждение именным справочником, и морфологический заслон не
      срабатывал.

    Словарь и слой здесь повторяют боевое состояние, а значения — заглушки.
    """

    #: Наша собственная формулировка системного промпта (значений клиентов в ней нет).
    SYSTEM_PROMPT = (
        "Ты — рабочий ассистент сети фитнес-клубов. Отвечай по-русски, кратко и по делу. "
        "Работай с базой CRM через инструменты: расписание занятий, карты клиентов, "
        "выручка и продления, отчёты по клубам. Никогда не выдумывай данные клиентов: если "
        "сведений нет — скажи об этом прямо. Персональные данные клиентов (ФИО, телефон, "
        "почта, адрес, дата рождения) приходят в коде и восстанавливаются доверенной "
        "границей. Клубы сети: Квартальный, Центральный, Базовый."
    )

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = TokenMapStore(
            os.path.join(self._tmp.name, "prompt.db"), fernet_key=b"f" * 32
        )
        # Справочник продакшен-вида: значения хранятся отпечатками, а служебная запись
        # «Персональный» из поля ФИО карточки даёт формо-дигест на «Персональные».
        payload = to_keyed_digests(
            {"P": ["Персональный", "Иванов", "Тесля", "Скрытница", "Камыш"]}, KEY
        )
        path = os.path.join(self._tmp.name, "pii_dict.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)
        self.dictionary = PiiDictionary(path, key=KEY)
        # Открытый список боевого вида: в нём есть «фио» (именно им подтверждалось «ФИО»)
        # и редкие настоящие фамилии, которые обязаны остаться находками.
        self.layer = NameLayer(
            {"P": {"фио", "иванов", "тесля", "скрытница", "камыш"}},
            {"source": "test", "licence": "n/a"},
        )

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def _detector(self, dictionary: PiiDictionary | None = None) -> NameDetector:
        return NameDetector(dictionary or self.dictionary, name_layer=self.layer)

    def _anonymize(self, text: str, detector: NameDetector | None = None) -> str:
        tokenizer = PayloadTokenizer(KEY, self.store, detector or self._detector())
        payload = {"messages": [{"role": "user", "content": text}]}
        anonymized, _stats = tokenizer.tokenize_payload(payload, "prompt")
        return anonymized["messages"][0]["content"]

    def test_service_words_of_the_prompt_are_not_people(self) -> None:
        """Ни «Персональные», ни «ФИО» персоной не становятся, и текст не портится."""
        detector = self._detector()
        found = [match.raw for match in detector.detect_names(self.SYSTEM_PROMPT)]
        self.assertEqual(found, [], msg=f"ложные находки в системном промпте: {found}")
        self.assertEqual(self._anonymize(self.SYSTEM_PROMPT, detector), self.SYSTEM_PROMPT)

    def test_a_service_word_does_not_confirm_itself(self) -> None:
        """Само слово «ФИО» не делает текст похожим на выгрузку клиентов.

        Признак клиентских данных — «фио» — стоит в той же строке, что и находка:
        в системном промпте он подтверждал и «Персональные» рядом, и сам себя.
        """
        detector = self._detector()
        for text in (
            "Персональные данные клиентов: телефон 79000000001",
            "ФИО и телефон клиента 79000000001",
            "Анкета: ФИО, телефон 79000000001",
        ):
            with self.subTest(text=text):
                found = [match.raw for match in detector.detect_names(text)]
                self.assertEqual(found, [], msg=f"ложная находка рядом с признаком данных: {found}")

    def test_the_whole_prompt_block_has_no_person_findings(self) -> None:
        """Повтор промпта, как в живом блоке: находок ноль, текст байт в байт тот же."""
        block = "\n".join([self.SYSTEM_PROMPT] * 12)
        self.assertEqual(self._detector().detect_names(block), [], msg="ложные находки в блоке")
        self.assertEqual(self._anonymize(block), block, msg="блок системного промпта испорчен")

    def test_rare_real_surnames_are_still_replaced(self) -> None:
        """Отрицательный контроль: редкие настоящие фамилии обязаны заменяться.

        «Тесля» и «Скрытница» открытым списком держатся именно потому, что морфологии
        неизвестны. Стоп-лист подписей полей не должен их задеть — иначе лечение ложной
        находки стало бы новой слепой зоной (замер 19.09.2026: такая правка уже теряла 12,9%
        настоящих значений).
        """
        for value in ("Тесля", "Скрытница"):
            with self.subTest(value=value):
                text = f"Клиент {value}, телефон 79000000001"
                result = self._anonymize(text)
                self.assertNotIn(value, result, msg=f"настоящая фамилия потеряна: {value}")
                self.assertTrue(find_tokens(result), msg="замена не выдала код")

    def test_a_declined_form_read_as_a_common_word_is_still_replaced(self) -> None:
        """Падеж, который морфология читает обычным словом, не теряется, если список знает основу.

        «Камыш» — настоящая фамилия и нарицательное существительное одновременно, как «Тополь»
        и «Грач». Заслон «обычное слово» обязан молчать, когда открытый список знает основу
        («Камыша» ← «камыш»): иначе склонённые формы настоящих клиентов перестали бы
        обезличиваться, то есть правка поменяла бы ложную замену на утечку.
        """
        text = "Анкета: Камыша, телефон 79000000001"
        found = [text[m.start : m.end] for m in self._detector().detect_names(text)]
        self.assertIn("Камыша", found, msg=f"падежная форма настоящей фамилии потеряна: {found}")
        self.assertTrue(find_tokens(self._anonymize(text)), msg="замена не выдала код")


class AddressMarkerTests(unittest.TestCase):
    """Адрес клуба остаётся адресом, а не фамилией, при любом написании маркера.

    Замер 19.09.2026 (адреса клубов, персональных данных нет): наши правила защищали 5 адресов
    из 10 — только сокращения («ул.», «б-р», «пр.»), — и «улица Садовая» рядом с телефоном
    заменялась как фамилия. NER на том же наборе давал 10 из 10; после правки — 10 из 10.
    """

    STREETS = ("Садовая", "Заводская", "Липовая", "Приморская", "Лесная")
    LINES = (
        "клуб на ул. Садовая 3а",
        "клуб на улица Садовая 3а",
        "клуб на б-р Садовая 3а",
        "клуб на бульвар Садовая 3а",
        "клуб на пр. Заводская 19А",
        "клуб на проспект Заводская 19А",
        "клуб на пер. Липовый 5",
        "клуб на переулок Липовый 5",
        "клуб на ш. Приморское 12",
        "клуб на шоссе Приморское 12",
    )

    def setUp(self) -> None:
        layer = NameLayer(
            {"P": {street.lower() for street in self.STREETS}},
            {"source": "test", "licence": "n/a"},
        )
        self.detector = NameDetector({"P": ["Иванов"]}, name_layer=layer)

    def _street_findings(self, line: str) -> list[str]:
        return [
            line[match.start : match.end]
            for match in self.detector.detect_names(line)
            if line[match.start : match.end].lower() in {s.lower() for s in self.STREETS}
        ]

    def test_street_names_are_never_persons(self) -> None:
        for line in self.LINES:
            with self.subTest(line=line):
                # Признаки работы с данными рядом: иначе заслон открытого слоя и без того молчит.
                text = f"Анкета: {line}, телефон 79000000001"
                self.assertEqual(self._street_findings(text), [], msg=f"улица стала персоной: {line}")

    def test_positive_control_a_surname_without_a_marker_is_replaced(self) -> None:
        text = "Анкета: Садовая, телефон 79000000001"
        self.assertEqual(
            self._street_findings(text), ["Садовая"], msg="положительный контроль: фамилия потеряна"
        )

    def test_a_person_after_the_house_number_is_not_swallowed_by_the_address(self) -> None:
        """Цифра дома закрывает адрес: имя за ней обязано заменяться (риск утечки)."""
        text = "Анкета: ул. Садовая 3а Иванов, телефон 79000000001"
        found = [text[m.start : m.end] for m in self.detector.detect_names(text)]
        self.assertIn("Иванов", found, msg=f"настоящая фамилия потеряна: {found}")
        self.assertNotIn("Садовая", found, msg=f"улица стала персоной: {found}")


if __name__ == "__main__":
    unittest.main()
