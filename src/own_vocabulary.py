# FILE: src/own_vocabulary.py
# VERSION: 1.0.0
# START_MODULE_CONTRACT
#   PURPOSE: Hold the lexicon that belongs to the operator itself — brand and branch names, tariff names, the city, the operator's own addresses, switchboard numbers and the service-object names of its CRM — taken from configuration, so no particular organisation is hardcoded, and keep every entry of it out of the person-name class.
#   SCOPE: dependency-free in-memory registry with neutral (empty) defaults, JSON file and environment loading, explicit injection for the configuration loader and tests, digit-normalisation of own phone numbers.
#   DEPENDS: none
#   LINKS: M-OWN-VOCABULARY, M-DETECT-NAME, M-DETECT-RULES, M-CLIENT-LAYER, M-CONFIG
#   ROLE: RUNTIME
#   MAP_MODE: EXPORTS
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   OwnVocabulary - frozen set of the operator's own lexicon
#   configure - replace the registry (configuration loader and tests)
#   reset - return the registry to the neutral default
#   own_terms - brand, branches, tariffs, city and other own words
#   own_addresses - the operator's own addresses
#   own_phone_digits - digit forms of the operator's own switchboards
#   service_object_names - CRM service records that are not people
#   from_env - build a value from environment variables without side effects
#   load_json - build a value from a JSON file without side effects
#   apply - install a value into the registry
# END_MODULE_MAP
#
# START_CHANGE_SUMMARY
#   LAST_CHANGE: v1.0.0 - the operator's own lexicon moved out of the code into configuration: the public build carries neutral defaults and any organisation fills its own brand, branches, tariffs, addresses and switchboard numbers from the example configuration.
# END_CHANGE_SUMMARY

"""The operator's own lexicon, taken from configuration.

Why this module exists: a brand, its branches, its tariff names, the city it works in, its own
addresses and switchboard numbers legally end up inside the client dictionary — cards are opened
with the club address or the club phone — and then the detector would replace them as if they were
client data. The stop-list that prevents this is not a property of the code but of the operator, so
it lives in configuration: the public build ships neutral (empty) defaults, and a new club fills
in its own values from ``config.example.yaml`` / ``.env.example``.

Own words are never personal data, so they are never replaced and can never act as a marker of
"client data nearby" (owner correction of 19.09.2026: «слово „карта“ не является же перс данными»).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Iterable, Mapping

LOGGER_NAME = "OwnVocabulary"
LOG_MARKER = "[OwnVocabulary][configure][BLOCK_OWN_VOCABULARY]"

#: Environment variables of the operator's own lexicon.
ENV_TERMS = "PII_PROXY_OWN_TERMS"
ENV_ADDRESSES = "PII_PROXY_OWN_ADDRESSES"
ENV_PHONES = "PII_PROXY_OWN_PHONES"
ENV_SERVICE_OBJECTS = "PII_PROXY_OWN_SERVICE_OBJECTS"
#: Optional path to a JSON file holding all four lists at once.
ENV_FILE = "PII_PROXY_OWN_VOCAB"


# START_BLOCK_OWN_VOCABULARY
@dataclass(frozen=True)
class OwnVocabulary:
    """The operator's own lexicon: brand, branches, tariffs, addresses, switchboards, CRM records.

    # START_CONTRACT: OwnVocabulary
    #   PURPOSE: Carry every value that belongs to the operator and must never be read as client data.
    #   INPUTS: { terms: frozenset[str], addresses: frozenset[str], phones: frozenset[str], service_objects: frozenset[str] }
    #   OUTPUTS: { OwnVocabulary - frozen value object }
    #   SIDE_EFFECTS: none
    #   LINKS: M-OWN-VOCABULARY, M-DETECT-NAME, M-DETECT-RULES
    # END_CONTRACT: OwnVocabulary
    """

    terms: frozenset[str] = field(default_factory=frozenset)
    addresses: frozenset[str] = field(default_factory=frozenset)
    phones: frozenset[str] = field(default_factory=frozenset)
    service_objects: frozenset[str] = field(default_factory=frozenset)

    def is_empty(self) -> bool:
        """Return True when nothing of the operator's own lexicon is configured."""
        return not (self.terms or self.addresses or self.phones or self.service_objects)


#: Neutral default: an empty lexicon. A fresh installation therefore says "no own words known"
#: instead of guessing somebody else's brand.
_DEFAULT = OwnVocabulary()
_registry: OwnVocabulary = _DEFAULT


def _as_items(raw: object) -> Iterable[str]:
    """Return an iterable of strings from a comma/semicolon/newline separated string or a sequence."""
    if raw is None:
        return ()
    if isinstance(raw, str):
        return [part for part in re.split(r"[,;\n]", raw)]
    if isinstance(raw, (list, tuple, set, frozenset)):
        return [str(item) for item in raw]
    return [str(raw)]


def _normalise(raw: object) -> frozenset[str]:
    """Return the lower-cased, trimmed entries of a configuration value.

    # START_CONTRACT: _normalise
    #   PURPOSE: Compare own words and configurations in one form, whatever the file format was.
    #   INPUTS: { raw: object - string, sequence or None }
    #   OUTPUTS: { frozenset[str] - non-empty lower-cased entries }
    #   SIDE_EFFECTS: none
    #   LINKS: M-OWN-VOCABULARY
    # END_CONTRACT: _normalise
    """
    items: set[str] = set()
    for item in _as_items(raw):
        value = " ".join(str(item).split()).strip().lower()
        if value:
            items.add(value)
    return frozenset(items)


def digits_only(value: str) -> str:
    """Return the digits of a value, with the 8-form of a Russian number folded to the 7-form."""
    digits = re.sub(r"\D", "", str(value))
    if len(digits) == 11 and digits.startswith("8"):
        return "7" + digits[1:]
    return digits


def _normalise_phones(raw: object) -> frozenset[str]:
    """Return digit forms of the operator's own switchboards, so any spelling of a number matches."""
    return frozenset(
        digits for digits in (digits_only(item) for item in _as_items(raw)) if digits
    )


def configure(
    *,
    terms: object = (),
    addresses: object = (),
    phones: object = (),
    service_objects: object = (),
) -> OwnVocabulary:
    """Install the operator's own lexicon and return it.

    # START_CONTRACT: configure
    #   PURPOSE: Replace the registry from the configuration loader, a tool or a test.
    #   INPUTS: { terms/addresses/phones/service_objects: object - string, sequence or None }
    #   OUTPUTS: { OwnVocabulary - the value now in effect }
    #   SIDE_EFFECTS: replaces the module registry
    #   LINKS: M-OWN-VOCABULARY, M-CONFIG
    # END_CONTRACT: configure
    """
    global _registry
    _registry = OwnVocabulary(
        terms=_normalise(terms),
        addresses=_normalise(addresses),
        phones=_normalise_phones(phones),
        service_objects=_normalise(service_objects),
    )
    return _registry


def reset() -> None:
    """Return the registry to the neutral default (an empty lexicon)."""
    global _registry
    _registry = _DEFAULT


def apply(vocabulary: OwnVocabulary) -> OwnVocabulary:
    """Install an already built value into the registry."""
    global _registry
    _registry = vocabulary
    return _registry


def current() -> OwnVocabulary:
    """Return the lexicon now in effect."""
    return _registry


def own_terms() -> frozenset[str]:
    """Return the operator's own words: brand, branches, tariffs, city and service vocabulary."""
    return _registry.terms


def own_addresses() -> frozenset[str]:
    """Return the operator's own addresses (club addresses legally present in the dictionary)."""
    return _registry.addresses


def own_phone_digits() -> frozenset[str]:
    """Return the digit forms of the operator's own switchboards."""
    return _registry.phones


def service_object_names() -> frozenset[str]:
    """Return the CRM service records that are not people."""
    return _registry.service_objects


def from_env(env: Mapping[str, str] | None = None) -> OwnVocabulary:
    """Build a lexicon from environment variables without touching the registry.

    # START_CONTRACT: from_env
    #   PURPOSE: Let the configuration loader see the lexicon before it is installed.
    #   INPUTS: { env: Mapping[str, str] | None - defaults to os.environ }
    #   OUTPUTS: { OwnVocabulary - value described by the environment }
    #   SIDE_EFFECTS: none
    #   LINKS: M-OWN-VOCABULARY, M-CONFIG
    # END_CONTRACT: from_env
    """
    source = os.environ if env is None else env
    terms = source.get(ENV_TERMS) or ()
    addresses = source.get(ENV_ADDRESSES) or ()
    phones = source.get(ENV_PHONES) or ()
    service_objects = source.get(ENV_SERVICE_OBJECTS) or ()
    vocabulary = OwnVocabulary(
        terms=_normalise(terms),
        addresses=_normalise(addresses),
        phones=_normalise_phones(phones),
        service_objects=_normalise(service_objects),
    )
    path = source.get(ENV_FILE)
    if path:
        vocabulary = merge(vocabulary, load_json(path))
    return vocabulary


def merge(*values: OwnVocabulary) -> OwnVocabulary:
    """Return the union of several lexicons, so a file and environment variables can add up."""
    return OwnVocabulary(
        terms=frozenset().union(*(item.terms for item in values)) if values else frozenset(),
        addresses=frozenset().union(*(item.addresses for item in values)) if values else frozenset(),
        phones=frozenset().union(*(item.phones for item in values)) if values else frozenset(),
        service_objects=(
            frozenset().union(*(item.service_objects for item in values)) if values else frozenset()
        ),
    )


def load_json(path: str) -> OwnVocabulary:
    """Build a lexicon from a JSON file without touching the registry.

    # START_CONTRACT: load_json
    #   PURPOSE: Read the operator's own lexicon from the JSON file named in the configuration.
    #   INPUTS: { path: str - file with keys terms, addresses, phones, service_objects }
    #   OUTPUTS: { OwnVocabulary - value described by the file }
    #   SIDE_EFFECTS: reads the filesystem
    #   LINKS: M-OWN-VOCABULARY, M-CONFIG
    # END_CONTRACT: load_json
    """
    if not path or not os.path.isfile(path):
        return _DEFAULT
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, Mapping):
        return _DEFAULT
    return OwnVocabulary(
        terms=_normalise(data.get("terms")),
        addresses=_normalise(data.get("addresses")),
        phones=_normalise_phones(data.get("phones")),
        service_objects=_normalise(data.get("service_objects")),
    )


def from_mapping(mapping: Mapping[str, object]) -> OwnVocabulary:
    """Build a lexicon from a configuration overlay mapping."""
    return OwnVocabulary(
        terms=_normalise(mapping.get("terms")),
        addresses=_normalise(mapping.get("addresses")),
        phones=_normalise_phones(mapping.get("phones")),
        service_objects=_normalise(mapping.get("service_objects")),
    )
# END_BLOCK_OWN_VOCABULARY
