"""TaiXin AT command catalog, command classification, and secret redaction."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

CATALOG_SCHEMA_VERSION = 1
DEFAULT_CATALOG_PATH = Path(__file__).with_name("catalog") / "taixin_at_commands.toml"
AT_PREFIX = "AT+"
QUERY_SUFFIX = "?"
TEST_SUFFIX = "=?"
SET_SEPARATOR = "="

CLASS_QUERY = "query"
CLASS_SET = "set"
CLASS_ACTION = "action"
CLASS_UNKNOWN = "unknown"

SAFETY_QUERY = "query"
SAFETY_SET = "set"
SAFETY_ACTION = "action"
SAFETY_VALUES = (SAFETY_QUERY, SAFETY_SET, SAFETY_ACTION)
PERSISTS_VALUES = ("yes", "no", "unknown")
CONFIDENCE_VALUES = ("high", "medium", "low")

REQUIRE_NOTHING = 0
REQUIRE_WRITE = 1
REQUIRE_DANGEROUS = 2

REDACTED = "[redacted]"
PSK_SET_PREFIX = "AT+PSK="
NAME_RE = re.compile(r"[A-Z0-9_]+")
PSK_VALUE_RE = re.compile(r"(psk:)[^\r\n]*", re.IGNORECASE)
HEX_RUN_RE = re.compile(r"[0-9A-Fa-f]{64,}")
PSK_HEX_RE = re.compile(r"[0-9A-Fa-f]{64}")

TOP_LEVEL_KEYS = {"schema_version", "command"}
ENTRY_KEYS = {
    "name", "summary", "query", "set", "args", "safety", "sensitive", "persists",
    "source", "confidence",
}


class CatalogError(ValueError):
    pass


@dataclass(frozen=True)
class CatalogEntry:
    name: str
    summary: str
    query: tuple[str, ...]
    set: str
    args: str
    safety: str
    sensitive: bool
    persists: str
    source: str
    confidence: str


def _name_length(command: str, start: int) -> int:
    index = start
    while index < len(command):
        character = command[index]
        if not (character.isascii() and (character.isalnum() or character == "_")):
            break
        index += 1
    return index - start


def normalize_command(command: str) -> str:
    """Strip whitespace and uppercase the AT+NAME part; arguments stay verbatim."""

    text = command.strip()
    if text[:len(AT_PREFIX)].upper() != AT_PREFIX:
        return text
    end = len(AT_PREFIX) + _name_length(text, len(AT_PREFIX))
    return text[:end].upper() + text[end:]


def command_name(command: str) -> str:
    """Return NAME for a normalized AT+NAME... command, or "" when there is none."""

    if not command.startswith(AT_PREFIX):
        return ""
    length = _name_length(command, len(AT_PREFIX))
    return command[len(AT_PREFIX):len(AT_PREFIX) + length]


def _require_text(entry: dict[str, object], key: str, source: str, allow_empty: bool) -> str:
    value = entry[key]
    if type(value) is not str:
        raise CatalogError(f"{source}: {key} must be a string")
    if not allow_empty and not value.strip():
        raise CatalogError(f"{source}: {key} must not be empty")
    return value


def _require_choice(entry: dict[str, object], key: str, source: str,
                    choices: tuple[str, ...]) -> str:
    value = _require_text(entry, key, source, False)
    if value not in choices:
        raise CatalogError(f"{source}: {key} must be one of {', '.join(choices)}")
    return value


def validate_entry(entry: object, source: str) -> CatalogEntry:
    if type(entry) is not dict:
        raise CatalogError(f"{source}: command must be a table")
    if set(entry) != ENTRY_KEYS:
        raise CatalogError(f"{source}: command fields must exactly match schema version 1")
    name = _require_text(entry, "name", source, False)
    if not NAME_RE.fullmatch(name):
        raise CatalogError(f"{source}: name must use uppercase ASCII, digits or '_'")
    source = f"{source} ({name})"
    summary = _require_text(entry, "summary", source, False)
    queries = entry["query"]
    if type(queries) is not list:
        raise CatalogError(f"{source}: query must be a list of strings")
    for query in queries:
        if type(query) is not str:
            raise CatalogError(f"{source}: query must be a list of strings")
        if normalize_command(query) != query or command_name(query) != name:
            raise CatalogError(f"{source}: query '{query}' must be a normalized AT+{name} command")
    set_form = _require_text(entry, "set", source, True)
    if set_form and (normalize_command(set_form) != set_form or command_name(set_form) != name):
        raise CatalogError(f"{source}: set must be empty or a normalized AT+{name} command")
    if not queries and not set_form:
        raise CatalogError(f"{source}: needs at least one query or a set form")
    args = _require_text(entry, "args", source, True)
    safety = _require_choice(entry, "safety", source, SAFETY_VALUES)
    sensitive = entry["sensitive"]
    if type(sensitive) is not bool:
        raise CatalogError(f"{source}: sensitive must be true or false")
    persists = _require_choice(entry, "persists", source, PERSISTS_VALUES)
    origin = _require_text(entry, "source", source, False)
    confidence = _require_choice(entry, "confidence", source, CONFIDENCE_VALUES)
    return CatalogEntry(
        name, summary, tuple(queries), set_form, args, safety, sensitive, persists,
        origin, confidence,
    )


def validate_catalog(data: dict[str, object], source: str = "catalog") -> list[CatalogEntry]:
    if set(data) != TOP_LEVEL_KEYS:
        raise CatalogError(f"{source}: top-level keys must be schema_version and command")
    version = data["schema_version"]
    if type(version) is not int or version != CATALOG_SCHEMA_VERSION:
        raise CatalogError(f"{source}: unsupported schema version")
    commands = data["command"]
    if type(commands) is not list or not commands:
        raise CatalogError(f"{source}: command must be a non-empty array of tables")
    entries: list[CatalogEntry] = []
    names: set[str] = set()
    for index in range(len(commands)):
        entry = validate_entry(commands[index], f"{source}: command {index + 1}")
        if entry.name in names:
            raise CatalogError(f"{source}: duplicate command name '{entry.name}'")
        names.add(entry.name)
        entries.append(entry)
    return entries


def load_catalog(path: Path | None = None) -> list[CatalogEntry]:
    if path is None:
        path = DEFAULT_CATALOG_PATH
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except tomllib.TOMLDecodeError as error:
        raise CatalogError(f"{path.name}: invalid TOML") from error
    except OSError as error:
        raise CatalogError(f"{path.name}: could not be read ({error.strerror})") from error
    return validate_catalog(data, path.name)


def find_entry(name: str, catalog: list[CatalogEntry]) -> CatalogEntry | None:
    for entry in catalog:
        if entry.name == name:
            return entry
    return None


def _looks_like_query(command: str, name: str) -> bool:
    """Only "AT+NAME?" and "AT+NAME=?" are query-shaped; "AT+NAME=val?" is not."""

    suffix = command[len(AT_PREFIX) + len(name):]
    return suffix == QUERY_SUFFIX or suffix == TEST_SUFFIX


def _matches_set_form(command: str, entry: CatalogEntry) -> bool:
    if not entry.set:
        return False
    if SET_SEPARATOR not in entry.set:
        return command == entry.set
    return command.startswith(f"{AT_PREFIX}{entry.name}=")


def classify(command: str, catalog: list[CatalogEntry]) -> tuple[str, CatalogEntry | None]:
    """Return (CLASS_*, matching catalog entry or None) for one raw command."""

    normalized = normalize_command(command)
    name = command_name(normalized)
    if not name:
        return CLASS_UNKNOWN, None
    entry = find_entry(name, catalog)
    if entry is None:
        if _looks_like_query(normalized, name):
            return CLASS_QUERY, None
        if SET_SEPARATOR in normalized:
            return CLASS_SET, None
        return CLASS_UNKNOWN, None
    # Every form of an action command is gated, including its "=?" query: several
    # LMAC test-table handlers are not known to treat "=?" as side-effect free.
    if entry.safety == SAFETY_ACTION:
        return CLASS_ACTION, entry
    if normalized in entry.query:
        return CLASS_QUERY, entry
    if _matches_set_form(normalized, entry):
        return CLASS_SET, entry
    # A known command in an undocumented form: allow only query-shaped text freely.
    if _looks_like_query(normalized, name):
        return CLASS_QUERY, entry
    return CLASS_UNKNOWN, entry


def argument_problem(command: str) -> str:
    """Return why a command must never be sent, even when its gate flag is given."""

    normalized = normalize_command(command)
    if normalized.startswith(PSK_SET_PREFIX):
        value = normalized[len(PSK_SET_PREFIX):]
        # The firmware clears the saved key when the value is not exactly 64 hex characters.
        if not PSK_HEX_RE.fullmatch(value):
            return "AT+PSK= needs exactly 64 hexadecimal characters (any other value clears the key)"
    return ""


def gate_for(command_class: str) -> int:
    if command_class == CLASS_QUERY:
        return REQUIRE_NOTHING
    if command_class == CLASS_SET:
        return REQUIRE_WRITE
    return REQUIRE_DANGEROUS


def redact_command(command: str) -> str:
    if normalize_command(command).startswith(PSK_SET_PREFIX):
        return PSK_SET_PREFIX + REDACTED
    return HEX_RUN_RE.sub(REDACTED, command)


def redact_reply(text: str) -> str:
    """Redact PSK values in a fully reassembled reply (never per fragment)."""

    redacted = PSK_VALUE_RE.sub(r"\1" + REDACTED, text)
    return HEX_RUN_RE.sub(REDACTED, redacted)
