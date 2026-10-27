"""Raw AT dispatch shared by the CLI and the TUI: checks, reply errors, first-write snapshot."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .catalog import CLASS_UNKNOWN, CatalogEntry, argument_problem, classify
from .native import ManagedConfig, NativeError, Netbridge, raw_command_problem
from .storage import StorageError, create_snapshot, ensure_data_root, snapshot_path

CHECK_OK = 0
CHECK_INVALID = 1  # malformed text: can never be sent
CHECK_REFUSED = 2  # well formed, but refused whatever the gate flags say

SNAPSHOT_EXISTS = 0
SNAPSHOT_CREATED = 1
SNAPSHOT_FAILED = 2
NO_NATIVE_STATUS = -1

DEFAULT_REPLY_TIMEOUT_MS = 1500
DEFAULT_REPLY_IDLE_MS = 250

# Whole-line status keywords, matched like the native classify_line(): the keyword
# alone or followed by ':' or a space. Value lines always carry a prefix.
DEVICE_ERROR_KEYWORDS = ("ERROR", "+ERROR", "UNSUPPORT", "UNSUPPORTED", "UNKNOWN")
KEYWORD_SEPARATORS = (":", " ")
INVALID_COMMAND_LINE = "valid cmds:"


@dataclass(frozen=True)
class CheckedCommand:
    text: str
    command_class: str
    entry: CatalogEntry | None
    result: int
    problem: str


@dataclass(frozen=True)
class SnapshotOutcome:
    result: int
    path: Path
    message: str
    native_status: int


def check_command(text: str, catalog: list[CatalogEntry]) -> CheckedCommand:
    """Validate and classify one raw command; the gate itself is the caller's policy."""

    problem = raw_command_problem(text)
    if problem:
        return CheckedCommand(text, CLASS_UNKNOWN, None, CHECK_INVALID, problem)
    command_class, entry = classify(text, catalog)
    problem = argument_problem(text)
    if problem:
        return CheckedCommand(text, command_class, entry, CHECK_REFUSED, problem)
    return CheckedCommand(text, command_class, entry, CHECK_OK, "")


def is_keyword_line(line: str, keyword: str) -> bool:
    if not line.startswith(keyword):
        return False
    if len(line) == len(keyword):
        return True
    return line[len(keyword)] in KEYWORD_SEPARATORS


def reply_is_device_error(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith(INVALID_COMMAND_LINE):
            return True
        upper = stripped.upper()
        for keyword in DEVICE_ERROR_KEYWORDS:
            if is_keyword_line(upper, keyword):
                return True
    return False


def snapshot_before_write(backend: Netbridge, data_root: Path, mac: bytes) -> SnapshotOutcome:
    """Create <data-root>/<mac>/snapshot.ini unless one exists; never overwrite one."""

    path = snapshot_path(data_root, mac)
    if os.path.lexists(path):
        return SnapshotOutcome(SNAPSHOT_EXISTS, path, "", NO_NATIVE_STATUS)
    config: ManagedConfig | None = None
    try:
        ensure_data_root(data_root)
        config = backend.read_config(mac)
        created = create_snapshot(data_root, config)
    except NativeError as error:
        return SnapshotOutcome(SNAPSHOT_FAILED, path, str(error), error.status)
    except (StorageError, ValueError, UnicodeError) as error:
        return SnapshotOutcome(SNAPSHOT_FAILED, path, str(error), NO_NATIVE_STATUS)
    finally:
        if config is not None:
            config.psk = b""
    return SnapshotOutcome(SNAPSHOT_CREATED, created, "", NO_NATIVE_STATUS)
