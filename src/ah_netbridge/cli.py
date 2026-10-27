"""Command entry point: the full-screen TUI by default, plus scriptable subcommands."""

from __future__ import annotations

import argparse
import curses
import json
import os
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import __version__
from .catalog import (
    CLASS_QUERY,
    CLASS_UNKNOWN,
    HEX_RUN_RE,
    REDACTED,
    REQUIRE_DANGEROUS,
    REQUIRE_WRITE,
    SAFETY_VALUES,
    CatalogEntry,
    CatalogError,
    gate_for,
    load_catalog,
    redact_command,
    redact_reply,
)
from .dispatch import (
    CHECK_INVALID,
    CHECK_REFUSED,
    DEFAULT_REPLY_IDLE_MS,
    DEFAULT_REPLY_TIMEOUT_MS,
    NO_NATIVE_STATUS,
    SNAPSHOT_CREATED,
    SNAPSHOT_FAILED,
    check_command,
    reply_is_device_error,
    snapshot_before_write,
)
from .native import (
    STATUS_BUFFER_TOO_SMALL,
    STATUS_NOT_FOUND,
    STATUS_TIMEOUT,
    STATUS_UNSUPPORTED,
    ManagedConfig,
    NativeError,
    Netbridge,
    c_text,
    status_name,
)
from .storage import StorageError, default_data_root, ensure_data_root
from .tui import Application, UI, format_channels, config_channels, tx_power_text

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_NOT_FOUND = 3
EXIT_TIMEOUT = 4
EXIT_DEVICE_ERROR = 5
EXIT_REFUSED = 6
EXIT_INTERRUPTED = 130

DEFAULT_TIMEOUT_MS = DEFAULT_REPLY_TIMEOUT_MS
DEFAULT_IDLE_MS = DEFAULT_REPLY_IDLE_MS
DEFAULT_SCAN_TIMEOUT_MS = 1500
MAX_WAIT_MS = 60000
MAC_HEX_LENGTH = 12
DEBUG_LOG_MODE = 0o600
SHELL_PROMPT = "ahnb> "
COMMENT_PREFIX = "#"

# status_name values for JSON records of commands that were never sent.
RECORD_DRY_RUN = "DRY_RUN"
RECORD_REFUSED = "REFUSED"
RECORD_INVALID = "INVALID"

BackendFactory = Callable[[], Netbridge]


@dataclass
class Prepared:
    text: str
    command_class: str


@dataclass
class Session:
    backend: Netbridge | None
    mac: bytes
    data_root: Path
    write_allowed: bool
    dangerous_allowed: bool
    show_secrets: bool
    dry_run: bool
    json_output: bool
    timeout_ms: int
    idle_ms: int
    snapshot_enabled: bool
    snapshot_done: bool = False


def program_name() -> str:
    name = Path(sys.argv[0]).name if sys.argv and sys.argv[0] else ""
    if not name or name.endswith(".py"):
        return "ahnb"
    return name


def error_line(message: str) -> None:
    print(f"{program_name()}: {message}", file=sys.stderr)


# -- argument parsing -----------------------------------------------------------


def parse_mac(text: str) -> bytes:
    digits = text.strip().replace(":", "").replace("-", "")
    if len(digits) != MAC_HEX_LENGTH:
        raise argparse.ArgumentTypeError(f"invalid MAC address: {text}")
    try:
        return bytes.fromhex(digits)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid MAC address: {text}") from error


def parse_wait_ms(text: str) -> int:
    try:
        value = int(text)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"not a number of milliseconds: {text}") from error
    if value < 1 or value > MAX_WAIT_MS:
        raise argparse.ArgumentTypeError(f"milliseconds must be 1–{MAX_WAIT_MS}")
    return value


def add_target_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-i", "--interface", required=True, metavar="IFACE",
                        help="IPv4 broadcast interface name")
    parser.add_argument("-m", "--mac", required=True, type=parse_mac, metavar="MAC",
                        help="exact device MAC")


def add_gate_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--write", action="store_true",
                        help="allow set commands (catalogued, or uncatalogued AT+NAME=...)")
    parser.add_argument("--dangerous", action="store_true",
                        help="allow action and unknown commands (implies --write)")
    parser.add_argument("--show-secrets", action="store_true",
                        help="do not redact PSKs in commands and replies")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the exact packet text and send nothing")
    parser.add_argument("--json", action="store_true", help="one JSON object per command")
    parser.add_argument("--timeout", type=parse_wait_ms, default=DEFAULT_TIMEOUT_MS, metavar="MS",
                        help=f"total reply wait in ms (default {DEFAULT_TIMEOUT_MS})")
    parser.add_argument("--idle", type=parse_wait_ms, default=DEFAULT_IDLE_MS, metavar="MS",
                        help=f"silence that ends a reply in ms (default {DEFAULT_IDLE_MS})")
    parser.add_argument("--no-snapshot", action="store_true",
                        help="do not create snapshot.ini before the first write")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data-root", type=Path, default=argparse.SUPPRESS, metavar="DIR",
                        help="snapshot/profile/shared.psk root")
    common.add_argument("--debug", action="store_true", default=argparse.SUPPRESS,
                        help="write a redacted traceback log on internal errors")

    parser = argparse.ArgumentParser(
        prog=program_name(),
        description="Safe TaiXin NetAT configuration tool. The subcommand is optional: "
        "without one the full-screen TUI starts.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--data-root", type=Path, default=None, metavar="DIR",
                        help="snapshot/profile/shared.psk root (default: $AHNB_DATA_ROOT, "
                        "$XDG_STATE_HOME/ah-netbridge or ~/.local/state/ah-netbridge)")
    parser.add_argument("--debug", action="store_true", default=False,
                        help="write a redacted traceback log on internal errors")
    parser.add_argument("--preset-dir", type=Path, default=None, metavar="DIR",
                        help="validated TOML radio preset directory")
    parser.add_argument("--interface", default=None, metavar="NAME",
                        help="preselect this interface in the TUI")
    parser.add_argument("--mac", type=parse_mac, default=None, metavar="MAC",
                        help="preselect this MAC in the TUI")
    subparsers = parser.add_subparsers(dest="command", metavar="[COMMAND]",
                                       title="subcommands (optional; none starts the TUI)")

    interfaces = subparsers.add_parser("interfaces", parents=[common],
                                       help="list eligible interfaces")
    interfaces.add_argument("--json", action="store_true", help="JSON output")

    scan = subparsers.add_parser("scan", parents=[common], help="discover devices")
    scan.add_argument("-i", "--interface", required=True, metavar="IFACE",
                      help="IPv4 broadcast interface name")
    scan.add_argument("--timeout", type=parse_wait_ms, default=DEFAULT_SCAN_TIMEOUT_MS,
                      metavar="MS", help=f"listen time in ms (default {DEFAULT_SCAN_TIMEOUT_MS})")
    scan.add_argument("--json", action="store_true", help="JSON output")

    show = subparsers.add_parser("show", parents=[common],
                                 help="show the current setup (never reads the PSK)")
    add_target_arguments(show)
    show.add_argument("--json", action="store_true", help="JSON output")

    commands = subparsers.add_parser("commands", parents=[common],
                                     help="list the TaiXin AT command catalog")
    commands.add_argument("--json", action="store_true", help="JSON output")
    commands.add_argument("--class", dest="safety", choices=SAFETY_VALUES, default=None,
                          help="only list commands of this safety class")

    at = subparsers.add_parser("at", parents=[common], help="send raw AT commands")
    add_target_arguments(at)
    add_gate_arguments(at)
    at.add_argument("--file", type=Path, default=None, metavar="FILE",
                    help="read commands from FILE (one per line, '#' comments)")
    at.add_argument("commands", nargs="*", metavar="CMD", help="AT command, e.g. AT+MODE?")

    shell = subparsers.add_parser("shell", parents=[common], help="interactive raw AT shell")
    add_target_arguments(shell)
    add_gate_arguments(shell)
    return parser


def resolve_data_root(arguments: argparse.Namespace) -> Path:
    if arguments.data_root is not None:
        return arguments.data_root.expanduser().resolve()
    return default_data_root()


def create_backend(factory: BackendFactory) -> Netbridge | None:
    try:
        return factory()
    except NativeError:
        raise
    except (OSError, RuntimeError) as error:
        error_line(f"native library unavailable: {error}")
        return None


def exit_code_for_status(status: int) -> int:
    if status == STATUS_NOT_FOUND:
        return EXIT_NOT_FOUND
    if status == STATUS_TIMEOUT:
        return EXIT_TIMEOUT
    if status == STATUS_UNSUPPORTED:
        return EXIT_DEVICE_ERROR
    return EXIT_ERROR


# -- raw command helpers ------------------------------------------------------------


def article(word: str) -> str:
    if word[:1] in "aeiou":
        return "an"
    return "a"


def required_flag(command_class: str, write_allowed: bool, dangerous_allowed: bool) -> str:
    """Return the flag needed to send this class, or "" when it is allowed."""

    gate = gate_for(command_class)
    if gate == REQUIRE_WRITE:
        if write_allowed or dangerous_allowed:
            return ""
        return "--write"
    if gate == REQUIRE_DANGEROUS:
        if dangerous_allowed:
            return ""
        return "--dangerous"
    return ""


def read_command_file(path: Path) -> list[str] | None:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        error_line(f"cannot read {path}: {error}")
        return None
    commands: list[str] = []
    for line in content.splitlines():
        text = line.strip()
        if not text or text.startswith(COMMENT_PREFIX):
            continue
        commands.append(text)
    return commands


def display_command(session: Session, text: str) -> str:
    if session.show_secrets:
        return text
    return redact_command(text)


def display_reply(session: Session, text: str) -> str:
    if session.show_secrets:
        return text
    return redact_reply(text)


def emit(session: Session, prepared: Prepared, status: int | None, name: str, reply: str) -> None:
    if session.json_output:
        record = {
            "command": display_command(session, prepared.text),
            "class": prepared.command_class,
            "status": status,
            "status_name": name,
            "reply": reply,
        }
        print(json.dumps(record))
        return
    if not reply:
        return
    sys.stdout.write(reply)
    if not reply.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()


def prepare(text: str, catalog: list[CatalogEntry],
            session: Session) -> tuple[Prepared | None, int]:
    checked = check_command(text, catalog)
    command_class = checked.command_class
    if checked.result == CHECK_INVALID:
        if session.json_output:
            emit(session, Prepared(text, CLASS_UNKNOWN), None, RECORD_INVALID, "")
        error_line(f"{display_command(session, text)!r}: {checked.problem}; nothing was sent")
        return None, EXIT_ERROR
    if checked.result == CHECK_REFUSED:
        if session.json_output:
            emit(session, Prepared(text, command_class), None, RECORD_REFUSED, "")
        error_line(f"refused {display_command(session, text)!r}: {checked.problem}. "
                   "Nothing was sent.")
        return None, EXIT_REFUSED
    flag = required_flag(command_class, session.write_allowed, session.dangerous_allowed)
    if flag:
        if session.json_output:
            emit(session, Prepared(text, command_class), None, RECORD_REFUSED, "")
        error_line(
            f"refused {display_command(session, text)!r}: it is {article(command_class)} "
            f"'{command_class}' command; "
            f"pass {flag} to send it. Nothing was sent."
        )
        return None, EXIT_REFUSED
    return Prepared(text, command_class), EXIT_OK


def ensure_snapshot(session: Session) -> int:
    """Create <data-root>/<mac>/snapshot.ini before the first write of this run."""

    if not session.snapshot_enabled:
        session.snapshot_done = True
        return EXIT_OK
    assert session.backend is not None
    outcome = snapshot_before_write(session.backend, session.data_root, session.mac)
    if outcome.result == SNAPSHOT_FAILED:
        error_line(f"snapshot before first write failed: {outcome.message}; nothing was written "
                   "(use --no-snapshot to skip)")
        if outcome.native_status == NO_NATIVE_STATUS:
            return EXIT_ERROR
        return exit_code_for_status(outcome.native_status)
    if outcome.result == SNAPSHOT_CREATED:
        print(f"{program_name()}: created snapshot {outcome.path} before the first write",
              file=sys.stderr)
    session.snapshot_done = True
    return EXIT_OK


def execute(session: Session, prepared: Prepared) -> int:
    if session.dry_run:
        if session.json_output:
            emit(session, prepared, None, RECORD_DRY_RUN, "")
        else:
            print(display_command(session, prepared.text))
        return EXIT_OK
    assert session.backend is not None
    if prepared.command_class != CLASS_QUERY and not session.snapshot_done:
        code = ensure_snapshot(session)
        if code != EXIT_OK:
            return code
    try:
        reply = session.backend.raw_query(session.mac, prepared.text,
                                          timeout_ms=session.timeout_ms, idle_ms=session.idle_ms)
    except NativeError as error:
        emit_failure(session, prepared, error.status, str(error))
        return exit_code_for_status(error.status)
    emit(session, prepared, reply.status, status_name(reply.status),
         display_reply(session, reply.text))
    if reply.status == STATUS_TIMEOUT:
        error_line(f"no reply to {display_command(session, prepared.text)!r}")
        return EXIT_TIMEOUT
    if reply_is_device_error(reply.text):
        error_line(f"device rejected {display_command(session, prepared.text)!r}")
        return EXIT_DEVICE_ERROR
    if reply.status == STATUS_BUFFER_TOO_SMALL:
        error_line("reply was truncated")
        return EXIT_ERROR
    return EXIT_OK


def emit_failure(session: Session, prepared: Prepared, status: int, message: str) -> None:
    if session.json_output:
        emit(session, prepared, status, status_name(status), "")
    error_line(message)


def make_session(arguments: argparse.Namespace, backend: Netbridge | None) -> Session:
    return Session(
        backend=backend,
        mac=arguments.mac,
        data_root=resolve_data_root(arguments),
        write_allowed=arguments.write,
        dangerous_allowed=arguments.dangerous,
        show_secrets=arguments.show_secrets,
        dry_run=arguments.dry_run,
        json_output=arguments.json,
        timeout_ms=arguments.timeout,
        idle_ms=arguments.idle,
        snapshot_enabled=not arguments.no_snapshot,
    )


# -- subcommands -------------------------------------------------------------------


def run_tui_window(window: "curses._CursesWindow", backend: Netbridge, data_root: Path,
                   preset_directory: Path, interface_name: str | None, mac: bytes | None) -> None:
    application = Application(UI(window), backend, data_root, preset_directory,
                              interface_name=interface_name, mac=mac)
    application.run()


def command_tui(arguments: argparse.Namespace, factory: BackendFactory) -> int:
    data_root = ensure_data_root(resolve_data_root(arguments))
    preset_directory = Path(__file__).with_name("presets")
    if arguments.preset_dir is not None:
        preset_directory = arguments.preset_dir
    backend = create_backend(factory)
    if backend is None:
        return EXIT_ERROR
    try:
        curses.wrapper(run_tui_window, backend, data_root, preset_directory.resolve(),
                       arguments.interface, arguments.mac)
    except curses.error:
        error_line("terminal does not support the required curses interface")
        return EXIT_ERROR
    return EXIT_OK


def command_interfaces(arguments: argparse.Namespace, factory: BackendFactory) -> int:
    backend = create_backend(factory)
    if backend is None:
        return EXIT_ERROR
    interfaces = backend.list_interfaces()
    if arguments.json:
        records = []
        for item in interfaces:
            records.append({
                "name": item.name, "address": item.address, "broadcast": item.broadcast,
            })
        print(json.dumps(records))
    if not interfaces:
        error_line("no eligible IPv4 broadcast interfaces were found")
        return EXIT_NOT_FOUND
    if arguments.json:
        return EXIT_OK
    for item in interfaces:
        print(f"{item.name}\t{item.address}\t{item.broadcast}")
    return EXIT_OK


def command_scan(arguments: argparse.Namespace, factory: BackendFactory) -> int:
    backend = create_backend(factory)
    if backend is None:
        return EXIT_ERROR
    try:
        backend.select_interface(arguments.interface)
        devices = backend.scan(timeout_ms=arguments.timeout)
    finally:
        backend.close()
    if arguments.json:
        records = []
        for device in devices:
            records.append({
                "mac": device.mac_text,
                "interface": device.interface,
                "response_address": device.response_address,
            })
        print(json.dumps(records))
        return EXIT_OK
    for device in devices:
        print(f"{device.mac_text}\t{device.interface}\t{device.response_address}")
    return EXIT_OK


def status_record(config: ManagedConfig) -> dict[str, object]:
    return {
        "mac": bytes(config.mac).hex(":"),
        "role": c_text(config.role),
        "connection_state": c_text(config.connection_state),
        "ssid": c_text(config.ssid),
        "encryption": c_text(config.encryption),
        "channels_khz": list(config_channels(config)),
        "bandwidth_mhz": config.bandwidth_mhz,
        "runtime_tx_power_dbm": config.runtime_tx_power_dbm,
        "stored_tx_power_dbm": config.stored_tx_power_dbm,
    }


def command_show(arguments: argparse.Namespace, factory: BackendFactory) -> int:
    backend = create_backend(factory)
    if backend is None:
        return EXIT_ERROR
    try:
        backend.select_interface(arguments.interface)
        config = backend.read_status(arguments.mac)
    finally:
        backend.close()
    config.psk = b""
    if arguments.json:
        print(json.dumps(status_record(config)))
        return EXIT_OK
    print(f"MAC: {arguments.mac.hex(':')}")
    print(f"Role: {c_text(config.role) or 'unknown'}")
    print(f"Connection: {c_text(config.connection_state) or 'unknown'}")
    print(f"SSID: {c_text(config.ssid) or '<empty>'}")
    print(f"Security: {c_text(config.encryption) or 'unknown'}")
    print(f"Channels: {format_channels(config_channels(config)) or 'unknown'} MHz")
    print(f"Bandwidth: {config.bandwidth_mhz} MHz")
    print(f"TX power: {tx_power_text(config)}")
    return EXIT_OK


def command_commands(arguments: argparse.Namespace, factory: BackendFactory) -> int:
    entries = load_catalog()
    selected: list[CatalogEntry] = []
    for entry in entries:
        if arguments.safety is None or entry.safety == arguments.safety:
            selected.append(entry)
    if arguments.json:
        records = []
        for entry in selected:
            records.append({
                "name": entry.name, "summary": entry.summary, "query": list(entry.query),
                "set": entry.set, "args": entry.args, "safety": entry.safety,
                "sensitive": entry.sensitive, "persists": entry.persists,
                "source": entry.source, "confidence": entry.confidence,
            })
        print(json.dumps(records, indent=2))
        return EXIT_OK
    for entry in selected:
        forms = " ".join(entry.query)
        if entry.set:
            forms = (forms + " " + entry.set).strip()
        marker = ""
        if entry.sensitive:
            marker = " [sensitive]"
        print(f"{entry.name:<14} {entry.safety:<6} {forms}")
        print(f"{'':<14} {entry.summary}{marker}")
    return EXIT_OK


def command_at(arguments: argparse.Namespace, factory: BackendFactory) -> int:
    texts = [text.strip() for text in arguments.commands]
    if arguments.file is not None:
        from_file = read_command_file(arguments.file)
        if from_file is None:
            return EXIT_ERROR
        texts.extend(from_file)
    if not texts:
        error_line("at: give at least one CMD or --file FILE")
        return EXIT_USAGE
    catalog = load_catalog()
    session = make_session(arguments, None)
    prepared_list: list[Prepared] = []
    for text in texts:
        prepared, code = prepare(text, catalog, session)
        if prepared is None:
            return code
        prepared_list.append(prepared)
    if not session.dry_run:
        session.backend = create_backend(factory)
        if session.backend is None:
            return EXIT_ERROR
        session.backend.select_interface(arguments.interface)
    try:
        for prepared in prepared_list:
            code = execute(session, prepared)
            if code != EXIT_OK:
                return code
    finally:
        if session.backend is not None:
            session.backend.close()
    return EXIT_OK


def command_shell(arguments: argparse.Namespace, factory: BackendFactory) -> int:
    catalog = load_catalog()
    session = make_session(arguments, None)
    if not session.dry_run:
        session.backend = create_backend(factory)
        if session.backend is None:
            return EXIT_ERROR
        session.backend.select_interface(arguments.interface)
    try:
        while True:
            sys.stderr.write(SHELL_PROMPT)
            sys.stderr.flush()
            line = sys.stdin.readline()
            if line == "":
                sys.stderr.write("\n")
                break
            text = line.strip()
            if not text or text.startswith(COMMENT_PREFIX):
                continue
            if text == "exit" or text == "quit":
                break
            prepared, _code = prepare(text, catalog, session)
            if prepared is None:
                continue
            execute(session, prepared)
    finally:
        if session.backend is not None:
            session.backend.close()
    return EXIT_OK


COMMANDS: dict[str | None, Callable[[argparse.Namespace, BackendFactory], int]] = {
    None: command_tui,
    "interfaces": command_interfaces,
    "scan": command_scan,
    "show": command_show,
    "commands": command_commands,
    "at": command_at,
    "shell": command_shell,
}


# -- error reporting ----------------------------------------------------------------


def write_private_file(path: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    descriptor = os.open(path, flags, DEBUG_LOG_MODE)
    try:
        os.fchmod(descriptor, DEBUG_LOG_MODE)
        data = text.encode("utf-8", "replace")
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
    finally:
        os.close(descriptor)


def report_unexpected(arguments: argparse.Namespace, error: BaseException) -> int:
    if not arguments.debug:
        error_line("unexpected internal error (details suppressed to protect secrets; "
                   "rerun with --debug to write a redacted log)")
        return EXIT_ERROR
    text = "".join(traceback.format_exception(type(error), error, error.__traceback__))
    text = HEX_RUN_RE.sub(REDACTED, text)
    try:
        data_root = ensure_data_root(resolve_data_root(arguments))
        path = data_root / f"debug-{os.getpid()}.log"
        write_private_file(path, text)
    except (OSError, StorageError) as log_error:
        error_line(f"unexpected internal error; debug log could not be written: {log_error}")
        return EXIT_ERROR
    error_line(f"unexpected internal error; redacted traceback written to {path}")
    return EXIT_ERROR


def main(argv: list[str] | None = None, backend_factory: BackendFactory | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    factory: BackendFactory = Netbridge
    if backend_factory is not None:
        factory = backend_factory
    handler = COMMANDS[arguments.command]
    try:
        return handler(arguments, factory)
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except NativeError as error:
        error_line(str(error))
        return exit_code_for_status(error.status)
    except (StorageError, CatalogError) as error:
        error_line(str(error))
        return EXIT_ERROR
    except Exception as error:  # noqa: BLE001 - last-resort handler that protects secrets
        return report_unexpected(arguments, error)


if __name__ == "__main__":
    raise SystemExit(main())
