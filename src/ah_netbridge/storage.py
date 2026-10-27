"""Protected snapshots, reusable PSKs, and named full configurations."""

from __future__ import annotations

import configparser
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .native import (
    BANDWIDTHS_MHZ, FIELD_ALL, MAC_LENGTH, MAX_CHANNELS, PSK_HEX_LENGTH, TX_POWER_MAX_DBM,
    TX_POWER_MIN_DBM, ManagedConfig, c_bytes, c_text, valid_channel_khz,
)

MAC_DIRECTORY_RE = re.compile(r"^[0-9a-f]{2}(?:-[0-9a-f]{2}){5}$")
CONFIG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")
ENCRYPTION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,30}")
HEX_CHARACTERS = "0123456789abcdefABCDEF"
HEX_BYTES = HEX_CHARACTERS.encode("ascii")
SSID_MAX_BYTES = 32
# ManagedConfig role/connection_state are char[32]: 31 bytes plus NUL.
IDENTITY_TEXT_MAX_BYTES = 31
PSK_PREVIEW_CHARS = 4
SCHEMA_VERSION = "1"
# The PSK shared by the paired units, as 64 lowercase hex characters (mode 0600).
SHARED_PSK_NAME = "shared.psk"
# stored_tx_power_dbm is the saved setting (WNBCFG tx_power) that restore applies.
# runtime_tx_power_dbm is the live AT+TXPOWER? value, informational only: the firmware's
# PA power control can run above the setting, so any int8 is accepted.
RUNTIME_TX_POWER_MIN_DBM = -128
RUNTIME_TX_POWER_MAX_DBM = 127
DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
PERMISSION_MASK = 0o777
STATE_DIRECTORY_NAME = "ah-netbridge"
IDENTITY_COMMENT = "# Informational only: identity fields are never applied to a device."
SECTION_FORMAT = "format"
SECTION_IDENTITY = "identity"
SECTION_MANAGED = "managed"
IDENTITY_KEYS = ("mac",)
MANAGED_KEYS = (
    "ssid_hex", "psk", "encryption", "channels_khz", "bandwidth_mhz",
    "stored_tx_power_dbm", "runtime_tx_power_dbm",
)
FORMAT_KEYS = ("schema_version", "name")


class StorageError(RuntimeError):
    pass


@dataclass(frozen=True)
class SavedConfiguration:
    name: str
    path: Path
    source_mac: bytes
    config: ManagedConfig


def default_data_root() -> Path:
    override = os.environ.get("AHNB_DATA_ROOT", "")
    if override:
        return Path(override).expanduser()
    state_home = os.environ.get("XDG_STATE_HOME", "")
    if state_home:
        return Path(state_home).expanduser() / STATE_DIRECTORY_NAME
    return Path.home() / ".local" / "state" / STATE_DIRECTORY_NAME


def ensure_data_root(path: Path) -> Path:
    if os.path.lexists(path):
        if not path.is_dir():
            raise StorageError(f"Data root is not a directory: {path}")
        return path
    try:
        path.mkdir(mode=DIRECTORY_MODE, parents=True)
        path.chmod(DIRECTORY_MODE)
    except FileExistsError:
        if not path.is_dir():
            raise StorageError(f"Data root is not a directory: {path}")
    except OSError as error:
        raise StorageError(f"Data root could not be created: {path} ({error.strerror})") from error
    return path


def _mode_of(path: Path) -> int:
    try:
        return path.stat().st_mode & PERMISSION_MASK
    except OSError as error:
        raise StorageError(f"{path.name} metadata could not be read ({error.strerror})") from error


def mac_directory_name(mac: bytes) -> str:
    if len(mac) != MAC_LENGTH:
        raise ValueError("MAC must contain six bytes")
    return "-".join(f"{value:02x}" for value in mac)


def device_directory(data_root: Path, mac: bytes) -> Path:
    path = data_root / mac_directory_name(mac)
    created = False
    try:
        path.mkdir(mode=DIRECTORY_MODE)
        created = True
    except FileExistsError:
        pass
    except OSError as error:
        raise StorageError(
            f"Device data directory could not be created: {path} ({error.strerror})"
        ) from error
    if path.is_symlink() or not path.is_dir():
        raise StorageError("Device data path is not a directory")
    if created:
        try:
            path.chmod(DIRECTORY_MODE)
        except OSError as error:
            raise StorageError(
                f"Device data directory mode could not be set: {path} ({error.strerror})"
            ) from error
    mode = _mode_of(path)
    if mode != DIRECTORY_MODE:
        raise StorageError(f"Device data directory must have mode 0700 (found {mode:04o})")
    return path


def snapshot_path(data_root: Path, mac: bytes) -> Path:
    return data_root / mac_directory_name(mac) / "snapshot.ini"


def shared_psk_path(data_root: Path) -> Path:
    return data_root / SHARED_PSK_NAME


def shared_psk_exists(data_root: Path) -> bool:
    return os.path.lexists(shared_psk_path(data_root))


def psk_preview(psk: str) -> str:
    if len(psk) != PSK_HEX_LENGTH:
        raise ValueError("PSK must be exactly 64 hexadecimal characters")
    return f"{psk[:PSK_PREVIEW_CHARS]},…,{psk[-PSK_PREVIEW_CHARS:]}"


def load_shared_psk(data_root: Path) -> str:
    path = shared_psk_path(data_root)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise StorageError(f"No {SHARED_PSK_NAME} exists in the data root") from error
    if path.is_symlink() or not path.is_file():
        raise StorageError(f"{SHARED_PSK_NAME} must be a regular file, not a symlink")
    mode = metadata.st_mode & PERMISSION_MASK
    if mode != FILE_MODE:
        raise StorageError(f"{SHARED_PSK_NAME} must have mode 0600 (found {mode:04o}); "
                           f"run chmod 600 {SHARED_PSK_NAME}")
    try:
        content = path.read_bytes()
    except OSError as error:
        raise StorageError(f"{SHARED_PSK_NAME} could not be read") from error
    if content.endswith(b"\n"):
        content = content[:-1]
    if not _valid_psk_bytes(content):
        raise StorageError(f"{SHARED_PSK_NAME} must contain exactly 64 hexadecimal characters and "
                           "an optional final newline")
    return content.decode("ascii").lower()


def write_shared_psk(data_root: Path, psk: str) -> Path:
    if psk == "" or not _valid_psk(psk):
        raise ValueError("PSK must be exactly 64 hexadecimal characters")
    if not data_root.is_dir() or data_root.is_symlink():
        raise StorageError("Data root must be an existing regular directory")
    path = shared_psk_path(data_root)
    temp = data_root / f".{SHARED_PSK_NAME}.tmp-{os.getpid()}-{os.urandom(8).hex()}"
    descriptor = -1
    replaced = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        descriptor = os.open(temp, flags, FILE_MODE)
        os.fchmod(descriptor, FILE_MODE)
        content = psk.lower().encode("ascii") + b"\n"
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temp, path)
        replaced = True
        directory_fd = os.open(data_root, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as error:
        raise StorageError(f"{SHARED_PSK_NAME} could not be written atomically") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not replaced:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass
    return path


def _ini_line(key: str, value: str) -> str:
    # Values must stay on one line; configparser would otherwise fold them.
    if "\n" in value or "\r" in value:
        raise StorageError(f"Configuration value for {key} contains a line break")
    return f"{key} = {value}\n"


def _config_problem(config: ManagedConfig) -> str:
    """Return "" when the config can be written and loaded back, else the reason."""

    if config.present_mask != FIELD_ALL:
        return "is incomplete"
    if config.channel_count < 1 or config.channel_count > MAX_CHANNELS:
        return "has an invalid channel count"
    channels = []
    for index in range(config.channel_count):
        value = int(config.channels_khz[index])
        if not valid_channel_khz(value) or value in channels:
            return f"has an invalid channel ({value} kHz)"
        channels.append(value)
    if not _valid_ssid(c_bytes(config.ssid)):
        return "has an invalid SSID"
    if not _valid_psk(c_text(config.psk)):
        return "has a malformed PSK"
    if not ENCRYPTION_RE.fullmatch(c_text(config.encryption)):
        return "has an unsupported encryption mode"
    if config.bandwidth_mhz not in BANDWIDTHS_MHZ:
        return f"has an invalid bandwidth ({config.bandwidth_mhz} MHz)"
    if not _valid_tx_power(config.stored_tx_power_dbm):
        return f"has an invalid stored TX power ({config.stored_tx_power_dbm} dBm)"
    if not _valid_runtime_tx_power(config.runtime_tx_power_dbm):
        return f"has an invalid runtime TX power ({config.runtime_tx_power_dbm} dBm)"
    return ""


def _config_text(config: ManagedConfig, saved_name: str | None = None) -> str:
    # Validate first: snapshots are immutable, so an unloadable one must never be written.
    problem = _config_problem(config)
    if problem:
        raise StorageError(f"Managed configuration {problem}")
    channel_texts = []
    for index in range(config.channel_count):
        channel_texts.append(str(config.channels_khz[index]))
    mac_texts = []
    for index in range(MAC_LENGTH):
        mac_texts.append(f"{config.mac[index]:02x}")
    lines = []
    if saved_name is not None:
        lines.append(f"[{SECTION_FORMAT}]\n")
        lines.append(_ini_line("schema_version", SCHEMA_VERSION))
        lines.append(_ini_line("name", saved_name))
        lines.append("\n")
    lines.append(IDENTITY_COMMENT + "\n")
    lines.append(f"[{SECTION_IDENTITY}]\n")
    lines.append(_ini_line("mac", ":".join(mac_texts)))
    lines.append(_ini_line("role", c_text(config.role)))
    lines.append(_ini_line("connection_state", c_text(config.connection_state)))
    lines.append("\n")
    lines.append(f"[{SECTION_MANAGED}]\n")
    lines.append(_ini_line("ssid_hex", c_bytes(config.ssid).hex()))
    lines.append(_ini_line("psk", c_text(config.psk)))
    lines.append(_ini_line("encryption", c_text(config.encryption)))
    lines.append(_ini_line("channels_khz", ",".join(channel_texts)))
    lines.append(_ini_line("bandwidth_mhz", str(config.bandwidth_mhz)))
    lines.append(_ini_line("stored_tx_power_dbm", str(config.stored_tx_power_dbm)))
    lines.append(_ini_line("runtime_tx_power_dbm", str(config.runtime_tx_power_dbm)))
    lines.append("\n")
    return "".join(lines)


def _atomic_create(path: Path, content: str) -> None:
    directory = path.parent
    temp_name = f".{path.name}.tmp-{os.getpid()}-{os.urandom(8).hex()}"
    temp = directory / temp_name
    descriptor = -1
    linked = False
    try:
        descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
        os.fchmod(descriptor, FILE_MODE)
        data = content.encode("utf-8")
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temp, path)
        linked = True
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileExistsError as error:
        raise StorageError(f"Protected file already exists: {path.name}") from error
    except OSError as error:
        raise StorageError(f"Protected file could not be created: {path.name}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
    if not linked:
        raise StorageError("Protected file could not be created")


def create_snapshot(data_root: Path, config: ManagedConfig) -> Path:
    content = _config_text(config)
    directory = device_directory(data_root, bytes(config.mac))
    path = directory / "snapshot.ini"
    _atomic_create(path, content)
    if _mode_of(path) != FILE_MODE:
        raise StorageError("Snapshot permissions are not 0600")
    return path


def _valid_ssid(ssid: bytes) -> bool:
    if len(ssid) < 1 or len(ssid) > SSID_MAX_BYTES:
        return False
    if b"\0" in ssid or b"\n" in ssid or b"\r" in ssid:
        return False
    return True


def _valid_psk(psk: str) -> bool:
    if psk == "":
        return True
    if len(psk) != PSK_HEX_LENGTH:
        return False
    for character in psk:
        if character not in HEX_CHARACTERS:
            return False
    return True


def _valid_psk_bytes(content: bytes) -> bool:
    if len(content) != PSK_HEX_LENGTH:
        return False
    for byte in content:
        if byte not in HEX_BYTES:
            return False
    return True


def _valid_tx_power(value: int) -> bool:
    return TX_POWER_MIN_DBM <= value <= TX_POWER_MAX_DBM


def _valid_runtime_tx_power(value: int) -> bool:
    return RUNTIME_TX_POWER_MIN_DBM <= value <= RUNTIME_TX_POWER_MAX_DBM


def _parse_int(text: str) -> int | None:
    try:
        return int(text)
    except ValueError:
        return None


def _parse_hex(text: str) -> bytes | None:
    try:
        return bytes.fromhex(text)
    except ValueError:
        return None


def _parse_channels(text: str) -> tuple[list[int], str]:
    """Return (channels, "") or ([], problem) for a channels_khz value."""

    channels: list[int] = []
    for item in text.split(","):
        value = _parse_int(item)
        if value is None:
            return [], "has a malformed channel list"
        channels.append(value)
    if len(channels) < 1 or len(channels) > MAX_CHANNELS:
        return [], "has an invalid channel count"
    if len(set(channels)) != len(channels):
        return [], "has duplicate channels"
    for value in channels:
        if not valid_channel_khz(value):
            return [], f"has an invalid channel ({value} kHz)"
    return channels, ""


def _missing_key(parser: configparser.ConfigParser, section: str,
                 keys: tuple[str, ...]) -> str:
    if not parser.has_section(section):
        return f"is missing the [{section}] section"
    for key in keys:
        if not parser.has_option(section, key):
            return f"is missing [{section}] {key}"
    return ""


def _parse_config(
    parser: configparser.ConfigParser, expected_mac: bytes | None
) -> tuple[ManagedConfig | None, bytes, str]:
    """Return (config, source MAC, "") or (None, b"", problem) for a parsed INI file."""

    problem = _missing_key(parser, SECTION_IDENTITY, IDENTITY_KEYS)
    if not problem:
        problem = _missing_key(parser, SECTION_MANAGED, MANAGED_KEYS)
    if problem:
        return None, b"", problem
    identity = parser[SECTION_IDENTITY]
    managed = parser[SECTION_MANAGED]

    source_mac = _parse_hex(identity["mac"].replace(":", ""))
    if source_mac is None or len(source_mac) != MAC_LENGTH:
        return None, b"", "has an invalid MAC"
    if expected_mac is not None and source_mac != expected_mac:
        return None, b"", f"belongs to MAC {source_mac.hex(':')}, not {expected_mac.hex(':')}"
    role = identity.get("role", "").encode("utf-8")
    connection_state = identity.get("connection_state", "").encode("utf-8")
    if len(role) > IDENTITY_TEXT_MAX_BYTES or len(connection_state) > IDENTITY_TEXT_MAX_BYTES:
        return None, b"", "has an overlong role or connection state"

    ssid = _parse_hex(managed["ssid_hex"])
    if ssid is None or not _valid_ssid(ssid):
        return None, b"", "has an invalid SSID"
    psk = managed["psk"]
    if not _valid_psk(psk):
        return None, b"", "has a malformed PSK"
    encryption = managed["encryption"]
    if not ENCRYPTION_RE.fullmatch(encryption):
        return None, b"", f"has an unsupported encryption mode ({encryption})"
    channels, problem = _parse_channels(managed["channels_khz"])
    if problem:
        return None, b"", problem
    bandwidth = _parse_int(managed["bandwidth_mhz"])
    if bandwidth is None or bandwidth not in BANDWIDTHS_MHZ:
        return None, b"", f"has an invalid bandwidth ({managed['bandwidth_mhz']} MHz)"
    runtime_tx_power = _parse_int(managed["runtime_tx_power_dbm"])
    if runtime_tx_power is None or not _valid_runtime_tx_power(runtime_tx_power):
        return None, b"", (
            f"has an invalid runtime TX power ({managed['runtime_tx_power_dbm']} dBm)"
        )
    stored_tx_power = _parse_int(managed["stored_tx_power_dbm"])
    if stored_tx_power is None or not _valid_tx_power(stored_tx_power):
        return None, b"", (
            f"has an invalid stored TX power ({managed['stored_tx_power_dbm']} dBm)"
        )

    config = ManagedConfig()
    target_mac = source_mac
    if expected_mac is not None:
        target_mac = expected_mac
    for index in range(MAC_LENGTH):
        config.mac[index] = target_mac[index]
    config.role = role
    config.connection_state = connection_state
    config.ssid = ssid
    config.psk = psk.encode("ascii")
    config.encryption = encryption.encode("ascii")
    config.channel_count = len(channels)
    for index in range(len(channels)):
        config.channels_khz[index] = channels[index]
    config.bandwidth_mhz = bandwidth
    config.stored_tx_power_dbm = stored_tx_power
    config.runtime_tx_power_dbm = runtime_tx_power
    config.present_mask = FIELD_ALL
    return config, source_mac, ""


def _load_config_file(
    path: Path, expected_mac: bytes | None = None
) -> tuple[ManagedConfig, bytes, configparser.ConfigParser]:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise StorageError(f"No usable mode-0600 configuration exists: {path.name}") from error
    except OSError as error:
        raise StorageError(f"Configuration could not be read: {path.name}") from error
    mode = metadata.st_mode & PERMISSION_MASK
    if path.is_symlink() or not path.is_file() or mode != FILE_MODE:
        raise StorageError(f"Configuration must be a regular mode-0600 file: {path.name}")
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with path.open("r", encoding="utf-8") as stream:
            parser.read_file(stream)
    except (UnicodeError, configparser.Error) as error:
        raise StorageError(f"Configuration {path.name} is not a valid INI file") from error
    except OSError as error:
        raise StorageError(f"Configuration could not be read: {path.name}") from error
    config, source_mac, problem = _parse_config(parser, expected_mac)
    if config is None:
        raise StorageError(f"Configuration {path.name} {problem}")
    return config, source_mac, parser


def load_snapshot(data_root: Path, mac: bytes) -> ManagedConfig:
    config, _source_mac, _parser = _load_config_file(snapshot_path(data_root, mac), mac)
    return config


def configuration_directory(data_root: Path, *, create: bool = False) -> Path:
    if not data_root.is_dir() or data_root.is_symlink():
        raise StorageError("Data root must be an existing regular directory")
    path = data_root / "configs"
    if create:
        try:
            path.mkdir(mode=DIRECTORY_MODE)
        except FileExistsError:
            pass
        except OSError as error:
            raise StorageError("configs directory could not be created") from error
    if os.path.lexists(path):
        if path.is_symlink() or not path.is_dir():
            raise StorageError("configs must be a regular directory, not a symlink")
        mode = _mode_of(path)
        if mode != DIRECTORY_MODE:
            raise StorageError(f"configs directory must have mode 0700 (found {mode:04o})")
    return path


def normalize_configuration_name(name: str) -> str:
    normalized = name.strip()
    if normalized.lower().endswith(".ini"):
        normalized = normalized[:-4].rstrip()
    if not CONFIG_NAME_RE.fullmatch(normalized) or ".." in normalized:
        raise ValueError("Configuration name must be 1–64 characters using letters, digits, spaces, '.', '_' or '-'.")
    return normalized


def create_saved_configuration(data_root: Path, name: str, config: ManagedConfig) -> Path:
    normalized = normalize_configuration_name(name)
    content = _config_text(config, normalized)
    directory = configuration_directory(data_root, create=True)
    path = directory / f"{normalized}.ini"
    _atomic_create(path, content)
    if _mode_of(path) != FILE_MODE:
        raise StorageError("Saved configuration permissions are not 0600")
    return path


def _casefold_name(path: Path) -> str:
    return path.name.casefold()


def _format_problem(parser: configparser.ConfigParser, path: Path) -> tuple[str, str]:
    """Return (name, "") or ("", problem) for the [format] section of a saved file."""

    problem = _missing_key(parser, SECTION_FORMAT, FORMAT_KEYS)
    if problem:
        return "", problem
    section = parser[SECTION_FORMAT]
    if section["schema_version"] != SCHEMA_VERSION:
        return "", f"has an unsupported schema version ({section['schema_version']})"
    name = section["name"]
    if not CONFIG_NAME_RE.fullmatch(name) or ".." in name:
        return "", "has an invalid name"
    if path.name != f"{name}.ini":
        return "", f"must be named '{name}.ini' to match its name field"
    return name, ""


def _load_saved_configuration(path: Path, target_mac: bytes) -> SavedConfiguration:
    config, source_mac, parser = _load_config_file(path)
    name, problem = _format_problem(parser, path)
    if problem:
        raise StorageError(f"Saved configuration {path.name} {problem}")
    for index in range(MAC_LENGTH):
        config.mac[index] = target_mac[index]
    return SavedConfiguration(name, path, source_mac, config)


def list_saved_configurations(
    data_root: Path, target_mac: bytes
) -> tuple[list[SavedConfiguration], list[tuple[str, str]]]:
    """Return (valid configurations, [(filename, error)]) for every *.ini file."""

    if len(target_mac) != MAC_LENGTH:
        raise ValueError("MAC must contain six bytes")
    directory = configuration_directory(data_root)
    saved: list[SavedConfiguration] = []
    errors: list[tuple[str, str]] = []
    if not directory.exists():
        return saved, errors
    for path in sorted(directory.glob("*.ini"), key=_casefold_name):
        try:
            saved.append(_load_saved_configuration(path, target_mac))
        except StorageError as error:
            errors.append((path.name, str(error)))
    return saved, errors
