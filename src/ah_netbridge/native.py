"""Typed ctypes bindings for the deliberately narrow libtaixinnet ABI."""

from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .network import DeviceInfo, InterfaceInfo, NetworkError
from .network import list_interfaces as python_list_interfaces
from .network import scan_interface

ABI_VERSION = 0x00020200
MAX_CHANNELS = 16
STRUCT_SIZE_COUNT = 6
MAC_LENGTH = 6

STATUS_OK = 0
STATUS_INVALID_ARGUMENT = 1
STATUS_SYSTEM_ERROR = 2
STATUS_TIMEOUT = 3
STATUS_PROTOCOL_ERROR = 4
STATUS_NOT_FOUND = 5
STATUS_UNSUPPORTED = 6
STATUS_VERIFY_FAILED = 7
STATUS_PARTIAL = 8
STATUS_BUFFER_TOO_SMALL = 9

OK = STATUS_OK
NOT_FOUND = STATUS_NOT_FOUND

# Machine names (JSON output) and human wording (messages), indexed by status.
STATUS_NAMES = (
    "OK",
    "INVALID_ARGUMENT",
    "SYSTEM_ERROR",
    "TIMEOUT",
    "PROTOCOL_ERROR",
    "NOT_FOUND",
    "UNSUPPORTED",
    "VERIFY_FAILED",
    "PARTIAL",
    "BUFFER_TOO_SMALL",
)
STATUS_TEXTS = (
    "ok",
    "invalid argument",
    "system error",
    "timeout",
    "protocol error",
    "not found",
    "unsupported",
    "verification failed",
    "partial",
    "buffer too small",
)

CAP_CORE = 1 << 0
CAP_CREDENTIALS = 1 << 1
CAP_RADIO = 1 << 2
CAP_CONNECTION_STATE = 1 << 8
CAP_STORED_TX_POWER = 1 << 9

FIELD_SSID = 1 << 0
FIELD_PSK = 1 << 1
FIELD_ENCRYPTION = 1 << 2
FIELD_CHANNELS = 1 << 3
FIELD_BANDWIDTH = 1 << 4
FIELD_TX_POWER = 1 << 5
FIELD_ALL = 0x3F

# OperationResult.failed_stage values.
STAGE_VALIDATE = 0
STAGE_PROBE = 2
STAGE_WRITE = 3
STAGE_VERIFY = 4

CHANNEL_MIN_KHZ = 700000
CHANNEL_MAX_KHZ = 1000000
CHANNEL_STEP_KHZ = 100
BANDWIDTHS_MHZ = (1, 2, 4, 8)
TX_POWER_MIN_DBM = 6  # wnb firmware v1.6 AT+TXPOWER= accepts 6..20
TX_POWER_MAX_DBM = 20

PSK_HEX_LENGTH = 64
PSK_BUFFER_SIZE = PSK_HEX_LENGTH + 1
HEX_DIGITS = "0123456789abcdef"

RAW_COMMAND_MAX_BYTES = 1024
RAW_PRINTABLE_MIN = 0x20
RAW_PRINTABLE_MAX = 0x7E
RAW_REPLY_CAPACITY = 16384
UINT32_MAX = 0xFFFFFFFF
REDISCOVER_TIMEOUT_MS = 1200


def status_name(status: int) -> str:
    if 0 <= status < len(STATUS_NAMES):
        return STATUS_NAMES[status]
    return f"STATUS_{status}"


def status_text(status: int) -> str:
    if 0 <= status < len(STATUS_TEXTS):
        return STATUS_TEXTS[status]
    return f"status {status}"


def valid_channel_khz(value: int) -> bool:
    if type(value) is not int:
        return False
    if value < CHANNEL_MIN_KHZ or value > CHANNEL_MAX_KHZ:
        return False
    return value % CHANNEL_STEP_KHZ == 0


def c_bytes(field: bytes | ctypes.Array[ctypes.c_char]) -> bytes:
    return bytes(field).split(b"\0", 1)[0]


def c_text(field: bytes | ctypes.Array[ctypes.c_char]) -> str:
    return c_bytes(field).decode("utf-8", "replace")


class Endpoint(ctypes.Structure):
    _fields_ = [
        ("interface_name", ctypes.c_char * 64),
        ("ipv4_address", ctypes.c_char * 16),
        ("broadcast_address", ctypes.c_char * 16),
    ]


class Target(ctypes.Structure):
    _fields_ = [
        ("mac", ctypes.c_uint8 * 6),
        ("reserved", ctypes.c_uint8 * 2),
        ("response_address", ctypes.c_char * 16),
    ]


class Capabilities(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint32),
        ("role", ctypes.c_char * 32),
        ("connection_state", ctypes.c_char * 32),
    ]


class ManagedConfig(ctypes.Structure):
    _fields_ = [
        ("mac", ctypes.c_uint8 * 6),
        ("reserved", ctypes.c_uint8 * 2),
        ("role", ctypes.c_char * 32),
        ("connection_state", ctypes.c_char * 32),
        ("ssid", ctypes.c_char * 129),
        ("psk", ctypes.c_char * 65),
        ("encryption", ctypes.c_char * 32),
        ("channels_khz", ctypes.c_uint32 * MAX_CHANNELS),
        ("channel_count", ctypes.c_uint32),
        ("bandwidth_mhz", ctypes.c_uint32),
        ("stored_tx_power_dbm", ctypes.c_int32),
        ("runtime_tx_power_dbm", ctypes.c_int32),
        ("present_mask", ctypes.c_uint32),
    ]


class RadioConfig(ctypes.Structure):
    _fields_ = [
        ("channels_khz", ctypes.c_uint32 * MAX_CHANNELS),
        ("channel_count", ctypes.c_uint32),
        ("bandwidth_mhz", ctypes.c_uint32),
        ("tx_power_dbm", ctypes.c_int32),
    ]


class OperationResult(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int32),
        ("failed_stage", ctypes.c_uint32),
        ("failed_field", ctypes.c_uint32),
        ("applied_mask", ctypes.c_uint32),
        ("verified_mask", ctypes.c_uint32),
        ("message", ctypes.c_char * 192),
    ]


# Order matches ahnb_struct_sizes(): endpoint, target, capabilities,
# managed_config, radio_config, operation_result.
ABI_STRUCTS = (Endpoint, Target, Capabilities, ManagedConfig, RadioConfig, OperationResult)
StructSizes = ctypes.c_uint32 * STRUCT_SIZE_COUNT


class NativeError(RuntimeError):
    """A sanitized native status. This exception never contains a PSK."""

    def __init__(self, status: int, message: str, result: OperationResult | None = None):
        self.status = status
        self.result = result
        super().__init__(message)


@dataclass(frozen=True)
class RawReply:
    status: int
    raw: bytes
    text: str


def _library_path() -> Path:
    override = os.environ.get("AHNB_NATIVE_LIBRARY")
    if override:
        return Path(override)
    suffix = ".dylib" if sys.platform == "darwin" else ".so"
    return Path(__file__).with_name("_native") / f"libtaixinnet{suffix}"


def configure_abi(lib: ctypes.CDLL) -> None:
    handle = ctypes.c_void_p
    result = ctypes.POINTER(OperationResult)
    lib.ahnb_struct_sizes.argtypes = [ctypes.POINTER(StructSizes)]
    lib.ahnb_struct_sizes.restype = None
    lib.ahnb_open.argtypes = [
        ctypes.POINTER(Endpoint), ctypes.POINTER(Target),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_int),
    ]
    lib.ahnb_open.restype = ctypes.c_int
    lib.ahnb_close.argtypes = [handle]
    lib.ahnb_close.restype = None
    lib.ahnb_probe.argtypes = [handle, ctypes.POINTER(Capabilities)]
    lib.ahnb_probe.restype = ctypes.c_int
    lib.ahnb_read_psk.argtypes = [handle, ctypes.POINTER(ctypes.c_char)]
    lib.ahnb_read_psk.restype = ctypes.c_int
    lib.ahnb_read_managed_config.argtypes = [handle, ctypes.POINTER(ManagedConfig)]
    lib.ahnb_read_managed_config.restype = ctypes.c_int
    lib.ahnb_read_status.argtypes = [handle, ctypes.POINTER(ManagedConfig)]
    lib.ahnb_read_status.restype = ctypes.c_int
    lib.ahnb_raw_query.argtypes = [
        handle, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.ahnb_raw_query.restype = ctypes.c_int
    lib.ahnb_apply_credentials.argtypes = [handle, ctypes.c_char_p, ctypes.c_char_p, result]
    lib.ahnb_apply_credentials.restype = ctypes.c_int
    lib.ahnb_apply_ssid.argtypes = [handle, ctypes.c_char_p, result]
    lib.ahnb_apply_ssid.restype = ctypes.c_int
    lib.ahnb_apply_psk.argtypes = [handle, ctypes.c_char_p, result]
    lib.ahnb_apply_psk.restype = ctypes.c_int
    lib.ahnb_apply_radio.argtypes = [handle, ctypes.POINTER(RadioConfig), result]
    lib.ahnb_apply_radio.restype = ctypes.c_int
    lib.ahnb_restore_managed_config.argtypes = [handle, ctypes.POINTER(ManagedConfig), result]
    lib.ahnb_restore_managed_config.restype = ctypes.c_int
    lib.ahnb_status_string.argtypes = [ctypes.c_int]
    lib.ahnb_status_string.restype = ctypes.c_char_p


def check_abi_version(lib: ctypes.CDLL) -> None:
    # Checked before any other symbol is bound so an old library fails cleanly.
    lib.ahnb_abi_version.argtypes = []
    lib.ahnb_abi_version.restype = ctypes.c_uint32
    actual = int(lib.ahnb_abi_version())
    if actual != ABI_VERSION:
        raise RuntimeError(f"Native ABI mismatch: expected {ABI_VERSION:#x}, got {actual:#x}")


def check_struct_sizes(lib: ctypes.CDLL) -> None:
    sizes = StructSizes()
    lib.ahnb_struct_sizes(ctypes.byref(sizes))
    for index in range(STRUCT_SIZE_COUNT):
        structure = ABI_STRUCTS[index]
        expected = ctypes.sizeof(structure)
        if int(sizes[index]) != expected:
            raise RuntimeError(
                f"Native ABI mismatch: {structure.__name__} is {int(sizes[index])} bytes "
                f"in the library but {expected} bytes in Python"
            )


def validate_radio(channels: list[int], bandwidth_mhz: int, tx_power_dbm: int) -> None:
    if not 1 <= len(channels) <= MAX_CHANNELS:
        raise ValueError(f"Radio configuration needs 1–{MAX_CHANNELS} channels")
    for value in channels:
        if not valid_channel_khz(value):
            raise ValueError(
                f"Channel {value} kHz is outside {CHANNEL_MIN_KHZ}–{CHANNEL_MAX_KHZ} kHz "
                f"or not a multiple of {CHANNEL_STEP_KHZ} kHz"
            )
    if len(set(channels)) != len(channels):
        raise ValueError("Channels must not be duplicated")
    if type(bandwidth_mhz) is not int or bandwidth_mhz not in BANDWIDTHS_MHZ:
        raise ValueError("Bandwidth must be 1, 2, 4 or 8 MHz")
    if type(tx_power_dbm) is not int:
        raise ValueError("TX power must be an integer")
    if tx_power_dbm < TX_POWER_MIN_DBM or tx_power_dbm > TX_POWER_MAX_DBM:
        raise ValueError(f"TX power must be {TX_POWER_MIN_DBM}–{TX_POWER_MAX_DBM} dBm")


def raw_command_problem(command: str) -> str:
    """Return "" for a sendable raw command, else the reason it cannot be sent."""

    if not command:
        return "empty command"
    try:
        encoded = command.encode("ascii")
    except UnicodeError:
        return "commands must be printable ASCII"
    if len(encoded) > RAW_COMMAND_MAX_BYTES:
        return f"commands are limited to {RAW_COMMAND_MAX_BYTES} bytes"
    for byte in encoded:
        if byte < RAW_PRINTABLE_MIN or byte > RAW_PRINTABLE_MAX:
            return "commands must be printable ASCII without control characters"
    return ""


def validate_raw_command(command: str) -> bytes | None:
    """Return the wire bytes for a raw command, or None when it is not sendable."""

    if raw_command_problem(command):
        return None
    return command.encode("ascii")


def _validate_wait(value: int, label: str) -> None:
    if type(value) is not int or value <= 0 or value > UINT32_MAX:
        raise ValueError(f"{label} must be a positive integer number of milliseconds")


class Netbridge:
    def __init__(
        self,
        library: ctypes.CDLL | None = None,
        *,
        interface_provider: Callable[[], list[InterfaceInfo]] = python_list_interfaces,
        scanner: Callable[[InterfaceInfo, int, bytes | None], list[DeviceInfo]] = scan_interface,
    ):
        if library is None:
            library = ctypes.CDLL(str(_library_path()))
        self.lib = library
        self.interface_provider = interface_provider
        self.scanner = scanner
        self.interface: InterfaceInfo | None = None
        check_abi_version(self.lib)
        configure_abi(self.lib)
        check_struct_sizes(self.lib)

    def _fail(self, status: int, detail: str = "") -> NativeError:
        if detail:
            return NativeError(status, detail)
        return NativeError(status, f"Native operation failed: {status_text(status)}.")

    def list_interfaces(self) -> list[InterfaceInfo]:
        try:
            return self.interface_provider()
        except NetworkError as error:
            raise NativeError(STATUS_SYSTEM_ERROR, str(error)) from error

    def select_interface(self, interface: InterfaceInfo | str) -> None:
        self.interface = None
        if not isinstance(interface, str):
            self.interface = interface
            return
        for item in self.list_interfaces():
            if item.name == interface:
                self.interface = item
                return
        raise NativeError(
            STATUS_NOT_FOUND,
            f"Interface {interface!r} is not an up, non-loopback IPv4 broadcast interface; "
            "run 'ahnb interfaces' to list eligible ones.",
        )

    def close(self) -> None:
        self.interface = None

    def __enter__(self) -> "Netbridge":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def scan(self, timeout_ms: int = 1500) -> list[DeviceInfo]:
        if self.interface is None:
            raise NativeError(STATUS_INVALID_ARGUMENT, "Select an interface before discovery.")
        try:
            devices = self.scanner(self.interface, timeout_ms, None)
        except NetworkError as error:
            raise NativeError(STATUS_SYSTEM_ERROR, str(error)) from error
        if not devices:
            raise NativeError(
                STATUS_NOT_FOUND, "No TaiXin devices responded on the selected broadcast domain."
            )
        return devices

    def _rediscover(self, mac: bytes) -> DeviceInfo:
        if len(mac) != MAC_LENGTH:
            raise ValueError("MAC must contain six bytes")
        if self.interface is None:
            raise NativeError(STATUS_INVALID_ARGUMENT, "Select an interface before discovery.")
        try:
            devices = self.scanner(self.interface, REDISCOVER_TIMEOUT_MS, mac)
        except NetworkError as error:
            raise NativeError(STATUS_SYSTEM_ERROR, str(error)) from error
        for device in devices:
            if device.mac == mac:
                return device
        raise NativeError(
            STATUS_NOT_FOUND, "Selected device was not rediscovered; no settings were written."
        )

    def _open_target(self, device: DeviceInfo) -> ctypes.c_void_p:
        if self.interface is None:
            raise NativeError(STATUS_INVALID_ARGUMENT, "Selected interface is unavailable.")
        endpoint = Endpoint()
        target = Target()
        try:
            endpoint.interface_name = self.interface.name.encode("utf-8")
            endpoint.ipv4_address = self.interface.address.encode("ascii")
            endpoint.broadcast_address = self.interface.broadcast.encode("ascii")
            target.response_address = device.response_address.encode("ascii")
        except (UnicodeError, ValueError) as error:
            raise NativeError(
                STATUS_INVALID_ARGUMENT, "Selected network endpoint is invalid."
            ) from error
        for index in range(MAC_LENGTH):
            target.mac[index] = device.mac[index]
        handle = ctypes.c_void_p()
        os_errno = ctypes.c_int(0)
        status = self.lib.ahnb_open(
            ctypes.byref(endpoint), ctypes.byref(target), ctypes.byref(handle),
            ctypes.byref(os_errno),
        )
        if status == STATUS_OK:
            return handle
        if status == STATUS_SYSTEM_ERROR and os_errno.value != 0:
            raise NativeError(
                status,
                f"Unable to open the selected interface: {os.strerror(os_errno.value)} "
                f"(errno {os_errno.value}).",
            )
        raise self._fail(status)

    def _connect(self, mac: bytes) -> ctypes.c_void_p:
        device = self._rediscover(mac)
        return self._open_target(device)

    def _close_target(self, handle: ctypes.c_void_p) -> None:
        if handle.value:
            self.lib.ahnb_close(handle)

    def probe(self, mac: bytes) -> Capabilities:
        handle = self._connect(mac)
        try:
            output = Capabilities()
            status = self.lib.ahnb_probe(handle, ctypes.byref(output))
        finally:
            self._close_target(handle)
        if status != STATUS_OK:
            raise self._fail(status)
        return output

    def read_config(self, mac: bytes) -> ManagedConfig:
        handle = self._connect(mac)
        try:
            output = ManagedConfig()
            status = self.lib.ahnb_read_managed_config(handle, ctypes.byref(output))
        finally:
            self._close_target(handle)
        if status != STATUS_OK:
            raise self._fail(status)
        return output

    def read_status(self, mac: bytes) -> ManagedConfig:
        handle = self._connect(mac)
        try:
            output = ManagedConfig()
            status = self.lib.ahnb_read_status(handle, ctypes.byref(output))
        finally:
            self._close_target(handle)
        if status != STATUS_OK:
            raise self._fail(status)
        return output

    def read_psk(self, mac: bytes) -> str:
        handle = self._connect(mac)
        output = ctypes.create_string_buffer(PSK_BUFFER_SIZE)
        try:
            status = self.lib.ahnb_read_psk(handle, output)
            if status != STATUS_OK:
                raise self._fail(status)
            psk = output.value.decode("ascii", "replace").lower()
            well_formed = len(psk) == PSK_HEX_LENGTH
            for character in psk:
                if character not in HEX_DIGITS:
                    well_formed = False
            if not well_formed:
                raise NativeError(
                    STATUS_PROTOCOL_ERROR, "Device returned a malformed protected PSK."
                )
            return psk
        finally:
            ctypes.memset(output, 0, ctypes.sizeof(output))
            self._close_target(handle)

    def raw_query(self, mac: bytes, command: str, timeout_ms: int = 1500,
                  idle_ms: int = 250) -> RawReply:
        encoded = validate_raw_command(command)
        if encoded is None:
            raise NativeError(
                STATUS_INVALID_ARGUMENT,
                f"Command must be 1–{RAW_COMMAND_MAX_BYTES} printable ASCII characters.",
            )
        _validate_wait(timeout_ms, "Timeout")
        _validate_wait(idle_ms, "Idle wait")
        handle = self._connect(mac)
        response = ctypes.create_string_buffer(RAW_REPLY_CAPACITY)
        length = ctypes.c_size_t(0)
        try:
            status = self.lib.ahnb_raw_query(
                handle, encoded, timeout_ms, idle_ms, response, RAW_REPLY_CAPACITY,
                ctypes.byref(length),
            )
            used = length.value
            if used > RAW_REPLY_CAPACITY - 1:
                used = RAW_REPLY_CAPACITY - 1
            raw = response.raw[:used]
        finally:
            ctypes.memset(response, 0, ctypes.sizeof(response))
            self._close_target(handle)
        if status == STATUS_TIMEOUT:
            return RawReply(status, b"", "")
        if status != STATUS_OK and status != STATUS_BUFFER_TOO_SMALL:
            raise self._fail(status)
        return RawReply(status, raw, raw.decode("utf-8", "replace"))

    def _finish(self, status: int, result: OperationResult) -> OperationResult:
        if status != STATUS_OK:
            message = c_text(result.message)
            if not message:
                message = f"Native operation failed: {status_text(status)}."
            raise NativeError(status, message, result)
        return result

    def apply_credentials(self, mac: bytes, ssid: str, psk: str) -> OperationResult:
        ssid_bytes = ssid.encode("utf-8")
        psk_bytes = psk.encode("ascii")
        handle = self._connect(mac)
        result = OperationResult()
        try:
            status = self.lib.ahnb_apply_credentials(
                handle, ssid_bytes, psk_bytes, ctypes.byref(result)
            )
        finally:
            self._close_target(handle)
        return self._finish(status, result)

    def apply_ssid(self, mac: bytes, ssid: str) -> OperationResult:
        ssid_bytes = ssid.encode("utf-8")
        handle = self._connect(mac)
        result = OperationResult()
        try:
            status = self.lib.ahnb_apply_ssid(handle, ssid_bytes, ctypes.byref(result))
        finally:
            self._close_target(handle)
        return self._finish(status, result)

    def apply_psk(self, mac: bytes, psk: str) -> OperationResult:
        psk_bytes = psk.encode("ascii")
        handle = self._connect(mac)
        result = OperationResult()
        try:
            status = self.lib.ahnb_apply_psk(handle, psk_bytes, ctypes.byref(result))
        finally:
            self._close_target(handle)
        return self._finish(status, result)

    def apply_radio(self, mac: bytes, channels_khz: Iterable[int], bandwidth_mhz: int,
                    tx_power_dbm: int) -> OperationResult:
        values = list(channels_khz)
        validate_radio(values, bandwidth_mhz, tx_power_dbm)
        config = RadioConfig()
        config.channel_count = len(values)
        config.bandwidth_mhz = bandwidth_mhz
        config.tx_power_dbm = tx_power_dbm
        for index in range(len(values)):
            config.channels_khz[index] = values[index]
        handle = self._connect(mac)
        result = OperationResult()
        try:
            status = self.lib.ahnb_apply_radio(handle, ctypes.byref(config), ctypes.byref(result))
        finally:
            self._close_target(handle)
        return self._finish(status, result)

    def restore(self, mac: bytes, config: ManagedConfig) -> OperationResult:
        handle = self._connect(mac)
        result = OperationResult()
        try:
            status = self.lib.ahnb_restore_managed_config(
                handle, ctypes.byref(config), ctypes.byref(result)
            )
        finally:
            self._close_target(handle)
        return self._finish(status, result)


def capability_text(capabilities: Capabilities) -> str:
    names = []
    if capabilities.flags & CAP_CREDENTIALS:
        names.append("SSID/PSK")
    if capabilities.flags & CAP_RADIO:
        names.append("radio")
    if not names:
        return "no managed workflows"
    return ", ".join(names)
