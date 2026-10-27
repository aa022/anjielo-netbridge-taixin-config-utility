"""Portable Python-owned interface enumeration and NetAT discovery."""

from __future__ import annotations

import ctypes
import secrets
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Callable

NETAT_PORT = 56789
HEADER_SIZE = 15
SCAN_REQUEST = 1
SCAN_RESPONSE = 2
IFF_UP = 0x1
IFF_BROADCAST = 0x2
IFF_LOOPBACK = 0x8
PLATFORM_DARWIN = "darwin"
# <netinet/in.h> values; Python's socket module does not export IP_BOUND_IF.
DARWIN_IP_BOUND_IF = 25
LINUX_IP_PKTINFO = 8
IN_PKTINFO_SIZE = 12
SOCKADDR_STORAGE_PREFIX = 16
MAX_SCAN_DEVICES = 128
RECEIVE_BUFFER_SIZE = 8192


class NetworkError(RuntimeError):
    pass


@dataclass(frozen=True)
class InterfaceInfo:
    name: str
    address: str
    broadcast: str


@dataclass(frozen=True)
class DeviceInfo:
    mac: bytes
    interface: str
    response_address: str

    @property
    def mac_text(self) -> str:
        return ":".join(f"{byte:02x}" for byte in self.mac)


class _SockAddr(ctypes.Structure):
    _fields_ = [("data", ctypes.c_ubyte * 16)]


class _IfAddrs(ctypes.Structure):
    pass


_IfAddrs._fields_ = [
    ("ifa_next", ctypes.POINTER(_IfAddrs)),
    ("ifa_name", ctypes.c_char_p),
    ("ifa_flags", ctypes.c_uint),
    ("ifa_addr", ctypes.POINTER(_SockAddr)),
    ("ifa_netmask", ctypes.POINTER(_SockAddr)),
    ("ifa_broadaddr", ctypes.POINTER(_SockAddr)),
    ("ifa_data", ctypes.c_void_p),
]


def _family(raw: bytes, platform: str) -> int:
    # BSD sockaddr starts with sa_len, then an 8-bit family; Linux has a 16-bit family.
    if platform == PLATFORM_DARWIN:
        return raw[1]
    return int.from_bytes(raw[:2], sys.byteorder)


def _ipv4(raw: bytes) -> str:
    if len(raw) < 8:
        raise NetworkError("Operating system returned a truncated IPv4 address")
    return socket.inet_ntoa(raw[4:8])


def list_interfaces(
    *, library: ctypes.CDLL | None = None, platform: str | None = None
) -> list[InterfaceInfo]:
    """Return eligible UP, non-loopback IPv4 broadcast interfaces."""

    if platform is None:
        platform = sys.platform
    libc = library
    if libc is None:
        libc = ctypes.CDLL(None, use_errno=True)
    libc.getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(_IfAddrs))]
    libc.getifaddrs.restype = ctypes.c_int
    libc.freeifaddrs.argtypes = [ctypes.POINTER(_IfAddrs)]
    head = ctypes.POINTER(_IfAddrs)()
    if libc.getifaddrs(ctypes.byref(head)) != 0:
        error = ctypes.get_errno()
        raise NetworkError(f"Unable to enumerate network interfaces (errno {error})")
    found: list[InterfaceInfo] = []
    seen: set[tuple[str, str, str]] = set()
    try:
        cursor = head
        while cursor:
            item = cursor.contents
            cursor = item.ifa_next
            if (
                not item.ifa_name
                or not item.ifa_addr
                or not item.ifa_broadaddr
                or not item.ifa_flags & IFF_UP
                or not item.ifa_flags & IFF_BROADCAST
                or item.ifa_flags & IFF_LOOPBACK
            ):
                continue
            address_raw = ctypes.string_at(item.ifa_addr, SOCKADDR_STORAGE_PREFIX)
            if _family(address_raw, platform) != socket.AF_INET:
                continue
            broadcast_raw = ctypes.string_at(item.ifa_broadaddr, SOCKADDR_STORAGE_PREFIX)
            try:
                name = item.ifa_name.decode("utf-8")
                address = _ipv4(address_raw)
                broadcast = _ipv4(broadcast_raw)
            except (UnicodeError, OSError) as error:
                raise NetworkError("Operating system returned malformed interface data") from error
            key = (name, address, broadcast)
            if key not in seen:
                seen.add(key)
                found.append(InterfaceInfo(*key))
    finally:
        libc.freeifaddrs(head)
    return found


def build_scan_request(cookie: bytes) -> bytes:
    if len(cookie) != 6:
        raise ValueError("NetAT cookie must contain six bytes")
    return bytes((SCAN_REQUEST, 0, 0)) + b"\xff" * 6 + cookie


def parse_scan_response(packet: bytes, cookie: bytes) -> bytes | None:
    if len(packet) < HEADER_SIZE or len(cookie) != 6:
        return None
    declared = int.from_bytes(packet[1:3], "big")
    mac = packet[9:15]
    if (
        packet[0] != SCAN_RESPONSE
        or declared != len(packet) - HEADER_SIZE
        or packet[3:9] != cookie
        or len(mac) != 6
        or mac == b"\0" * 6
        or mac[0] & 1
    ):
        return None
    return mac


def _open_discovery_socket(interface: InterfaceInfo, platform: str) -> socket.socket:
    descriptor: socket.socket | None = None
    try:
        descriptor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        descriptor.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        descriptor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        descriptor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        index = socket.if_nametoindex(interface.name)
        if platform == PLATFORM_DARWIN:
            descriptor.setsockopt(socket.IPPROTO_IP, DARWIN_IP_BOUND_IF, index)
        else:
            descriptor.setsockopt(socket.IPPROTO_IP, LINUX_IP_PKTINFO, 1)
        descriptor.bind(("0.0.0.0", NETAT_PORT))
        return descriptor
    except OSError as error:
        if descriptor is not None:
            try:
                descriptor.close()
            except OSError:
                pass
        raise NetworkError("Unable to open discovery socket on the selected interface") from error


def _send_scan(descriptor: socket.socket, interface: InterfaceInfo,
               packet: bytes, platform: str) -> None:
    # Firmware variants respond inconsistently to limited versus directed
    # broadcast. Send the same cookie-bound request to both, while
    # IP_BOUND_IF/IP_PKTINFO confines both datagrams to the selected domain.
    destinations = [
        ("255.255.255.255", NETAT_PORT),
        (interface.broadcast, NETAT_PORT),
    ]
    try:
        if platform == PLATFORM_DARWIN:
            for destination in destinations:
                descriptor.sendto(packet, destination)
        else:
            index = socket.if_nametoindex(interface.name)
            packet_info = struct.pack("=I4s4s", index, socket.inet_aton(interface.address), b"\0" * 4)
            for destination in destinations:
                ancillary = [(socket.IPPROTO_IP, LINUX_IP_PKTINFO, packet_info)]
                descriptor.sendmsg([packet], ancillary, 0, destination)
    except OSError as error:
        raise NetworkError("Unable to send NetAT discovery on the selected interface") from error


def _receive(descriptor: socket.socket, platform: str, expected_index: int) -> tuple[bytes, tuple[str, int]] | None:
    if platform == PLATFORM_DARWIN:
        packet, source = descriptor.recvfrom(RECEIVE_BUFFER_SIZE)
        return packet, source
    packet, ancillary, _flags, source = descriptor.recvmsg(
        RECEIVE_BUFFER_SIZE, socket.CMSG_SPACE(IN_PKTINFO_SIZE)
    )
    matching_interface = False
    for level, kind, data in ancillary:
        if level == socket.IPPROTO_IP and kind == LINUX_IP_PKTINFO and len(data) >= 4:
            matching_interface = struct.unpack_from("=I", data)[0] == expected_index
    if not matching_interface:
        return None
    return packet, source


def scan_interface(
    interface: InterfaceInfo,
    timeout_ms: int = 1500,
    target_mac: bytes | None = None,
    *,
    socket_factory: Callable[[InterfaceInfo, str], socket.socket] | None = None,
    platform: str | None = None,
) -> list[DeviceInfo]:
    """Broadcast one NetAT scan and return exact-MAC-deduplicated replies.

    With target_mac set, stop listening as soon as that exact MAC answers."""

    if timeout_ms <= 0:
        raise ValueError("Discovery timeout must be positive")
    if platform is None:
        platform = sys.platform
    cookie = secrets.token_bytes(6)
    packet = build_scan_request(cookie)
    if socket_factory is None:
        socket_factory = _open_discovery_socket
    descriptor = socket_factory(interface, platform)
    devices: dict[bytes, DeviceInfo] = {}
    deadline = time.monotonic() + timeout_ms / 1000
    expected_index = socket.if_nametoindex(interface.name)
    try:
        _send_scan(descriptor, interface, packet, platform)
        while len(devices) < MAX_SCAN_DEVICES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            descriptor.settimeout(remaining)
            try:
                received = _receive(descriptor, platform, expected_index)
            except TimeoutError:
                break
            except OSError as error:
                raise NetworkError("Unable to receive NetAT discovery responses") from error
            if received is None:
                continue
            response, source = received
            if source[1] != NETAT_PORT:
                continue
            mac = parse_scan_response(response, cookie)
            if mac is not None and mac not in devices:
                devices[mac] = DeviceInfo(mac, interface.name, source[0])
            if target_mac is not None and mac == target_mac:
                break
    finally:
        descriptor.close()
    return list(devices.values())
