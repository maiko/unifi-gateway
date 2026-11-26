"""Read bounded header observations on the approved Notify router path."""

import ctypes
import re
import socket
import struct
import sys
import time
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from uuid import UUID

MAX_OBSERVATIONS = 4096
_TCP_BASE_BYTES = 20
_HEADER_BYTES = 60 + _TCP_BASE_BYTES
_ETH_P_ALL = 0x0003
_ETH_P_IP = 0x0800
_PACKET_HOST = 0
_PACKET_OUTGOING = 4
_SOL_PACKET = 263
_PACKET_STATISTICS = 6
_PACKET_AUXDATA = 8
_SO_ATTACH_FILTER = 26
_TIMESTAMP_NS = 64  # Linux SO_TIMESTAMPNS_NEW and its timespec64 control message.
_GSO_TCP = 1 << 8
_CLOCK_SAMPLE_NS = 5_000_000
_CLOCK_TOLERANCE_NS = 10_000_000
_SETTLE_NS = 50_000_000
_TIMESPEC = struct.Struct("=qq")
_AUXDATA = struct.Struct("=IIIHHHH")
_STATS = struct.Struct("=II")
_IPV4 = struct.Struct("!BBHHHBBH4s4s")
_TCP = struct.Struct("!HHIIBB")
_CAPTURE_ID = re.compile(r"[0-9a-f]{32}", re.ASCII)


@dataclass(frozen=True, slots=True)
class NotifyScope:
    ingress_interface: str
    egress_interface: str
    initiator_ip: str
    responder_ip: str
    server_port: int
    signature_id: int


APPROVED_NOTIFY_SCOPE = NotifyScope(
    "eth3.110", "eth3.120", "192.168.110.2", "192.168.120.2", 18743, 1000043,
)


@dataclass(frozen=True, slots=True)
class TcpObservation:
    timestamp_ns: int
    interface: str
    direction: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    payload_len: int
    ip_id: int
    ttl: int


@dataclass(frozen=True, slots=True)
class NotifyCapture:
    boot_id: str
    capture_id: str
    start_ns: int
    end_ns: int
    dropped: int
    observations: tuple[TcpObservation, ...]
    complete: bool


@dataclass(frozen=True, slots=True)
class _Clock:
    realtime: int
    monotonic: int
    uncertainty: int


def _sample_clock():
    before = time.monotonic_ns()
    realtime = time.time_ns()
    after = time.monotonic_ns()
    return _Clock(realtime, (before + after) // 2, after - before)


def _coherent(before, after):
    elapsed = after.monotonic - before.monotonic
    delta = after.realtime - before.realtime
    return (
        max(before.uncertainty, after.uncertainty) <= _CLOCK_SAMPLE_NS
        and elapsed >= 0 and delta >= 0
        and abs(delta - elapsed) <= _CLOCK_TOLERANCE_NS + elapsed // 2_000
    )


def _boot_id():
    value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    if str(UUID(value)) != value:
        raise ValueError("Cannot establish the Notify capture boot")
    return value


def _direction(scope, interface, packet_type):
    if interface == scope.ingress_interface and packet_type == _PACKET_HOST:
        return "ingress"
    if interface == scope.egress_interface and packet_type == _PACKET_OUTGOING:
        return "egress"
    return None


def decode_tcp_header(
    packet, *, interface, packet_type, timestamp_ns, original_length, scope=APPROVED_NOTIFY_SCOPE,
):
    """Decode a cooked IPv4 header and omit all application bytes."""
    direction = _direction(scope, interface, packet_type)
    if direction is None:
        return None
    if len(packet) < _IPV4.size:
        raise ValueError("Truncated IPv4 header")
    ver_ihl, _, total, ip_id, fragment, ttl, proto, _, raw_src, raw_dst = _IPV4.unpack_from(packet)
    source, destination = str(IPv4Address(raw_src)), str(IPv4Address(raw_dst))
    if (ver_ihl >> 4, proto, source, destination) != (4, socket.IPPROTO_TCP, scope.initiator_ip, scope.responder_ip):
        return None
    ip_length = (ver_ihl & 0x0F) * 4
    if (
        ip_length < _IPV4.size or len(packet) < ip_length + _TCP_BASE_BYTES
        or total < ip_length + _TCP_BASE_BYTES or original_length < total
        or fragment & 0xBFFF or ttl == 0
    ):
        raise ValueError("Truncated or fragmented scoped IPv4 packet")
    sport, dport, seq, ack, offset, flags = _TCP.unpack_from(packet, ip_length)
    if dport != scope.server_port:
        return None
    tcp_length = (offset >> 4) * 4
    if (
        tcp_length < _TCP_BASE_BYTES or offset & 0x0F or sport == 0
        or total < ip_length + tcp_length
    ):
        raise ValueError("Truncated or ambiguous scoped TCP header")
    return TcpObservation(
        timestamp_ns, interface, direction, source, destination, sport, dport, seq, ack,
        flags, total - ip_length - tcp_length, ip_id, ttl,
    )


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("rows", ctypes.POINTER(_SockFilter))]


def _attach_filter(packet_socket, packet_type, scope):
    # Linux cooked sockets expose IPv4 bytes from offset zero. The negative
    # ancillary offsets read the skb protocol and packet direction.
    load_word, load_byte, load_indirect_half = 0x20, 0x30, 0x48
    ip_header_length, equal = 0xB1, 0x15
    load_constant, add_index, return_accumulator, return_constant = 0x00, 0x0C, 0x16, 0x06
    checks = (
        (load_word, 0xFFFFF000, _ETH_P_IP),
        (load_word, 0xFFFFF004, packet_type),
        (load_byte, 9, socket.IPPROTO_TCP),
        (load_word, 12, int(IPv4Address(scope.initiator_ip))),
        (load_word, 16, int(IPv4Address(scope.responder_ip))),
        (load_indirect_half, 2, scope.server_port),
    )
    program = []
    for code, offset, value in checks:
        if code == load_indirect_half:
            program.append((ip_header_length, 0, 0, 0))
        program.extend(((code, 0, 0, offset), (equal, 0, 0, value)))
    # X still holds IPv4 IHL in bytes. Return only that header and the TCP
    # base header. AUXDATA reports the original length and the IP/TCP headers
    # establish the amount of payload without making it available to userspace.
    program.extend((
        (load_constant, 0, 0, _TCP_BASE_BYTES), (add_index, 0, 0, 0),
        (return_accumulator, 0, 0, 0), (return_constant, 0, 0, 0),
    ))
    for index, (code, _, _, value) in enumerate(program):
        if code == equal:
            program[index] = (code, 0, len(program) - index - 2, value)
    rows = (_SockFilter * len(program))(*(_SockFilter(*row) for row in program))
    packet_socket.setsockopt(socket.SOL_SOCKET, _SO_ATTACH_FILTER, bytes(_SockFprog(len(rows), rows)))


def _open_socket(interface, packet_type, scope):
    if sys.platform != "linux" or not hasattr(socket, "AF_PACKET"):
        raise OSError("Notify header capture requires Linux AF_PACKET")
    packet_socket = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, 0)
    try:
        packet_socket.setblocking(False)
        packet_socket.setsockopt(socket.SOL_SOCKET, _TIMESTAMP_NS, 1)
        packet_socket.setsockopt(_SOL_PACKET, _PACKET_AUXDATA, 1)
        _attach_filter(packet_socket, packet_type, scope)
        # Outgoing packets reach the ETH_P_ALL tap; the filter narrows the
        # registered socket to the approved IPv4 TCP tuple before it queues.
        packet_socket.bind((interface, _ETH_P_ALL))
    except BaseException:
        packet_socket.close()
        raise
    return packet_socket


def _ancillary_value(items, level, kind, layout):
    matched = [data for item_level, item_kind, data in items if (item_level, item_kind) == (level, kind)]
    if len(matched) != 1 or len(matched[0]) != layout.size:
        raise ValueError("Missing or ambiguous Linux packet metadata")
    return layout.unpack(matched[0])


def _receive(packet_socket, interface, scope):
    packet, ancillary, flags, address = packet_socket.recvmsg(
        _HEADER_BYTES, socket.CMSG_SPACE(_TIMESPEC.size) + socket.CMSG_SPACE(_AUXDATA.size),
    )
    if (
        flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or not isinstance(address, tuple)
        or len(address) < 3 or address[:2] != (interface, _ETH_P_IP)
    ):
        raise ValueError("Truncated or inconsistent Linux packet evidence")
    seconds, nanos = _ancillary_value(ancillary, socket.SOL_SOCKET, _TIMESTAMP_NS, _TIMESPEC)
    status, original, captured, mac, network, _, _ = _ancillary_value(
        ancillary, _SOL_PACKET, _PACKET_AUXDATA, _AUXDATA,
    )
    if (
        seconds <= 0 or not 0 <= nanos < 10**9 or status & _GSO_TCP
        or mac != 0 or network != 0 or captured != len(packet) or original < captured
    ):
        raise ValueError("Ambiguous Linux packet timestamp, segment, or length")
    return decode_tcp_header(
        packet, interface=interface, packet_type=address[2],
        timestamp_ns=seconds * 10**9 + nanos, original_length=original, scope=scope,
    )


class _NotifyReader:
    def __init__(self, scope, capture_id, boot_id, endpoints, start):
        self._scope = scope
        self._capture_id = capture_id
        self._boot_id = boot_id
        self._endpoints = endpoints
        self._start = self._last = start
        self._end = start.realtime
        self._rows = []
        self._dropped = 0
        self._complete = start.uncertainty <= _CLOCK_SAMPLE_NS
        self._snapshots = 0
        self._closed = False

    def _drain(self, interface, packet_socket, remaining):
        for _ in range(remaining):
            try:
                row = _receive(packet_socket, interface, self._scope)
            except BlockingIOError:
                return remaining
            except (OSError, ValueError):
                self._complete = False
                return remaining
            remaining -= 1
            if row is None or (not self._snapshots and row.timestamp_ns < self._start.realtime):
                continue
            if (self._snapshots and row.timestamp_ns <= self._end) or len(self._rows) >= MAX_OBSERVATIONS:
                self._complete = False
                continue
            self._rows.append(row)
        self._complete = False
        return remaining

    def snapshot(self):
        """Drain a bounded amount and expose only rows inside the finalized window."""
        if self._closed:
            raise RuntimeError("Notify capture has closed")
        before = _sample_clock()
        remaining = MAX_OBSERVATIONS + 1
        for interface, index, packet_socket in self._endpoints:
            remaining = self._drain(interface, packet_socket, remaining)
            try:
                packets, drops = _STATS.unpack(
                    packet_socket.getsockopt(_SOL_PACKET, _PACKET_STATISTICS, _STATS.size)
                )
                self._dropped += drops
                if drops > packets or socket.if_nametoindex(interface) != index:
                    self._complete = False
            except (OSError, struct.error):
                self._complete = False
        after = _sample_clock()
        if (
            not _coherent(self._last, before) or not _coherent(before, after) or self._dropped
            or any(row.timestamp_ns > after.realtime + _CLOCK_TOLERANCE_NS for row in self._rows)
        ):
            self._complete = False
        self._last = after
        self._end = max(self._end, before.realtime - _SETTLE_NS)
        self._snapshots += 1
        visible = tuple(sorted(
            (row for row in self._rows if row.timestamp_ns <= self._end),
            key=lambda row: row.timestamp_ns,
        ))
        return NotifyCapture(
            self._boot_id, self._capture_id, self._start.realtime, self._end,
            self._dropped, visible, self._complete and self._end > self._start.realtime,
        )


@contextmanager
def open_notify_capture(scope=APPROVED_NOTIFY_SCOPE, *, capture_id):
    """Open a read-only observer for one trusted engine generation."""
    if (
        type(scope) is not NotifyScope or scope != APPROVED_NOTIFY_SCOPE
        or type(capture_id) is not str or _CAPTURE_ID.fullmatch(capture_id) is None
    ):
        raise ValueError("Notify capture requires the exact approved scope and generation")
    boot_id = _boot_id()
    with ExitStack() as stack:
        endpoints = []
        for interface, packet_type in (
            (scope.ingress_interface, _PACKET_HOST), (scope.egress_interface, _PACKET_OUTGOING),
        ):
            index = socket.if_nametoindex(interface)
            packet_socket = _open_socket(interface, packet_type, scope)
            stack.callback(packet_socket.close)
            if socket.if_nametoindex(interface) != index:
                raise OSError("Notify capture interface changed during open")
            endpoints.append((interface, index, packet_socket))
        reader = _NotifyReader(scope, capture_id, boot_id, endpoints, _sample_clock())
        try:
            yield reader
        finally:
            reader._closed = True
