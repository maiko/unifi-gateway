import socket
import struct
from dataclasses import asdict, replace
from ipaddress import IPv4Address

import pytest


@pytest.fixture
def module():
    from inspection import notify_capture

    return notify_capture


def datagram(*, port=18743, ttl=64, fragment=0, data_offset=5, payload=b"sensitive-content"):
    source = IPv4Address("192.168.110.2").packed
    destination = IPv4Address("192.168.120.2").packed
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 34, fragment,
                     ttl, 6, 0, source, destination)
    tcp = struct.pack("!HHIIBBHHH", 49000, port, 11, 22, data_offset << 4,
                      0x18, 4096, 0, 0)
    return ip + tcp + payload


def decode(module, packet, *, interface="eth3.110", packet_type=0, original_length=None, timestamp=1_000):
    return module.decode_tcp_header(
        packet, interface=interface, packet_type=packet_type, timestamp_ns=timestamp,
        original_length=len(packet) if original_length is None else original_length,
    )


def test_cooked_header_preserves_only_exact_tcp_and_kernel_direction(module):
    packet = datagram()
    ingress = decode(module, packet[:40], original_length=len(packet))
    outgoing = decode(module, datagram(ttl=63), interface="eth3.120", packet_type=4)

    assert asdict(ingress) == {
        "interface": "eth3.110", "direction": "ingress", "timestamp_ns": 1000,
        "src_ip": "192.168.110.2", "dst_ip": "192.168.120.2", "src_port": 49000,
        "dst_port": 18743, "seq": 11, "ack": 22, "flags": 0x18,
        "payload_len": len(b"sensitive-content"), "ip_id": 34, "ttl": 64,
    }
    assert (outgoing.direction, outgoing.ttl) == ("egress", 63)
    assert decode(module, packet, interface="eth3.120", packet_type=0) is None
    assert decode(module, packet, interface="eth3.110", packet_type=4) is None
    assert decode(module, datagram(port=443)) is None


@pytest.mark.parametrize("kind", ["fragment", "bad-tcp-length", "short-header", "short-wire"])
def test_scoped_truncated_or_ambiguous_header_is_rejected(module, kind):
    packet = datagram(
        fragment=0x2000 if kind == "fragment" else 0,
        data_offset=3 if kind == "bad-tcp-length" else 5,
    )
    original = len(packet) - int(kind == "short-wire")
    if kind == "short-header":
        packet = packet[:31]
    with pytest.raises(ValueError):
        decode(module, packet, original_length=original)


class Socket:
    def __init__(self, frames=(), dropped=0):
        self.frames = list(frames)
        self.dropped = dropped
        self.closed = False

    def recvmsg(self, *_args):
        if not self.frames:
            raise BlockingIOError
        return self.frames.pop(0)

    def getsockopt(self, *_args):
        dropped, self.dropped = self.dropped, 0
        return struct.pack("=II", dropped, dropped)

    def close(self):
        self.closed = True


def frame(module, data, timestamp, *, interface="eth3.110", packet_type=0, aux_status=1, flags=0):
    seconds, ns = divmod(timestamp, 10**9)
    captured = data[: (data[0] & 0xF) * 4 + 20]
    ancillary = [
        (socket.SOL_SOCKET, module._TIMESTAMP_NS, struct.pack("=qq", seconds, ns)),
        (module._SOL_PACKET, module._PACKET_AUXDATA,
         struct.pack("=IIIHHHH", aux_status, len(data), len(captured), 0, 0, 0, 0)),
    ]
    return captured, ancillary, flags, (interface, 0x0800, packet_type, 1, b"")


def open_fake(module, monkeypatch, left, right, samples):
    sockets = {"eth3.110": left, "eth3.120": right}
    monkeypatch.setattr(module, "_open_socket", lambda interface, _packet_type, _scope: sockets[interface])
    monkeypatch.setattr(module, "_boot_id", lambda: "12345678-1234-1234-1234-123456789abc")
    monkeypatch.setattr(module.socket, "if_nametoindex", lambda name: tuple(sockets).index(name) + 1)
    ticks = iter(module._Clock(*sample) for sample in samples)
    monkeypatch.setattr(module, "_sample_clock", lambda: next(ticks))
    return module.open_notify_capture(capture_id="1" * 32)


def test_snapshot_orders_two_sides_and_accumulates_kernel_loss(module, monkeypatch):
    start, snapshot = 1_000_000_000, 1_500_000_000
    a = Socket([frame(module, datagram(), start + 1_000)])
    b = Socket([frame(module, datagram(ttl=63), start + 2_000, interface="eth3.120", packet_type=4)])
    clocks = [(start, 0, 0), (snapshot, snapshot-start, 0), (snapshot, snapshot-start, 0),
              (snapshot+1, snapshot-start+1, 0), (snapshot+1, snapshot-start+1, 0),
              (snapshot+2, snapshot-start+2, 0), (snapshot+2, snapshot-start+2, 0)]
    with open_fake(module, monkeypatch, a, b, clocks) as capture:
        first = capture.snapshot()
        assert first.complete and first.dropped == 0 and first.capture_id == "1"*32
        assert first.start_ns == start and first.end_ns <= snapshot
        assert [row.direction for row in first.observations] == ["ingress", "egress"]
        b.dropped = 2
        assert not capture.snapshot().complete
        later = capture.snapshot()
        assert not later.complete and later.dropped == 2
    assert a.closed and b.closed


@pytest.mark.parametrize("problem", ["clock", "ancillary-truncation", "segmentation", "row-bound"])
def test_clock_unknown_metadata_and_bounds_permanently_invalidate(module, monkeypatch, problem):
    start = 1_000_000_000
    observation = frame(
        module, datagram(), start+1_000,
        flags=socket.MSG_CTRUNC if problem == "ancillary-truncation" else 0,
        aux_status=0x101 if problem == "segmentation" else 1,
    )
    a = Socket([observation, observation] if problem == "row-bound" else [observation])
    b = Socket()
    if problem == "row-bound":
        monkeypatch.setattr(module, "MAX_OBSERVATIONS", 1)
    end = start + 500_000_000
    clock_delta = 400_000_000 if problem == "clock" else 0
    samples = [(start, 0, 0), (end, end-start-clock_delta, 0), (end, end-start-clock_delta, 0)]
    with open_fake(module, monkeypatch, a, b, samples) as capture:
        report = capture.snapshot()
    assert report.complete is False
    assert len(report.observations) <= module.MAX_OBSERVATIONS


def test_unapproved_scope_and_invalid_capture_id_are_refused_before_open(module, monkeypatch):
    def unexpected(*_args):
        pytest.fail("opened a packet socket for an unapproved capture")
    monkeypatch.setattr(module, "_open_socket", unexpected)
    for scope, token in (
        (replace(module.APPROVED_NOTIFY_SCOPE, server_port=443), "1"*32),
        (module.APPROVED_NOTIFY_SCOPE, "1"*64),
    ):
        with pytest.raises(ValueError), module.open_notify_capture(scope, capture_id=token):
            pass


def test_kernel_program_strips_payload_and_rejects_nonmatching_direction_and_port(module):
    class Filter:
        def setsockopt(self, _level, _name, encoded):
            program = module._SockFprog.from_buffer_copy(encoded)
            self.rows = tuple(
                (row.code, row.jt, row.jf, row.k)
                for row in program.rows[:program.length]
            )

    target = Filter()
    module._attach_filter(target, module._PACKET_OUTGOING, module.APPROVED_NOTIFY_SCOPE)

    def evaluate(packet, *, packet_type=4, protocol=0x0800):
        anc = {0xFFFFF000: protocol, 0xFFFFF004: packet_type}
        address = index = instruction = 0
        while instruction < len(target.rows):
            code, yes, no, value = target.rows[instruction]
            instruction += 1
            if code == 0x20:
                address = anc[value] if value in anc else int.from_bytes(packet[value:value+4], "big")
            elif code == 0x30:
                address = packet[value]
            elif code == 0xB1:
                index = (packet[value] & 0xF) * 4
            elif code == 0x48:
                address = int.from_bytes(packet[index+value:index+value+2], "big")
            elif code == 0x15:
                instruction += yes if address == value else no
            elif code == 0x00:
                address = value
            elif code == 0x0C:
                address += index
            elif code == 0x16:
                return address
            elif code == 0x06:
                return value
            else:
                pytest.fail(f"unexpected filter instruction {code}")
        pytest.fail("unterminated filter")

    packet = datagram()
    assert evaluate(packet) == 40
    assert not evaluate(packet, packet_type=0)
    assert not evaluate(packet, protocol=0x86DD)
    assert not evaluate(datagram(port=8443))


def test_deliberate_header_capture_can_omit_options_but_not_missing_wire_bytes(module):
    packet = datagram(data_offset=6, payload=b"\x01\x01\x01\x01example")
    short_capture = packet[:40]
    row = decode(module, short_capture, original_length=len(packet))
    assert row.payload_len == len(b"example")
    with pytest.raises(ValueError):
        decode(module, short_capture, original_length=42)
