"""Read complete header-only capture windows and emit verified TCP observations.

Each JSONL record pairs one conntrack-tools 1.4.7 XML DESTROY report, two
scoped tcpdump egress captures with final loss counters, and both endpoint
receipts. A trusted capture supervisor supplies matching begin/end markers
only after the capture children have stopped cleanly. The source expects
the two tcpdump directions to use exact tuple filters and `-Q out`.
"""

import argparse
import json
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import BinaryIO
from uuid import UUID
from xml.etree import ElementTree

from inspection.connection_flow import validate_connection_flow_evidence

MAX_RECORD_BYTES = 131_072
_MAX_CAPTURE_CHARS = 32_768
_MAX_PACKETS = 128
_MAX_WINDOW_NS = 300 * 1_000_000_000
_MAX_INTEGER = (1 << 63) - 1
_TCP = 6
_WINDOW_FIELDS = {
    "begin",
    "end",
    "conntrack",
    "original_capture",
    "reply_capture",
    "verified_application",
}
_MARKER_FIELDS = {"collector_run_id", "router_boot_id", "unix_ns"}
_ENDPOINT_FIELDS = {
    "initiator": {
        "peer",
        "request_bytes",
        "received_bytes",
        "observed_server_eof",
        "time_ns",
    },
    "responder": {
        "peer",
        "received_bytes",
        "reply_bytes",
        "observed_client_eof",
        "time_ns",
    },
}
_CONNTRACK_REPORT = "conntrack v1.4.7 (conntrack-tools): 1 flow events have been shown."
_ADDRESS = r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})"
_IP_LINE = re.compile(
    r"([0-9]{1,10})\.([0-9]{6}) IP \(tos 0x[0-9a-f]{1,2}, ttl [0-9]{1,3}, "
    r"id [0-9]{1,5}, offset 0, flags \[DF\], proto TCP \(6\), length ([0-9]{1,5})\)"
)
_TCP_LINE = re.compile(
    rf"[ \t]+{_ADDRESS}\.([0-9]{{1,5}}) > "
    rf"{_ADDRESS}\.([0-9]{{1,5}}): Flags \[([.FSRPUEW]+)\], .*?length ([0-9]{{1,5}})"
)


@dataclass(frozen=True, slots=True)
class FlowScope:
    source_address: str
    source_port: int
    destination_address: str
    destination_port: int
    original_egress: str
    reply_egress: str

    def __post_init__(self):
        try:
            for address in (self.source_address, self.destination_address):
                parsed = IPv4Address(address)
                if (
                    str(parsed) != address
                    or parsed.is_unspecified
                    or parsed.is_multicast
                    or parsed.is_loopback
                    or parsed.is_reserved
                ):
                    raise ValueError
        except (TypeError, ValueError):
            raise ValueError(
                "Flow scope requires canonical IPv4 unicast endpoints"
            ) from None
        if self.source_address == self.destination_address or not all(
            _uint(port, maximum=65535)
            for port in (self.source_port, self.destination_port)
        ):
            raise ValueError(
                "Flow scope requires distinct endpoints with exact TCP ports"
            )
        if self.original_egress == self.reply_egress or not all(
            isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name)
            for name in (self.original_egress, self.reply_egress)
        ):
            raise ValueError(
                "Flow scope requires two distinct router egress interfaces"
            )

    @property
    def original_tuple(self) -> tuple:
        return (
            self.source_address,
            self.source_port,
            self.destination_address,
            self.destination_port,
            _TCP,
        )

    @property
    def reply_tuple(self) -> tuple:
        return (
            self.destination_address,
            self.destination_port,
            self.source_address,
            self.source_port,
            _TCP,
        )


def decode_capture_window(record: dict, *, scope: FlowScope) -> dict:
    """Translate one completed, non-NAT capture window to publisher input."""
    if (
        type(record) is not dict
        or record.keys() != _WINDOW_FIELDS
        or not isinstance(scope, FlowScope)
    ):
        raise ValueError("Completed flow requires a scoped capture window")
    begin, end = _marker(record["begin"]), _marker(record["end"])
    if begin[:2] != end[:2] or not 0 < end[2] - begin[2] <= _MAX_WINDOW_NS:
        raise ValueError("Capture window is incomplete, restarted, or too long")

    original, reply, flow_id, start_ns, stop_ns = _conntrack(record["conntrack"], scope)
    original = _capture(
        record["original_capture"],
        scope.original_egress,
        scope.original_tuple,
        original,
    )
    reply = _capture(
        record["reply_capture"], scope.reply_egress, scope.reply_tuple, reply
    )
    first = original["packet_headers"][0]["unix_ns"]
    last = max(row["packet_headers"][-1]["unix_ns"] for row in (original, reply))
    if not begin[2] <= start_ns <= first < last < stop_ns <= end[2]:
        raise ValueError("Conntrack and packet times are outside the completed capture")

    application = record["verified_application"]
    if type(application) is not dict or application.keys() != _ENDPOINT_FIELDS.keys():
        raise ValueError("Capture requires separate initiator and responder receipts")
    for role, fields in _ENDPOINT_FIELDS.items():
        row = application[role]
        if (
            type(row) is not dict
            or row.keys() != fields
            or not _uint(row["time_ns"])
            or not first <= row["time_ns"] <= end[2]
            or type(row["peer"]) is not list
            or len(row["peer"]) != 2
        ):
            raise ValueError(
                "Endpoint receipt is outside the capture or has unknown fields"
            )

    evidence = {
        "verified_application": {role: dict(row) for role, row in application.items()},
        "tracking": {
            "conntrack_flow_id": flow_id,
            "state": "TIME_WAIT",
            "assured": True,
            "kernel_start_ns": start_ns,
            "kernel_expiry_ns": stop_ns,
            "first_egress_packet_ns": first,
            "last_egress_packet_ns": last,
        },
        "directions": {"original": original, "reply": reply},
    }
    validate_connection_flow_evidence(evidence)
    return evidence


def iter_conntrack_observations(
    stream: BinaryIO, *, scope: FlowScope
) -> Iterator[dict]:
    """Read bounded, nonoverlapping capture windows without buffering across them."""
    last_run, last_end_ns = None, 0
    for line in iter(lambda: stream.readline(MAX_RECORD_BYTES + 1), b""):
        if len(line) > MAX_RECORD_BYTES or not line.endswith(b"\n"):
            raise ValueError("Completed capture record is oversized or incomplete")
        try:
            record = json.loads(
                line, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant
            )
        except (UnicodeError, json.JSONDecodeError, RecursionError):
            raise ValueError("Completed capture record is invalid JSON") from None
        evidence = decode_capture_window(record, scope=scope)
        begin = record["begin"]
        if begin["unix_ns"] < last_end_ns or begin["collector_run_id"] == last_run:
            raise ValueError(
                "Completed capture windows overlap or reuse a collector run"
            )
        last_run, last_end_ns = begin["collector_run_id"], record["end"]["unix_ns"]
        yield evidence


def _uint(value, *, minimum=1, maximum=_MAX_INTEGER):
    return type(value) is int and minimum <= value <= maximum


def _marker(row):
    if (
        type(row) is not dict
        or row.keys() != _MARKER_FIELDS
        or not _uint(row["unix_ns"])
    ):
        raise ValueError("Capture requires complete collector and boot markers")
    run, boot = row["collector_run_id"], row["router_boot_id"]
    try:
        if not all(
            isinstance(value, str) and value == str(UUID(value)) and UUID(value).int
            for value in (run, boot)
        ):
            raise ValueError
    except ValueError:
        raise ValueError("Capture requires canonical collector and boot IDs") from None
    return run, boot, row["unix_ns"]


def _unique_fields(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate completed capture field")
        result[name] = value
    return result


def _invalid_constant(_value):
    raise ValueError("Non-JSON capture number")


def _bounded_text(value):
    if (
        type(value) is not str
        or not value.isascii()
        or not 0 < len(value) <= _MAX_CAPTURE_CHARS
    ):
        raise ValueError("Capture requires bounded ASCII command output")
    return value.strip()


def _xml_children(node, tag, attributes, names):
    if (
        node.tag != tag
        or node.attrib != attributes
        or (node.text or "").strip()
        or [child.tag for child in node] != names
        or any((child.tail or "").strip() for child in node)
    ):
        raise ValueError("Unexpected conntrack XML structure")
    return tuple(node)


def _xml_leaf(node):
    if node.attrib or len(node):
        raise ValueError("Unexpected conntrack XML value")
    return node.text or ""


def _xml_number(node, *, minimum=1, maximum=_MAX_INTEGER):
    value = _xml_leaf(node)
    if not re.fullmatch(r"[0-9]{1,19}", value) or not minimum <= int(value) <= maximum:
        raise ValueError("Invalid conntrack counter or timestamp")
    return int(value)


def _conntrack_direction(node, name, endpoints):
    ip, tcp, counters = _xml_children(
        node,
        "meta",
        {"direction": name},
        ["layer3", "layer4", "counters"],
    )
    source, destination = _xml_children(
        ip, "layer3", {"protonum": "2", "protoname": "ipv4"}, ["src", "dst"]
    )
    sport, dport = _xml_children(
        tcp, "layer4", {"protonum": "6", "protoname": "tcp"}, ["sport", "dport"]
    )
    observed = (
        _xml_leaf(source),
        _xml_number(sport, maximum=65535),
        _xml_leaf(destination),
        _xml_number(dport, maximum=65535),
        _TCP,
    )
    if observed != endpoints:
        raise ValueError("Conntrack tuple changed or has address/port translation")
    packets, octets = _xml_children(counters, "counters", {}, ["packets", "bytes"])
    return _xml_number(packets, maximum=_MAX_PACKETS), _xml_number(octets)


def _conntrack(raw, scope):
    document, _, report = _bounded_text(raw).rpartition("\n")
    if report != _CONNTRACK_REPORT or "<!" in document:
        raise ValueError("Capture needs one clean conntrack-tools 1.4.7 DESTROY report")
    try:
        root = ElementTree.fromstring(document)
    except ElementTree.ParseError:
        raise ValueError("Malformed conntrack XML") from None
    (flow,) = _xml_children(root, "conntrack", {}, ["flow"])
    original, reply, independent = _xml_children(
        flow, "flow", {"type": "destroy"}, ["meta", "meta", "meta"]
    )
    original = _conntrack_direction(original, "original", scope.original_tuple)
    reply = _conntrack_direction(reply, "reply", scope.reply_tuple)
    state, flow_id, assured, timestamps, duration = _xml_children(
        independent,
        "meta",
        {"direction": "independent"},
        ["state", "id", "assured", "timestamp", "deltatime"],
    )
    if _xml_leaf(state) != "TIME_WAIT" or _xml_leaf(assured):
        raise ValueError("Conntrack did not report an assured TIME_WAIT completion")
    start, stop = _xml_children(timestamps, "timestamp", {}, ["start", "stop"])
    _xml_number(duration, minimum=0)
    return (
        original,
        reply,
        _xml_number(flow_id, maximum=(1 << 32) - 1),
        _xml_number(start),
        _xml_number(stop),
    )


def _capture(raw, interface, endpoints, counters):
    lines = [line for line in _bounded_text(raw).splitlines() if line.strip()]
    if not 4 < len(lines) <= (_MAX_PACKETS * 2 + 4) or len(lines) % 2:
        raise ValueError("Packet capture has incomplete or too many header lines")
    header, captured, received, dropped = lines[-4:]
    count = (len(lines) - 4) // 2
    if (
        header
        != f"tcpdump: listening on {interface}, link-type EN10MB (Ethernet), snapshot length 128 bytes"
        or captured != f"{count} packets captured"
        or received != f"{count} packets received by filter"
        or dropped != "0 packets dropped by kernel"
    ):
        raise ValueError(
            "Packet capture interface, completion, or loss counters do not match"
        )

    packets = []
    for index in range(0, len(lines) - 4, 2):
        ip, tcp = (
            _IP_LINE.fullmatch(lines[index]),
            _TCP_LINE.fullmatch(lines[index + 1]),
        )
        if (
            ip is None
            or tcp is None
            or (tcp[1], int(tcp[2]), tcp[3], int(tcp[4]), _TCP) != endpoints
        ):
            raise ValueError(
                "Packet capture has an unknown or translated IPv4 TCP header"
            )
        packets.append(
            {
                "unix_ns": int(ip[1]) * 1_000_000_000 + int(ip[2]) * 1_000,
                "l3_bytes": int(ip[3]),
                "flags": tcp[5],
                "tcp_payload_bytes": int(tcp[6]),
            }
        )
    if sum("S" in packet["flags"] for packet in packets) != 1:
        raise ValueError(
            "Packet capture may contain a reused flow tuple or incomplete handshake"
        )
    tracked_packets, tracked_bytes = counters
    return {
        "tuple": list(endpoints),
        "egress": interface,
        "conntrack_packets": tracked_packets,
        "conntrack_l3_bytes": tracked_bytes,
        "captured_packets": count,
        "captured_l3_bytes": sum(packet["l3_bytes"] for packet in packets),
        "packet_headers": packets,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read completed IPv4 TCP capture windows from stdin and emit verified flow observations.",
    )
    parser.add_argument("--source-address", required=True)
    parser.add_argument("--source-port", type=int, required=True)
    parser.add_argument("--destination-address", required=True)
    parser.add_argument("--destination-port", type=int, required=True)
    parser.add_argument("--original-egress", required=True)
    parser.add_argument("--reply-egress", required=True)
    args = parser.parse_args(argv)
    try:
        scope = FlowScope(**vars(args))
        for observation in iter_conntrack_observations(sys.stdin.buffer, scope=scope):
            print(json.dumps(observation, separators=(",", ":")), flush=True)
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except BrokenPipeError:
            pass
        return 1
    except ValueError as error:
        print(f"Completed capture rejected. {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
