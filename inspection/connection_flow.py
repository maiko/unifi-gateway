"""Project one completed IPv4 TCP flow with matching conntrack and egress evidence."""

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Address
from uuid import UUID

_LONG_MAX = (1 << 63) - 1
_TCP = 6
_NANOSECONDS = 1_000_000_000
_EVENT_FIELDS = {
    "type",
    "site_id",
    "gateway_mac",
    "timestamp",
    "action",
    "flow_id",
    "ip",
    "flow_start",
    "flow_end",
    "stats",
}
_IP_FIELDS = {"saddr", "sport", "daddr", "dport", "protocol"}
_STAT_FIELDS = {"rxBytes", "rxPackets", "txBytes", "txPackets"}


@dataclass(frozen=True, slots=True)
class CompletedFlow:
    event_id: str
    event: dict
    kernel_expiry_ns: int


@dataclass(frozen=True, slots=True)
class _Direction:
    endpoint_tuple: tuple[str, int, str, int, int]
    egress: str
    packets: int
    octets: int
    payload_bytes: int
    first_ns: int
    last_ns: int
    fin_ns: int
    last_is_ack: bool


def _unsigned(value: object, *, minimum: int = 1, maximum: int = _LONG_MAX) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _endpoint(ip, port) -> tuple[str, int]:
    try:
        if (
            type(ip) is str
            and str(IPv4Address(ip)) == ip
            and _unsigned(port, maximum=65535)
        ):
            return ip, port
    except ValueError:
        pass
    raise ValueError("Flow requires a canonical IPv4 address and TCP port")


def _tuple(src, sport, dst, dport, protocol):
    if type(protocol) is not int or protocol != _TCP or src == dst:
        raise ValueError("Flow requires a routed IPv4 TCP tuple")
    return (*_endpoint(src, sport), *_endpoint(dst, dport), protocol)


def _scope(site_id: str, gateway_mac: str) -> None:
    if type(site_id) is not str or str(UUID(site_id)) != site_id:
        raise ValueError("Flow requires a canonical site UUID")
    if type(gateway_mac) is not str or not re.fullmatch(
        r"(?:[0-9a-f]{12}|[0-9a-f]{2}(?::[0-9a-f]{2}){5})", gateway_mac, re.I
    ):
        raise ValueError("Flow requires an adopted gateway MAC")


def _wire_timestamp(epoch_ns: int) -> str:
    seconds, fraction = divmod(epoch_ns, _NANOSECONDS)
    utc = datetime.fromtimestamp(seconds, tz=timezone.utc)
    return f"{utc:%Y-%m-%dT%H:%M:%S}.{fraction:09d}Z"


def _validate_timestamp(value: object) -> None:
    if type(value) is not str or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z", value, re.ASCII
    ):
        raise ValueError("Flow requires a UTC timestamp with nanosecond precision")
    datetime.fromisoformat(value)


def completed_flow_event_id(event: dict) -> str:
    """Validate the narrow wire schema and derive its broker replay identity."""
    if (
        type(event) is not dict
        or event.keys() != _EVENT_FIELDS
        or event["type"] != "FLOW_POLICY"
        or event["action"] != "ACCEPT"
        or not _unsigned(event["flow_id"])
    ):
        raise ValueError("Invalid completed-flow event")
    _scope(event["site_id"], event["gateway_mac"])
    for field in ("flow_start", "flow_end", "timestamp"):
        _validate_timestamp(event[field])
    if not event["flow_start"] < event["flow_end"] == event["timestamp"]:
        raise ValueError("Completed-flow timestamps are inconsistent")
    ip = event["ip"]
    if type(ip) is not dict or ip.keys() != _IP_FIELDS:
        raise ValueError("Invalid completed-flow IP fields")
    endpoints = _tuple(
        ip["saddr"], ip["sport"], ip["daddr"], ip["dport"], ip["protocol"]
    )
    stats = event["stats"]
    if (
        type(stats) is not dict
        or stats.keys() != _STAT_FIELDS
        or not all(_unsigned(value) for value in stats.values())
        or stats["rxBytes"] + stats["txBytes"] > _LONG_MAX
        or stats["rxPackets"] + stats["txPackets"] > _LONG_MAX
        or stats["rxBytes"] < stats["rxPackets"] * 40
        or stats["txBytes"] < stats["txPackets"] * 40
    ):
        raise ValueError("Invalid completed-flow counters")

    identity = (
        event["type"],
        event["site_id"],
        event["gateway_mac"].replace(":", "").lower(),
        event["flow_id"],
        endpoints,
        event["flow_start"],
    )
    return hashlib.sha256(
        json.dumps(identity, separators=(",", ":")).encode()
    ).hexdigest()


def _direction(row: dict, *, is_reply: bool) -> _Direction:
    evidence_tuple = row["tuple"]
    if type(evidence_tuple) is not list or len(evidence_tuple) != 5:
        raise ValueError("Expected a five-element conntrack tuple")
    endpoints = _tuple(*evidence_tuple)
    egress = row["egress"]
    if type(egress) is not str or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", egress):
        raise ValueError("Expected an observed egress interface")

    headers = row["packet_headers"]
    if type(headers) is not list or len(headers) < 3:
        raise ValueError("Each direction requires captured packet headers")
    total_bytes = payload_bytes = earlier_ns = 0
    times = []
    fins = []
    for item in headers:
        ns, octets, payload, flags = (
            item["unix_ns"],
            item["l3_bytes"],
            item["tcp_payload_bytes"],
            item["flags"],
        )
        if (
            not _unsigned(ns)
            or ns < earlier_ns
            or not _unsigned(octets, minimum=40, maximum=65535)
            or not _unsigned(payload, minimum=0, maximum=octets - 40)
            or type(flags) is not str
            or re.fullmatch(r"[.FSRPUEW]+", flags) is None
            or "R" in flags
        ):
            raise ValueError("Invalid or reset TCP packet capture")
        if not times and ("S" not in flags or ("." in flags) != is_reply or payload):
            raise ValueError("A captured TCP handshake is required")
        if "F" in flags:
            fins.append(ns)
        earlier_ns = ns
        times.append(ns)
        total_bytes += octets
        payload_bytes += payload

    for key, actual in (
        ("conntrack_packets", len(headers)),
        ("captured_packets", len(headers)),
        ("conntrack_l3_bytes", total_bytes),
        ("captured_l3_bytes", total_bytes),
    ):
        if not _unsigned(row[key]) or row[key] != actual:
            raise ValueError("Conntrack and routed packet counters must agree")
    if len(fins) != 1 or fins[0] <= times[0] or payload_bytes == 0:
        raise ValueError("Each direction requires traffic and a captured FIN")
    return _Direction(
        endpoints,
        egress,
        len(headers),
        total_bytes,
        payload_bytes,
        times[0],
        times[-1],
        fins[0],
        flags == "." and payload == 0,
    )


def _check_application(verified: dict, original: _Direction, reply: _Direction) -> None:
    initiator, responder = verified["initiator"], verified["responder"]
    if (
        initiator["observed_server_eof"] is not True
        or responder["observed_client_eof"] is not True
        or _endpoint(*initiator["peer"]) != original.endpoint_tuple[2:4]
        or _endpoint(*responder["peer"]) != original.endpoint_tuple[:2]
        or any(
            not _unsigned(observed) or observed != captured
            for observed, captured in (
                (initiator["request_bytes"], original.payload_bytes),
                (responder["received_bytes"], original.payload_bytes),
                (initiator["received_bytes"], reply.payload_bytes),
                (responder["reply_bytes"], reply.payload_bytes),
            )
        )
    ):
        raise ValueError("Independent request, reply and EOF evidence must agree")


def _verified_flow(evidence):
    try:
        tracking = evidence["tracking"]
        original = _direction(evidence["directions"]["original"], is_reply=False)
        reply = _direction(evidence["directions"]["reply"], is_reply=True)
        _check_application(evidence["verified_application"], original, reply)
        start_ns = tracking["kernel_start_ns"]
        expiry_ns = tracking["kernel_expiry_ns"]
        first_ns = tracking["first_egress_packet_ns"]
        end_ns = tracking["last_egress_packet_ns"]
        flow_id = tracking["conntrack_flow_id"]
        last_direction = max((original, reply), key=lambda direction: direction.last_ns)
        if (
            tracking["state"] != "TIME_WAIT"
            or tracking["assured"] is not True
            or not all(
                _unsigned(value)
                for value in (flow_id, start_ns, expiry_ns, first_ns, end_ns)
            )
            or reply.endpoint_tuple
            != (*original.endpoint_tuple[2:4], *original.endpoint_tuple[:2], _TCP)
            or original.egress == reply.egress
            or first_ns != original.first_ns
            or not start_ns <= first_ns < reply.first_ns
            or end_ns != last_direction.last_ns
            or not last_direction.last_is_ack
            or not reply.first_ns < min(original.fin_ns, reply.fin_ns)
            or not max(original.fin_ns, reply.fin_ns) < end_ns < expiry_ns
        ):
            raise ValueError("Incomplete or inconsistent completed TCP flow")
    except (IndexError, KeyError, TypeError):
        raise ValueError("Missing or invalid completed TCP flow evidence") from None
    return original, reply, flow_id, start_ns, end_ns, expiry_ns


def validate_connection_flow_evidence(evidence: dict) -> None:
    """Check complete flow evidence independently of the delivery identity."""
    _verified_flow(evidence)


def project_connection_flow(
    evidence: dict, *, site_id: str, gateway_mac: str
) -> CompletedFlow:
    """Build a FLOW_POLICY event from a tracked flow and independent forwarding proof."""
    _scope(site_id, gateway_mac)
    original, reply, flow_id, start_ns, end_ns, expiry_ns = _verified_flow(evidence)

    src, sport, dst, dport, protocol = original.endpoint_tuple
    end = _wire_timestamp(end_ns)
    event = {
        "type": "FLOW_POLICY",
        "site_id": site_id,
        "gateway_mac": gateway_mac,
        "timestamp": end,
        "action": "ACCEPT",
        "flow_id": flow_id,
        "ip": {
            "saddr": src,
            "sport": sport,
            "daddr": dst,
            "dport": dport,
            "protocol": protocol,
        },
        "flow_start": _wire_timestamp(start_ns),
        "flow_end": end,
        # Network flow statistics are from the initiator’s perspective.
        "stats": {
            "txBytes": original.octets,
            "txPackets": original.packets,
            "rxBytes": reply.octets,
            "rxPackets": reply.packets,
        },
    }
    return CompletedFlow(completed_flow_event_id(event), event, expiry_ns)
