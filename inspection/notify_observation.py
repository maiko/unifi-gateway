"""Correlate one passive Notify alert with independently observed routed TCP."""

import re
from datetime import datetime, timezone

from inspection.notify_capture import (
    APPROVED_NOTIFY_SCOPE,
    MAX_OBSERVATIONS,
    NotifyCapture,
    NotifyScope,
    TcpObservation,
)

_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}"
    r"(?:Z|[+-](?:[01]\d|2[0-3]):?[0-5]\d)",
    re.ASCII,
)
_BOOT_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_CAPTURE_ID = re.compile(r"[0-9a-f]{32}")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MAX_TIMESTAMP = (1 << 63) - 1
_MAX_TRANSIT_NS = 1_000_000_000
_NS_PER_US = 1000
_FIN, _SYN, _RST, _ACK = 0x01, 0x02, 0x04, 0x10


def _uint(value: object, maximum: int, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _alert_time_ns(value: object) -> int | None:
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        delta = datetime.fromisoformat(value) - _EPOCH
    except (ValueError, OverflowError):
        return None
    seconds = delta.days * 86_400 + delta.seconds
    return seconds * 1_000_000_000 + delta.microseconds * _NS_PER_US


def _scope_alert(eve: dict, scope: NotifyScope) -> bool:
    if type(eve) is not dict:
        return False
    alert = eve.get("alert")
    return (
        eve.get("event_type") == "alert"
        and eve.get("proto") == "TCP"
        and eve.get("direction") == "to_server"
        and eve.get("pkt_src") == "wire/pcap"
        and eve.get("in_iface") == scope.ingress_interface
        and eve.get("src_ip") == scope.initiator_ip
        and eve.get("dest_ip") == scope.responder_ip
        and _uint(eve.get("src_port"), 65_535, 1)
        and eve.get("dest_port") == scope.server_port
        and _uint(eve.get("dest_port"), 65_535, 1)
        and _uint(eve.get("flow_id"), _MAX_TIMESTAMP, 1)
        and eve.get("verdict") == {"action": "alert"}
        and type(alert) is dict
        and type(alert.get("signature_id")) is int
        and alert["signature_id"] == scope.signature_id
        and _uint(alert.get("gid"), 1, 1)
        and _uint(alert.get("rev"), 1, 1)
        and alert.get("action") == "allowed"
    )


def _capture_bound(
    capture: NotifyCapture, boot_id: str, capture_id: str, alert_time: int
) -> bool:
    return (
        isinstance(capture, NotifyCapture)
        and type(boot_id) is str
        and _BOOT_ID.fullmatch(boot_id) is not None
        and type(capture_id) is str
        and _CAPTURE_ID.fullmatch(capture_id) is not None
        and (capture.boot_id, capture.capture_id) == (boot_id, capture_id)
        and capture.complete is True
        and _uint(capture.dropped, 0)
        and _uint(capture.start_ns, _MAX_TIMESTAMP, 1)
        and _uint(capture.end_ns, _MAX_TIMESTAMP, 1)
        and capture.start_ns <= alert_time
        and alert_time + _NS_PER_US - 1 <= capture.end_ns
        and type(capture.observations) is tuple
        and 0 < len(capture.observations) <= MAX_OBSERVATIONS
    )


def _valid_packet(packet: TcpObservation, scope: NotifyScope) -> bool:
    return (
        isinstance(packet, TcpObservation)
        and (packet.src_ip, packet.dst_ip) == (scope.initiator_ip, scope.responder_ip)
        and (packet.direction, packet.interface)
        in (("ingress", scope.ingress_interface), ("egress", scope.egress_interface))
        and _uint(packet.src_port, 65_535, 1)
        and _uint(packet.dst_port, 65_535, 1)
        and packet.dst_port == scope.server_port
        and _uint(packet.timestamp_ns, _MAX_TIMESTAMP, 1)
        and _uint(packet.seq, 0xFFFFFFFF)
        and _uint(packet.ack, 0xFFFFFFFF)
        and _uint(packet.flags, 0xFF)
        and _uint(packet.payload_len, 65_495)
        and _uint(packet.ip_id, 0xFFFF)
        and _uint(packet.ttl, 255, 1)
    )


def _fingerprint(packet: TcpObservation) -> tuple[int, ...]:
    return packet.ip_id, packet.seq, packet.ack, packet.flags, packet.payload_len


def _routed(
    packet: TcpObservation,
    ingress: list[TcpObservation],
    egress: list[TcpObservation],
) -> TcpObservation | None:
    key = _fingerprint(packet)
    if sum(_fingerprint(item) == key for item in ingress) != 1:
        return None
    matches = [item for item in egress if _fingerprint(item) == key]
    if len(matches) != 1:
        return None
    output = matches[0]
    if (
        0 < output.timestamp_ns - packet.timestamp_ns <= _MAX_TRANSIT_NS
        and packet.ttl == output.ttl + 1
    ):
        return output
    return None


def forwarding_observed(
    eve: dict,
    *,
    scope: NotifyScope,
    capture: NotifyCapture,
    boot_id: str,
    capture_id: str,
) -> bool:
    """Test for this alert's original segment on the pinned router egress.

    The caller supplies the verified Notify EVE generation and boot identity.
    Capture must begin before the connection SYN. The observer must provide
    loss-free, complete snapshots with the same packet time source as EVE.
    """
    if not isinstance(scope, NotifyScope) or scope != APPROVED_NOTIFY_SCOPE:
        return False
    if not _scope_alert(eve, scope):
        return False
    alert_time = _alert_time_ns(eve.get("timestamp"))
    if alert_time is None or not _capture_bound(
        capture, boot_id, capture_id, alert_time
    ):
        return False

    ingress, egress = [], []
    previous_ns = capture.start_ns
    for packet in capture.observations:
        if not _valid_packet(packet, scope) or not (
            previous_ns <= packet.timestamp_ns <= capture.end_ns
        ):
            return False
        previous_ns = packet.timestamp_ns
        if packet.src_port == eve["src_port"]:
            (ingress if packet.direction == "ingress" else egress).append(packet)

    # Suricata's pinned AF_PACKET reader truncates the packet time to microseconds.
    candidates = [
        packet
        for packet in ingress
        if alert_time <= packet.timestamp_ns < alert_time + _NS_PER_US
    ]
    if len(candidates) != 1:
        return False
    target = candidates[0]
    if target.payload_len == 0 or target.flags & (_FIN | _SYN | _RST | _ACK) != _ACK:
        return False

    syns = [packet for packet in ingress if packet.flags & _SYN]
    if len(syns) != 1:
        return False
    syn = syns[0]
    if syn.flags & (_FIN | _SYN | _RST | _ACK) != _SYN or syn.payload_len or syn.ack:
        return False
    if any(
        packet.timestamp_ns < target.timestamp_ns and packet.flags & (_FIN | _RST)
        for packet in ingress
    ):
        return False
    forwarded_syn = _routed(syn, ingress, egress)
    return (
        forwarded_syn is not None
        and forwarded_syn.timestamp_ns < target.timestamp_ns
        and _routed(target, ingress, egress) is not None
    )
