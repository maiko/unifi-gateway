"""Project confirmed Suricata events into the Network 11.0.104 listener DTO."""

import re
from dataclasses import dataclass
from datetime import datetime, timezone

from inspection.suricata import SecurityEvent

_PROTOCOL_NUMBERS = {"TCP": 6, "UDP": 17}
_JAVA_LONG_MAX = (1 << 63) - 1
_JAVA_INT_MAX = (1 << 31) - 1


@dataclass(frozen=True)
class FlowObservation:
    """Correlated flow identity and counters observed by the caller."""

    flow_id: int
    session_id: int
    started_at: datetime
    bytes_to_client: int
    bytes_to_server: int
    packets_to_client: int
    packets_to_server: int


@dataclass(frozen=True)
class SignatureMetadata:
    """Metadata from the configured signature that produced the alert."""

    gid: int
    revision: int
    severity: int
    signature: str
    category: str


def _require_int(name: str, value: int, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")


def project_suricata_event(
    event: SecurityEvent,
    *,
    site_id: str,
    gateway_mac: str,
    flow: FlowObservation,
    signature: SignatureMetadata,
    forwarding_observed: bool = False,
) -> dict | None:
    """Build an event body from EVE and caller-supplied observations.

    A detection does not establish forwarding. Supply forwarding_observed
    only when delivery of the matching traffic was observed separately.
    """
    if type(forwarding_observed) is not bool:
        raise ValueError("forwarding_observed must be a boolean")
    if event.verdict == "drop" and not forwarding_observed:
        action = "DROP"
    elif event.verdict == "alert" and forwarding_observed:
        action = "ACCEPT"
    else:
        return None

    protocol = _PROTOCOL_NUMBERS.get(event.protocol)
    if protocol is None:
        return None
    if not isinstance(site_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", site_id):
        raise ValueError("site_id must be an observed Network site identifier")
    if not isinstance(gateway_mac, str) or not re.fullmatch(
        r"(?:[0-9a-f]{12}|[0-9a-f]{2}(?::[0-9a-f]{2}){5})", gateway_mac, re.I
    ):
        raise ValueError("gateway_mac must be an observed gateway MAC address")

    _require_int("flow_id", flow.flow_id, 1, _JAVA_LONG_MAX)
    _require_int("session_id", flow.session_id, 1, _JAVA_LONG_MAX)
    observed_counts = {
        "bytes_to_client": flow.bytes_to_client,
        "bytes_to_server": flow.bytes_to_server,
        "packets_to_client": flow.packets_to_client,
        "packets_to_server": flow.packets_to_server,
    }
    for name, value in observed_counts.items():
        _require_int(name, value, 0, _JAVA_LONG_MAX)
    if not isinstance(flow.started_at, datetime) or flow.started_at.utcoffset() is None:
        raise ValueError("started_at must include a time zone")
    if flow.started_at > event.timestamp:
        raise ValueError("started_at must be at or before the alert")

    _require_int("gid", signature.gid, 0, _JAVA_INT_MAX)
    _require_int("revision", signature.revision, 0, _JAVA_INT_MAX)
    _require_int("severity", signature.severity, 1, 4)
    if not isinstance(signature.signature, str) or not signature.signature.strip():
        raise ValueError("signature must be the observed rule name")
    if not isinstance(signature.category, str):
        raise ValueError("category must be the signature category string")

    return {
        "type": "SuricataEvent",
        "site_id": site_id,
        "gateway_mac": gateway_mac,
        "timestamp": event.timestamp.isoformat(),
        "action": action,
        "flow_id": flow.flow_id,
        "ip": {
            "saddr": event.source,
            "sport": event.source_port,
            "daddr": event.destination,
            "dport": event.destination_port,
            "protocol": protocol,
        },
        "flow": {
            "flow_id": flow.session_id,
            "start": flow.started_at.astimezone(timezone.utc).isoformat(),
            "bytes_toclient": flow.bytes_to_client,
            "bytes_toserver": flow.bytes_to_server,
            "pkts_toclient": flow.packets_to_client,
            "pkts_toserver": flow.packets_to_server,
        },
        "alert": {
            "signature_id": event.signature_id,
            "signature": signature.signature,
            "gid": signature.gid,
            "rev": signature.revision,
            "severity": signature.severity,
            "category": signature.category,
        },
        # The receiver dereferences this object and tolerates absent vendor fields.
        "ubnt": {},
    }
