"""Decode native inspection intent and Suricata 7.0.10 EVE alerts."""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address
from typing import Literal


DISABLED_INSPECTION = {"enabled": False, "tor": False, "alien": False, "signatureScheduler": 0}
_WIRE_MODES = {"pcap-high": "notify", "pcap-l3-blocking-high": "block"}
_ACTIVE_FIELDS = DISABLED_INSPECTION.keys() | {
    "mode",
    "interfaces",
    "blockTime",
    "deviceID",
    "token",
    "signatures",
    "suppress",
}


@dataclass(frozen=True, slots=True)
class InspectionIntent:
    mode: Literal["off", "notify", "block"]
    networks: tuple[str, ...]
    vendor_controls_sha256: str | None = None


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Inspection snapshot contains a duplicate JSON field")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise ValueError("Inspection snapshot contains a non-JSON constant")


def decode_inspection_intent(system_cfg: str) -> InspectionIntent:
    """Describe the requested mode and bridges before mapping them to VyOS."""
    if not isinstance(system_cfg, str):
        raise ValueError("Inspection system_cfg must be a JSON string")
    try:
        root = json.loads(
            system_cfg,
            object_pairs_hook=_unique_fields,
            parse_constant=_invalid_constant,
        )
        udapi = root["udapi"]
        if (
            type(udapi["version"]) is not int
            or udapi["version"] != 48
            or udapi["versionFormat"] != "v2"
            or type(udapi["versionDetail"]["services/idsIps"]) is not int
            or udapi["versionDetail"]["services/idsIps"] != 8
        ):
            raise ValueError("Unsupported UniFi inspection schema version")
        config = udapi["services"]["idsIps"]
    except (TypeError, KeyError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError(
            "Inspection snapshot is missing a valid UDAPI service"
        ) from error

    if (
        isinstance(config, dict)
        and config == DISABLED_INSPECTION
        and all(type(config[key]) is type(value) for key, value in DISABLED_INSPECTION.items())
    ):
        return InspectionIntent("off", ())
    if (
        not isinstance(config, dict)
        or config.keys() != _ACTIVE_FIELDS
        or config["enabled"] is not True
        or type(config["tor"]) is not bool
        or type(config["alien"]) is not bool
        or any(
            not _is_uint(config[key], 0xFFFFFFFF)
            for key in ("blockTime", "signatureScheduler")
        )
    ):
        raise ValueError("Unsupported UniFi inspection service settings")
    mode = config["mode"]
    if not isinstance(mode, str) or mode not in _WIRE_MODES:
        raise ValueError("Unsupported UniFi inspection mode")
    if config["suppress"] != []:
        raise ValueError("UniFi inspection exclusions have no VyOS mapping")

    networks = config["interfaces"]
    if (
        not isinstance(networks, list)
        or not networks
        or any(
            not isinstance(name, str) or re.fullmatch(r"br[0-9]{1,4}", name) is None
            for name in networks
        )
        or len(set(networks)) != len(networks)
    ):
        raise ValueError(
            "Inspection needs distinct, explicitly selected bridge interfaces"
        )
    topology = udapi.get("interfaces")
    if not isinstance(topology, list):
        raise ValueError("Inspection snapshot has no interface topology")
    selected = []
    for row in topology:
        identity = row.get("identification") if isinstance(row, dict) else None
        if isinstance(identity, dict) and identity.get("id") in networks:
            status = row.get("status")
            if (
                identity.get("type") != "bridge"
                or not isinstance(status, dict)
                or status.get("enabled") is not True
            ):
                raise ValueError("Inspection selection is not an enabled bridge")
            selected.append(identity["id"])
    if sorted(selected) != sorted(networks):
        raise ValueError("Inspection scope does not match the reported bridge topology")

    signatures = config["signatures"]
    action = "alert" if mode == "pcap-high" else "block"
    if (
        not isinstance(signatures, list)
        or not signatures
        or any(
            not isinstance(rule, dict)
            or rule.keys() != {"category", "action"}
            or not isinstance(rule["category"], str)
            or not rule["category"]
            or rule["action"] != action
            for rule in signatures
        )
    ):
        raise ValueError("Unsupported UniFi signature configuration")
    categories = sorted(rule["category"] for rule in signatures)
    if len(set(categories)) != len(categories):
        raise ValueError("UniFi inspection has duplicate signature categories")

    # Bind the vendor selections without interpreting or leaking them.
    unmanaged = {
        key: config[key] for key in ("tor", "alien", "blockTime", "signatureScheduler")
    }
    unmanaged["categories"] = categories
    digest = sha256(json.dumps(unmanaged, sort_keys=True).encode("utf-8")).hexdigest()
    return InspectionIntent(_WIRE_MODES[mode], tuple(networks), digest)


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    timestamp: datetime
    signature_id: int
    source: str
    source_port: int | None
    destination: str
    destination_port: int | None
    protocol: str
    verdict: Literal["alert", "drop", "unknown"]


def _is_uint(value: object, max_value: int) -> bool:
    return type(value) is int and 0 <= value <= max_value


def decode_eve_event(event: dict) -> SecurityEvent | None:
    """Decode an IP alert, returning None for unsupported or malformed records.

    An alert establishes a signature match. Only an explicit final packet
    verdict establishes a drop.
    """
    if not isinstance(event, dict) or event.get("event_type") != "alert":
        return None

    alert = event.get("alert")
    if not isinstance(alert, dict) or alert.get("action") not in ("allowed", "blocked"):
        return None
    gid, signature_id, revision = (
        alert.get(key) for key in ("gid", "signature_id", "rev")
    )
    if not all(_is_uint(value, 0xFFFFFFFF) for value in (gid, signature_id, revision)):
        return None
    if signature_id == 0:
        return None

    raw_verdict = event.get("verdict")
    if "verdict" in event:
        if not isinstance(raw_verdict, dict):
            return None
        action = raw_verdict.get("action")
        if action not in ("alert", "pass", "drop"):
            return None
        verdict = "drop" if action == "drop" else "alert"
    else:
        # A rule can report "blocked" for a reject in passive IDS mode.
        verdict = "unknown" if alert["action"] == "blocked" else "alert"

    timestamp_text = event.get("timestamp")
    if not isinstance(timestamp_text, str) or timestamp_text[10:11] != "T":
        return None
    addresses = (event.get("src_ip"), event.get("dest_ip"))
    if not all(
        isinstance(address, str) and "%" not in address for address in addresses
    ):
        return None
    try:
        timestamp = datetime.fromisoformat(timestamp_text)
        if timestamp.tzinfo is None:
            return None
        timestamp = timestamp.astimezone(timezone.utc)
        source, destination = (ip_address(address) for address in addresses)
    except (ValueError, OverflowError):
        return None
    if source.version != destination.version:
        return None

    protocol = event.get("proto")
    if not isinstance(protocol, str) or not re.fullmatch(
        r"[a-zA-Z0-9_.-]{1,15}", protocol
    ):
        return None
    source_port, destination_port = event.get("src_port"), event.get("dest_port")
    if (
        protocol in ("TCP", "UDP", "SCTP")
        or "src_port" in event
        or "dest_port" in event
    ):
        if not _is_uint(source_port, 65535) or not _is_uint(destination_port, 65535):
            return None

    correlation_fields = []
    for field in ("sensor_id", "flow_id", "tx_id", "pcap_cnt"):
        value = event.get(field)
        if field in event and not _is_uint(value, 0xFFFFFFFFFFFFFFFF):
            return None
        correlation_fields.append(value)

    # The same alert line can be delivered again when the reader restarts.
    # Hash only normalized alert fields, excluding payload and application metadata.
    identity = (
        timestamp.isoformat(),
        gid,
        signature_id,
        revision,
        str(source),
        source_port,
        str(destination),
        destination_port,
        protocol,
        verdict,
        *correlation_fields,
    )
    event_id = sha256(
        json.dumps(identity, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        signature_id=signature_id,
        source=str(source),
        source_port=source_port,
        destination=str(destination),
        destination_port=destination_port,
        protocol=protocol,
        verdict=verdict,
    )
