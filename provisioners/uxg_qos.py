"""Decode the observed native IPv4 WAN speed-limit policy."""

from dataclasses import dataclass
import json
import re

from provisioners.uxg_intent import _invalid_constant, _unique_object
from provisioners.uxg_wan_failover import _exact


QOS_CAPABILITY = 0x100
QOS_SOURCE = "192.168.110.0/24"
QOS_WAN_HOST = "198.18.210.2"
_MANGLE = "firewall/mangle"
_VERSIONS = {"firewall/filter": 4, _MANGLE: 6, "firewall/sets": 1}
_CHAIN = {"enabled": True, "name": "POSTROUTING", "policy": "ACCEPT", "logDefault": False}


class QosError(ValueError):
    """The native policy or observed VyOS QoS state is outside the supported scope."""


@dataclass(frozen=True, slots=True)
class QosLimit:
    download_kbps: int
    upload_kbps: int

    def __post_init__(self):
        if any(type(value) is not int or not 1 <= value <= 1_000_000 for value in (self.download_kbps, self.upload_kbps)):
            raise QosError("QoS rates must be integer Kbps between 1 and 1000000")


@dataclass(frozen=True, slots=True)
class QosIntent:
    revision: str
    limit: QosLimit | None


def _set_name(entry):
    identity = entry.get("identification") if isinstance(entry, dict) else None
    name = identity.get("name") if isinstance(identity, dict) else None
    return name if isinstance(name, str) else ""


def _decode_limit(udapi, rule, sets):
    source = rule.get("source") if isinstance(rule, dict) else None
    references = source.get("sets") if isinstance(source, dict) else None
    if (not isinstance(references, list) or len(references) != 1 or not isinstance(references[0], str)
            or not (name := re.fullmatch(r"qosrule_net4_([1-9][0-9]{0,5})", references[0]))):
        raise QosError("Native QoS needs the observed IPv4 network source")
    short_id = name[1]
    source_name, destination_name, queue_name = (f"qosrule_{kind}_{short_id}" for kind in ("net4", "ip", "qos"))
    expected_rule = {
        "id": 10001, "enabled": True, "target": "FW_QOS", "log": False, "negateInInterface": False,
        "negateOutInterface": False, "ipVersion": "v4only", "source": {"sets": [source_name]},
        "destination": {"sets": [destination_name]}, "outInterface": {"id": "eth0"}, "fwQoSQueueName": queue_name,
    }
    if not _exact(rule, expected_rule):
        raise QosError("Native QoS needs one IPv4 classifier confined to WAN 210")
    expected_sets = {
        source_name: {
            "identification": {"name": source_name, "type": "address"},
            "description": f"Network addresses related to QoS Rule (short_id: {short_id})",
            "entries": [QOS_SOURCE],
        },
        destination_name: {
            "identification": {"name": destination_name, "type": "address"},
            "description": f"IP addresses and ranges related to QoS rule (short_id: {short_id})",
            "entries": [QOS_WAN_HOST],
        },
    }
    if len(sets) != 2 or not _exact({_set_name(entry): entry for entry in sets}, expected_sets):
        raise QosError("Native QoS requires the pinned VLAN 110 and WAN 210 peer address sets")
    try:
        qos = udapi["qos"]
        queue = qos["fw"]["queues"][0]
        rates = QosLimit(download_kbps=queue["downloadSpeed"], upload_kbps=queue["uploadSpeed"])
    except (KeyError, IndexError, TypeError) as error:
        raise QosError("Native QoS needs a complete upload and download queue") from error
    if not _exact(qos, {"global": {"enabled": True, "connectivity": [{"interfaceID": "eth0"}]}, "fw": {"queues": [{
        "name": queue_name, "downloadSpeed": rates.download_kbps, "uploadSpeed": rates.upload_kbps,
    }]}}):
        raise QosError("Native QoS queue differs from the scoped bidirectional speed limit")
    return rates


def normalize_qos_policy(system_cfg, *, revision):
    """Consume only the exact native QoS companions of the approved policy."""
    if not isinstance(system_cfg, str) or not isinstance(revision, str) or not revision:
        raise QosError("QoS requires a complete native snapshot and a revision")
    try:
        document = json.loads(system_cfg, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        udapi = document["udapi"]
        versions = {section: udapi["versionDetail"][section] for section in _VERSIONS}
        chains = udapi[_MANGLE]
        rules = chains[0]["rules"]
        sets = udapi["firewall/sets"]
    except (KeyError, IndexError, TypeError, ValueError, RecursionError) as error:
        raise QosError("Native QoS snapshot is incomplete or invalid") from error
    if (not _exact(udapi.get("version"), 48) or udapi.get("versionFormat") != "v2" or not _exact(versions, _VERSIONS)
            or not isinstance(rules, list) or len(rules) > 1 or not isinstance(sets, list)
            or not _exact(chains, [{"config": _CHAIN, "rules": rules}]) or "qos/ip" in udapi):
        raise QosError("Unsupported native QoS envelope or concurrent Smart Queues")

    owned = [entry for entry in sets if _set_name(entry).startswith("qosrule_")]
    if not rules and (owned or "qos" in udapi):
        raise QosError("Native QoS sets or queues are present without a classifier")
    limit = _decode_limit(udapi, rules[0], owned) if rules else None
    del udapi[_MANGLE]
    udapi.pop("qos", None)
    udapi["firewall/sets"] = [entry for entry in sets if not _set_name(entry).startswith("qosrule_")]
    return json.dumps(document), QosIntent(revision, limit)
