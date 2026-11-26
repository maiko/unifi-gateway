"""Decode the pinned IPv4 Kill Switch policy route emitted by Network."""

from dataclasses import dataclass
import json
import re

from provisioners.uxg_intent import _invalid_constant, _unique_object
from provisioners.uxg_wan_failover import _SUPPORTED_WANS, _exact


POLICY_ROUTE_VERSION = {"firewall/pbr": 12}
POLICY_ROUTE_CAPABILITY = 0x00800000
POLICY_ROUTE_SOURCE = "192.168.110.0/24"
POLICY_ROUTE_DESTINATIONS = ("198.19.210.243/32", "198.19.210.244/32")


class PolicyRouteError(ValueError):
    """The policy route is incomplete or outside its verified scope."""


@dataclass(frozen=True, slots=True)
class PolicyRouteIntent:
    revision: str
    destination: str | None


def _set_name(entry):
    identity = entry.get("identification") if isinstance(entry, dict) else None
    name = identity.get("name") if isinstance(identity, dict) else None
    return name if isinstance(name, str) else ""


def _generated_sets(short_id, destination):
    for kind, entries in (("net4", [POLICY_ROUTE_SOURCE]), ("net6", None), ("ip", [destination])):
        subject = "IP addresses and ranges" if kind == "ip" else "Network addresses"
        yield {
            "identification": {"name": f"trafficroute_{kind}_{short_id}", "type": "address"},
            "description": f"{subject} related to Traffic Route (short_id: {short_id})",
            **({"entries": entries} if entries is not None else {}),
        }


def _decode_route(action, sets):
    source = action.get("source") if isinstance(action, dict) else None
    references = source.get("sets") if isinstance(source, dict) else None
    if (not isinstance(references, list) or len(references) != 1 or not isinstance(references[0], str)
            or not (name := re.fullmatch(r"trafficroute_net4_([1-9][0-9]{0,5})", references[0]))):
        raise PolicyRouteError("The policy route requires the observed source set")
    short_id = name[1]
    expected = {
        "id": 10001, "enabled": True, "negateInInterface": False, "ipVersion": "v4only",
        "routingMode": {"mode": "table", "pbrTable": _SUPPORTED_WANS["eth0"][0], "strict": True},
        "source": {"sets": [f"trafficroute_net4_{short_id}"]},
        "destination": {"sets": [f"trafficroute_ip_{short_id}"]},
    }
    if not _exact(action, expected):
        raise PolicyRouteError("Only IPv4 policy routing through WAN VLAN 210 with Kill Switch is supported")
    observed = {_set_name(row): row for row in sets}
    for destination in POLICY_ROUTE_DESTINATIONS:
        expected_sets = {_set_name(row): row for row in _generated_sets(short_id, destination.removesuffix("/32"))}
        if len(sets) == len(expected_sets) and _exact(observed, expected_sets):
            return destination
    raise PolicyRouteError("The policy route address sets require the supported source VLAN and a single supported IPv4 host")


def normalize_policy_route(system_cfg, *, revision):
    """Validate the complete action and strip only its recognized companion fields."""
    if not isinstance(system_cfg, str) or not isinstance(revision, str) or not revision:
        raise PolicyRouteError("Policy routing requires a complete snapshot and a revision")
    section = "firewall/pbr"
    try:
        document = json.loads(system_cfg, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        udapi = document["udapi"]
        versions = udapi["versionDetail"]
        rules = udapi[section]["rules"]
        sets = udapi["firewall/sets"]
        version = versions[section]
    except (KeyError, TypeError, ValueError, RecursionError) as error:
        raise PolicyRouteError("Policy route snapshot is incomplete or invalid") from error
    if (not _exact(udapi.get("version"), 48) or udapi.get("versionFormat") != "v2"
            or not _exact(version, POLICY_ROUTE_VERSION[section]) or udapi[section].keys() != {"rules"}
            or not isinstance(rules, list) or len(rules) > 1 or not isinstance(sets, list)):
        raise PolicyRouteError("Unsupported native policy route schema")

    owned = [row for row in sets if _set_name(row).startswith("trafficroute_")]
    if not rules and owned:
        raise PolicyRouteError("Policy route address sets are present without a routing action")
    destination = _decode_route(rules[0], owned) if rules else None
    udapi["firewall/sets"] = [row for row in sets if not _set_name(row).startswith("trafficroute_")]
    del udapi[section]
    del versions[section]
    return json.dumps(document), PolicyRouteIntent(revision, destination)
