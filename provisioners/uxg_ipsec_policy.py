"""Normalize only the generated policy companions of the observed one-tunnel IPsec shape."""

from copy import deepcopy
import json
import re
from uuid import UUID

from provisioners.vyos_ipsec import IpsecIntent, IpsecIntentError, _decode_peer, _SECTION


_FILTER = "firewall/filter"
_NAT = "firewall/nat"
_SETS = "firewall/sets"
_SECTIONS = (_FILTER, _NAT, _SETS)
_MARKERS = re.compile(
    r"vti\+|ipsecPolicy|ipsec_ports|ipsec_remote_subnets|ipsec_site_to_site|Policy-Based IPsec Site-to-Site VPN"
    r"|Do not NAT outbound IPsec site-to-site traffic|\[WAN_LOCAL\]Allow (?:IPsec|ESP)",
    re.IGNORECASE,
)
_SHARED_SETS = re.compile(r'"!?(?:VPN_subnets|remote_site_vpn_network)"')
_ZONE_DISPATCH = {15: "WAN", 21: "LAN", 27: "GUEST", 33: "VPN", 39: "DMZ"}


def scrub_ipsec_policy(udapi: dict, intent: IpsecIntent) -> dict:
    """Exclude generated IPsec rules when hashing the unmanaged configuration."""
    if not isinstance(udapi, dict) or not isinstance(intent, IpsecIntent):
        raise IpsecIntentError("IPsec companion normalization needs the decoded intent and UDAPI object")
    if intent.peer is None:
        if _SECTION in udapi:
            raise IpsecIntentError("IPsec companion snapshot disagrees with the absent tunnel")
        _reject_leftover_references(udapi)
        return deepcopy(udapi)
    entries = udapi.get(_SECTION)
    if (
        not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict)
        or _decode_peer(entries[0], intent.scope) != intent.peer
    ):
        raise IpsecIntentError("IPsec companion snapshot disagrees with the decoded tunnel")

    result = deepcopy(udapi)
    del result[_SECTION]
    _scrub_filter(result.get(_FILTER))
    _scrub_nat(result.get(_NAT), intent.scope.wan_id)
    _scrub_sets(result.get(_SETS), intent.scope.remote_selector)
    _reject_leftover_references(result)
    _require_shared_set_dispatch(result)
    return result


def _scrub_filter(chains):
    for index, chain, description, interface_field, target in (
        (0, "INPUT", "Forward IPSEC_SITE_TO_SITE traffic to VPN_LOCAL", "inInterface", "VPN_LOCAL"),
        (6, "OUTPUT", "Forward IPSEC_SITE_TO_SITE traffic to LOCAL_VPN", "outInterface", "LOCAL_VPN"),
        (13, "FORWARD_IN", "VPN_IN jump (interface: vti+) ", "inInterface", "VPN_IN"),
    ):
        rules = _chain_rules(chains, index, chain, 5)
        _require_rule(rules[4], {
            "connectionState": [], "description": description, "id": 30004, "ipVersion": "both",
            interface_field: {"id": "vti+"}, "log": False, "negateInInterface": False,
            "negateOutInterface": False, "protocol": "all", "target": target,
        })
        rules.pop()

    wan_local = _chain_rules(chains, 1, "WAN_LOCAL", 8)
    _require_rule(wan_local[2], {
        "description": "[WAN_LOCAL]Allow IPsec", "destination": {"sets": ["ipsec_ports"]},
        "id": 30002, "ipVersion": "v4only", "log": False, "protocol": "udp", "target": "ACCEPT",
    })
    _require_rule(wan_local[3], {
        "description": "[WAN_LOCAL]Allow ESP", "id": 30003, "ipVersion": "v4only", "log": False,
        "protocol": "esp", "target": "ACCEPT",
    })
    _require_policy_rule(wan_local[6], "WAN_LOCAL", 30006, "corporate_network")
    for index, label, icmp_type in (
        (4, "Solicitations", "neighbor-solicitation"), (5, "Advertisements", "neighbor-advertisement"),
    ):
        _require_rule(wan_local[index], {
            "description": f"[WAN_LOCAL]Allow Neighbor {label}", "id": 30000 + index, "icmpv6Type": icmp_type,
            "ipVersion": "v6only", "log": False, "protocol": "icmpv6", "target": "ACCEPT",
        })
        wan_local[index]["id"] -= 2
    del wan_local[6]
    del wan_local[2:4]

    wan_lan = _chain_rules(chains, 18, "WAN_LAN", 4)
    _require_policy_rule(wan_lan[0], "WAN_LAN", 30000, "LAN_corporate_network")
    for index, description, target, states in (
        (1, "Allow Return Traffic", "ACCEPT", ["established", "related"]),
        (2, "Block Invalid Traffic", "DROP", ["invalid"]),
    ):
        _require_rule(wan_lan[index], {
            "description": f"[WAN_LAN]{description}", "id": 30000 + index, "ipVersion": "both",
            "log": False, "target": target, "connectionState": states,
        })
        wan_lan[index]["id"] -= 1
    del wan_lan[0]


def _chain_rules(chains, index, name, count):
    if not isinstance(chains, list) or len(chains) <= index:
        raise IpsecIntentError("IPsec companion lacks its ordered generated firewall chains")
    chain = chains[index]
    if (not isinstance(chain, dict) or not isinstance(chain.get("config"), dict)
            or chain["config"].get("name") != name or not isinstance(chain.get("rules"), list)
            or len(chain["rules"]) != count):
        raise IpsecIntentError("IPsec companion differs from its ordered generated firewall chains")
    return chain["rules"]


def _require_policy_rule(rule, chain, rule_id, destination):
    _require_rule(rule, {
        "description": f"[{chain}]Allow Policy-Based IPsec Site-to-Site VPN", "id": rule_id,
        "destination": {"sets": [destination]}, "source": {"sets": ["ipsec_remote_subnets"]},
        "ipsecPolicy": "match_inbound_ipsec", "ipVersion": "v4only", "log": False, "target": "ACCEPT",
    })


def _require_rule(rule, expected):
    origin = rule.get("originId") if isinstance(rule, dict) else None
    try:
        identity = UUID(origin) if isinstance(origin, str) else None
    except ValueError:
        identity = None
    if identity is None or str(identity) != origin or identity.version != 4:
        raise IpsecIntentError("IPsec companion lacks a generated native firewall origin")
    if not _same(rule, {**expected, "originId": origin}):
        raise IpsecIntentError("IPsec companion firewall rule differs from the expected IPsec policy")


def _scrub_nat(rules, wan_id):
    if not isinstance(rules, list) or len(rules) != 2:
        raise IpsecIntentError("IPsec companion needs its two ordered source NAT rules")
    native = {"chain": "POSTROUTING", "enabled": True, "ipVersion": "v4only", "log": False,
              "outInterface": {"id": wan_id}}
    if not _same(rules[0], {
        **native, "description": "Do not NAT outbound IPsec site-to-site traffic", "id": 1,
        "destination": {"sets": ["ipsec_remote_subnets"]}, "target": "RETURN",
    }):
        raise IpsecIntentError("IPsec companion lacks its exact remote-selector NAT exemption")
    _require_rule(rules[1], {
        **native, "id": 2, "source": {"sets": [f"!ALL_ADDRv4_{wan_id}"]}, "target": "MASQUERADE",
    })
    rules[1]["id"] = 1
    del rules[0]


def _scrub_sets(sets, remote_selector):
    if not isinstance(sets, list) or len(sets) != 29 or any(not isinstance(row, dict) for row in sets):
        raise IpsecIntentError("IPsec companion lacks its ordered generated firewall sets")
    for index, name, kind, description, entries in (
        (9, "VPN_subnets", "address", "Vpn zone subnets", [remote_selector]),
        (19, "remote_site_vpn_network", "address", "remote site VPN subnets", [remote_selector]),
        (27, "ipsec_ports", "port", "IPSec VPN ports", ["500", "4500"]),
        (28, "ipsec_remote_subnets", "address", "IPSec remote subnets", [remote_selector]),
    ):
        if not _same(sets[index], {"description": description, "identification": {"name": name, "type": kind},
                                   "entries": entries}):
            raise IpsecIntentError("IPsec companion firewall set differs from the expected IPsec policy")
    del sets[9]["entries"]
    del sets[19]["entries"]
    del sets[27:]


def _same(value, expected):
    return json.dumps(value, sort_keys=True) == json.dumps(expected, sort_keys=True)


def _reject_leftover_references(udapi):
    for section in _SECTIONS:
        if _MARKERS.search(json.dumps(udapi.get(section))):
            raise IpsecIntentError("Unexpected IPsec reference remains in unmanaged firewall or NAT policy")


def _require_shared_set_dispatch(udapi):
    for key, value in udapi.items():
        if key not in {_FILTER, _SETS} and _SHARED_SETS.search(json.dumps(value)):
            raise IpsecIntentError("An unmanaged policy refers to a firewall set changed by IPsec")
    if any(_SHARED_SETS.search(json.dumps(row.get("entries"))) for row in udapi[_SETS]):
        raise IpsecIntentError("An unmanaged firewall set refers to a set changed by IPsec")
    for index, chain in enumerate(udapi[_FILTER]):
        if not _SHARED_SETS.search(json.dumps(chain)):
            continue
        zone = _ZONE_DISPATCH.get(index)
        if zone is None:
            raise IpsecIntentError("An unmanaged chain refers to a firewall set changed by IPsec")
        rules = _chain_rules(udapi[_FILTER], index, f"{zone}_IN", 7)
        target = f"{zone}_VPN"
        _require_rule(rules[3], {
            "id": 30003, "target": target, "description": f"{target} jump ", "log": False, "protocol": "all",
            "destination": {"sets": ["VPN_subnets"]}, "ipVersion": "both",
        })
        if _SHARED_SETS.search(json.dumps({**chain, "rules": [*rules[:3], *rules[4:]]})):
            raise IpsecIntentError("An unmanaged rule refers to a firewall set changed by IPsec")
