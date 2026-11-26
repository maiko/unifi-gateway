"""Exclude validated WireGuard rules when comparing unmanaged policy."""

from copy import deepcopy
from ipaddress import IPv4Interface, IPv4Network
import re
from uuid import UUID

from provisioners.vyos_wireguard import WireGuardIntent, WireGuardIntentError, _decode_server, _SERVER_SECTION


_FILTER = "firewall/filter"
_SETS = "firewall/sets"
_PORT_SET = "wireguard_ports"
_SUBNET_SETS = {
    "VPN_subnets": "Vpn zone subnets",
    "remote_user_vpn_network": "Remote User VPN subnets",
}
_ZONE_JUMPS = {
    "INPUT": ("VPN_LOCAL", "inInterface", "Forward WIREGUARD_SERVER traffic to VPN_LOCAL"),
    "OUTPUT": ("LOCAL_VPN", "outInterface", "Forward WIREGUARD_SERVER traffic to LOCAL_VPN"),
    "FORWARD_IN": ("VPN_IN", "inInterface", "VPN_IN jump (interface: wgsrv+) "),
}
_ZONE_PREFIXES = ("WAN", "LAN", "GUEST", "VPN", "DMZ")
_REFERENCE = re.compile(
    r"\b(?:wireguard_ports|vpn_subnets|remote_user_vpn_network|wgsrv[0-9]*|wireguard_server)\b"
    r"|\bAllow WireGuard (?:VPNs|Server)\b",
    re.IGNORECASE,
)
_IPV4_LITERAL = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:/[0-9]+)?")


def scrub_wireguard_policy(udapi: dict, intent: WireGuardIntent) -> dict:
    """Prove ownership of the generated companions, then restore the pre-server shape."""
    if not isinstance(udapi, dict) or not isinstance(intent, WireGuardIntent):
        raise WireGuardIntentError("WireGuard policy needs a matched UDAPI snapshot and intent")
    _match_server(udapi, intent)
    normalized = deepcopy({key: value for key, value in udapi.items() if key != _SERVER_SECTION})
    chains = _named_entries(normalized.get(_FILTER), "config")
    sets = _named_entries(normalized.get(_SETS), "identification")
    active = intent.server is not None
    tunnel = IPv4Interface(intent.scope.tunnel_cidr).network

    removed = []
    if active:
        for name, (target, direction, description) in _ZONE_JUMPS.items():
            rules = _chain_rules(normalized, chains, name)
            expected = {
                "id": 30004, "target": target, "negateInInterface": False, "negateOutInterface": False,
                "description": description, "log": False, "protocol": "all", "connectionState": [],
                direction: {"id": "wgsrv+"}, "ipVersion": "both",
            }
            removed.append(_require_rule(rules, 4, expected))
            rules.pop(4)

    wan_rules = _chain_rules(normalized, chains, "WAN_LOCAL")
    removed.extend(_normalize_wan_local(wan_rules, active))
    exempt = _normalize_sets(normalized, sets, tunnel, intent.server.port if active else None)
    exempt.update(_known_zone_references(normalized, chains))
    if len(set(removed)) != len(removed):
        raise WireGuardIntentError("Generated WireGuard rules share an origin reference")
    _reject_residual_references(normalized, exempt, tunnel, set(removed))
    return normalized


def _match_server(udapi, intent):
    if intent.server is None:
        if _SERVER_SECTION in udapi:
            raise WireGuardIntentError("WireGuard server differs from the decoded intent")
        return
    entries = udapi.get(_SERVER_SECTION)
    if not isinstance(entries, list) or len(entries) != 1 or _decode_server(entries[0], intent.scope) != intent.server:
        raise WireGuardIntentError("WireGuard server differs from the decoded intent")


def _named_entries(entries, field):
    if not isinstance(entries, list):
        raise WireGuardIntentError("WireGuard policy needs complete firewall chains and sets")
    names = {}
    for index, entry in enumerate(entries):
        identity = entry.get(field) if isinstance(entry, dict) else None
        name = identity.get("name") if isinstance(identity, dict) else None
        if not isinstance(name, str) or not name or name in names:
            raise WireGuardIntentError("WireGuard policy includes an invalid or duplicate chain or set name")
        names[name] = index
    return names


def _chain_rules(document, chains, name):
    chain = document[_FILTER][chains[name]] if name in chains else {}
    rules = chain.get("rules")
    if not isinstance(rules, list):
        raise WireGuardIntentError("WireGuard policy is missing a required firewall chain")
    return rules


def _rule_origin(rule, expected):
    if (
        not isinstance(rule, dict) or rule.keys() != expected.keys() | {"originId"}
        or any(type(rule[key]) is not type(value) or rule[key] != value for key, value in expected.items())
    ):
        return None
    origin = rule["originId"]
    if not isinstance(origin, str):
        return None
    try:
        parsed = UUID(origin)
    except ValueError:
        return None
    return origin if parsed.int and str(parsed) == origin else None


def _require_rule(rules, index, expected):
    origin = _rule_origin(rules[index], expected) if index < len(rules) else None
    if origin is None or any(
        position != index and isinstance(rule, dict) and rule.get("id") == expected["id"]
        for position, rule in enumerate(rules)
    ):
        raise WireGuardIntentError("WireGuard generated firewall rule differs from the expected WireGuard policy")
    return origin


def _normalize_wan_local(rules, active):
    offset = int(active)
    for index, label, icmp_type in (
        (2, "Solicitations", "neighbor-solicitation"), (3, "Advertisements", "neighbor-advertisement"),
    ):
        _require_rule(rules, index + offset, {
            "id": 30000 + index + offset, "target": "ACCEPT", "log": False, "protocol": "icmpv6",
            "description": f"[WAN_LOCAL]Allow Neighbor {label}", "icmpv6Type": icmp_type, "ipVersion": "v6only",
        })
    if not active:
        return []
    origin = _require_rule(rules, 2, {
        "id": 30002, "target": "ACCEPT", "description": "[WAN_LOCAL]Allow WireGuard VPNs",
        "log": False, "protocol": "udp", "destination": {"sets": [_PORT_SET]}, "ipVersion": "both",
    })
    rules.pop(2)
    rules[2]["id"] = 30002
    rules[3]["id"] = 30003
    return [origin]


def _normalize_sets(document, indices, tunnel, port):
    sets = document[_SETS]
    if port is None:
        if _PORT_SET in indices:
            raise WireGuardIntentError("WireGuard port set remains without an owned server")
    else:
        expected = {
            "identification": {"name": _PORT_SET, "type": "port"},
            "description": "Wireguard VPN ports", "entries": [str(port)],
        }
        if indices.get(_PORT_SET) != len(sets) - 1 or sets[-1] != expected:
            raise WireGuardIntentError("WireGuard generated port set differs from the expected WireGuard policy")
        sets.pop()
    exempt = set()
    for name, description in _SUBNET_SETS.items():
        base = {"identification": {"name": name, "type": "address"}, "description": description}
        expected = {**base, "entries": [str(tunnel)]} if port is not None else base
        index = indices.get(name)
        if index is None or sets[index] != expected:
            raise WireGuardIntentError("WireGuard generated subnet set differs from the expected WireGuard policy")
        sets[index] = base
        exempt.add((_SETS, index, "identification", "name"))
    return exempt


def _known_zone_references(document, chains):
    exempt = set()
    for zone in _ZONE_PREFIXES:
        name, target = f"{zone}_IN", f"{zone}_VPN"
        if name not in chains:
            continue
        rules = _chain_rules(document, chains, name)
        expected = {
            "id": 30003, "target": target, "description": f"{target} jump ", "log": False,
            "protocol": "all", "destination": {"sets": ["VPN_subnets"]}, "ipVersion": "both",
        }
        if len(rules) > 3 and _rule_origin(rules[3], expected) is not None:
            exempt.add((_FILTER, chains[name], "rules", 3, "destination", "sets", 0))
    return exempt


def _reject_residual_references(document, exempt, tunnel, removed_origins):
    pending = [((), document)]
    while pending:
        path, value = pending.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                if _is_reference(key, tunnel, removed_origins):
                    raise WireGuardIntentError("Unmanaged UDAPI contains a WireGuard reference")
                pending.append((path + (key,), item))
        elif isinstance(value, list):
            pending.extend((path + (index,), item) for index, item in enumerate(value))
        elif path not in exempt and _is_reference(value, tunnel, removed_origins):
            raise WireGuardIntentError("Unmanaged UDAPI contains a WireGuard reference")


def _is_reference(value, tunnel, removed_origins):
    if not isinstance(value, str):
        return False
    if value.lower() in removed_origins or _REFERENCE.search(value):
        return True
    if _IPV4_LITERAL.fullmatch(value) is None:
        return False
    try:
        return IPv4Network(value, strict=False).subnet_of(tunnel)
    except ValueError:
        return False
