"""Translate the native Shadow management firewall policy to stock VyOS."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network

from provisioners.vyos_firewall_commands import _set_commands


_LAN_GROUP = ("firewall", "group", "network-group", "UXGSHADOW-LAN")
_MGMT_GROUP = ("firewall", "group", "address-group", "UXGSHADOW-MGMT")
_RULE_PATHS = tuple(("firewall", "ipv4", chain, "filter", "rule", "1") for chain in ("forward", "input"))
_GUARD_PATHS = (_LAN_GROUP, _MGMT_GROUP, *_RULE_PATHS)
_STATE_POLICY = ("firewall", "global-options", "state-policy")
_FLOWTABLE = ("firewall", "flowtable")
_BRIDGES = ("interfaces", "bridge")
SHADOW_GUARD_CONTAINERS = (("firewall", "group"), ("firewall", "ipv4", "input"))
_NATIVE_SET = "vrrp_mgmt_addr"
_SOURCE_SET = "local_network"


def _stock_path(configuration, path):
    for part in path:
        if not isinstance(configuration, dict):
            raise ValueError("Malformed VyOS Shadow management firewall configuration")
        if part not in configuration:
            return None
        configuration = configuration[part]
    return configuration


def _group_matches(actual, expected):
    if not isinstance(actual, dict) or actual.keys() != expected.keys():
        return False
    name, members = next(iter(actual.items()))
    if isinstance(members, str):
        members = [members]
    return (isinstance(members, list) and all(isinstance(member, str) for member in members)
            and sorted(members) == sorted(expected[name]))


@dataclass(frozen=True)
class ShadowManagementGuard:
    networks: tuple[str, ...]
    addresses: tuple[str, ...]

    @property
    def paths(self):
        return _GUARD_PATHS

    @property
    def eligibility_paths(self):
        return (*self.paths, _STATE_POLICY, _FLOWTABLE, _BRIDGES)

    def _stock_rules(self):
        rule = {
            "action": "drop",
            "source": {"group": {"network-group": _LAN_GROUP[-1]}},
            "destination": {"group": {"address-group": _MGMT_GROUP[-1]}},
        }
        return ({"network": list(self.networks)}, {"address": list(self.addresses)}, rule, rule)

    def verify_stock(self, configuration, *, installed, interconnect=None):
        actual = tuple(_stock_path(configuration, path) for path in self.paths)
        if installed:
            expected = self._stock_rules()
            if (not all(_group_matches(left, right) for left, right in zip(actual[:2], expected[:2]))
                    or actual[2:] != expected[2:]):
                raise ValueError("VyOS Shadow management firewall differs from the verified drops")
        elif any(value is not None for value in actual):
            raise ValueError("VyOS Shadow management firewall resources are already in use")
        state = _stock_path(configuration, _STATE_POLICY)
        if state is not None and (not isinstance(state, dict) or any(
            not isinstance(rule, dict) or rule.get("action") not in ("drop", "reject") for rule in state.values()
        )):
            raise ValueError("VyOS global state policy may bypass the Shadow management drops")
        if _stock_path(configuration, _FLOWTABLE):
            raise ValueError("VyOS flow offload needs separate qualification for Shadow management drops")
        bridges = _stock_path(configuration, _BRIDGES)
        if interconnect is not None and bridges is not None:
            if not isinstance(bridges, dict):
                raise ValueError("Invalid VyOS bridge configuration")
            for bridge in bridges.values():
                members = _stock_path(bridge, ("member", "interface"))
                if members is not None and (not isinstance(members, dict) or any(
                    member == interconnect or member.startswith(f"{interconnect}.") for member in members
                )):
                    raise ValueError("VyOS Shadow management interconnect must be routed independently")

    def create_commands(self):
        commands = []
        for path, value in zip(self.paths, self._stock_rules()):
            _set_commands(commands, list(path), value)
        return commands

    def created_containers(self, preimage):
        """Remember the stock containers that were absent before staging."""
        return tuple(path for path in SHADOW_GUARD_CONTAINERS if _stock_path(preimage, path) is None)

    def withdraw_commands(self, configuration, *, created_containers=()):
        self.verify_stock(configuration, installed=True)
        owned = set(self.paths)
        for path in SHADOW_GUARD_CONTAINERS:
            if path in created_containers and _only_owned(_stock_path(configuration, path), path, owned):
                owned = {leaf for leaf in owned if leaf[:len(path)] != path}
                owned.add(path)
        return [{"op": "delete", "path": list(path)} for path in sorted(owned, reverse=True)]


def _only_owned(tree, path, owned):
    if path in owned:
        return True
    return isinstance(tree, dict) and bool(tree) and all(
        _only_owned(value, (*path, key), owned) for key, value in tree.items()
    )


def _set_rows(sets, name):
    return [row for row in sets if isinstance(row.get("identification"), dict)
            and row["identification"].get("name") == name]


def _normalize_generated_lan_rules(rules):
    for number, rule in enumerate(rules, start=60002):
        source = rule.get("source") if isinstance(rule, dict) else None
        address = source.get("address") if isinstance(source, dict) else None
        expected = {
            "id": number, "target": "RETURN", "ipVersion": "v4only", "source": {"address": address},
            "description": f"[LAN_IN]Allow Network {address} Traffic",
        }
        if rule != expected or not isinstance(address, str) or type(rule["id"]) is not int:
            break
        if str(IPv4Network(address)) != address:
            raise ValueError("Shadow management guard changed the generated LAN rule")
        rule["id"] -= 1


def normalize_shadow_management_guard(udapi, *, source, peer):
    """Extract the exact native guard and undo only its generated LAN rule renumbering."""
    sets = udapi.get("firewall/sets", [])
    if not isinstance(sets, list) or not all(isinstance(row, dict) for row in sets):
        raise ValueError("Invalid Shadow management firewall sets")
    management = _set_rows(sets, _NATIVE_SET)
    if not management:
        return None
    addresses = (source, peer)
    expected_set = {"identification": {"name": _NATIVE_SET, "type": "address"},
                    "description": "VRRP management addresses", "entries": list(addresses)}
    sources = _set_rows(sets, _SOURCE_SET)
    if management != [expected_set] or len(sources) != 1 or sources[0]["identification"] != {
        "name": _SOURCE_SET, "type": "address",
    }:
        raise ValueError("Invalid Shadow management firewall address sets")
    entries = sources[0].get("entries")
    if not isinstance(entries, list) or not entries or any(not isinstance(value, str) for value in entries):
        raise ValueError("Shadow management firewall requires explicit local IPv4 networks")
    networks = tuple(IPv4Network(value) for value in entries)
    if (tuple(map(str, networks)) != tuple(entries) or len(set(networks)) != len(networks)
            or any(IPv4Address(address) in network for address in addresses for network in networks)):
        raise ValueError("Shadow management firewall cannot isolate the native source networks")
    chains = udapi.get("firewall/filter")
    if not isinstance(chains, list) or not all(isinstance(row, dict) for row in chains):
        raise ValueError("Invalid Shadow management firewall chain inventory")
    for name in ("LAN_IN", "LAN_LOCAL"):
        matches = [row for row in chains if isinstance(row.get("config"), dict) and row["config"].get("name") == name]
        rules = matches[0].get("rules") if len(matches) == 1 else None
        expected = {
            "id": 60001, "target": "DROP", "ipVersion": "v4only", "protocol": "all",
            "source": {"sets": [_SOURCE_SET]}, "destination": {"sets": [_NATIVE_SET]},
            "description": f"[{name}] Forbid Accessing Shadow Mode Management Link",
        }
        if (not isinstance(rules, list) or not rules or rules[0] not in (expected, expected | {"log": False})
                or type(rules[0]["id"]) is not int or rules[0].get("log", False) is not False):
            raise ValueError("Unsupported Shadow management firewall guard")
        rules.pop(0)
        if name == "LAN_IN":
            _normalize_generated_lan_rules(rules)
    sets.remove(expected_set)
    return ShadowManagementGuard(tuple(entries), addresses)
