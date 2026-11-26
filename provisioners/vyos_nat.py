"""Decode and plan a narrow, explicitly owned VyOS IPv4 source NAT scope."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
import json
import re
from uuid import UUID

from provisioners.uxg_schema import selected_schema

_NAT_PATH = ("nat", "source", "rule")
_RULE_LIMIT = 32
_LAST_RULE = 999999
_DESCRIPTION = "UniFi managed source NAT"
_RULE_FIELDS = {
    "id", "chain", "target", "description", "enabled", "log", "protocol",
    "source", "destination", "outInterface", "ipVersion",
}
_COMMAND_FIELDS = (
    ("description",), ("protocol",), ("outbound-interface", "name"), ("source", "address"),
    ("destination", "address"), ("destination", "port"), ("translation", "address"),
)


class NatIntentError(ValueError):
    """The gateway configuration does not establish owned source NAT rules."""


@dataclass(frozen=True)
class NatScope:
    source: str
    destination: str
    bridge: str
    interface: str
    rule_base: int
    ports: tuple[int, ...]
    translation_addresses: tuple[str, ...] = ()

    def __post_init__(self):
        source = _address_network(self.source)
        destination = _ipv4_host(self.destination)
        if source is None or str(source) != self.source or source.prefixlen == 0 or destination in source:
            raise NatIntentError("Source NAT needs a canonical source CIDR distinct from the destination")
        bridge = re.fullmatch(r"br([1-9][0-9]{0,3})", self.bridge) if isinstance(self.bridge, str) else None
        if (bridge is None or int(bridge[1]) > 4094 or not isinstance(self.interface, str)
                or len(self.interface) > 15 or re.fullmatch(rf"eth[0-9]+\.{bridge[1]}", self.interface) is None):
            raise NatIntentError("Source NAT needs a pinned controller bridge and corresponding VyOS ethernet VLAN")
        if type(self.rule_base) is not int or not 1 <= self.rule_base <= _LAST_RULE - _RULE_LIMIT + 1:
            raise NatIntentError("Invalid reserved VyOS source NAT rule range")
        if (not isinstance(self.ports, (tuple, list)) or not self.ports
                or any(type(port) is not int or not 1 <= port <= 65535 for port in self.ports)
                or len(set(self.ports)) != len(self.ports)):
            raise NatIntentError("Source NAT needs explicit, unique TCP destination ports")
        if not isinstance(self.translation_addresses, (tuple, list)):
            raise NatIntentError("Source NAT translation pins must be a list of IPv4 addresses")
        for value in self.translation_addresses:
            translation = _ipv4_host(value)
            if translation == destination or translation in source:
                raise NatIntentError("Pinned source NAT translation overlaps the source or destination")
        if len(set(self.translation_addresses)) != len(self.translation_addresses):
            raise NatIntentError("Source NAT translation pins contain a duplicate IPv4 address")
        object.__setattr__(self, "ports", tuple(self.ports))
        object.__setattr__(self, "translation_addresses", tuple(self.translation_addresses))

    @property
    def slots(self):
        return tuple(str(number) for number in range(self.rule_base, self.rule_base + _RULE_LIMIT))


@dataclass(frozen=True)
class SourceNatRule:
    controller_rule_id: int
    source: IPv4Network
    destination: IPv4Address
    port: int
    translation: IPv4Address | None


@dataclass(frozen=True)
class NatIntent:
    revision: str
    scope: NatScope
    rules: tuple[SourceNatRule, ...]


@dataclass(frozen=True)
class NatPlan:
    desired_rules: dict
    commands: tuple[dict, ...]


def decode_nat_intent(
    system_cfg: str, *, revision: str, scope: NatScope,
    dns_forwarder=False, message_broker=False, wireguard=False,
) -> NatIntent:
    """Decode the complete observed source NAT list and exact schema pins."""
    if not isinstance(revision, str) or not revision:
        raise NatIntentError("Source NAT snapshot needs a controller revision")
    if not isinstance(system_cfg, str) or not isinstance(scope, NatScope):
        raise NatIntentError("Source NAT requires a JSON snapshot and configured scope")
    try:
        document = json.loads(system_cfg, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except NatIntentError:
        raise
    except (ValueError, RecursionError) as error:
        raise NatIntentError("Source NAT snapshot is not valid JSON") from error

    udapi = document.get("udapi") if isinstance(document, dict) else None
    versions = udapi.get("versionDetail") if isinstance(udapi, dict) else None
    expected_versions = selected_schema(message_broker=message_broker, dns_forwarder=dns_forwarder,
                                        nat=True, wireguard=wireguard)
    if (versions != expected_versions or any(type(value) is not int for value in versions.values())
            or type(udapi.get("version")) is not int or udapi["version"] != 48 or udapi.get("versionFormat") != "v2"):
        raise NatIntentError("Unsupported UDAPI source NAT schema")
    entries = udapi.get("firewall/nat")
    if not isinstance(entries, list):
        raise NatIntentError("Source NAT snapshot needs an explicit list within the reserved rule capacity")
    rules = tuple(_read_rule(entry, scope) for entry in entries if not _automatic_wan_rule(entry))
    if len(rules) > _RULE_LIMIT:
        raise NatIntentError("Source NAT snapshot needs an explicit list within the reserved rule capacity")
    _validate_rules(rules, scope)
    return NatIntent(revision, scope, rules)


def outside_nat_rules(entries):
    """Preserve the controller's existing automatic WAN masquerade in the baseline."""
    return [entry for entry in entries if _automatic_wan_rule(entry)]


def _automatic_wan_rule(entry):
    if not isinstance(entry, dict):
        return False
    outbound = entry.get("outInterface")
    name = outbound.get("id") if isinstance(outbound, dict) else None
    identifier = entry.get("originId")
    if not isinstance(name, str) or re.fullmatch(r"eth[0-9]+", name) is None:
        return False
    if not isinstance(identifier, str) or type(entry.get("id")) is not int or entry["id"] < 1:
        return False
    try:
        if str(UUID(identifier)) != identifier:
            return False
    except ValueError:
        return False
    return entry == {
        "id": entry["id"], "originId": identifier, "chain": "POSTROUTING", "target": "MASQUERADE",
        "enabled": True, "log": False, "source": {"sets": [f"!ALL_ADDRv4_{name}"]},
        "outInterface": {"id": name}, "ipVersion": "v4only",
    } and entry["enabled"] is True and entry["log"] is False


def _read_rule(entry, scope):
    if not isinstance(entry, dict):
        raise NatIntentError("Source NAT entry must be an object")
    target = entry.get("target")
    if (target not in ("MASQUERADE", "SNAT")
            or entry.keys() != (_RULE_FIELDS | {"translation"} if target == "SNAT" else _RULE_FIELDS)
            or entry["chain"] != "POSTROUTING" or entry["enabled"] is not True or entry["log"] is not False
            or entry["protocol"] != "tcp" or entry["ipVersion"] != "v4only"
            or not isinstance(entry["description"], str)):
        raise NatIntentError("Unsupported source NAT rule fields or options")
    destination = entry["destination"]
    if (entry["source"] != {"address": scope.source} or entry["outInterface"] != {"id": scope.bridge}
            or not isinstance(destination, dict) or destination.keys() != {"address", "port"}
            or destination["address"] != scope.destination):
        raise NatIntentError("Source NAT rule expands or changes the approved packet match")

    translation = None
    if target == "SNAT":
        fields = entry["translation"]
        if not isinstance(fields, dict) or fields.keys() != {"address"}:
            raise NatIntentError("Source NAT only supports one explicit translation address")
        translation = _ipv4_host(fields["address"])
    port = _port(destination["port"])
    return SourceNatRule(entry["id"], IPv4Network(scope.source), IPv4Address(scope.destination), port, translation)


def plan_nat_commands(
    intent: NatIntent, *, scope: NatScope, live_interface_addresses: dict, current_rules: dict, verified_rules: dict,
) -> NatPlan:
    """Plan from the complete source rule map and the fresh observed egress CIDRs."""
    if not isinstance(intent, NatIntent) or intent.scope != scope:
        raise NatIntentError("Source NAT intent belongs to another configured scope")
    _validate_rules(intent.rules, scope)
    slots = scope.slots
    if not isinstance(current_rules, dict) or not isinstance(verified_rules, dict):
        raise NatIntentError("Source NAT planning needs complete current rules and verified ownership")
    if not set(verified_rules).issubset(slots):
        raise NatIntentError("Verified source NAT rules escape the configured slots")
    for key, rule in current_rules.items():
        if (not isinstance(key, str) or re.fullmatch(r"[1-9][0-9]{0,5}", key) is None
                or not isinstance(rule, dict)):
            raise NatIntentError("Invalid VyOS source NAT rule collection")
    for tree in verified_rules.values():
        _check_owned_tree(tree, scope)
    owned = {slot: current_rules[slot] for slot in slots if slot in current_rules}
    if owned != verified_rules:
        raise NatIntentError("VyOS source NAT rules differ from the last verified ownership")

    desired = {}
    if intent.rules:
        egress = _read_egress(live_interface_addresses, scope)
        operators = {slot: rule for slot, rule in current_rules.items() if slot not in owned}
        for slot, rule in zip(slots, intent.rules):
            if rule.translation is None:
                if len(egress) != 1:
                    raise NatIntentError("Masquerade needs one known IPv4 address on the pinned egress")
                translation = "masquerade"
            else:
                if not any(address.ip == rule.translation for address in egress):
                    raise NatIntentError("Pinned source NAT translation is absent from the live VyOS egress")
                translation = str(rule.translation)
            for operator_slot, operator in operators.items():
                if not _provably_disjoint(operator, rule, scope.interface):
                    raise NatIntentError(f"Operator source NAT rule {operator_slot} may match the managed flow")

            desired[slot] = _desired_rule(scope, rule.port, translation)

    commands = []
    for slot in slots:
        before, after = owned.get(slot), desired.get(slot)
        if before == after:
            continue
        path = [*_NAT_PATH, slot]
        if before is not None:
            commands.append({"op": "delete", "path": path})
        if after is not None:
            for keys in _COMMAND_FIELDS:
                value = after[keys[0]] if len(keys) == 1 else after[keys[0]][keys[1]]
                commands.append({"op": "set", "path": path + list(keys), "value": value})
    return NatPlan(desired, tuple(commands))


def _unique_fields(pairs):
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise NatIntentError("Source NAT snapshot contains a duplicate JSON field")
        fields[key] = value
    return fields


def _invalid_constant(_value):
    raise NatIntentError("Source NAT snapshot contains a non-JSON constant")


def _ipv4_host(value):
    try:
        address = IPv4Address(value)
    except ValueError as error:
        raise NatIntentError("Source NAT needs a single IPv4 host address") from error
    if (str(address) != value or address.is_unspecified or address.is_multicast
            or address.is_loopback or address.is_reserved):
        raise NatIntentError("Source NAT needs a canonical unicast IPv4 host address")
    return address


def _address_network(value):
    if not isinstance(value, str):
        return None
    try:
        network = IPv4Network(value)
    except ValueError:
        return None
    return network if value in (str(network), str(network.network_address)) else None


def _port(value):
    if not isinstance(value, str) or re.fullmatch(r"[1-9][0-9]{0,4}", value) is None or int(value) > 65535:
        raise NatIntentError("Source NAT needs one valid TCP destination port")
    return int(value)


def _validate_rules(rules, scope):
    if len(rules) > _RULE_LIMIT:
        raise NatIntentError("Source NAT rules exceed the reserved capacity")
    ids, ports = set(), set()
    for rule in rules:
        if (not isinstance(rule, SourceNatRule) or type(rule.controller_rule_id) is not int
                or rule.controller_rule_id < 1 or str(rule.source) != scope.source
                or str(rule.destination) != scope.destination or type(rule.port) is not int or rule.port not in scope.ports):
            raise NatIntentError("Source NAT rule does not match the approved packet scope")
        if rule.translation is not None and str(rule.translation) not in scope.translation_addresses:
            raise NatIntentError("Source NAT rule needs an explicitly approved translation address")
        if rule.controller_rule_id in ids or rule.port in ports:
            raise NatIntentError("Source NAT rules have duplicate IDs or overlapping packet matches")
        ids.add(rule.controller_rule_id)
        ports.add(rule.port)


def _desired_rule(scope, port, translation):
    return {
        "description": _DESCRIPTION, "protocol": "tcp", "outbound-interface": {"name": scope.interface},
        "source": {"address": scope.source}, "destination": {"address": scope.destination, "port": str(port)},
        "translation": {"address": translation},
    }


def _check_owned_tree(tree, scope):
    destination = tree.get("destination") if isinstance(tree, dict) else None
    translation = tree.get("translation") if isinstance(tree, dict) else None
    if not isinstance(destination, dict) or not isinstance(translation, dict):
        raise NatIntentError("Invalid verified VyOS source NAT rule")
    port = _port(destination.get("port"))
    address = translation.get("address")
    if (port not in scope.ports or address not in ("masquerade", *scope.translation_addresses)
            or tree != _desired_rule(scope, port, address)):
        raise NatIntentError("Verified VyOS source NAT rule escapes the configured scope")


def _read_egress(live, scope):
    values = live.get(scope.interface) if isinstance(live, dict) else None
    if not isinstance(values, (list, tuple)) or not values:
        raise NatIntentError("No live IPv4 address on the pinned source NAT egress")
    try:
        interfaces = [IPv4Interface(value) for value in values]
    except (ValueError, TypeError) as error:
        raise NatIntentError("Invalid live IPv4 address on the pinned source NAT egress") from error
    source = IPv4Network(scope.source)
    destination = IPv4Address(scope.destination)
    if any((address.network.overlaps(source) or address.ip == destination) for address in interfaces):
        raise NatIntentError("Source NAT egress overlaps its source or owns its destination")
    if not any(destination in address.network and (
        address.network.prefixlen == 31 or address.network.network_address < destination < address.network.broadcast_address
    ) for address in interfaces):
        raise NatIntentError("Source NAT destination is outside the pinned egress subnet")
    return interfaces


def _provably_disjoint(operator, rule, interface):
    egress = operator.get("outbound-interface")
    if isinstance(egress, dict) and egress.keys() == {"name"}:
        name = egress["name"]
        if (isinstance(name, str) and name not in (interface, "any")
                and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name)):
            return True
    protocol = operator.get("protocol")
    if protocol == "udp":
        return True
    source = operator.get("source")
    if isinstance(source, dict) and source.keys() == {"address"}:
        network = _address_network(source["address"])
        if network is not None and not network.overlaps(rule.source):
            return True
    destination = operator.get("destination")
    if isinstance(destination, dict) and destination.keys() <= {"address", "port"}:
        network = _address_network(destination.get("address"))
        if network is not None and rule.destination not in network:
            return True
        if protocol in ("tcp", "tcp_udp") and "port" in destination:
            try:
                return _port(destination["port"]) != rule.port
            except NatIntentError:
                return False
    return False
