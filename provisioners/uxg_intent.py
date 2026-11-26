"""Decode the supported UniFi LAN_LAN firewall intent without side effects."""

from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network
import json
import re
from uuid import UUID

from provisioners.uxg_schema import selected_schema

_CHAIN_NAME = "LAN_LAN"
_ALLOW_ALL_ID = 2147483647
_ALLOW_ALL = {
    "id": _ALLOW_ALL_ID,
    "target": "ACCEPT",
    "description": "[LAN_LAN]Allow All Traffic",
    "log": False,
    "ipVersion": "both",
}
_RULE_FIELDS = {
    "id", "target", "description", "protocol", "source", "destination",
    "connectionState", "ipVersion",
}
_LOGGED_RULE_FIELDS = _RULE_FIELDS | {"log"}
_ACTIONS = {"DROP": "drop", "REJECT": "reject", "ACCEPT": "return"}
_PROTOCOLS = ("tcp", "udp")
_CONNECTION_STATES = ("established", "invalid", "new", "related")
_RETURN_STATES = ("established", "related")
_RETURN_SUFFIX = " (Return)"


class FirewallIntentError(ValueError):
    """A controller snapshot did not establish supported firewall intent."""


@dataclass(frozen=True, slots=True)
class FirewallRule:
    controller_rule_id: int
    source: IPv4Network | IPv6Network
    destination: IPv4Network | IPv6Network
    port: int | str
    action: str = "drop"
    states: tuple[str, ...] = ()
    source_port: bool = False
    log: bool = True
    protocol: str = "tcp"

    def __post_init__(self):
        if self.action not in _ACTIONS.values():
            raise FirewallIntentError("Unsupported LAN_LAN rule action")
        if self.protocol not in _PROTOCOLS:
            raise FirewallIntentError("Unsupported LAN_LAN rule protocol")
        if (
            not isinstance(self.states, tuple) or any(state not in _CONNECTION_STATES for state in self.states)
            or len(set(self.states)) != len(self.states)
        ):
            raise FirewallIntentError("Unsupported LAN_LAN connection states")
        if type(self.source_port) is not bool or type(self.log) is not bool:
            raise FirewallIntentError("Invalid LAN_LAN port direction or logging")
        if self.protocol == "udp" and (
            self.action != "drop" or self.states or self.source_port or self.log
            or not isinstance(self.source, IPv4Network) or not isinstance(self.destination, IPv4Network)
        ):
            raise FirewallIntentError("Unsupported LAN_LAN UDP rule")
        if type(self.port) is int:
            valid_port = 1 <= self.port <= 65535
        else:
            limits = (re.fullmatch(r"([1-9][0-9]{0,4})-([1-9][0-9]{0,4})", self.port)
                      if self.protocol == "udp" and isinstance(self.port, str) else None)
            valid_port = limits is not None and int(limits[1]) < int(limits[2]) <= 65535
        if not valid_port:
            raise FirewallIntentError(f"LAN_LAN rule {self.controller_rule_id} has an unsupported {self.protocol.upper()} port")
        if self.action == "return":
            if (
                not isinstance(self.source, (IPv4Network, IPv6Network))
                or not isinstance(self.destination, (IPv4Network, IPv6Network))
                or self.source.version != self.destination.version
                or (self.source_port and (self.log or self.states != _RETURN_STATES))
            ):
                raise FirewallIntentError("Unsupported LAN_LAN Allow rule")
        elif self.source_port:
            raise FirewallIntentError("Unsupported LAN_LAN deny rule")


@dataclass(frozen=True, slots=True)
class FirewallIntent:
    revision: str
    rules: tuple[FirewallRule, ...]


def decode_firewall_intent(
    system_cfg: str, *, revision: str, message_broker=False, dns_forwarder=False, nat=False, wireguard=False,
) -> FirewallIntent:
    """Return the ordered rules from a complete supported controller snapshot."""
    if not isinstance(revision, str) or not revision:
        raise FirewallIntentError("The firewall snapshot needs a controller revision")
    if not isinstance(system_cfg, str):
        raise FirewallIntentError("system_cfg must be a JSON string")
    try:
        envelope = json.loads(system_cfg, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except FirewallIntentError:
        raise
    except (ValueError, RecursionError) as error:
        raise FirewallIntentError("system_cfg is not valid JSON") from error

    udapi = envelope.get("udapi") if isinstance(envelope, dict) else None
    if not isinstance(udapi, dict):
        raise FirewallIntentError("system_cfg has no UDAPI configuration object")
    versions = udapi.get("versionDetail")
    expected_versions = selected_schema(message_broker=message_broker, dns_forwarder=dns_forwarder,
                                        nat=nat, wireguard=wireguard)
    if (
        type(udapi.get("version")) is not int or udapi["version"] != 48
        or udapi.get("versionFormat") != "v2"
        or versions != expected_versions or any(type(value) is not int for value in versions.values())
    ):
        raise FirewallIntentError("Unsupported UDAPI firewall schema version")

    chains = _index_by_name(udapi.get("firewall/filter"), "config", "firewall/filter")
    chain = chains.get(_CHAIN_NAME)
    if chain is None or chain.keys() != {"config", "rules"}:
        raise FirewallIntentError("The snapshot needs a complete LAN_LAN chain")
    config = chain["config"]
    if config.keys() != {"name", "logDefault"} or config["logDefault"] is not False:
        raise FirewallIntentError("Unsupported LAN_LAN chain configuration")
    rules = chain["rules"]
    if not isinstance(rules, list) or not rules:
        raise FirewallIntentError("The LAN_LAN chain has no final allow rule")
    _check_final_allow(rules[-1])

    sets = _index_by_name(udapi.get("firewall/sets"), "identification", "firewall/sets")
    decoded_rules = []
    rule_ids = set()
    earlier_allows = {}
    paired_allows = set()
    for rule in rules[:-1]:
        decoded = _decode_rule(rule, sets)
        rule_id = decoded.controller_rule_id
        if rule_id in rule_ids:
            raise FirewallIntentError(f"Duplicate LAN_LAN rule ID {rule_id}")
        rule_ids.add(rule_id)
        if decoded.action == "return":
            source_refs = tuple(rule["source"]["sets"])
            destination_refs = tuple(rule["destination"]["sets"])
            description = rule["description"]
            if decoded.source_port:
                parent = (description, destination_refs, source_refs)
                if earlier_allows.get(parent) != 1 or parent in paired_allows:
                    raise FirewallIntentError(f"LAN_LAN Return companion {rule_id} needs one unpaired earlier Allow")
                paired_allows.add(parent)
            else:
                parent = (description + _RETURN_SUFFIX, source_refs, destination_refs)
                earlier_allows[parent] = earlier_allows.get(parent, 0) + 1
        decoded_rules.append(decoded)
    return FirewallIntent(revision=revision, rules=tuple(decoded_rules))


def _unique_object(pairs):
    value = {}
    for key, entry in pairs:
        if key in value:
            raise FirewallIntentError("system_cfg has a duplicate JSON field")
        value[key] = entry
    return value


def _invalid_constant(_value):
    raise FirewallIntentError("system_cfg contains a non-JSON constant")


def _index_by_name(entries, identity_field, section):
    if not isinstance(entries, list):
        raise FirewallIntentError(f"UDAPI {section} must be a list")
    indexed = {}
    for entry in entries:
        identity = entry.get(identity_field) if isinstance(entry, dict) else None
        name = identity.get("name") if isinstance(identity, dict) else None
        if not isinstance(name, str) or not name:
            raise FirewallIntentError(f"UDAPI {section} contains an unnamed entry")
        if name in indexed:
            raise FirewallIntentError(f"UDAPI {section} contains a duplicate name")
        indexed[name] = entry
    return indexed


def _check_final_allow(rule):
    if (
        not isinstance(rule, dict) or rule.keys() != _ALLOW_ALL.keys() | {"originId"}
        or type(rule["id"]) is not int or rule["log"] is not False
        or rule != {**_ALLOW_ALL, "originId": rule["originId"]}
    ):
        raise FirewallIntentError("The LAN_LAN chain must end with its built-in allow rule")
    origin = rule["originId"]
    if not isinstance(origin, str):
        raise FirewallIntentError("The LAN_LAN allow rule has no valid origin ID")
    try:
        parsed = UUID(origin)
    except ValueError as error:
        raise FirewallIntentError("The LAN_LAN allow rule has no valid origin ID") from error
    if str(parsed) != origin.lower():
        raise FirewallIntentError("The LAN_LAN allow rule has no valid origin ID")


def _decode_rule(rule, sets):
    if not isinstance(rule, dict) or rule.keys() not in (_RULE_FIELDS, _LOGGED_RULE_FIELDS):
        raise FirewallIntentError("LAN_LAN contains a rule with unsupported fields")
    rule_id = rule["id"]
    if type(rule_id) is not int or not 0 < rule_id < _ALLOW_ALL_ID:
        raise FirewallIntentError("LAN_LAN contains an invalid policy rule ID")
    target, protocol, states = rule["target"], rule["protocol"], rule["connectionState"]
    log = "log" in rule
    if (
        not isinstance(target, str) or target not in _ACTIONS or not isinstance(rule["description"], str)
        or (log and rule["log"] is not True) or protocol not in _PROTOCOLS
        or not isinstance(states, list) or any(not isinstance(state, str) for state in states)
        or rule["ipVersion"] not in ("v4only", "v6only")
    ):
        raise FirewallIntentError(f"Unsupported LAN_LAN rule options for rule {rule_id}")
    source_refs = _references(rule["source"], "source", rule_id)
    dest_refs = _references(rule["destination"], "destination", rule_id)
    selector_sizes = len(source_refs), len(dest_refs)
    if selector_sizes not in ((1, 2), (2, 1)):
        raise FirewallIntentError(f"LAN_LAN rule {rule_id} needs two address sets and one port set")
    source_port = selector_sizes == (2, 1)
    if len(set(source_refs + dest_refs)) != 3:
        raise FirewallIntentError(f"Duplicate set reference in LAN_LAN rule {rule_id}")
    network_type = IPv4Network if rule["ipVersion"] == "v4only" else IPv6Network
    source = _network(_singleton(sets, source_refs[0], "address", rule_id), rule_id, network_type)
    destination = _network(_singleton(sets, dest_refs[0], "address", rule_id), rule_id, network_type)
    port_ref = source_refs[1] if source_port else dest_refs[1]
    port_text = _singleton(sets, port_ref, "port", rule_id)
    port = int(port_text) if re.fullmatch(r"[0-9]{1,5}", port_text) else port_text
    return FirewallRule(rule_id, source, destination, port, action=_ACTIONS[target],
                        states=tuple(sorted(states)), source_port=source_port, log=log, protocol=protocol)


def _references(selector, field, rule_id):
    refs = selector.get("sets") if isinstance(selector, dict) and selector.keys() == {"sets"} else None
    if not isinstance(refs, list) or len(refs) not in (1, 2) or any(not isinstance(ref, str) or not ref for ref in refs):
        raise FirewallIntentError(f"Unsupported {field} selector in LAN_LAN rule {rule_id}")
    return refs


def _singleton(sets, name, kind, rule_id):
    entry = sets.get(name)
    if (
        entry is None or entry.keys() - {"identification", "description", "entries"}
        or entry["identification"] != {"name": name, "type": kind}
        or not isinstance(entry.get("description", ""), str)
    ):
        raise FirewallIntentError(f"LAN_LAN rule {rule_id} has a missing or unsupported {kind} set")
    values = entry.get("entries")
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str):
        raise FirewallIntentError(f"LAN_LAN rule {rule_id} needs a singleton {kind} set")
    return values[0]


def _network(value, rule_id, network_type):
    try:
        network = network_type(value)
    except ValueError as error:
        raise FirewallIntentError(f"LAN_LAN rule {rule_id} needs a single CIDR in its configured address family") from error
    if str(network) != value:
        raise FirewallIntentError(f"LAN_LAN rule {rule_id} needs a canonical CIDR")
    return network
