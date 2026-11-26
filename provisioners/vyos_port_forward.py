"""Plan one pinned WAN-peer TCP forward with a separately enforced firewall guard."""

from dataclasses import dataclass
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
import json
import re
from uuid import UUID

from provisioners.uxg_schema import selected_schema


_DNAT_PATH = ("nat", "destination", "rule")
_DESCRIPTION = "UniFi managed TCP port forward"
_ACCOUNTING = ("WAN_PF_IN", "WAN_PF_OUT")
_TCP = {"log": False, "protocol": "tcp", "ipVersion": "v4only"}
_COMMAND_FIELDS = (
    ("description",), ("protocol",), ("inbound-interface", "name"), ("source", "address"),
    ("destination", "address"), ("destination", "port"), ("translation", "address"), ("translation", "port"),
)
_OPERATOR_DNAT_FIELDS = {
    "description", "protocol", "inbound-interface", "source", "destination", "translation", "log",
}


class PortForwardIntentError(ValueError):
    """The gateway configuration does not establish an owned port forward."""


@dataclass(frozen=True, slots=True)
class PortForwardScope:
    wan_id: str
    wan_interface: str
    wan_cidr: str
    peer: str
    lan_bridge: str
    lan_interface: str
    lan_cidr: str
    target: str
    rule_base: int
    ports: tuple[tuple[int, int], ...]

    def __post_init__(self):
        wan, lan = _interface_cidr(self.wan_cidr), _interface_cidr(self.lan_cidr)
        peer, target = _host(self.peer), _host(self.target)
        if (self.wan_id != "eth0" or not _ethernet_vlan(self.wan_interface)
                or not _ethernet_vlan(self.lan_interface) or self.wan_interface == self.lan_interface
                or self.lan_bridge != "br" + self.lan_interface.rsplit(".", 1)[1]):
            raise PortForwardIntentError("Port forward requires a pinned primary WAN VLAN and separate LAN bridge")
        if (wan.network.overlaps(lan.network) or not _usable(wan.ip, wan.network)
                or not _usable(lan.ip, lan.network) or not _usable(peer, wan.network)
                or not _usable(target, lan.network) or peer == wan.ip or target == lan.ip):
            raise PortForwardIntentError("Port forward requires separate on-link WAN peer and LAN target hosts")
        if type(self.rule_base) is not int or not 1 <= self.rule_base <= 999999:
            raise PortForwardIntentError("Invalid reserved VyOS destination NAT rule slot")
        if not isinstance(self.ports, (list, tuple)) or not self.ports:
            raise PortForwardIntentError("Port forward needs explicit, approved WAN and target port pairs")
        pairs = []
        for pair in self.ports:
            if (not isinstance(pair, (tuple, list)) or len(pair) != 2
                    or any(type(port) is not int or not 1 <= port <= 65535 for port in pair)):
                raise PortForwardIntentError("Port forward needs valid TCP port pairs")
            pairs.append(tuple(pair))
        if len(set(pairs)) != len(pairs):
            raise PortForwardIntentError("Port forward scope contains duplicate TCP port pairs")
        object.__setattr__(self, "ports", tuple(pairs))

    @property
    def wan_address(self):
        return self.wan_cidr.partition("/")[0]

    @property
    def slots(self):
        return (str(self.rule_base),)


@dataclass(frozen=True, slots=True)
class PortForward:
    wan_port: int
    target_port: int
    name: str
    _nat_indices: tuple[int, int]


@dataclass(frozen=True, slots=True)
class PortForwardIntent:
    revision: str
    scope: PortForwardScope
    forward: PortForward | None
    section_digest: str

    @property
    def filter_match(self):
        """Exact post-DNAT match for the caller's same-transaction firewall guard."""
        if self.forward is None:
            return None
        return {
            "protocol": "tcp", "inbound-interface": {"name": self.scope.wan_interface},
            "outbound-interface": {"name": self.scope.lan_interface},
            "source": {"address": self.scope.peer},
            "destination": {"address": self.scope.target, "port": str(self.forward.target_port)},
        }


@dataclass(frozen=True, slots=True)
class PortForwardPlan:
    desired_rules: dict
    commands: tuple[dict, ...]


def decode_port_forward_intent(
    system_cfg: str, *, revision: str, scope: PortForwardScope,
    dns_forwarder: bool = False, message_broker: bool = False, wireguard: bool = False,
) -> PortForwardIntent:
    """Validate the native DNAT, implicit sets, hairpin and generated firewall policy."""
    if not isinstance(revision, str) or not revision:
        raise PortForwardIntentError("Port forward snapshot needs a controller revision")
    if not isinstance(system_cfg, str) or not isinstance(scope, PortForwardScope):
        raise PortForwardIntentError("Port forward needs a JSON snapshot and explicit scope")
    try:
        document = json.loads(system_cfg, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except PortForwardIntentError:
        raise
    except (ValueError, RecursionError) as error:
        raise PortForwardIntentError("Port forward snapshot is not valid JSON") from error

    udapi = document.get("udapi") if isinstance(document, dict) else None
    versions = udapi.get("versionDetail") if isinstance(udapi, dict) else None
    expected = selected_schema(dns_forwarder=dns_forwarder, message_broker=message_broker, nat=True)
    if wireguard:
        expected["vpn/wireguard/servers"] = 6
    if (versions != expected or any(type(version) is not int for version in versions.values())
            or type(udapi.get("version")) is not int or udapi["version"] != 48 or udapi.get("versionFormat") != "v2"):
        raise PortForwardIntentError("Unsupported UDAPI port forward schema")
    _prove_controller_interfaces(udapi, scope)
    forward = _decode_nat(udapi.get("firewall/nat"), scope)
    _verify_firewall(udapi.get("firewall/filter"), scope, forward)
    return PortForwardIntent(revision, scope, forward, _section_digest(udapi))


def port_forward_remainder(udapi, intent: PortForwardIntent):
    """Keep unrelated configuration and remove only the validated native projection."""
    if not isinstance(intent, PortForwardIntent) or _section_digest(udapi) != intent.section_digest:
        raise PortForwardIntentError("Port forward policy differs from the verified snapshot")
    result = dict(udapi)
    if intent.forward is None:
        return result
    result["firewall/nat"] = [row for index, row in enumerate(udapi["firewall/nat"])
                             if index not in intent.forward._nat_indices]
    chains = []
    for chain in udapi["firewall/filter"]:
        name = chain["config"]["name"]
        if name in _ACCOUNTING:
            continue
        if name == "FORWARD_IN":
            chain = {**chain, "rules": [{**row, "id": row["id"] - 1} for row in chain["rules"][1:]]}
        elif name == "FORWARD_OUT":
            chain = {"config": chain["config"]}
        elif name == "WAN_LAN":
            returned, invalid, default = chain["rules"][1:]
            chain = {**chain, "rules": [{**returned, "id": 30000}, {**invalid, "id": 30001}, default]}
        chains.append(chain)
    result["firewall/filter"] = chains
    return result


def plan_port_forward_commands(
    intent: PortForwardIntent, *, scope: PortForwardScope,
    current_rules: dict, verified_rules: dict, live_interface_addresses: dict,
) -> PortForwardPlan:
    """Plan DNAT only. The caller must stage the exact firewall guard in the same batch."""
    if not isinstance(intent, PortForwardIntent) or intent.scope != scope:
        raise PortForwardIntentError("Port forward intent belongs to another configured scope")
    if not isinstance(current_rules, dict) or not isinstance(verified_rules, dict):
        raise PortForwardIntentError("Port forward needs the complete VyOS destination NAT and verified rule maps")
    if not set(verified_rules).issubset(scope.slots):
        raise PortForwardIntentError("Verified destination NAT rules escape the configured slot")
    for number, rule in current_rules.items():
        if (not isinstance(number, str) or re.fullmatch(r"[1-9][0-9]{0,5}", number) is None
                or not isinstance(rule, dict)):
            raise PortForwardIntentError("Invalid VyOS destination NAT rule collection")
    slot = scope.slots[0]
    if slot in verified_rules:
        _verify_readback(verified_rules[slot], scope)
    owned = {slot: current_rules[slot]} if slot in current_rules else {}
    if owned != verified_rules:
        raise PortForwardIntentError("VyOS destination NAT differs from the last verified ownership")

    forward = intent.forward
    desired = {}
    if forward is not None:
        if (forward.wan_port, forward.target_port) not in scope.ports:
            raise PortForwardIntentError("Port forward port pair escapes the approved scope")
        _prove_live_interfaces(live_interface_addresses, scope)
        for operator_slot, rule in current_rules.items():
            if operator_slot != slot and not _operator_disjoint(rule, scope, forward):
                raise PortForwardIntentError(f"Operator destination NAT rule {operator_slot} may match the managed flow")

        desired[slot] = _desired_rule(scope, forward.wan_port, forward.target_port)

    if desired == owned:
        return PortForwardPlan(desired, ())
    path = [*_DNAT_PATH, slot]
    commands = [{"op": "delete", "path": path}] if owned else []
    if desired:
        after = desired[slot]
        for keys in _COMMAND_FIELDS:
            value = after[keys[0]] if len(keys) == 1 else after[keys[0]][keys[1]]
            commands.append({"op": "set", "path": path + list(keys), "value": value})
    return PortForwardPlan(desired, tuple(commands))


def _unique_fields(pairs):
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise PortForwardIntentError("Port forward snapshot contains a duplicate JSON field")
        fields[key] = value
    return fields


def _invalid_constant(_value):
    raise PortForwardIntentError("Port forward snapshot contains a non-JSON constant")


def _host(value):
    try:
        address = IPv4Address(value)
    except ValueError as error:
        raise PortForwardIntentError("Port forward needs a canonical IPv4 host address") from error
    if address.is_multicast or address.is_loopback or address.is_unspecified or address.is_reserved or str(address) != value:
        raise PortForwardIntentError("Port forward needs a canonical unicast IPv4 host address")
    return address


def _interface_cidr(value):
    try:
        address = IPv4Interface(value)
    except ValueError as error:
        raise PortForwardIntentError("Port forward needs a canonical static IPv4 CIDR") from error
    if str(address) != value or not 0 < address.network.prefixlen < 32:
        raise PortForwardIntentError("Port forward needs a canonical static IPv4 CIDR")
    _host(str(address.ip))
    return address


def _usable(ip, network):
    return ip in network and (network.prefixlen == 31 or network.network_address < ip < network.broadcast_address)


def _ethernet_vlan(name):
    match = re.fullmatch(r"eth[0-9]+\.([1-9][0-9]{0,3})", name) if isinstance(name, str) else None
    return match is not None and len(name) <= 15 and int(match[1]) <= 4094


def _port(value):
    if not isinstance(value, str) or re.fullmatch(r"[1-9][0-9]{0,4}", value) is None or int(value) > 65535:
        raise PortForwardIntentError("Port forward requires single decimal TCP ports")
    return int(value)


def _id(value):
    return type(value) is int and 1 <= value <= 2147483647


def _has_origin(value):
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except ValueError:
        return False


def _matches(row, expected, *, origin=False):
    if not isinstance(row, dict) or not _id(row.get("id")) or row.get("log") is not False:
        return False
    if "enabled" in expected and row.get("enabled") is not True:
        return False
    if origin:
        if not _has_origin(row.get("originId")):
            return False
        expected = {**expected, "originId": row["originId"]}
    return row == expected


def _prove_controller_interfaces(udapi, scope):
    rows = udapi.get("interfaces")
    if not isinstance(rows, list):
        raise PortForwardIntentError("Port forward requires an explicit native interface list")
    interfaces = {}
    for row in rows:
        identity = row.get("identification") if isinstance(row, dict) else None
        name = identity.get("id") if isinstance(identity, dict) else None
        if not isinstance(name, str) or not name or name in interfaces:
            raise PortForwardIntentError("Port forward snapshot has an invalid or duplicate interface ID")
        interfaces[name] = row
    for name, kind, cidr in ((scope.wan_id, "ethernet", scope.wan_cidr), (scope.lan_bridge, "bridge", scope.lan_cidr)):
        row = interfaces.get(name, {})
        status = row.get("status")
        if (row.get("identification") != {"id": name, "type": kind} or not isinstance(status, dict)
                or status.get("enabled") is not True
                or row.get("addresses") != [{"type": "static", "cidr": cidr, "version": "v4"}]):
            raise PortForwardIntentError(f"Native interface {name} does not match the pinned static IPv4 scope")
    bridge = interfaces[scope.lan_bridge].get("bridge")
    if not isinstance(bridge, dict) or type(bridge.get("id")) is not int or bridge["id"] != int(scope.lan_bridge[2:]):
        raise PortForwardIntentError("Native port forward LAN bridge has a different VLAN ID")

    sets = udapi.get("firewall/sets")
    if not isinstance(sets, list):
        raise PortForwardIntentError("Port forward requires an explicit native set list")
    implicit = {f"KEY_ADDRv4_{scope.wan_id}", f"ALL_NETv4_{scope.lan_bridge}", f"ALL_ADDRv4_{scope.wan_id}"}
    for entry in sets:
        identity = entry.get("identification") if isinstance(entry, dict) else None
        name = identity.get("name") if isinstance(identity, dict) else None
        if not isinstance(name, str) or name in implicit:
            raise PortForwardIntentError("Port forward has an invalid set or override of an interface-generated set")


def _decode_nat(rows, scope):
    if not isinstance(rows, list):
        raise PortForwardIntentError("Port forward requires a complete native NAT list")
    ids = set()
    wan_masquerades, forwards, hairpins, unrelated = [], [], [], []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not _id(row.get("id")) or row["id"] in ids:
            raise PortForwardIntentError("Native NAT list contains an invalid or duplicate rule ID")
        ids.add(row["id"])
        chain, target = row.get("chain"), row.get("target")
        if chain == "PREROUTING" or target == "DNAT":
            forwards.append(index)
        elif chain != "POSTROUTING":
            raise PortForwardIntentError("Unsupported native NAT chain")
        elif _matches(row, {
            "id": row["id"], "chain": "POSTROUTING", "target": "MASQUERADE", "enabled": True,
            "log": False, "source": {"sets": [f"!ALL_ADDRv4_{scope.wan_id}"]},
            "outInterface": {"id": scope.wan_id}, "ipVersion": "v4only",
        }, origin=True):
            wan_masquerades.append(index)
        elif isinstance(row.get("description"), str) and row["description"].startswith("PortForward MASQUERADE"):
            hairpins.append(index)
        else:
            unrelated.append(row)
    if len(wan_masquerades) != 1:
        raise PortForwardIntentError("Port forward needs the observed, unchanged WAN masquerade rule")
    if not forwards and not hairpins:
        return None
    if len(forwards) != 1 or len(hairpins) != 1 or hairpins[0] != forwards[0] + 1:
        raise PortForwardIntentError("Port forward requires exactly one ordered DNAT and its hairpin companion")
    if any(not _unrelated_native_nat(row, scope) for row in unrelated):
        raise PortForwardIntentError("An unrelated native NAT rule may match the managed forwarded flow")

    row, hairpin = rows[forwards[0]], rows[hairpins[0]]
    label = row.get("description")
    label = re.fullmatch(r"PortForward DNAT \[([^\r\n]{1,200})\]", label) if isinstance(label, str) else None
    destination, translation = row.get("destination"), row.get("translation")
    if label is None or not isinstance(destination, dict) or not isinstance(translation, dict):
        raise PortForwardIntentError("Native port forward has no complete DNAT match and translation")
    wan_port, target_port = _port(destination.get("port")), _port(translation.get("port"))
    if (wan_port, target_port) not in scope.ports:
        raise PortForwardIntentError("Native port forward uses an unapproved TCP port pair")
    source = {"address": scope.peer}
    target = {"address": scope.target, "port": str(target_port)}
    if not _matches(row, {
        **_TCP, "id": row["id"], "chain": "PREROUTING", "target": "DNAT", "enabled": True,
        "description": label[0], "source": source,
        "destination": {"sets": [f"KEY_ADDRv4_{scope.wan_id}"], "port": str(wan_port)}, "translation": target,
    }):
        raise PortForwardIntentError("Native DNAT expands or changes the approved scoped packet match")
    if not _matches(hairpin, {
        **_TCP, "id": row["id"] + 1, "chain": "POSTROUTING", "target": "MASQUERADE", "enabled": True,
        "description": f"PortForward MASQUERADE [{label[1]}]", "source": {"sets": [f"ALL_NETv4_{scope.lan_bridge}"]},
        "destination": target,
    }):
        raise PortForwardIntentError("Native port forward's hairpin companion changes its LAN-only match")
    return PortForward(wan_port, target_port, label[1], (forwards[0], hairpins[0]))


def _unrelated_native_nat(row, scope):
    outgoing = row.get("outInterface")
    if isinstance(outgoing, dict) and outgoing.keys() == {"id"}:
        name = outgoing["id"]
        if isinstance(name, str) and name != scope.lan_bridge and re.fullmatch(r"(?:eth|br)[0-9]+", name):
            return True
    if row.get("protocol") == "udp":
        return True
    source = row.get("source")
    if isinstance(source, dict) and source.keys() == {"address"}:
        network = _address_network(source["address"])
        return network is not None and IPv4Address(scope.peer) not in network
    return False


def _verify_firewall(rows, scope, forward):
    if not isinstance(rows, list):
        raise PortForwardIntentError("Port forward needs the complete native firewall chain list")
    chains = {}
    for row in rows:
        config = row.get("config") if isinstance(row, dict) else None
        name = config.get("name") if isinstance(config, dict) else None
        if not isinstance(name, str) or not name or name in chains:
            raise PortForwardIntentError("Native firewall contains an invalid or duplicate chain")
        chains[name] = row
    _verify_wan_lan(chains, scope, forward)
    _verify_forward_jumps(chains, scope, forward is not None)
    if forward is None:
        if any(name in chains for name in _ACCOUNTING):
            raise PortForwardIntentError("Native firewall contains accounting without an approved port forward")
        return
    _verify_accounting(chains, scope, forward)


def _chain_rules(chains, name):
    chain = chains.get(name)
    if (chain is None or chain.keys() != {"config", "rules"}
            or chain["config"] != {"name": name, "logDefault": False} or chain["config"]["logDefault"] is not False
            or not isinstance(chain["rules"], list)):
        raise PortForwardIntentError(f"Port forward needs the supported native {name} chain")
    return chain["rules"]


def _verify_wan_lan(chains, scope, forward):
    rules = _chain_rules(chains, "WAN_LAN")
    offset = int(forward is not None)
    if len(rules) != 3 + offset:
        raise PortForwardIntentError("Unexpected native WAN_LAN rules")
    original = (
        {"id": 30000 + offset, "target": "ACCEPT", "description": "[WAN_LAN]Allow Return Traffic",
         "log": False, "connectionState": ["established", "related"], "ipVersion": "both"},
        {"id": 30001 + offset, "target": "DROP", "description": "[WAN_LAN]Block Invalid Traffic",
         "log": False, "connectionState": ["invalid"], "ipVersion": "both"},
        {"id": 2147483647, "target": "DROP", "description": "[WAN_LAN]Block All Traffic",
         "log": False, "ipVersion": "both"},
    )
    if any(not _matches(row, expected, origin=True) for row, expected in zip(rules[offset:], original)):
        raise PortForwardIntentError("Native WAN_LAN baseline safeguards differ from the supported policy")
    if forward is not None and not _matches(rules[0], {
        **_TCP, "id": 30000, "target": "ACCEPT",
        "description": f"[WAN_LAN]Allow Port Forward {forward.name}", "source": {"address": scope.peer},
        "destination": {"address": scope.target, "port": str(forward.target_port)},
    }, origin=True):
        raise PortForwardIntentError("Native WAN_LAN allowance does not match the exact forwarded flow")


def _verify_forward_jumps(chains, scope, active):
    original = _chain_rules(chains, "FORWARD_IN")
    if not original:
        raise PortForwardIntentError("Native port forward needs the original forwarding jump list")
    offset = int(active)
    if active:
        first = original[0]
        if not _matches(first, {
            "id": 30000, "target": "WAN_PF_IN", "description": f"WAN_IN_PF jump (interface: {scope.wan_id})",
            "log": False, "inInterface": {"id": scope.wan_id}, "ipVersion": "both",
        }, origin=True):
            raise PortForwardIntentError("Unexpected native inbound accounting jump")
        outgoing = _chain_rules(chains, "FORWARD_OUT")
        if len(outgoing) != 1 or not _matches(outgoing[0], {
            "id": 30000, "target": "WAN_PF_OUT", "description": f"WAN_OUT_PF jump (interface: {scope.wan_id})",
            "log": False, "outInterface": {"id": scope.wan_id}, "ipVersion": "both",
        }, origin=True):
            raise PortForwardIntentError("Unexpected native outbound accounting jump")
    else:
        outgoing = chains.get("FORWARD_OUT")
        if (outgoing != {"config": {"name": "FORWARD_OUT", "logDefault": False}}
                or outgoing["config"]["logDefault"] is not False):
            raise PortForwardIntentError("Unexpected native outbound jump without a port forward")

    seen = set()
    for index, row in enumerate(original[offset:]):
        interface = row.get("inInterface") if isinstance(row, dict) else None
        interface = interface.get("id") if isinstance(interface, dict) else None
        target = "WAN_IN" if index == 0 else "LAN_IN"
        if (not isinstance(interface, str) or interface in seen
                or (index == 0 and interface != scope.wan_id)
                or (index != 0 and re.fullmatch(r"br[0-9]+", interface) is None)
                or not _matches(row, {
                    "id": 30000 + index + offset, "target": target,
                    "description": f"{target} jump (interface: {interface})", "log": False,
                    "inInterface": {"id": interface}, "ipVersion": "both",
                }, origin=True)):
            raise PortForwardIntentError("Native forwarding jump order cannot be normalized safely")
        seen.add(interface)
    if scope.lan_bridge not in seen:
        raise PortForwardIntentError("Native forwarding jumps do not cover the pinned LAN bridge")


def _verify_accounting(chains, scope, forward):
    incoming = _chain_rules(chains, "WAN_PF_IN")
    outgoing = _chain_rules(chains, "WAN_PF_OUT")
    if len(incoming) != 1 or len(outgoing) != 1 or not isinstance(incoming[0], dict):
        raise PortForwardIntentError("Native port forward needs one accounting rule per direction")
    rule_id = incoming[0].get("id")
    peer = {"address": scope.peer}
    target = {"address": scope.target, "port": str(forward.target_port)}
    for name, row, source, destination in (
        ("WAN_PF_IN", incoming[0], peer, target), ("WAN_PF_OUT", outgoing[0], target, peer),
    ):
        if not _matches(row, {
            **_TCP, "id": rule_id, "target": "RETURN",
            "description": f"[{name}] PortForward Accounting [{forward.name}]",
            "source": source, "destination": destination,
        }, origin=True):
            raise PortForwardIntentError(f"Native {name} accounting changes the scoped port forward")


def _section_digest(udapi):
    if not isinstance(udapi, dict):
        raise PortForwardIntentError("Port forward needs a UDAPI object")
    material = [udapi.get("firewall/nat"), udapi.get("firewall/filter")]
    return sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _desired_rule(scope, wan_port, target_port):
    return {
        "description": _DESCRIPTION, "protocol": "tcp", "inbound-interface": {"name": scope.wan_interface},
        "source": {"address": scope.peer}, "destination": {"address": scope.wan_address, "port": str(wan_port)},
        "translation": {"address": scope.target, "port": str(target_port)},
    }


def _verify_readback(rule, scope):
    destination = rule.get("destination") if isinstance(rule, dict) else None
    translation = rule.get("translation") if isinstance(rule, dict) else None
    if not isinstance(destination, dict) or not isinstance(translation, dict):
        raise PortForwardIntentError("Invalid verified VyOS destination NAT rule")
    ports = _port(destination.get("port")), _port(translation.get("port"))
    if (ports not in scope.ports
            or rule != _desired_rule(scope, *ports)):
        raise PortForwardIntentError("Verified VyOS destination NAT rule escapes the configured scope")


def _prove_live_interfaces(addresses, scope):
    for interface, cidr in ((scope.wan_interface, scope.wan_cidr), (scope.lan_interface, scope.lan_cidr)):
        live = addresses.get(interface) if isinstance(addresses, dict) else None
        if not isinstance(live, (list, tuple)) or tuple(live) != (cidr,):
            raise PortForwardIntentError(f"Live VyOS interface {interface} does not have the pinned IPv4 CIDR")


def _address_network(value):
    if not isinstance(value, str):
        return None
    try:
        network = IPv4Network(value)
    except ValueError:
        return None
    return network if value in (str(network), str(network.network_address)) else None


def _operator_disjoint(rule, scope, forward):
    ingress = rule.get("inbound-interface")
    if isinstance(ingress, dict) and ingress.keys() == {"name"}:
        name = ingress["name"]
        if isinstance(name, str) and name not in (scope.wan_interface, "any") and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name):
            return True
    protocol = rule.get("protocol")
    if protocol == "udp":
        return True
    source = rule.get("source")
    if isinstance(source, dict) and source.keys() == {"address"}:
        network = _address_network(source["address"])
        if network is not None and IPv4Address(scope.peer) not in network:
            return True
    destination = rule.get("destination")
    translation = rule.get("translation")
    if rule.keys() - _OPERATOR_DNAT_FIELDS or protocol not in ("tcp", "tcp_udp"):
        return False
    # The firewall guard matches the translated tuple, so the operator rule
    # must be disjoint both before and after DNAT if its ingress and peer overlap.
    return (
        _destination_disjoint(destination, scope.wan_address, forward.wan_port)
        and _destination_disjoint(translation, scope.target, forward.target_port)
    )


def _destination_disjoint(selector, address, port):
    if not isinstance(selector, dict) or selector.keys() - {"address", "port"}:
        return False
    network = _address_network(selector.get("address"))
    if network is not None and IPv4Address(address) not in network:
        return True
    try:
        return _port(selector.get("port")) != port
    except PortForwardIntentError:
        return False
