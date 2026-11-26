"""Decode a UniFi routed VLAN and plan its owned VyOS VIF."""

from copy import deepcopy
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network, ip_interface
import json
import re
from uuid import UUID

from collectors.vyos import interface_ipv4_addresses
from provisioners.uxg_schema import selected_schema


_CONTROLLER_PORTS = ("eth1", "eth2", "eth3")
_LAN_JUMPS = {"INPUT": ("LAN_LOCAL", "inInterface"), "OUTPUT": ("LOCAL_LAN", "outInterface"),
              "FORWARD_IN": ("LAN_IN", "inInterface")}
_SUBNET_GROUPS = ("LAN_subnets", "LAN_corporate_network", "local_zoned_subnets", "corporate_network", "local_network")
_IPV4_LITERAL = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:/[0-9]+)?")


class VlanIntentError(ValueError):
    """The gateway configuration does not establish the owned VyOS VLAN."""


@dataclass(frozen=True, slots=True)
class VlanScope:
    parent: str
    vlan_id: int
    address: str

    def __post_init__(self):
        if not isinstance(self.parent, str) or re.fullmatch(r"eth[0-9]{1,7}", self.parent) is None:
            raise VlanIntentError("VLAN needs an existing VyOS Ethernet parent")
        if type(self.vlan_id) is not int or not 1 <= self.vlan_id <= 4094:
            raise VlanIntentError("VLAN needs one explicit tagged ID from 1 to 4094")
        try:
            gateway = IPv4Interface(self.address) if isinstance(self.address, str) else None
        except ValueError:
            gateway = None
        if (
            gateway is None or str(gateway) != self.address or gateway.network.prefixlen == 0
            or gateway.ip.is_multicast or gateway.ip.is_loopback or gateway.ip.is_link_local
            or gateway.ip.is_reserved or not gateway.network.network_address < gateway.ip < gateway.network.broadcast_address
        ):
            raise VlanIntentError("VLAN needs a canonical IPv4 gateway address and client subnet")

    @property
    def interface(self) -> str:
        return f"{self.parent}.{self.vlan_id}"

    @property
    def bridge(self) -> str:
        return f"br{self.vlan_id}"


@dataclass(frozen=True, slots=True)
class VlanPlan:
    desired_vif: dict | None
    commands: tuple[dict, ...]


@dataclass(frozen=True, slots=True)
class VlanIntent:
    revision: str
    scope: VlanScope
    present: bool


def decode_vlan_intent(
    system_cfg: str, *, revision: str, scope: VlanScope,
    message_broker=False, dns_forwarder=False, nat=False, wireguard=False,
) -> VlanIntent:
    """Decode a routed bridge and its tagged Ethernet member."""
    if not isinstance(revision, str) or not revision:
        raise VlanIntentError("VLAN snapshot needs a controller revision")
    if not isinstance(scope, VlanScope) or not isinstance(system_cfg, str):
        raise VlanIntentError("VLAN snapshot needs a configured scope and a JSON string")
    try:
        document = json.loads(system_cfg, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except VlanIntentError:
        raise
    except (ValueError, RecursionError):
        raise VlanIntentError("VLAN snapshot is not valid JSON") from None

    udapi = document.get("udapi") if isinstance(document, dict) else None
    versions = udapi.get("versionDetail") if isinstance(udapi, dict) else None
    expected = selected_schema(
        message_broker=message_broker, dns_forwarder=dns_forwarder, nat=nat, wireguard=wireguard,
    )
    if (
        not _matches(versions, expected) or type(udapi.get("version")) is not int
        or udapi["version"] != 48 or udapi.get("versionFormat") != "v2"
    ):
        raise VlanIntentError("Unsupported UDAPI VLAN schema")
    return VlanIntent(revision, scope, bool(_native_vlan_positions(udapi, scope)))


def scrub_vlan_policy(udapi: dict, intent: VlanIntent, *, managed_mdns: bool = False) -> dict:
    """Exclude generated VLAN configuration from comparison after validation."""
    if not isinstance(udapi, dict) or not isinstance(intent, VlanIntent) or type(managed_mdns) is not bool:
        raise VlanIntentError("VLAN policy needs a matched UDAPI snapshot and intent")
    services = udapi.get("services")
    if managed_mdns and (not isinstance(services, dict) or "mdns" in services):
        raise VlanIntentError("Managed mDNS must be normalized before VLAN policy")
    scope = intent.scope
    positions = _native_vlan_positions(udapi, scope)
    if bool(positions) is not intent.present:
        raise VlanIntentError("VLAN snapshot differs from the decoded intent")

    normalized = deepcopy(udapi)
    origins = []
    if intent.present:
        for position in sorted(positions, reverse=True):
            normalized["interfaces"].pop(position)
        origins = _remove_lan_jumps(normalized, scope.bridge)
        _remove_subnet_group_entries(normalized, scope.address)
        _remove_service_references(normalized, scope.bridge, managed_mdns=managed_mdns)
    _reject_residual_vlan_references(normalized, scope, set(origins))
    return normalized


def _unique_fields(pairs):
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise VlanIntentError("VLAN snapshot contains a duplicate JSON field")
        fields[key] = value
    return fields


def _invalid_constant(_value):
    raise VlanIntentError("VLAN snapshot contains a non-JSON constant")


def _matches(value, expected):
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return value.keys() == expected.keys() and all(_matches(value[key], item) for key, item in expected.items())
    if isinstance(expected, list):
        return len(value) == len(expected) and all(_matches(a, b) for a, b in zip(value, expected))
    return value == expected


def _indexed_rows(rows, section, field):
    if not isinstance(rows, list):
        raise VlanIntentError("VLAN snapshot needs complete interfaces, firewall chains, and sets")
    result = {}
    for index, row in enumerate(rows):
        identity = row.get(section) if isinstance(row, dict) else None
        name = identity.get(field) if isinstance(identity, dict) else None
        if not isinstance(name, str) or not name or name in result:
            raise VlanIntentError("VLAN snapshot contains an invalid or duplicate identity")
        result[name] = (index, row)
    return result


def _native_vlan_positions(udapi, scope):
    indexed = _indexed_rows(udapi.get("interfaces"), "identification", "id")
    anchors = {port: "ethernet" for port in _CONTROLLER_PORTS} | {"br0": "bridge"}
    if any(
        name not in indexed or indexed[name][1]["identification"].get("type") != kind
        for name, kind in anchors.items()
    ):
        raise VlanIntentError("VLAN snapshot lacks the expected Ethernet interfaces and LAN bridge")

    tag = scope.vlan_id
    members = {f"{port}.{tag}": port for port in _CONTROLLER_PORTS}
    reserved = {
        name for name, (_, row) in indexed.items()
        if name == scope.bridge or name.endswith(f".{tag}") or any(
            isinstance(row.get(field), dict) and row[field].get("id") == tag for field in ("vlan", "bridge")
        )
    }
    if not reserved:
        return ()
    if reserved != members.keys() | {scope.bridge}:
        raise VlanIntentError("VLAN snapshot has incomplete or foreign tag membership")

    positions = []
    for name, port in members.items():
        position, row = indexed[name]
        expected = {
            "identification": {"id": name, "type": "vlan"}, "status": {"enabled": True},
            "vlan": {"id": tag, "interface": {"id": port}},
        }
        if position != indexed[port][0] + 1 or not _matches(row, expected):
            raise VlanIntentError("VLAN member differs from the expected tagged interface")
        positions.append(position)

    bridge_position, bridge = indexed[scope.bridge]
    expected_bridge = {
        "identification": {"id": scope.bridge, "type": "bridge"}, "status": {"enabled": True, "comment": "LAN"},
        "addresses": [{"type": "static", "cidr": scope.address, "version": "v4"}],
        "bridge": {"interfaces": [{"id": name} for name in members], "id": tag},
    }
    if bridge_position != indexed["br0"][0] + 1 or not _matches(bridge, expected_bridge):
        raise VlanIntentError("VLAN bridge differs from the mapped routed LAN")
    return (*positions, bridge_position)


def _remove_lan_jumps(udapi, bridge):
    indexed = _indexed_rows(udapi.get("firewall/filter"), "config", "name")
    origins = []
    for name, (target, direction) in _LAN_JUMPS.items():
        chain = indexed[name][1] if name in indexed else {}
        rules = chain.get("rules")
        if not isinstance(rules, list) or len(rules) <= 4 or not isinstance(rules[4], dict):
            raise VlanIntentError("VLAN snapshot lacks its generated LAN firewall jump")
        candidate = rules[4]
        origin = candidate.get("originId")
        expected = {
            "id": 30004, "target": target, "description": f"{target} jump (interface: {bridge})",
            "log": False, direction: {"id": bridge}, "ipVersion": "both", "originId": origin,
        }
        if not _uuid(origin) or origin in origins or not _matches(candidate, expected) or any(
            index != 4 and isinstance(rule, dict) and rule.get("id") == 30004
            for index, rule in enumerate(rules)
        ):
            raise VlanIntentError("VLAN LAN jump differs from the expected LAN firewall rule")
        origins.append(origin)
        rules.pop(4)
    return origins


def _uuid(value):
    if not isinstance(value, str):
        return False
    try:
        parsed = UUID(value)
    except ValueError:
        return False
    return bool(parsed.int and str(parsed) == value)


def _remove_subnet_group_entries(udapi, address):
    indexed = _indexed_rows(udapi.get("firewall/sets"), "identification", "name")
    subnet = str(IPv4Interface(address).network)
    position = None
    for name in _SUBNET_GROUPS:
        row = indexed[name][1] if name in indexed else {}
        entries = row.get("entries")
        if (
            row.get("identification") != {"name": name, "type": "address"}
            or not isinstance(entries, list) or len(entries) < 2 or entries.count(subnet) != 1
        ):
            raise VlanIntentError("VLAN snapshot lacks its exact generated LAN subnet entry")
        # Native creates use a common insertion point, which varies between revisions.
        index = entries.index(subnet)
        if position is not None and position != index:
            raise VlanIntentError("VLAN snapshot mixes generated LAN subnet positions")
        position = index
        entries.pop(index)


def _remove_service_references(udapi, bridge, *, managed_mdns):
    services = udapi.get("services")
    listeners = [("dnsForwarder", "listenInterfaces", 1)]
    if not managed_mdns:
        listeners.append(("mdns", "interfaces", 3))
    for service, field, index in listeners:
        row = services.get(service) if isinstance(services, dict) else None
        interfaces = row.get(field) if isinstance(row, dict) else None
        if not isinstance(interfaces, list) or len(interfaces) <= index or interfaces[index] != {"id": bridge}:
            raise VlanIntentError("VLAN snapshot lacks its exact generated service listener")
        interfaces.pop(index)


def _reject_residual_vlan_references(udapi, scope, origins):
    network = IPv4Interface(scope.address).network
    interface_ref = re.compile(rf"\b(?:{scope.bridge}|eth[0-9]+\.{scope.vlan_id})\b", re.IGNORECASE)
    pending = [udapi]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            if value.lower() in origins or interface_ref.search(value) or _scoped_ipv4(value, network):
                raise VlanIntentError("Unmanaged UDAPI contains a reference to the owned VLAN")


def _scoped_ipv4(value, network):
    if _IPV4_LITERAL.fullmatch(value) is None:
        return False
    try:
        return IPv4Network(value, strict=False).subnet_of(network)
    except ValueError:
        return False


def plan_vlan_commands(
    *, scope: VlanScope, present: bool, current_ethernet: dict,
    verified_vif: dict | None, live_interfaces: dict,
) -> VlanPlan:
    """Plan against fresh link/config evidence and the previously verified subtree."""
    if type(present) is not bool:
        raise VlanIntentError("VLAN planning needs explicit presence or removal")
    parent_active, current = _read_vlan(scope, current_ethernet, live_interfaces)
    expected = {"address": scope.address}
    if current != verified_vif or (verified_vif is not None and verified_vif != expected):
        raise VlanIntentError("VyOS VLAN differs from verified ownership")
    if scope.interface in live_interfaces:
        _, addresses = _live_ipv4(live_interfaces[scope.interface])
        if current is None or (addresses and addresses != [IPv4Interface(scope.address)]):
            raise VlanIntentError("Live VyOS VLAN differs from verified ownership")

    desired = expected if present else None
    if present:
        _require_active_parent(parent_active)
        _check_overlap(scope, current_ethernet, live_interfaces)
    if current == desired:
        _verify_link(scope, desired, live_interfaces)
        return VlanPlan(desired, ())

    path = ["interfaces", "ethernet", scope.parent, "vif", str(scope.vlan_id)]
    if desired is None:
        return VlanPlan(None, ({"op": "delete", "path": path},))
    return VlanPlan(desired, ({"op": "set", "path": path + ["address"], "value": scope.address},))


def verify_vlan_state(
    *, scope: VlanScope, expected_vif: dict | None, current_ethernet: dict, live_interfaces: dict,
) -> None:
    """Check the exact configured VIF and its operational presence or absence."""
    parent_active, current = _read_vlan(scope, current_ethernet, live_interfaces)
    if current != expected_vif or (expected_vif is not None and expected_vif != {"address": scope.address}):
        raise VlanIntentError("VyOS VLAN read-back differs from the intended subtree")
    if expected_vif is not None:
        _require_active_parent(parent_active)
        _check_overlap(scope, current_ethernet, live_interfaces)
    _verify_link(scope, expected_vif, live_interfaces)


def _read_vlan(scope, ethernet, live):
    if not isinstance(scope, VlanScope) or not isinstance(ethernet, dict) or not isinstance(live, dict):
        raise VlanIntentError("VLAN planning needs a configured scope and complete VyOS interface snapshots")
    parent = ethernet.get(scope.parent)
    if not isinstance(parent, dict) or scope.parent not in live:
        raise VlanIntentError("VyOS VLAN parent lacks existing Ethernet configuration or link")
    flags, _ = _live_ipv4(live[scope.parent])
    parent_active = "disable" not in parent and {"UP", "LOWER_UP"}.issubset(flags)
    vifs = _vifs(parent)
    tag = str(scope.vlan_id)
    current = vifs.get(tag)
    if tag in vifs and not isinstance(current, dict):
        raise VlanIntentError("Unexpected VyOS VLAN ownership subtree")
    return parent_active, current


def _vifs(ethernet):
    vifs = ethernet.get("vif", {})
    if not isinstance(vifs, dict):
        raise VlanIntentError("Unexpected VyOS VIF collection")
    return vifs


def _live_ipv4(link):
    if (
        not isinstance(link, (tuple, list)) or len(link) != 2
        or not isinstance(link[0], (tuple, list)) or not isinstance(link[1], str)
    ):
        raise VlanIntentError("Unexpected VyOS operational interface read-back")
    try:
        addresses = interface_ipv4_addresses(link[1])
    except ValueError:
        raise VlanIntentError("Invalid IPv4 address in VyOS operational interface read-back") from None
    return link[0], addresses


def _require_active_parent(parent_active):
    if not parent_active:
        raise VlanIntentError("VyOS VLAN parent needs an active Ethernet link")


def _verify_link(scope, expected, live):
    if expected is None:
        if scope.interface in live:
            raise VlanIntentError("Owned VyOS VLAN link remains after removal")
        return
    if scope.interface not in live:
        raise VlanIntentError("Owned VyOS VLAN link is not active")
    flags, addresses = _live_ipv4(live[scope.interface])
    if not {"UP", "LOWER_UP"}.issubset(flags) or addresses != [IPv4Interface(scope.address)]:
        raise VlanIntentError("Owned VyOS VLAN link is not active with the pinned IPv4 address")


def _check_overlap(scope, ethernet, live):
    network = IPv4Interface(scope.address).network
    for name, link in live.items():
        if name != scope.interface and any(network.overlaps(entry.network) for entry in _live_ipv4(link)[1]):
            raise VlanIntentError("Managed VLAN subnet overlaps another live VyOS interface")
    for name, interface in ethernet.items():
        if not isinstance(interface, dict):
            raise VlanIntentError("Unexpected VyOS Ethernet interface configuration")
        siblings = [
            vif for tag, vif in _vifs(interface).items()
            if (name, tag) != (scope.parent, str(scope.vlan_id))
        ]
        for tree in [interface, *siblings]:
            if any(network.overlaps(entry.network) for entry in _configured_ipv4(tree)):
                raise VlanIntentError("Managed VLAN subnet overlaps another configured VyOS Ethernet interface")


def _configured_ipv4(tree):
    if not isinstance(tree, dict):
        raise VlanIntentError("Unexpected VyOS Ethernet VIF configuration")
    addresses = tree.get("address", [])
    if isinstance(addresses, str):
        addresses = [addresses]
    if not isinstance(addresses, list) or any(not isinstance(value, str) for value in addresses):
        raise VlanIntentError("Unexpected VyOS Ethernet address configuration")
    for value in addresses:
        if value in ("dhcp", "dhcpv6"):
            continue
        try:
            address = ip_interface(value)
        except ValueError:
            raise VlanIntentError("Invalid configured VyOS interface address") from None
        if isinstance(address, IPv4Interface):
            yield address
