"""Plan one scoped VyOS WireGuard server interface and redact its ownership."""

from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from hashlib import sha256
from ipaddress import IPv4Interface, IPv4Network
import json
import re

from collectors.vyos import interface_ipv4_addresses
from provisioners.uxg_schema import selected_schema


_SERVER_SECTION = "vpn/wireguard/servers"
_SERVER_FIELDS = {"id", "enabled", "name", "address", "port", "privateKey", "interfaceIPs", "remotePeers"}
_PEER_FIELDS = {"publicKey", "allowedIPs", "name"}
_PEER_NAME = "unifi-peer"
_INTERFACE_FIELDS = {"address", "port", "private-key", "peer"}
_PEER_CONFIG_FIELDS = {"allowed-ips", "public-key"}
_WIREGUARD_PATH = ("interfaces", "wireguard")
_PRIVATE_NETWORKS = tuple(map(IPv4Network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))


class WireGuardIntentError(ValueError):
    """The gateway configuration does not establish the owned WireGuard server."""


@dataclass(frozen=True, slots=True)
class WireGuardScope:
    wan_id: str
    wan_interface: str
    wan_cidr: str
    interface: str
    ports: tuple[int, ...]
    tunnel_cidr: str
    peer_cidr: str
    server_id: str = "1"

    def __post_init__(self):
        if not isinstance(self.wan_id, str) or re.fullmatch(r"eth[0-9]{1,10}", self.wan_id) is None:
            raise WireGuardIntentError("WireGuard needs an explicit controller WAN interface")
        wan = re.fullmatch(r"eth[0-9]+(?:\.([1-9][0-9]{0,3}))?", self.wan_interface) if isinstance(
            self.wan_interface, str
        ) else None
        if wan is None or len(self.wan_interface) > 15 or (wan[1] is not None and int(wan[1]) > 4094):
            raise WireGuardIntentError("WireGuard needs an explicit VyOS WAN interface")
        if not isinstance(self.interface, str) or re.fullmatch(r"wg[0-9]{1,13}", self.interface) is None:
            raise WireGuardIntentError("WireGuard needs an explicit VyOS wgN interface")
        if not isinstance(self.server_id, str) or re.fullmatch(r"[1-9][0-9]{0,9}", self.server_id) is None:
            raise WireGuardIntentError("WireGuard needs an explicit native server ID")
        if int(self.server_id) > 2147483647:
            raise WireGuardIntentError("WireGuard needs an explicit native server ID")
        if (
            not isinstance(self.ports, (list, tuple)) or not 1 <= len(self.ports) <= 8
            or any(type(port) is not int or not 1024 <= port <= 65535 for port in self.ports)
            or len(set(self.ports)) != len(self.ports)
        ):
            raise WireGuardIntentError("WireGuard needs one to eight distinct nonprivileged UDP ports")
        object.__setattr__(self, "ports", tuple(self.ports))

        wan_cidr = _ipv4_interface(self.wan_cidr)
        tunnel = _ipv4_interface(self.tunnel_cidr)
        peer = _ipv4_interface(self.peer_cidr)
        if wan_cidr.network.prefixlen == 0 or not _usable_host(wan_cidr):
            raise WireGuardIntentError("WireGuard needs a pinned unicast IPv4 WAN address")
        if (
            not any(tunnel.network.subnet_of(network) for network in _PRIVATE_NETWORKS)
            or tunnel.network.overlaps(wan_cidr.network) or not _usable_host(tunnel)
            or peer.network.prefixlen != 32 or peer.ip not in tunnel.network
            or peer.ip in (tunnel.ip, tunnel.network.network_address, tunnel.network.broadcast_address)
        ):
            raise WireGuardIntentError("WireGuard needs a separate private tunnel CIDR and one usable peer /32")

    @property
    def wan_ip(self) -> str:
        return self.wan_cidr.partition("/")[0]


@dataclass(frozen=True, slots=True)
class WireGuardServer:
    port: int
    _private_key: str = field(repr=False)
    _peer_public_key: str = field(repr=False)
    _preshared_key: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class WireGuardIntent:
    revision: str
    scope: WireGuardScope
    server: WireGuardServer | None


@dataclass(frozen=True, slots=True)
class WireGuardPlan:
    desired_interface: dict | None
    commands: tuple[dict, ...] = field(repr=False)


def decode_wireguard_intent(
    system_cfg: str, *, revision: str, scope: WireGuardScope,
    message_broker=False, dns_forwarder=False, nat=False,
) -> WireGuardIntent:
    """Decode only the one supported server and the pinned native WAN address."""
    if not isinstance(revision, str) or not revision:
        raise WireGuardIntentError("WireGuard snapshot needs a controller revision")
    if not isinstance(scope, WireGuardScope) or not isinstance(system_cfg, str):
        raise WireGuardIntentError("WireGuard snapshot needs a configured scope and a JSON string")
    try:
        document = json.loads(system_cfg, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except WireGuardIntentError:
        raise
    except (ValueError, RecursionError):
        raise WireGuardIntentError("WireGuard snapshot is not valid JSON") from None

    udapi = document.get("udapi") if isinstance(document, dict) else None
    versions = udapi.get("versionDetail") if isinstance(udapi, dict) else None
    expected = selected_schema(message_broker=message_broker, dns_forwarder=dns_forwarder, nat=nat, wireguard=True)
    if (
        versions != expected or any(type(version) is not int for version in versions.values())
        or type(udapi.get("version")) is not int or udapi["version"] != 48 or udapi.get("versionFormat") != "v2"
    ):
        raise WireGuardIntentError("Unsupported UDAPI WireGuard schema")
    _prove_controller_wan(udapi.get("interfaces"), scope)

    entries = udapi.get(_SERVER_SECTION)
    if _SERVER_SECTION not in udapi:
        return WireGuardIntent(revision, scope, None)
    if not isinstance(entries, list) or len(entries) != 1:
        raise WireGuardIntentError("WireGuard snapshot must contain exactly one server when present")
    return WireGuardIntent(revision, scope, _decode_server(entries[0], scope))


def redact_wireguard_interface(tree: dict | None, *, scope: WireGuardScope) -> dict | None:
    """Validate exact raw ownership read-back and return only key digests."""
    return _verified_tree(tree, scope, _key_digest)


def plan_wireguard_commands(
    intent: WireGuardIntent, *, scope: WireGuardScope, current_interfaces: dict,
    verified_interface: dict | None, live_interfaces: dict,
) -> WireGuardPlan:
    """Plan interface operations for a transaction that also confines VPN traffic."""
    if not isinstance(intent, WireGuardIntent) or not isinstance(scope, WireGuardScope) or intent.scope != scope:
        raise WireGuardIntentError("WireGuard intent belongs to another configured scope")
    if not isinstance(current_interfaces, dict) or not isinstance(live_interfaces, dict):
        raise WireGuardIntentError("WireGuard planning needs complete VyOS interface snapshots")

    path = [*_WIREGUARD_PATH, scope.interface]
    current = redact_wireguard_interface(current_interfaces.get(scope.interface), scope=scope)
    verified = _verified_tree(verified_interface, scope, _existing_digest)
    if current != verified or (scope.interface in current_interfaces and current is None):
        raise WireGuardIntentError("VyOS WireGuard interface differs from verified ownership")
    if current is None and scope.interface in live_interfaces:
        raise WireGuardIntentError("Live VyOS WireGuard interface lacks verified ownership")
    if intent.server is None:
        operations = ({"op": "delete", "path": path},) if current is not None else ()
        return WireGuardPlan(None, operations)

    _prove_live_interfaces(live_interfaces, scope)
    raw_desired = _server_tree(intent.server, scope)
    desired = redact_wireguard_interface(raw_desired, scope=scope)
    _check_port_ownership(current_interfaces, scope, desired["port"])

    commands = _leaf_changes(path, current or {}, desired, raw_desired, ("address", "port", "private-key"))
    peer_before = current["peer"][_PEER_NAME] if current is not None else {}
    peer_after = desired["peer"][_PEER_NAME]
    peer_raw = raw_desired["peer"][_PEER_NAME]
    commands += _leaf_changes(
        path + ["peer", _PEER_NAME], peer_before, peer_after, peer_raw,
        ("allowed-ips", "public-key", "preshared-key"),
    )
    return WireGuardPlan(desired, tuple(commands))


def _unique_fields(pairs):
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise WireGuardIntentError("WireGuard snapshot contains a duplicate JSON field")
        fields[key] = value
    return fields


def _invalid_constant(_value):
    raise WireGuardIntentError("WireGuard snapshot contains a non-JSON constant")


def _ipv4_interface(value):
    try:
        address = IPv4Interface(value) if isinstance(value, str) else None
    except ValueError:
        address = None
    if address is None or str(address) != value:
        raise WireGuardIntentError("WireGuard scope needs a canonical IPv4 address and prefix")
    return address


def _usable_host(address):
    return (
        not (address.ip.is_multicast or address.ip.is_loopback or address.ip.is_unspecified or address.ip.is_reserved)
        and (address.network.prefixlen >= 31 or address.ip not in (
            address.network.network_address, address.network.broadcast_address,
        ))
    )


def _prove_controller_wan(interfaces, scope):
    if not isinstance(interfaces, list):
        raise WireGuardIntentError("WireGuard needs an explicit controller WAN address snapshot")
    selected = []
    for entry in interfaces:
        identification = entry.get("identification") if isinstance(entry, dict) else None
        if not isinstance(identification, dict) or not isinstance(identification.get("id"), str):
            raise WireGuardIntentError("WireGuard WAN snapshot includes an unidentified interface")
        if identification["id"] == scope.wan_id:
            selected.append(entry)
    if (
        len(selected) != 1
        or selected[0]["identification"] != {"id": scope.wan_id, "type": "ethernet"}
        or selected[0].get("addresses") != [{"type": "static", "cidr": scope.wan_cidr, "version": "v4"}]
    ):
        raise WireGuardIntentError("Pinned controller WAN needs the exact static IPv4 address")


def _valid_name(value):
    return isinstance(value, str) and 1 <= len(value) <= 128 and value.strip() and value.isprintable()


def _decode_server(value, scope):
    if (
        not isinstance(value, dict) or value.keys() != _SERVER_FIELDS
        or value["enabled"] is not True or value["id"] != scope.server_id or not _valid_name(value["name"])
        or value["address"] != {"source": "interface", "id": scope.wan_id, "ipVersion": "v4"}
        or type(value["port"]) is not int or value["port"] not in scope.ports
        or value["interfaceIPs"] != [scope.tunnel_cidr]
    ):
        raise WireGuardIntentError("WireGuard server differs from the pinned IPv4 interface scope")
    peers = value["remotePeers"]
    if not isinstance(peers, list) or len(peers) != 1:
        raise WireGuardIntentError("WireGuard server needs exactly one peer")
    peer = peers[0]
    if (
        not isinstance(peer, dict) or not _PEER_FIELDS <= peer.keys() <= _PEER_FIELDS | {"preSharedKey"}
        or not _valid_name(peer["name"]) or peer["allowedIPs"] != [scope.peer_cidr]
    ):
        raise WireGuardIntentError("WireGuard peer needs exactly the pinned IPv4 address and supported fields")
    _key_digest(value["privateKey"])
    _key_digest(peer["publicKey"])
    if "preSharedKey" in peer:
        _key_digest(peer["preSharedKey"])
    return WireGuardServer(value["port"], value["privateKey"], peer["publicKey"], peer.get("preSharedKey"))


def _key_digest(value):
    if not isinstance(value, str) or len(value) != 44:
        raise WireGuardIntentError("WireGuard key needs a canonical nonzero 32-byte Base64 value")
    try:
        decoded = b64decode(value, validate=True)
    except ValueError:
        raise WireGuardIntentError("WireGuard key needs a canonical nonzero 32-byte Base64 value") from None
    if len(decoded) != 32 or not any(decoded) or b64encode(decoded).decode("ascii") != value:
        raise WireGuardIntentError("WireGuard key needs a canonical nonzero 32-byte Base64 value")
    return "sha256:" + sha256(decoded).hexdigest()


def _existing_digest(value):
    if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise WireGuardIntentError("Verified WireGuard ownership needs redacted key digests")
    return value


def _verified_tree(tree, scope, redact):
    if tree is None:
        return None
    if (
        not isinstance(scope, WireGuardScope) or not isinstance(tree, dict) or tree.keys() != _INTERFACE_FIELDS
        or tree["address"] != scope.tunnel_cidr or tree["port"] not in tuple(map(str, scope.ports))
        or not isinstance(tree["peer"], dict) or tree["peer"].keys() != {_PEER_NAME}
    ):
        raise WireGuardIntentError("Unexpected VyOS WireGuard interface ownership subtree")
    peer = tree["peer"][_PEER_NAME]
    if (
        not isinstance(peer, dict) or not _PEER_CONFIG_FIELDS <= peer.keys() <= _PEER_CONFIG_FIELDS | {"preshared-key"}
        or peer["allowed-ips"] != scope.peer_cidr
    ):
        raise WireGuardIntentError("Unexpected VyOS WireGuard peer ownership subtree")
    redacted_peer = {**peer, "public-key": redact(peer["public-key"])}
    if "preshared-key" in peer:
        redacted_peer["preshared-key"] = redact(peer["preshared-key"])
    return {**tree, "private-key": redact(tree["private-key"]), "peer": {_PEER_NAME: redacted_peer}}


def _prove_live_interfaces(interfaces, scope):
    wan = interfaces.get(scope.wan_interface)
    if (
        wan is None or scope.wan_cidr not in {str(address) for address in _live_addresses(wan)}
        or not {"UP", "LOWER_UP"}.issubset(wan[0])
    ):
        raise WireGuardIntentError("Pinned VyOS WAN lacks its active IPv4 address")
    tunnel = IPv4Interface(scope.tunnel_cidr).network
    if any(
        tunnel.overlaps(address.network)
        for name, interface in interfaces.items() if name != scope.interface
        for address in _live_addresses(interface)
    ):
        raise WireGuardIntentError("WireGuard tunnel prefix overlaps another live VyOS interface")


def _live_addresses(interface):
    if (
        not isinstance(interface, (tuple, list)) or len(interface) != 2
        or not isinstance(interface[0], (tuple, list)) or not isinstance(interface[1], str)
    ):
        raise WireGuardIntentError("Unexpected live VyOS interface read-back")
    try:
        return interface_ipv4_addresses(interface[1])
    except ValueError:
        raise WireGuardIntentError("Invalid live VyOS interface address") from None


def _check_port_ownership(interfaces, scope, desired_port):
    for name, tree in interfaces.items():
        if name == scope.interface:
            continue
        if not isinstance(tree, dict):
            raise WireGuardIntentError("Unexpected VyOS WireGuard port read-back")
        if "port" not in tree:
            continue
        port = tree["port"]
        if not isinstance(port, str) or re.fullmatch(r"[1-9][0-9]{0,4}", port) is None or int(port) > 65535:
            raise WireGuardIntentError("Unexpected VyOS WireGuard port read-back")
        if port == desired_port:
            raise WireGuardIntentError("WireGuard port belongs to another VyOS interface")


def _server_tree(server, scope):
    if not isinstance(server, WireGuardServer) or type(server.port) is not int or server.port not in scope.ports:
        raise WireGuardIntentError("WireGuard server port is outside the pinned scope")
    peer = {"allowed-ips": scope.peer_cidr, "public-key": server._peer_public_key}
    if server._preshared_key is not None:
        peer["preshared-key"] = server._preshared_key
    return {
        "address": scope.tunnel_cidr, "port": str(server.port), "private-key": server._private_key,
        "peer": {_PEER_NAME: peer},
    }


def _leaf_changes(path, before, after, raw, fields):
    commands = []
    for name in fields:
        if before.get(name) == after.get(name):
            continue
        if name in after:
            commands.append({"op": "set", "path": path + [name], "value": raw[name]})
        else:
            commands.append({"op": "delete", "path": path + [name]})
    return commands
