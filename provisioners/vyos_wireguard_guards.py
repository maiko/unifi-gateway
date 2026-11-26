"""Build a confined VyOS firewall policy for an owned IPv4 WireGuard server."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface
import re

from provisioners.vyos_firewall_commands import firewall_rule_changes, reserved_rules

GUARD_PATHS = {
    f"{family}/{chain}": ["firewall", family, chain, "filter", "rule"]
    for family in ("ipv4", "ipv6") for chain in ("input", "forward")
}
_SLOT_COUNT = 4


@dataclass(frozen=True, slots=True)
class WireGuardGuardScope:
    wan_peer: str
    target: str
    target_interface: str
    target_port: int
    rule_base: int

    def __post_init__(self):
        for value in (self.wan_peer, self.target):
            address = IPv4Address(value)
            if str(address) != value or address.is_multicast or address.is_unspecified or address.is_reserved:
                raise ValueError("WireGuard guard endpoints must be pinned unicast IPv4 addresses")
        if not isinstance(self.target_interface, str) or not re.fullmatch(r"eth[0-9]+\.[0-9]+", self.target_interface):
            raise ValueError("WireGuard needs a mapped Ethernet VLAN for forwarding")
        if type(self.target_port) is not int or not 1 <= self.target_port <= 65535:
            raise ValueError("WireGuard needs an explicitly allowed TCP service port")
        if type(self.rule_base) is not int or not 1 <= self.rule_base <= 999999 - _SLOT_COUNT:
            raise ValueError("WireGuard firewall range is invalid")


@dataclass(frozen=True, slots=True)
class WireGuardGuardPlan:
    desired: dict
    commands: tuple[dict, ...]


def owned_guard_rules(current, scope):
    return reserved_rules(current, GUARD_PATHS, scope.rule_base, _SLOT_COUNT)


def plan_wireguard_guards(tunnel, scope, port, *, current, verified):
    """Return rule operations for the same transaction as the WireGuard interface."""
    owned = owned_guard_rules(current, scope)
    if owned != verified:
        raise ValueError("WireGuard firewall slots differ from verified ownership")
    desired = {name: {} for name in GUARD_PATHS}
    if port is not None:
        if type(port) is not int or port not in tunnel.ports:
            raise ValueError("WireGuard listener is outside approved ports")
        wan = IPv4Interface(tunnel.wan_cidr)
        peer = IPv4Address(scope.wan_peer)
        if peer not in wan.network or peer in {wan.ip, wan.network.network_address, wan.network.broadcast_address}:
            raise ValueError("WireGuard ingress peer is outside the pinned WAN")
        if IPv4Address(scope.target) in IPv4Interface(tunnel.tunnel_cidr).network:
            raise ValueError("WireGuard forwarding target must be outside the tunnel network")
        for name, rules in current.items():
            if any(int(slot) < scope.rule_base for slot in rules):
                raise ValueError(f"An operator rule could precede the WireGuard guard in {name}")
        desired = {
            name: {str(scope.rule_base + index): rule for index, rule in enumerate(rules)}
            for name, rules in _guard_templates(tunnel, scope, port).items()
        }

    return WireGuardGuardPlan(desired, firewall_rule_changes(GUARD_PATHS, owned, desired))


def _guard_templates(tunnel, scope, port):
    incoming = {"inbound-interface": {"name": tunnel.interface}}
    outgoing = {"outbound-interface": {"name": tunnel.interface}}
    tcp_port = str(scope.target_port)
    peer_ip = tunnel.peer_cidr.partition("/")[0]
    drop_wireguard_port = {"action": "drop", "protocol": "udp", "destination": {"port": str(port)}}
    drop_incoming = {"action": "drop", **incoming}
    drop_outgoing = {"action": "drop", **outgoing}
    return {
        "ipv4/input": [
            {"action": "accept", "protocol": "udp", "inbound-interface": {"name": tunnel.wan_interface},
             "source": {"address": scope.wan_peer}, "destination": {"address": tunnel.wan_ip, "port": str(port)}},
            drop_wireguard_port, drop_incoming,
        ],
        "ipv4/forward": [
            {"action": "accept", "protocol": "tcp", **incoming, "outbound-interface": {"name": scope.target_interface},
             "source": {"address": peer_ip}, "destination": {"address": scope.target, "port": tcp_port}},
            {"action": "accept", "protocol": "tcp", **outgoing, "inbound-interface": {"name": scope.target_interface},
             "source": {"address": scope.target, "port": tcp_port}, "destination": {"address": peer_ip},
             "state": "established"},
            drop_incoming, drop_outgoing,
        ],
        "ipv6/input": [drop_wireguard_port, drop_incoming],
        "ipv6/forward": [drop_incoming, drop_outgoing],
    }
