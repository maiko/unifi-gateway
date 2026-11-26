"""Confine an owned OpenVPN client to one router-local IPv4 probe."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface
import re

from provisioners.vyos_firewall_commands import firewall_rule_changes, reserved_rules


OPENVPN_GUARD_PATHS = {
    f"{family}/{chain}": ["firewall", family, chain, "filter", "rule"]
    for family in ("ipv4", "ipv6") for chain in ("input", "forward", "output")
}
OPENVPN_GUARD_SLOTS = 4


@dataclass(frozen=True, slots=True)
class OpenVpnGuardScope:
    interface: str
    local_cidr: str
    peer: str
    rule_base: int
    wan_interface: str
    wan_address: str
    remote_host: str
    remote_ports: tuple[int, ...]

    def __post_init__(self):
        local = IPv4Interface(self.local_cidr)
        peer = IPv4Address(self.peer)
        wan = IPv4Address(self.wan_address)
        remote = IPv4Address(self.remote_host)
        if (
            not isinstance(self.interface, str) or re.fullmatch(r"vtun[0-9]{1,4}", self.interface) is None
            or str(local) != self.local_cidr or str(peer) != self.peer or local.network.prefixlen < 24
            or local.ip == peer or local.ip not in local.network.hosts() or peer not in local.network.hosts()
            or str(wan) != self.wan_address or str(remote) != self.remote_host or wan == remote
            or wan in local.network or remote in local.network
            or any(ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_reserved
                   for ip in (local.ip, peer, wan, remote))
            or not isinstance(self.wan_interface, str) or re.fullmatch(r"eth[0-9]+\.[0-9]+", self.wan_interface) is None
            or len(self.wan_interface) > 15
            or type(self.remote_ports) is not tuple or len(self.remote_ports) != 2
            or any(type(port) is not int or not 1 <= port <= 65535 for port in self.remote_ports)
            or len(set(self.remote_ports)) != 2
            or type(self.rule_base) is not int or not 1 <= self.rule_base <= 1_000_000 - OPENVPN_GUARD_SLOTS
        ):
            raise ValueError("OpenVPN guard requires a pinned tunnel interface, a local peer, and reserved rules")


@dataclass(frozen=True, slots=True)
class OpenVpnGuardPlan:
    desired: dict
    commands: tuple[dict, ...]


def owned_openvpn_guards(current, scope):
    return reserved_rules(current, OPENVPN_GUARD_PATHS, scope.rule_base, OPENVPN_GUARD_SLOTS)


def verify_openvpn_guard_order(current, scope):
    for chain, rules in current.items():
        if any(int(slot) < scope.rule_base for slot in rules):
            raise ValueError(f"An operator rule could precede the OpenVPN guard in {chain}")


def _expected_guards(scope):
    return {chain: {str(scope.rule_base + index): rule for index, rule in enumerate(rules)}
            for chain, rules in _rules(scope).items()}


def verify_openvpn_guards(current, scope):
    if owned_openvpn_guards(current, scope) != _expected_guards(scope):
        raise ValueError("OpenVPN requires the exact pre-installed VyOS firewall guards")


def plan_openvpn_guards(scope, *, active, current, verified):
    owned = owned_openvpn_guards(current, scope)
    if owned != verified:
        raise ValueError("OpenVPN firewall slots differ from verified ownership")
    desired = {chain: {} for chain in OPENVPN_GUARD_PATHS}
    if active:
        verify_openvpn_guard_order(current, scope)
        desired = _expected_guards(scope)
    return OpenVpnGuardPlan(desired, firewall_rule_changes(OPENVPN_GUARD_PATHS, owned, desired))


def _rules(scope):
    local = {"address": str(IPv4Interface(scope.local_cidr).ip)}
    peer = {"address": scope.peer}
    incoming = {"inbound-interface": {"name": scope.interface}}
    outgoing = {"outbound-interface": {"name": scope.interface}}
    drop_in = {"action": "drop", **incoming}
    drop_out = {"action": "drop", **outgoing}
    outer_peer = {"address": scope.remote_host, "port": ",".join(map(str, sorted(scope.remote_ports)))}
    drop_outer = {"action": "drop", "protocol": "udp", "destination": outer_peer}
    return {
        "ipv4/input": [
            {"action": "accept", "protocol": "icmp", "state": "established", "icmp": {"type-name": "echo-reply"},
             **incoming, "source": peer, "destination": local},
            drop_in,
            {"action": "drop", "destination": local},
        ],
        "ipv4/forward": [drop_in, drop_out],
        "ipv4/output": [
            {"action": "accept", "protocol": "icmp", "icmp": {"type-name": "echo-request"},
             **outgoing, "source": local, "destination": peer},
            drop_out,
            {**drop_outer, "outbound-interface": {"name": f"!{scope.wan_interface}"}},
            {**drop_outer, "source": {"address": f"!{scope.wan_address}"}},
        ],
        "ipv6/input": [drop_in],
        "ipv6/forward": [drop_in, drop_out],
        "ipv6/output": [drop_out],
    }
