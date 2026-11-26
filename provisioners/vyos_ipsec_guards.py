"""Keep the approved policy-based IPsec selectors closed to plaintext traffic."""

from dataclasses import dataclass
from ipaddress import IPv4Interface

from provisioners.vyos_firewall_commands import firewall_rule_changes, reserved_rules


IPSEC_GUARD_PATHS = {
    f"ipv4/{chain}": ["firewall", "ipv4", chain, "filter", "rule"]
    for chain in ("input", "forward", "output")
}
IPSEC_GUARD_SLOTS = 4


@dataclass(frozen=True, slots=True)
class IpsecGuardPlan:
    desired: dict
    commands: tuple[dict, ...]


def owned_ipsec_guards(current, rule_base):
    if type(rule_base) is not int or not 1 <= rule_base <= 1_000_000 - IPSEC_GUARD_SLOTS:
        raise ValueError("IPsec firewall range is invalid")
    return reserved_rules(current, IPSEC_GUARD_PATHS, rule_base, IPSEC_GUARD_SLOTS)


def plan_ipsec_guards(scope, rule_base, *, active, current, verified):
    """Plan policy for the same commit-confirm transaction as VPN configuration."""
    owned = owned_ipsec_guards(current, rule_base)
    if owned != verified:
        raise ValueError("IPsec firewall slots differ from verified ownership")
    if type(active) is not bool:
        raise ValueError("IPsec firewall intent requires a verified enabled or disabled state")
    desired = {chain: {} for chain in IPSEC_GUARD_PATHS}
    if active:
        verify_ipsec_guard_order(current, rule_base)
        desired = {
            chain: {str(rule_base + index): rule for index, rule in enumerate(rules)}
            for chain, rules in _templates(scope).items()
        }
    return IpsecGuardPlan(desired, firewall_rule_changes(IPSEC_GUARD_PATHS, owned, desired))


def verify_ipsec_guard_order(current, rule_base):
    for chain, rules in current.items():
        if any(int(slot) < rule_base for slot in rules):
            raise ValueError(f"An operator rule could precede the IPsec guard in {chain}")


def _templates(scope):
    wan_address = str(IPv4Interface(scope.wan_cidr).ip)
    wan = {"name": scope.wan_interface}
    lan = {"name": scope.lan_interface}
    peer = {"address": str(scope.remote_peer)}
    ike = {"protocol": "udp", "destination": {"address": wan_address, "port": "500,4500"}}
    esp = {"protocol": "esp", "destination": {"address": wan_address}}
    inbound = {"source": {"address": str(scope.remote_selector)}, "destination": {"address": str(scope.local_selector)}}
    outbound = {"source": inbound["destination"], "destination": inbound["source"]}
    deny_plaintext = {"action": "drop", "destination": outbound["destination"]}
    return {
        "ipv4/input": [
            {"action": "accept", "inbound-interface": wan, "source": peer, **ike},
            {"action": "accept", "inbound-interface": wan, "source": peer, **esp},
            {"action": "drop", **ike},
            {"action": "drop", **esp},
        ],
        "ipv4/forward": [
            {"action": "accept", "inbound-interface": wan, "outbound-interface": lan,
             "ipsec": {"match-ipsec-in": {}}, **inbound},
            {"action": "accept", "inbound-interface": lan, "outbound-interface": wan,
             "ipsec": {"match-ipsec-out": {}}, **outbound},
            {"action": "drop", **inbound},
            deny_plaintext,
        ],
        "ipv4/output": [deny_plaintext],
    }
