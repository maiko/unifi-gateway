"""Build permit and confinement rules for a scoped IPv4 DNAT policy."""

from dataclasses import dataclass

from provisioners.vyos_firewall_commands import firewall_rule_changes, reserved_rules


PORT_FORWARD_GUARD_PATHS = {
    f"ipv4/{chain}": ["firewall", "ipv4", chain, "filter", "rule"] for chain in ("input", "forward")
}


@dataclass(frozen=True, slots=True)
class PortForwardGuardPlan:
    desired: dict
    commands: tuple[dict, ...]


def port_forward_guard_slots(scope, rule_base):
    slots = max(len({wan for wan, _ in scope.ports}), 1 + len({target for _, target in scope.ports}))
    if type(rule_base) is not int or not 1 <= rule_base <= 1_000_000 - slots:
        raise ValueError("Port forwarding firewall range is invalid")
    return slots


def owned_port_forward_guards(current, scope, rule_base):
    slots = port_forward_guard_slots(scope, rule_base)
    return reserved_rules(current, PORT_FORWARD_GUARD_PATHS, rule_base, slots)


def plan_port_forward_guards(intent, rule_base, *, current, verified):
    """Confine the permitted translated service to the pinned peer and interfaces."""
    scope = intent.scope
    owned = owned_port_forward_guards(current, scope, rule_base)
    if owned != verified:
        raise ValueError("Port forwarding firewall slots differ from verified ownership")
    desired = {chain: {} for chain in PORT_FORWARD_GUARD_PATHS}
    if intent.forward is not None:
        for name, rules in current.items():
            if any(int(slot) < rule_base for slot in rules):
                raise ValueError(f"An operator rule could precede the port forward guard in {name}")
        guard = [
            {"action": "accept", **intent.filter_match, "connection-status": {"nat": "destination"}},
        ]
        inbound = {"inbound-interface": {"name": scope.wan_interface}}
        blocked = {"action": "drop", "protocol": "tcp", **inbound}
        for port in sorted({target for _, target in scope.ports}):
            guard.append({**blocked, "outbound-interface": {"name": scope.lan_interface},
                          "destination": {"address": scope.target, "port": str(port)}})
        desired["ipv4/forward"] = {str(rule_base + index): rule for index, rule in enumerate(guard)}
        desired["ipv4/input"] = {
            str(rule_base + index): {**blocked, "destination": {"address": scope.wan_address, "port": str(port)}}
            for index, port in enumerate(sorted({wan for wan, _ in scope.ports}))
        }
    return PortForwardGuardPlan(desired, firewall_rule_changes(PORT_FORWARD_GUARD_PATHS, owned, desired))
