"""Plan the dual-WAN default route and source NAT for both managed LANs."""

from provisioners.uxg_wan_failover import (
    DEFAULT_ROUTE, WanFailoverPlan, WanFailoverError, _verify_kernel_routes, plan_failover_route,
)
from provisioners.vyos_pbr import read_policy_route_state


_SOURCE_NAT_PATH = ("nat", "source", "rule")
_SOURCE_NETWORKS = ("192.168.110.0/24", "192.168.120.0/24")
_WAN_INTERFACES = ("eth3.210", "eth3.220")


def _nat_rules():
    rules = {}
    for interface in _WAN_INTERFACES:
        for source in _SOURCE_NETWORKS:
            slot = str(80180 + len(rules))
            rules[slot] = {
                "description": "UniFi managed WAN failover",
                "source": {"address": source},
                "outbound-interface": {"name": interface},
                "translation": {"address": "masquerade"},
            }
    return rules


def read_wan_state(running, *, ignore_inactive=False, policy_route=None):
    if not isinstance(running, dict):
        raise WanFailoverError("WAN failover needs the complete VyOS configuration")
    protocols = running.get("protocols", {})
    nat = running.get("nat", {})
    if not isinstance(protocols, dict) or not isinstance(nat, dict) or not isinstance(nat.get("source", {}), dict):
        raise WanFailoverError("Invalid VyOS WAN routing or NAT configuration")
    rules = nat.get("source", {}).get("rule", {})
    failover = protocols.get("failover")
    if not isinstance(rules, dict):
        raise WanFailoverError("Invalid VyOS WAN source NAT rule collection")
    if ignore_inactive and failover is None and not rules.keys() & _nat_rules().keys():
        return None
    unowned_policy = (running.get("policy", {}) != {}
                      and (policy_route is None or read_policy_route_state(running) != policy_route))
    if {"vrf", "load-balancing"}.intersection(running) or unowned_policy:
        raise WanFailoverError("WAN failover requires exclusive ownership of routing and policy configuration")
    if (protocols.keys() - {"static", "failover"}
            or DEFAULT_ROUTE in protocols.get("static", {}).get("route", {})):
        raise WanFailoverError("WAN failover requires an empty or owned default route")
    if any(value for key, value in nat.items() if key != "source") or nat.get("source", {}).keys() - {"rule"}:
        raise WanFailoverError("WAN failover requires a dedicated IPv4 source NAT scope")
    if rules not in ({}, _nat_rules()):
        raise WanFailoverError("WAN failover found unrelated or changed VyOS source NAT rules")
    if failover is None and not rules:
        return None
    return {"failover": failover, "nat": rules}


def _verify_probe_lookup(fib):
    lookup = fib["lookup"]
    forwarding = [row for row in fib["routes"] if not row["flags"]]
    if not forwarding and lookup is None:
        return
    if (not forwarding or not isinstance(lookup, dict) or lookup.get("protocol") != "failover"
            or {key: value for key, value in lookup.items() if key != "protocol"}
            != min(forwarding, key=lambda row: row["metric"])):
        raise WanFailoverError("A foreign or unverified forwarding route handles the WAN probe")


def verify_wan_fib(fib, expected, *, require_route):
    """Verify the actual active default or its withdrawal without inferring link health."""
    if not isinstance(fib, dict) or not {"routes", "lookup"}.issubset(fib):
        raise WanFailoverError("WAN failover needs the protocol 111 route inventory and the probe's FIB lookup")
    _verify_kernel_routes(fib["routes"], (expected or {}).get("failover"), DEFAULT_ROUTE)
    _verify_probe_lookup(fib)
    if expected is not None and require_route and fib["lookup"] is None:
        raise WanFailoverError("No verified VyOS default route has converged")


def _nat_install(rules):
    for slot, rule in rules.items():
        path = [*_SOURCE_NAT_PATH, slot]
        yield {"op": "set", "path": [*path, "description", rule["description"]]}
        for section, leaf in (("source", "address"), ("outbound-interface", "name"), ("translation", "address")):
            yield {"op": "set", "path": [*path, section, leaf, rule[section][leaf]]}


def plan_wan_default(intent, *, running, verified, fib, live_interfaces, policy_route=None):
    """Pair the verified route intent with exact NAT and existing FIB ownership checks."""
    current = read_wan_state(running, policy_route=policy_route)
    if current != verified:
        raise WanFailoverError("VyOS WAN state differs from the last verified revision")
    if not isinstance(fib, dict) or not {"routes", "lookup"}.issubset(fib):
        raise WanFailoverError("WAN failover needs the protocol 111 route inventory and the probe's FIB lookup")
    previous = (current or {}).get("failover")
    route = plan_failover_route(intent, current=previous, verified=previous, kernel_routes=fib["routes"],
                                   live_interfaces=live_interfaces, destination=DEFAULT_ROUTE)
    _verify_probe_lookup(fib)
    if route.expected is None:
        removal = ({"op": "delete", "path": [*_SOURCE_NAT_PATH, slot]} for slot in (current or {}).get("nat", {}))
        return WanFailoverPlan(None, (*route.commands, *removal))

    rules = _nat_rules()
    nat_commands = tuple(_nat_install(rules)) if current is None else ()
    return WanFailoverPlan({"failover": route.expected, "nat": rules}, (*nat_commands, *route.commands))
