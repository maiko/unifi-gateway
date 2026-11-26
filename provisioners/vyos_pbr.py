"""Prepare one fail-closed table and reconcile its scoped VyOS ingress policy."""

from copy import deepcopy
from ipaddress import IPv4Network
import json

from backends.vyos_failover import VyOSRoutingSSH, _invalid_constant, _read_helper, _unique_fields
from provisioners.uxg_pbr import POLICY_ROUTE_DESTINATIONS, POLICY_ROUTE_SOURCE, PolicyRouteError
from provisioners.uxg_wan_failover import _SUPPORTED_WANS, _exact


POLICY_ROUTE_TABLE = "179"
POLICY_ROUTE_FALLBACK = "198.19.210.240/29"
POLICY_ROUTE_NAME = "UNIFI_PBR"
_RULE = "10"
_INGRESS = "eth3.110"
_, _EGRESS, _, _GATEWAY = _SUPPORTED_WANS["eth0"]
_MARK_MASK = 0x7FFFFFFF
_MARK = _MARK_MASK - int(POLICY_ROUTE_TABLE)
_TABLE = "vyos_mangle"
_PREROUTING = "VYOS_PBR_PREROUTING"
_POSTROUTING = "VYOS_PBR_POSTROUTING"
_GUARD_PATH = ("firewall", "ipv4", "forward", "filter", "rule")
_GUARD_CHAIN = "VYOS_FORWARD_filter"
_GUARD_SLOTS = {destination: str(index) for index, destination in enumerate(sorted(POLICY_ROUTE_DESTINATIONS), 1)}


def _table_configuration(running):
    protocols = running.get("protocols", {})
    static = protocols.get("static", {}) if isinstance(protocols, dict) else None
    tables = static.get("table", {}) if isinstance(static, dict) else None
    if not isinstance(tables, dict):
        raise PolicyRouteError("VyOS static table configuration is invalid")
    return protocols, static, tables


def _fallback_table():
    return {"route": {
        **{destination: {"next-hop": {_GATEWAY: {"interface": _EGRESS}}}
           for destination in POLICY_ROUTE_DESTINATIONS},
        POLICY_ROUTE_FALLBACK: {"blackhole": {"distance": "254"}},
    }}


def _check_no_offload(running):
    firewall = running.get("firewall", {})
    if not isinstance(firewall, dict) or "flowtable" in firewall:
        raise PolicyRouteError("The policy route requires a forwarding path without VyOS flow offload")


def _check_fallback_table(running):
    _, _, tables = _table_configuration(running)
    if tables.get(POLICY_ROUTE_TABLE) != _fallback_table():
        raise PolicyRouteError("Policy routing needs the pinned WAN 210 routes and covering blackhole in table 179")
    _check_no_offload(running)


def prepare_policy_table(running):
    """Plan the table by itself, before any policy rule can select it."""
    if not isinstance(running, dict):
        raise PolicyRouteError("Policy table preparation needs the complete VyOS configuration")
    protocols, static, tables = _table_configuration(running)
    if POLICY_ROUTE_TABLE in tables:
        _check_fallback_table(running)
        return running, ()
    if running.get("policy", {}) != {}:
        raise PolicyRouteError("Policy table preparation requires an unused selector")
    _check_no_offload(running)
    table = _fallback_table()
    prepared = {**running, "protocols": {**protocols, "static": {
        **static, "table": {**tables, POLICY_ROUTE_TABLE: table},
    }}}
    path = ["protocols", "static", "table", POLICY_ROUTE_TABLE, "route"]
    commands = [{"op": "set", "path": [*path, POLICY_ROUTE_FALLBACK, "blackhole", "distance", "254"]}]
    commands.extend({"op": "set", "path": [*path, prefix, "next-hop", _GATEWAY, "interface", _EGRESS]}
                    for prefix in POLICY_ROUTE_DESTINATIONS)
    return prepared, tuple(commands)


def _expected_policy(destination):
    return {"route": {POLICY_ROUTE_NAME: {"interface": _INGRESS, "rule": {_RULE: {
        "source": {"address": POLICY_ROUTE_SOURCE},
        "destination": {"address": destination},
        "set": {"table": POLICY_ROUTE_TABLE},
    }}}}}


def read_policy_route_state(running):
    """Identify the exact owned rule so WAN reconciliation can reject every foreign policy."""
    if not isinstance(running, dict):
        raise PolicyRouteError("Policy routing needs the complete VyOS configuration")
    policy = running.get("policy", {})
    if policy == {}:
        return None
    for destination in POLICY_ROUTE_DESTINATIONS:
        if policy == _expected_policy(destination):
            _check_fallback_table(running)
            return destination
    raise PolicyRouteError("VyOS policy routing differs from the reserved ingress policy")


def plan_policy_route(destination, *, running, current, verified, wan_active):
    if current != verified or current != read_policy_route_state(running):
        raise PolicyRouteError("The VyOS policy route differs from last verified ownership")
    policy_path = ("policy", "route", POLICY_ROUTE_NAME)
    rule_path = (*policy_path, "rule", _RULE)
    if destination is None:
        return ({"op": "delete", "path": list(policy_path)},) if current is not None else ()
    if destination not in POLICY_ROUTE_DESTINATIONS or not wan_active:
        raise PolicyRouteError("The policy route requires a pinned IPv4 destination and two verified WAN uplinks")
    _check_fallback_table(running)
    if current == destination:
        return ()
    change_destination = {"op": "set", "path": [*rule_path, "destination", "address", destination]}
    if current is not None:
        return (change_destination,)
    return (
        {"op": "set", "path": [*policy_path, "interface", _INGRESS]},
        {"op": "set", "path": [*rule_path, "source", "address", POLICY_ROUTE_SOURCE]},
        change_destination,
        {"op": "set", "path": [*rule_path, "set", "table", POLICY_ROUTE_TABLE]},
    )


def read_policy_route_fib(command):
    body = command.read("policy") if isinstance(command, VyOSRoutingSSH) else _read_helper(command, reader="VyOS policy routing reader")
    try:
        return json.loads(body, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except (ValueError, RecursionError) as error:
        raise PolicyRouteError("VyOS policy routing reader returned invalid JSON") from error


def _guard_rules(destinations):
    return {_GUARD_SLOTS[destination]: {
        "action": "drop", "inbound-interface": {"name": _INGRESS}, "outbound-interface": {"name": f"!{_EGRESS}"},
        "source": {"address": POLICY_ROUTE_SOURCE}, "destination": {"address": destination},
    } for destination in sorted(destinations)}


def read_policy_route_guard(running):
    _check_no_offload(running)
    options = running.get("firewall", {}).get("global-options", {})
    if not isinstance(options, dict) or options.get("state-policy"):
        raise PolicyRouteError("VyOS global state policy takes precedence over the policy route guard")
    rules = running
    for part in _GUARD_PATH:
        rules = rules.get(part, {}) if isinstance(rules, dict) else None
    if not isinstance(rules, dict):
        raise PolicyRouteError("VyOS returned an invalid policy route guard chain")
    entries = _guard_rules(POLICY_ROUTE_DESTINATIONS)
    existing = {slot: rules[slot] for slot in entries.keys() & rules.keys()}
    if any(rule != entries[slot] for slot, rule in existing.items()):
        raise PolicyRouteError("VyOS policy route guard slots contain unrelated rules")
    return sorted(destination for destination, slot in _GUARD_SLOTS.items() if slot in existing)


def plan_policy_route_guard(running, current, desired):
    previous, proposed = _guard_rules(current), _guard_rules(desired)
    expected = deepcopy(running)
    rules = expected
    for part in _GUARD_PATH:
        rules = rules.setdefault(part, {})
    commands = []
    for slot in sorted(previous.keys() - proposed.keys()):
        del rules[slot]
        commands.append({"op": "delete", "path": [*_GUARD_PATH, slot]})
    for slot in sorted(proposed.keys() - previous.keys()):
        rules[slot] = proposed[slot]
        path = [*_GUARD_PATH, slot]
        for key, leaf in proposed[slot].items():
            if isinstance(leaf, dict):
                name, value = next(iter(leaf.items()))
                commands.append({"op": "set", "path": [*path, key, name, value]})
            else:
                commands.append({"op": "set", "path": [*path, key, leaf]})
    return expected, tuple(commands)


def policy_route_guard_configuration(running):
    """Ignore empty containers on the guard path when comparing API read-back."""
    normalized = deepcopy(running)
    parents = []
    node = normalized
    for key in _GUARD_PATH:
        if not isinstance(node, dict) or key not in node:
            break
        parents.append((node, key))
        node = node[key]
    for parent, key in reversed(parents):
        if parent[key] == {}:
            del parent[key]
    return normalized


def _verify_kernel_table(rows):
    expected = {str(IPv4Network(prefix).network_address) for prefix in POLICY_ROUTE_DESTINATIONS}
    fallback = {"type": "6", "dst": POLICY_ROUTE_FALLBACK, "protocol": "196", "metric": 20, "flags": []}
    if not isinstance(rows, list) or sum(_exact(row, fallback) for row in rows) != 1:
        raise PolicyRouteError("The permanent VyOS policy blackhole is absent from the kernel table")
    for row in rows:
        if _exact(row, fallback):
            continue
        if (not isinstance(row, dict) or not isinstance(row.get("dst"), str)
                or row["dst"] not in expected or type(row.get("nhid")) is not int or row["nhid"] <= 0
                or row.get("flags") not in ([], ["linkdown"])
                or not _exact(row, {"dst": row["dst"], "nhid": row["nhid"], "gateway": _GATEWAY, "dev": _EGRESS,
                                   "protocol": "196", "metric": 20, "flags": row["flags"]})):
            raise PolicyRouteError("The kernel policy table contains a route outside its WAN 210 scope")
        expected.remove(row["dst"])


def _expected_nft(destination):
    table = {"family": "ip", "table": _TABLE}
    nft = [
        {"table": {"family": "ip", "name": _TABLE}},
        {"chain": {**table, "name": _PREROUTING, "type": "filter", "hook": "prerouting", "prio": -150,
                   "policy": "accept"}},
        {"chain": {**table, "name": _POSTROUTING, "type": "filter", "hook": "postrouting", "prio": -150,
                   "policy": "accept"}},
    ]
    if destination is None:
        return nft
    source = IPv4Network(POLICY_ROUTE_SOURCE)
    chain = f"VYOS_PBR_UD_{POLICY_ROUTE_NAME}"
    return [*nft,
        {"chain": {**table, "name": chain}},
        {"rule": {**table, "chain": _PREROUTING, "expr": [
            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": _INGRESS}},
            {"counter": {}}, {"jump": {"target": chain}},
        ]}},
        {"rule": {**table, "chain": chain, "comment": f"ipv4-route-{POLICY_ROUTE_NAME}-{_RULE}", "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                       "right": str(IPv4Network(destination).network_address)}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                       "right": {"prefix": {"addr": str(source.network_address), "len": source.prefixlen}}}},
            {"counter": {}},
            {"mangle": {"key": {"meta": {"key": "mark"}},
                        "value": {"|": [{"&": [{"meta": {"key": "mark"}}, 0xFFFFFFFF - int(POLICY_ROUTE_TABLE)]}, _MARK]}}},
            {"return": None},
        ]}},
    ]


def _normalize_nft(snapshot):
    if not isinstance(snapshot, dict) or snapshot.keys() != {"nftables"} or not isinstance(snapshot["nftables"], list):
        raise PolicyRouteError("Invalid VyOS policy nftables inventory")
    result = []
    for item in snapshot["nftables"]:
        if not isinstance(item, dict) or len(item) != 1 or not isinstance((row := next(iter(item.values()))), dict):
            raise PolicyRouteError("Invalid VyOS policy nftables entry")
        kind = next(iter(item))
        if kind == "metainfo":
            continue
        row = {name: value for name, value in row.items() if name != "handle"}
        if kind == "rule" and isinstance(row.get("expr"), list):
            row["expr"] = [{"counter": {}} if isinstance(expr, dict) and expr.keys() == {"counter"} else expr
                           for expr in row["expr"]]
        result.append({kind: row})
    return result


def verify_policy_route_guard(snapshot, protected):
    if not isinstance(snapshot, dict) or "forward" not in snapshot:
        raise PolicyRouteError("The VyOS kernel reader did not report the policy route forward guard")
    observed = _normalize_nft(snapshot["forward"])
    chain = {"family": "ip", "table": "vyos_filter", "chain": _GUARD_CHAIN}
    base = {"chain": {"family": "ip", "table": "vyos_filter", "name": _GUARD_CHAIN,
                       "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}}
    source = IPv4Network(POLICY_ROUTE_SOURCE)
    expected = [base]
    for destination in sorted(protected):
        expected.append({"rule": {**chain, "comment": f"ipv4-FWD-filter-{_GUARD_SLOTS[destination]}", "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                       "right": str(IPv4Network(destination).network_address)}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                       "right": {"prefix": {"addr": str(source.network_address), "len": source.prefixlen}}}},
            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": _INGRESS}},
            {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": _EGRESS}},
            {"counter": {}}, {"drop": None},
        ]}})
    if protected and observed[:len(expected)] != expected:
        raise PolicyRouteError("VyOS policy route guard is missing, changed or preceded by another rule")
    comments = [item["rule"].get("comment") for item in observed if "rule" in item]
    for destination, slot in _GUARD_SLOTS.items():
        if comments.count(f"ipv4-FWD-filter-{slot}") != int(destination in protected):
            raise PolicyRouteError("VyOS policy route guard slots differ from the expected kernel rules")


def verify_policy_route_fib(snapshot, destination, *, table_present=True):
    """Verify the live packet mark, isolated IPv4 lookup and permanent fallback."""
    fields = {"ipv4_rules", "ipv6_rules", "table", "nft"}
    if not isinstance(snapshot, dict) or snapshot.keys() not in (fields, fields | {"forward"}):
        raise PolicyRouteError("Incomplete VyOS policy routing observation")
    default = [{"priority": 0, "src": "all", "table": "255"}, {"priority": 32766, "src": "all", "table": "254"}]
    ipv4 = [*default, {"priority": 32767, "src": "all", "table": "253"}]
    if destination is not None:
        ipv4.insert(1, {"priority": int(POLICY_ROUTE_TABLE), "src": "all", "fwmark": hex(_MARK),
                        "fwmask": hex(_MARK_MASK), "table": POLICY_ROUTE_TABLE})
    if not _exact(snapshot["ipv4_rules"], ipv4) or not _exact(snapshot["ipv6_rules"], default):
        raise PolicyRouteError("The VyOS routing rules differ from the isolated IPv4 policy and system defaults")
    if table_present:
        _verify_kernel_table(snapshot["table"])
    elif destination is not None or snapshot["table"] != []:
        raise PolicyRouteError("The reserved VyOS policy table is already in use in the kernel")
    actual_nft = _normalize_nft(snapshot["nft"])
    if (destination is not None or actual_nft) and not _exact(actual_nft, _expected_nft(destination)):
        raise PolicyRouteError("The compiled VyOS policy match or packet mark differs from the expected rule")
