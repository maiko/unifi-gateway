"""Verify the native IPv4 Kill Switch route and its VyOS ingress policy."""

from copy import deepcopy
import json
from pathlib import Path

import pytest


FIXTURES = json.loads((Path(__file__).parent / "fixtures/uxg_pro/native-policy-route-snapshots.json").read_text())


@pytest.mark.parametrize(("phase", "destination"), [
    ("strict", "198.19.210.243/32"), ("edit", "198.19.210.244/32"), ("withdrawn", None),
])
def test_native_policy_route_normalizes_only_its_observed_companions(phase, destination):
    from provisioners.uxg_pbr import normalize_policy_route

    document = deepcopy(FIXTURES[phase])
    udapi = document["udapi"]
    unrelated = {"identification": {"name": "native-lan", "type": "address"}, "entries": ["192.168.120.0/24"]}
    udapi["firewall/sets"].insert(0, unrelated)
    udapi["versionDetail"]["firewall/sets"] = 1

    normalized, route = normalize_policy_route(json.dumps(document), revision="native-revision")

    assert route.destination == destination
    assert route.revision == "native-revision"
    assert json.loads(normalized) == {"udapi": {
        "version": 48, "versionFormat": "v2", "versionDetail": {"firewall/sets": 1}, "firewall/sets": [unrelated],
    }}


@pytest.mark.parametrize("change", [
    "no kill switch", "missing action", "missing version", "additional IPv6 source", "broken set reference",
    "negated ingress", "different WAN", "port match", "second policy", "different router destination",
])
def test_native_policy_route_rejects_incomplete_or_outside_scope_payloads(change):
    from provisioners.uxg_pbr import PolicyRouteError, normalize_policy_route

    document = deepcopy(FIXTURES["without-kill-switch" if change == "no kill switch" else "strict"])
    udapi = document["udapi"]
    action = udapi["firewall/pbr"]["rules"][0]
    if change == "missing action":
        udapi["firewall/pbr"]["rules"].clear()
    if change == "missing version":
        del udapi["versionDetail"]["firewall/pbr"]
    if change == "additional IPv6 source":
        udapi["firewall/sets"][1]["entries"] = ["fd52:1234::/64"]
    if change == "broken set reference":
        action["source"]["sets"] = ["unrelated"]
    if change == "negated ingress":
        action["negateInInterface"] = True
    if change == "different WAN":
        action["routingMode"]["pbrTable"] = 202
    if change == "port match":
        action["destination"]["ports"] = [443]
    if change == "second policy":
        udapi["firewall/pbr"]["rules"].append(action)
    if change == "different router destination":
        udapi["firewall/sets"][2]["entries"] = ["192.168.77.1"]
    with pytest.raises(PolicyRouteError):
        normalize_policy_route(json.dumps(document), revision="native-revision")


def seed_table():
    return {"route": {
        "198.19.210.243/32": {"next-hop": {"198.18.210.2": {"interface": "eth3.210"}}},
        "198.19.210.244/32": {"next-hop": {"198.18.210.2": {"interface": "eth3.210"}}},
        "198.19.210.240/29": {"blackhole": {"distance": "254"}},
    }}


def running_policy(destination=None, *, name="UNIFI_PBR"):
    config = {"protocols": {"static": {"table": {"179": seed_table(), "180": {"description": "Operator"}}}}}
    if destination is not None:
        config["policy"] = {"route": {name: {"interface": "eth3.110", "rule": {"10": {
            "source": {"address": "192.168.110.0/24"}, "destination": {"address": destination}, "set": {"table": "179"},
        }}}}}
    return config


def test_policy_route_only_edits_its_ingress_policy_and_uses_existing_fallback_table():
    from provisioners.vyos_pbr import plan_policy_route, read_policy_route_state

    first, second = "198.19.210.243/32", "198.19.210.244/32"
    initial = running_policy()
    assert read_policy_route_state(initial) is None
    create = plan_policy_route(first, running=initial, current=None, verified=None, wan_active=True)
    assert len(create) == 4
    assert {tuple(command["path"][:3]) for command in create} == {("policy", "route", "UNIFI_PBR")}
    assert {"op": "set", "path": ["policy", "route", "UNIFI_PBR", "rule", "10", "set", "table", "179"]} in create

    active = running_policy(first)
    assert read_policy_route_state(active) == first
    assert not plan_policy_route(first, running=active, current=first, verified=first, wan_active=True)
    assert plan_policy_route(second, running=active, current=first, verified=first, wan_active=True) == (
        {"op": "set", "path": ["policy", "route", "UNIFI_PBR", "rule", "10", "destination", "address", second]},
    )
    assert plan_policy_route(None, running=active, current=first, verified=first, wan_active=False) == (
        {"op": "delete", "path": ["policy", "route", "UNIFI_PBR"]},
    )


@pytest.mark.parametrize("drift", ["no fallback", "invalid tables", "foreign policy", "journal", "missing WAN", "offload"])
def test_lab_policy_route_refuses_unowned_state(drift):
    from provisioners.uxg_pbr import PolicyRouteError
    from provisioners.vyos_pbr import plan_policy_route, read_policy_route_state

    first = "198.19.210.243/32"
    running = running_policy(first if drift == "journal" else None)
    if drift == "no fallback":
        del running["protocols"]["static"]["table"]["179"]["route"]["198.19.210.240/29"]
    if drift == "invalid tables":
        running["protocols"]["static"]["table"] = []
    if drift == "foreign policy":
        running["policy"] = {"route": {"operator": {}}}
    if drift == "offload":
        running["firewall"] = {"flowtable": {"operator": {}}}
    with pytest.raises(PolicyRouteError):
        plan_policy_route(first, running=running, current=read_policy_route_state(running),
                              verified=None, wan_active=drift != "missing WAN")


def policy_kernel(active=True, *, wan=True, name="UNIFI_PBR"):
    source, mark, mask = "192.168.110.0", 2147483468, 4294967116
    table = {"family": "ip", "table": "vyos_mangle"}
    prerouting, postrouting = "VYOS_PBR_PREROUTING", "VYOS_PBR_POSTROUTING"
    owned = f"VYOS_PBR_UD_{name}"
    nft = [
        {"metainfo": {"json_schema_version": 1}},
        {"table": {"family": "ip", "name": "vyos_mangle", "handle": 113}},
        {"chain": {**table, "name": prerouting, "handle": 1, "type": "filter", "hook": "prerouting",
                   "prio": -150, "policy": "accept"}},
        {"chain": {**table, "name": postrouting, "handle": 2, "type": "filter", "hook": "postrouting",
                   "prio": -150, "policy": "accept"}},
    ]
    ipv6 = [{"priority": 0, "src": "all", "table": "255"}, {"priority": 32766, "src": "all", "table": "254"}]
    ipv4 = [*ipv6, {"priority": 32767, "src": "all", "table": "253"}]
    if active:
        ipv4.insert(1, {"priority": 179, "src": "all", "fwmark": "0x7fffff4c", "fwmask": "0x7fffffff",
                        "table": "179"})
        count = {"counter": {"packets": 13, "bytes": 980}}
        nft.extend([
            {"chain": {**table, "name": owned, "handle": 3}},
            {"rule": {**table, "chain": prerouting, "handle": 4, "expr": [
                {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eth3.110"}},
                count, {"jump": {"target": owned}},
            ]}},
            {"rule": {**table, "chain": owned, "handle": 5, "comment": f"ipv4-route-{name}-10", "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                           "right": "198.19.210.243"}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                           "right": {"prefix": {"addr": source, "len": 24}}}},
                count, {"mangle": {"key": {"meta": {"key": "mark"}},
                                  "value": {"|": [{"&": [{"meta": {"key": "mark"}}, mask]}, mark]}}},
                {"return": None},
            ]}},
        ])
    routes = [{"type": "6", "dst": "198.19.210.240/29", "protocol": "196", "metric": 20, "flags": []}]
    if wan:
        routes.extend({"dst": dest, "nhid": 35, "gateway": "198.18.210.2", "dev": "eth3.210",
                       "protocol": "196", "metric": 20, "flags": []}
                      for dest in ("198.19.210.243", "198.19.210.244"))
    return {"ipv4_rules": ipv4, "ipv6_rules": ipv6, "table": routes, "nft": {"nftables": nft}}


def test_kernel_verification_requires_exact_match_and_permanent_covering_blackhole():
    from provisioners.vyos_pbr import verify_policy_route_fib

    verify_policy_route_fib(policy_kernel(), "198.19.210.243/32")
    verify_policy_route_fib(policy_kernel(wan=False), "198.19.210.243/32")
    verify_policy_route_fib(policy_kernel(active=False), None)


def test_foreign_selector_name_is_rejected_in_config_and_kernel():
    from provisioners.uxg_pbr import PolicyRouteError
    from provisioners.vyos_pbr import read_policy_route_state, verify_policy_route_fib

    destination = "198.19.210.243/32"
    with pytest.raises(PolicyRouteError):
        read_policy_route_state(running_policy(destination, name="OPERATOR"))
    with pytest.raises(PolicyRouteError):
        verify_policy_route_fib(policy_kernel(name="OPERATOR"), destination)


@pytest.mark.parametrize("drift", ["no blackhole", "earlier rule", "IPv6 rule", "broadened match", "foreign egress"])
def test_kernel_verification_rejects_routing_drift(drift):
    from provisioners.uxg_pbr import PolicyRouteError
    from provisioners.vyos_pbr import verify_policy_route_fib

    snapshot = policy_kernel()
    if drift == "no blackhole":
        del snapshot["table"][0]
    if drift == "earlier rule":
        snapshot["ipv4_rules"].insert(1, {"priority": 100, "src": "all", "table": "254"})
    if drift == "IPv6 rule":
        snapshot["ipv6_rules"].insert(1, snapshot["ipv4_rules"][1])
    if drift == "broadened match":
        del snapshot["nft"]["nftables"][-1]["rule"]["expr"][0]
    if drift == "foreign egress":
        snapshot["table"][1]["dev"] = "eth3.220"
    with pytest.raises(PolicyRouteError):
        verify_policy_route_fib(snapshot, "198.19.210.243/32")


def test_policy_route_guard_checks_the_compiled_drop_and_preceding_rules():
    from provisioners.uxg_pbr import PolicyRouteError
    from provisioners.vyos_pbr import verify_policy_route_guard

    # Sanitized stock nft -j list chain output after a real denied probe.
    chain = {"family": "ip", "table": "vyos_filter", "name": "VYOS_FORWARD_filter",
             "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}
    rule = {"family": "ip", "table": "vyos_filter", "chain": "VYOS_FORWARD_filter", "comment": "ipv4-FWD-filter-1",
            "expr": [
                {"match": {"left": {"payload": {"field": "daddr", "protocol": "ip"}}, "op": "==", "right": "198.19.210.243"}},
                {"match": {"left": {"payload": {"field": "saddr", "protocol": "ip"}}, "op": "==",
                           "right": {"prefix": {"addr": "192.168.110.0", "len": 24}}}},
                {"match": {"left": {"meta": {"key": "iifname"}}, "op": "==", "right": "eth3.110"}},
                {"match": {"left": {"meta": {"key": "oifname"}}, "op": "!=", "right": "eth3.210"}},
                {"counter": {"bytes": 360, "packets": 6}}, {"drop": None},
            ]}
    rows = [{"chain": chain}, {"rule": rule}]
    snapshot = {"forward": {"nftables": rows}}
    verify_policy_route_guard(snapshot, ["198.19.210.243/32"])
    rows.insert(1, {"rule": {"expr": [{"jump": {"target": "VYOS_STATE_POLICY_FORWARD"}}]}})
    with pytest.raises(PolicyRouteError, match="preceded by another rule"):
        verify_policy_route_guard(snapshot, ["198.19.210.243/32"])
    rows.pop(1)
    with pytest.raises(PolicyRouteError, match="slots differ"):
        verify_policy_route_guard(snapshot, [])
