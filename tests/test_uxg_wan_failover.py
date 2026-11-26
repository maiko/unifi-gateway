from copy import deepcopy
import json
from pathlib import Path

import pytest

from provisioners.uxg_wan_failover import (
    WanFailoverError,
    decode_wan_failover,
    plan_failover_route,
)
from provisioners.uxg_wan_failover_policy import normalize_wan_failover_policy
from provisioners.vyos_wan_failover import plan_wan_default


FIXTURES = json.loads((Path(__file__).parent / "fixtures/uxg_pro/native-wan-failover-snapshots.json").read_text())
COMPANIONS = json.loads((Path(__file__).parent / "fixtures/uxg_pro/native-wan-failover-companions.json").read_text())
LIVE = {
    "eth3.210": (["UP", "LOWER_UP"], "\n    inet 198.18.210.1/30\n"),
    "eth3.220": (["UP", "LOWER_UP"], "\n    inet 198.18.220.1/30\n"),
}
PROTOCOL_ROUTES = [
    {"dst": "198.19.210.242", "gateway": "198.18.210.2", "dev": "eth3.210", "metric": 10, "flags": []},
    {"dst": "198.19.210.242", "gateway": "198.18.220.2", "dev": "eth3.220", "metric": 20, "flags": []},
]


def decode(phase_or_document):
    document = FIXTURES[phase_or_document] if isinstance(phase_or_document, str) else phase_or_document
    return decode_wan_failover(json.dumps(document), revision="native-revision")


def test_native_sla_and_priority_follow_observed_controller_snapshot():
    assert decode("baseline").primary is None
    assert decode("restored").primary is None
    assert decode("monitors").primary == "eth0"
    intent = decode("reversed")
    assert intent.primary == "eth2"
    assert intent.revision == "native-revision"
    with pytest.raises(WanFailoverError, match="SLA"):
        decode("two-wans")


@pytest.mark.parametrize("field,value", [("metric", 1), ("weight", 17), ("monitorHealthThreshold", 2)])
def test_native_priority_or_sla_drift_is_rejected(field, value):
    changed = deepcopy(FIXTURES["monitors"])
    rows = changed["udapi"]["services"]["wanFailover"]["wanInterfaces"]
    rows[0][field] = value
    with pytest.raises(WanFailoverError):
        decode(changed)


def test_native_unsupported_monitor_targets_are_rejected():
    changed = deepcopy(FIXTURES["monitors"])
    rows = changed["udapi"]["services"]["wanFailover"]["wanInterfaces"]
    rows[0]["monitors"][0]["target"] = "8.8.8.8"
    with pytest.raises(WanFailoverError, match="SLA"):
        decode(changed)


def test_failover_route_plans_health_monitor_edit_and_removal():
    install = plan_failover_route(decode("monitors"), current=None, verified=None, kernel_routes=[], live_interfaces=LIVE)
    first = install.expected["route"]["198.19.210.242/32"]["next-hop"]
    assert first["198.18.210.2"] == {"interface": "eth3.210", "metric": "10", "check": {
        "type": "icmp", "timeout": "1", "target": {"198.18.210.2": {"interface": "eth3.210"}},
    }}
    assert first["198.18.220.2"]["metric"] == "20"
    assert len(install.commands) == 10

    steady = plan_failover_route(decode("monitors"), current=install.expected, verified=install.expected,
                                    kernel_routes=PROTOCOL_ROUTES[1:], live_interfaces=LIVE)
    assert steady.commands == ()
    edited = plan_failover_route(decode("reversed"), current=install.expected, verified=install.expected,
                                     kernel_routes=PROTOCOL_ROUTES, live_interfaces=LIVE)
    assert edited.expected["route"]["198.19.210.242/32"]["next-hop"]["198.18.220.2"]["metric"] == "10"
    assert {tuple(row["path"][-2:]) for row in edited.commands} == {("metric", "10"), ("metric", "20")}

    removal = plan_failover_route(decode("restored"), current=install.expected, verified=install.expected,
                                      kernel_routes=PROTOCOL_ROUTES, live_interfaces={})
    assert removal.expected is None
    assert removal.commands == ({"op": "delete", "path": ["protocols", "failover"]},)


@pytest.mark.parametrize("drift", ["extra-route", "ownership", "interface"])
def test_failover_route_refuses_unowned_protocol_or_interface_state(drift):
    intent = decode("monitors")
    clean = plan_failover_route(intent, current=None, verified=None, kernel_routes=[], live_interfaces=LIVE)
    current, routes, interfaces = clean.expected, PROTOCOL_ROUTES, LIVE
    if drift == "extra-route":
        routes = [*routes, {**routes[0], "table": 25}]
    elif drift == "ownership":
        current = None
    else:
        interfaces = {"eth3.210": LIVE["eth3.210"]}
    with pytest.raises(WanFailoverError):
        plan_failover_route(intent, current=current, verified=clean.expected,
                                 kernel_routes=routes, live_interfaces=interfaces)


@pytest.mark.parametrize("capture", ["observed", "wan1-first"])
def test_native_generated_dual_wan_changes_normalize_to_the_original_envelope(capture):
    original = deepcopy(COMPANIONS[capture])
    original["udapi"]["system"]["independent-setting"] = {"leave": True}
    normalized, intent = normalize_wan_failover_policy(json.dumps(original), revision="native-revision")
    expected = deepcopy(COMPANIONS["expected"])
    expected["udapi"]["system"]["independent-setting"] = {"leave": True}
    assert json.loads(normalized) == expected
    assert intent.primary == "eth0"


@pytest.mark.parametrize("drift", ["nat match", "wrong bridge", "foreign default", "firewall allowance"])
def test_native_companion_policy_refuses_semantic_changes(drift):
    data = deepcopy(COMPANIONS["observed"])
    udapi = data["udapi"]
    if drift == "nat match":
        udapi["firewall/nat"][0]["source"]["sets"] = []
    elif drift == "wrong bridge":
        udapi["interfaces"][-1]["bridge"]["interfaces"][1]["id"] = "eth2.110"
    elif drift == "foreign default":
        udapi["routes/static"][1]["gateway"] = "203.0.113.100"
    else:
        udapi["firewall/filter"][0]["rules"][0]["target"] = "ACCEPT"
    with pytest.raises(WanFailoverError):
        normalize_wan_failover_policy(json.dumps(data), revision="native-revision")


def test_default_route_couples_failover_to_both_wan_masquerades():
    snapshot = {"routes": [], "lookup": None}
    plan = plan_wan_default(decode("monitors"), running={}, verified=None, fib=snapshot, live_interfaces=LIVE)
    assert set(plan.expected["failover"]["route"]) == {"0.0.0.0/0"}
    assert len(plan.expected["nat"]) == 4
    assert {rule["source"]["address"] for rule in plan.expected["nat"].values()} == {
        "192.168.110.0/24", "192.168.120.0/24",
    }
    assert {rule["outbound-interface"]["name"] for rule in plan.expected["nat"].values()} == {"eth3.210", "eth3.220"}
    assert all(rule["translation"] == {"address": "masquerade"} for rule in plan.expected["nat"].values())
    assert {tuple(command["path"][:2]) for command in plan.commands} == {("nat", "source"), ("protocols", "failover")}

    for rule in plan.expected["nat"].values():
        assert rule["description"] == "UniFi managed WAN failover"

    actual = {"protocols": {"failover": plan.expected["failover"]},
              "nat": {"source": {"rule": plan.expected["nat"]}}}
    active = {"routes": [{**r, "dst": "default"} for r in PROTOCOL_ROUTES],
              "lookup": {**PROTOCOL_ROUTES[0], "dst": "default", "protocol": "failover"}}
    edit = plan_wan_default(decode("reversed"), running=actual, verified=plan.expected, fib=active,
                               live_interfaces=LIVE)
    assert {tuple(op["path"][-2:]) for op in edit.commands} == {("metric", "10"), ("metric", "20")}
    remove = plan_wan_default(decode("restored"), running=actual, verified=plan.expected, fib=active,
                                 live_interfaces={})
    assert remove.expected is None
    assert len(remove.commands) == 5 and {op["op"] for op in remove.commands} == {"delete"}


@pytest.mark.parametrize("running,fib", [
    ({"vrf": {"name": {"foreign": {}}}}, {"routes": [], "lookup": None}),
    ({"protocols": {"static": {"route": {"0.0.0.0/0": {}}}}}, {"routes": [], "lookup": None}),
    ({"nat": {"source": {"rule": {"1": {"translation": {"address": "masquerade"}}}}}},
     {"routes": [], "lookup": None}),
    ({}, {"routes": [], "lookup": {"dst": "default", "protocol": "static"}}),
])
def test_default_route_refuses_foreign_routing_nat_or_probe_ownership(running, fib):
    with pytest.raises(WanFailoverError):
        plan_wan_default(decode("monitors"), running=running, verified=None, fib=fib, live_interfaces=LIVE)
