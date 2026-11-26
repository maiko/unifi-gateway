"""Verify the rules that keep an owned policy-based IPsec tunnel confined."""

from types import SimpleNamespace

import pytest

from provisioners.vyos_ipsec_guards import IPSEC_GUARD_PATHS, plan_ipsec_guards


TUNNEL = SimpleNamespace(wan_cidr="198.18.210.1/30", wan_interface="eth3.210", remote_peer="198.18.210.2",
                         lan_interface="eth3.120", local_selector="192.168.120.2/32", remote_selector="198.19.210.240/32")
BASE = 79200


def empty():
    return {chain: {} for chain in IPSEC_GUARD_PATHS}


def plan(active, *, current=None, verified=None):
    return plan_ipsec_guards(TUNNEL, BASE, active=active, current=empty() if current is None else current,
                             verified=empty() if verified is None else verified)


def test_requires_ipsec_and_both_interface_and_host_selectors_before_accepting():
    planned = plan(True)
    inbound, outbound, no_unprotected_in, no_unprotected_out = planned.desired["ipv4/forward"].values()
    assert inbound == {
        "action": "accept", "ipsec": {"match-ipsec-in": {}},
        "inbound-interface": {"name": "eth3.210"}, "outbound-interface": {"name": "eth3.120"},
        "source": {"address": "198.19.210.240/32"}, "destination": {"address": "192.168.120.2/32"},
    }
    assert outbound["ipsec"] == {"match-ipsec-out": {}}
    assert outbound["source"] == inbound["destination"] and outbound["destination"] == inbound["source"]
    assert outbound["inbound-interface"] == inbound["outbound-interface"]
    assert outbound["outbound-interface"] == inbound["inbound-interface"]
    assert no_unprotected_in["action"] == "drop" and no_unprotected_out["action"] == "drop"
    assert no_unprotected_in["source"] == inbound["source"] and no_unprotected_in["destination"] == inbound["destination"]
    assert no_unprotected_out == {"action": "drop", "destination": outbound["destination"]}
    assert list(planned.desired["ipv4/output"].values()) == [no_unprotected_out]
    assert {"op": "set", "path": [*IPSEC_GUARD_PATHS["ipv4/forward"], str(BASE), "ipsec", "match-ipsec-in"]} in planned.commands


def test_closes_ike_on_other_interfaces_and_leaves_other_local_addresses_alone():
    allow_ike, allow_esp, deny_ike, deny_esp = plan(True).desired["ipv4/input"].values()
    for allow, deny in ((allow_ike, deny_ike), (allow_esp, deny_esp)):
        assert allow["source"] == {"address": "198.18.210.2"}
        assert allow["inbound-interface"] == {"name": "eth3.210"}
        assert allow["action"] == "accept" and deny["action"] == "drop"
        assert allow["destination"] == deny["destination"]
        assert deny["destination"]["address"] == "198.18.210.1"
        assert deny.keys() == {"action", "protocol", "destination"}
    assert allow_ike["protocol"] == "udp" and allow_ike["destination"]["port"] == "500,4500"
    assert allow_esp["protocol"] == "esp"


def test_idempotence_and_only_owned_deletion():
    active = plan(True).desired
    runtime = {name: rules.copy() for name, rules in active.items()}
    runtime["ipv4/input"]["90000"] = {"action": "accept", "protocol": "icmp"}
    assert plan(True, current=runtime, verified=active).commands == ()
    removed = plan(False, current=runtime, verified=active)
    assert removed.desired == empty()
    assert len(removed.commands) == 9
    assert all(command["op"] == "delete" and command["path"][-1] != "90000" for command in removed.commands)


def test_rejects_conflicting_reserved_or_preceding_rules_without_planning_changes():
    runtime = empty()
    runtime["ipv4/input"][str(BASE)] = {"action": "accept"}
    with pytest.raises(ValueError, match="ownership"):
        plan(True, current=runtime)
    runtime = empty()
    runtime["ipv4/forward"]["100"] = {"action": "accept"}
    with pytest.raises(ValueError, match="precede"):
        plan(True, current=runtime)
