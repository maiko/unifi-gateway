"""Constrain the OpenVPN client to one local IPv4 proof flow."""

import pytest

from provisioners.vyos_openvpn_guards import OPENVPN_GUARD_PATHS, OpenVpnGuardScope, plan_openvpn_guards


SCOPE = OpenVpnGuardScope("vtun246", "172.29.94.2/29", "172.29.94.1", 79300,
                         "eth3.210", "198.18.210.1", "198.18.210.2", (19443, 19444))


def empty():
    return {name: {} for name in OPENVPN_GUARD_PATHS}


def test_vtun_has_only_pinned_ipv4_echo_and_denies_all_transit_and_ipv6():
    rules = plan_openvpn_guards(SCOPE, active=True, current=empty(), verified=empty()).desired
    assert rules["ipv4/input"]["79300"] == {
        "action": "accept", "protocol": "icmp", "state": "established", "icmp": {"type-name": "echo-reply"},
        "inbound-interface": {"name": "vtun246"}, "source": {"address": "172.29.94.1"},
        "destination": {"address": "172.29.94.2"},
    }
    assert rules["ipv4/output"]["79300"] == {
        "action": "accept", "protocol": "icmp", "icmp": {"type-name": "echo-request"},
        "outbound-interface": {"name": "vtun246"}, "source": {"address": "172.29.94.2"},
        "destination": {"address": "172.29.94.1"},
    }
    for family in ("ipv4", "ipv6"):
        assert list(rules[f"{family}/forward"].values()) == [
            {"action": "drop", "inbound-interface": {"name": "vtun246"}},
            {"action": "drop", "outbound-interface": {"name": "vtun246"}},
        ]
    assert all(rule["action"] == "drop" for name in ("ipv6/input", "ipv6/output") for rule in rules[name].values())
    assert rules["ipv4/input"]["79301"]["action"] == rules["ipv4/output"]["79301"]["action"] == "drop"
    assert rules["ipv4/input"]["79302"] == {"action": "drop", "destination": {"address": "172.29.94.2"}}
    endpoint = {"address": "198.18.210.2", "port": "19443,19444"}
    assert rules["ipv4/output"]["79302"] == {
        "action": "drop", "protocol": "udp", "outbound-interface": {"name": "!eth3.210"}, "destination": endpoint,
    }
    assert rules["ipv4/output"]["79303"] == {
        "action": "drop", "protocol": "udp", "source": {"address": "!198.18.210.1"}, "destination": endpoint,
    }


def test_owned_tunnel_guard_deletion_preserves_later_operator_policy():
    verified = plan_openvpn_guards(SCOPE, active=True, current=empty(), verified=empty()).desired
    live = {name: dict(rules) for name, rules in verified.items()}
    live["ipv4/input"]["90000"] = {"action": "accept"}
    assert plan_openvpn_guards(SCOPE, active=True, current=live, verified=verified).commands == ()
    removed = plan_openvpn_guards(SCOPE, active=False, current=live, verified=verified)
    assert removed.desired == empty()
    assert len(removed.commands) == 13
    assert all(row["op"] == "delete" and row["path"][-1] != "90000" for row in removed.commands)


def test_unverified_or_prior_operator_rule_stops_activation():
    live = empty()
    live["ipv4/input"]["79300"] = {"action": "accept"}
    with pytest.raises(ValueError, match="ownership"):
        plan_openvpn_guards(SCOPE, active=True, current=live, verified=empty())
    live = empty()
    live["ipv6/output"]["100"] = {"action": "accept"}
    with pytest.raises(ValueError, match="precede"):
        plan_openvpn_guards(SCOPE, active=True, current=live, verified=empty())
