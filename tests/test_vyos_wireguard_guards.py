"""Ensure a scoped tunnel cannot expose other local or forwarded services."""

import pytest

from provisioners.vyos_wireguard import WireGuardScope
from provisioners.vyos_wireguard_guards import GUARD_PATHS, WireGuardGuardScope, plan_wireguard_guards


TUNNEL = WireGuardScope("eth0", "eth3.210", "198.18.210.1/30", "wg119", (51820, 51821),
                        "172.29.91.1/24", "172.29.91.2/32")
GUARD = WireGuardGuardScope("198.18.210.2", "192.0.2.120", "eth3.120", 8444, 79000)


def empty():
    return {path: {} for path in GUARD_PATHS}


def test_guard_confines_ingress_and_both_forwarding_directions():
    plan = plan_wireguard_guards(TUNNEL, GUARD, 51820, current=empty(), verified=empty())
    ingress, forward = plan.desired["ipv4/input"], plan.desired["ipv4/forward"]
    assert ingress["79000"] == {
        "action": "accept", "protocol": "udp",
        "inbound-interface": {"name": "eth3.210"}, "source": {"address": "198.18.210.2"},
        "destination": {"address": "198.18.210.1", "port": "51820"},
    }
    assert ingress["79001"] == {"action": "drop", "protocol": "udp", "destination": {"port": "51820"}}
    assert ingress["79002"] == {"action": "drop", "inbound-interface": {"name": "wg119"}}
    assert forward["79000"]["destination"] == {"address": "192.0.2.120", "port": "8444"}
    assert forward["79001"]["state"] == "established"
    assert {
        "op": "set", "path": [*GUARD_PATHS["ipv4/forward"], "79001", "state"], "value": "established",
    } in plan.commands
    assert forward["79001"]["source"] == {"address": "192.0.2.120", "port": "8444"}
    assert forward["79003"] == {"action": "drop", "outbound-interface": {"name": "wg119"}}
    assert all(row["action"] == "drop" for key in ("ipv6/input", "ipv6/forward") for row in plan.desired[key].values())


def test_guard_removes_only_previously_verified_slots():
    loaded = plan_wireguard_guards(TUNNEL, GUARD, 51820, current=empty(), verified=empty()).desired
    running = {path: {**rules, "81000": {"action": "accept"}} for path, rules in loaded.items()}
    plan = plan_wireguard_guards(TUNNEL, GUARD, None, current=running, verified=loaded)
    assert plan.desired == empty()
    assert all(command["op"] == "delete" and int(command["path"][-1]) < 81000 for command in plan.commands)


def test_guard_rejects_an_unowned_rule_that_could_take_precedence():
    current = empty()
    current["ipv4/input"]["100"] = {"action": "accept"}
    with pytest.raises(ValueError, match="preced"):
        plan_wireguard_guards(TUNNEL, GUARD, 51820, current=current, verified=empty())


def test_guard_rejects_incomplete_or_unverified_readback():
    current = empty()
    current["ipv4/input"]["79002"] = {"action": "drop"}
    with pytest.raises(ValueError, match="ownership"):
        plan_wireguard_guards(TUNNEL, GUARD, 51820, current=current, verified=empty())
    with pytest.raises(ValueError, match="complete"):
        plan_wireguard_guards(TUNNEL, GUARD, 51820, current={}, verified=empty())
