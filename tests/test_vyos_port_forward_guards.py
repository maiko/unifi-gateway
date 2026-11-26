"""Ensure native port forwarding is limited to a translated, authorized flow."""

from types import SimpleNamespace

import pytest

from provisioners.vyos_port_forward import PortForwardScope
from provisioners.vyos_port_forward_guards import PORT_FORWARD_GUARD_PATHS, plan_port_forward_guards


SCOPE = PortForwardScope(
    "eth0", "eth3.210", "198.18.210.1/30", "198.18.210.2",
    "br120", "eth3.120", "192.0.2.1/24", "192.0.2.120", 80150, ((18446, 8444), (18447, 8443)),
)


def active():
    return SimpleNamespace(scope=SCOPE, forward=SimpleNamespace(wan_port=18446, target_port=8444),
                           filter_match={"protocol": "tcp", "inbound-interface": {"name": "eth3.210"},
                                         "outbound-interface": {"name": "eth3.120"},
                                         "source": {"address": "198.18.210.2"},
                                         "destination": {"address": "192.0.2.120", "port": "8444"}})


def empty():
    return {chain: {} for chain in PORT_FORWARD_GUARD_PATHS}


def test_guards_allow_only_the_actual_translated_connection():
    plan = plan_port_forward_guards(active(), 79100, current=empty(), verified=empty())
    forward = plan.desired["ipv4/forward"]
    assert forward["79100"] == {"action": "accept", **active().filter_match,
                                "connection-status": {"nat": "destination"}}
    assert forward["79101"] == {"action": "drop", "protocol": "tcp",
                                "inbound-interface": {"name": "eth3.210"},
                                "outbound-interface": {"name": "eth3.120"},
                                "destination": {"address": "192.0.2.120", "port": "8443"}}
    assert forward["79102"]["destination"]["port"] == "8444"
    assert plan.desired["ipv4/input"]["79100"]["destination"] == {"address": "198.18.210.1", "port": "18446"}


def test_port_forward_guards_preserve_unrelated_rules_and_detect_priority_conflicts():
    loaded = plan_port_forward_guards(active(), 79100, current=empty(), verified=empty()).desired
    running = {name: {**data, "80300": {"action": "drop"}} for name, data in loaded.items()}
    deletion = plan_port_forward_guards(SimpleNamespace(scope=SCOPE, forward=None), 79100, current=running, verified=loaded)
    assert deletion.desired == empty()
    assert all(command["op"] == "delete" and command["path"][-1] != "80300" for command in deletion.commands)
    running["ipv4/forward"]["25"] = {"action": "accept"}
    with pytest.raises(ValueError, match="precede"):
        plan_port_forward_guards(active(), 79100, current=running, verified=loaded)
