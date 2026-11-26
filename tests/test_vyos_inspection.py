"""Check the exact stock VyOS terminal-permit inspection topology."""

from copy import deepcopy
import json

import pytest

from provisioners.vyos_inspection import StockInspectionPolicy


SCOPE = {
    "queue": 41110,
    "server_port": 18443,
    "rule_id": 20,
    "passthrough_chain": "INS_PASS",
    "topology_sha256": "0" * 64,
    "initiator": {"interface": "eth0.130", "host": "192.0.2.2", "zone": "INS_A", "chain": "INS_AB"},
    "responder": {"interface": "eth0.140", "host": "198.51.100.2", "zone": "INS_B", "chain": "INS_BA"},
}


@pytest.fixture
def permits():
    forward = {
        "action": "accept", "protocol": "tcp",
        "inbound-interface": {"name": "eth0.130"}, "outbound-interface": {"name": "eth0.140"},
        "source": {"address": "192.0.2.2/32"}, "destination": {"address": "198.51.100.2/32", "port": "18443"},
    }
    reverse = {
        "action": "accept", "protocol": "tcp",
        "inbound-interface": {"name": "eth0.140"}, "outbound-interface": {"name": "eth0.130"},
        "source": {"address": "198.51.100.2/32", "port": "18443"}, "destination": {"address": "192.0.2.2/32"},
    }
    base_deny = {**forward, "action": "drop", "source": {"address": "192.0.2.2/32", "port": "46710"}}
    zone_deny = {**forward, "action": "drop", "source": {"address": "192.0.2.2/32", "port": "46711"}}
    return {
        "ipv4": {
            "forward": {"filter": {"rule": {"80300": base_deny}}},
            "name": {
                "INS_AB": {"default-action": "return", "rule": {"10": zone_deny, "20": forward}},
                "INS_BA": {"default-action": "return", "rule": {"20": reverse}},
                "INS_PASS": {"default-action": "return"},
            },
        },
        "ipv6": {"forward": {"filter": {}}, "name": {"INS_PASS": {"default-action": "return"}}},
        "zone": {
            "INS_A": {"member": {"interface": "eth0.130"}, "default-action": "drop",
                      "default-firewall": {"name": "INS_PASS", "ipv6-name": "INS_PASS"},
                      "from": {"INS_B": {"firewall": {"name": "INS_BA"}}}},
            "INS_B": {"member": {"interface": "eth0.140"}, "default-action": "drop",
                      "default-firewall": {"name": "INS_PASS", "ipv6-name": "INS_PASS"},
                      "from": {"INS_A": {"firewall": {"name": "INS_AB"}}}},
        },
    }


@pytest.fixture
def policy(permits):
    commissioning = StockInspectionPolicy.from_json(json.dumps(SCOPE))
    digest = commissioning.fingerprint(permits)
    return StockInspectionPolicy.from_json(json.dumps({**SCOPE, "topology_sha256": digest}))


def test_scope_configuration_pins_the_engine_tuple_and_controller_networks(policy):
    assert policy.networks == ("br130", "br140")
    assert policy.scope == {**SCOPE, "topology_sha256": policy.scope["topology_sha256"]}
    assert policy.engine_scope == {
        "queue": 41110, "server_port": 18443,
        "initiator": {"interface": "eth0.130", "host": "192.0.2.2"},
        "responder": {"interface": "eth0.140", "host": "198.51.100.2"},
    }


def test_exact_stock_command_roundtrip_preserves_both_existing_deny_rules(permits, policy):
    original = deepcopy(permits)
    assert policy.read(permits) is False
    assert policy.commands(False, False) == ()
    activation = []
    restoration = []
    for name in ("INS_AB", "INS_BA"):
        path = ["firewall", "ipv4", "name", name, "rule", "20"]
        activation.extend((
            {"op": "set", "path": [*path, "action"], "value": "queue"},
            {"op": "set", "path": [*path, "queue"], "value": "41110"},
            {"op": "set", "path": [*path, "queue-options"], "value": "bypass"},
        ))
        restoration.extend((
            {"op": "delete", "path": [*path, "queue-options"]},
            {"op": "delete", "path": [*path, "queue"]},
            {"op": "set", "path": [*path, "action"], "value": "accept"},
        ))

    assert policy.commands(False, True) == tuple(activation)
    queued = deepcopy(permits)
    for name in ("INS_AB", "INS_BA"):
        queued["ipv4"]["name"][name]["rule"]["20"].update(
            {"action": "queue", "queue": "41110", "queue-options": "bypass"},
        )
    assert policy.read(queued) is True
    assert policy.fingerprint(queued) == policy.fingerprint(permits)
    assert policy.commands(True, True) == ()
    assert policy.commands(True, False) == tuple(restoration)
    assert permits == original
    assert queued["ipv4"]["forward"] == original["ipv4"]["forward"]
    assert queued["ipv4"]["name"]["INS_AB"]["rule"]["10"] == original["ipv4"]["name"]["INS_AB"]["rule"]["10"]


def test_base_filter_and_normal_managed_chain_can_change_without_reapproval(permits, policy):
    permits["ipv4"]["name"]["UNIFI_LAN_80200"] = {"default-action": "return", "rule": {"5": {"action": "drop"}}}
    permits["ipv4"]["forward"]["filter"]["rule"]["80200"] = {"action": "jump", "jump-target": "UNIFI_LAN_80200"}

    assert policy.read(permits) is False


def test_partial_activation_does_not_establish_ownership(permits, policy):
    permits["ipv4"]["name"]["INS_AB"]["rule"]["20"].update(
        {"action": "queue", "queue": "41110", "queue-options": "bypass"},
    )

    with pytest.raises(ValueError, match="mixed"):
        policy.read(permits)


def test_preceding_owned_deny_remains_pinned(permits, policy):
    permits["ipv4"]["name"]["INS_AB"]["rule"]["10"]["source"]["port"] = "46712"

    with pytest.raises(ValueError, match="approved topology"):
        policy.read(permits)


@pytest.mark.parametrize("update", [
    {"action": "return"}, {"disable": {}}, {"log": {}}, {"source": {"address": "192.0.2.0/24"}},
    {"queue": "41110"}, {"action": "queue", "queue": "41110"},
    {"action": "queue", "queue": 41110, "queue-options": "bypass"},
    {"action": "queue", "queue": "41110", "queue-options": ["bypass"]},
])
def test_terminal_gate_accepts_only_the_exact_permit_or_queue_body(permits, policy, update):
    permits["ipv4"]["name"]["INS_AB"]["rule"]["20"].update(update)

    with pytest.raises(ValueError, match="terminal permit"):
        policy.fingerprint(permits)


@pytest.mark.parametrize(("slot", "action"), [("21", "drop"), ("5", "accept")])
def test_terminal_rule_does_not_skip_another_owned_decision(permits, policy, slot, action):
    permits["ipv4"]["name"]["INS_AB"]["rule"][slot] = {"action": action}

    with pytest.raises(ValueError, match="terminal rule position"):
        policy.fingerprint(permits)


@pytest.mark.parametrize(("path", "value"), [
    (("global-options", "state-policy"), {"established": {"action": "accept"}}),
    (("flowtable", "FAST"), {"offload": "hardware"}),
    (("zone", "INS_A", "member", "interface"), ["eth0.130", "eth0.140"]),
    (("zone", "FOREIGN", "member", "interface"), "eth0.130"),
    (("zone", "FOREIGN", "member", "interface"), "eth0.*"),
    (("zone", "FOREIGN", "member", "vrf"), "BLUE"),
    (("zone", "FOREIGN", "from", "INS_A"), {"firewall": {"name": "OTHER"}}),
    (("zone", "FOREIGN", "default-firewall", "ipv6-name"), "INS_PASS"),
    (("zone", "FOREIGN", "default-firewall", "ipv6-name"), ["INS_PASS"]),
    (("ipv6", "name", "INS_PASS", "default-action"), "drop"),
    (("ipv4", "forward", "filter", "rule", "100"), {"action": "jump", "jump-target": "INS_AB"}),
    (("ipv4", "forward", "filter", "rule", "100"), {"action": "jump", "jump-target": ["INS_AB"]}),
    (("ipv4", "forward", "filter", "rule", "100"), {"action": "offload", "offload-target": "FAST"}),
    (("ipv4", "forward", "filter", "rule", "100"), {"action": "queue", "queue": "41110"}),
    (("ipv4", "forward", "filter", "rule", "100"), {"action": "queue", "queue": "41109-41111"}),
    (("ipv4", "forward", "filter", "rule", "100"), {"action": "queue", "queue": "41110", "disable": {}}),
])
def test_bypass_or_conflicting_ownership_cannot_be_approved(permits, policy, path, value):
    node = permits
    for component in path[:-1]:
        node = node.setdefault(component, {})
    node[path[-1]] = value

    with pytest.raises(ValueError):
        policy.fingerprint(permits)


@pytest.mark.parametrize("update", [
    {"queue": True}, {"server_port": 65536}, {"rule_id": "20"}, {"topology_sha256": "xyz"},
    {"passthrough_chain": "INS_AB"}, {"extra": 1},
    {"initiator": {**SCOPE["initiator"], "host": "192.0.2.2/32"}},
    {"initiator": {**SCOPE["initiator"], "interface": "eth5.140"}},
])
def test_scope_rejects_unpinned_inputs_and_aliases(update):
    with pytest.raises(ValueError):
        StockInspectionPolicy.from_json(json.dumps({**SCOPE, **update}))


def test_scope_rejects_duplicate_json_fields():
    with pytest.raises(ValueError):
        StockInspectionPolicy.from_json(json.dumps(SCOPE).replace('"queue": 41110', '"queue": 1, "queue": 41110'))
