"""Qualify the captured WAN-peer TCP forward and its narrow VyOS projection."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from provisioners.vyos_port_forward import (
    PortForwardIntentError, PortForwardScope, decode_port_forward_intent, plan_port_forward_commands,
    port_forward_remainder,
)


WAN = "192.0.2.1/30"
PEER = "192.0.2.2"
LAN = "198.51.100.1/24"
TARGET = "198.51.100.2"
PATH = ["nat", "destination", "rule", "80150"]


@pytest.fixture
def native():
    path = Path(__file__).parent / "fixtures" / "uxg_pro" / "native-port-forward-snapshots.json"
    data = json.loads(path.read_text())
    return {stage: {"udapi": {**deepcopy(data["udapi"]), **rows}} for stage, rows in data["snapshots"].items()}


@pytest.fixture
def scope():
    return PortForwardScope(
        "eth0", "eth3.210", WAN, PEER, "br120", "eth3.120", LAN, TARGET, 80150, ((18446, 8444), (18447, 8443)),
    )


def _decode(snapshot, scope):
    return decode_port_forward_intent(
        json.dumps(snapshot), revision="observed-revision", scope=scope, dns_forwarder=True, wireguard=True,
    )


def _plan(snapshot, scope, *, current=None, verified=None, live=None):
    return plan_port_forward_commands(
        _decode(snapshot, scope), scope=scope,
        live_interface_addresses={"eth3.210": [WAN], "eth3.120": [LAN]} if live is None else live,
        current_rules={} if current is None else current, verified_rules={} if verified is None else verified,
    )


def _chain(snapshot, name):
    return next(chain for chain in snapshot["udapi"]["firewall/filter"] if chain["config"]["name"] == name)


def test_create_only_plans_dnat_and_exposes_exact_forward_filter(native, scope):
    snapshot = native["create"]
    intent = _decode(snapshot, scope)
    plan = _plan(snapshot, scope)

    assert intent.revision == "observed-revision"
    assert (intent.forward.wan_port, intent.forward.target_port) == (18446, 8444)
    assert intent.filter_match == {
        "protocol": "tcp", "inbound-interface": {"name": "eth3.210"},
        "outbound-interface": {"name": "eth3.120"},
        "source": {"address": PEER}, "destination": {"address": TARGET, "port": "8444"},
    }
    expected = {"description": "UniFi managed TCP port forward", "protocol": "tcp",
                "inbound-interface": {"name": "eth3.210"}, "source": {"address": PEER},
                "destination": {"address": "192.0.2.1", "port": "18446"},
                "translation": {"address": TARGET, "port": "8444"}}
    assert plan.desired_rules == {"80150": expected}
    leaves = [(["description"], expected["description"]), (["protocol"], "tcp"),
              (["inbound-interface", "name"], "eth3.210"), (["source", "address"], PEER),
              (["destination", "address"], "192.0.2.1"), (["destination", "port"], "18446"),
              (["translation", "address"], TARGET), (["translation", "port"], "8444")]
    assert plan.commands == tuple({"op": "set", "path": PATH + keys, "value": value} for keys, value in leaves)


def test_rejects_foreign_resource_label_even_when_copied_into_journal(native, scope):
    owned = _plan(native["create"], scope).desired_rules
    owned["80150"]["description"] = "Operator-managed rule"
    with pytest.raises(PortForwardIntentError):
        _plan(native["edit"], scope, current=owned, verified=owned)


def test_validated_compound_companions_normalize_to_native_baseline(native, scope):
    for stage in ("create", "edit"):
        snapshot = native[stage]
        before = deepcopy(snapshot)
        assert port_forward_remainder(snapshot["udapi"], _decode(snapshot, scope)) == native["baseline"]["udapi"]
        assert snapshot == before


def test_unowned_nat_and_policy_survive_normalization(native, scope):
    snapshot = native["create"]
    custom = {"id": 40, "chain": "POSTROUTING", "target": "MASQUERADE", "outInterface": {"id": "eth2"}}
    snapshot["udapi"]["firewall/nat"].append(custom)
    snapshot["udapi"]["custom"] = {"owned_by_operator": True}
    remainder = port_forward_remainder(snapshot["udapi"], _decode(snapshot, scope))
    assert remainder["firewall/nat"] == [*native["baseline"]["udapi"]["firewall/nat"], custom]
    assert remainder["custom"] == {"owned_by_operator": True}


def test_stale_intent_cannot_remove_policy_from_different_snapshot(native, scope):
    with pytest.raises(PortForwardIntentError):
        port_forward_remainder(native["edit"]["udapi"], _decode(native["create"], scope))


def test_edit_and_delete_replace_only_verified_slot(native, scope):
    old = _plan(native["create"], scope).desired_rules
    plan = _plan(native["edit"], scope, current=old, verified=old)
    assert plan.commands[0] == {"op": "delete", "path": PATH}
    assert plan.desired_rules["80150"]["destination"]["port"] == "18447"
    assert plan.desired_rules["80150"]["translation"]["port"] == "8443"
    assert _plan(native["edit"], scope, current=plan.desired_rules, verified=plan.desired_rules).commands == ()
    removal = _plan(native["baseline"], scope, current=plan.desired_rules, verified=plan.desired_rules, live={})
    assert removal.desired_rules == {}
    assert removal.commands == ({"op": "delete", "path": PATH},)


@pytest.mark.parametrize("patch", [
    {"source": {"address": "0.0.0.0/0"}}, {"source": {"address": "192.0.2.3"}}, {"enabled": False},
    {"protocol": "udp"}, {"ipVersion": "both"}, {"destination": {"sets": ["KEY_ADDRv4_eth2"], "port": "18446"}},
    {"translation": {"address": TARGET, "port": "8443"}}, {"translation": {"address": "198.51.100.3", "port": "8444"}},
    {"translation": {"address": TARGET, "port": "8444", "random": True}},
])
def test_reject_unsupported_or_wider_dnat(native, scope, patch):
    native["create"]["udapi"]["firewall/nat"][1].update(patch)
    with pytest.raises(PortForwardIntentError):
        _decode(native["create"], scope)


@pytest.mark.parametrize("name,index,patch", [
    ("WAN_PF_IN", 0, {"source": {"address": "0.0.0.0/0"}}),
    ("WAN_PF_OUT", 0, {"target": "ACCEPT"}),
    ("FORWARD_IN", 0, {"inInterface": {"id": "eth2"}}),
    ("FORWARD_IN", 1, {"id": 30002}),
    ("FORWARD_OUT", 0, {"outInterface": {"id": "eth2"}}),
    ("WAN_LAN", 0, {"destination": {"address": TARGET, "port": "8443"}}),
    ("WAN_LAN", -1, {"target": "ACCEPT"}),
])
def test_reject_unverified_firewall_companions(native, scope, name, index, patch):
    _chain(native["create"], name)["rules"][index].update(patch)
    with pytest.raises(PortForwardIntentError):
        _decode(native["create"], scope)


def test_reject_hairpin_matching_wan_peer_or_unresolved_set(native, scope):
    row = native["create"]["udapi"]["firewall/nat"][2]
    row["source"] = {"address": PEER}
    with pytest.raises(PortForwardIntentError):
        _decode(native["create"], scope)
    row["source"] = {"sets": ["ALL_NETv4_br120"]}
    native["create"]["udapi"]["firewall/sets"].append({
        "identification": {"name": "ALL_NETv4_br120", "type": "address"}, "entries": [PEER],
    })
    with pytest.raises(PortForwardIntentError):
        _decode(native["create"], scope)


def test_missing_controller_nat_section_cannot_delete(native, scope):
    native["baseline"]["udapi"].pop("firewall/nat")
    with pytest.raises(PortForwardIntentError):
        _decode(native["baseline"], scope)


def test_wan_and_lan_must_match_live_static_assignments(native, scope):
    with pytest.raises(PortForwardIntentError):
        _plan(native["create"], scope, live={"eth3.210": ["192.0.2.1/24"], "eth3.120": [LAN]})
    native["create"]["udapi"]["interfaces"][0]["addresses"][0]["cidr"] = "192.0.2.5/30"
    with pytest.raises(PortForwardIntentError):
        _plan(native["create"], scope)


@pytest.mark.parametrize("operator", [
    {"inbound-interface": {"name": "any"}}, {"destination": {"port": "18440-18449"}, "protocol": "tcp"},
    {"inbound-interface": {"name": "eth3.*"}},
])
def test_refuse_ambiguous_operator_destination_rule(native, scope, operator):
    with pytest.raises(PortForwardIntentError):
        _plan(native["create"], scope, current={"111": operator})


def test_disjoint_operator_rule_preserved_and_matching_unowned_slot_rejected(native, scope):
    operator = {"111": {"inbound-interface": {"name": "eth0"}}}
    planned = _plan(native["create"], scope, current=operator)
    assert "111" not in planned.desired_rules
    with pytest.raises(PortForwardIntentError):
        _plan(native["create"], scope, current=planned.desired_rules)


def test_other_public_port_cannot_reuse_managed_filter_after_translation(native, scope):
    operator = {"111": {"protocol": "tcp", "destination": {"port": "18448"},
                        "translation": {"address": TARGET, "port": "8444"}}}

    with pytest.raises(PortForwardIntentError):
        _plan(native["create"], scope, current=operator)


def test_operator_rule_disjoint_on_both_sides_of_nat_is_preserved(native, scope):
    operator = {"111": {"protocol": "tcp", "destination": {"port": "18448"},
                        "translation": {"address": TARGET, "port": "8445"}}}

    assert set(_plan(native["create"], scope, current=operator).desired_rules) == {"80150"}
