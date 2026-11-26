"""Qualify the native source NAT projection and its ownership boundaries."""

from copy import deepcopy
from ipaddress import IPv4Address, IPv4Network
import json
from pathlib import Path

import pytest

from provisioners.vyos_nat import NatIntentError, NatScope, decode_nat_intent, outside_nat_rules, plan_nat_commands


SOURCE = "192.0.2.0/24"
DESTINATION = "198.51.100.2"
TRANSLATION = "198.51.100.1"
DESCRIPTION = "UniFi managed source NAT"
RULE_PATH = ["nat", "source", "rule", "80100"]


@pytest.fixture
def native():
    path = Path(__file__).parent / "fixtures" / "uxg_pro" / "native-source-nat-snapshots.json"
    fixture = json.loads(path.read_text())
    version = {key: fixture[key] for key in ("version", "versionFormat", "versionDetail")}
    return {stage: {"udapi": {**deepcopy(version), "firewall/nat": rules}}
            for stage, rules in fixture["rules"].items()}


@pytest.fixture
def scope():
    return NatScope(SOURCE, DESTINATION, "br120", "eth3.120", 80100, (8443, 8444), (TRANSLATION,))


def _decode(document, scope, *, dns_forwarder=True, message_broker=False):
    return decode_nat_intent(
        json.dumps(document), revision="observed-revision", scope=scope,
        dns_forwarder=dns_forwarder, message_broker=message_broker,
    )


def _plan(document, scope, *, current=None, verified=None, addresses=None):
    return plan_nat_commands(
        _decode(document, scope), scope=scope,
        live_interface_addresses={"eth3.120": [f"{TRANSLATION}/24"]} if addresses is None else addresses,
        current_rules={} if current is None else current, verified_rules={} if verified is None else verified,
    )


def test_native_masquerade_plans_exact_vyos_rule(native, scope):
    intent = _decode(native["create"], scope)
    assert intent.revision == "observed-revision"
    assert intent.rules[0].source == IPv4Network(SOURCE)
    assert intent.rules[0].destination == IPv4Address(DESTINATION)
    operator = {"1": {"outbound-interface": {"name": "eth0"}, "translation": {"address": "masquerade"}}}
    result = _plan(native["create"], scope, current=operator)

    assert result.desired_rules == {"80100": {
        "description": DESCRIPTION, "protocol": "tcp", "source": {"address": SOURCE},
        "destination": {"address": DESTINATION, "port": "8444"},
        "outbound-interface": {"name": "eth3.120"}, "translation": {"address": "masquerade"},
    }}
    leaves = [
        (["description"], DESCRIPTION), (["protocol"], "tcp"), (["outbound-interface", "name"], "eth3.120"),
        (["source", "address"], SOURCE), (["destination", "address"], DESTINATION),
        (["destination", "port"], "8444"), (["translation", "address"], "masquerade"),
    ]
    assert result.commands == tuple({"op": "set", "path": RULE_PATH + path, "value": value} for path, value in leaves)
    assert operator == {"1": {"outbound-interface": {"name": "eth0"}, "translation": {"address": "masquerade"}}}


def test_rejects_foreign_resource_label_even_when_copied_into_journal(native, scope):
    owned = _plan(native["create"], scope).desired_rules
    owned["80100"]["description"] = "Operator-managed rule"
    with pytest.raises(NatIntentError):
        _plan(native["edit"], scope, current=owned, verified=owned)


def test_preserves_observed_wan_automatic_masquerade_outside_the_managed_scope(native, scope):
    document = native["create"]
    owned = document["udapi"]["firewall/nat"][0]
    owned["id"] = 2
    default = {
        "id": 1, "chain": "POSTROUTING", "target": "MASQUERADE",
        "enabled": True, "log": False, "source": {"sets": ["!ALL_ADDRv4_eth0"]},
        "outInterface": {"id": "eth0"}, "ipVersion": "v4only",
        "originId": "62aea5f6-3000-4000-8000-88feff010001",
    }
    document["udapi"]["firewall/nat"].insert(0, default)

    assert len(_decode(document, scope).rules) == 1
    assert outside_nat_rules(document["udapi"]["firewall/nat"]) == [default]
    default["source"]["sets"] = ["!ALL_ADDRv4_eth3"]
    with pytest.raises(NatIntentError, match="Unsupported"):
        _decode(document, scope)


def test_native_edit_replaces_only_verified_owned_rule(native, scope):
    known = _plan(native["create"], scope).desired_rules
    result = _plan(native["edit"], scope, current=known, verified=known)

    assert result.commands[0] == {"op": "delete", "path": RULE_PATH}
    assert result.desired_rules["80100"]["translation"] == {"address": TRANSLATION}
    assert result.desired_rules["80100"]["destination"]["port"] == "8443"


def test_native_delete_removes_only_recorded_owned_rule(native, scope):
    owned = _plan(native["create"], scope).desired_rules
    current = {"5": {"translation": {"address": "masquerade"}}, **owned}
    result = _plan(native["delete"], scope, current=current, verified=owned, addresses={})

    assert result.commands == ({"op": "delete", "path": RULE_PATH},)
    assert result.desired_rules == {}


def test_plan_equal_to_verified_readback_has_no_commands(native, scope):
    known = _plan(native["edit"], scope).desired_rules

    assert _plan(native["edit"], scope, current=known, verified=known).commands == ()


def test_port_order_follows_controller_sequence(native, scope):
    rules = native["edit"]["udapi"]["firewall/nat"]
    next_rule = deepcopy(native["create"]["udapi"]["firewall/nat"][0])
    next_rule["id"] = 2
    rules.append(next_rule)

    result = _plan(native["edit"], scope)

    assert result.desired_rules["80100"]["destination"]["port"] == "8443"
    assert result.desired_rules["80101"]["destination"]["port"] == "8444"


@pytest.mark.parametrize("patch", [
    {"enabled": False}, {"log": True}, {"chain": "PREROUTING"}, {"target": "DNAT"},
    {"protocol": "udp"}, {"ipVersion": "both"}, {"source": {"address": "0.0.0.0/0"}},
    {"source": {"address": "!192.0.2.0/24"}}, {"source": {"sets": ["source-rule"]}},
    {"destination": {"address": DESTINATION, "port": "22"}},
    {"destination": {"address": DESTINATION, "port": "8443-8444"}},
    {"destination": {"address": "198.51.100.0/24", "port": "8444"}},
    {"outInterface": {"id": "br110"}}, {"connectionState": ["new"]},
    {"translation": {"address": TRANSLATION}},
])
def test_reject_unsupported_or_wider_native_rule(native, scope, patch):
    native["create"]["udapi"]["firewall/nat"][0].update(patch)

    with pytest.raises(NatIntentError):
        _decode(native["create"], scope)


def test_duplicate_packet_match_is_rejected_before_allocating_slots(native, scope):
    rules = native["create"]["udapi"]["firewall/nat"]
    rules.append({**rules[0], "id": 2})

    with pytest.raises(NatIntentError):
        _decode(native["create"], scope)


def test_missing_nat_section_is_unavailable_instead_of_delete(native, scope):
    native["delete"]["udapi"].pop("firewall/nat")

    with pytest.raises(NatIntentError):
        _decode(native["delete"], scope)


def test_explicit_snat_needs_an_operator_pin_and_live_address(native, scope):
    unpinned = NatScope(SOURCE, DESTINATION, "br120", "eth3.120", 80100, (8443, 8444))
    with pytest.raises(NatIntentError):
        _decode(native["edit"], unpinned)
    with pytest.raises(NatIntentError):
        _plan(native["edit"], scope, addresses={"eth3.120": ["198.51.100.3/24"]})


def test_egress_must_still_reach_the_scoped_destination(native, scope):
    with pytest.raises(NatIntentError):
        _plan(native["create"], scope, addresses={"eth3.120": ["203.0.113.1/24"]})


@pytest.mark.parametrize("operator", [
    {"translation": {"address": "masquerade"}},
    {"outbound-interface": {"name": "any"}, "translation": {"address": "masquerade"}},
    {"outbound-interface": {"name": "eth3.*"}, "translation": {"address": "masquerade"}},
    {"destination": {"port": "8440-8449"}, "protocol": "tcp"},
])
def test_operator_overlap_or_unknown_match_refuses_create(native, scope, operator):
    with pytest.raises(NatIntentError):
        _plan(native["create"], scope, current={"999999": operator})


def test_disjoint_operator_port_stays_intact_until_controller_edit_would_overlap(native, scope):
    operator = {"99": {"protocol": "tcp", "destination": {"port": "8443"}}}
    owned = _plan(native["create"], scope, current=operator).desired_rules

    with pytest.raises(NatIntentError):
        _plan(native["edit"], scope, current={**operator, **owned}, verified=owned)


def test_rule_cannot_be_claimed_when_identical_but_unverified(native, scope):
    unverified = _plan(native["create"], scope).desired_rules

    with pytest.raises(NatIntentError):
        _plan(native["create"], scope, current=unverified)


def test_owned_vyos_drift_prevents_delete(native, scope):
    known = _plan(native["create"], scope).desired_rules
    drifted = deepcopy(known)
    drifted["80100"]["log"] = {}

    with pytest.raises(NatIntentError):
        _plan(native["delete"], scope, current=drifted, verified=known)


def test_nat_schema_compatibility_is_exact_and_opt_in(native, scope):
    document = native["create"]
    with pytest.raises(NatIntentError):
        _decode(document, scope, dns_forwarder=False)
    document["udapi"]["versionDetail"]["services/messageBroker"] = 3
    with pytest.raises(NatIntentError):
        _decode(document, scope)
    assert _decode(document, scope, message_broker=True).rules
    document["udapi"]["versionDetail"]["firewall/nat"] = 6
    with pytest.raises(NatIntentError):
        _decode(document, scope, message_broker=True)
