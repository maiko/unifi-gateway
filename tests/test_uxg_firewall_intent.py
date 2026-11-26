"""Decode the complete LAN-to-LAN policy recorded from a Network 11 controller."""

from copy import deepcopy
from ipaddress import IPv4Network, IPv6Network
import json
from pathlib import Path

import pytest

from provisioners.uxg_intent import (
    FirewallRule,
    FirewallIntentError,
    decode_firewall_intent,
)


@pytest.fixture(scope="module")
def snapshots():
    path = Path(__file__).parent / "fixtures" / "uxg_pro" / "zbf-native-snapshots.json"
    return json.loads(path.read_text())["snapshots"]


@pytest.fixture(scope="module")
def action_snapshots():
    path = Path(__file__).parent / "fixtures/uxg_pro/zbf-native-actions.json"
    return json.loads(path.read_text())["snapshots"]


@pytest.fixture
def native(snapshots):
    return json.loads(snapshots["created"]["system_cfg"])


@pytest.fixture(params=["allow-return", "ipv6-allow-return"])
def native_allow_return(action_snapshots, request):
    return json.loads(action_snapshots[request.param]["system_cfg"])


@pytest.mark.parametrize(("snapshot", "port"), [
    ("baseline", None), ("created", 8443), ("edited", 8444), ("deleted", None),
])
def test_decode_native_policy_lifecycle(snapshots, snapshot, port):
    captured = snapshots[snapshot]
    intent = decode_firewall_intent(captured["system_cfg"], revision=captured["cfgversion"])

    assert intent.revision == captured["cfgversion"]
    expected = () if port is None else (
        FirewallRule(10000, IPv4Network("192.0.2.0/24"), IPv4Network("198.51.100.0/24"), port),
    )
    assert intent.rules == expected


def test_preserve_controller_chain_order(native):
    rules = native["udapi"]["firewall/filter"][0]["rules"]
    first = {**deepcopy(rules[0]), "id": 10001}
    rules.insert(0, first)

    intent = decode_firewall_intent(json.dumps(native), revision="opaque revision")

    assert intent.revision == "opaque revision"
    assert tuple(rule.controller_rule_id for rule in intent.rules) == (10001, 10000)


def test_native_ipv6_deny_keeps_its_address_family_and_exact_tcp_port():
    path = Path(__file__).parent / "fixtures/uxg_pro/native-ipv6-lan-deny.json"
    observed = path.read_text()
    intent = decode_firewall_intent(observed, revision="native-ipv6")
    assert intent.rules == (FirewallRule(10000, IPv6Network("fd42:7891:110::/64"),
                                        IPv6Network("fd42:7891:120::/64"), 18443),)

    malformed = json.loads(observed)
    malformed["udapi"]["firewall/sets"][0]["entries"] = ["192.0.2.0/24"]
    with pytest.raises(FirewallIntentError):
        decode_firewall_intent(json.dumps(malformed), revision="wrong-family")


@pytest.mark.parametrize(("case", "states"), [
    ("reject", ()), ("reject-new", ("new",)), ("reject-return", ("established", "related")),
    ("reject-invalid", ("invalid",)),
])
def test_decode_native_reject_and_state(action_snapshots, case, states):
    captured = action_snapshots[case]
    intent = decode_firewall_intent(captured["system_cfg"], revision=captured["cfgversion"])

    assert intent.rules == (FirewallRule(
        10000, IPv4Network("192.0.2.0/24"), IPv4Network("198.51.100.0/24"), 8443,
        action="reject", states=states,
    ),)


@pytest.mark.parametrize(("case", "action"), [("unlogged-reject", "reject"), ("unlogged-block", "drop")])
def test_decode_native_unlogged_deny(action_snapshots, case, action):
    captured = action_snapshots[case]

    intent = decode_firewall_intent(captured["system_cfg"], revision=captured["cfgversion"])

    assert intent.rules == (FirewallRule(
        10000, IPv4Network("192.0.2.0/24"), IPv4Network("198.51.100.0/24"), 18443,
        action=action, states=("established", "related"), log=False,
    ),)


def test_decode_native_ipv4_udp_block(action_snapshots):
    captured = action_snapshots["udp-block"]

    intent = decode_firewall_intent(captured["system_cfg"], revision=captured["cfgversion"])

    assert intent.rules == (FirewallRule(
        10000, IPv4Network("192.0.2.0/24"), IPv4Network("198.51.100.0/24"), 18443,
        protocol="udp", log=False,
    ),)


def test_decode_native_ipv4_udp_block_range(action_snapshots):
    captured = action_snapshots["udp-block-range"]

    intent = decode_firewall_intent(captured["system_cfg"], revision=captured["cfgversion"])

    assert intent.rules == (FirewallRule(
        10000, IPv4Network("192.0.2.0/24"), IPv4Network("198.51.100.0/24"), "18443-18444",
        protocol="udp", log=False,
    ),)


@pytest.mark.parametrize("entries", [
    ["18444-18443"], ["18443-18443"], ["0-18444"], ["18443-65536"],
    ["018443-18444"], ["18443 - 18444"], ["18443:18444"], ["!18443-18444"],
    ["18443-18444,18446"], ["18443-18444", "18446"],
])
def test_reject_invalid_udp_port_ranges(action_snapshots, entries):
    document = json.loads(action_snapshots["udp-block-range"]["system_cfg"])
    port_set = next(entry for entry in document["udapi"]["firewall/sets"]
                    if entry["identification"]["type"] == "port")
    port_set["entries"] = entries

    with pytest.raises(FirewallIntentError):
        decode_firewall_intent(json.dumps(document), revision="invalid-udp-range")


@pytest.mark.parametrize("case", ["udp-block", "udp-block-range"])
@pytest.mark.parametrize("patch", [
    {"target": "ACCEPT"},
    {"target": "REJECT"},
    {"connectionState": ["new"]},
    {"log": True},
    {"protocol": "tcp_udp"},
    {
        "source": {"sets": ["policy_src_ip_1", "policy_dst_port_1"]},
        "destination": {"sets": ["policy_dst_ip_1"]},
    },
])
def test_reject_udp_rules_outside_the_captured_scope(action_snapshots, case, patch):
    document = json.loads(action_snapshots[case]["system_cfg"])
    document["udapi"]["firewall/filter"][0]["rules"][0].update(patch)

    with pytest.raises(FirewallIntentError):
        decode_firewall_intent(json.dumps(document), revision="unsupported-udp")


@pytest.mark.parametrize("port", ["18443", "18443-18444"])
def test_reject_ipv6_udp_block(port):
    path = Path(__file__).parent / "fixtures/uxg_pro/native-ipv6-lan-deny.json"
    document = json.loads(path.read_text())
    rule = document["udapi"]["firewall/filter"][0]["rules"][0]
    rule["protocol"] = "udp"
    del rule["log"]
    port_set = next(entry for entry in document["udapi"]["firewall/sets"]
                    if entry["identification"]["type"] == "port")
    port_set["entries"] = [port]

    with pytest.raises(FirewallIntentError):
        decode_firewall_intent(json.dumps(document), revision="unsupported-ipv6-udp")


@pytest.mark.parametrize(("case", "states"), [
    ("allow", ()), ("allow-return", ()), ("allow-invalid", ("invalid",)),
    ("allow-invalid-return", ("invalid",)),
])
def test_decode_native_allow_and_automatic_return(action_snapshots, case, states):
    captured = action_snapshots[case]
    source = IPv4Network("192.0.2.0/24")
    destination = IPv4Network("198.51.100.0/24")

    intent = decode_firewall_intent(captured["system_cfg"], revision=captured["cfgversion"])

    expected = (FirewallRule(10000, source, destination, 8443, action="return", states=states),)
    if case.endswith("-return"):
        expected += (FirewallRule(
            30000, destination, source, 8443, action="return",
            states=("established", "related"), source_port=True, log=False,
        ),)
    assert intent.rules == expected


def test_decode_native_unlogged_allow_and_automatic_return(action_snapshots):
    captured = action_snapshots["unlogged-allow-return"]
    source = IPv4Network("192.0.2.0/24")
    destination = IPv4Network("198.51.100.0/24")

    intent = decode_firewall_intent(captured["system_cfg"], revision=captured["cfgversion"])

    assert intent.rules == (
        FirewallRule(10000, source, destination, 18443, action="return", log=False),
        FirewallRule(
            30000, destination, source, 18443, action="return",
            states=("established", "related"), source_port=True, log=False,
        ),
    )


def test_explicit_allow_uses_supported_connection_states(native_allow_return):
    parent, _, _ = native_allow_return["udapi"]["firewall/filter"][0]["rules"]
    parent["connectionState"] = ["related", "new", "invalid", "established"]

    intent = decode_firewall_intent(json.dumps(native_allow_return), revision="revision")

    assert intent.rules[0].states == ("established", "invalid", "new", "related")
    assert intent.rules[1].states == ("established", "related")


def test_decode_native_ipv6_allow_and_automatic_return(action_snapshots):
    captured = action_snapshots["ipv6-allow-return"]
    source = IPv6Network("2001:db8:130::/64")
    destination = IPv6Network("2001:db8:140::/64")

    intent = decode_firewall_intent(captured["system_cfg"], revision=captured["cfgversion"])

    assert intent.rules == (
        FirewallRule(10000, source, destination, 8443, action="return"),
        FirewallRule(
            30000, destination, source, 8443, action="return", states=("established", "related"),
            source_port=True, log=False,
        ),
    )


def test_native_return_rejects_a_mismatched_address_family(native_allow_return):
    parent, companion, _ = native_allow_return["udapi"]["firewall/filter"][0]["rules"]
    companion["ipVersion"] = "v6only" if parent["ipVersion"] == "v4only" else "v4only"

    with pytest.raises(FirewallIntentError, match="configured address family"):
        decode_firewall_intent(json.dumps(native_allow_return), revision="revision")


def test_native_return_preserves_position_after_intervening_policy(native_allow_return):
    rules = native_allow_return["udapi"]["firewall/filter"][0]["rules"]
    rules.insert(1, {**deepcopy(rules[0]), "id": 40000, "target": "REJECT"})

    intent = decode_firewall_intent(json.dumps(native_allow_return), revision="revision")

    assert [(rule.controller_rule_id, rule.action) for rule in intent.rules] == [
        (10000, "return"), (40000, "reject"), (30000, "return"),
    ]


@pytest.mark.parametrize(("case", "expected"), [
    ("block-before-allow", [(10000, "drop"), (10001, "return")]),
    ("allow-before-block", [(10000, "return"), (10001, "drop")]),
    ("auto-off", [(10000, "return"), (10001, "drop"), (10002, "drop")]),
    ("auto-on-default", [(10000, "return"), (10001, "drop"), (10002, "drop"), (30000, "return")]),
    ("auto-on-ordered", [(10000, "return"), (10001, "drop"), (30000, "return"), (40000, "drop")]),
    ("auto-off-again", [(10000, "return"), (10001, "drop"), (40000, "drop")]),
    ("paused", [(10000, "return"), (10001, "drop")]),
    ("resumed", [(10000, "return"), (10001, "drop"), (40000, "drop")]),
    ("v6-reject-before-allow", [(10000, "reject"), (10001, "return")]),
    ("v6-allow-before-reject", [(10000, "return"), (10001, "reject")]),
    ("v6-auto-off", [(10000, "return"), (10001, "reject"), (10002, "drop")]),
    ("v6-auto-on-default", [(10000, "return"), (10001, "reject"), (10002, "drop"), (30000, "return")]),
    ("v6-auto-on-ordered", [(10000, "return"), (10001, "reject"), (30000, "return"), (40000, "drop")]),
])
def test_observed_policy_editor_reordering(action_snapshots, case, expected):
    captured = action_snapshots[case]
    intent = decode_firewall_intent(captured["system_cfg"], revision=captured["cfgversion"])

    assert [(rule.controller_rule_id, rule.action) for rule in intent.rules] == expected
    if "auto-on" in case:
        companion, = (rule for rule in intent.rules if rule.source_port)
        assert companion.port == 8443 and companion.states == ("established", "related")


@pytest.mark.parametrize(("case", "states"), [
    ("v6-reject-new", ("new",)),
    ("v6-reject-return", ("established", "related")),
    ("v6-reject-all", ()),
])
def test_native_ipv6_reject_state_changes(action_snapshots, case, states):
    captured = action_snapshots[case]
    intent = decode_firewall_intent(captured["system_cfg"], revision=captured["cfgversion"])

    assert intent.rules == (FirewallRule(
        10000, IPv6Network("2001:db8:130::/64"), IPv6Network("2001:db8:140::/64"),
        8443, action="reject", states=states,
    ),)


@pytest.mark.parametrize(("case", "expected"), [
    ("invalid-block", [("drop", ("invalid",))]),
    ("invalid-block-before-allow", [("drop", ("invalid",)), ("return", ("invalid",)), ("return", ("established", "related"))]),
    ("invalid-allow-before-block", [("return", ("invalid",)), ("drop", ("invalid",)), ("return", ("established", "related"))]),
    ("invalid-allow-fallback", [("return", ("invalid",)), ("drop", ()), ("return", ("established", "related"))]),
])
def test_native_invalid_scope_and_order(action_snapshots, case, expected):
    captured = action_snapshots[case]
    intent = decode_firewall_intent(captured["system_cfg"], revision=captured["cfgversion"])

    assert [(rule.action, rule.states) for rule in intent.rules] == expected
    assert [rule.source_port for rule in intent.rules] == ([False] if case == "invalid-block" else [False, False, True])


@pytest.mark.parametrize("mutation", [
    "orphan", "before-parent", "different-description", "equal-set-with-different-id",
    "duplicate-parent", "duplicate-companion",
])
def test_native_return_requires_one_unpaired_earlier_allow(native_allow_return, mutation):
    udapi = native_allow_return["udapi"]
    rules = udapi["firewall/filter"][0]["rules"]
    parent, companion = rules[:2]
    if mutation == "orphan":
        rules.pop(0)
    elif mutation == "before-parent":
        rules[:2] = [companion, parent]
    elif mutation == "different-description":
        companion["description"] = "Unrelated (Return)"
    elif mutation == "equal-set-with-different-id":
        sets = udapi["firewall/sets"]
        alias = deepcopy(next(entry for entry in sets if entry["identification"]["type"] == "port"))
        alias["identification"]["name"] = "aliased_port"
        sets.append(alias)
        companion["source"]["sets"][1] = "aliased_port"
    elif mutation == "duplicate-parent":
        rules.insert(1, {**deepcopy(parent), "id": 20000})
    else:
        rules.insert(2, {**deepcopy(companion), "id": 40000})

    with pytest.raises(FirewallIntentError, match="Return companion"):
        decode_firewall_intent(json.dumps(native_allow_return), revision="revision")


@pytest.mark.parametrize(("rule_index", "patch"), [
    (0, {"log": False}),
    (0, {"log": 1}),
    (0, {"connectionState": ["untracked"]}),
    (0, {"connectionState": ["invalid", "invalid"]}),
    (1, {"log": False}),
    (1, {"log": True}),
    (1, {"target": "REJECT"}),
    (1, {"connectionState": ["related", "related"]}),
    (1, {"connectionState": ["related", "established", "new"]}),
    (1, {"connectionState": ["related", "established", "invalid"]}),
    (1, {"description": "Lab Allow State"}),
    (1, {"source": {"sets": ["policy_dst_port_1", "policy_dst_ip_1"]}}),
])
def test_reject_unobserved_allow_shapes(native_allow_return, rule_index, patch):
    native_allow_return["udapi"]["firewall/filter"][0]["rules"][rule_index].update(patch)
    with pytest.raises(FirewallIntentError):
        decode_firewall_intent(json.dumps(native_allow_return), revision="revision")


@pytest.mark.parametrize("mutation", [
    "missing-chain", "duplicate-chain", "empty-chain", "missing-sentinel", "early-sentinel",
    "matched-sentinel", "duplicate-rule-id", "unsupported-version", "missing-sets",
])
def test_reject_incomplete_or_ambiguous_snapshots(native, mutation):
    udapi = native["udapi"]
    chains = udapi["firewall/filter"]
    rules = chains[0]["rules"]
    if mutation == "missing-chain":
        chains.clear()
    elif mutation == "duplicate-chain":
        chains.append(deepcopy(chains[0]))
    elif mutation == "empty-chain":
        rules.clear()
    elif mutation == "missing-sentinel":
        rules.pop()
    elif mutation == "early-sentinel":
        rules.reverse()
    elif mutation == "matched-sentinel":
        rules[-1]["protocol"] = "tcp"
    elif mutation == "duplicate-rule-id":
        rules.insert(1, deepcopy(rules[0]))
    elif mutation == "unsupported-version":
        udapi["versionDetail"]["firewall/filter"] = 5
    else:
        udapi.pop("firewall/sets")

    with pytest.raises(FirewallIntentError):
        decode_firewall_intent(json.dumps(native), revision="revision")


@pytest.mark.parametrize("patch", [
    {"target": "RETURN"},
    {"target": ["REJECT"]},
    {"protocol": "udp"},
    {"ipVersion": "both"},
    {"log": False},
    {"connectionState": ["ESTABLISHED"]},
    {"connectionState": "new"},
    {"connectionState": ["new", "new"]},
    {"connectionState": ["new", "untracked"]},
    {"inInterface": {"id": "br0"}},
    {"source": {"sets": ["policy_src_ip_1"], "negate": True}},
    {"source": {"sets": []}},
    {"destination": {"sets": ["policy_dst_ip_1", "policy_dst_ip_1"]}},
    {"destination": {"sets": ["policy_dst_ip_1", "missing_port"]}},
])
def test_reject_rules_with_unsupported_or_unresolved_matches(native, patch):
    native["udapi"]["firewall/filter"][0]["rules"][0].update(patch)

    with pytest.raises(FirewallIntentError):
        decode_firewall_intent(json.dumps(native), revision="revision")


@pytest.mark.parametrize(("set_index", "entries"), [
    (0, []),
    (0, ["192.0.2.9/24"]),
    (0, ["192.0.2.1-192.0.2.254"]),
    (0, ["2001:db8::/64"]),
    (0, ["192.0.2.0/24", "192.0.3.0/24"]),
    (2, ["8443-8444"]),
    (2, [8443]),
    (2, ["0"]),
    (2, ["65536"]),
])
def test_reject_sets_with_unsupported_values(native, set_index, entries):
    native["udapi"]["firewall/sets"][set_index]["entries"] = entries

    with pytest.raises(FirewallIntentError):
        decode_firewall_intent(json.dumps(native), revision="revision")


def test_reject_duplicate_set_name_even_on_another_set_type(native):
    sets = native["udapi"]["firewall/sets"]
    duplicate = deepcopy(sets[0])
    duplicate["identification"]["type"] = "port"
    sets.append(duplicate)

    with pytest.raises(FirewallIntentError):
        decode_firewall_intent(json.dumps(native), revision="revision")


def test_reject_duplicate_json_field(native):
    payload = json.dumps(native).replace('"target": "DROP"', '"target": "ACCEPT", "target": "DROP"')

    with pytest.raises(FirewallIntentError):
        decode_firewall_intent(payload, revision="revision")


def test_reject_empty_revision(snapshots):
    with pytest.raises(FirewallIntentError):
        decode_firewall_intent(snapshots["deleted"]["system_cfg"], revision="")
