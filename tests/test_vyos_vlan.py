"""Test the one-VIF write budget against VyOS configuration and link read-back."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from collectors.vyos import interface_details
from provisioners.vyos_mdns import MdnsScope, decode_mdns_intent, scrub_mdns_policy
from provisioners.vyos_vlan import (
    VlanIntentError,
    VlanScope,
    decode_vlan_intent,
    plan_vlan_commands,
    scrub_vlan_policy,
    verify_vlan_state,
)


VIF_PATH = ["interfaces", "ethernet", "eth3", "vif", "130"]
OWNED = {"address": "192.168.130.1/24"}
PARENT = "eth3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
CHILD = (
    "eth3.130@eth3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
    "    inet 192.168.130.1/24 scope global eth3.130\n"
    "    inet6 fe80::1/64 scope link\n"
)
OTHER_LINKS = (
    "eth3.110@eth3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
    "    inet 192.168.110.1/24 scope global eth3.110\n"
    "eth3.220@eth3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
    "    inet 198.18.220.1/30 scope global eth3.220\n"
)


@pytest.fixture
def scope():
    return VlanScope(parent="eth3", vlan_id=130, address=OWNED["address"])


@pytest.fixture
def ethernet():
    return {
        "eth0": {"address": "dhcp"},
        "eth2": {"address": ["192.168.77.1/24", "fd00:77::1/64"]},
        "eth3": {
            "description": "Lab packet trunk",
            "vif": {
                "110": {"address": "192.168.110.1/24"},
                "220": {"address": "198.18.220.1/30", "description": "Other owned network"},
            },
        },
    }


def _live(*, child="", parent=PARENT):
    return interface_details(parent + OTHER_LINKS + child)


def _plan(scope, ethernet, *, present=True, known=None, live=None):
    return plan_vlan_commands(
        scope=scope, present=present, current_ethernet=ethernet,
        verified_vif=known, live_interfaces=_live() if live is None else live,
    )


def test_native_single_vlan_maps_to_only_one_vyos_address_leaf(scope, ethernet):
    before = deepcopy(ethernet)
    assert (scope.interface, scope.bridge) == ("eth3.130", "br130")

    plan = _plan(scope, ethernet)

    assert plan.desired_vif == OWNED
    assert plan.commands == ({"op": "set", "path": VIF_PATH + ["address"], "value": OWNED["address"]},)
    assert ethernet == before


def test_removal_deletes_only_the_verified_vlan_and_preserves_parent(scope, ethernet):
    ethernet["eth3"]["vif"]["130"] = dict(OWNED)
    before = deepcopy(ethernet)

    plan = _plan(scope, ethernet, present=False, known=OWNED, live=_live(child=CHILD))

    assert plan.commands == ({"op": "delete", "path": VIF_PATH},)
    assert plan.desired_vif is None
    assert ethernet == before


def test_matched_already_present_and_already_absent_are_noops(scope, ethernet):
    assert _plan(scope, ethernet, present=False).commands == ()
    ethernet["eth3"]["vif"]["130"] = dict(OWNED)
    assert _plan(scope, ethernet, known=OWNED, live=_live(child=CHILD)).commands == ()


@pytest.mark.parametrize("owned", [OWNED, {"address": ["192.168.130.1/24"]}, {}, None])
@pytest.mark.parametrize("present", [False, True])
def test_unjournaled_vif_is_never_claimed_even_if_exact(scope, ethernet, owned, present):
    ethernet["eth3"]["vif"]["130"] = owned
    with pytest.raises(VlanIntentError, match="ownership"):
        _plan(scope, ethernet, present=present, live=_live(child=CHILD))


def test_unconfigured_live_vif_is_never_adopted(scope, ethernet):
    with pytest.raises(VlanIntentError, match="ownership"):
        _plan(scope, ethernet, live=_live(child=CHILD))


@pytest.mark.parametrize("change", [
    {"description": "Operator extended this VLAN"},
    {"disable": {}},
    {"address": "192.168.130.2/24"},
    {"address": ["192.168.130.1/24", "fd00:130::1/64"]},
])
def test_drifted_owned_vif_cannot_be_removed(scope, ethernet, change):
    ethernet["eth3"]["vif"]["130"] = {**OWNED, **change}
    with pytest.raises(VlanIntentError, match="ownership"):
        _plan(scope, ethernet, present=False, known=OWNED, live=_live(child=CHILD))


def test_unexpected_nodes_cannot_be_journaled_as_owned(scope, ethernet):
    malformed = {**OWNED, "description": "Operator ext"}
    ethernet["eth3"]["vif"]["130"] = malformed
    with pytest.raises(VlanIntentError, match="ownership"):
        _plan(scope, ethernet, present=False, known=malformed)


def test_trunk_must_have_existing_ethernet_config_and_carrier_for_creation(scope, ethernet):
    inactive = _live(parent=PARENT.replace(",LOWER_UP", ""))
    with pytest.raises(VlanIntentError, match="parent"):
        _plan(scope, ethernet, live=inactive)

    del ethernet["eth3"]
    with pytest.raises(VlanIntentError, match="parent"):
        _plan(scope, ethernet)


def test_deleting_verified_vlan_can_clean_up_when_trunk_is_down(scope, ethernet):
    ethernet["eth3"]["vif"]["130"] = dict(OWNED)
    parent = PARENT.replace(",UP,LOWER_UP", "").replace("state UP", "state DOWN")
    plan = _plan(scope, ethernet, present=False, known=OWNED, live=_live(parent=parent))
    assert plan.commands == ({"op": "delete", "path": VIF_PATH},)


@pytest.mark.parametrize("link", ["eth3", "eth3.130"])
def test_incomplete_live_readback_cannot_delete_verified_vlan(scope, ethernet, link):
    ethernet["eth3"]["vif"]["130"] = dict(OWNED)
    live = _live(child=CHILD)
    live[link] = None
    with pytest.raises(VlanIntentError, match="operational"):
        _plan(scope, ethernet, present=False, known=OWNED, live=live)


@pytest.mark.parametrize("address", ["192.168.130.42/32", "192.168.130.129/25", "192.168.128.1/22"])
def test_live_overlapping_segment_on_another_interface_is_rejected(scope, ethernet, address):
    other = f"br99: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet {address} scope global\n"
    with pytest.raises(VlanIntentError, match="overlaps"):
        _plan(scope, ethernet, live=_live(child=other))


def test_configured_overlap_is_rejected_even_if_other_vlan_is_not_live(scope, ethernet):
    ethernet["eth3"]["vif"]["221"] = {"address": "192.168.130.2/25", "disable": {}}
    with pytest.raises(VlanIntentError, match="overlaps"):
        _plan(scope, ethernet)


def test_live_foreign_ipv4_on_owned_vlan_prevents_deletion(scope, ethernet):
    ethernet["eth3"]["vif"]["130"] = dict(OWNED)
    child = CHILD + "    inet 192.168.131.1/24 scope global\n"
    with pytest.raises(VlanIntentError, match="ownership"):
        _plan(scope, ethernet, present=False, known=OWNED, live=_live(child=child))


def test_verify_active_vlan_uses_exact_config_and_real_carrier(scope, ethernet):
    ethernet["eth3"]["vif"]["130"] = dict(OWNED)
    verify_vlan_state(scope=scope, expected_vif=OWNED, current_ethernet=ethernet, live_interfaces=_live(child=CHILD))

    inactive = CHILD.replace(",LOWER_UP", "")
    with pytest.raises(VlanIntentError, match="not active"):
        verify_vlan_state(
            scope=scope, expected_vif=OWNED, current_ethernet=ethernet, live_interfaces=_live(child=inactive),
        )

    with pytest.raises(VlanIntentError, match="not active"):
        _plan(scope, ethernet, known=OWNED, live=_live(child=inactive))


def test_verify_requires_managed_link_gone_after_deletion(scope, ethernet):
    verify_vlan_state(scope=scope, expected_vif=None, current_ethernet=ethernet, live_interfaces=_live())
    with pytest.raises(VlanIntentError, match="remains"):
        verify_vlan_state(scope=scope, expected_vif=None, current_ethernet=ethernet, live_interfaces=_live(child=CHILD))
    ethernet["eth3"]["vif"]["130"] = dict(OWNED)
    with pytest.raises(VlanIntentError, match="read-back"):
        verify_vlan_state(scope=scope, expected_vif=None, current_ethernet=ethernet, live_interfaces=_live())


@pytest.mark.parametrize("settings", [
    {"parent": "eth3.110"}, {"parent": "eth3 "}, {"vlan_id": 0}, {"vlan_id": 4095}, {"vlan_id": True},
    {"address": "192.168.130.1"}, {"address": "192.168.130.0/24"},
    {"address": "192.168.130.255/24"}, {"address": "0.0.0.1/0"},
    {"address": "224.0.0.1/24"}, {"address": "fd00:130::1/64"},
])
def test_bad_scope_never_reaches_planner(settings):
    defaults = {"parent": "eth3", "vlan_id": 130, "address": OWNED["address"]}
    with pytest.raises(VlanIntentError):
        VlanScope(**(defaults | settings))


@pytest.fixture
def native_vlan():
    fixture = Path(__file__).parent / "fixtures" / "uxg_pro" / "native-vlan-snapshots.json"
    captures = json.loads(fixture.read_text())
    changes = captures.pop("second_create_changes")
    second = deepcopy(captures["create"])
    for row in second["firewall/sets"]:
        name = row["identification"]["name"]
        if name in changes["subnet_entries"]:
            row["entries"] = changes["subnet_entries"][name]
    for name, origin in changes["jump_origins"].items():
        _chain(second, name)[4]["originId"] = origin
    captures["second_create"] = second
    return captures


def _decode(udapi, scope, **pins):
    return decode_vlan_intent(
        json.dumps({"udapi": udapi}), revision="observed-vlan-revision", scope=scope,
        **({"dns_forwarder": True, "nat": True, "wireguard": True} | pins),
    )


def _normalize(udapi, scope):
    return scrub_vlan_policy(udapi, _decode(udapi, scope))


def _udapi_interfaces(udapi):
    return {row["identification"]["id"]: row for row in udapi["interfaces"]}


def _chain(udapi, name):
    return next(row["rules"] for row in udapi["firewall/filter"] if row["config"]["name"] == name)


def test_native_create_normalizes_to_pre_vlan_capture(native_vlan, scope):
    baseline, created = native_vlan["baseline"], native_vlan["create"]
    before = deepcopy(created)
    assert _decode(baseline, scope).present is False
    intent = _decode(created, scope)
    assert intent.present is True
    assert intent.revision == "observed-vlan-revision"

    assert scrub_vlan_policy(created, intent) == baseline
    assert created == before
    assert _normalize(baseline, scope) == baseline


def test_native_delete_matches_original_capture(native_vlan, scope):
    deleted = native_vlan["delete"]
    assert _decode(deleted, scope).present is False
    assert _normalize(deleted, scope) == native_vlan["baseline"]


@pytest.mark.parametrize("stage", ["baseline", "create", "second_create", "delete"])
def test_vlan_normalization_with_managed_mdns_requires_the_pre_scrubbed_service(native_vlan, scope, stage):
    source = native_vlan[stage]
    with pytest.raises(VlanIntentError, match="mDNS"):
        scrub_vlan_policy(source, _decode(source, scope), managed_mdns=True)

    normalized = deepcopy(source)
    normalized["services"].pop("mdns")
    expected = deepcopy(native_vlan["baseline"])
    expected["services"].pop("mdns")
    assert scrub_vlan_policy(normalized, _decode(source, scope), managed_mdns=True) == expected


def test_managed_mdns_never_waives_the_exact_vlan_dns_listener(native_vlan, scope):
    source = native_vlan["create"]
    source["services"].pop("mdns")
    source["services"]["dnsForwarder"]["listenInterfaces"][1]["mode"] = "unapproved"

    with pytest.raises(VlanIntentError, match="service listener"):
        scrub_vlan_policy(source, _decode(source, scope), managed_mdns=True)


def test_captured_custom_mdns_and_vlan_create_normalize_together(scope):
    path = Path(__file__).parent / "fixtures" / "uxg_pro" / "native-vlan-mdns-snapshots.json"
    captures = json.loads(path.read_text())
    combined = captures["combined"]
    before = deepcopy(combined)
    mdns_scope = MdnsScope(
        interfaces={"br110": "eth3.110", "br120": "eth3.120"},
        addresses={"br110": "192.168.110.1/24", "br120": "192.168.120.1/24"},
    )
    mdns = decode_mdns_intent(
        json.dumps({"udapi": combined}), revision="combined", scope=mdns_scope,
        dns_forwarder=True, nat=True, wireguard=True,
    )
    vlan = _decode(combined, scope)
    assert mdns.enabled and vlan.present
    assert scrub_vlan_policy(scrub_mdns_policy(combined, mdns), vlan, managed_mdns=True) == captures["off"]
    assert combined == before


def test_second_native_create_prepends_only_the_generated_subnet(native_vlan, scope):
    second = native_vlan["second_create"]
    before = deepcopy(second)
    assert _decode(second, scope).present is True
    assert _normalize(second, scope) == native_vlan["baseline"]
    assert second == before


def test_repeat_create_with_new_generated_rule_ids_reuses_baseline(native_vlan, scope):
    created = native_vlan["create"]
    for index, name in enumerate(("INPUT", "OUTPUT", "FORWARD_IN"), start=1):
        _chain(created, name)[4]["originId"] = f"33333333-3333-4333-8333-{index:012d}"
    assert _normalize(created, scope) == native_vlan["baseline"]


def test_standalone_vlan_fingerprint_preserves_other_fields_and_order(native_vlan, scope):
    before, after = native_vlan["baseline"], native_vlan["create"]
    for u in (before, after):
        u["unrelated"] = {"order": ["alpha", "gamma", "beta"]}
        u["services"]["dnsForwarder"]["extra-option"] = "preserved"
        _chain(u, "INPUT")[0]["log"] = True
        u["firewall/sets"].reverse()
    assert _normalize(after, scope) == before


@pytest.mark.parametrize("patch", [
    {"addresses": [{"type": "dhcp", "cidr": "192.168.130.1/24", "version": "v4"}]},
    {"addresses": [{"type": "static", "cidr": "192.168.130.1/25", "version": "v4"}]},
    {"status": {"enabled": False, "comment": "LAN"}},
    {"status": {"enabled": 1, "comment": "LAN"}},
    {"bridge": {"id": 130, "interfaces": [{"id": "eth3.130"}]}},
    {"bridge": {"id": 130, "interfaces": [{"id": "eth3.130"}, {"id": "eth2.130"}, {"id": "eth1.130"}]}},
    {"bridge": {"id": "130", "interfaces": [{"id": "eth1.130"}, {"id": "eth2.130"}, {"id": "eth3.130"}]}},
    {"extra": {"ip": "192.0.2.53"}},
])
def test_native_bridge_shape_is_exact(native_vlan, scope, patch):
    created = native_vlan["create"]
    _udapi_interfaces(created)[scope.bridge].update(patch)
    with pytest.raises(VlanIntentError):
        _decode(created, scope)


@pytest.mark.parametrize("mutation", [
    lambda rows: rows.pop(7),
    lambda rows: rows[3]["vlan"]["interface"].update(id="eth0"),
    lambda rows: rows[3]["vlan"].update(id=131),
    lambda rows: rows[3].update(status={"enabled": 1}),
    lambda rows: rows.append(deepcopy(rows[3])),
    lambda rows: rows.insert(8, rows.pop(7)),
])
def test_native_vlan_members_are_complete_and_positioned(native_vlan, scope, mutation):
    created = native_vlan["create"]
    mutation(created["interfaces"])
    with pytest.raises(VlanIntentError):
        _decode(created, scope)


@pytest.mark.parametrize("stage", ["baseline", "create"])
@pytest.mark.parametrize("reference", ["br130", "eth3.130", "eth0.130", "192.168.130.1/24", "192.168.130.0/24"])
def test_residual_native_references_cannot_be_left_for_other_scopes(native_vlan, scope, stage, reference):
    value = native_vlan[stage]
    value["unrelated"] = {"source": [reference]}
    with pytest.raises(VlanIntentError, match="reference"):
        _normalize(value, scope)


@pytest.mark.parametrize("chain", ["INPUT", "OUTPUT", "FORWARD_IN"])
@pytest.mark.parametrize("patch", [{"id": 30005}, {"log": 0}, {"originId": "malformed"}, {"options": []}])
def test_exact_native_lan_jump_required(native_vlan, scope, chain, patch):
    created = native_vlan["create"]
    _chain(created, chain)[4].update(patch)
    with pytest.raises(VlanIntentError, match="jump"):
        _normalize(created, scope)


@pytest.mark.parametrize("kind,field,index", [
    ("dnsForwarder", "listenInterfaces", 1), ("mdns", "interfaces", 3),
])
def test_native_listener_changes_only_own_one_exact_bridge_reference(native_vlan, scope, kind, field, index):
    created = native_vlan["create"]
    created["services"][kind][field][index]["mode"] = "extra"
    with pytest.raises(VlanIntentError, match="service"):
        _normalize(created, scope)


@pytest.mark.parametrize("name", [
    "LAN_subnets", "LAN_corporate_network", "local_zoned_subnets", "corporate_network", "local_network",
])
@pytest.mark.parametrize("position", [0, 1])
def test_native_subnet_sets_reject_mixed_positions(native_vlan, scope, name, position):
    created = native_vlan["create"]
    target = next(row for row in created["firewall/sets"] if row["identification"]["name"] == name)
    target["entries"].insert(position, target["entries"].pop())
    with pytest.raises(VlanIntentError, match="subnet"):
        _normalize(created, scope)


@pytest.mark.parametrize("mode", ["missing", "duplicate"])
def test_native_subnet_sets_require_exactly_one_owned_atom(native_vlan, scope, mode):
    second = native_vlan["second_create"]
    target = next(row for row in second["firewall/sets"] if row["identification"]["name"] == "LAN_subnets")
    if mode == "missing":
        target["entries"].pop(0)
    else:
        target["entries"].append(target["entries"][0])
    with pytest.raises(VlanIntentError, match="subnet"):
        _normalize(second, scope)


def test_subnet_normalization_preserves_unrelated_policy_and_order_for_baseline_gate(native_vlan, scope):
    second = native_vlan["second_create"]
    target = next(row for row in second["firewall/sets"] if row["identification"]["name"] == "LAN_subnets")
    target["entries"][1:] = ["192.0.2.0/24", "192.168.110.0/24", "192.168.1.0/24"]
    normalized = _normalize(second, scope)
    result = next(row for row in normalized["firewall/sets"] if row["identification"]["name"] == "LAN_subnets")

    assert result["entries"] == ["192.0.2.0/24", "192.168.110.0/24", "192.168.1.0/24"]
    assert normalized != native_vlan["baseline"]


def test_normalizer_checks_matching_complete_vlan_intent(native_vlan, scope):
    missing, present = native_vlan["baseline"], native_vlan["create"]
    with pytest.raises(VlanIntentError, match="intent"):
        scrub_vlan_policy(present, _decode(missing, scope))


@pytest.mark.parametrize("flags", [{"nat": False}, {"wireguard": False}, {"dns_forwarder": False}, {"message_broker": True}])
def test_native_vlan_requires_matching_optional_schema_pins(native_vlan, scope, flags):
    with pytest.raises(VlanIntentError, match="schema"):
        _decode(native_vlan["create"], scope, **flags)
