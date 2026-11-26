"""Exercise the qualified two-interface VyOS mDNS repeater write budget."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from collectors.vyos import interface_details
from provisioners.vyos_mdns import (
    MdnsIntentError,
    MdnsScope,
    decode_mdns_intent,
    plan_mdns_commands,
    scrub_mdns_policy,
    verify_mdns_state,
)


REPEATER = ["service", "mdns", "repeater"]
INTERFACES = {"br110": "eth3.110", "br120": "eth3.120"}
ADDRESSES = {"br110": "192.168.110.1/24", "br120": "192.168.120.1/24"}
OWNED = {"interface": ["eth3.110", "eth3.120"], "ip-version": "ipv4"}
LINKS = """\
eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet 192.168.1.1/24 scope global
eth3.110@eth3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet 192.168.110.1/24 scope global
    inet6 fe80::1/64 scope link
eth3.120@eth3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet 192.168.120.1/24 scope global
    inet6 fe80::1/64 scope link
"""


@pytest.fixture
def scope():
    return MdnsScope(interfaces=INTERFACES, addresses=ADDRESSES)


def _plan(scope, *, enabled=True, current=None, verified=None, live=LINKS, listener_present=False, services=()):
    return plan_mdns_commands(
        scope=scope, enabled=enabled, current_mdns=current, verified_repeater=verified,
        live_interfaces=interface_details(live), listener_present=listener_present,
        **({"services": services} if services else {}),
    )


def _verify(scope, expected, current, *, live=LINKS, listener_present=False):
    verify_mdns_state(
        scope=scope, expected_repeater=expected, current_mdns=current,
        live_interfaces=interface_details(live), listener_present=listener_present,
    )


def test_custom_scope_creates_exactly_one_ipv4_repeater(scope):
    plan = _plan(scope)
    assert plan.desired_repeater == OWNED
    assert plan.commands == (
        {"op": "set", "path": REPEATER + ["interface"], "value": "eth3.110"},
        {"op": "set", "path": REPEATER + ["interface"], "value": "eth3.120"},
        {"op": "set", "path": REPEATER + ["ip-version"], "value": "ipv4"},
    )


def test_specific_scope_installs_and_withdraws_only_the_service_list(scope):
    services = ("_airplay._tcp.local", "_uxgtest._tcp.local")
    filtered = {**OWNED, "allow-service": list(services)}
    created = _plan(scope, services=services)
    assert created.desired_repeater == filtered
    assert created.commands[-2:] == tuple(
        {"op": "set", "path": REPEATER + ["allow-service"], "value": service} for service in services
    )
    _verify(scope, filtered, {"repeater": filtered}, listener_present=True)
    assert _plan(scope, services=services, current={"repeater": filtered}, verified=filtered,
                 listener_present=True).commands == ()

    all_services = _plan(scope, current={"repeater": filtered}, verified=filtered, listener_present=True)
    assert all_services.desired_repeater == OWNED
    assert all_services.commands == ({"op": "delete", "path": REPEATER + ["allow-service"]},)


def test_filtered_repeater_cannot_delete_an_operator_filter(scope):
    verified = {**OWNED, "allow-service": "_airplay._tcp.local"}
    operator = {**OWNED, "allow-service": "_ipp._tcp.local"}
    with pytest.raises(MdnsIntentError, match="ownership"):
        _plan(scope, enabled=False, current={"repeater": operator}, verified=verified, listener_present=True)


def test_single_filter_uses_the_stock_vyos_scalar_readback(scope):
    service = "_uxgtest._tcp.local"
    changed = _plan(scope, current={"repeater": OWNED}, verified=OWNED, listener_present=True,
                    services=(service,))
    running = {"repeater": {**OWNED, "allow-service": service}}
    _verify(scope, changed.desired_repeater, running, listener_present=True)
    duplicate = _plan(scope, current=running, verified=changed.desired_repeater,
                      listener_present=True, services=(service,))
    assert duplicate.commands == ()


def test_plan_preserves_service_label_case_for_the_stock_matcher(scope):
    label = "_MyService._tcp.local"
    planned = _plan(scope, services=(label,))
    assert planned.desired_repeater["allow-service"] == label
    assert planned.commands[-1]["value"] == label


def test_repeater_order_is_deterministic_for_each_explicit_selection():
    scope = MdnsScope(interfaces=dict(reversed(list(INTERFACES.items()))), addresses=ADDRESSES)
    assert _plan(scope).desired_repeater == OWNED


def test_off_removes_the_service_root_when_its_only_child_is_owned(scope):
    current = {"repeater": deepcopy(OWNED)}
    before = deepcopy(current)
    plan = _plan(scope, enabled=False, current=current, verified=OWNED, live="", listener_present=True)

    assert plan.desired_repeater is None
    assert plan.commands == ({"op": "delete", "path": REPEATER[:-1]},)
    assert current == before


def test_absence_and_verified_custom_are_idempotent(scope):
    assert _plan(scope, enabled=False).commands == ()
    assert _plan(scope, current={"repeater": OWNED}, verified=OWNED, listener_present=True).commands == ()


@pytest.mark.parametrize("current", [
    {"repeater": OWNED}, {"repeater": {**OWNED, "disable": {}}},
    {"repeater": {**OWNED, "interface": ["eth3.110", "eth1"]}},
    {"unknown": {"listen": ["eth1"]}}, {"repeater": None}, {},
])
@pytest.mark.parametrize("enabled", [True, False])
def test_unowned_service_never_gets_claimed_or_deleted(scope, current, enabled):
    with pytest.raises(MdnsIntentError, match="ownership"):
        _plan(scope, enabled=enabled, current=current)


@pytest.mark.parametrize("extra", [
    {"interface": ["eth3.110", "eth3.120", "eth1"]},
    {"ip-version": "both"}, {"allow-service": "_ipp._tcp"}, {"browse-domain": "example.test"},
    {"vrrp-disable": {}}, {"disable": {}},
])
def test_operator_drift_refuses_delete_even_if_pinned_members_still_present(scope, extra):
    current = {"repeater": {**OWNED, **extra}}
    with pytest.raises(MdnsIntentError, match="ownership"):
        _plan(scope, enabled=False, current=current, verified=OWNED)


def test_other_mdns_subtrees_also_block_the_singleton_service(scope):
    current = {"repeater": OWNED, "other": {"listener": "eth1"}}
    with pytest.raises(MdnsIntentError, match="ownership"):
        _plan(scope, enabled=False, current=current, verified=OWNED)


def test_logged_tree_cannot_authorize_operator_filters(scope):
    outside = {**OWNED, "allow-service": "_ipp._tcp"}
    with pytest.raises(MdnsIntentError, match="ownership"):
        _plan(scope, enabled=False, current={"repeater": outside}, verified=outside)


@pytest.mark.parametrize("enabled", [True, False])
def test_out_of_band_udp_listener_cannot_be_adopted_or_acknowledged(scope, enabled):
    with pytest.raises(MdnsIntentError, match="listener"):
        _plan(scope, enabled=enabled, listener_present=True)


@pytest.mark.parametrize("live", [
    "", LINKS.replace("eth3.120", "eth3.220"), LINKS.replace("192.168.120.1/24", "192.168.120.2/24"),
    LINKS.replace(",LOWER_UP", ""),
    LINKS.replace("192.168.120.1/24 scope global",
                  "192.168.120.1/24 scope global\n    inet 203.0.113.1/24 scope global"),
])
def test_scope_requires_two_live_links_with_exact_ipv4_cidrs(scope, live):
    with pytest.raises(MdnsIntentError, match="interface"):
        _plan(scope, live=live)


def test_verify_requires_config_listener_and_live_mapped_vlans(scope):
    _verify(scope, OWNED, {"repeater": OWNED}, listener_present=True)
    with pytest.raises(MdnsIntentError, match="listener"):
        _verify(scope, OWNED, {"repeater": OWNED})
    with pytest.raises(MdnsIntentError, match="read-back"):
        _verify(scope, OWNED, {"repeater": {**OWNED, "disable": {}}}, listener_present=True)
    with pytest.raises(MdnsIntentError, match="interface"):
        _verify(scope, OWNED, {"repeater": OWNED}, live="", listener_present=True)


def test_verify_off_requires_repeater_and_udp_listener_gone(scope):
    _verify(scope, None, None)
    with pytest.raises(MdnsIntentError, match="listener"):
        _verify(scope, None, None, listener_present=True)
    with pytest.raises(MdnsIntentError, match="read-back"):
        _verify(scope, None, {"repeater": OWNED})


@pytest.mark.parametrize(("interfaces", "addresses"), [
    ({"br110": "eth3.110"}, {"br110": "192.168.110.1/24"}),
    ({"br0": "eth1", "br120": "eth3.120"}, {"br0": "192.168.1.1/24", "br120": "192.168.120.1/24"}),
    ({"br110": "eth3.120", "br120": "eth3.110"}, ADDRESSES),
    ({"br110": "eth3.110", "br120": "eth3.120", "br130": "eth3.130"}, ADDRESSES),
    (INTERFACES, {"br110": "192.168.110.1/24", "br120": "192.168.110.129/25"}),
    (INTERFACES, {"br110": "192.168.110.1", "br120": "192.168.120.1/24"}),
    (INTERFACES, {"br110": "192.168.110.0/24", "br120": "192.168.120.1/24"}),
])
def test_scope_needs_two_distinct_tagged_lans_and_nonoverlapping_gateway_addresses(interfaces, addresses):
    with pytest.raises(MdnsIntentError):
        MdnsScope(interfaces=interfaces, addresses=addresses)


@pytest.fixture
def native_mdns():
    path = Path(__file__).parent / "fixtures" / "uxg_pro" / "native-mdns-snapshots.json"
    return json.loads(path.read_text())


def _decode(udapi, scope, **pins):
    return decode_mdns_intent(
        json.dumps({"udapi": udapi}), revision="observed-mdns-revision", scope=scope,
        **({"dns_forwarder": True, "nat": True, "wireguard": True} | pins),
    )


def _normalize(udapi, scope):
    return scrub_mdns_policy(udapi, _decode(udapi, scope))


def _mdns_rule(udapi):
    return next(chain["rules"][0] for chain in udapi["firewall/filter"] if chain["config"]["name"] == "LAN_LOCAL")


def _topology_row(udapi, name):
    return next(i for i in udapi["interfaces"] if i["identification"]["id"] == name)


@pytest.mark.parametrize(("stage", "desired"), [("off", False), ("custom", True), ("off-again", False)])
def test_three_native_snapshots_normalize_to_off(native_mdns, scope, stage, desired):
    source = native_mdns[stage]
    before = deepcopy(source)
    intent = _decode(source, scope)

    assert intent.revision == "observed-mdns-revision"
    assert intent.enabled is desired
    assert scrub_mdns_policy(source, intent) == native_mdns["off"]
    assert source == before


def test_native_service_scope_v2_preserves_only_the_observed_service_list(native_mdns, scope):
    path = Path(__file__).parent / "fixtures" / "uxg_pro" / "native-mdns-service-scope.json"
    wire = json.loads(path.read_text())
    for capture_name, base_name in (("off", "off"), ("specific", "custom")):
        capture = wire[capture_name]
        source = deepcopy(native_mdns[base_name])
        for section in ("versionDetail", "services"):
            source[section].update(capture[section])
        intent = _decode(source, scope)
        assert intent.services == tuple(sorted(capture["services"].get("mdns", {}).get("reflectFilter", ())))
        assert scrub_mdns_policy(source, intent) == native_mdns["off"]


@pytest.mark.parametrize(("preset_filter", "local_type"), [
    ("_http_alt._tcp.local", "_http_alt._tcp.local"),
    ("_matter_gateway._tcp.local", "_matter_gateway._tcp.local"),
    ("_amazonecho-remote._tcp", "_amazonecho-remote._tcp.local"),
    ("_hap._tcp", "_hap._tcp.local"),
    ("_hap._udp", "_hap._udp.local"),
    ("_matter._tcp", "_matter._tcp.local"),
    ("_matter_gateway._tcp", "_matter_gateway._tcp.local"),
    ("_matterc._udp", "_matterc._udp.local"),
    ("_matterd._udp", "_matterd._udp.local"),
    ("_scanner._tcp", "_scanner._tcp.local"),
])
def test_native_preset_filters_use_complete_local_service_types(native_mdns, scope, preset_filter, local_type):
    source = native_mdns["custom"]
    source["versionDetail"]["services/mdns"] = 2
    source["services"]["mdns"]["reflectFilter"] = [preset_filter]

    intent = _decode(source, scope)

    assert intent.services == (local_type,)
    assert scrub_mdns_policy(source, intent) == native_mdns["off"]
    plan = _plan(scope, services=intent.services)
    assert plan.desired_repeater == {**OWNED, "allow-service": local_type}
    assert plan.commands[-1] == {"op": "set", "path": REPEATER + ["allow-service"], "value": local_type}


def test_native_preset_catalog_compiles_one_filter_per_local_type(native_mdns, scope):
    path = Path(__file__).parent / "fixtures" / "uxg_pro" / "network-11.0.104-mdns-presets.json"
    presets = json.loads(path.read_text())["presets"]
    # Network removes literal duplicates while keeping short and full names.
    native_filters = list(dict.fromkeys(value for values in presets.values() for value in values))
    source = native_mdns["custom"]
    source["versionDetail"]["services/mdns"] = 2
    source["services"]["mdns"]["reflectFilter"] = native_filters

    intent = _decode(source, scope)

    assert len(native_filters) == 35
    assert len(intent.services) == 28
    assert {"_hap._tcp.local", "_hap._udp.local", "_matter_gateway._tcp.local",
            "_amazonecho-remote._tcp.local", "_http_alt._tcp.local", "_scanner._tcp.local"} <= set(intent.services)
    assert all(value.endswith(".local") for value in intent.services)
    assert scrub_mdns_policy(source, intent) == native_mdns["off"]
    with pytest.raises(MdnsIntentError, match="255-byte"):
        _plan(scope, services=intent.services)


def test_stock_filter_line_fits_without_truncating_a_selection(scope):
    services = tuple(f"_{name}{'a' * size}._tcp.local" for name, size in zip("abcd", (45, 45, 45, 46), strict=True))
    assert len("reflect-filters=" + ", ".join(services)) == 255
    assert _plan(scope, services=services).desired_repeater["allow-service"] == list(services)

    oversized = (*services[:-1], services[-1].replace("._tcp", "a._tcp"))
    assert len("reflect-filters=" + ", ".join(oversized)) == 256
    with pytest.raises(MdnsIntentError, match="255-byte"):
        _plan(scope, services=oversized)


@pytest.mark.parametrize("version", [None, True, 1, 3, "2"])
def test_nonempty_native_filters_require_the_negotiated_v2_schema(native_mdns, version):
    from provisioners.vyos_mdns import normalize_mdns_service_version

    native = native_mdns["custom"]
    native["services"]["mdns"]["reflectFilter"] = ["_airplay._tcp.local"]
    if version is not None:
        native["versionDetail"]["services/mdns"] = version
    with pytest.raises(MdnsIntentError, match="schema"):
        normalize_mdns_service_version(json.dumps({"udapi": native}))


def test_native_custom_preserves_other_policy_and_array_order(native_mdns, scope):
    for source in (native_mdns["off"], native_mdns["custom"]):
        source["custom"] = {"keys": ["second", "first"]}
        source["services"]["dnsForwarder"]["additional"] = "preserved"
        source["firewall/sets"][0], source["firewall/sets"][1] = source["firewall/sets"][1], source["firewall/sets"][0]
    assert _normalize(native_mdns["custom"], scope) == native_mdns["off"]


@pytest.mark.parametrize("patch", [
    {"enabled": False}, {"enabled": 1}, {"reflectFilter": ["_ipp._tcp.local,_other._tcp.local"]},
    {"reflectFilter": ["_unknown._tcp"]},
    {"reflectFilter": ["_hap._tcp", "_HAP._tcp.local"]},
    {"reflectFilter": None}, {"reflectFilter": ["_ipp._tcp.local", "_IPP._tcp.local"]},
    {"reflectFilter": [f"_{'a' * 63}._tcp.local"]},
    {"mode": "custom"}, {"interfaces": [{"id": "br110"}]},
    {"interfaces": [{"id": "br110"}, {"id": "br120"}, {"id": "br0"}]},
    {"interfaces": [{"id": "br110"}, {"id": "br130"}]},
    {"interfaces": [{"id": "br120"}, {"id": "br110"}]},
    {"interfaces": [{"id": "br110"}, {"id": "br110"}]},
])
def test_native_auto_filter_or_expanded_lan_scope_is_never_claimed(native_mdns, scope, patch):
    source = native_mdns["custom"]
    source["services"]["mdns"].update(patch)
    with pytest.raises(MdnsIntentError, match="scope"):
        _decode(source, scope)


def test_explicit_null_is_not_the_captured_off_shape(native_mdns, scope):
    source = native_mdns["off"]
    source["services"]["mdns"] = None
    with pytest.raises(MdnsIntentError):
        _decode(source, scope)


@pytest.mark.parametrize(("name", "patch"), [
    ("br110", {"addresses": [{"type": "static", "cidr": "192.168.110.1/25", "version": "v4"}]}),
    ("br110", {"status": {"enabled": 1, "comment": "LAN"}}),
    ("br110", {"bridge": {"id": 110, "interfaces": [{"id": "eth3.110"}]}}),
    ("br120", {"bridge": {"id": 120, "interfaces": [{"id": "eth1.120"}, {"id": "eth3.120"}, {"id": "eth2.120"}]}}),
    ("eth3.110", {"vlan": {"id": 110, "interface": {"id": "eth1"}}}),
    ("eth2.120", {"status": {"enabled": False}}),
    ("eth1", {"status": {"enabled": False}}),
])
@pytest.mark.parametrize("stage", ["off", "custom"])
def test_complete_native_lan_topology_is_required_before_control(native_mdns, scope, name, patch, stage):
    source = native_mdns[stage]
    _topology_row(source, name).update(patch)
    with pytest.raises(MdnsIntentError, match="topology"):
        _decode(source, scope)


@pytest.mark.parametrize("patch", [
    {"ipVersion": "v4only"}, {"log": 0}, {"protocol": "tcp"}, {"originId": "not-an-id"},
    {"source": {"port": "5353"}}, {"destination": {"sets": ["mdns_addresses_name"]}},
    {"ipOptions": []},
])
def test_generated_lan_local_rule_is_exact(native_mdns, scope, patch):
    source = native_mdns["custom"]
    _mdns_rule(source).update(patch)
    with pytest.raises(MdnsIntentError, match="rule"):
        _normalize(source, scope)


@pytest.mark.parametrize(("index", "patch"), [
    (17, {"entries": ["224.0.0.251"]}), (18, {"entries": [5353]}),
    (18, {"entries": ["5353", "5354"]}), (18, {"extra": []}),
])
def test_generated_set_shapes_are_exact(native_mdns, scope, index, patch):
    source = native_mdns["custom"]
    source["firewall/sets"][index].update(patch)
    with pytest.raises(MdnsIntentError, match="set"):
        _normalize(source, scope)


@pytest.mark.parametrize("reference", ["mdns_addresses_name", "mdns_ports_name", "[LAN_LOCAL]Allow mDNS"])
@pytest.mark.parametrize("stage", ["off", "custom"])
def test_unmanaged_references_to_generated_mdns_scope_are_rejected(native_mdns, scope, stage, reference):
    source = native_mdns[stage]
    source["unrelated"] = {reference: "operator-owned"}
    with pytest.raises(MdnsIntentError, match="reference"):
        _normalize(source, scope)


def test_removed_rule_origin_must_not_be_reused_outside_scope(native_mdns, scope):
    source = native_mdns["custom"]
    source["unrelated"] = {"origin": _mdns_rule(source)["originId"]}
    with pytest.raises(MdnsIntentError, match="reference"):
        _normalize(source, scope)


def test_other_parsed_snapshot_cannot_reuse_decoded_intent(native_mdns, scope):
    with pytest.raises(MdnsIntentError, match="intent"):
        scrub_mdns_policy(native_mdns["off"], _decode(native_mdns["custom"], scope))


@pytest.mark.parametrize("patch", [{"dns_forwarder": False}, {"nat": False}, {"wireguard": False}, {"message_broker": True}])
def test_protocol_schema_must_match_all_explicit_gateway_pins(native_mdns, scope, patch):
    with pytest.raises(MdnsIntentError, match="schema"):
        _decode(native_mdns["custom"], scope, **patch)
