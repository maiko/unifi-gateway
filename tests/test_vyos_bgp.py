"""Verify the supported Enterprise FRR upload and the equivalent stock config."""

from base64 import b64encode
from configparser import RawConfigParser
from dataclasses import replace
from ipaddress import IPv4Address, IPv4Network, IPv6Address
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

from provisioners.vyos_bgp import (
    BgpIntentError, BgpProvisioningIntent, BgpScope, bgp_checkpoint, bgp_checkpoint_resources, decode_bgp_intent,
    normalize_bgp_policy, plan_bgp_commands,
    read_bgp_configuration,
    redact_bgp_configuration, vyos_bgp_configuration,
)
from provisioners.vyos import VyOSReconciler
from provisioners.uxg_intent import FirewallIntent
from unifi_gateway import UnifiGateway
from unifi_protocol import decode_inform, encode_inform


_FRR = """\
router bgp 64520
 bgp router-id 192.0.2.1
 network 203.0.113.0 mask 255.255.255.0
 neighbor 192.0.2.2 remote-as 64521
 address-family ipv4
  neighbor 192.0.2.2 activate
  neighbor 192.0.2.2 route-map IMPORT-ROUTES in
  neighbor 192.0.2.2 route-map EXPORT-ROUTES out
 exit-address-family
exit
!
route-map IMPORT-ROUTES permit 10
 match ip address prefix-list IMPORT-PREFIXES
exit
route-map EXPORT-ROUTES permit 10
 match ip address prefix-list EXPORT-PREFIXES
exit
ip prefix-list IMPORT-PREFIXES seq 20 permit 198.51.100.128/25
ip prefix-list IMPORT-PREFIXES seq 10 permit 198.51.100.0/25
ip prefix-list EXPORT-PREFIXES seq 5 permit 203.0.113.0/24
"""


def _upload(text):
    return {"enabled": True, "config": b64encode(text.encode()).decode()}


_FRR6 = """\
router bgp 64520
 bgp router-id 192.0.2.1
 no bgp default ipv4-unicast
 neighbor 2001:db8:10::50 remote-as 64521
 address-family ipv6 unicast
  network 2001:db8:60::/64
  neighbor 2001:db8:10::50 activate
  neighbor 2001:db8:10::50 route-map IMPORT-ROUTES in
  neighbor 2001:db8:10::50 route-map EXPORT-ROUTES out
 exit-address-family
exit
route-map IMPORT-ROUTES permit 10
 match ipv6 address prefix-list IMPORT-PREFIXES
exit
route-map EXPORT-ROUTES permit 10
 match ipv6 address prefix-list EXPORT-PREFIXES
exit
ipv6 prefix-list IMPORT-PREFIXES seq 10 permit 2001:db8:50::10/128
ipv6 prefix-list EXPORT-PREFIXES seq 5 permit 2001:db8:60::/64
"""

_MIXED_V6_ROUTER, _MIXED_V6_POLICY = _FRR6.replace("IMPORT", "IMPORT6").replace("EXPORT", "EXPORT6").split("\nexit\n", 1)
_MIXED_V6_AF = _MIXED_V6_ROUTER[_MIXED_V6_ROUTER.index(" address-family ipv6"):]
_MIXED = _FRR.replace(" address-family ipv4",
    " neighbor 2001:db8:10::50 remote-as 64521\n address-family ipv4",
).replace(" bgp router-id", " no bgp default ipv4-unicast\n bgp router-id", 1).replace(
    "\nexit\n", f"\n{_MIXED_V6_AF}\nexit\n", 1,
) + _MIXED_V6_POLICY


def test_mixed_bgp_preserves_existing_ipv4_ownership_and_withdraws_ipv6_selectively():
    ipv4 = decode_bgp_intent(_upload(_FRR))
    mixed = decode_bgp_intent(_upload(_MIXED))
    config = BgpScope(frozenset(peer.address for peer in mixed.peers),
                      frozenset(mixed.imports), frozenset(mixed.exports))
    config.require(mixed)
    assert config.accepts_existing_scope({
        "peer": str(ipv4.peers[0].address), "imports": sorted(map(str, ipv4.imports)),
        "exports": sorted(map(str, ipv4.exports)),
    })
    old, combined = map(vyos_bgp_configuration, (ipv4, mixed))
    for path, tree in old.items():
        if path != ("protocols", "bgp"):
            assert combined[path] == tree
    remove = plan_bgp_commands(ipv4, current=combined, verified=combined)
    assert {tuple(command["path"]) for command in remove} == {
        ("policy", "prefix-list6", "UNIFI-BGP6-IN"), ("policy", "prefix-list6", "UNIFI-BGP6-OUT"),
        ("protocols", "bgp", "neighbor", "2001:db8:10::50"),
        ("protocols", "bgp", "address-family", "ipv6-unicast"),
    }
    assert all(command["op"] == "delete" for command in remove)


def test_mixed_bgp_refresh_only_targets_retained_peers_in_the_edited_family(tmp_path):
    mixed = decode_bgp_intent(_upload(_MIXED))
    edited = decode_bgp_intent(_upload(_MIXED.replace("2001:db8:50::10/128", "2001:db8:50::20/128")))
    backend = Mock()
    scope = BgpScope(frozenset(peer.address for peer in mixed.peers),
                     frozenset(mixed.imports + edited.imports), frozenset(mixed.exports))
    router = VyOSReconciler(backend, interfaces={IPv4Network("192.0.2.0/24"): "br0"},
                                state_path=tmp_path / "bgp.json", rule_base=80200,
                                bgp_scope=scope, commit_proof=Mock())
    router._refresh_bgp_filters(bgp_checkpoint(vyos_bgp_configuration(mixed)),
                                bgp_checkpoint(vyos_bgp_configuration(edited)))
    backend.soft_refresh_bgp_ipv4.assert_not_called()
    ipv6_peer = next(peer.address for peer in mixed.peers if peer.address.version == 6)
    backend.soft_refresh_bgp_ipv6.assert_called_once_with(ipv6_peer, direction="in")


def test_one_ipv4_bgp_peer_carries_both_families_with_independent_filters(tmp_path):
    upload = _MIXED.replace(" neighbor 2001:db8:10::50 remote-as 64521\n", "").replace(
        "2001:db8:10::50", "192.0.2.2").replace(
        " address-family ipv6 unicast\n", " address-family ipv6 unicast\n  neighbor 192.0.2.2 soft-reconfiguration inbound\n",
    )
    original = decode_bgp_intent(_upload(upload))
    updated = decode_bgp_intent(_upload(upload.replace("2001:db8:50::10/128", "2001:db8:50::20/128")))
    config = vyos_bgp_configuration(original)
    peer = IPv4Address("192.0.2.2")
    node = config[("protocols", "bgp")]["neighbor"]
    assert set(node) == {str(peer)}
    families = node[str(peer)]["address-family"]
    assert "soft-reconfiguration" not in families["ipv4-unicast"]
    assert families["ipv6-unicast"]["soft-reconfiguration"] == {"inbound": {}}
    backend = Mock()
    separate = decode_bgp_intent(_upload(_MIXED))
    legacy_scope = BgpScope(frozenset(item.address for item in separate.peers),
                            frozenset(original.imports + updated.imports), frozenset(original.exports))
    with pytest.raises(BgpIntentError, match="not approved for IPv6"):
        legacy_scope.require(updated)
    scope = BgpScope.from_config({
        "peer": str(peer), "dual_stack_peers": json.dumps([str(peer)]),
        "import_prefixes": json.dumps(sorted(set(map(str, original.imports + updated.imports)))),
        "export_prefixes": json.dumps(list(map(str, original.exports))),
    })
    plain = decode_bgp_intent(_upload(_FRR))
    assert scope.accepts_existing_scope({
        "peer": str(peer), "imports": sorted(map(str, plain.imports)), "exports": sorted(map(str, plain.exports)),
    })
    scope.require(updated)
    router = VyOSReconciler(backend, interfaces={IPv4Network("192.0.2.0/24"): "br0"},
                                state_path=tmp_path / "bgp.json", rule_base=80200,
                                bgp_scope=scope, commit_proof=Mock())
    router._refresh_bgp_filters(bgp_checkpoint(config), bgp_checkpoint(vyos_bgp_configuration(updated)))
    backend.soft_refresh_bgp_ipv4.assert_not_called()
    backend.soft_refresh_bgp_ipv6.assert_called_once_with(peer, direction="in")


def test_one_ipv6_bgp_peer_carries_both_families_with_an_ipv4_only_refresh(tmp_path):
    peer = IPv6Address("2001:db8:10::50")
    capability = f" neighbor {peer} capability extended-nexthop\n"
    upload = _MIXED.replace(" neighbor 192.0.2.2 remote-as 64521\n", capability).replace("192.0.2.2", str(peer))
    with pytest.raises(BgpIntentError):
        decode_bgp_intent(_upload(upload.replace(capability, "")))
    original = decode_bgp_intent(_upload(upload))
    updated = decode_bgp_intent(_upload(upload.replace("198.51.100.128/25", "198.51.101.0/24")))
    config = vyos_bgp_configuration(original)
    node = config[("protocols", "bgp")]["neighbor"]
    assert set(node) == {str(peer)}
    assert node[str(peer)]["capability"] == {"extended-nexthop": {}}
    assert set(node[str(peer)]["address-family"]) == {"ipv4-unicast", "ipv6-unicast"}
    ipv6_only = decode_bgp_intent(_upload(_FRR6))
    withdraw_ipv4 = plan_bgp_commands(ipv6_only, current=config, verified=config)
    assert {
        tuple(command["path"]) for command in withdraw_ipv4 if command["op"] == "delete"
    } == {
        ("policy", "prefix-list", "UNIFI-BGP4-IN"),
        ("policy", "prefix-list", "UNIFI-BGP4-OUT"),
        ("protocols", "bgp", "neighbor", str(peer), "capability"),
        ("protocols", "bgp", "neighbor", str(peer), "address-family", "ipv4-unicast"),
        ("protocols", "bgp", "address-family", "ipv4-unicast"),
    }

    settings = {
        "peers": json.dumps([str(peer), "192.0.2.2"]),
        "import_prefixes": json.dumps(sorted(set(map(str, original.imports + updated.imports)))),
        "export_prefixes": json.dumps(list(map(str, original.exports))),
    }
    with pytest.raises(BgpIntentError, match="not approved for IPv4"):
        BgpScope.from_config(settings).require(updated)
    scope = BgpScope.from_config({
        "peer": str(peer), "dual_stack_peers": json.dumps([str(peer)]),
        "import_prefixes": settings["import_prefixes"], "export_prefixes": settings["export_prefixes"],
    })
    scope.require(updated)
    assert scope.accepts_existing_scope({
        "peer": str(peer), "imports": sorted(map(str, ipv6_only.imports)), "exports": sorted(map(str, ipv6_only.exports)),
    })
    backend = Mock()
    router = VyOSReconciler(backend, interfaces={IPv4Network("192.0.2.0/24"): "br0"},
                                state_path=tmp_path / "bgp.json", rule_base=80200,
                                bgp_scope=scope, commit_proof=Mock())
    router._refresh_bgp_filters(bgp_checkpoint(config), bgp_checkpoint(vyos_bgp_configuration(updated)))
    backend.soft_refresh_bgp_ipv4.assert_called_once_with(peer, direction="in")
    backend.soft_refresh_bgp_ipv6.assert_not_called()


def test_bgp_checkpoint_rejects_filter_pairs_for_another_family():
    old = bgp_checkpoint(vyos_bgp_configuration(decode_bgp_intent(_upload(_FRR))))
    new = bgp_checkpoint(vyos_bgp_configuration(decode_bgp_intent(_upload(_FRR6))))
    with pytest.raises(BgpIntentError, match="ownership checkpoint"):
        bgp_checkpoint_resources(new | {"process": old["process"]})


def test_adding_ipv6_checks_the_ipv6_forwarding_table(tmp_path, monkeypatch):
    old, mixed = [decode_bgp_intent(_upload(frr)) for frr in (_FRR, _MIXED)]
    backend = Mock()
    backend.show_ipv6_routes.return_value = {
        "2001:db8:99::/64": [{"protocol": "bgp", "table": 254, "vrfId": 0, "selected": True, "installed": True}],
    }
    scope = BgpScope(frozenset(peer.address for peer in mixed.peers), frozenset(mixed.imports), frozenset(mixed.exports))
    router = VyOSReconciler(backend, interfaces={IPv4Network("192.0.2.0/24"): "br0"},
                                state_path=tmp_path / "bgp.json", rule_base=80200, bgp_scope=scope, commit_proof=Mock())
    monkeypatch.setattr("provisioners.vyos.time.sleep", lambda _seconds: None)
    from backends.vyos import VyOSReadError
    with pytest.raises(VyOSReadError, match="outside the intended import policy"):
        router._verify_bgp_import_policy(bgp_checkpoint(vyos_bgp_configuration(old)),
                                        bgp_checkpoint(vyos_bgp_configuration(mixed)))
    backend.show_ipv4_routes.assert_not_called()


_BGP_WITH_OPTIONS = _FRR.replace(
    " neighbor 192.0.2.2 remote-as 64521", " neighbor 192.0.2.2 remote-as 64521\n neighbor 192.0.2.2 description Lab  edge (WAN)"
).replace("  neighbor 192.0.2.2 activate", "  neighbor 192.0.2.2 activate\n  neighbor 192.0.2.2 soft-reconfiguration inbound")

_DUAL_PEER = _BGP_WITH_OPTIONS.replace(
    " address-family ipv4", " neighbor 192.0.2.3 remote-as 64522\n neighbor 192.0.2.3 description Second tunnel\n address-family ipv4",
).replace(
    " exit-address-family", "  neighbor 192.0.2.3 activate\n  neighbor 192.0.2.3 route-map IMPORT-ROUTES in\n"
    "  neighbor 192.0.2.3 route-map EXPORT-ROUTES out\n exit-address-family",
)


def test_two_approved_bgp_peers_share_filters_and_keep_independent_settings():
    single = decode_bgp_intent(_upload(_BGP_WITH_OPTIONS))
    dual = decode_bgp_intent(_upload(_DUAL_PEER))
    scope = BgpScope.from_config({"peers": '["192.0.2.2", "192.0.2.3"]', "import_prefixes": '["198.51.100.0/25", "198.51.100.128/25"]',
                                  "export_prefixes": '["203.0.113.0/24"]'})
    scope.require(dual)
    with pytest.raises(BgpIntentError, match="approved peer"):
        BgpScope(frozenset({IPv4Address("192.0.2.2")}), scope.imports, scope.exports).require(dual)

    before, after = vyos_bgp_configuration(single), vyos_bgp_configuration(dual)
    neighbors = after[("protocols", "bgp")]["neighbor"]
    assert neighbors["192.0.2.2"] == before[("protocols", "bgp")]["neighbor"]["192.0.2.2"]
    assert neighbors["192.0.2.3"]["description"] == "Second tunnel"
    assert neighbors["192.0.2.3"]["remote-as"] == "64522"
    assert neighbors["192.0.2.3"]["address-family"]["ipv4-unicast"]["prefix-list"] == {
        "import": "UNIFI-BGP4-IN", "export": "UNIFI-BGP4-OUT",
    }
    addition = plan_bgp_commands(dual, current=before, verified=before)
    branch = ["protocols", "bgp", "neighbor", "192.0.2.3"]
    assert addition and all(command["op"] == "set" and command["path"][:4] == branch for command in addition)
    assert plan_bgp_commands(single, current=after, verified=after) == ({"op": "delete", "path": branch},)


def test_two_peer_upload_cannot_flatten_distinct_import_filters():
    distinct = _DUAL_PEER.replace("192.0.2.3 route-map IMPORT-ROUTES", "192.0.2.3 route-map DISTINCT") + (
        "route-map DISTINCT permit 10\nmatch ip address prefix-list OTHER\nexit\n"
        "ip prefix-list OTHER seq 10 permit 198.51.100.0/25\n"
    )
    with pytest.raises(BgpIntentError):
        decode_bgp_intent(_upload(distinct))


def test_two_bgp_peers_keep_separate_password_proofs_and_rotation_paths():
    dual = decode_bgp_intent(_upload(_DUAL_PEER))
    initial = replace(dual, peers=tuple(replace(peer, password="test-shared-password") for peer in dual.peers))
    first, second = initial.peers
    rotated = replace(initial, peers=(first, replace(second, password="new-test-password")))
    proof_key = b"k" * 32
    current = redact_bgp_configuration(vyos_bgp_configuration(initial), proof_key)
    neighbors = current[("protocols", "bgp")]["neighbor"]
    assert neighbors[str(first.address)]["password"] != neighbors[str(second.address)]["password"]
    assert plan_bgp_commands(rotated, current=current, verified=current, proof_key=proof_key) == ({
        "op": "set", "path": ["protocols", "bgp", "neighbor", str(second.address), "password"], "value": "new-test-password",
    },)


def test_adding_an_approved_bgp_peer_preserves_the_existing_verified_journal(tmp_path):
    single = decode_bgp_intent(_upload(_BGP_WITH_OPTIONS))
    dual = decode_bgp_intent(_upload(_DUAL_PEER))
    old_scope = BgpScope(frozenset(peer.address for peer in single.peers), frozenset(single.imports), frozenset(single.exports))
    wider_scope = replace(old_scope, peers=frozenset(peer.address for peer in dual.peers))
    running = {("firewall", "ipv4", "forward", "filter"): {"default-action": "accept"}}
    backend = Mock()
    backend.read_config.side_effect = lambda path: running.get(tuple(path))
    backend.show_interfaces.return_value = {}
    options = dict(interfaces={IPv4Network("192.0.2.0/24"): "eth3", IPv4Network("203.0.113.0/24"): "eth4"},
                   state_path=tmp_path / "router.json", rule_base=80200, commit_proof=Mock(return_value="a" * 64))
    original = VyOSReconciler(backend, bgp_scope=old_scope, **options)
    backend.stage_configuration.side_effect = lambda *args, **kwargs: running.update(vyos_bgp_configuration(single))
    first = original.reconcile(FirewallIntent("single", ()), bgp_intent=BgpProvisioningIntent("single", single))
    assert first.error is None and first.verified_revision == "single"

    expanded = VyOSReconciler(backend, bgp_scope=wider_scope, **options)
    backend.stage_configuration.side_effect = lambda *args, **kwargs: running.update(vyos_bgp_configuration(dual))
    second = expanded.reconcile(FirewallIntent("dual", ()), bgp_intent=BgpProvisioningIntent("dual", dual))
    assert second.error is None and second.verified_revision == "dual"
    checkpoint = json.loads(options["state_path"].read_text())
    assert checkpoint["previous_revisions"] == ["single"]
    assert checkpoint["scope"]["bgp"]["peers"] == ["192.0.2.2", "192.0.2.3"]


@pytest.mark.parametrize("outcome", ["refreshed", "stale", "ambiguous", "no-proof"])
@pytest.mark.parametrize("version", [4, 6])
def test_bgp_import_edit_refreshes_live_routes_before_confirmation(tmp_path, monkeypatch, outcome, version):
    from backends.vyos import VyOSWriteError

    if version == 4:
        old_prefix, new_prefix, source = "198.51.100.0/25", "198.51.101.0/24", _BGP_WITH_OPTIONS
    else:
        old_prefix, new_prefix, source = "2001:db8:50::10/128", "2001:db8:50::20/128", _FRR6
    old = decode_bgp_intent(_upload(source))
    edited = decode_bgp_intent(_upload(source.replace(old_prefix, new_prefix)))
    peer, = old.peers
    scope = BgpScope(frozenset({peer.address}), frozenset(old.imports + edited.imports), frozenset(old.exports))
    running = {("firewall", "ipv4", "forward", "filter"): {"default-action": "accept"}}
    backend = Mock()
    backend.read_config.side_effect = lambda path: running.get(tuple(path))
    backend.show_interfaces.return_value = {}
    route = {"protocol": "bgp", "table": 254, "vrfId": 0, "selected": True, "installed": True}
    read_routes = getattr(backend, f"show_ipv{version}_routes")
    refresh_peer = getattr(backend, f"soft_refresh_bgp_ipv{version}")
    read_routes.return_value = {old_prefix: [route]}
    proof = Mock(return_value="a" * 64)
    state_path = tmp_path / "router.json"
    router = VyOSReconciler(backend, interfaces={IPv4Network("192.0.2.0/24"): "eth3", IPv4Network("203.0.113.0/24"): "eth4"},
                                state_path=state_path, rule_base=80200, bgp_scope=scope, commit_proof=proof)
    backend.stage_configuration.side_effect = lambda *_args, **_kwargs: running.update(vyos_bgp_configuration(old))
    result = router.reconcile(FirewallIntent("old", ()), bgp_intent=BgpProvisioningIntent("old", old))
    assert result.error is None and result.verified_revision == "old"
    backend.reset_mock()

    def refresh(address, *, direction):
        assert address == peer.address and direction == "in"
        assert json.loads(state_path.read_text())["pending"]["confirmed"] is False
        backend.confirm_configuration.assert_not_called()
        if outcome == "ambiguous":
            raise VyOSWriteError("Soft reset reply lost")
        if outcome == "refreshed":
            read_routes.return_value = {new_prefix: [route]}

    monkeypatch.setattr("provisioners.vyos.time.sleep", lambda _seconds: None)
    if outcome == "no-proof":
        proof.side_effect = lambda *, phase: None if phase == "staged" else "a" * 64
    refresh_peer.side_effect = refresh
    backend.stage_configuration.side_effect = lambda *_args, **_kwargs: running.update(vyos_bgp_configuration(edited))
    result = router.reconcile(FirewallIntent("edit", ()), bgp_intent=BgpProvisioningIntent("edit", edited))
    if outcome == "no-proof":
        refresh_peer.assert_not_called()
    else:
        refresh_peer.assert_called_once_with(peer.address, direction="in")
    if outcome == "refreshed":
        assert result.error is None and result.verified_revision == "edit"
        backend.confirm_configuration.assert_called_once()
        backend.save_configuration.assert_called_once()
    else:
        assert result.error and result.verified_revision == "old"
        backend.confirm_configuration.assert_not_called()
        backend.save_configuration.assert_not_called()


def test_ipv6_upload_uses_disjoint_filters_and_withdraws_only_those_resources():
    intent = decode_bgp_intent(_upload(_FRR6))
    resources = vyos_bgp_configuration(intent)
    process = resources[("protocols", "bgp")]
    family = process["neighbor"]["2001:db8:10::50"]["address-family"]
    assert family == {"ipv6-unicast": {"prefix-list": {"import": "UNIFI-BGP6-IN", "export": "UNIFI-BGP6-OUT"}}}
    assert process["address-family"] == {"ipv6-unicast": {"network": {"2001:db8:60::/64": {}}}}
    assert resources[("policy", "prefix-list6", "UNIFI-BGP6-IN")]["rule"]["10"]["prefix"] == "2001:db8:50::10/128"
    assert {tuple(command["path"]) for command in plan_bgp_commands(None, current=resources, verified=resources)} == resources.keys()


@pytest.mark.parametrize(("before", "after"), [
    ("match ipv6 address", "match ip address"),
    (" no bgp default ipv4-unicast\n", ""),
    ("2001:db8:10::50", "fe80::50%eth3"),
    (" address-family ipv6 unicast\n  network 2001:db8:60::/64",
     " network 2001:db8:60::/64\n address-family ipv6 unicast"),
    (" no bgp default ipv4-unicast\n neighbor 2001:db8:10::50 remote-as 64521",
     " neighbor 2001:db8:10::50 remote-as 64521\n no bgp default ipv4-unicast"),
])
def test_ipv6_upload_rejects_ambiguous_address_family_or_peer(before, after):
    with pytest.raises(BgpIntentError):
        decode_bgp_intent(_upload(_FRR6.replace(before, after)))


def test_explicit_ipv4_neighbor_and_exact_route_filters_compile_to_stock_vyos():
    resources = vyos_bgp_configuration(decode_bgp_intent(_upload(_FRR)))
    assert resources[("protocols", "bgp")] == {
        "system-as": "64520",
        "parameters": {"router-id": "192.0.2.1", "network-import-check": {}},
        "address-family": {"ipv4-unicast": {"network": {"203.0.113.0/24": {}}}},
        "neighbor": {"192.0.2.2": {"remote-as": "64521", "address-family": {"ipv4-unicast": {
            "prefix-list": {"import": "UNIFI-BGP4-IN", "export": "UNIFI-BGP4-OUT"},
        }}}},
    }
    assert resources[("policy", "prefix-list", "UNIFI-BGP4-IN")] == {"rule": {
        "10": {"action": "permit", "prefix": "198.51.100.0/25"},
        "20": {"action": "permit", "prefix": "198.51.100.128/25"},
    }}
    assert resources[("policy", "prefix-list", "UNIFI-BGP4-OUT")] == {"rule": {
        "10": {"action": "permit", "prefix": "203.0.113.0/24"},
    }}


def test_documented_neighbor_options_use_stock_leaf_changes_without_replacing_the_bgp_process():
    original = vyos_bgp_configuration(decode_bgp_intent(_upload(_FRR)))
    intent = decode_bgp_intent(_upload(_BGP_WITH_OPTIONS))
    neighbor = ["protocols", "bgp", "neighbor", "192.0.2.2"]
    soft = neighbor + ["address-family", "ipv4-unicast", "soft-reconfiguration"]
    expected = [
        {"op": "set", "path": soft + ["inbound"]},
        {"op": "set", "path": neighbor + ["description"], "value": "Lab  edge (WAN)"},
    ]
    assert list(plan_bgp_commands(intent, current=original, verified=original)) == expected

    configured = vyos_bgp_configuration(intent)
    old_intent = decode_bgp_intent(_upload(_FRR))
    assert list(plan_bgp_commands(old_intent, current=configured, verified=configured)) == [
        {"op": "delete", "path": soft}, {"op": "delete", "path": neighbor + ["description"]},
    ]


def test_neighbor_timer_edit_and_removal_touch_only_the_selected_peer():
    before = vyos_bgp_configuration(decode_bgp_intent(_upload(_DUAL_PEER)))
    with_timers = _DUAL_PEER.replace(
        " neighbor 192.0.2.3 description Second tunnel",
        " neighbor 192.0.2.3 description Second tunnel\n"
        " neighbor 192.0.2.3 timers 10 30\n"
        " neighbor 192.0.2.3 timers connect 5",
    )
    intent = decode_bgp_intent(_upload(with_timers))
    path = ["protocols", "bgp", "neighbor", "192.0.2.3", "timers"]
    assert sorted(plan_bgp_commands(intent, current=before, verified=before), key=lambda command: command["path"]) == [
        {"op": "set", "path": [*path, "connect"], "value": "5"},
        {"op": "set", "path": [*path, "holdtime"], "value": "30"},
        {"op": "set", "path": [*path, "keepalive"], "value": "10"},
    ]
    configured = vyos_bgp_configuration(intent)
    edited = decode_bgp_intent(_upload(with_timers.replace("timers 10 30", "timers 5 15")))
    assert plan_bgp_commands(edited, current=configured, verified=configured) == (
        {"op": "set", "path": [*path, "holdtime"], "value": "15"},
        {"op": "set", "path": [*path, "keepalive"], "value": "5"},
    )
    assert plan_bgp_commands(decode_bgp_intent(_upload(_DUAL_PEER)), current=configured, verified=configured) == (
        {"op": "delete", "path": path},
    )


def test_zero_bgp_hold_timer_supplies_both_stock_leaves_to_disable_keepalive():
    text = _FRR.replace(" address-family ipv4", " neighbor 192.0.2.2 timers 0 0\n address-family ipv4")
    resources = vyos_bgp_configuration(decode_bgp_intent(_upload(text)))
    assert resources[("protocols", "bgp")]["neighbor"]["192.0.2.2"]["timers"] == {"holdtime": "0", "keepalive": "1"}


@pytest.mark.parametrize("line", [
    "192.0.2.3 timers 10 30",
    "192.0.2.2 timers 0 30",
    "192.0.2.2 timers 1 2",
    "192.0.2.2 timers 10 65536",
    "192.0.2.2 timers connect 0",
    "192.0.2.2 timers 10 30\n neighbor 192.0.2.2 timers 5 15",
    "192.0.2.2 timers connect 5\n neighbor 192.0.2.2 timers connect 10",
])
def test_bgp_timers_reject_ambiguous_or_unrepresentable_settings(line):
    text = _FRR.replace(" address-family ipv4", f" neighbor {line}\n address-family ipv4")
    with pytest.raises(BgpIntentError):
        decode_bgp_intent(_upload(text))


@pytest.mark.parametrize(("old", "new"), [
    ("192.0.2.2 description", "192.0.2.3 description"),
    ("192.0.2.2 soft-reconfiguration", "192.0.2.3 soft-reconfiguration"),
    ("soft-reconfiguration inbound", "soft-reconfiguration outbound"),
    ("description Lab  edge (WAN)", "description Lab  edge (WAN)\n neighbor 192.0.2.2 description duplicate"),
])
def test_neighbor_options_cannot_silently_select_another_peer_or_direction(old, new):
    with pytest.raises(BgpIntentError):
        decode_bgp_intent(_upload(_BGP_WITH_OPTIONS.replace(old, new)))


@pytest.mark.parametrize(("old", "new"), [
    ("network 203.0.113.0 mask 255.255.255.0", "redistribute connected"),
    ("neighbor 192.0.2.2 activate", "neighbor 192.0.2.3 activate"),
    ("neighbor 192.0.2.2 route-map IMPORT-ROUTES in", ""),
    ("permit 198.51.100.0/25", "permit 198.51.100.0/25 le 32"),
    ("permit 198.51.100.0/25", "permit any"),
    ("permit 198.51.100.0/25", "permit 0.0.0.0/0"),
    ("permit 203.0.113.0/24", "permit 203.0.113.0/25"),
    ("remote-as 64521", "remote-as 64520"),
    ("remote-as 64521", "remote-as 64521\n neighbor 192.0.2.3 password private-router-secret"),
    ("remote-as 64521", "remote-as 64521\n neighbor 192.0.2.2 password private-router-secret invalid"),
    ("seq 10 permit", "seq 20 permit"),
    ("exit-address-family", "exit-address-family\n no bgp network import-check"),
])
def test_unsupported_or_ambiguous_uploads_are_rejected_without_echoing_text(old, new):
    with pytest.raises(BgpIntentError) as rejected:
        decode_bgp_intent(_upload(_FRR.replace(old, new)))
    assert "private-router-secret" not in str(rejected.value)


def test_disabled_upload_withdraws_only_through_an_explicit_boolean():
    assert decode_bgp_intent({"enabled": False, "config": ""}) is None
    assert vyos_bgp_configuration(None) == {}
    for incomplete in ({}, {"enabled": False}, {"enabled": 0, "config": ""}, {"enabled": True, "config": "!?"}):
        with pytest.raises(BgpIntentError):
            decode_bgp_intent(incomplete)


def test_bgp_plan_creates_edits_and_withdraws_only_owned_subtrees():
    intent = decode_bgp_intent(_upload(_FRR))
    desired = vyos_bgp_configuration(intent)
    created = plan_bgp_commands(intent, current={}, verified={})
    assert created == plan_bgp_commands(intent, current={}, verified={})
    assert all(command["op"] == "set" for command in created)
    assert {tuple(command["path"][:2]) for command in created} == {("protocols", "bgp"), ("policy", "prefix-list")}
    assert plan_bgp_commands(intent, current=desired, verified=desired) == ()

    updated = decode_bgp_intent(_upload(_FRR.replace("198.51.100.128/25", "198.51.101.0/24")))
    changes = plan_bgp_commands(updated, current=desired, verified=desired)
    assert changes and all(command["path"][:3] == ["policy", "prefix-list", "UNIFI-BGP4-IN"] for command in changes)
    assert plan_bgp_commands(None, current=desired, verified=desired) == tuple(
        {"op": "delete", "path": list(path)} for path in desired
    )


def test_bgp_plan_refuses_unowned_roots_and_incomplete_ownership():
    intent = decode_bgp_intent(_upload(_FRR))
    desired = vyos_bgp_configuration(intent)
    for path, tree in desired.items():
        foreign = {path: tree}
        with pytest.raises(BgpIntentError, match="ownership"):
            plan_bgp_commands(intent, current=foreign, verified={})
        with pytest.raises(BgpIntentError, match="ownership"):
            plan_bgp_commands(None, current=foreign, verified=foreign)
    changed = desired | {("protocols", "bgp"): {"system-as": "64599"}}
    with pytest.raises(BgpIntentError, match="ownership"):
        plan_bgp_commands(None, current=changed, verified=desired)


def test_bgp_password_rotation_and_removal_modify_only_the_password_leaf():
    plain = decode_bgp_intent(_upload(_FRR))
    peer, = plain.peers
    initial = replace(plain, peers=(replace(peer, password="first-test-key"),))
    rotated = replace(plain, peers=(replace(peer, password="second-test-key"),))
    proof_key = b"k" * 32
    baseline = redact_bgp_configuration(vyos_bgp_configuration(initial), proof_key)
    assert "first-test-key" not in repr(baseline)
    password_path = ["protocols", "bgp", "neighbor", "192.0.2.2", "password"]
    assert plan_bgp_commands(initial, current=baseline, verified=baseline, proof_key=proof_key) == ()
    assert plan_bgp_commands(rotated, current=baseline, verified=baseline, proof_key=proof_key) == (
        {"op": "set", "path": password_path, "value": "second-test-key"},
    )
    assert plan_bgp_commands(plain, current=baseline, verified=baseline, proof_key=proof_key) == (
        {"op": "delete", "path": password_path},
    )
    drift = redact_bgp_configuration(vyos_bgp_configuration(rotated), proof_key)
    with pytest.raises(BgpIntentError, match="ownership"):
        plan_bgp_commands(rotated, current=drift, verified=baseline, proof_key=proof_key)


def test_stock_readback_queries_only_the_bgp_process_and_reserved_prefix_lists():
    intent = decode_bgp_intent(_upload(_FRR))
    expected = vyos_bgp_configuration(intent)
    reserved_paths = list(expected)
    present = reserved_paths[1]
    backend = Mock()
    backend.read_config.side_effect = lambda path: expected[present] if tuple(path) == present else None

    current = read_bgp_configuration(backend)

    assert current == {present: expected[present]}
    ipv6_paths = [path for path in vyos_bgp_configuration(decode_bgp_intent(_upload(_FRR6)))
                  if path not in reserved_paths]
    assert backend.read_config.call_args_list == [call(list(path)) for path in reserved_paths + ipv6_paths]
    with pytest.raises(BgpIntentError, match="ownership"):
        plan_bgp_commands(intent, current=current, verified={})


def test_bgp_snapshot_separates_an_explicit_off_from_an_omitted_resource():
    version, resource = "routes/bgp/raw", _upload(_FRR)
    ordinary = {"udapi": {"versionDetail": {"interfaces": 8}, "interfaces": []}, "site_data": {"tag": "retained"}}
    before = json.dumps(ordinary)
    assert normalize_bgp_policy(before, revision="current") == (before, None)
    ordinary["udapi"]["versionDetail"][version] = 1
    normalized, omitted = normalize_bgp_policy(json.dumps(ordinary), revision="current")
    assert json.loads(normalized) == json.loads(before)
    assert omitted is None
    ordinary["udapi"][version] = resource
    normalized, desired = normalize_bgp_policy(json.dumps(ordinary), revision="current")
    assert json.loads(normalized) == json.loads(before)
    assert desired.revision == "current" and desired.policy == decode_bgp_intent(resource)

    ordinary["udapi"][version] = {"enabled": False, "config": ""}
    normalized, desired = normalize_bgp_policy(json.dumps(ordinary), revision="next")
    assert json.loads(normalized) == json.loads(before)
    assert desired.revision == "next" and desired.policy is None


@pytest.mark.parametrize("bad", ["missing_version", "unsupported_version", "boolean_version", "empty_unknown_version", "duplicate"])
def test_bgp_normalization_never_strips_an_unverified_block(bad):
    key = "routes/bgp/raw"
    version = True if bad == "boolean_version" else 2 if bad in ("unsupported_version", "empty_unknown_version") else 1
    versions = {} if bad == "missing_version" else {key: version}
    block = "" if bad == "empty_unknown_version" else f', "{key}": {{"enabled": false, "config": ""}}'
    if bad == "duplicate":
        block += block
    with pytest.raises(BgpIntentError):
        normalize_bgp_policy(f'{{"udapi":{{"versionDetail":{json.dumps(versions)}{block}}}}}', revision="current")


def test_bgp_commit_recovery_checks_saved_state_before_acknowledging(tmp_path):
    from backends.vyos import VyOSWriteError

    desired = decode_bgp_intent(_upload(_FRR))
    scope = BgpScope(frozenset({IPv4Address("192.0.2.2")}), frozenset(desired.imports), frozenset(desired.exports))
    previous = {("firewall", "ipv4", "forward", "filter"): {"default-action": "accept"}}
    running = previous.copy()
    backend = Mock()
    backend.read_config.side_effect = lambda path: running.get(tuple(path))
    backend.show_interfaces.return_value = {}
    backend.stage_configuration.side_effect = lambda *args, **kwargs: running.update(vyos_bgp_configuration(desired))
    backend.save_configuration.side_effect = [VyOSWriteError("Save reply lost"), None]
    proof = Mock(return_value="a" * 64)
    options = dict(interfaces={IPv4Network("192.0.2.0/24"): "eth3", IPv4Network("203.0.113.0/24"): "eth4"},
                   state_path=tmp_path / "router.json", rule_base=80200, bgp_scope=scope, commit_proof=proof)
    router = VyOSReconciler(backend, **options)

    result = router.reconcile(FirewallIntent("bgp-1", ()), bgp_intent=BgpProvisioningIntent("bgp-1", desired))
    assert result.error == "Save reply lost" and result.verified_revision is None
    journal = json.loads(options["state_path"].read_text())
    assert journal["pending"]["confirmed"] is True and set(journal["pending"]["bgp"]) == {"process", "import", "export"}

    restarted = VyOSReconciler(backend, **options)
    damaged = journal | {"pending": {key: value for key, value in journal["pending"].items()
                                     if key != "confirmation_sha256"}}
    options["state_path"].write_text(json.dumps(damaged))
    result = restarted.reconcile(FirewallIntent("bgp-1", ()), bgp_intent=BgpProvisioningIntent("bgp-1", desired))
    assert "proof" in result.error and result.verified_revision is None
    backend.save_configuration.assert_called_once()

    options["state_path"].write_text(json.dumps(journal))
    result = restarted.reconcile(FirewallIntent("bgp-1", ()), bgp_intent=BgpProvisioningIntent("bgp-1", desired))
    assert result.error is None and result.verified_revision == "bgp-1"
    backend.stage_configuration.assert_called_once()
    backend.confirm_configuration.assert_called_once()
    assert proof.call_args == call(phase="saved")
    journal = json.loads(options["state_path"].read_text())
    assert journal["pending"] is None and len(journal["verified_bgp"]) == 3

    result = restarted.reconcile(FirewallIntent("omitted", ()))
    assert result.error and result.verified_revision == "bgp-1"
    unapproved = decode_bgp_intent(_upload(_FRR.replace("198.51.100.128/25", "198.51.101.0/24")))
    result = restarted.reconcile(FirewallIntent("widened", ()), bgp_intent=BgpProvisioningIntent("widened", unapproved))
    assert "exceeds the approved" in result.error and result.verified_revision == "bgp-1"
    backend.stage_configuration.assert_called_once()

    backend.save_configuration.side_effect = None
    backend.show_ipv4_routes.return_value = {}
    backend.stage_configuration.side_effect = lambda *args, **kwargs: running.clear() or running.update(previous)
    result = restarted.reconcile(FirewallIntent("off", ()), bgp_intent=BgpProvisioningIntent("off", None))
    assert result.error is None and result.changed and result.verified_revision == "off"
    assert json.loads(options["state_path"].read_text())["verified_bgp"] == {}
    assert backend.stage_configuration.call_args.args[0] == [
        {"op": "delete", "path": list(path)} for path in vyos_bgp_configuration(desired)
    ]


def test_packaged_enterprise_decoder_preserves_baseline_and_requires_authenticated_inform(tmp_path):
    config = RawConfigParser()
    config.read_dict({"global": {"pid_file": str(tmp_path / "gateway.pid")},
                      "gateway": {"device": "UXGENT", "platform": "vyos", "is_adopted": True, "use_aes_gcm": True},
                      "vyos_bgp": {"enabled": True}})
    gateway = UnifiGateway(_observer_config=config)
    desired = decode_bgp_intent(_upload(_FRR))
    gateway.vyos_provisioner = VyOSReconciler(
        Mock(), interfaces={IPv4Network("192.0.2.0/24"): "eth3", IPv4Network("203.0.113.0/24"): "eth4"},
        state_path=tmp_path / "router.json", rule_base=80200, commit_proof=Mock(),
        bgp_scope=BgpScope(frozenset(peer.address for peer in desired.peers), frozenset(desired.imports), frozenset(desired.exports)),
    )
    fixture = json.loads((Path(__file__).parent / "fixtures/uxg_pro/zbf-native-snapshots.json").read_text())
    document = json.loads(fixture["snapshots"]["baseline"]["system_cfg"])
    _, _, _, baseline = gateway._decode_vyos_policy(json.dumps(document), "ordinary")
    document["udapi"]["versionDetail"]["routes/bgp/raw"] = 1
    document["udapi"]["routes/bgp/raw"] = _upload(_FRR)

    _, options, _, observed = gateway._decode_vyos_policy(json.dumps(document), "new")
    assert observed == baseline
    assert options["bgp_intent"] == BgpProvisioningIntent("new", desired)
    config.set("gateway", "use_aes_gcm", "False")
    with pytest.raises(ValueError, match="authenticated"):
        gateway._decode_vyos_policy(json.dumps(document), "new")


@pytest.mark.parametrize("peer_auth", [False, True])
@pytest.mark.parametrize(("frr", "peer"), [(_FRR, "192.0.2.2"), (_FRR6, "2001:db8:10::50")])
def test_advertised_bgp_upload_uses_authenticated_inform_and_reports_saved_revision(tmp_path, monkeypatch, peer_auth, frr, peer):
    config = RawConfigParser()
    config.read_dict({
        "global": {"pid_file": str(tmp_path / "gateway.pid")},
        "gateway": {"device": "UXGENT", "platform": "vyos", "is_adopted": True, "use_aes_gcm": True,
                    "url": "http://controller.test:8080/inform", "lan_ip": "192.0.2.1", "ports": "[]",
                    "lan_mac": "02:00:00:00:00:03", "key": "a" * 32},
        "vyos_firewall": {"enabled": True}, "vyos_restart": {"recover_provisioning": True},
        "vyos_bgp": {"enabled": True, "advertise": True},
    })
    state_path = tmp_path / "gateway.conf"
    monkeypatch.setitem(UnifiGateway._save_config.__globals__, "CONFIG_FILE", str(state_path))
    gateway = UnifiGateway(_observer_config=config)
    password = "test-peer-only-key"
    if peer_auth:
        frr = frr.replace("remote-as 64521", f"remote-as 64521\n neighbor {peer} password {password}")
    desired = decode_bgp_intent(_upload(frr))
    assert password not in repr(desired)
    running = {("firewall", "ipv4", "forward", "filter"): {"default-action": "accept"}}
    backend = Mock()
    backend.read_config.side_effect = lambda path: running.get(tuple(path))
    backend.show_interfaces.return_value = {}
    backend.stage_configuration.side_effect = lambda *args, **kwargs: running.update(vyos_bgp_configuration(desired))
    gateway.datacollector = SimpleNamespace(data={}, backend=backend)
    gateway.vyos_provisioner = VyOSReconciler(
        backend, interfaces={IPv4Network("192.0.2.0/24"): "eth3", IPv4Network("203.0.113.0/24"): "eth4"},
        state_path=tmp_path / "router.json", rule_base=80200, commit_proof=Mock(return_value="a" * 64),
        bgp_scope=BgpScope(frozenset(peer.address for peer in desired.peers), frozenset(desired.imports), frozenset(desired.exports)),
    )
    fixture = json.loads((Path(__file__).parent / "fixtures/uxg_pro/zbf-native-snapshots.json").read_text())
    document = json.loads(fixture["snapshots"]["baseline"]["system_cfg"])
    _, _, _, baseline = gateway._decode_vyos_policy(json.dumps(document), "ordinary")
    config.set("vyos_firewall", "unmanaged_baseline_sha256", baseline)
    upload = _upload(frr)
    document["udapi"]["routes/bgp/raw"] = upload
    document["udapi"]["versionDetail"]["routes/bgp/raw"] = 1
    provision = {"_type": "setparam", "cfgversion": "bgp-1", "system_cfg": json.dumps(document), "interval": 10}
    replies = iter(encode_inform(config, json.dumps(reply)) for reply in (provision, {"_type": "noop"}))
    observed = []

    def exchange(request, *, timeout):
        observed.append(decode_inform(config, request.data, require_gcm=True))
        return SimpleNamespace(read=lambda: next(replies))

    monkeypatch.setattr("unifi_gateway.urllib.request.urlopen", exchange)
    gateway._exchange_inform()
    gateway._exchange_inform()
    assert observed[0]["udapi_caps"] & 0x00400000
    assert observed[0]["cfgversion"] != "bgp-1" and observed[1]["cfgversion"] == "bgp-1"
    backend.stage_configuration.assert_called_once()
    backend.confirm_configuration.assert_called_once()
    backend.save_configuration.assert_called_once()
    assert upload["config"] not in state_path.read_text()
    assert json.loads(config["provisioned"]["system_cfg"])["udapi"]["routes/bgp/raw"] == {"enabled": True}
    if peer_auth:
        assert {"op": "set", "path": ["protocols", "bgp", "neighbor", peer, "password"], "value": password} in (
            backend.stage_configuration.call_args.args[0]
        )
        journal_path = tmp_path / "router.json"
        journal = journal_path.read_text()
        assert password not in journal and password not in state_path.read_text()
        proof_key = tmp_path / "router.json.bgp-proof-key"
        assert proof_key.stat().st_mode & 0o777 == 0o600
        proof_key.unlink()
        result = gateway.vyos_provisioner.reconcile(FirewallIntent("bgp-2", ()), bgp_intent=BgpProvisioningIntent("bgp-2", desired))
        assert "BGP credential proof key" in result.error and result.verified_revision == "bgp-1"
        backend.stage_configuration.assert_called_once()
