"""Check only the captured native WireGuard companion policy is masked."""

from base64 import b64encode
from copy import deepcopy
import json
from pathlib import Path

import pytest

from provisioners.vyos_wireguard import WireGuardIntentError, WireGuardScope, decode_wireguard_intent
from provisioners.uxg_wireguard_policy import scrub_wireguard_policy


_FIXTURES = Path(__file__).parent / "fixtures" / "uxg_pro"
_WG = "vpn/wireguard/servers"
_FILTER = "firewall/filter"
_SETS = "firewall/sets"


@pytest.fixture
def scope():
    return WireGuardScope(
        wan_id="eth0", wan_interface="eth3.210", wan_cidr="198.18.210.1/30", interface="wg91",
        ports=(51820, 51821), tunnel_cidr="172.29.91.1/24", peer_cidr="172.29.91.2/32",
    )


@pytest.fixture
def native():
    common = json.loads((_FIXTURES / "native-wireguard-server.json").read_text())["udapi"]
    server = common.pop(_WG)[0]
    server["privateKey"] = b64encode(bytes(range(1, 33))).decode()
    server["remotePeers"][0]["publicKey"] = b64encode(bytes(range(33, 65))).decode()
    snapshots = json.loads((_FIXTURES / "native-wireguard-policy-snapshots.json").read_text())
    common["other"] = {"untouched-order": ["third", "second", "first"]}
    baseline = deepcopy(common | snapshots["baseline"])
    create = deepcopy(common | snapshots["create"] | {_WG: [server]})
    edit = deepcopy(create)
    edit[_WG][0]["port"] = 51821
    edit[_SETS][-1] = snapshots["edited_port_set"]
    return {"baseline": baseline, "create": create, "edit": edit, "delete": deepcopy(baseline)}


def _intent(udapi, scope):
    return decode_wireguard_intent(
        json.dumps({"udapi": udapi}), revision="capture", scope=scope, dns_forwarder=True, nat=True,
    )


def _scrub(udapi, scope):
    return scrub_wireguard_policy(udapi, _intent(udapi, scope))


def _rules(udapi, chain):
    return next(row["rules"] for row in udapi[_FILTER] if row["config"]["name"] == chain)


def _set(udapi, name):
    return next(row for row in udapi[_SETS] if row["identification"]["name"] == name)


@pytest.mark.parametrize("stage", ["baseline", "create", "edit", "delete"])
def test_only_native_wireguard_artifacts_are_removed(native, scope, stage):
    source = native[stage]
    before = deepcopy(source)
    normalized = _scrub(source, scope)
    assert normalized == native["baseline"]
    assert source == before
    assert _WG in normalized["versionDetail"]

    normalized["other"]["untouched-order"].reverse()
    assert source == before


def test_mutations_to_outside_fields_and_relative_order_survive_scrub(native, scope):
    payload = native["create"]
    _rules(payload, "OUTPUT")[0]["log"] = True
    _rules(payload, "LAN_LAN")[0]["example-outside-extension"] = "exactly retained"
    payload["other"]["untouched-order"].reverse()
    payload[_FILTER][0], payload[_FILTER][1] = payload[_FILTER][1], payload[_FILTER][0]
    payload[_SETS][0], payload[_SETS][1] = payload[_SETS][1], payload[_SETS][0]

    expected = native["baseline"]
    _rules(expected, "OUTPUT")[0]["log"] = True
    _rules(expected, "LAN_LAN")[0]["example-outside-extension"] = "exactly retained"
    expected["other"]["untouched-order"].reverse()
    expected[_FILTER][0], expected[_FILTER][1] = expected[_FILTER][1], expected[_FILTER][0]
    expected[_SETS][0], expected[_SETS][1] = expected[_SETS][1], expected[_SETS][0]
    assert _scrub(payload, scope) == expected


@pytest.mark.parametrize("chain", ["INPUT", "OUTPUT", "FORWARD_IN"])
@pytest.mark.parametrize("mutation", [
    lambda rows: rows.pop(4),
    lambda rows: rows[4].update(target="ACCEPT"),
    lambda rows: rows[4].update(negateInInterface=0),
    lambda rows: rows[4].update(originId="x"),
    lambda rows: rows[4].update(state=["new"]),
    lambda rows: rows.insert(4, rows.pop(3)),
    lambda rows: rows.append(deepcopy(rows[4])),
])
def test_tunnel_jump_requires_exact_rule_at_its_slot(native, scope, chain, mutation):
    source = native["create"]
    mutation(_rules(source, chain))
    with pytest.raises(WireGuardIntentError):
        _scrub(source, scope)


@pytest.mark.parametrize("mutation", [
    lambda rows: rows[2].update(protocol="tcp"),
    lambda rows: rows[2].update(destination={"port": "51820"}),
    lambda rows: rows[3].update(id=30002),
    lambda rows: rows[3].update(icmpv6Type="echo-request"),
    lambda rows: rows[4].update(log=True),
    lambda rows: rows.insert(3, rows.pop(4)),
])
def test_wan_udp_allow_and_neighbor_shift_must_be_exact(native, scope, mutation):
    source = native["create"]
    mutation(_rules(source, "WAN_LOCAL"))
    with pytest.raises(WireGuardIntentError):
        _scrub(source, scope)


@pytest.mark.parametrize("mutation", [
    lambda rows: rows.pop(),
    lambda rows: rows[-1].update(entries=["51821"]),
    lambda rows: rows[-1].update(entries=["51820", "51821"]),
    lambda rows: rows[-1].update(description="Custom rule"),
    lambda rows: rows.insert(0, rows.pop()),
])
def test_generated_port_set_matches_only_this_server(native, scope, mutation):
    source = native["create"]
    mutation(source[_SETS])
    with pytest.raises(WireGuardIntentError):
        _scrub(source, scope)


@pytest.mark.parametrize("name", ["VPN_subnets", "remote_user_vpn_network"])
@pytest.mark.parametrize("entries", [None, [], ["172.29.91.1/24"], ["172.29.91.0/24", "192.0.2.0/24"]])
def test_shared_sets_cannot_hide_extra_entries(native, scope, name, entries):
    source = native["create"]
    _set(source, name)["entries"] = entries
    with pytest.raises(WireGuardIntentError):
        _scrub(source, scope)


@pytest.mark.parametrize("stage", ["baseline", "create"])
@pytest.mark.parametrize("reference", [
    "wgsrv+", "wgsrv1", "wireguard_ports", "VPN_subnets", "remote_user_vpn_network",
    "172.29.91.0/24", "172.29.91.2/32", "172.29.91.1",
])
def test_remaining_outside_references_to_wireguard_scope_are_rejected(native, scope, stage, reference):
    source = native[stage]
    source["other"]["extra"] = [{"selector": reference}]
    with pytest.raises(WireGuardIntentError, match="reference"):
        _scrub(source, scope)


def test_recorded_native_zone_references_remain_in_pre_wireguard_policy(native, scope):
    normalized = _scrub(native["create"], scope)
    for zone in ("WAN", "LAN", "GUEST", "VPN", "DMZ"):
        assert _rules(normalized, zone + "_IN")[3]["destination"] == {"sets": ["VPN_subnets"]}


def test_tunnel_origin_cannot_be_referenced_after_removal(native, scope):
    source = native["create"]
    source["other"]["rule-origin"] = _rules(source, "INPUT")[4]["originId"]
    with pytest.raises(WireGuardIntentError, match="reference"):
        _scrub(source, scope)


def test_cannot_use_an_intent_from_a_different_wire_snapshot(native, scope):
    source, different = native["create"], native["edit"]
    with pytest.raises(WireGuardIntentError, match="intent"):
        scrub_wireguard_policy(source, _intent(different, scope))


def test_missing_server_cannot_still_own_generated_artifacts(native, scope):
    source = native["create"]
    del source[_WG]
    with pytest.raises(WireGuardIntentError):
        _scrub(source, scope)
