"""Exercise the one-peer native WireGuard shape and redacted VyOS ownership."""

from base64 import b64encode
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import pytest

from provisioners.vyos_wireguard import (
    WireGuardIntentError,
    WireGuardScope,
    decode_wireguard_intent,
    plan_wireguard_commands,
    redact_wireguard_interface,
)


WIREGUARD = "vpn/wireguard/servers"
WG_PATH = ["interfaces", "wireguard", "wg91"]
PEER_PATH = WG_PATH + ["peer", "unifi-peer"]
TUNNEL_CIDR = "172.29.91.1/24"
PEER_CIDR = "172.29.91.2/32"
WAN_CIDR = "198.18.210.1/30"
SYNTHETIC_BYTES = [bytes(range(i, i + 32)) for i in (1, 33, 65, 97)]
PRIVATE, PUBLIC, PSK, ROTATED_PUBLIC = [b64encode(key).decode("ascii") for key in SYNTHETIC_BYTES]
PRIVATE_DIGEST, PUBLIC_DIGEST, PSK_DIGEST, ROTATED_PUBLIC_DIGEST = [
    "sha256:" + sha256(key).hexdigest() for key in SYNTHETIC_BYTES
]


@pytest.fixture
def native():
    path = Path(__file__).parent / "fixtures" / "uxg_pro" / "native-wireguard-server.json"
    snapshot = json.loads(path.read_text())
    server = _server(snapshot)
    server["privateKey"] = PRIVATE
    server["remotePeers"][0]["publicKey"] = PUBLIC
    return snapshot


@pytest.fixture
def scope():
    return WireGuardScope(
        wan_id="eth0", wan_interface="eth3.210", wan_cidr=WAN_CIDR, interface="wg91",
        ports=(51820, 51821), tunnel_cidr=TUNNEL_CIDR, peer_cidr=PEER_CIDR, server_id="1",
    )


@pytest.fixture
def live():
    flags = ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"]
    return {
        "eth3.210": (flags, f"    inet {WAN_CIDR} scope global\n"),
        "eth3.220": (flags, "    inet 198.18.220.1/30 scope global\n"),
        "eth3.110": (flags, "    inet 192.168.110.1/24 scope global\n"),
    }


@pytest.fixture
def raw_interface():
    return {
        "address": TUNNEL_CIDR, "port": "51820", "private-key": PRIVATE,
        "peer": {"unifi-peer": {"allowed-ips": PEER_CIDR, "public-key": PUBLIC}},
    }


@pytest.fixture
def verified():
    return {
        "address": TUNNEL_CIDR, "port": "51820", "private-key": PRIVATE_DIGEST,
        "peer": {"unifi-peer": {"allowed-ips": PEER_CIDR, "public-key": PUBLIC_DIGEST}},
    }


def _server(document):
    return document["udapi"][WIREGUARD][0]


def _decode(document, scope):
    return decode_wireguard_intent(
        json.dumps(document), revision="native-revision", scope=scope, dns_forwarder=True, nat=True,
    )


def _plan(document, scope, live, *, current=None, verified=None):
    return plan_wireguard_commands(
        _decode(document, scope), scope=scope, current_interfaces={} if current is None else current,
        verified_interface=verified, live_interfaces=live,
    )


def test_native_create_plans_interface_with_redacted_journal(native, scope, live, verified):
    intent = _decode(native, scope)
    plan = _plan(native, scope, live)

    assert intent.revision == "native-revision"
    assert intent.server.port == 51820
    assert plan.desired_interface == verified
    assert plan.commands == (
        {"op": "set", "path": WG_PATH + ["address"], "value": TUNNEL_CIDR},
        {"op": "set", "path": WG_PATH + ["port"], "value": "51820"},
        {"op": "set", "path": WG_PATH + ["private-key"], "value": PRIVATE},
        {"op": "set", "path": PEER_PATH + ["allowed-ips"], "value": PEER_CIDR},
        {"op": "set", "path": PEER_PATH + ["public-key"], "value": PUBLIC},
    )
    assert all(key not in repr(obj) for obj in (intent, intent.server, plan) for key in (PRIVATE, PUBLIC))
    assert PRIVATE not in json.dumps(plan.desired_interface)
    assert PUBLIC not in json.dumps(plan.desired_interface)


def test_native_port_edit_keeps_both_keys_and_the_peer(native, scope, live, raw_interface, verified):
    _server(native)["port"] = 51821
    plan = _plan(native, scope, live, current={"wg91": raw_interface}, verified=verified)

    assert plan.desired_interface == {**verified, "port": "51821"}
    assert plan.commands == ({"op": "set", "path": WG_PATH + ["port"], "value": "51821"},)


def test_peer_key_and_psk_changes_touch_only_changed_leaves(native, scope, live, raw_interface, verified):
    peer = _server(native)["remotePeers"][0]
    peer.update(publicKey=ROTATED_PUBLIC, preSharedKey=PSK)
    plan = _plan(native, scope, live, current={"wg91": raw_interface}, verified=verified)

    assert plan.commands == (
        {"op": "set", "path": PEER_PATH + ["public-key"], "value": ROTATED_PUBLIC},
        {"op": "set", "path": PEER_PATH + ["preshared-key"], "value": PSK},
    )
    assert plan.desired_interface["peer"]["unifi-peer"] == {
        "allowed-ips": PEER_CIDR, "public-key": ROTATED_PUBLIC_DIGEST, "preshared-key": PSK_DIGEST,
    }
    assert all(key not in repr(plan) for key in (PRIVATE, PUBLIC, PSK, ROTATED_PUBLIC))


def test_native_psk_removal_is_a_leaf_delete(native, scope, live, raw_interface):
    raw_interface["peer"]["unifi-peer"]["preshared-key"] = PSK
    known = redact_wireguard_interface(raw_interface, scope=scope)
    plan = _plan(native, scope, live, current={"wg91": raw_interface}, verified=known)

    assert plan.commands == ({"op": "delete", "path": PEER_PATH + ["preshared-key"]},)
    assert known["peer"]["unifi-peer"]["preshared-key"] == PSK_DIGEST
    assert PSK not in repr(_decode(native, scope))


def test_native_absence_can_remove_only_a_verified_interface(native, scope, raw_interface, verified):
    del native["udapi"][WIREGUARD]
    plan = _plan(native, scope, {}, current={"wg91": raw_interface, "wg88": {"port": "2190"}}, verified=verified)

    assert plan.desired_interface is None
    assert plan.commands == ({"op": "delete", "path": WG_PATH},)


def test_same_redacted_readback_is_no_op(native, scope, live, raw_interface, verified):
    assert redact_wireguard_interface(raw_interface, scope=scope) == verified
    assert _plan(native, scope, live, current={"wg91": raw_interface}, verified=verified).commands == ()


@pytest.mark.parametrize("patch", [
    {"id": "2"}, {"id": 1}, {"enabled": False}, {"enabled": 1},
    {"port": 51822}, {"port": "51820"}, {"name": " "}, {"tunnelMTU": 1420},
    {"interfaceIPs": ["172.29.91.1/25"]}, {"interfaceIPs": [TUNNEL_CIDR, "fd00::1/64"]},
    {"address": {"source": "any"}}, {"address": {"source": "interface", "id": "eth2", "ipVersion": "v4"}},
    {"address": {"source": "interface", "id": "eth0", "ipVersion": "v6"}},
    {"address": {"source": "static", "address": "198.18.210.1"}},
])
def test_rejects_unpinned_server_fields(native, scope, patch):
    _server(native).update(patch)
    with pytest.raises(WireGuardIntentError):
        _decode(native, scope)


@pytest.mark.parametrize("patch", [
    {"allowedIPs": ["0.0.0.0/0"]}, {"allowedIPs": ["172.29.91.3/32"]}, {"allowedIPs": [PEER_CIDR, PEER_CIDR]},
    {"address": "198.18.210.2"}, {"port": 51820}, {"persistentKeepAlive": 25}, {"name": "\ninvalid"},
])
def test_rejects_additional_peer_routes_or_endpoint(native, scope, patch):
    _server(native)["remotePeers"][0].update(patch)
    with pytest.raises(WireGuardIntentError):
        _decode(native, scope)


@pytest.mark.parametrize("site_field", [None, [], [{}, {}]])
def test_present_invalid_server_section_is_never_removal(native, scope, site_field):
    native["udapi"][WIREGUARD] = site_field
    with pytest.raises(WireGuardIntentError):
        _decode(native, scope)


def test_additional_peer_is_rejected(native, scope):
    peers = _server(native)["remotePeers"]
    peers.append(dict(peers[0], publicKey=ROTATED_PUBLIC))
    with pytest.raises(WireGuardIntentError):
        _decode(native, scope)


@pytest.mark.parametrize("kind", ["privateKey", "publicKey", "preSharedKey"])
@pytest.mark.parametrize("value", ["secret-like-invalid-value", "AA==", "A" * 43 + "=", PUBLIC + "\n"])
def test_invalid_key_diagnostic_discards_value(native, scope, kind, value):
    server = _server(native)
    target = server if kind == "privateKey" else server["remotePeers"][0]
    target[kind] = value
    with pytest.raises(WireGuardIntentError) as error:
        _decode(native, scope)

    assert value.strip() not in str(error.value)
    assert value.strip() not in repr(error.value)


@pytest.mark.parametrize("modify", [
    lambda interfaces: interfaces.pop(0),
    lambda interfaces: interfaces.append(deepcopy(interfaces[0])),
    lambda interfaces: interfaces[0]["addresses"][0].update(cidr="198.18.210.2/30"),
    lambda interfaces: interfaces[0]["addresses"][0].update(type="dhcp"),
])
def test_static_controller_wan_address_is_required(native, scope, modify):
    modify(native["udapi"]["interfaces"])
    with pytest.raises(WireGuardIntentError, match="WAN"):
        _decode(native, scope)


@pytest.mark.parametrize("wan", [
    None, (["UP"], f"    inet {WAN_CIDR} scope global\n"),
    (["UP", "LOWER_UP"], "    inet 198.18.210.2/30 scope global\n"),
    (["UP", "LOWER_UP"], "    inet 198.18.210.1/24 scope global\n"),
])
def test_current_vyos_wan_must_have_exact_active_cidr(native, scope, live, wan):
    if wan is None:
        del live["eth3.210"]
    else:
        live["eth3.210"] = wan
    with pytest.raises(WireGuardIntentError, match="WAN"):
        _plan(native, scope, live)


def test_live_tunnel_prefix_overlap_is_rejected(native, scope, live):
    live["eth9"] = (["UP", "LOWER_UP"], "    inet 172.29.91.100/25 scope global\n")
    with pytest.raises(WireGuardIntentError, match="overlap"):
        _plan(native, scope, live)


def test_foreign_runtime_interface_is_not_claimed(native, scope, live):
    live["wg91"] = (["UP", "LOWER_UP"], "")
    with pytest.raises(WireGuardIntentError, match="ownership"):
        _plan(native, scope, live)


def test_existing_config_with_no_verified_owner_is_rejected(native, scope, live, raw_interface):
    with pytest.raises(WireGuardIntentError, match="ownership"):
        _plan(native, scope, live, current={"wg91": raw_interface})


def test_port_collision_with_other_interface_is_rejected(native, scope, live):
    with pytest.raises(WireGuardIntentError, match="port"):
        _plan(native, scope, live, current={"wg88": {"port": "51820"}})


@pytest.mark.parametrize("readback", [{"port": ["51820"]}, {"port": 51820}, []])
def test_malformed_operator_wireguard_state_does_not_prove_free_port(native, scope, live, readback):
    with pytest.raises(WireGuardIntentError, match="port"):
        _plan(native, scope, live, current={"wg88": readback})


def test_malformed_owned_readback_is_rejected_as_ownership_error(scope, raw_interface):
    raw_interface["port"] = ["51820"]

    with pytest.raises(WireGuardIntentError, match="ownership"):
        redact_wireguard_interface(raw_interface, scope=scope)


@pytest.mark.parametrize("readback", [(["UP", "LOWER_UP"],), (None, ""), (["UP", "LOWER_UP"], None)])
def test_invalid_live_wan_snapshot_is_rejected(scope, native, live, readback):
    live["eth3.210"] = readback

    with pytest.raises(WireGuardIntentError, match="interface read-back"):
        _plan(native, scope, live)


def test_verified_tree_with_raw_key_is_rejected(native, scope, live, raw_interface):
    with pytest.raises(WireGuardIntentError, match="ownership"):
        _plan(native, scope, live, current={"wg91": raw_interface}, verified=raw_interface)


def test_current_key_rotation_without_matching_controller_journal_is_rejected(native, scope, live, raw_interface, verified):
    raw_interface["peer"]["unifi-peer"]["public-key"] = ROTATED_PUBLIC
    with pytest.raises(WireGuardIntentError, match="ownership"):
        _plan(native, scope, live, current={"wg91": raw_interface}, verified=verified)


def test_current_unowned_settings_prevent_deletion(native, scope, live, raw_interface, verified):
    raw_interface["peer"]["unifi-peer"]["persistent-keepalive"] = "25"
    del native["udapi"][WIREGUARD]

    with pytest.raises(WireGuardIntentError, match="ownership"):
        _plan(native, scope, live, current={"wg91": raw_interface}, verified=verified)


@pytest.mark.parametrize("pin, wire, accepted", [(False, None, True), (True, 3, True), (True, None, False), (False, 3, False)])
def test_optional_broker_pin_is_explicit(native, scope, pin, wire, accepted):
    versions = native["udapi"]["versionDetail"]
    if wire is not None:
        versions["services/messageBroker"] = wire

    def decode():
        return decode_wireguard_intent(
            json.dumps(native), revision="native-revision", scope=scope, dns_forwarder=True, nat=True,
            message_broker=pin,
        )

    if accepted:
        assert decode().server.port == 51820
    else:
        with pytest.raises(WireGuardIntentError, match="schema"):
            decode()


@pytest.mark.parametrize("wire_revision", [True, 5, 7])
def test_wireguard_revision_must_be_exact(native, scope, wire_revision):
    native["udapi"]["versionDetail"][WIREGUARD] = wire_revision
    with pytest.raises(WireGuardIntentError, match="schema"):
        _decode(native, scope)
