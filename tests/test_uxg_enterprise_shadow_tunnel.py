"""Correlate the two COMPLETE snapshots using their public tunnel certificates."""

from base64 import b64encode
from hashlib import sha256
import json
from ssl import PEM_cert_to_DER_cert

import pytest


# Self-signed leaf and CA test certificates. Private keys were discarded.
PRIMARY_PEM = """-----BEGIN CERTIFICATE-----
MIIBjTCCATSgAwIBAgIUcVq7LNaORquWP+NTPvz48nQuUi4wCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTVGVzdC1TaGFkb3ctUHJpbWFyeTAeFw0yNjExMjUyMzAyMTZa
Fw0zNjExMjIyMzAyMTZaMB4xHDAaBgNVBAMME1Rlc3QtU2hhZG93LVByaW1hcnkw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARaecnp9vsKQ6++AXOaAEjkfjbHlo4Z
Hw6KibZfumSOQiL+Ju9bncIwMJp8fQq4ZP7IkvMw1ZLVl9+vSQFds6Nto1AwTjAd
BgNVHQ4EFgQUp0P20F/7IyeuDBRtVh5a1LhAFf8wHwYDVR0jBBgwFoAUp0P20F/7
IyeuDBRtVh5a1LhAFf8wDAYDVR0TAQH/BAIwADAKBggqhkjOPQQDAgNHADBEAiAL
k1tHU54L/j8+AjdjAAlq8n4fafZwApzn+/NUZ1G97gIgekUwLosU7k4nREP+z9cX
jjdmiLN7RszM/VZNjgY1Tsg=
-----END CERTIFICATE-----
"""
STANDBY_PEM = """-----BEGIN CERTIFICATE-----
MIIBkDCCATegAwIBAgIUOrM/KoFwZ0s83r2oCFp5WIS6iggwCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTVGVzdC1TaGFkb3ctU3RhbmRieTAeFw0yNjExMjUyMjU4NDVa
Fw0zNjExMjIyMjU4NDVaMB4xHDAaBgNVBAMME1Rlc3QtU2hhZG93LVN0YW5kYnkw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATZ6nI9NRYUqT18mp3gXR/LDhZxpBJx
+73ShE77nBsYxuJ80d58Ngine0xlTtrsu9kITqOASh9Ofh5hacGvtcf5o1MwUTAd
BgNVHQ4EFgQUotJZthA5FBQros/LDZ2dG99eLqMwHwYDVR0jBBgwFoAUotJZthA5
FBQros/LDZ2dG99eLqMwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBE
AiB+ppWRXHI071eY5prda3NNEYZJQQY8x4y6QCX+DIuV8gIgBcRcWacXhvq3yDYs
kZpfbo+ApxJGw1e6ggbx47r15Uk=
-----END CERTIFICATE-----
"""
PRIMARY_IP = "169.254.254.2"
STANDBY_IP = "169.254.254.3"


def _wire_cert(pem):
    return b64encode(pem.encode("ascii")).decode("ascii")


def _system_cfg(*, standby=False):
    source, peer = (STANDBY_IP, PRIMARY_IP) if standby else (PRIMARY_IP, STANDBY_IP)
    local_pem, peer_pem = (STANDBY_PEM, PRIMARY_PEM) if standby else (PRIMARY_PEM, STANDBY_PEM)
    # Deliberately unequal and non-PEM: the decoder must never inspect a key value.
    local_client = {"crt": _wire_cert(local_pem), "key": "opaque private client value"}
    local_server = {"crt": _wire_cert(local_pem.replace("\n", "\r\n")), "key": "opaque private server value"}
    peer_cert = {"crt": _wire_cert(peer_pem)}
    instance = {
        "interface": "eth1", "vrid": 42, "priority": 100 if standby else 255, "advertisementInterval": 1,
        "useVmac": False, "unicastAdvertise": {"sourceIP": source, "peerIP": peer},
        "virtualIPs": [{"interface": "br0", "address": "192.0.2.1/24"}],
    }
    if standby:
        instance["masterGuard"] = {"peerLan": {"interface": "br0", "address": "fe80::2"}}
    return {"udapi": {
        "versionDetail": {"services/stunnel": 1, "services/vrrp": 5},
        "services": {
            "vrrp": {"enabled": True, "instances": [instance]},
            "stunnel": {"enabled": True, "clients": [{
                "id": "uuspeersock", "server": peer, "serverPort": 31000,
                "localSocket": "/var/run/ubnt-udapi-server-peer.sock",
                "clientCert": local_client, "serverCert": peer_cert,
            }], "servers": [{
                "id": "uuslocalsock", "listenPort": 31000, "localSocket": "/var/run/ubnt-udapi-server.sock",
                "serverCert": local_server, "clientCert": peer_cert.copy(),
            }]},
        },
    }}


def _setparam(data, revision):
    return {"_type": "setparam", "cfgversion": revision, "system_cfg": json.dumps(data)}


def test_complete_pair_checks_both_heads_and_returns_only_public_role_evidence():
    from provisioners.uxg_enterprise_shadow_tunnel import verify_shadow_complete_pair

    primary, standby = verify_shadow_complete_pair(
        _setparam(_system_cfg(), "revision-a"), _setparam(_system_cfg(standby=True), "revision-b"),
        primary_head="revision-a", standby_head="revision-b",
    )

    assert primary.election.source == standby.election.peer == PRIMARY_IP
    assert standby.election.source == primary.election.peer == STANDBY_IP
    assert (primary.election.priority, standby.election.priority) == (255, 100)
    assert primary.local_certificate_sha256 == standby.peer_certificate_sha256 == sha256(
        PEM_cert_to_DER_cert(PRIMARY_PEM),
    ).hexdigest()
    assert standby.local_certificate_sha256 == primary.peer_certificate_sha256 == sha256(
        PEM_cert_to_DER_cert(STANDBY_PEM),
    ).hexdigest()
    assert "opaque private" not in repr((primary, standby))


@pytest.fixture
def enrolled_pair():
    from provisioners.vyos_shadow_binding import ShadowManagementIdentity, bind_shadow_enrollments

    expected = (
        ShadowManagementIdentity("02:00:00:00:00:01", "https://192.0.2.15", "SHA256:" + "A" * 43),
        ShadowManagementIdentity("02:00:00:00:00:02", "https://192.0.2.16", "SHA256:" + "B" * 42 + "A"),
    )
    inventory = [{"_id": device_id, "mac": router.mac, "site_id": "site-a", "model": "UXGENT",
                  "adopted": True, "version": "6.0.17", "cfgversion": f"head-{device_id}",
                  "known_cfgversion": f"prior-{device_id}"}
                 for device_id, router in zip(("a", "b"), expected, strict=True)]
    binding = bind_shadow_enrollments(
        site_id="site-a", pair={"primary_mac": expected[0].mac, "secondary_mac": expected[1].mac,
                                "state": "IN_PROGRESS"},
        inventory=inventory, routers=expected,
    )
    return binding, expected


def test_initial_complete_uses_only_the_current_primary_response(enrolled_pair):
    from dataclasses import replace

    from provisioners.uxg_enterprise_shadow_tunnel import verify_bound_shadow_primary_complete

    binding, (primary, standby) = enrolled_pair
    response = _setparam(_system_cfg(), "head-a")
    snapshot = verify_bound_shadow_primary_complete(binding, authenticated_response=(primary, response))
    assert snapshot.election.source == PRIMARY_IP and snapshot.election.priority == 255
    for other_binding, observation in (
        (replace(binding, state="SETUP_COMPLETED"), (primary, response)),
        (binding, (standby, response)),
        (binding, (primary, response | {"cfgversion": "prior-a"})),
        (binding, (primary, _setparam(_system_cfg(standby=True), "head-a"))),
    ):
        with pytest.raises(ValueError):
            verify_bound_shadow_primary_complete(other_binding, authenticated_response=observation)


def test_primary_complete_plan_binds_the_entire_authenticated_snapshot(enrolled_pair, monkeypatch):
    from dataclasses import make_dataclass
    from unittest.mock import Mock
    from provisioners import uxg_enterprise_shadow_tunnel as tunnel
    from provisioners.uxg_enterprise_shadow import shadow_management_port

    binding, (primary, standby) = enrolled_pair
    data = _system_cfg()
    addresses = [{"type": "dynamic", "cidr": None, "origin": "vrrp", "eui64": False, "version": "v4"}]
    ordinary = [{"type": "static", "cidr": "192.0.2.1/24", "version": "v4"}]
    row = {"identification": {"id": "br0", "type": "bridge"}, "addresses": addresses}
    data["udapi"]["interfaces"] = [row, shadow_management_port("169.254.254.2/24")]
    response = _setparam(data, "head-a")
    compile_plan = Mock(return_value=make_dataclass("Planner", [
        ("complete_snapshot_sha256", str), ("complete_binding", object), ("management_guard", object),
        ("guard_containers", tuple), ("standby_resources_sha256", str), ("site_policy_sha256", str),
        ("created_vrrp_parent", tuple),
    ])(None, None, None, (), None, None, ()))
    monkeypatch.setattr(tunnel, "prepare_shadow_primary_lan_handoff", compile_plan)
    handoff = tunnel.prepare_bound_shadow_primary_lan_handoff(
        binding, authenticated_response=(primary, response), nodes=(), primary_lan_link_local="fe80::2",
        ordinary=ordinary, local=None, peer=None, route_source="192.0.2.1",
    )
    assert compile_plan.call_args.args[0].priority == 255
    assert compile_plan.call_args.kwargs["complete"] == addresses
    assert handoff.complete_binding == binding
    assert handoff.complete_snapshot_sha256 == tunnel.complete_snapshot_fingerprint(json.dumps(data, sort_keys=True))
    assert handoff.complete_snapshot_sha256 != tunnel.complete_snapshot_fingerprint(json.dumps(data | {"other": 1}))
    assert handoff.created_vrrp_parent == ()
    from_stock = tunnel.prepare_bound_shadow_primary_lan_handoff(
        binding, authenticated_response=(primary, response), nodes=(), primary_lan_link_local="fe80::2",
        ordinary=ordinary, local=None, peer=None, route_source="192.0.2.1",
        stock_configuration={"high-availability": {}},
    )
    assert from_stock.created_vrrp_parent == ("high-availability", "vrrp")
    reservation = {
        "phase": "saved", "target": "a" * 64, "revision": "b" * 64, "saved_sha256": "c" * 64,
        "config_sha256": "d" * 64, "receipt_generation": "e" * 64, "outside_sha256": "f" * 64,
        "staged_sha256": "1" * 64, "final_saved_sha256": "2" * 64,
        "boot_id": "158dd3a3-dc93-4ae3-94b1-489e4f6ecc6d", "transaction": "6303a0a3-d505-4782-93e1-0639a40dd670",
        "lan_preimage": {
            "addresses": ["192.0.2.1/24", "192.0.2.9/24"], "route_source": "192.0.2.1", "guard_containers": [],
        },
    }
    rebuilt = tunnel.prepare_bound_shadow_primary_lan_handoff(
        binding, authenticated_response=(primary, response), nodes=(), primary_lan_link_local="fe80::2",
        ordinary=ordinary, local=None, peer=None, route_source=None, reservation=reservation,
    )
    assert rebuilt == handoff
    assert compile_plan.call_args.kwargs["recovery"].addresses == ("192.0.2.1/24", "192.0.2.9/24")
    with pytest.raises(ValueError, match="different authenticated device"):
        tunnel.prepare_bound_shadow_primary_lan_handoff(
            binding, authenticated_response=(standby, response), nodes=(), primary_lan_link_local="fe80::2",
            ordinary=[], local=None, peer=None, route_source="192.0.2.1",
        )
    data["udapi"]["interfaces"].append(row)
    with pytest.raises(ValueError, match="unique"):
        tunnel.prepare_bound_shadow_primary_lan_handoff(
            binding, authenticated_response=(primary, _setparam(data, "head-a")), nodes=(), primary_lan_link_local="fe80::2",
            ordinary=[], local=None, peer=None, route_source="192.0.2.1",
        )


@pytest.mark.parametrize("body", ['{"other": 1, "other": 2}', '{"other": 1e1000}', '{"other": NaN}'])
def test_complete_fingerprint_rejects_ambiguous_or_nonfinite_snapshot_values(body):
    from provisioners.uxg_enterprise_shadow_tunnel import complete_snapshot_fingerprint

    with pytest.raises(ValueError, match="COMPLETE"):
        complete_snapshot_fingerprint(body)


def test_complete_policy_fingerprint_keeps_firewall_and_unrelated_services_in_comparison():
    from provisioners.uxg_enterprise_shadow_tunnel import primary_shadow_policy_fingerprint

    complete = _system_cfg()
    ordinary = [{"type": "static", "cidr": "192.0.2.1/24", "version": "v4"}]
    br0 = {"identification": {"id": "br0", "type": "bridge"}}
    complete["udapi"]["interfaces"] = [br0 | {"addresses": [
        {"type": "dynamic", "cidr": None, "origin": "vrrp", "eui64": False, "version": "v4"},
    ]}]
    complete["udapi"]["firewall/filter"] = [{"description": "operator", "rules": [1, 2]}]
    complete["udapi"]["services"]["dnsForwarder"] = {"enabled": True}
    prior = json.loads(json.dumps(complete))
    prior["udapi"]["interfaces"][0]["addresses"] = ordinary
    del prior["udapi"]["services"]["vrrp"], prior["udapi"]["services"]["stunnel"]
    expected = primary_shadow_policy_fingerprint(json.dumps(prior), ordinary, complete=False)

    assert primary_shadow_policy_fingerprint(json.dumps(complete), ordinary, complete=True) == expected
    complete["udapi"]["firewall/filter"][0]["rules"].reverse()
    assert primary_shadow_policy_fingerprint(json.dumps(complete), ordinary, complete=True) != expected
    complete["udapi"]["interfaces"][0]["addresses"].append(ordinary[0])
    with pytest.raises(ValueError, match="transfer exactly"):
        primary_shadow_policy_fingerprint(json.dumps(complete), ordinary, complete=True)


def test_complete_management_guard_preserves_lan_policy_and_compiles_narrow_stock_drops():
    from provisioners.uxg_enterprise_shadow import shadow_management_port
    from provisioners.uxg_enterprise_shadow_tunnel import (
        decode_primary_management_guard, decode_shadow_complete_snapshot,
        primary_shadow_policy_fingerprint, shadow_site_policy_fingerprint, standby_policy_snapshot,
    )

    complete = _system_cfg()
    ordinary = [{"type": "static", "cidr": "192.0.2.1/24", "version": "v4"}]
    complete["udapi"]["interfaces"] = [{"identification": {"id": "br0", "type": "bridge"}, "addresses": [
        {"type": "dynamic", "cidr": None, "origin": "vrrp", "eui64": False, "version": "v4"},
    ]}]
    local_network = {"identification": {"name": "local_network", "type": "address"}, "entries": ["192.0.2.0/24"]}
    mgmt_set = {"identification": {"name": "vrrp_mgmt_addr", "type": "address"},
                "description": "VRRP management addresses", "entries": [PRIMARY_IP, STANDBY_IP]}
    old_lan_rule = {"id": 60001, "target": "RETURN", "description": "[LAN_IN]Allow Network 192.0.2.0/24 Traffic",
                    "source": {"address": "192.0.2.0/24"}, "ipVersion": "v4only"}
    drop = {"id": 60001, "target": "DROP", "ipVersion": "v4only", "protocol": "all",
            "source": {"sets": ["local_network"]}, "destination": {"sets": ["vrrp_mgmt_addr"]}}
    terminal = {"id": 2147483647, "target": "RETURN", "ipVersion": "v4only"}
    prior = json.loads(json.dumps(complete))
    prior["udapi"]["interfaces"][0]["addresses"] = ordinary
    prior["udapi"]["firewall/sets"] = [local_network]
    prior["udapi"]["firewall/filter"] = [
        {"config": {"name": "LAN_IN"}, "rules": [old_lan_rule, terminal]},
        {"config": {"name": "LAN_LOCAL"}, "rules": [terminal]},
    ]
    complete["udapi"]["firewall/sets"] = [local_network, mgmt_set]
    complete["udapi"]["firewall/filter"] = [
        {"config": {"name": "LAN_IN"}, "rules": [
            drop | {"description": "[LAN_IN] Forbid Accessing Shadow Mode Management Link"},
            old_lan_rule | {"id": 60002}, terminal,
        ]},
        {"config": {"name": "LAN_LOCAL"}, "rules": [
            drop | {"description": "[LAN_LOCAL] Forbid Accessing Shadow Mode Management Link"}, terminal,
        ]},
    ]
    body = json.dumps(complete)
    guard = decode_primary_management_guard(body)
    assert guard.networks == ("192.0.2.0/24",)
    assert guard.addresses == (PRIMARY_IP, STANDBY_IP)
    assert primary_shadow_policy_fingerprint(body, ordinary, complete=True) == primary_shadow_policy_fingerprint(
        json.dumps(prior), ordinary, complete=False,
    )
    complete["udapi"]["interfaces"].append(shadow_management_port("169.254.254.2/24"))
    primary_body = json.dumps(complete)
    primary_snapshot = decode_shadow_complete_snapshot(primary_body)
    expected_site = shadow_site_policy_fingerprint(primary_body, election=primary_snapshot.election)
    standby = _system_cfg(standby=True)
    standby["udapi"].update({key: json.loads(json.dumps(complete["udapi"][key]))
                            for key in ("interfaces", "firewall/sets", "firewall/filter")})
    standby["udapi"]["interfaces"][-1] = shadow_management_port("169.254.254.3/24")
    standby["udapi"]["firewall/sets"][-1]["entries"].reverse()
    standby_body = json.dumps(standby)
    standby_snapshot = decode_shadow_complete_snapshot(standby_body)
    assert shadow_site_policy_fingerprint(standby_body, election=standby_snapshot.election) == expected_site
    projected, standby_guard = standby_policy_snapshot(standby_body, election=standby_snapshot.election)
    assert standby_guard.networks == guard.networks
    assert standby_guard.addresses == (STANDBY_IP, PRIMARY_IP)
    assert json.loads(projected)["udapi"]["firewall/filter"] == prior["udapi"]["firewall/filter"]
    standby["udapi"]["firewall/sets"] = prior["udapi"]["firewall/sets"]
    standby["udapi"]["firewall/filter"] = prior["udapi"]["firewall/filter"]
    assert shadow_site_policy_fingerprint(json.dumps(standby), election=standby_snapshot.election) != expected_site
    stock = {}
    for command in guard.create_commands():
        tree = stock
        *parents, leaf = command["path"]
        for parent in parents:
            tree = tree.setdefault(parent, {})
        if leaf in tree:
            tree[leaf] = [tree[leaf], command["value"]]
        else:
            tree[leaf] = command["value"]
    guard.verify_stock(stock, installed=True)
    containers = guard.created_containers({})
    assert {tuple(command["path"]) for command in guard.withdraw_commands(stock, created_containers=containers)} == {
        ("firewall", "group"), ("firewall", "ipv4", "input"), guard.paths[2],
    }
    stock["firewall"]["ipv4"]["input"]["filter"]["rule"]["50"] = {"action": "accept"}
    paths = {tuple(command["path"]) for command in guard.withdraw_commands(stock, created_containers=containers)}
    assert guard.paths[3] in paths
    assert ("firewall", "ipv4", "input") not in paths
    with pytest.raises(ValueError):
        guard.verify_stock(stock, installed=False)
    stock["interfaces"] = {"bridge": {"br0": {"member": {"interface": {"eth2.110": {}}}}}}
    with pytest.raises(ValueError, match="routed independently"):
        guard.verify_stock(stock, installed=True, interconnect="eth2")
    stock["firewall"]["global-options"] = {"state-policy": {"established": {"action": "accept"}}}
    with pytest.raises(ValueError, match="state policy"):
        guard.verify_stock(stock, installed=True)
    complete["udapi"]["firewall/filter"][1]["rules"][0]["target"] = "ACCEPT"
    with pytest.raises(ValueError, match="management"):
        primary_shadow_policy_fingerprint(json.dumps(complete), ordinary, complete=True)


def test_bound_snapshots_use_the_device_specific_head_and_authentication_channel(enrolled_pair):
    from dataclasses import replace

    from provisioners.uxg_enterprise_shadow_tunnel import verify_bound_shadow_complete

    binding, expected = enrolled_pair
    responses = {"a": (expected[0], _setparam(_system_cfg(), "head-a")),
                 "b": (expected[1], _setparam(_system_cfg(standby=True), "head-b"))}
    primary, standby = verify_bound_shadow_complete(binding, authenticated_responses=responses)
    assert primary.local_certificate_sha256 == standby.peer_certificate_sha256

    for candidate in (
        responses | {"a": (expected[1], responses["a"][1])},
        responses | {"b": (replace(expected[1], https_origin="https://192.0.2.19"), responses["b"][1])},
        responses | {"c": responses["b"]},
        responses | {"a": (expected[0], responses["a"][1] | {"cfgversion": "prior-a"})},
    ):
        with pytest.raises(ValueError):
            verify_bound_shadow_complete(binding, authenticated_responses=candidate)


@pytest.mark.parametrize("loss", [None, "no-commitment", "reservation", "standby-head", "primary-head", "foreign-site",
                                  "lan-link", "peer-guard", "certificate-roles", "policy", "standby-revision", "receipt",
                                  "fallback", "fallback-policy", "fallback-wrong-port", "fallback-wan-mac",
                                  "fallback-early", "superseded-policy", "superseded-resources"])
def test_standby_complete_needs_the_reciprocal_primary_receipt_and_its_own_verified_policy(enrolled_pair, loss):
    from dataclasses import replace
    from ipaddress import ip_interface
    from unittest.mock import Mock

    from provisioners.vyos_shadow_complete import ShadowStockState
    from provisioners.vyos_shadow_handoff import _identity_digest, _revision_digest, _standby_reservation, verify_standby_complete
    from provisioners.vyos_shadow_receipt import ShadowHandoffObservation, ShadowPolicyReceipt, ShadowReceiptStatus
    from provisioners.uxg_enterprise_shadow_tunnel import (
        complete_snapshot_fingerprint,
        expected_standby_resources,
        primary_shadow_policy_fingerprint,
        verify_bound_shadow_primary_complete,
    )

    original, (primary, standby) = enrolled_pair
    primary_response = _setparam(_system_cfg(), "head-a")
    snapshot = verify_bound_shadow_primary_complete(original, authenticated_response=(primary, primary_response))
    target = "1" * 64
    record = {
        "phase": "primary_active", "target": target, "revision": _revision_digest(target, "head-a"),
        "controller_revision": "head-a", "primary_identity_sha256": _identity_digest(primary),
        "complete_snapshot_sha256": complete_snapshot_fingerprint(primary_response["system_cfg"]),
        "standby_resources_sha256": expected_standby_resources(original, snapshot, "fe80::2"),
        "boot_id": "158dd3a3-dc93-4ae3-94b1-489e4f6ecc6d", "transaction": "6303a0a3-d505-4782-93e1-0639a40dd670",
        "saved_sha256": "2" * 64, "config_sha256": "3" * 64, "outside_sha256": "4" * 64,
        "receipt_generation": "5" * 64, "staged_sha256": "6" * 64, "final_saved_sha256": "7" * 64,
        "policy_sha256": "8" * 64, "receipt_id": "9" * 64,
    }
    persisted = json.loads(json.dumps(record))
    peer_record = _standby_reservation(persisted)
    binding = replace(original, state="SETUP_COMPLETED", standby=replace(original.standby, desired_revision="complete-b"))
    ordinary = [{"type": "static", "cidr": "192.0.2.1/24", "version": "v4"}]
    bridge = {"identification": {"id": "br0", "type": "bridge"}, "addresses": ordinary}
    phase_one = {"udapi": {"versionDetail": {}, "interfaces": [bridge]}, "policy": "prior"}
    policy = primary_shadow_policy_fingerprint(json.dumps(phase_one), ordinary, complete=False)
    complete = _system_cfg(standby=True)
    complete["udapi"]["interfaces"] = [bridge | {"addresses": [
        {"type": "dynamic", "cidr": None, "origin": "vrrp", "eui64": False, "version": "v4"},
    ]}]
    complete["policy"] = "foreign" if loss in ("policy", "superseded-policy", "superseded-resources") else "prior"
    if loss and loss.startswith("fallback"):
        from provisioners.uxg_enterprise_shadow_tunnel import shadow_site_policy_fingerprint

        def management_row(address):
            return {"identification": {"id": "eth1", "type": "ethernet"},
                    "status": {"enabled": True, "comment": "MGMT_SHADOW"},
                    "addresses": [{"type": "static", "cidr": address, "version": "v4"}]}

        wan = {"identification": {"id": "eth0", "type": "ethernet"}, "status": {"enabled": True},
               "addresses": [{"type": "static", "cidr": "203.0.113.2/24", "version": "v4"}]}
        complete["udapi"]["interfaces"].append(wan)
        primary_cfg = _system_cfg()
        primary_cfg["udapi"]["interfaces"] = [*complete["udapi"]["interfaces"], management_row("169.254.254.2/24")]
        primary_cfg["policy"] = "verified-site"
        persisted["site_policy_sha256"] = shadow_site_policy_fingerprint(
            json.dumps(primary_cfg), election=snapshot.election,
        )
        standby_address = "169.254.254.2/24" if loss == "fallback-wrong-port" else "169.254.254.3/24"
        complete["udapi"]["interfaces"].append(management_row(standby_address))
        if loss == "fallback-wan-mac":
            wan["mac"] = "02:00:00:00:00:03"
        complete["policy"] = "changed-site" if loss == "fallback-policy" else "verified-site"
        ordinary = [{"type": "static", "cidr": "198.51.100.1/24", "version": "v4"}]
        phase_one["udapi"]["interfaces"] = [
            bridge | {"addresses": ordinary},
            wan | {"addresses": [{"type": "dynamic", "origin": "dhcp", "version": "v4"}]},
            management_row("169.254.254.3/24"),
        ]
        policy = primary_shadow_policy_fingerprint(json.dumps(phase_one), ordinary, complete=False)
    response = _setparam(complete, "head-b" if loss == "standby-head" else "complete-b")
    if loss == "no-commitment":
        del persisted["standby_resources_sha256"]
    elif loss == "reservation":
        peer_record["transaction"] = persisted["boot_id"]
    elif loss == "foreign-site":
        binding = replace(binding, site_id="site-other")
    elif loss == "primary-head":
        binding = replace(binding, primary=replace(binding.primary, desired_revision="stale-a"))
    elif loss == "fallback-early":
        binding = replace(binding, state="IN_PROGRESS")
    elif loss in ("peer-guard", "superseded-resources"):
        complete["udapi"]["services"]["vrrp"]["instances"][0]["masterGuard"]["peerLan"]["address"] = "fe80::3"
        response = _setparam(complete, "complete-b")
    elif loss == "certificate-roles":
        wrong_tunnel = _system_cfg()["udapi"]["services"]["stunnel"]
        wrong_tunnel["clients"][0]["server"] = PRIMARY_IP
        complete["udapi"]["services"]["stunnel"] = wrong_tunnel
        response = _setparam(complete, "complete-b")
    receipt = Mock(management_identity=primary)
    accepted = ShadowPolicyReceipt(record["receipt_id"], record["policy_sha256"], record["transaction"], record["staged_sha256"])
    receipt.status.return_value = ShadowReceiptStatus(record["receipt_generation"], None if loss == "receipt" else accepted)
    state = ShadowStockState({}, {}, {"eth3": (ip_interface("fe80::3/64" if loss == "lan-link" else "fe80::2/64"),)})
    receipt.observe_handoff_state.return_value = ShadowHandoffObservation(
        state, "master", record["boot_id"], record["final_saved_sha256"], record["staged_sha256"], "reboot", "saved_commit",
    )
    backend, proof = Mock(), Mock(return_value=(record["boot_id"], record["staged_sha256"]))
    options = dict(binding=binding, observation=(standby, response), receipt_client=receipt, backend=backend,
                   commit_proof=proof, primary_lan_interface="eth3", ordinary=ordinary, phase_one_digest=policy,
                   phase_one_revision="prepare-b", verified_standby_revision="other" if loss == "standby-revision" else "prepare-b")
    if loss in (None, "fallback"):
        verified = verify_standby_complete(persisted, peer_record, **options)
        assert verified.election.priority == 100
        assert receipt.status.call_count == 2
        receipt.observe_handoff_state.assert_called_once()
    else:
        with pytest.raises(ValueError):
            verify_standby_complete(persisted, peer_record, **options)
    if loss in ("superseded-policy", "superseded-resources"):
        from provisioners.vyos_shadow_handoff import verify_standby_rollback_resources

        binding = replace(binding, primary=replace(binding.primary, desired_revision="new-a"),
                          standby=replace(binding.standby, desired_revision="new-b"))
        recovery = dict(binding=binding, observation=(standby, response | {"cfgversion": "new-b"}),
                        receipt_client=receipt, backend=backend, commit_proof=proof, primary_lan_interface="eth3")
        if loss == "superseded-policy":
            assert verify_standby_rollback_resources(persisted, peer_record, **recovery).election.priority == 100
        else:
            with pytest.raises(ValueError, match="verified primary resources"):
                verify_standby_rollback_resources(persisted, peer_record, **recovery)


@pytest.mark.parametrize(("primary_head", "standby_head"), [
    ("old-a", "revision-b"), ("revision-a", "old-b"), ("revision-b", "revision-a"), ("", "revision-b"),
])
def test_complete_pair_rejects_stale_or_swapped_heads(primary_head, standby_head):
    from provisioners.uxg_enterprise_shadow_tunnel import verify_shadow_complete_pair

    with pytest.raises(ValueError, match="controller head"):
        verify_shadow_complete_pair(
            _setparam(_system_cfg(), "revision-a"), _setparam(_system_cfg(standby=True), "revision-b"),
            primary_head=primary_head, standby_head=standby_head,
        )


@pytest.mark.parametrize(("resource", "field", "replacement"), [
    ("clients", "server", PRIMARY_IP),
    ("clients", "id", "unknown"),
    ("clients", "serverPort", 31000.0),
    ("clients", "localSocket", "/wrong"),
    ("servers", "listenPort", 31001),
    ("servers", "serverCert", {"crt": _wire_cert(STANDBY_PEM), "key": "opaque"}),
    ("servers", "clientCert", {"crt": _wire_cert(STANDBY_PEM), "key": "foreign wrapper"}),
])
def test_complete_snapshot_rejects_nonmatching_stunnel_topology(resource, field, replacement):
    from provisioners.uxg_enterprise_shadow_tunnel import decode_shadow_complete_snapshot

    config = _system_cfg()
    config["udapi"]["services"]["stunnel"][resource][0][field] = replacement
    with pytest.raises(ValueError, match="Shadow Mode tunnel"):
        decode_shadow_complete_snapshot(json.dumps(config))


@pytest.mark.parametrize("encoded", [
    "a" * 16385,
    "%%%",
    _wire_cert(PRIMARY_PEM + STANDBY_PEM),
    _wire_cert("-----BEGIN CERTIFICATE-----\nZ29vZA==\n-----END CERTIFICATE-----\n"),
])
def test_complete_snapshot_requires_one_bounded_x509_certificate(encoded):
    from provisioners.uxg_enterprise_shadow_tunnel import decode_shadow_complete_snapshot

    config = _system_cfg()
    config["udapi"]["services"]["stunnel"]["clients"][0]["clientCert"]["crt"] = encoded
    with pytest.raises(ValueError, match="Shadow Mode tunnel certificate"):
        decode_shadow_complete_snapshot(json.dumps(config))


def test_complete_pair_rejects_competing_virtual_addresses():
    from provisioners.uxg_enterprise_shadow_tunnel import verify_shadow_complete_pair

    standby = _system_cfg(standby=True)
    standby["udapi"]["services"]["vrrp"]["instances"][0]["virtualIPs"][0]["address"] = "192.0.2.4/24"
    with pytest.raises(ValueError, match="reciprocal"):
        verify_shadow_complete_pair(
            _setparam(_system_cfg(), "revision-a"), _setparam(standby, "revision-b"),
            primary_head="revision-a", standby_head="revision-b",
        )


def test_complete_pair_rejects_two_valid_snapshots_with_the_same_certificate_role():
    from provisioners.uxg_enterprise_shadow_tunnel import decode_shadow_complete_snapshot, verify_shadow_complete_pair

    primary = _system_cfg()
    standby = _system_cfg(standby=True)
    first = primary["udapi"]["services"]["stunnel"]
    second = standby["udapi"]["services"]["stunnel"]
    for endpoint_type in ("clients", "servers"):
        for field in ("clientCert", "serverCert"):
            second[endpoint_type][0][field] = first[endpoint_type][0][field]

    primary_response = _setparam(primary, "revision-a")
    standby_response = _setparam(standby, "revision-b")
    assert decode_shadow_complete_snapshot(standby_response["system_cfg"]).election.priority == 100
    with pytest.raises(ValueError, match="reciprocal"):
        verify_shadow_complete_pair(
            primary_response, standby_response, primary_head="revision-a", standby_head="revision-b",
        )


@pytest.mark.parametrize(("schema", "version"), [("services/stunnel", True), ("services/stunnel", 2), ("services/vrrp", 3)])
def test_complete_snapshot_requires_pinned_resource_versions(schema, version):
    from provisioners.uxg_enterprise_shadow_tunnel import decode_shadow_complete_snapshot

    config = _system_cfg()
    config["udapi"]["versionDetail"][schema] = version
    with pytest.raises(ValueError, match="schema"):
        decode_shadow_complete_snapshot(json.dumps(config))
