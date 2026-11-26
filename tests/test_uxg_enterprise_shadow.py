"""The native Shadow Mode status command requires a fresh interconnect probe."""

from collections import deque
from configparser import ConfigParser
from contextlib import nullcontext
from ipaddress import IPv4Interface
import json
from pathlib import Path
import runpy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from backends.vyos import VyOSBackend, VyOSReadError
from gateway_profiles.uxg_enterprise_shadow import ShadowPeerProbe
from unifi_gateway import UnifiGateway
from unifi_protocol import create_inform, encode_inform


REQUEST = {
    "_type": "cmd", "cmd": "shadow-mode-adopt", "action": "status",
    "request_id": "12345678-90ab-4def-8123-4567890abcde", "is_secondary": True,
}


def _gateway(*, reachable, authenticated=True, enrolled=True, model="UXGENT"):
    gateway = UnifiGateway.__new__(UnifiGateway)
    gateway.config = ConfigParser()
    gateway.config.read_dict({"gateway": {
        "device": model, "platform": "vyos", "is_adopted": enrolled, "use_aes_gcm": authenticated,
        "lan_mac": "02:78:91:00:12:04", "lan_ip": "192.0.2.1", "ports": "[]",
        "url": "http://lab.example:8080/inform",
    }})
    gateway.datacollector = SimpleNamespace(data={})
    gateway._shadow_peer_probe = Mock()
    gateway._shadow_prepare_primary = None
    gateway._shadow_advertiser = None
    gateway._shadow_credential_prefix = ""
    gateway._shadow_peer_probe.reachable.return_value = reachable
    gateway._send_inform = Mock(return_value={"_type": "noop"})
    gateway._record_unhandled = Mock()
    return gateway


@pytest.mark.parametrize("reachable", [True, False, None])
def test_shadow_status_returns_a_correlated_measurement(reachable):
    gateway = _gateway(reachable=reachable)
    if reachable is None:
        gateway._shadow_peer_probe.reachable.side_effect = VyOSReadError("Unavailable interconnect")

    gateway._handle_response(REQUEST)

    gateway._shadow_peer_probe.reachable.assert_called_once_with(is_secondary=True)
    payload = json.loads(gateway._send_inform.call_args.args[0])
    assert payload["inform_as_notif"] is True and payload["notif_reason"] == "cmd"
    assert payload["notif_payload"] == {
        "event_string": REQUEST["cmd"], "request_id": REQUEST["request_id"],
        "status": {"flags": {"peer_connection_test": {"ping": reachable is True}}},
    }
    assert (payload.get("usg2_caps", 0) & 0x40000000) == 0


@pytest.mark.parametrize("changes", [
    {"action": "begin-adoption"}, {"is_secondary": 1}, {"request_id": "invalid"},
    {"address": "192.0.2.1"}, {"username": "test", "password": "sample-secret"},
])
def test_shadow_status_does_not_execute_unrecognized_requests(changes):
    gateway = _gateway(reachable=True)

    gateway._handle_response(REQUEST | changes)

    gateway._shadow_peer_probe.reachable.assert_not_called()
    gateway._send_inform.assert_not_called()


@pytest.mark.parametrize("options", [
    {"authenticated": False}, {"enrolled": False}, {"model": "UNKNOWN"},
])
def test_shadow_status_needs_an_authenticated_adopted_enterprise(options):
    gateway = _gateway(reachable=True, **options)

    gateway._handle_response(REQUEST)

    gateway._shadow_peer_probe.reachable.assert_not_called()
    gateway._send_inform.assert_not_called()


def _vrrp_config():
    return {
        "sync-group": {"UXGHA": {"member": ["UXGLAN", "UXGWAN"]}},
        "group": {
            "UXGLAN": {"interface": "eth3", "vrid": "42", "address": {"192.0.2.1/24": {}}},
            "UXGWAN": {"interface": "eth1", "vrid": "41", "address": {"198.18.240.1/24": {}}},
        },
    }


def _vrrp_detail(lan_state, wan_state):
    return f"""
 VRRP Instance: UNRELATED
   State: MASTER
   Interface: eth6
   Virtual Router ID: 13
 VRRP Instance: UXGLAN
   VRRP Version: 2
   State: {lan_state}
   Wantstate: MASTER
   Last transition: 1795637144.879514
   Interface: eth3
   Virtual Router ID: 42
   Virtual IP (1):
      192.0.2.1/24 dev eth3
 VRRP Instance: UXGWAN
   VRRP Version: 2
   State: {wan_state}
   Wantstate: MASTER
   Last transition: 1795637144.872668
   Interface: eth1
   Virtual Router ID: 41
   Virtual IP (1):
      198.18.240.1/24 dev eth1
"""


def _inform_cycle(gateway):
    gateway._speedtest_reports = deque()
    gateway._speedtest_completed = None
    gateway._vyos_restart = None
    gateway.interval = 10
    gateway._exchange_inform()
    return json.loads(gateway._send_inform.call_args.args[0])


def test_primary_complete_waits_for_coordinator_without_ordinary_provisioning(monkeypatch):
    gateway = _gateway(reachable=False)
    gateway.config.read_dict({
        "vyos_shadow": {"provisioning_enabled": True},
        "vyos_shadow_primary": {"enabled": True},
    })
    gateway.vyos_provisioner = Mock()
    gateway.datacollector.backend = Mock()
    monkeypatch.setattr("gateway_profiles.vyos_vrrp.observe_shadow_role", Mock(return_value="unknown"))
    gateway.vyos_provisioner.locked_state.return_value = nullcontext({})
    gateway._handle_response = Mock()
    gateway._send_inform.return_value = {
        "_type": "setparam", "cfgversion": "complete",
        "system_cfg": '{"udapi":{"services":{"vrrp":{"enabled":true}}}}',
    }
    _inform_cycle(gateway)
    gateway._handle_response.assert_not_called()
    gateway.vyos_provisioner.reconcile.assert_not_called()


@pytest.mark.parametrize(("role", "authenticated", "ready"), [
    ("primary_", True, True), ("standby_", True, True), ("primary_", True, False),
    ("standby_", False, True), ("", True, True),
])
def test_managed_shadow_inform_negotiates_exact_schemas_only_for_verified_packaged_role(role, authenticated, ready):
    gateway = _gateway(reachable=False, authenticated=authenticated)
    gateway._shadow_credential_prefix = role
    gateway.config.read_dict({
        "vyos_firewall": {"enabled": True}, "vyos_shadow": {"provisioning_enabled": True},
        "vyos_applied": {"cfgversion": "ordinary"}, "vyos_mdns": {"enabled": True},
    })
    gateway.datacollector.backend = Mock()
    gateway.datacollector.backend.read_config.return_value = None
    gateway.vyos_provisioner = Mock()
    advertiser = Mock()
    gateway._build_shadow_advertiser = Mock(return_value=advertiser)
    if not ready:
        advertiser.verify_capability.side_effect = ValueError("Controller read session expired")
    payload = _inform_cycle(gateway)
    enabled = bool(role and authenticated and ready)
    assert bool(payload.get("usg2_caps", 0) & 0x40000000) is enabled
    versions = payload["udapi_version"]["versionDetail"]
    assert {key: value for key, value in versions.items() if key in {"services/vrrp", "services/stunnel"}} == (
        {"services/vrrp": 5, "services/stunnel": 1} if enabled else {}
    )
    assert (payload["cfgversion"], versions["services/mdns"]) == ("ordinary", 2)
    if role and authenticated:
        advertiser.verify_capability.assert_called_once_with(role=role.removesuffix("_"))
    else:
        advertiser.verify_capability.assert_not_called()


@pytest.mark.parametrize(("roles", "owns", "state"), [
    (("MASTER", "MASTER"), "both", "master"),
    (("BACKUP", "BACKUP"), "neither", "backup"),
    (("FAULT", "FAULT"), "neither", "fault"),
    (("INIT", "INIT"), "neither", "init"),
    (("MASTER", "BACKUP"), "one", "unknown"),
    (("MASTER", "MASTER"), "one", "unknown"),
    (("BACKUP", "BACKUP"), "both", "unknown"),
    (("MASTER", "MASTER"), "wrong-prefix", "unknown"),
    (("MASTER", "MASTER"), "elsewhere", "unknown"),
])
def test_shadow_inform_reports_role_only_when_kernel_vip_ownership_agrees(roles, owns, state):
    gateway = _gateway(reachable=True)
    lan_vip = ("192.0.2.1", 24)
    wan_vip = ("198.18.240.1", 24)
    lan = (lan_vip,) if owns in {"both", "one", "wrong-prefix"} else ()
    wan = {"both": (wan_vip,), "wrong-prefix": (("198.18.240.1", 25),)}.get(owns, ())
    backend = Mock()
    gateway.datacollector.backend = backend
    backend.read_config.return_value = _vrrp_config()
    backend.show_vrrp_detail.return_value = _vrrp_detail(*roles)
    backend.show_kernel_interfaces.return_value = [
        _row("eth3", *lan), _row("eth1", *wan), _row("eth7", lan_vip, wan_vip) if owns == "elsewhere" else _row("eth7"),
    ]

    payload = _inform_cycle(gateway)

    assert payload["vrrp"] == {"state": state}
    assert (payload.get("usg2_caps", 0) & 0x40000000) == 0
    backend.read_config.assert_called_once_with(["high-availability", "vrrp"])
    backend.show_vrrp_detail.assert_called_once_with()
    backend.show_kernel_interfaces.assert_called_once_with()


def test_shadow_inform_does_not_advance_pairing_during_pending_handoff():
    gateway = _gateway(reachable=True)
    gateway.config["vyos_shadow"] = {"provisioning_enabled": "True"}
    gateway.vyos_provisioner = Mock()
    gateway.vyos_provisioner.locked_state.return_value = nullcontext({"shadow_handoff": {}})
    backend = gateway.datacollector.backend = Mock()
    backend.read_config.return_value = _vrrp_config()
    backend.show_vrrp_detail.return_value = _vrrp_detail("MASTER", "MASTER")
    backend.show_kernel_interfaces.return_value = [_row("eth3", ("192.0.2.1", 24)), _row("eth1", ("198.18.240.1", 24))]
    assert _inform_cycle(gateway)["vrrp"] == {"state": "unknown"}


@pytest.mark.parametrize("kind", ["complete", "waiting-vrrp", "ordinary", "unauthenticated"])
def test_first_complete_dispatch_uses_the_authenticated_primary_plan(kind):
    from provisioners.vyos_shadow_handoff import ShadowPrimaryPending

    gateway = _gateway(reachable=True, authenticated=kind != "unauthenticated")
    gateway.config["vyos_shadow"] = {"provisioning_enabled": "True"}
    gateway.vyos_provisioner = Mock()
    gateway.vyos_provisioner.locked_state.return_value = nullcontext({})
    gateway._handle_response = Mock()
    gateway._notify_vyos_provisioning_error = Mock()
    gateway._vyos_provisioning_error = None
    backend = gateway.datacollector.backend = Mock()
    backend.read_config.return_value = {}
    gateway._shadow_prepare_primary = Mock()
    gateway._shadow_forwarding_probe = Mock()
    gateway._verify_shadow_complete_policy = Mock(return_value="phase-one")
    if kind == "waiting-vrrp":
        gateway._shadow_prepare_primary.return_value.advance_authenticated_complete.side_effect = ShadowPrimaryPending()
    response = {"_type": "setparam", "cfgversion": "head", "system_cfg": json.dumps({"udapi": {"services": {
        "vrrp": {"enabled": kind != "ordinary"}, "stunnel": {"enabled": kind != "ordinary"},
    }}}), "interval": 15}
    gateway._send_inform.return_value = response

    _inform_cycle(gateway)

    if kind in {"complete", "waiting-vrrp"}:
        observation = (gateway._shadow_peer_probe.management_identity.return_value, response)
        gateway._shadow_prepare_primary.assert_called_once_with(observation)
        gateway._shadow_prepare_primary.return_value.advance_authenticated_complete.assert_called_once_with(
            observation, verify_forwarding=gateway._shadow_forwarding_probe, phase_one_revision="phase-one",
        )
        gateway._handle_response.assert_not_called()
        assert gateway.interval == (15 if kind == "complete" else 10)
    else:
        gateway._shadow_prepare_primary.assert_not_called()
        gateway._handle_response.assert_called_once_with(response)
    gateway._notify_vyos_provisioning_error.assert_not_called()


@pytest.mark.parametrize("kind", ["complete", "distinct-baseline", "rejected", "waiting-backup",
                                  "unconfigured", "ordinary", "unauthenticated"])
def test_standby_complete_dispatch_uses_scoped_authenticated_policy(kind):
    from provisioners.vyos_shadow_standby import ShadowStandbyPending

    gateway = _gateway(reachable=True, authenticated=kind != "unauthenticated")
    gateway._shadow_credential_prefix = "standby_"
    gateway.config["vyos_shadow"] = {"provisioning_enabled": "True"}
    gateway.config["vyos_firewall"] = {"unmanaged_baseline_sha256": "A" * 64}
    if kind == "distinct-baseline":
        gateway.config["vyos_shadow"]["complete_unmanaged_baseline_sha256"] = "B" * 64
    gateway.vyos_provisioner = Mock()
    gateway.vyos_provisioner.locked_state.return_value = nullcontext({})
    gateway.datacollector.backend = Mock()
    gateway.datacollector.backend.read_config.return_value = {}
    gateway._handle_response = Mock()
    gateway._notify_vyos_provisioning_error = Mock()
    gateway._vyos_provisioning_error = None
    gateway._decode_vyos_policy = Mock()
    standby = Mock()
    gateway._build_shadow_advertiser = Mock(return_value=None if kind == "unconfigured" else standby)
    if kind == "rejected":
        standby.advance_standby_response.side_effect = ValueError("Standby candidate changed")
    if kind == "waiting-backup":
        standby.advance_standby_response.side_effect = ShadowStandbyPending()
    response = {"_type": "setparam", "cfgversion": "head", "system_cfg": json.dumps({"udapi": {"services": {
        "vrrp": {"enabled": kind != "ordinary"}, "stunnel": {"enabled": kind != "ordinary"},
    }}}), "interval": 15}
    gateway._send_inform.return_value = response

    payload = _inform_cycle(gateway)

    if kind in {"complete", "distinct-baseline", "rejected", "waiting-backup"}:
        standby.advance_standby_response.assert_called_once_with(
            (gateway._shadow_peer_probe.management_identity.return_value, response),
            decode_policy=gateway._decode_vyos_policy, approved_outside_scope=("b" if kind == "distinct-baseline" else "a") * 64,
        )
        assert payload.get("cfgversion") != "head"
    else:
        standby.advance_standby_response.assert_not_called()
    if kind in {"ordinary", "unauthenticated"}:
        gateway._handle_response.assert_called_once_with(response)
    else:
        gateway._handle_response.assert_not_called()
    assert gateway._notify_vyos_provisioning_error.call_count == (1 if kind in {"rejected", "unconfigured"} else 0)
    assert gateway.interval == (15 if kind in {"complete", "distinct-baseline"} else 10)
    if kind in {"complete", "distinct-baseline"}:
        gateway._send_inform.return_value = {"_type": "noop"}
        next_inform = _inform_cycle(gateway)
        assert next_inform.get("cfgversion") != "head"
        assert next_inform["vrrp"]["state"] != "backup"


@pytest.mark.parametrize("kind", ["verified", "stale", "unavailable", "promoted", "returning-primary"])
def test_standby_inform_reports_the_revision_only_after_live_backup_verification(monkeypatch, kind):
    gateway = _gateway(reachable=True)
    gateway._shadow_credential_prefix = "primary_" if kind == "returning-primary" else "standby_"
    gateway.config.read_dict({"vyos_shadow": {"provisioning_enabled": True},
                              "vyos_applied": {"cfgversion": "prepare"}, "vyos_firewall": {"enabled": True}})
    gateway.vyos_provisioner = Mock()
    gateway.vyos_provisioner.locked_state.return_value = nullcontext({})
    gateway.datacollector.backend = Mock()
    gateway._shadow_advertiser = None if kind == "unavailable" else Mock()
    gateway._build_shadow_advertiser = Mock(return_value=None)
    gateway._handle_response = Mock()
    role = "master" if kind == "promoted" else "backup"
    monkeypatch.setattr("gateway_profiles.vyos_vrrp.observe_shadow_role", Mock(return_value=role))
    verified = kind in ("verified", "promoted", "returning-primary")
    if verified:
        gateway._shadow_advertiser.verify_pair_inform.return_value = "complete"
    elif kind == "stale":
        gateway._shadow_advertiser.verify_pair_inform.side_effect = ValueError("Standby receipt drift")

    payload = _inform_cycle(gateway)

    assert payload["vrrp"]["state"] == (role if verified else "unknown")
    revision = "complete" if verified else "prepare"
    assert payload["cfgversion"] == revision
    assert payload.get("cfgversion_effective") == revision
    if gateway._shadow_advertiser is not None:
        gateway._shadow_advertiser.verify_pair_inform.assert_called_once_with(role=role, is_standby=kind != "returning-primary")
    gateway.vyos_provisioner.locked_state.assert_not_called()


@pytest.mark.parametrize(("prefix", "role", "changed"), [
    ("standby_", "master", None), ("primary_", "backup", None),
    ("standby_", "master", "body"), ("primary_", "backup", "revision"),
])
def test_reversed_roles_handle_complete_retries_before_initial_takeover(monkeypatch, prefix, role, changed):
    gateway = _gateway(reachable=True)
    gateway._shadow_credential_prefix = prefix
    gateway.config.read_dict({"vyos_shadow": {"provisioning_enabled": True}})
    gateway.vyos_provisioner = Mock()
    gateway.datacollector.backend = Mock()
    gateway._shadow_advertiser = Mock()
    gateway._dispatch_shadow_standby_complete = Mock(return_value=False)
    gateway._verify_shadow_complete_retry = Mock(return_value=False)
    gateway._dispatch_shadow_primary_complete = Mock(return_value=False)
    gateway._handle_response = Mock()
    gateway._vyos_provisioning_error = ("newer", "New revision is pending")
    rejected = gateway._reject_vyos_provisioning = Mock()
    monkeypatch.setattr("gateway_profiles.vyos_vrrp.observe_shadow_role", Mock(return_value=role))
    observation = {"_type": "setparam", "cfgversion": "complete", "system_cfg": "snapshot", "interval": 7}
    if changed == "revision":
        observation.update(cfgversion="new", system_cfg='{"udapi":{}}')
    gateway._send_inform.return_value = observation

    def verify(*, role, is_standby, replay=None):
        assert is_standby == (prefix == "standby_")
        if replay is not None and changed:
            raise ValueError("Shadow Mode replay differs from the verified COMPLETE")
        return "complete"

    verifier = gateway._shadow_advertiser.verify_pair_inform
    verifier.side_effect = verify
    assert _inform_cycle(gateway)["vrrp"]["state"] == role
    assert verifier.call_count == 2
    verifier.assert_called_with(role=role, is_standby=prefix == "standby_", replay=observation)
    gateway._dispatch_shadow_standby_complete.assert_not_called()
    gateway._verify_shadow_complete_retry.assert_not_called()
    gateway._dispatch_shadow_primary_complete.assert_not_called()
    gateway._handle_response.assert_not_called()
    assert rejected.call_count == (1 if changed else 0)
    assert gateway.interval == (10 if changed else 7)
    assert gateway._vyos_provisioning_error == ("newer", "New revision is pending")


def _active_primary_gateway(tmp_path, loss=None):
    from dataclasses import asdict
    from hashlib import sha256
    from provisioners.vyos_shadow_binding import ShadowManagementIdentity
    from provisioners.vyos_shadow_complete import ShadowStockState
    from provisioners.vyos_shadow_receipt import ShadowHandoffObservation, ShadowPolicyReceipt, ShadowReceiptStatus
    from provisioners.uxg_enterprise_shadow_tunnel import complete_snapshot_fingerprint
    from provisioners.vyos import VyOSReconciler
    from ipaddress import IPv4Network

    gateway = _gateway(reachable=True)
    gateway.config["vyos_shadow"] = {"provisioning_enabled": "True"}
    gateway.config["vyos_applied"] = {"cfgversion": "ordinary"}
    gateway.config["vyos_firewall"] = {"enabled": "True"}
    backend = gateway.datacollector.backend = Mock(management_origin="https://192.0.2.10")
    backend.read_config.return_value = _vrrp_config()
    backend.show_vrrp_detail.return_value = _vrrp_detail("MASTER", "MASTER")
    backend.show_kernel_interfaces.return_value = [_row("eth3", ("192.0.2.1", 24)), _row("eth1", ("198.18.240.1", 24))]
    commit_proof = Mock()
    gateway.vyos_provisioner = VyOSReconciler(
        backend, interfaces={IPv4Network("192.0.2.0/24"): "eth3", IPv4Network("198.18.240.0/24"): "eth1"},
        state_path=tmp_path / "router.json", rule_base=80200, commit_proof=commit_proof,
    )
    identity = ShadowManagementIdentity(gateway.config["gateway"]["lan_mac"], backend.management_origin, "SHA256:" + "A" * 43)
    target = "a" * 64
    revision = "native-complete-r2"
    boot = "12345678-90ab-4def-8123-4567890abcde"
    transaction = "cdbb26bb-183f-464c-b9bb-4c7094e20207"
    system_cfg = '{"udapi":{"services":{"stunnel":{"enabled":true}}},"other":[1,2]}'
    record = {
        "phase": "primary_active", "target": target, "revision": sha256(json.dumps([target, revision]).encode()).hexdigest(),
        "controller_revision": revision,
        "primary_identity_sha256": sha256(json.dumps(asdict(identity), sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "boot_id": boot, "transaction": transaction, "receipt_generation": "b" * 64,
        "config_sha256": "c" * 64, "saved_sha256": "d" * 64, "final_saved_sha256": "e" * 64,
        "staged_sha256": "f" * 64, "outside_sha256": "1" * 64, "policy_sha256": "2" * 64, "receipt_id": "3" * 64,
        "complete_snapshot_sha256": complete_snapshot_fingerprint(system_cfg),
    }
    if loss == "revision":
        record["controller_revision"] = "forged-revision"
    if loss == "unbound":
        del record["complete_snapshot_sha256"]
    live_boot = transaction if loss in ("cold-boot", "cold-drift") else boot
    commit_proof.return_value = (live_boot, "9" * 64 if loss == "cold-drift" else record["staged_sha256"])
    with gateway.vyos_provisioner.locked_state() as journal:
        journal["shadow_handoff"] = record
        gateway.vyos_provisioner._write_state(journal, durable=True)
    client = gateway._shadow_peer_probe.receipt_client.return_value
    client.management_identity = identity if loss != "identity" else ShadowManagementIdentity(
        identity.mac, identity.https_origin, "SHA256:" + "B" * 43,
    )
    accepted = ShadowPolicyReceipt(record["receipt_id"], record["policy_sha256"], transaction, record["staged_sha256"])
    slot = ShadowReceiptStatus(record["receipt_generation"], accepted)
    client.status.side_effect = [slot, ShadowReceiptStatus(slot.generation, None) if loss == "receipt" else slot]
    client.observe_handoff_state.return_value = ShadowHandoffObservation(
        ShadowStockState({}, {}, {}), "unknown" if loss == "address" else "master",
        transaction if loss == "boot" else live_boot,
        record["final_saved_sha256"], record["staged_sha256"], "reboot", "saved_commit",
    )
    return gateway, client, record, system_cfg


@pytest.mark.parametrize("loss", [None, "boot", "cold-boot", "cold-drift", "receipt", "identity", "address", "revision", "unbound"])
def test_shadow_inform_acknowledges_only_a_fresh_journaled_primary(tmp_path, loss):
    gateway, client, record, _ = _active_primary_gateway(tmp_path, loss)
    payload = _inform_cycle(gateway)

    verified = loss in (None, "cold-boot")
    assert payload["vrrp"]["state"] == ("master" if verified else "unknown")
    expected = record["controller_revision"] if verified else "ordinary"
    assert payload.get("cfgversion_effective") == payload.get("cfgversion") == expected
    if verified:
        client.observe_handoff_state.assert_called_once_with(
            gateway.datacollector.backend, gateway.vyos_provisioner.commit_proof, phase="saved_commit",
            expected_boot_id=record["transaction"] if loss == "cold-boot" else record["boot_id"],
            expected_saved_sha256=record["final_saved_sha256"],
        )


@pytest.mark.parametrize("change", [None, "payload", "duplicate-key", "receipt", "bad-tag", "legacy-frame"])
def test_repeated_complete_from_authenticated_inform_uses_only_readback(tmp_path, monkeypatch, change):
    from itertools import repeat
    from provisioners.vyos_shadow_receipt import ShadowReceiptStatus
    from unifi_protocol import decode_inform

    gateway, client, record, system_cfg = _active_primary_gateway(tmp_path)
    slot = client.status.side_effect.__next__()
    client.status.side_effect = repeat(slot)
    gateway._handle_response = Mock()
    gateway._notify_vyos_provisioning_error = Mock()
    gateway._vyos_provisioning_error = None
    document = json.loads(system_cfg)
    if change == "payload":
        document["other"].reverse()
    body = json.dumps(document, sort_keys=True, indent=2)
    if change == "duplicate-key":
        body = '{"other":0,' + body[1:]
    if change == "receipt":
        client.status.side_effect = [slot, slot, ShadowReceiptStatus(slot.generation, None)]
    response = {
        "_type": "setparam", "cfgversion": record["controller_revision"], "system_cfg": body, "interval": 15,
    }
    if change == "legacy-frame":
        gateway.config["gateway"]["use_aes_gcm"] = "False"
    gateway.config["gateway"]["key"] = "1" * 32
    frame = encode_inform(gateway.config, json.dumps(response))
    gateway.config["gateway"]["use_aes_gcm"] = "True"
    if change == "bad-tag":
        frame = frame[:-1] + bytes([frame[-1] ^ 1])

    def exchange(request, *, timeout):
        assert timeout == 30
        assert decode_inform(gateway.config, request.data, require_gcm=True)["model"] == "UXGENT"
        return SimpleNamespace(read=lambda: frame)

    monkeypatch.setattr("unifi_gateway.urllib.request.urlopen", exchange)
    del gateway._send_inform
    state = gateway.vyos_provisioner.state_path.read_bytes()
    gateway._speedtest_reports = deque()
    gateway._speedtest_completed = None
    gateway._vyos_restart = None
    if change in {"bad-tag", "legacy-frame"}:
        with pytest.raises(ValueError):
            gateway._exchange_inform()
    else:
        gateway._exchange_inform()
    gateway._handle_response.assert_not_called()
    if change is None:
        gateway._notify_vyos_provisioning_error.assert_not_called()
        assert gateway.interval == 15 and client.observe_handoff_state.call_count == 2
    elif change in {"payload", "duplicate-key", "receipt"}:
        gateway._notify_vyos_provisioning_error.assert_called_once_with()
    else:
        gateway._notify_vyos_provisioning_error.assert_not_called()
    assert gateway.vyos_provisioner.state_path.read_bytes() == state
    gateway.datacollector.backend.stage_configuration.assert_not_called()
    gateway.datacollector.backend.save_configuration.assert_not_called()
    client.publish.assert_not_called()


def test_shadow_inform_invalidates_the_prior_role_on_an_unavailable_observation():
    gateway = _gateway(reachable=True)
    backend = Mock()
    gateway.datacollector.backend = backend
    backend.read_config.return_value = _vrrp_config()
    backend.show_vrrp_detail.side_effect = [_vrrp_detail("MASTER", "MASTER"), VyOSReadError("no VRRP data")]
    backend.show_kernel_interfaces.return_value = [_row("eth3", ("192.0.2.1", 24)), _row("eth1", ("198.18.240.1", 24))]

    assert _inform_cycle(gateway)["vrrp"] == {"state": "master"}
    assert _inform_cycle(gateway)["vrrp"] == {"state": "unknown"}


@pytest.mark.parametrize("address_state", [{}, {"tentative": True}, {"dadfailed": True}])
def test_shadow_role_uses_the_configured_vip_device_and_rejects_unready_ipv6(address_state):
    gateway = _gateway(reachable=True)
    backend = gateway.datacollector.backend = Mock()
    backend.read_config.return_value = {
        "sync-group": {"UXGHA": {"member": "UXGLAN"}},
        "group": {"UXGLAN": {"interface": "eth3", "vrid": "42", "excluded-address": {
            "2001:db8::1/64": {"interface": "br0"},
        }}},
    }
    backend.show_vrrp_detail.return_value = _vrrp_detail("MASTER", "FAULT")
    backend.show_kernel_interfaces.return_value = [
        _row("eth3"), {**_row("br0"), "addr_info": [
            {"family": "inet6", "local": "2001:db8::1", "prefixlen": 64, **address_state},
        ]},
    ]

    assert _inform_cycle(gateway)["vrrp"] == {"state": "unknown" if address_state else "master"}


@pytest.mark.parametrize("options", [{"model": "UNKNOWN"}, {"authenticated": False}, {"enrolled": False}])
def test_other_enrollments_do_not_observe_or_advertise_shadow_role(options):
    gateway = _gateway(reachable=True, **options)
    gateway.datacollector.backend = Mock()

    if "model" in options:
        with pytest.raises(ValueError, match="requires model UXGENT"):
            _inform_cycle(gateway)
    else:
        assert "vrrp" not in _inform_cycle(gateway)
    assert gateway.datacollector.backend.mock_calls == []


def test_prepared_shadow_gateways_require_authenticated_inform_replies(monkeypatch):
    gateway = _gateway(reachable=True)
    gateway._vyos_restart = None
    gateway.config["gateway"]["key"] = "0123456789abcdef0123456789abcdef"
    encoded = encode_inform(gateway.config, json.dumps(REQUEST))
    gateway.config["gateway"]["use_aes_gcm"] = "False"
    legacy = encode_inform(gateway.config, json.dumps(REQUEST))
    gateway.config["gateway"]["use_aes_gcm"] = "True"
    response = Mock()
    response.read.side_effect = [encoded, legacy]
    monkeypatch.setattr("unifi_gateway.urllib.request.urlopen", Mock(return_value=response))

    assert UnifiGateway._send_inform(gateway, "{}") == REQUEST
    with pytest.raises(ValueError, match="requires authenticated AES-GCM"):
        UnifiGateway._send_inform(gateway, "{}")


def test_shadow_readiness_is_suppressed_until_the_address_revision_is_verified():
    gateway = _gateway(reachable=True)
    gateway.config.read_dict({
        "gateway": {"ports": json.dumps([
            {"ifname": "eth1", "name": "LAN", "type": "lan", "realif": "eth6", "port_idx": 2},
        ])},
        "vyos_firewall": {"enabled": True},
        "vyos_shadow": {"provisioning_enabled": True},
    })
    gateway.datacollector.data = {
        "links": {"eth1": {"enable": True, "up": True}},
        "ip": {"eth1": {"address": "169.254.254.3", "netmask": "255.255.255.0"}},
        "ipv4": {"eth1": ["169.254.254.3/24"]},
    }

    staged = json.loads(create_inform(gateway.config, gateway.datacollector))
    assert staged["network_table"] == []
    gateway._handle_response(REQUEST)
    gateway._shadow_peer_probe.reachable.assert_not_called()
    rejected = json.loads(gateway._send_inform.call_args.args[0])["notif_payload"]
    assert rejected["status"]["flags"]["peer_connection_test"]["ping"] is False

    gateway.config.read_dict({"vyos_applied": {"cfgversion": "verified"},
                              "vyos_shadow_applied": {"address": "169.254.254.3/24"}})
    published = json.loads(create_inform(gateway.config, gateway.datacollector))
    assert published["network_table"][0]["addresses"] == ["169.254.254.3/24"]
    gateway._handle_response(REQUEST)
    gateway._shadow_peer_probe.reachable.assert_called_once_with(is_secondary=True)


@pytest.mark.parametrize(("role", "source", "target"), [
    ("primary", "169.254.254.2", "169.254.254.3"),
    ("secondary", "169.254.254.3", "169.254.254.2"),
])
def test_router_probe_uses_a_bounded_count_and_the_fixed_link_for_each_role(monkeypatch, role, source, target):
    script = Path(__file__).resolve().parents[1] / "scripts/vyos-shadow-peer.py"
    monkeypatch.setattr("sys.argv", [str(script), "eth6"])
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", f"/bin/false uxg-shadow-peer-{role}")
    execute = Mock()
    monkeypatch.setattr("os.execve", execute)

    runpy.run_path(str(script), run_name="__main__")

    execute.assert_called_once_with(
        "/usr/bin/ping",
        ["/usr/bin/ping", "-4", "-n", "-q", "-I", "eth6", "-I", source,
         "-c", "3", "-i", "0.2", "-W", "1", target],
        {"LC_ALL": "C"},
    )


@pytest.mark.parametrize(("command", "peer", "allowed"), [
    ("/bin/false uxg-shadow-lan-peer", "192.0.2.3", True),
    ("/bin/false uxg-shadow-lan-peer 192.0.2.4", "192.0.2.3", False),
    ("/bin/false uxg-shadow-lan-peer", "198.51.100.3", False),
    ("/bin/false uxg-shadow-lan-peer", "192.0.2.2", False),
])
def test_router_lan_peer_probe_is_fixed_to_the_enrolled_addresses(monkeypatch, command, peer, allowed):
    script = Path(__file__).resolve().parents[1] / "scripts/vyos-shadow-peer.py"
    monkeypatch.setattr("sys.argv", [str(script), "eth6", "br0", "192.0.2.0/24", "192.0.2.7", "192.0.2.2", peer])
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", command)
    execute = Mock()
    monkeypatch.setattr("os.execve", execute)

    if allowed:
        runpy.run_path(str(script), run_name="__main__")
        execute.assert_called_once_with(
            "/usr/bin/ping", ["/usr/bin/ping", "-4", "-n", "-q", "-I", "br0", "-I", "192.0.2.2",
                              "-c", "3", "-i", "0.2", "-W", "1", "192.0.2.3"], {"LC_ALL": "C"},
        )
    else:
        with pytest.raises(SystemExit):
            runpy.run_path(str(script), run_name="__main__")
        execute.assert_not_called()


def _row(interface, *addresses, flags=("UP", "LOWER_UP")):
    return {"ifname": interface, "flags": list(flags), "addr_info": [
        {"family": "inet", "local": address, "prefixlen": prefix} for address, prefix in addresses
    ]}


@pytest.fixture
def shadow_probe(monkeypatch):
    config = ConfigParser()
    config.read_dict({
        "vyos": {"api_url": "https://192.0.2.1"},
        "vyos_shadow": {"ssh_user": "gwprobe", "ssh_key_file": "/key", "ssh_known_hosts_file": "/pin"},
    })
    ssh = Mock(return_value=["/usr/bin/ssh", "/bin/false"])
    monkeypatch.setattr("gateway_profiles.uxg_enterprise_shadow.vyos_ssh_command", ssh)
    runner = Mock()
    monkeypatch.setattr("gateway_profiles.uxg_enterprise_shadow._run_helper", runner)
    backend = VyOSBackend.__new__(VyOSBackend)
    backend._show = Mock()
    ports = [{"ifname": "eth1", "port_idx": 2, "type": "lan", "realif": "eth6"}]
    return config, ports, backend, runner, ssh


def test_shadow_management_identity_uses_the_actual_https_backend_and_ssh_pin(shadow_probe, monkeypatch):
    config, ports, backend, _, _ = shadow_probe
    config.read_dict({"gateway": {"device": "UXGENT", "platform": "vyos", "is_adopted": True,
                                  "use_aes_gcm": True, "lan_mac": "02:00:00:00:00:04"}})
    backend._origin = "https://192.0.2.1"
    fingerprint = Mock(return_value="SHA256:" + "A" * 43)
    monkeypatch.setattr("gateway_profiles.uxg_enterprise_shadow.vyos_ssh_host_fingerprint", fingerprint)
    probe = ShadowPeerProbe(backend, ports, config)
    identity = probe.management_identity()
    assert (identity.mac, identity.https_origin, identity.ssh_host_key) == (
        "02:00:00:00:00:04", backend._origin, fingerprint.return_value,
    )
    fingerprint.assert_called_once_with("192.0.2.1", 22, "/pin")
    backend._origin = "https://192.0.2.1:1234"
    with pytest.raises(ValueError, match="management endpoint"):
        probe.management_identity()
    backend._origin = "https://192.0.2.1"
    config.set("gateway", "use_aes_gcm", "false")
    with pytest.raises(ValueError, match="AES-GCM enrollment"):
        probe.management_identity()

@pytest.mark.parametrize("kind", ["replied", "disconnected", "wrong-source", "changed-address"])
def test_peer_check_verifies_live_binding_and_the_returned_packet_sample(shadow_probe, kind):
    config, ports, backend, runner, ssh = shadow_probe
    before = [_row("eth6", ("169.254.254.3", 24)), _row("eth0", ("192.0.2.1", 24))]
    backend._show.side_effect = [json.dumps(before), json.dumps([] if kind == "changed-address" else before)]
    source = "192.0.2.1" if kind == "wrong-source" else "169.254.254.3"
    received = 0 if kind == "disconnected" else 1
    runner.return_value = (
        f"PING 169.254.254.2 (169.254.254.2) from {source} eth6: 56(84) bytes of data.\n\n"
        "--- 169.254.254.2 ping statistics ---\n"
        f"3 packets transmitted, {received} received, 66.6667% packet loss, time 403ms\n"
        .encode() + (b"rtt min/avg/max/mdev = 1.100/1.100/1.100/0.000 ms\n" if received else b""),
        0 if received else 1,
    )
    probe = ShadowPeerProbe(backend, ports, config)

    if kind == "wrong-source":
        with pytest.raises(VyOSReadError, match="matching measurement"):
            probe.reachable(is_secondary=True)
    else:
        assert probe.reachable(is_secondary=True) is (kind == "replied")
    ssh.assert_called_once_with("192.0.2.1", 22, "gwprobe", "/key", "/pin")
    assert runner.call_args.args[0] == ["/usr/bin/ssh", "/bin/false uxg-shadow-peer-secondary"]
    assert backend._show.call_args.args[0] == ["interfaces", "kernel", "json"]


@pytest.mark.parametrize("kind", ["healthy", "wrong-route", "wrong-source", "moved-after-probe"])
def test_lan_peer_check_requires_the_mapped_lan_and_exact_bound_addresses(shadow_probe, kind):
    config, ports, backend, runner, _ = shadow_probe
    ports.append({"ifname": "br0", "realif": "br10"})
    rows = [_row("eth6", ("169.254.254.3", 24)), _row("br10", ("192.0.2.3", 24))]
    moved = [_row("eth6", ("169.254.254.3", 24)), _row("eth4", ("192.0.2.3", 24))]
    backend._show.side_effect = [json.dumps(moved if kind == "wrong-route" else rows),
                                 json.dumps(moved if kind == "moved-after-probe" else rows)]
    source = "192.0.2.1" if kind == "wrong-source" else "192.0.2.3"
    runner.return_value = ((
        f"PING 192.0.2.2 (192.0.2.2) from {source} br10: 56(84) bytes of data.\n\n"
        "--- 192.0.2.2 ping statistics ---\n"
        "3 packets transmitted, 3 received, 0% packet loss, time 403ms\n"
        "rtt min/avg/max/mdev = 1.100/1.100/1.100/0.000 ms\n"
    ).encode(), 0)
    probe = ShadowPeerProbe(backend, ports, config)
    local, peer = map(IPv4Interface, ("192.0.2.3/24", "192.0.2.2/24"))

    if kind == "wrong-source":
        with pytest.raises(VyOSReadError, match="matching measurement"):
            probe.lan_peer_reachable(local, peer)
    else:
        assert probe.lan_peer_reachable(local, peer) is (kind == "healthy")
    if kind == "wrong-route":
        runner.assert_not_called()
    else:
        assert runner.call_args.args[0] == ["/usr/bin/ssh", "/bin/false uxg-shadow-lan-peer"]


@pytest.mark.parametrize("rows", [
    [_row("eth6", ("169.254.254.2", 24)), _row("eth0", ("169.254.254.3", 24))],
    [_row("eth6", ("169.254.254.3", 32))],
    [_row("eth6", ("169.254.254.3", 24), flags=("UP",))],
    [_row("eth6", ("169.254.254.3", 24)) | {"master": "br0"}],
    [_row("eth6", ("169.254.254.3", 24)), _row("eth0", ("169.254.254.2", 24))],
])
def test_peer_probe_needs_the_exact_remote_and_local_address_mapping(shadow_probe, rows):
    config, ports, backend, runner, _ = shadow_probe
    backend._show.return_value = json.dumps(rows)

    assert ShadowPeerProbe(backend, ports, config).reachable(is_secondary=True) is False
    runner.assert_not_called()


def test_router_lan_source_probe_uses_two_unbound_read_only_kernel_lookups(monkeypatch, capsys):
    script = Path(__file__).resolve().parents[1] / "scripts/vyos-shadow-peer.py"
    monkeypatch.setattr("sys.argv", [str(script), "eth6", "eth3", "192.0.2.0/24", "192.0.2.2"])
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "/bin/false uxg-shadow-lan-source")
    fib = {"dst": "192.0.2.0/24", "dev": "eth3", "protocol": "kernel", "scope": "link", "prefsrc": "192.0.2.1"}
    route = {"dst": "192.0.2.2", "dev": "eth3", "prefsrc": "192.0.2.1", "uid": 1001, "cache": []}
    execute = Mock(side_effect=[SimpleNamespace(stdout=json.dumps([row]).encode()) for row in (fib, route)])
    monkeypatch.setattr("subprocess.run", execute)

    runpy.run_path(str(script), run_name="__main__")

    command = ["/usr/sbin/ip", "-j", "-4", "route", "get"]
    assert [call.args[0] for call in execute.call_args_list] == [
        [*command, "fibmatch", "192.0.2.2"], [*command, "192.0.2.2"],
    ]
    assert json.loads(capsys.readouterr().out) == {"fib": fib, "route": route}


@pytest.mark.parametrize(("operation", "arguments"), [
    ("/bin/false uxg-shadow-lan-source 192.0.2.2", ["eth6", "eth3", "192.0.2.0/24", "192.0.2.2"]),
    ("/bin/false uxg-shadow-lan-source", ["eth6"]),
    ("/bin/false uxg-shadow-lan-source", ["eth6", "eth3", "192.0.2.0/24", "198.51.100.2"]),
])
def test_router_lan_source_rejects_unpinned_requests_without_running_ip(monkeypatch, operation, arguments):
    script = Path(__file__).resolve().parents[1] / "scripts/vyos-shadow-peer.py"
    monkeypatch.setattr("sys.argv", [str(script), *arguments])
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", operation)
    execute = Mock()
    monkeypatch.setattr("subprocess.run", execute)
    monkeypatch.setattr("os.execve", execute)

    with pytest.raises(SystemExit):
        runpy.run_path(str(script), run_name="__main__")

    execute.assert_not_called()


@pytest.mark.parametrize(("status", "fib_change", "route_change"), [
    (0, {}, {}),
    (1, {}, {}),
    (0, {"dst": "192.0.2.0/25"}, {}),
    (0, {"protocol": "static"}, {}),
    (0, {"table": 181}, {}),
    (0, {"scope": "host"}, {}),
    (0, {"flags": ["linkdown"]}, {}),
    (0, {"gateway": "192.0.2.254"}, {}),
    (0, {}, {"dev": "eth4"}),
    (0, {}, {"dst": "192.0.2.3"}),
    (0, {}, {"prefsrc": "192.0.2.254"}),
    (0, {"prefsrc": "198.51.100.1"}, {"prefsrc": "198.51.100.1"}),
    (0, {}, {"from": "192.0.2.1"}),
])
def test_lan_source_requires_the_exact_connected_route_and_unbound_resolution(shadow_probe, status, fib_change, route_change):
    config, ports, backend, runner, _ = shadow_probe
    fib = {"dst": "192.0.2.0/24", "dev": "eth3", "protocol": "kernel", "scope": "link",
           "prefsrc": "192.0.2.1", "flags": []} | fib_change
    route = {"dst": "192.0.2.2", "dev": "eth3", "prefsrc": "192.0.2.1",
             "uid": 1001, "flags": [], "cache": []} | route_change
    runner.return_value = json.dumps({"fib": fib, "route": route}).encode(), status
    probe = ShadowPeerProbe(backend, ports, config)

    if status or fib_change or route_change:
        with pytest.raises(VyOSReadError, match="Shadow LAN"):
            probe.lan_preferred_source("192.0.2.0/24", interface="eth3", destination="192.0.2.2")
    else:
        assert probe.lan_preferred_source("192.0.2.0/24", interface="eth3", destination="192.0.2.2") == "192.0.2.1"
    assert runner.call_args.args[0] == ["/usr/bin/ssh", "/bin/false uxg-shadow-lan-source"]
    assert runner.call_args.kwargs["limit"] == 4096


def test_lan_source_requires_the_configured_br0_mapping_when_present(shadow_probe):
    config, ports, backend, runner, _ = shadow_probe
    ports.append({"ifname": "br0", "type": "lan", "realif": "eth4"})
    probe = ShadowPeerProbe(backend, ports, config)

    with pytest.raises(ValueError, match="mapped VyOS Shadow LAN"):
        probe.lan_preferred_source("192.0.2.0/24", interface="eth3", destination="192.0.2.2")

    runner.assert_not_called()


@pytest.mark.parametrize("extra", [b'"dev":"eth3"', b'"metric":NaN'])
def test_lan_source_rejects_ambiguous_json(shadow_probe, extra):
    config, ports, backend, runner, _ = shadow_probe
    runner.return_value = (
        b'{"fib":{"dst":"192.0.2.0/24","dev":"eth3","protocol":"kernel","scope":"link","prefsrc":"192.0.2.1"},'
        b'"route":{"dst":"192.0.2.2","dev":"eth3","prefsrc":"192.0.2.1",' + extra + b"}}", 0,
    )
    probe = ShadowPeerProbe(backend, ports, config)

    with pytest.raises(VyOSReadError, match="invalid JSON"):
        probe.lan_preferred_source("192.0.2.0/24", interface="eth3", destination="192.0.2.2")


def test_lan_source_reports_json_decoder_recursion_as_a_read_failure(shadow_probe, monkeypatch):
    config, ports, backend, runner, _ = shadow_probe
    runner.return_value = b"{}", 0
    decoder = SimpleNamespace(loads=Mock(side_effect=RecursionError))
    monkeypatch.setattr("gateway_profiles.uxg_enterprise_shadow.json", decoder)

    with pytest.raises(VyOSReadError, match="invalid JSON"):
        ShadowPeerProbe(backend, ports, config).lan_preferred_source(
            "192.0.2.0/24", interface="eth3", destination="192.0.2.2",
        )
