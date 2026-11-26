"""Exercise the installed primary assembly and its restart path."""

from configparser import RawConfigParser
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from ipaddress import IPv4Network, ip_interface
import json
from pathlib import Path
import os
import signal
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from backends.vyos import VyOSReadError
from gateway_profiles import vyos_shadow_runtime as runtime
from gateway_profiles.vyos_install import load_enrolled_config
from provisioners.vyos_shadow_binding import ShadowEnrolledNode, ShadowEnrollmentPair, ShadowManagementIdentity
from provisioners.vyos_shadow_complete import ShadowElection, ShadowNode, ShadowStockState
from provisioners.vyos import VyOSReconciler
from unifi_gateway import UnifiGateway, main


@pytest.mark.parametrize("resumed", [False, True])
def test_primary_runtime_uses_current_peer_and_the_correct_primary_preimage(tmp_path, monkeypatch, resumed):
    config, standby_config = RawConfigParser(), RawConfigParser()
    for node, address in ((config, "192.0.2.2/24"), (standby_config, "192.0.2.3/24")):
        node.read_dict({
            "vyos_shadow": {"lan_election_address": address},
            "vyos_restart": {"ssh_known_hosts_file": "/known-hosts"},
        })
    config.read_dict({
        "vyos_shadow_primary": {
            "controller_origin": "https://controller.test", "site": "lab", "site_id": "site",
            "controller_ca_file": "/ca", "controller_session_file": "/cookie",
            "forwarding_probe": "/probe", "lan_probe_destination": "192.0.2.50",
        },
        "vyos_shadow_applied": {"reference": '{"lan_preimage":{"addresses":[{"cidr":"192.0.2.1/24"}]}}'},
    })
    writers, probes = [], []
    for number in (1, 2):
        state_path = tmp_path / str(number) / "firewall.json"
        state_path.parent.mkdir()
        writer = Mock(state_path=state_path)
        writer.commit_proof.return_value = (f"boot-{number}", f"hash-{number}")
        probe = Mock(interface="eth2")
        probe.management_identity.return_value = ShadowManagementIdentity(
            f"02:00:00:00:00:0{number}", f"https://router-{number}.test", f"pin-{number}",
        )
        probe.receipt_client.return_value.observe_handoff_state.return_value = SimpleNamespace(
            state=f"projected-{number}", boot_id=f"boot-{number}", config_sha256=f"hash-{number}",
        )
        writers.append(writer)
        probes.append(probe)
    primary, peer = writers
    primary_probe, standby_probe = probes
    primary_probe.lan_preferred_source.return_value = "192.0.2.1"
    stock = {"firewall": {"group": {"network-group": {"OPERATOR": {}}}}}
    primary.backend.read_complete_configuration.return_value = stock
    primary.backend.show_kernel_interfaces.return_value = [{"ifname": "br0", "addr_info": [
        {"family": "inet6", "scope": "link", "local": "fe80::2"},
        {"family": "inet6", "scope": "link", "local": "fe80::3", "flags": ["tentative"]},
    ]}]
    reservation = {"phase": "saving"} if resumed else None
    primary.locked_state.return_value = nullcontext({"shadow_handoff": reservation})
    controller = Mock()
    monkeypatch.setattr(runtime, "ShadowControllerReader", Mock(return_value=controller))
    monkeypatch.setattr(runtime, "vyos_ssh_host_fingerprint",
                        lambda host, *_: {"router-1.test": "pin-1", "router-2.test": "pin-2"}[host])
    election = SimpleNamespace(virtual_ips=(("br0", ip_interface("192.0.2.1/24")),))
    authenticate = Mock(return_value=SimpleNamespace(election=election))
    monkeypatch.setattr(runtime, "verify_bound_shadow_primary_complete", authenticate)
    compile_plan, transfer = Mock(), Mock()
    monkeypatch.setattr(runtime, "prepare_bound_shadow_primary_lan_handoff", compile_plan)
    monkeypatch.setattr(runtime, "ShadowPrimaryTransfer", transfer)
    ports = [{"ifname": "br0", "realif": "br0"}]
    installed = runtime.ShadowPrimaryRuntime(config, ports, primary, primary_probe, standby_config, ports, peer, standby_probe)
    observation = (primary_probe.management_identity(), {"system_cfg": "authenticated"})
    assert installed.prepare(observation) == transfer.return_value
    authenticate.assert_called_once_with(controller.read_pair.return_value, authenticated_response=observation)
    assert transfer.call_args.args[:2] == (primary, peer)
    inputs = compile_plan.call_args.kwargs
    assert inputs["primary_lan_link_local"] == "fe80::2" and inputs["peer"] == "projected-2"
    assert inputs["reservation"] == reservation
    if resumed:
        assert inputs["local"] is inputs["stock_configuration"] is inputs["route_source"] is None
        primary.commit_proof.assert_not_called()
        primary_probe.lan_preferred_source.assert_not_called()
    else:
        assert inputs["local"] == "projected-1" and inputs["stock_configuration"] == stock
        assert inputs["route_source"] == "192.0.2.1"
        assert primary.commit_proof.call_count == 2


def test_standby_complete_plans_with_ordinary_feature_decoders_under_the_pair_locks(tmp_path, monkeypatch):
    path = Path(__file__).parent / "fixtures/uxg_pro/zbf-native-actions.json"
    ordinary = json.loads(path.read_text())["snapshots"]["udp-block-range"]
    document = json.loads(ordinary["system_cfg"])
    udapi = document["udapi"]
    udapi["versionDetail"].update({"services/vrrp": 5, "services/stunnel": 1})
    udapi.setdefault("services", {}).update({"vrrp": {"enabled": True}, "stunnel": {"enabled": True}})
    udapi["interfaces"] = [
        {"identification": {"id": "br0", "type": "bridge"}, "bridge": {"interfaces": []}, "addresses": [
            {"type": "dynamic", "cidr": None, "origin": "vrrp", "eui64": False, "version": "v4"},
        ]},
        {"identification": {"id": "eth1", "type": "ethernet"}, "status": {"enabled": True, "comment": "MGMT_SHADOW"},
         "addresses": [{"type": "static", "cidr": "169.254.254.3/24", "version": "v4"}]},
    ]
    election = ShadowElection("169.254.254.3", "169.254.254.2", 100, (("br0", ip_interface("192.0.2.1/24")),),
                              ("br0", "fe80::2"))

    gateway = UnifiGateway.__new__(UnifiGateway)
    gateway.vyos_provisioner = VyOSReconciler(
        Mock(), interfaces={IPv4Network("192.0.2.0/24"): "eth0", IPv4Network("198.51.100.0/24"): "eth1"},
        state_path=tmp_path / "firewall.json", rule_base=80200,
    )
    gateway.vyos_inspection = gateway.controller_broker_trust = None
    gateway._stock_inspection = False
    installed = runtime.ShadowPrimaryRuntime.__new__(runtime.ShadowPrimaryRuntime)
    installed._peer_writer = Mock()
    installed._peer_receipt = Mock()
    installed._nodes = (
        ShadowNode("eth2", "169.254.254.2/24", {"br0": "eth3"}, "192.0.2.2/24"),
        ShadowNode("eth2", "169.254.254.3/24", {"br0": "eth3"}, "192.0.2.3/24"),
    )
    ordinary_port = {"identification": {"id": "eth1", "type": "ethernet"}, "status": {"enabled": True}}
    members = [{"id": "eth1"}]
    installed._standby_config = RawConfigParser()
    installed._standby_config.read_dict({"vyos_shadow_applied": {
        "reference": json.dumps({"port": ordinary_port, "memberships": {"br0": members}}),
    }})
    state = {"verified_revision": "standby-phase-one"}
    inside_locks = False

    @contextmanager
    def verified(observation):
        nonlocal inside_locks
        assert observation[1]["cfgversion"] == ordinary["cfgversion"]
        inside_locks = True
        yield {}, state, Mock(return_value=SimpleNamespace(election=election))
        inside_locks = False

    def plan(intent, journal, **options):
        assert inside_locks and journal is state
        rule, = intent.rules
        assert rule.port == "18443-18444" and rule.protocol == "udp" and rule.action == "drop"
        assert intent.revision == ordinary["cfgversion"] and options["nat_intent"] is None
        return "standby-plan"

    monkeypatch.setattr(installed, "_locked_standby_response", verified)
    installed._peer_writer.plan_shadow_standby_policy.side_effect = plan
    observation = ("standby", ordinary | {"system_cfg": json.dumps(document)})
    preview, outside_scope = installed.plan_standby_response(observation, decode_policy=gateway._decode_vyos_policy)
    del udapi["services"]
    del udapi["versionDetail"]["services/vrrp"], udapi["versionDetail"]["services/stunnel"]
    udapi["interfaces"][0]["bridge"]["interfaces"] = members
    udapi["interfaces"][0]["addresses"] = [{"type": "static", "cidr": "192.0.2.1/24", "version": "v4"}]
    udapi["interfaces"][1] = ordinary_port
    expected = gateway._decode_vyos_policy(json.dumps(document), ordinary["cfgversion"])[-1]
    assert preview == "standby-plan" and outside_scope == expected

    def stage(writer, journal, receipt, *, plan, **args):
        assert inside_locks and journal is state and plan == "standby-plan"
        assert args["approved_outside_scope"] == args["outside_scope"] == expected
        assert writer is installed._peer_writer and receipt is installed._peer_receipt
        state[runtime.STANDBY_POLICY] = {"phase": "staged"}

    def confirm(_writer, journal, _receipt, **_args):
        assert inside_locks and journal is state
        assert state[runtime.STANDBY_POLICY]["phase"] in ("staged", "saved")
        state[runtime.STANDBY_POLICY] = {"phase": "saved"}
        return "saved-proof"

    stage_call, confirm_call = Mock(side_effect=stage), Mock(side_effect=confirm)
    monkeypatch.setattr(runtime, "stage_standby_policy", stage_call)
    monkeypatch.setattr(runtime, "confirm_and_save_standby_policy", confirm_call)

    def advance_election(_writer, journal, _receipt, election_plan, *, preimage, verify_primary, management_guard):
        assert inside_locks and journal is state
        assert preimage == ("saved-proof" if runtime.STANDBY_ELECTION not in journal else None)
        assert election_plan.group["priority"] == "100"
        assert verify_primary().election == election
        assert management_guard is None
        journal[runtime.STANDBY_ELECTION] = {"phase": "saved"}
        return "saved-election"

    election_call = Mock(side_effect=advance_election)
    def publish(_writer, journal, _receipt, _plan, *, verify_ready, **_activation):
        assert inside_locks and journal is state
        assert verify_ready == installed.verify_standby_readiness
        journal[runtime.STANDBY_ELECTION] = {"phase": "published"}

    publication = Mock(side_effect=publish)
    verify_backup = Mock(return_value="verified-backup")
    installed._standby_inform_binding = Mock(return_value="e" * 64)
    verify_policy_reservation = Mock()
    monkeypatch.setattr(runtime, "advance_standby_election", election_call)
    monkeypatch.setattr(runtime, "publish_standby_election", publication)
    monkeypatch.setattr(runtime, "verify_published_standby_election", verify_backup)
    monkeypatch.setattr(runtime, "_policy_reservation", verify_policy_reservation)
    for _ in range(2):
        assert installed.advance_standby_response(
            observation, decode_policy=gateway._decode_vyos_policy, approved_outside_scope=expected,
        ) == "verified-backup"
    stage_call.assert_called_once()
    confirm_call.assert_called_once()
    election_call.assert_called_once()
    publication.assert_called_once()
    assert verify_backup.call_count == 2
    verify_policy_reservation.assert_called_once()
    assert installed._peer_writer.plan_shadow_standby_policy.call_count == 2
    assert state["verified_revision"] == "standby-phase-one" and not inside_locks


@pytest.mark.parametrize("observed", ["reboot", "same-boot", "unsaved", "saved-then-rebooted"])
def test_standby_rollback_uses_old_checkpoint_and_current_pair(monkeypatch, observed):
    installed = runtime.ShadowPrimaryRuntime.__new__(runtime.ShadowPrimaryRuntime)
    installed._writer, installed._peer_writer = Mock(), Mock()
    installed._receipt, installed._peer_receipt = Mock(), Mock()
    installed._read_pair = Mock()
    installed._nodes = (
        ShadowNode("eth2", "169.254.254.2/24", {"br0": "eth3"}, "192.0.2.2/24"),
        ShadowNode("eth2", "169.254.254.3/24", {"br0": "eth3"}, "192.0.2.3/24"),
    )
    election = ShadowElection("169.254.254.3", "169.254.254.2", 100,
                              (("br0", ip_interface("192.0.2.1/24")),), ("br0", "fe80::2"))
    primary = {runtime.SHADOW_HANDOFF: {"phase": "primary_active"}}
    standby = {"verified_revision": "prepare", runtime.SHADOW_HANDOFF: {"phase": "standby"}, runtime.STANDBY_POLICY: {
        "phase": "saving" if observed == "saved-then-rebooted" else "staged",
        "boot_id": "old-boot", "config_sha256": "e" * 64, "staged_sha256": "f" * 64,
        "controller_revision": "old", "snapshot_sha256": "a" * 64, "outside_scope_sha256": "b" * 64,
        "mapped_resources_sha256": runtime._standby_mapping_digest(runtime.standby_resource_scope(election, installed._nodes)),
    }}
    installed._writer.locked_state.return_value = nullcontext(primary)
    installed._peer_writer.locked_state.return_value = nullcontext(standby)
    installed._writer.state_path = Path("/primary")
    installed._peer_writer.state_path = Path("/standby")
    if observed == "unsaved":
        installed._peer_writer.commit_proof.side_effect = VyOSReadError("Saved proof unavailable")
    else:
        installed._peer_writer.commit_proof.return_value = (
            "old-boot" if observed == "same-boot" else "new-boot",
            ("f" if observed == "saved-then-rebooted" else "e") * 64,
        )
    resources = Mock(return_value=SimpleNamespace(election=election))
    monkeypatch.setattr(runtime, "verify_standby_rollback_resources", resources)
    observation = ("standby", {"cfgversion": "new"})

    def recover(writer, state, receipt, *, revision, snapshot_sha256, verify_fenced, verify_primary,
                approved_outside_scope, outside_scope, mapped_resources_sha256):
        assert (writer, state, receipt) == (installed._peer_writer, standby, installed._peer_receipt)
        assert (revision, snapshot_sha256) == ("old", "a" * 64)
        assert approved_outside_scope == outside_scope == "b" * 64
        assert mapped_resources_sha256 == standby[runtime.STANDBY_POLICY]["mapped_resources_sha256"]
        verify_primary()
        preimage = ShadowStockState({}, {}, {
            "eth2": (ip_interface("169.254.254.3/24"),), "eth3": (ip_interface("192.0.2.3/24"),),
        })
        verify_fenced(preimage)
        return preimage

    recovery = Mock(side_effect=recover)
    monkeypatch.setattr(runtime, "recover_standby_policy_rollback", recovery)
    installed._standby_config = RawConfigParser()
    ordinary_verification = Mock(side_effect=ValueError("Controller replaced the policy"))
    monkeypatch.setattr(runtime, "verify_standby_complete", ordinary_verification)
    decode_policy = Mock()
    if observed != "reboot":
        with pytest.raises(ValueError, match="replaced the policy"):
            installed.advance_standby_response(observation, decode_policy=decode_policy, approved_outside_scope="b" * 64)
        recovery.assert_not_called()
        ordinary_verification.assert_called_once()
        return

    installed.advance_standby_response(observation, decode_policy=decode_policy, approved_outside_scope="b" * 64)
    decode_policy.assert_not_called()
    ordinary_verification.assert_not_called()
    recovery.assert_called_once()
    assert resources.call_count == 2
    assert all(call.kwargs["observation"] is observation for call in resources.call_args_list)
    assert all(call.kwargs["binding"] is installed._read_pair.return_value for call in resources.call_args_list)


@pytest.mark.parametrize("failure", [None, "primary-sync", "standby-sync", "primary-lan", "standby-lan", "no-vrrp"])
def test_standby_readiness_requires_bidirectional_lan_and_sync_and_primary_forwarding(failure):
    installed = runtime.ShadowPrimaryRuntime.__new__(runtime.ShadowPrimaryRuntime)
    installed._probe, installed._peer_probe = Mock(), Mock()
    installed._peer_receipt = Mock()
    installed._peer_receipt.observe_standby_vrrp.return_value = failure != "no-vrrp"
    installed._nodes = (
        ShadowNode("eth2", "169.254.254.2/24", {"br0": "eth3"}, "192.0.2.2/24"),
        ShadowNode("eth4", "169.254.254.3/24", {"br0": "eth5"}, "192.0.2.3/24"),
    )
    primary, standby = installed._probe, installed._peer_probe
    primary.reachable.return_value = failure != "primary-sync"
    standby.reachable.return_value = failure != "standby-sync"
    primary.lan_peer_reachable.return_value = failure != "primary-lan"
    standby.lan_peer_reachable.return_value = failure != "standby-lan"
    installed.verify_forwarding = Mock(return_value=True)

    binding = dict(boot_id="158dd3a3-dc93-4ae3-94b1-489e4f6ecc6d", config_sha256="a" * 64, generation="b" * 64)
    assert installed.verify_standby_readiness(**binding) is (failure is None)
    if failure not in (None, "no-vrrp"):
        installed.verify_forwarding.assert_not_called()
        installed._peer_receipt.observe_standby_vrrp.assert_not_called()
        return
    primary.reachable.assert_called_once_with(is_secondary=False)
    standby.reachable.assert_called_once_with(is_secondary=True)
    local, peer = map(ip_interface, ("192.0.2.2/24", "192.0.2.3/24"))
    primary.lan_peer_reachable.assert_called_once_with(local, peer)
    standby.lan_peer_reachable.assert_called_once_with(peer, local)
    installed.verify_forwarding.assert_called_once_with()
    installed._peer_receipt.observe_standby_vrrp.assert_called_once_with(
        **binding, interface="eth5", local=peer.ip, peer=local.ip,
    )


@pytest.mark.parametrize(("changed", "role", "is_standby"), [
    (None, "backup", True), ("desired-revision", "backup", True), ("device-record", "backup", True),
    ("pair-withdrawn", "backup", True), (None, "master", True), (None, "backup", False),
    (None, "master", False), ("initial", "master", False),
    ("exact-replay", "master", True), ("exact-replay", "backup", False),
    ("changed-replay", "master", True), ("wrong-replay-head", "backup", False),
])
def test_pair_inform_rechecks_the_durable_binding_and_requires_reciprocal_roles(monkeypatch, changed, role, is_standby):
    installed = runtime.ShadowPrimaryRuntime.__new__(runtime.ShadowPrimaryRuntime)
    installed._writer, installed._peer_writer = Mock(state_path=Path("/primary")), Mock(state_path=Path("/standby"))
    installed._receipt, installed._peer_receipt = Mock(), Mock()
    installed._nodes = (
        ShadowNode("eth2", "169.254.254.2/24", {"br0": "eth3"}, "192.0.2.2/24"),
        ShadowNode("eth4", "169.254.254.3/24", {"br0": "eth5"}, "192.0.2.3/24"),
    )
    primary, standby = (ShadowEnrolledNode(
        f"device-{n}", ShadowManagementIdentity(f"02:00:00:00:00:0{n}", f"https://router-{n}.test", f"pin-{n}"),
        f"revision-{n}",
    ) for n in (1, 2))
    pair = ShadowEnrollmentPair("site", "dev-build", primary, standby, "SETUP_COMPLETED")
    later = {
        None: pair,
        "desired-revision": replace(pair, standby=replace(standby, desired_revision="new-intent")),
        "device-record": replace(pair, standby=replace(standby, device_id="replacement")),
        "pair-withdrawn": replace(pair, state="UNPAIRED"),
        "initial": pair,
        "exact-replay": pair,
        "changed-replay": pair,
        "wrong-replay-head": pair,
    }[changed]
    installed._read_pair = Mock(side_effect=[pair, later])
    primary_cfg, standby_cfg = '{"device":"primary","state":1}', '{"device":"standby","state":1}'
    primary_record = {"phase": "primary_active", "controller_revision": "revision-1",
                      "complete_snapshot_sha256": runtime.complete_snapshot_fingerprint(primary_cfg)}
    standby_record = {"phase": "standby"}
    installed._writer.locked_state.return_value = nullcontext({runtime.SHADOW_HANDOFF: primary_record})
    standby_journal = {runtime.SHADOW_HANDOFF: standby_record}
    if changed != "initial":
        standby_journal[runtime.STANDBY_ELECTION] = {"inform_binding_sha256": "a" * 64}
    standby_journal[runtime.STANDBY_POLICY] = {
        "controller_revision": "revision-2", "snapshot_sha256": runtime.complete_snapshot_fingerprint(standby_cfg),
    }
    installed._peer_writer.locked_state.return_value = nullcontext(standby_journal)
    monkeypatch.setattr(runtime, "_standby_reservation", Mock(return_value=standby_record))
    primary_proof, backup_proof = Mock(return_value="revision-1"), Mock(return_value="revision-2")
    monkeypatch.setattr(runtime, "verify_primary_inform", primary_proof)
    monkeypatch.setattr(runtime, "verify_standby_inform", backup_proof)
    if changed == "initial":
        assert installed.verify_pair_inform(role=role, is_standby=is_standby) == "revision-1"
        primary_proof.assert_called_once()
        backup_proof.assert_not_called()
        installed._read_pair.assert_not_called()
        return
    replay = None
    if changed in ("exact-replay", "changed-replay", "wrong-replay-head"):
        replay = {"_type": "setparam", "cfgversion": ("revision-2" if is_standby else "revision-1"),
                  "system_cfg": json.dumps(json.loads(standby_cfg if is_standby else primary_cfg), indent=2)}
        if changed == "changed-replay":
            replay["system_cfg"] = '{"device":"standby","state":2}'
        if changed == "wrong-replay-head":
            replay["cfgversion"] = "new"
    if changed in ("changed-replay", "wrong-replay-head"):
        with pytest.raises(ValueError, match="replay differs"):
            installed.verify_pair_inform(role=role, is_standby=is_standby, replay=replay)
        primary_proof.assert_not_called()
        backup_proof.assert_not_called()
        return
    if changed in ("device-record", "pair-withdrawn"):
        with pytest.raises(ValueError):
            installed.verify_pair_inform(role=role, is_standby=is_standby)
        backup_proof.assert_not_called()
    else:
        assert installed.verify_pair_inform(role=role, is_standby=is_standby, replay=replay) == (
            "revision-2" if is_standby else "revision-1"
        )
        backup_proof.assert_called_once()
        assert len(backup_proof.call_args.kwargs["inform_binding_sha256"]) == 64
        assert backup_proof.call_args.kwargs["expected_role"] == (role if is_standby else ("backup" if role == "master" else "master"))
    primary_proof.assert_called_once()
    assert primary_proof.call_args.kwargs["expected_role"] == (role if not is_standby else ("master" if role == "backup" else "backup"))


@pytest.mark.parametrize("phase", ["revoking", "revoked"])
def test_standby_inform_polls_vip_release_without_live_controller_or_primary(monkeypatch, phase):
    installed = runtime.ShadowPrimaryRuntime.__new__(runtime.ShadowPrimaryRuntime)
    installed._writer = Mock(state_path=Path("/primary"))
    installed._peer_writer = Mock(state_path=Path("/standby"))
    installed._read_pair = Mock(side_effect=OSError("Controller unavailable"))
    installed._receipt = Mock()
    installed._peer_receipt = Mock()
    primary = {"phase": "primary_active"}
    candidate = {"phase": "standby"}
    election = {"phase": phase}
    if phase == "revoked":
        election["revoked_generation"] = "a" * 64
    standby = {runtime.SHADOW_HANDOFF: candidate, runtime.STANDBY_ELECTION: election}
    installed._writer.locked_state.return_value = nullcontext({runtime.SHADOW_HANDOFF: primary})
    installed._peer_writer.locked_state.return_value = nullcontext(standby)
    monkeypatch.setattr(runtime, "_standby_reservation", Mock(return_value=candidate))
    released = Mock()
    monkeypatch.setattr(runtime, "verify_revoked_standby_release", released)

    installed.poll_standby_release()

    released.assert_called_once_with(installed._peer_writer, standby, installed._peer_receipt)
    installed._read_pair.assert_not_called()
    assert not installed._receipt.mock_calls


@pytest.mark.parametrize("drift", [
    None, "carrier", "shared-management", "mapped-management", "loopback-management", "wrong-election", "pending-commit",
    "receipt-prerequisites",
])
def test_prepared_router_uses_saved_lan_state_and_an_independent_physical_link(drift):
    backend = Mock()
    backend.read_config.side_effect = lambda path: {} if path == ["interfaces", "ethernet", "eth2"] else None
    backend.show_kernel_interfaces.return_value = [
        {"ifname": "eth2", "flags": ["UP"] if drift == "carrier" else ["UP", "LOWER_UP"], "addr_info": []},
    ]
    configuration = {"interfaces": {"bridge": {"br0": {"address": "192.0.2.2/24"}}}}
    lan = (ip_interface("192.0.2.3/24" if drift == "wrong-election" else "192.0.2.2/24"),)
    management = "br0" if drift == "shared-management" else "eth4"
    management_ip = "198.18.100.2"
    if drift == "mapped-management":
        management = "eth1"
    if drift == "loopback-management":
        management = "lo"
        management_ip = "127.0.0.1"
    kernel = {"br0": lan, "eth2": ()}
    kernel[management] = kernel.get(management, ()) + (ip_interface(f"{management_ip}/24"),)
    state = ShadowStockState(configuration, configuration, kernel)
    writer = Mock(backend=backend, ipv6_interfaces=())
    writer.commit_proof.side_effect = [("boot", "saved"), ("boot", "other" if drift == "pending-commit" else "saved")]
    receipt = Mock(management_identity=ShadowManagementIdentity("02:00:00:00:00:02", f"https://{management_ip}", "pin"))
    receipt.observe_handoff_state.return_value = SimpleNamespace(state=state, boot_id="boot", config_sha256="saved")
    if drift == "receipt-prerequisites":
        receipt.verify_admission.side_effect = ValueError("Router-local receipt prerequisites are missing")
    node = ShadowNode("eth2", "169.254.254.2/24", {"br0": "br0"}, "192.0.2.2/24")
    ports = {"eth1", "eth2", "br0"}
    if drift is None:
        runtime._check_prepared_router(writer, receipt, node, port_interfaces=ports)
        receipt.observe_handoff_state.assert_called_once_with(
            backend, writer.commit_proof, phase="saved_commit", expected_boot_id="boot", expected_saved_sha256=None,
        )
        assert writer.commit_proof.call_count == 2
        receipt.verify_admission.assert_called_once()
        assert {("interfaces", "bridge", "br0"), ("interfaces", "ethernet", "eth2"),
                ("firewall", "ipv4", "forward", "filter")} <= set(
                    receipt.verify_admission.call_args.kwargs["required_paths"]
                )
    else:
        with pytest.raises(ValueError):
            runtime._check_prepared_router(writer, receipt, node, port_interfaces=ports)


def test_packaged_shadow_roles_use_independent_credentials_and_the_same_standby_journal(tmp_path):
    credentials = tmp_path / "credentials"
    credentials.mkdir()
    configs = {}
    for role in ("primary", "standby"):
        site = credentials / f"{role}_site.conf"
        site.write_text(
            "[gateway]\ndevice = UXGENT\nplatform = vyos\nurl = http://controller.test:8080/inform\n"
            "lan_ip = 192.0.2.1\nports = []\n"
            f"[vyos]\napi_url = https://{role}.test\n"
            "[vyos_firewall]\nenabled = true\n"
            "[vyos_restart]\nrecover_provisioning = true\n"
            "[vyos_shadow]\nprobe_enabled = true\n"
            + ("[vyos_shadow_primary]\nenabled = true\n" if role == "primary" else ""),
            encoding="utf-8",
        )
        (credentials / f"{role}_shadow-receipt-ssh-key").touch()
        state = tmp_path / role / "gateway.conf"
        state.parent.mkdir(mode=0o700)
        with pytest.raises(FileNotFoundError):
            load_enrolled_config(str(site), str(state), require_existing=True, credential_prefix=f"{role}_")
        assert not state.exists()
        config = load_enrolled_config(str(site), str(state), credential_prefix=f"{role}_")
        assert config["vyos"]["key_file"] == str(credentials / f"{role}_vyos-api-key")
        assert config["vyos_restart"]["ssh_key_file"] == str(credentials / f"{role}_restart-ssh-key")
        assert config["vyos_shadow"]["receipt_ssh_key_file"] == str(credentials / f"{role}_shadow-receipt-ssh-key")
        configs[role] = config
    primary = configs["primary"]["vyos_shadow_primary"]
    observed_standby = load_enrolled_config(primary["standby_enrollment"], primary["standby_state"],
                                           require_existing=True, credential_prefix="standby_")
    assert observed_standby["vyos_firewall"]["state_path"] == configs["standby"]["vyos_firewall"]["state_path"]
    assert Path(primary["controller_session_file"]).name == "primary_network-session.cookies"


@pytest.mark.parametrize(("conflict", "restored", "message"), [
    (None, False, None),
    (None, True, None),
    ("mac", False, "distinct gateway MAC addresses"),
    ("mac", True, "distinct gateway MAC addresses"),
    ("origin", False, "distinct VyOS management endpoints"),
    ("controller", False, "same inform endpoint"),
])
def test_shadow_pair_preflight_checks_both_enrollments_without_writing(
    tmp_path, monkeypatch, capsys, conflict, restored, message,
):
    credentials = tmp_path / "credentials"
    credentials.mkdir()
    state = tmp_path / "state"
    originals = {}
    for index, role in enumerate(("primary", "standby"), 1):
        site = credentials / f"{role}_site.conf"
        role_state = state / role / "gateway.conf"
        role_state.parent.mkdir(parents=True, mode=0o700)
        endpoint = "https://PRIMARY.test.:443/" if conflict == "origin" and index == 2 else f"https://{role}.test"
        controller = "other" if conflict == "controller" and index == 2 else "controller"
        site.write_text(
            f"[gateway]\ndevice = UXGENT\nplatform = vyos\nurl = http://{controller}.test:8080/inform\n"
            f"lan_ip = 192.0.2.1\nports = []\n[vyos]\napi_url = {endpoint}\n",
            encoding="utf-8",
        )
        literal_mac = "02:AB:00:00:00:01" if index == 2 else "02:ab:00:00:00:01"
        if conflict == "mac" and not restored:
            config = RawConfigParser()
            config.read(site)
            config["gateway"]["lan_mac"] = literal_mac
            with site.open("w", encoding="utf-8") as stream:
                config.write(stream)
        if restored:
            config = load_enrolled_config(str(site), str(role_state), credential_prefix=f"{role}_")
            config["gateway"]["lan_mac"] = literal_mac if conflict == "mac" else f"02:ab:00:00:00:{index:02d}"
            with role_state.open("w", encoding="utf-8") as stream:
                config.write(stream)
            originals[role_state] = role_state.read_bytes()
    monkeypatch.setattr(sys, "argv", ["unifi-gateway", "check-shadow-pair-enrollment"])
    monkeypatch.setenv("STATE_DIRECTORY", str(state))
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials))
    if message:
        with pytest.raises(SystemExit) as rejected:
            main()
        assert rejected.value.code == 2
        assert message in capsys.readouterr().err
    else:
        main()
    assert {path: path.read_bytes() for path in state.glob("*/gateway.conf")} == originals


@pytest.mark.parametrize(("worker_status", "launcher_status", "ignores_term", "incomplete_restore"), [
    (23, 23, False, False), (0, 1, False, False), (0, 1, True, False), (0, 31, False, True),
])
def test_pair_launcher_stops_survivor_and_reports_an_unexpected_exit(
    tmp_path, worker_status, launcher_status, ignores_term, incomplete_restore,
):
    root = Path(__file__).resolve().parents[1]
    script = tmp_path / "run.sh"
    tool = tmp_path / "gateway"
    source = (root / "scripts/run-shadow-pair.sh").read_text()
    script.write_text(source.replace("/usr/bin/unifi-gateway", str(tool))
                      .replace("shutdown_grace_seconds=60", "shutdown_grace_seconds=2"))
    stop_handler = "trap '' TERM" if ignores_term else 'trap \'touch "$STATE_DIRECTORY/$role/stopped"; exit 0\' TERM'
    tool.write_text(
        '#!/bin/bash\n'
        'role=${UNIFI_GW_SHADOW_CREDENTIAL_PREFIX%_}\n'
        'if [[ "$1" == check-shadow-pair-enrollment ]]; then\n'
        '  if [[ -f "$CREDENTIALS_DIRECTORY/primary_site.conf.incomplete" ]]; then exit 31; fi\n'
        '  exit 0\n'
        'fi\n'
        f'{stop_handler}\n'
        'printf "%s\\n" "$UNIFI_GW_CONFIG" "$UNIFI_GW_SITE_CONFIG" > "$STATE_DIRECTORY/$role/ready"\n'
        'if [[ $role == primary ]]; then\n'
        '  while [[ ! -f $STATE_DIRECTORY/standby/ready ]]; do sleep 0.1; done\n'
        f'  exit {worker_status}\n'
        'fi\n'
        'while :; do sleep 0.1; done\n',
        encoding="utf-8",
    )
    tool.chmod(0o700)
    credentials, state = tmp_path / "credentials", tmp_path / "state"
    credentials.mkdir()
    state.mkdir()
    for role in ("primary", "standby"):
        for name in ("site.conf", "vyos-ca.pem", "vyos-api-key", "shadow-ssh-key", "shadow-ssh-known-hosts",
                     "shadow-receipt-ssh-key", "restart-ssh-key", "restart-ssh-known-hosts"):
            (credentials / f"{role}_{name}").touch()
    if incomplete_restore:
        (credentials / "primary_site.conf.incomplete").touch()
    with subprocess.Popen(
        ["/bin/bash", str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
        env=os.environ | {"STATE_DIRECTORY": str(state), "CREDENTIALS_DIRECTORY": str(credentials)},
    ) as launcher:
        try:
            _, diagnostic = launcher.communicate(timeout=6)
        except subprocess.TimeoutExpired:
            os.killpg(launcher.pid, signal.SIGKILL)
            launcher.communicate()
            pytest.fail("pair launcher did not exit after a worker failed")
    assert launcher.returncode == launcher_status, diagnostic
    if incomplete_restore:
        assert not list(state.glob("*/ready"))
        return
    assert f"primary worker exited unexpectedly with status {worker_status}" in diagnostic
    for role in ("primary", "standby"):
        assert (state / role / "ready").read_text().splitlines() == [
            str(state / role / "gateway.conf"), str(credentials / f"{role}_site.conf"),
        ]
        assert (state / role).stat().st_mode & 0o777 == 0o700
    assert (state / "standby" / "stopped").exists() is not ignores_term
    if ignores_term:
        assert "standby worker did not stop within 2s. Sending SIGKILL." in diagnostic
