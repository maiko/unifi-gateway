"""Reconciliation rules for the explicitly owned VyOS forwarding entries."""
from base64 import b64encode
from configparser import ConfigParser
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from ipaddress import IPv4Network, IPv6Network
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from provisioners import vyos
import unifi_gateway
from backends.vyos import VyOSReadError, VyOSWriteError
from inspection.suricata import InspectionIntent
from provisioners.vyos import VyOSReconciler, OpenVpnDesired, unmanaged_config_fingerprint
from provisioners.vyos_dhcp import DhcpScope, decode_dhcp_intent
from provisioners.vyos_dns import DnsScope, decode_dns_intent
from provisioners.uxg_intent import FirewallRule, FirewallIntent, decode_firewall_intent
from provisioners.vyos_ipsec import IpsecScope, decode_ipsec_intent
from provisioners.vyos_mdns import MdnsIntent, MdnsScope
from provisioners.vyos_nat import NatScope, decode_nat_intent
from provisioners.uxg_openvpn import OpenVpnClientIntent
from provisioners.vyos_ospf import OspfScope, decode_ospf_intent
from provisioners.vyos_port_forward import PortForwardScope, decode_port_forward_intent
from provisioners.vyos_routes import StaticRouteScope, decode_route_intent
from provisioners.vyos_vlan import VlanIntent, VlanScope
from provisioners.uxg_wan_failover import WanFailoverIntent
from provisioners.vyos_wireguard import WireGuardScope, decode_wireguard_intent
from provisioners.vyos_ipsec_guards import IPSEC_GUARD_PATHS
from provisioners.vyos_openvpn import OpenVpnScope
from provisioners.vyos_openvpn_guards import OPENVPN_GUARD_PATHS, OpenVpnGuardScope, plan_openvpn_guards
from provisioners.vyos_wireguard_guards import GUARD_PATHS, WireGuardGuardScope
from unifi_protocol import create_inform


class FakeFirewall:
    def __init__(self):
        self.rules = {"20": {"description": "Operator decision", "action": "accept"}}
        self.events = []
        self.timeout = False
        self.save_timeout = False
        self.firewall_config = {}
        self.conntrack_ignore = None

    def read_config(self, path):
        if path == ["firewall"]:
            return self.firewall_config
        if path == ["system", "conntrack", "ignore"]:
            return self.conntrack_ignore
        assert path == ["firewall", "ipv4", "forward", "filter", "rule"]
        self.events.append("read")
        return {"rule": self.rules.copy()}

    def stage_configuration(self, commands, *, confirm_minutes):
        assert confirm_minutes > 0
        self.events.append("stage")
        for command in commands:
            path = command["path"]
            assert path[:5] == ["firewall", "ipv4", "forward", "filter", "rule"]
            slot = path[5]
            if command["op"] == "delete":
                del self.rules[slot]
                continue
            current = self.rules.setdefault(slot, {})
            for part in path[6:-1]:
                current = current.setdefault(part, {})
            if path[6:] == ["state"]:
                value = command["value"]
                assert isinstance(value, str)
                previous = current.get("state")
                current["state"] = [value, previous] if previous is not None else value
                continue
            current[path[-1]] = {}
            if "value" in command:
                current[path[-1]] = command["value"]
        if self.timeout:
            raise VyOSWriteError("configure timed out")

    def show_interfaces(self):
        self.events.append("management")
        return "management is reachable"

    def confirm_configuration(self):
        self.events.append("confirm")

    def save_configuration(self):
        self.events.append("save")
        if self.save_timeout:
            raise VyOSWriteError("save timed out")


def make_reconciler(tmp_path, backend, **options):
    return VyOSReconciler(
        backend, state_path=tmp_path / "firewall.json", rule_base=80200,
        interfaces={IPv4Network("192.168.110.0/24"): "eth3.110", IPv4Network("192.168.120.0/24"): "eth3.120"},
        **options,
    )


@pytest.mark.parametrize("schema_version", [None, True, 2])
def test_incompatible_journal_cannot_authorize_router_changes(tmp_path, schema_version):
    backend = FakeFirewall()
    reconciler = make_reconciler(tmp_path, backend)
    assert reconciler.reconcile(intent("before", 8443)).verified_revision == "before"
    state = json.loads(reconciler.state_path.read_text())
    if schema_version is None:
        state.pop("schema_version", None)
    else:
        state["schema_version"] = schema_version
    reconciler.state_path.write_text(json.dumps(state))
    backend.events.clear()
    result = reconciler.reconcile(intent("remove"))
    assert result.error and "schema" in result.error
    assert not backend.events
    assert json.loads(reconciler.state_path.read_text()) == state


def test_one_lan_can_verify_an_empty_policy_without_accepting_unmapped_forwarding(tmp_path):
    backend = FakeFirewall()
    lan = IPv4Network("192.0.2.0/24")
    reconciler = VyOSReconciler(backend, state_path=tmp_path / "firewall.json",
                                   rule_base=80200, interfaces={lan: "br0"})
    baseline = reconciler.reconcile(FirewallIntent("ordinary", ()))
    assert baseline.verified_revision == "ordinary" and baseline.error is None

    deny = FirewallRule("outside", lan, IPv4Network("198.51.100.0/24"), 8443)
    failed = reconciler.reconcile(FirewallIntent("outside", (deny,)))
    assert failed.verified_revision == "ordinary"
    assert "two explicitly mapped VyOS LAN prefixes" in failed.error
    assert not {"stage", "confirm", "save"}.intersection(backend.events)


class ShadowInterconnectLab(FakeFirewall):
    def __init__(self):
        super().__init__()
        self.addresses = ["198.18.241.2/30"]
        self.saved = list(self.addresses)
        self.kernel_overrides = None
        self.kernel_other = []
        self.fail_after_save = False
        self.vrrp = None

    def read_config(self, path):
        if path == ["interfaces", "ethernet", "eth2"]:
            return {"description": "Operator link description", "address": list(self.addresses)}
        if path == ["high-availability", "vrrp"]:
            return self.vrrp
        return super().read_config(path)

    def show_kernel_interfaces(self):
        addresses = self.addresses if self.kernel_overrides is None else self.kernel_overrides
        return [{"ifname": "eth2", "flags": ["UP", "LOWER_UP"], "addr_info": [
            {"family": "inet", "local": address.split("/")[0], "prefixlen": int(address.split("/")[1])}
            for address in addresses
        ]}, *self.kernel_other]

    def stage_configuration(self, commands, *, confirm_minutes):
        self.events.append("stage")
        for command in commands:
            path = command["path"]
            assert path[:4] == ["interfaces", "ethernet", "eth2", "address"] and len(path) == 5
            if command["op"] == "set":
                self.addresses.append(path[-1])
            else:
                self.addresses.remove(path[-1])
        if self.timeout:
            raise VyOSWriteError("configure timed out")

    def save_configuration(self):
        self.events.append("save")
        if not self.fail_after_save:
            self.saved = list(self.addresses)

    def proof(self, *, phase):
        if phase == "saved" and self.saved != self.addresses:
            raise VyOSReadError("Saved configuration differs")
        return "a" * 64


@pytest.mark.parametrize("changed", [None, "saved-proof", "owner-rule"])
def test_standby_policy_plan_reuses_the_scoped_firewall_without_writes(tmp_path, changed):
    backend = ShadowInterconnectLab()
    address = "169.254.254.3/24"
    boot = "158dd3a3-dc93-4ae3-94b1-489e4f6ecc6d"
    observations = iter([(boot, "a" * 64), (boot, "b" * 64 if changed == "saved-proof" else "a" * 64)])

    def proof(*, phase):
        return next(observations) if phase == "saved_commit" else backend.proof(phase=phase)

    writer = make_reconciler(tmp_path, backend, shadow_interconnect="eth2", commit_proof=proof)
    applied = writer.reconcile(intent("phase-one"), shadow_interconnect_address=address)
    assert applied.verified_revision == "phase-one"
    with writer.locked_state() as state:
        state["shadow_handoff"] = {
            "phase": "standby", "target": "a" * 64, "revision": "b" * 64, "saved_sha256": "c" * 64,
            "config_sha256": "d" * 64, "receipt_generation": "e" * 64, "outside_sha256": "f" * 64,
            "boot_id": "158dd3a3-dc93-4ae3-94b1-489e4f6ecc6d", "transaction": "6303a0a3-d505-4782-93e1-0639a40dd670",
        }
        writer._write_state(state, durable=True)
    journal = writer.state_path.read_bytes()
    if changed == "owner-rule":
        backend.rules["80200"] = {"action": "accept"}
    backend.events.clear()
    with writer.locked_state() as state:
        if changed:
            with pytest.raises(ValueError):
                writer.plan_shadow_standby_policy(intent("standby-complete", 8443), state)
        else:
            plan = writer.plan_shadow_standby_policy(intent("standby-complete", 8443), state)
            assert plan.revision == "standby-complete"
            assert plan.configuration_sha256 == "a" * 64
            assert any(command["path"][-2:] == ["80200", "action"] and command["value"] == "drop"
                       for command in plan.commands)
            assert plan.desired["shadow_interconnect"] == address
    assert writer.state_path.read_bytes() == journal
    assert not {"stage", "confirm", "save"}.intersection(backend.events)
    assert backend.rules["20"] == {"description": "Operator decision", "action": "accept"}


@pytest.mark.parametrize("fault", [None, "lost-reply", "operator-edit", "foreign-receipt", "wrong-scope",
                                  "wrong-slot", "vip-after-stage", "lost-confirm", "lost-save",
                                  "save-not-applied", "drift-before-save", "bad-saved-proof",
                                  "rollback", "rollback-same-boot", "rollback-drift", "rollback-fence", "rollback-mapping",
                                  "unchanged", "cold-unchanged", "cold-saved", "cold-lost-save", "cold-raw-drift",
                                  "cold-fence", "cold-policy-drift"])
def test_standby_policy_stage_keeps_fence_and_recovers_without_replay(tmp_path, fault):
    from unittest.mock import Mock

    from provisioners.vyos_shadow_binding import ShadowManagementIdentity
    from provisioners.vyos_shadow_complete import ShadowStockState
    from provisioners.vyos_shadow_receipt import ShadowHandoffObservation, ShadowReceiptStatus
    from provisioners.vyos_shadow_standby import STANDBY_POLICY, stage_standby_policy
    from provisioners.vyos import ShadowStandbyPolicyPlan

    backend = FakeFirewall()
    backend.management_origin = "https://192.0.2.50"
    backend.timeout = fault == "lost-reply"
    boot = "158dd3a3-dc93-4ae3-94b1-489e4f6ecc6d"
    new_boot = "a02a80ea-c337-4b57-9764-34e7521d3bee"
    current_boot = boot
    before, after, saved, scope = "a" * 64, "b" * 64, "c" * 64, "d" * 64
    new_saved = "7" * 64
    saved_digest = saved
    running_fingerprint = before
    backend.read_complete_configuration = lambda: {"firewall": {"ipv4": {"forward": {"filter": {
        "rule": backend.rules, "default-action": "drop",
    }}}}, "system": {"host-name": "drift" if (
        fault == "operator-edit" and "stage" in backend.events
        or fault == "drift-before-save" and "confirm" in backend.events
    ) else "standby"}}

    def proof(*, phase):
        if phase == "saved_commit":
            return current_boot, running_fingerprint
        return after

    writer = make_reconciler(tmp_path, backend, commit_proof=proof)
    with writer.locked_state() as state:
        state["verified_revision"] = "fallback"
        state["shadow_handoff"] = {
            "phase": "standby", "target": "a" * 64, "revision": "b" * 64, "saved_sha256": "c" * 64,
            "config_sha256": "d" * 64, "receipt_generation": "0" * 64, "outside_sha256": "f" * 64,
            "boot_id": boot, "transaction": "6303a0a3-d505-4782-93e1-0639a40dd670",
        }
        writer._write_state(state, durable=True)
        policy = {name.removeprefix("verified_"): value for name, value in state.items()
                  if name.startswith("verified_") and name != "verified_revision"}
    policy["rules"] = {"80200": {"action": "drop"}}
    commands = ({"op": "set", "path": ["firewall", "ipv4", "forward", "filter", "rule",
                                      "1" if fault == "wrong-slot" else "80200", "action"], "value": "drop"},)
    if fault in ("unchanged", "cold-unchanged"):
        commands, policy["rules"] = (), {}
    plan = ShadowStandbyPolicyPlan("complete", boot, before, commands, policy)
    receipt = Mock(management_identity=ShadowManagementIdentity("02:00:00:00:00:02", backend.management_origin, "pin"))
    receipt.status.return_value = ShadowReceiptStatus("1" * 64, object() if fault == "foreign-receipt" else None)
    stock = ShadowStockState({}, {}, {})

    def observe(_backend, _proof, *, phase, expected_boot_id, expected_saved_sha256):
        if expected_boot_id != current_boot or expected_saved_sha256 not in (None, saved_digest):
            raise ValueError("Unexpected saved fingerprint or boot in receipt observation")
        if phase == "staged_reboot":
            assert "stage" in backend.events and "confirm" not in backend.events
        if phase == "completed":
            assert "confirm" in backend.events
        stamp = (before if fault == "bad-saved-proof" else running_fingerprint) if phase == "saved_commit" else after
        return ShadowHandoffObservation(stock, "unknown", current_boot, saved_digest, stamp, "reboot", phase)

    def fence(generation):
        assert generation == "1" * 64
        receipt.status.return_value = ShadowReceiptStatus("2" * 64, None)
        return receipt.status.return_value

    receipt.observe_handoff_state.side_effect = observe
    receipt.fence.side_effect = fence
    def verify_fenced(_stock):
        if fault == "vip-after-stage" and "stage" in backend.events:
            raise ValueError("Unexpected standby VIP")

    options = dict(revision="complete", snapshot_sha256="e" * 64, plan=plan, verify_fenced=verify_fenced,
                   verify_primary=Mock(), approved_outside_scope=scope,
                   outside_scope=("f" * 64 if fault == "wrong-scope" else scope), mapped_resources_sha256="8" * 64)

    def run(**updates):
        with writer.locked_state() as state:
            return stage_standby_policy(writer, state, receipt, **(options | updates))

    def finish():
        from provisioners.vyos_shadow_standby import confirm_and_save_standby_policy

        with writer.locked_state() as state:
            return confirm_and_save_standby_policy(writer, state, receipt, **{
                key: value for key, value in options.items() if key != "plan"
            })

    def confirm():
        backend.events.append("confirm")
        if fault == "lost-confirm":
            raise VyOSWriteError("confirm reply lost")

    def save():
        nonlocal saved_digest, running_fingerprint
        backend.events.append("save")
        if fault == "save-not-applied" and backend.events.count("save") == 1:
            raise VyOSWriteError("save timed out before writing")
        saved_digest = new_saved
        running_fingerprint = after
        if fault in ("lost-save", "cold-lost-save"):
            raise VyOSWriteError("save reply lost")

    completing = (None, "lost-confirm", "lost-save", "save-not-applied", "drift-before-save", "bad-saved-proof")
    if fault in ("unchanged", "cold-unchanged"):
        assert run().config_sha256 == before
        if fault == "cold-unchanged":
            current_boot = new_boot
        assert finish().saved_sha256 == saved
        assert finish().boot_id == current_boot
        assert not {"stage", "confirm", "save"}.intersection(backend.events)
        assert json.loads(writer.state_path.read_text())["verified_revision"] == "fallback"
        receipt.publish.assert_not_called()
        return

    if fault and fault.startswith("cold-"):
        run()
        backend.confirm_configuration = confirm
        backend.save_configuration = save
        if fault == "cold-lost-save":
            with pytest.raises(VyOSWriteError, match="save reply lost"):
                finish()
        else:
            assert finish().saved_sha256 == new_saved
        current_boot = new_boot
        if fault == "cold-raw-drift":
            saved_digest = "3" * 64
        elif fault == "cold-fence":
            receipt.status.return_value = ShadowReceiptStatus("3" * 64, None)
        elif fault == "cold-policy-drift":
            backend.rules["80200"] = {"action": "accept"}
        journal = writer.state_path.read_bytes()
        if fault in ("cold-saved", "cold-lost-save"):
            assert finish().boot_id == new_boot
            assert finish().saved_sha256 == new_saved
            checkpoint = json.loads(writer.state_path.read_text())
            assert checkpoint[STANDBY_POLICY]["phase"] == "saved"
            assert checkpoint[STANDBY_POLICY]["boot_id"] == new_boot
            assert checkpoint["verified_revision"] == "fallback"
        else:
            with pytest.raises(ValueError):
                finish()
            assert writer.state_path.read_bytes() == journal
        assert backend.events.count("stage") == backend.events.count("confirm") == backend.events.count("save") == 1
        receipt.publish.assert_not_called()
        return

    if fault and fault.startswith("rollback"):
        from provisioners.vyos_shadow_standby import recover_standby_policy_rollback

        run()
        if fault != "rollback-same-boot":
            current_boot = "a02a80ea-c337-4b57-9764-34e7521d3bee"
        del backend.rules["80200"]
        if fault == "rollback-drift":
            backend.rules["20"]["action"] = "drop"
        if fault == "rollback-fence":
            receipt.status.return_value = ShadowReceiptStatus("3" * 64, None)
        journal = writer.state_path.read_bytes()

        def recover(state):
            args = {key: value for key, value in options.items() if key != "plan"}
            if fault == "rollback-mapping":
                args["mapped_resources_sha256"] = "9" * 64
            return recover_standby_policy_rollback(writer, state, receipt, **args)

        with writer.locked_state() as state:
            if fault == "rollback":
                assert recover(state).boot_id == current_boot
                assert STANDBY_POLICY not in state
                assert state["verified_revision"] == "fallback" and state["pending"] is None
                assert state["shadow_handoff"]["phase"] == "standby"
            else:
                with pytest.raises(ValueError):
                    recover(state)
                assert writer.state_path.read_bytes() == journal
        if fault == "rollback":
            receipt.fence.reset_mock()
            with pytest.raises(ValueError, match="already rolled back"):
                run()
            receipt.fence.assert_not_called()
        assert backend.events.count("stage") == 1
        assert not {"confirm", "save"}.intersection(backend.events)
        receipt.publish.assert_not_called()
        return

    if fault == "lost-reply":
        with pytest.raises(VyOSWriteError):
            run()
        assert json.loads(writer.state_path.read_text())[STANDBY_POLICY]["phase"] == "armed"
        with pytest.raises(ValueError, match="snapshot changed"):
            run(plan=None, snapshot_sha256="6" * 64)
        assert run(plan=None).config_sha256 == after
    elif fault in completing:
        assert run().config_sha256 == after
        assert run(plan=None).config_sha256 == after
        backend.confirm_configuration = confirm
        backend.save_configuration = save
        if fault in ("lost-confirm", "lost-save", "save-not-applied"):
            with pytest.raises(VyOSWriteError):
                finish()
            checkpoint = json.loads(writer.state_path.read_text())
            assert checkpoint[STANDBY_POLICY]["phase"] == ("confirming" if fault == "lost-confirm" else "saving")
        if fault in ("drift-before-save", "bad-saved-proof"):
            with pytest.raises(ValueError, match="candidate"):
                finish()
            assert backend.events.count("save") == (1 if fault == "bad-saved-proof" else 0)
        else:
            assert finish().saved_sha256 == new_saved
            assert finish().saved_sha256 == new_saved
            assert backend.events.count("save") == (2 if fault == "save-not-applied" else 1)
        assert backend.events.count("confirm") == 1
    else:
        with pytest.raises(ValueError):
            run()
    checkpoint = json.loads(writer.state_path.read_text())
    assert checkpoint["verified_revision"] == "fallback" and checkpoint["pending"] is None
    assert backend.rules["20"] == {"description": "Operator decision", "action": "accept"}
    stages = backend.events.count("stage")
    assert not receipt.publish.called
    if fault not in completing:
        assert not {"confirm", "save"}.intersection(backend.events)
    if fault in completing or fault == "lost-reply":
        expected_phase = {"lost-reply": "staged", "drift-before-save": "confirming", "bad-saved-proof": "saving"}
        assert checkpoint[STANDBY_POLICY]["phase"] == expected_phase.get(fault, "saved") and stages == 1
        assert checkpoint[STANDBY_POLICY]["receipt_generation"] == "2" * 64
    elif fault in ("operator-edit", "vip-after-stage"):
        assert checkpoint[STANDBY_POLICY]["phase"] == "armed" and stages == 1
    else:
        assert STANDBY_POLICY not in checkpoint and stages == 0


def test_native_shadow_interconnect_applies_and_withdraws_only_its_address(tmp_path):
    backend = ShadowInterconnectLab()
    reconcile = make_reconciler(tmp_path, backend, shadow_interconnect="eth2", commit_proof=backend.proof)

    first = reconcile.reconcile(FirewallIntent("shadow-pair", ()), shadow_interconnect_address="169.254.254.3/24")

    assert first.verified_revision == "shadow-pair" and first.error is None
    assert backend.saved == backend.addresses == ["198.18.241.2/30", "169.254.254.3/24"]
    assert reconcile._load_state()["verified_shadow_interconnect"] == "169.254.254.3/24"

    incomplete = reconcile.reconcile(FirewallIntent("incomplete", ()))
    assert incomplete.verified_revision == "shadow-pair" and incomplete.error

    withdrawn = reconcile.reconcile(FirewallIntent("shadow-withdrawn", ()), shadow_interconnect_address=None)

    assert withdrawn.verified_revision == "shadow-withdrawn" and withdrawn.error is None
    assert backend.saved == backend.addresses == ["198.18.241.2/30"]
    assert backend.events.count("stage") == 2


@pytest.mark.parametrize("failure", ["unowned", "reserved-vip", "prefix-overlap", "kernel", "save"])
def test_shadow_interconnect_refuses_an_unowned_or_unverified_address(tmp_path, failure):
    backend = ShadowInterconnectLab()
    reconcile = make_reconciler(tmp_path, backend, shadow_interconnect="eth2", commit_proof=backend.proof)
    if failure == "unowned":
        backend.addresses.append("169.254.254.3/24")
    elif failure == "reserved-vip":
        backend.vrrp = {"group": {"operator": {"address": {"169.254.254.2/24": {}}}}}
    elif failure == "prefix-overlap":
        backend.kernel_other = [{"ifname": "eth7", "flags": ["UP"], "addr_info": [
            {"family": "inet", "local": "169.254.254.55", "prefixlen": 24},
        ]}]
    elif failure == "kernel":
        backend.kernel_overrides = list(backend.addresses)
    else:
        backend.fail_after_save = True

    result = reconcile.reconcile(FirewallIntent("shadow-pair", ()), shadow_interconnect_address="169.254.254.3/24")

    assert result.error is not None and result.verified_revision is None
    assert reconcile._load_state()["verified_shadow_interconnect"] is None
    if failure in {"unowned", "reserved-vip", "prefix-overlap"}:
        assert "stage" not in backend.events
    if failure == "kernel":
        assert "confirm" not in backend.events
    if failure == "save":
        backend.fail_after_save = False
        recovered = make_reconciler(tmp_path, backend, shadow_interconnect="eth2", commit_proof=backend.proof)
        verified = recovered.reconcile(FirewallIntent("shadow-pair", ()), shadow_interconnect_address="169.254.254.3/24")
        assert verified.verified_revision == "shadow-pair" and not verified.error
        assert backend.events.count("stage") == 1


def test_shadow_interconnect_recovery_waits_for_both_configured_and_kernel_rollback(tmp_path, monkeypatch):
    backend = ShadowInterconnectLab()
    reconciler = make_reconciler(tmp_path, backend, shadow_interconnect="eth2", commit_proof=backend.proof)
    assert reconciler.reconcile(FirewallIntent("base", ()), shadow_interconnect_address=None).verified_revision == "base"
    backend.timeout = True
    desired = "169.254.254.3/24"
    assert reconciler.reconcile(FirewallIntent("prepare", ()), shadow_interconnect_address=desired).error
    assert reconciler._load_state()["verified_revision"] == "base"
    deadline = reconciler._load_state()["pending"]["retry_after"]
    backend.addresses = list(backend.saved)
    backend.kernel_overrides = [*backend.addresses, desired]
    monkeypatch.setattr(vyos.time, "time", lambda: deadline + 1)

    assert reconciler.reconcile(FirewallIntent("cancel", ()), shadow_interconnect_address=None).error
    assert reconciler._load_state()["pending"] is not None

    backend.kernel_overrides = None
    assert reconciler.reconcile(FirewallIntent("cancel", ()), shadow_interconnect_address=None).verified_revision == "cancel"
    assert reconciler._load_state()["pending"] is None
    assert backend.events.count("stage") == 1


def test_confirmed_shadow_journal_without_a_staged_fingerprint_stays_unverified(tmp_path):
    backend = ShadowInterconnectLab()
    backend.fail_after_save = True
    reconciler = make_reconciler(tmp_path, backend, shadow_interconnect="eth2", commit_proof=backend.proof)
    desired = "169.254.254.3/24"
    assert reconciler.reconcile(FirewallIntent("prepare", ()), shadow_interconnect_address=desired).error
    state = reconciler._load_state()
    assert state["pending"]["confirmed"] is True
    del state["pending"]["confirmation_sha256"]
    reconciler._write_state(state)
    backend.fail_after_save = False

    result = reconciler.reconcile(FirewallIntent("prepare", ()), shadow_interconnect_address=desired)

    assert result.verified_revision is None and "fingerprint" in result.error
    assert backend.saved == ["198.18.241.2/30"]


@pytest.mark.parametrize("negotiated", [False, True])
def test_enterprise_setparam_prepares_and_withdraws_the_interconnect(tmp_path, negotiated):
    backend = ShadowInterconnectLab()
    gateway = unifi_gateway.UnifiGateway.__new__(unifi_gateway.UnifiGateway)
    gateway.config = ConfigParser()
    gateway.config.read_dict({"gateway": {
        "device": "UXGENT", "platform": "vyos", "is_adopted": True, "use_aes_gcm": True,
    }, "provisioned": {}, "vyos_shadow": {"provisioning_enabled": True}})
    gateway._shadow_peer_probe = object()
    gateway.vyos_inspection = gateway.controller_broker_trust = gateway._security_event_worker = None
    gateway._stock_inspection = False
    gateway._vyos_provisioning_error = gateway._verified_ipsec = gateway._verified_openvpn = None
    gateway._notify_vyos_provisioning_error = lambda: None
    gateway.vyos_provisioner = make_reconciler(tmp_path, backend, shadow_interconnect="eth2", commit_proof=backend.proof)
    path = Path(__file__).parent / "fixtures/uxg_pro/zbf-native-snapshots.json"
    ordinary = json.loads(json.loads(path.read_text())["snapshots"]["baseline"]["system_cfg"])
    lan_addresses = [
        {"type": "static", "cidr": "192.0.2.1/24", "version": "v4"},
        {"type": "static", "cidr": "2001:db8::1/64", "version": "v6"},
    ]
    ordinary["udapi"]["interfaces"] = [
        {"identification": {"id": "eth1", "type": "ethernet"}, "status": {"enabled": True}},
        {"identification": {"id": "br0", "type": "bridge"},
         "bridge": {"id": 0, "interfaces": [{"id": "eth1"}, {"id": "eth2"}]}, "addresses": lan_addresses},
    ]
    gateway.config.read_dict({"vyos_firewall": {
        "unmanaged_baseline_sha256": unmanaged_config_fingerprint(json.dumps(ordinary), revision="ordinary"),
    }})
    if negotiated:
        ordinary["udapi"]["versionDetail"].update({"services/vrrp": 5, "services/stunnel": 1})
        ordinary["udapi"].setdefault("services", {}).update({
            "vrrp": {"enabled": False, "instances": []},
            "stunnel": {"enabled": False, "clients": [], "servers": []},
        })

    prepare = deepcopy(ordinary)
    prepare["udapi"]["interfaces"][0] = {
        "identification": {"id": "eth1", "type": "ethernet"}, "status": {"enabled": True, "comment": "MGMT_SHADOW"},
        "addresses": [{"type": "static", "version": "v4", "cidr": "169.254.254.3/24"}],
    }
    prepare["udapi"]["interfaces"][1]["bridge"]["interfaces"] = [{"id": "eth2"}]
    for cfg, revision in ((ordinary, "ordinary"), (prepare, "prepare")):
        gateway._apply_vyos_policy({"system_cfg": json.dumps(cfg), "cfgversion": revision})
        assert gateway._vyos_provisioning_error is None
        assert gateway.config["vyos_applied"]["cfgversion"] == revision

    assert backend.saved[-1] == gateway.config["vyos_shadow_applied"]["address"] == "169.254.254.3/24"
    shadow_state = gateway.config["vyos_shadow_applied"]
    assert shadow_state["standby_policy_revision"] == "prepare"
    assert len(shadow_state["standby_policy_sha256"]) == 64 and "primary_policy_sha256" not in shadow_state
    reference = json.loads(gateway.config["vyos_shadow_applied"]["reference"])
    assert reference["lan_preimage"] == {"cfgversion": "ordinary", "addresses": lan_addresses}
    bad = deepcopy(prepare)
    bad["udapi"]["interfaces"][1]["bridge"]["interfaces"] = []
    gateway._apply_vyos_policy({"system_cfg": json.dumps(bad), "cfgversion": "unrelated"})
    assert gateway.config["vyos_applied"]["cfgversion"] == "prepare"
    assert json.loads(gateway.config["vyos_shadow_applied"]["reference"]) == reference
    if negotiated:
        bad_schema = deepcopy(prepare)
        bad_schema["udapi"]["versionDetail"]["services/stunnel"] = True
        gateway._apply_vyos_policy({"system_cfg": json.dumps(bad_schema), "cfgversion": "bad-schema"})
        assert gateway.config["vyos_applied"]["cfgversion"] == "prepare"
        assert "Unsupported inactive Shadow Mode service version" in gateway._vyos_provisioning_error[1]

    gateway._apply_vyos_policy({"system_cfg": json.dumps(ordinary), "cfgversion": "withdraw"})
    assert gateway._vyos_provisioning_error is None
    assert gateway.config["vyos_applied"]["cfgversion"] == "withdraw"
    assert gateway.config["vyos_shadow_applied"]["address"] == ""
    assert backend.saved == ["198.18.241.2/30"]


class FakeInspectionQueue:
    scope = {"test_queue": 41110}
    networks = ("br110", "br120")

    def read(self, config):
        return config.get("test_queue", False)

    def commands(self, current, desired):
        assert current != desired
        return ({"op": "set", "path": ["test-queue"], "value": desired},)


class InspectionLabFirewall(FakeFirewall):
    def stage_configuration(self, commands, *, confirm_minutes):
        self.events.append("stage")
        assert confirm_minutes > 0 and len(commands) == 1
        assert commands[0]["path"] == ["test-queue"]
        self.firewall_config["test_queue"] = commands[0]["value"]


class FakeInspectionEngine:
    networks = FakeInspectionQueue.networks
    vendor_controls_sha256 = "a" * 64

    def __init__(self, backend):
        self.backend = backend
        self.mode = "off"
        self.listener_lost = False
        self.finish_failed = False

    def prepare_engine(self, intent):
        assert intent.mode == "block"
        self.backend.events.append("prepare-engine")
        self.mode = "block"

    def verify_engine(self, intent):
        self.backend.events.append("verify-engine")
        if self.mode != intent.mode or self.listener_lost:
            raise ValueError("Inspection listener unavailable")

    def apply_engine(self, intent):
        self.backend.events.append("finish-engine")
        assert not self.backend.firewall_config.get("test_queue")
        if self.finish_failed:
            raise ValueError("Engine cleanup unavailable")
        self.mode = intent.mode


def intent(revision, *ports):
    return FirewallIntent(revision, tuple(
        FirewallRule(10000 + index, IPv4Network("192.168.110.0/24"), IPv4Network("192.168.120.0/24"), port)
        for index, port in enumerate(ports)
    ))


def test_stock_inspection_stages_after_listener_and_restores_before_stopping(tmp_path):
    backend = InspectionLabFirewall()
    engine = FakeInspectionEngine(backend)
    reconciler = make_reconciler(tmp_path, backend, stock_inspection_policy=FakeInspectionQueue(), inspection_controller=engine)
    block = InspectionIntent("block", engine.networks, engine.vendor_controls_sha256)
    off = InspectionIntent("off", ())

    assert reconciler.reconcile(intent("block"), inspection_intent=block).verified_revision == "block"
    assert backend.events.index("prepare-engine") < backend.events.index("stage")
    assert backend.events.index("stage") < backend.events.index("verify-engine") < backend.events.index("confirm")
    assert backend.firewall_config["test_queue"] is True
    assert backend.rules == {"20": {"description": "Operator decision", "action": "accept"}}

    backend.events.clear()
    assert reconciler.reconcile(intent("off"), inspection_intent=off).verified_revision == "off"
    assert backend.events.index("stage") < backend.events.index("confirm") < backend.events.index("save")
    assert backend.events.index("save") < backend.events.index("finish-engine")
    assert backend.firewall_config["test_queue"] is False and engine.mode == "off"


def test_stock_inspection_withholds_confirmation_on_listener_loss(tmp_path):
    backend = InspectionLabFirewall()
    engine = FakeInspectionEngine(backend)
    reconciler = make_reconciler(tmp_path, backend, stock_inspection_policy=FakeInspectionQueue(), inspection_controller=engine)
    assert reconciler.reconcile(intent("off"), inspection_intent=InspectionIntent("off", ())).verified_revision == "off"
    engine.listener_lost = True
    block = InspectionIntent("block", engine.networks, engine.vendor_controls_sha256)

    result = reconciler.reconcile(intent("block"), inspection_intent=block)

    assert result.verified_revision == "off" and result.error == "Inspection listener unavailable"
    assert "stage" in backend.events and "confirm" not in backend.events
    pending = json.loads((tmp_path / "firewall.json").read_text())["pending"]
    assert pending["confirmed"] is False and pending["inspection_mode"] == "block"


def test_stock_inspection_recovers_failed_post_save_engine_transition(tmp_path):
    backend = InspectionLabFirewall()
    engine = FakeInspectionEngine(backend)
    options = {"stock_inspection_policy": FakeInspectionQueue(), "inspection_controller": engine}
    reconciler = make_reconciler(tmp_path, backend, **options)
    block = InspectionIntent("block", engine.networks, engine.vendor_controls_sha256)
    off = InspectionIntent("off", ())
    assert reconciler.reconcile(intent("block"), inspection_intent=block).verified_revision == "block"
    engine.finish_failed = True

    result = reconciler.reconcile(intent("off"), inspection_intent=off)

    assert result.verified_revision == "block" and result.error == "Engine cleanup unavailable"
    assert backend.firewall_config["test_queue"] is False and engine.mode == "block"
    pending = json.loads((tmp_path / "firewall.json").read_text())["pending"]
    assert pending["confirmed"] is True and pending["inspection_mode"] == "off"
    engine.finish_failed = False
    backend.events.clear()
    restarted = make_reconciler(tmp_path, backend, **options)
    assert restarted.reconcile(intent("off"), inspection_intent=off).verified_revision == "off"
    assert engine.mode == "off" and "stage" not in backend.events


def test_create_edit_order_delete_and_stale_revision(tmp_path):
    backend = FakeFirewall()
    reconcile = make_reconciler(tmp_path, backend).reconcile
    assert reconcile(intent("create", 8443, 8445)).verified_revision == "create"
    assert backend.rules["80200"]["destination"]["port"] == "8443"
    assert backend.rules["80201"]["destination"]["port"] == "8445"
    assert backend.events == ["read", "stage", "read", "management", "confirm", "save"]
    assert reconcile(intent("edit", 8444)).verified_revision == "edit"
    assert "80201" not in backend.rules
    assert backend.rules["80200"]["destination"]["port"] == "8444"
    assert reconcile(intent("edit", 8444)).changed is False
    assert reconcile(intent("create", 8443, 8445)).error
    assert backend.rules["80200"]["destination"]["port"] == "8444"
    assert reconcile(intent("delete")).verified_revision == "delete"
    assert backend.rules == {"20": {"description": "Operator decision", "action": "accept"}}


def test_ipv4_udp_block_updates_tcp_rule_and_reuses_ownership_after_restart(tmp_path):
    backend = FakeFirewall()
    operator = backend.rules["20"].copy()
    tcp = intent("tcp", 18443)
    reconcile = make_reconciler(tmp_path, backend).reconcile
    assert reconcile(tcp).verified_revision == "tcp"
    original = backend.rules["80200"].copy()
    assert original["protocol"] == "tcp"
    assert original.pop("log") == {}

    udp = FirewallIntent("udp", (replace(tcp.rules[0], protocol="udp", log=False),))
    assert reconcile(udp).verified_revision == "udp"
    projected = {**original, "protocol": "udp"}
    assert backend.rules == {"20": operator, "80200": projected}
    saved = json.loads((tmp_path / "firewall.json").read_text())
    assert saved["verified_rules"] == {"80200": projected}
    assert saved["pending"] is None

    restarted = make_reconciler(tmp_path, backend).reconcile
    assert restarted(udp).verified_revision == "udp"
    assert backend.events.count("stage") == 2
    assert restarted(intent("withdrawn")).verified_revision == "withdrawn"
    assert backend.rules == {"20": operator}


def test_udp_block_range_requires_exact_readback_and_recovers_after_rollback(tmp_path, monkeypatch):
    class IncorrectRangeFirewall(FakeFirewall):
        drop_range_end = True

        def stage_configuration(self, commands, *, confirm_minutes):
            super().stage_configuration(commands, confirm_minutes=confirm_minutes)
            destination = self.rules.get("80200", {}).get("destination", {})
            if self.drop_range_end and destination.get("port") == "18443-18444":
                destination["port"] = "18443"

    path = Path(__file__).parent / "fixtures/uxg_pro/zbf-native-actions.json"
    snapshot = json.loads(path.read_text())["snapshots"]["udp-block-range"]
    wanted = decode_firewall_intent(snapshot["system_cfg"], revision=snapshot["cfgversion"])
    rule, = wanted.rules
    interfaces = {rule.source: "eth3.110", rule.destination: "eth3.120"}
    backend = IncorrectRangeFirewall()
    journal = tmp_path / "firewall.json"

    def restart():
        return VyOSReconciler(backend, state_path=journal, rule_base=80200, interfaces=interfaces).reconcile

    baseline = FirewallIntent("previous-singleton", (replace(rule, port=18443),))
    assert restart()(baseline).verified_revision == baseline.revision
    previous = deepcopy(backend.rules)
    backend.events.clear()

    result = restart()(wanted)

    assert result.verified_revision == baseline.revision
    assert result.error == "Staged VyOS read-back differs from intended configuration"
    assert backend.events == ["read", "stage", "read"]
    pending = json.loads(journal.read_text())["pending"]
    assert pending["confirmed"] is False
    assert pending["rules"]["80200"]["destination"]["port"] == "18443-18444"
    assert restart()(wanted).error == "Prior VyOS transaction still requires recovery"

    backend.rules = deepcopy(previous)
    backend.drop_range_end = False
    monkeypatch.setattr(vyos.time, "time", lambda: pending["retry_after"] + 1)
    assert restart()(wanted).verified_revision == wanted.revision
    expected = {**previous["80200"], "destination": {"address": str(rule.destination), "port": "18443-18444"}}
    assert backend.rules == {"20": previous["20"], "80200": expected}
    assert backend.events[-2:] == ["confirm", "save"]
    state = json.loads(journal.read_text())
    assert state["verified_rules"] == {"80200": expected}
    assert state["pending"] is None

    stages = backend.events.count("stage")
    assert restart()(wanted).changed is False
    assert backend.events.count("stage") == stages
    assert restart()(FirewallIntent("withdrawn", ())).verified_revision == "withdrawn"
    assert backend.rules == {"20": previous["20"]}


def test_conflicting_rule_in_reserved_range_is_preserved(tmp_path):
    backend = FakeFirewall()
    backend.rules["80200"] = {"description": "Operator rule", "action": "accept"}
    result = make_reconciler(tmp_path, backend).reconcile(intent("create", 8443))
    assert result.error
    assert result.verified_revision is None
    assert backend.events == ["read"]
    assert backend.rules["80200"]["action"] == "accept"


def test_reject_and_state_update_existing_drop_without_replacing_operator_rule(tmp_path):
    backend = FakeFirewall()
    drop = intent("drop", 8443)
    reconcile = make_reconciler(tmp_path, backend).reconcile
    assert reconcile(drop).verified_revision == "drop"
    deny = drop.rules[0]
    for revision, states, readback in (
        ("reject", (), None), ("new", ("new",), "new"),
        ("return", ("established", "related"), ["related", "established"]),
    ):
        mapped = FirewallIntent(revision, (replace(deny, action="reject", states=states),))
        reconcile = make_reconciler(tmp_path, backend).reconcile
        result = reconcile(mapped)
        assert (result.verified_revision, result.error) == (revision, None)
        assert backend.rules["80200"]["action"] == "reject"
        assert backend.rules["80200"].get("state") == readback
        assert reconcile(mapped).changed is False

    assert reconcile(intent("withdrawn")).verified_revision == "withdrawn"
    assert backend.rules == {"20": {"description": "Operator decision", "action": "accept"}}


def test_reject_state_readback_mismatch_retains_previous_revision(tmp_path):
    class IncorrectStateFirewall(FakeFirewall):
        def stage_configuration(self, commands, *, confirm_minutes):
            super().stage_configuration(commands, confirm_minutes=confirm_minutes)
            if self.rules["80200"].get("state") is not None:
                self.rules["80200"]["state"] = "related"

    backend = IncorrectStateFirewall()
    drop = intent("drop", 8443)
    reconcile = make_reconciler(tmp_path, backend).reconcile
    assert reconcile(drop).verified_revision == "drop"
    backend.events.clear()
    desired = FirewallIntent("reject", (replace(drop.rules[0], action="reject", states=("new",)),))

    result = reconcile(desired)

    assert result.verified_revision == "drop"
    assert result.error == "Staged VyOS read-back differs from intended configuration"
    assert backend.events == ["read", "stage", "read"]


@pytest.mark.parametrize(("firewall", "ignore"), [
    ({"global-options": {"state-policy": {"established": {"action": "accept"}}}}, None),
    ({"global-options": {"state-policy": {"offload": {"offload-target": "fast"}}}}, None),
    ({"ipv4": {"name": {"from-wan": {"rule": {"20": {"action": "offload", "offload-target": "fast"}}}}}}, None),
    ({"ipv4": {"forward": {"filter": {"disable-conntrack": {}}}}}, None),
    ({"ipv4": {"prerouting": {"raw": {"rule": {"20": {"action": "notrack"}}}}}}, None),
    ({}, {"ipv4": {"rule": {"20": {"protocol": "tcp"}}}}),
])
def test_stateful_rule_rejects_an_unverified_packet_path_but_can_be_withdrawn(tmp_path, firewall, ignore):
    backend = FakeFirewall()
    base = intent("base", 8443)
    desired = FirewallIntent("return", (replace(base.rules[0], action="reject", states=("established", "related")),))
    reconcile = make_reconciler(tmp_path, backend).reconcile
    assert reconcile(desired).verified_revision == "return"
    backend.firewall_config = firewall
    backend.conntrack_ignore = ignore
    backend.events.clear()

    result = reconcile(desired)

    assert result.error
    assert result.verified_revision == "return"
    assert "stage" not in backend.events
    assert reconcile(base).verified_revision == "base"
    assert "state" not in backend.rules["80200"]


class FakeLanPolicy(FakeFirewall):
    chain_name = "UNIFI_LAN_80200"

    def __init__(self):
        super().__init__()
        self.named = {}
        self.rules["80300"] = {"description": "Operator decision after managed rules", "action": "drop"}
        self.last_commands = ()

    def read_config(self, path):
        if path == ["firewall"]:
            configuration = deepcopy(self.firewall_config)
            ipv4 = configuration.setdefault("ipv4", {})
            ipv4["name"] = deepcopy(self.named)
            ipv4.setdefault("forward", {}).setdefault("filter", {})["rule"] = deepcopy(self.rules)
            return configuration
        return super().read_config(path)

    def stage_configuration(self, commands, *, confirm_minutes):
        self.last_commands = commands
        base = []
        for command in commands:
            path = command["path"]
            if path[:3] != ["firewall", "ipv4", "name"]:
                base.append(command)
                continue
            self._apply_leaf(self.named, path[3:], command)
        super().stage_configuration(base, confirm_minutes=confirm_minutes)

    @staticmethod
    def _apply_leaf(node, path, command):
        for key in path[:-1]:
            node = node.setdefault(key, {})
        leaf = path[-1]
        if command["op"] == "delete":
            del node[leaf]
        elif leaf == "state" and leaf in node:
            node[leaf] = [command["value"], node[leaf]]
        else:
            node[leaf] = command.get("value", {})


def lan_allow(revision="allow", *, companion=True):
    deny = intent("deny", 8443).rules[0]
    allow = replace(deny, action="return")
    rules = [allow]
    if companion:
        rules.append(replace(allow, controller_rule_id=30000, source=deny.destination, destination=deny.source,
                             states=("established", "related"), source_port=True, log=False))
    return FirewallIntent(revision, (*rules, replace(deny, controller_rule_id=10001)))


def test_allow_moves_direct_deny_to_ordered_chain_and_withdraws_it(tmp_path):
    backend = FakeLanPolicy()
    operator = deepcopy(backend.rules)
    reconcile = make_reconciler(tmp_path, backend).reconcile
    assert reconcile(intent("deny", 8443)).verified_revision == "deny"
    native = lan_allow()

    assert reconcile(native).verified_revision == "allow"
    anchor = backend.rules["80200"]
    assert anchor["action"] == "jump" and anchor["jump-target"] == backend.chain_name
    assert backend.rules == {**operator, "80200": anchor}
    chain = backend.named[backend.chain_name]
    assert chain["default-action"] == "return"
    ordered = [chain["rule"][slot] for slot in sorted(chain["rule"], key=int)]
    assert [rule["action"] for rule in ordered] == ["return", "return", "drop"]
    assert ordered[0]["destination"]["port"] == "8443"
    assert ordered[1]["source"] == {"address": "192.168.120.0/24", "port": "8443"}
    assert ordered[1]["destination"] == {"address": "192.168.110.0/24"}
    assert ordered[1]["state"] == ["related", "established"]
    assert "log" not in ordered[1]
    backend.events.clear()

    result = make_reconciler(tmp_path, backend).reconcile(native)

    assert (result.verified_revision, result.error, result.changed) == ("allow", None, False)
    assert "stage" not in backend.events
    assert reconcile(intent("direct-deny", 8445)).verified_revision == "direct-deny"
    assert backend.named == {}
    assert backend.rules["80200"]["destination"]["port"] == "8445"
    assert reconcile(intent("withdraw")).verified_revision == "withdraw"
    assert backend.rules == operator


@pytest.mark.parametrize("interrupted", [False, True])
def test_foreign_firewall_anchor_in_verified_or_pending_journal_prevents_writes(tmp_path, interrupted):
    backend = FakeLanPolicy()
    reconcile = make_reconciler(tmp_path, backend).reconcile
    backend.save_timeout = interrupted
    initial = reconcile(lan_allow())
    assert bool(initial.error) == interrupted
    journal = tmp_path / "firewall.json"
    state = json.loads(journal.read_text())
    record = state["pending"] if interrupted else state
    prefix = "" if interrupted else "verified_"
    record[prefix + "rules"]["80200"]["jump-target"] = "OPERATOR"
    journal.write_text(json.dumps(state))
    backend.events.clear()
    refused = reconcile(intent("withdraw"))
    assert "ownership" in refused.error
    assert "stage" not in backend.events


def test_allow_stops_on_operator_chain_name_collision(tmp_path):
    backend = FakeLanPolicy()
    backend.named[backend.chain_name] = {"default-action": "return"}

    result = make_reconciler(tmp_path, backend).reconcile(lan_allow())

    assert result.verified_revision is None and result.error
    assert "stage" not in backend.events
    assert backend.named[backend.chain_name] == {"default-action": "return"}


@pytest.mark.parametrize("referrer", ["jump", "default-jump", "zone", "default-zone"])
def test_allow_preserves_foreign_references_to_an_owned_chain(tmp_path, referrer):
    backend = FakeLanPolicy()
    reconcile = make_reconciler(tmp_path, backend).reconcile
    assert reconcile(lan_allow()).verified_revision == "allow"
    name = backend.chain_name
    if referrer == "jump":
        backend.rules["80301"] = {"action": "jump", "jump-target": name}
    elif referrer == "default-jump":
        backend.named["Operator"] = {"default-action": "jump", "default-jump-target": name}
    elif referrer == "zone":
        backend.firewall_config["zone"] = {"B": {"from": {"A": {"firewall": {"name": name}}}}}
    else:
        backend.firewall_config["zone"] = {"B": {"default-firewall": {"name": name}}}
    before = backend.read_config(["firewall"])
    backend.events.clear()

    result = reconcile(intent("withdraw"))

    assert result.verified_revision == "allow" and result.error
    assert "stage" not in backend.events
    assert backend.read_config(["firewall"]) == before


def test_allow_recovery_saves_only_the_confirmed_chain_and_anchor(tmp_path):
    backend = FakeLanPolicy()
    reconcile = make_reconciler(tmp_path, backend).reconcile
    assert reconcile(intent("deny", 8443)).verified_revision == "deny"
    backend.save_timeout = True
    native = lan_allow()

    assert reconcile(native).verified_revision == "deny"
    assert "confirm" in backend.events
    backend.save_timeout = False
    backend.events.clear()
    result = make_reconciler(tmp_path, backend).reconcile(native)

    assert (result.verified_revision, result.error) == ("allow", None)
    assert backend.events.count("save") == 1 and "stage" not in backend.events


@pytest.mark.parametrize("observation", ["completed", "rollback-pending", "operator-drift", "helper-disabled"])
def test_lost_confirmation_recovers_only_the_exact_completed_commit(tmp_path, monkeypatch, observation):
    backend = FakeFirewall()
    archive_ready = False
    fingerprint = "1" * 64

    def proof(*, phase):
        if phase == "completed" and not archive_ready:
            raise VyOSReadError("VyOS completed configuration could not be verified")
        return fingerprint

    def lost_confirm():
        backend.events.append("confirm")
        raise VyOSWriteError("Confirmation response was lost")

    monkeypatch.setattr(backend, "confirm_configuration", lost_confirm)
    options = {"commit_proof": proof}
    request = intent("confirmed-on-router", 8443)
    result = make_reconciler(tmp_path, backend, **options).reconcile(request)
    assert result.verified_revision is None and result.error == "Confirmation response was lost"
    journal = json.loads((tmp_path / "firewall.json").read_text())
    assert not journal["pending"]["confirmed"]
    assert journal["pending"]["confirmation_sha256"] == fingerprint
    assert backend.events.count("confirm") == 1 and "save" not in backend.events

    archive_ready = observation != "rollback-pending"
    if observation == "operator-drift":
        fingerprint = "2" * 64
    if observation == "helper-disabled":
        options = {}
    backend.events.clear()
    result = make_reconciler(tmp_path, backend, **options).reconcile(request)
    assert "confirm" not in backend.events and "stage" not in backend.events
    if observation == "completed":
        assert (result.verified_revision, result.error) == ("confirmed-on-router", None)
        assert backend.events.count("save") == 1
    else:
        assert result.verified_revision is None and result.error
        assert "save" not in backend.events


def test_staged_configuration_drift_never_requests_confirmation(tmp_path):
    backend = FakeFirewall()
    fingerprints = iter(("1" * 64, "2" * 64))

    def proof(*, phase):
        if phase == "saved":
            return None
        assert phase == "staged"
        return next(fingerprints)

    result = make_reconciler(tmp_path, backend, commit_proof=proof).reconcile(intent("r1", 8443))
    assert result.error == "VyOS staged configuration changed during verification"
    assert "confirm" not in backend.events and "save" not in backend.events
    assert "confirmation_sha256" not in json.loads((tmp_path / "firewall.json").read_text())["pending"]


def test_proof_enabled_provisioning_preserves_unsaved_operator_configuration(tmp_path):
    backend = FakeFirewall()

    def proof(*, phase):
        assert phase == "saved"
        raise VyOSReadError("VyOS running configuration differs from saved")

    result = make_reconciler(tmp_path, backend, commit_proof=proof).reconcile(intent("r1", 8443))
    assert result.error == "VyOS running configuration differs from saved"
    assert not {"stage", "confirm", "save"}.intersection(backend.events)
    assert not (tmp_path / "firewall.json").exists()


def test_allow_companion_checks_tracking_in_the_named_policy(tmp_path):
    backend = FakeLanPolicy()
    backend.firewall_config = {"global-options": {"state-policy": {"established": {"action": "accept"}}}}
    reconcile = make_reconciler(tmp_path, backend).reconcile
    assert reconcile(lan_allow("without", companion=False)).verified_revision == "without"
    before = backend.read_config(["firewall"])
    backend.events.clear()

    result = reconcile(lan_allow("with"))

    assert result.verified_revision == "without" and "global state policy" in result.error
    assert "stage" not in backend.events
    assert backend.read_config(["firewall"]) == before


def test_allow_requires_exact_staged_chain_before_confirmation(tmp_path):
    class WrongNamedVerdict(FakeLanPolicy):
        def stage_configuration(self, commands, *, confirm_minutes):
            super().stage_configuration(commands, confirm_minutes=confirm_minutes)
            if self.chain_name in self.named:
                self.named[self.chain_name]["rule"]["80200"]["action"] = "accept"

    backend = WrongNamedVerdict()
    reconcile = make_reconciler(tmp_path, backend).reconcile
    assert reconcile(intent("deny", 8443)).verified_revision == "deny"
    backend.events.clear()

    result = reconcile(lan_allow())

    assert result.verified_revision == "deny"
    assert result.error == "Staged VyOS read-back differs from intended configuration"
    assert "confirm" not in backend.events and "save" not in backend.events


@pytest.mark.parametrize("action", ["reject", "return"])
def test_invalid_state_preserves_the_verified_revision_while_operator_policy_preempts_it(tmp_path, action):
    backend = FakeLanPolicy()
    reconcile = make_reconciler(tmp_path, backend).reconcile
    assert reconcile(intent("baseline")).verified_revision == "baseline"
    rule = replace(intent("scoped", 8443).rules[0], action=action, states=("invalid",))
    requested = FirewallIntent("invalid", (rule,))
    operator = {"global-options": {"state-policy": {"invalid": {"action": "drop"}}}}
    backend.firewall_config = deepcopy(operator)
    backend.events.clear()

    blocked = reconcile(requested)

    assert blocked.verified_revision == "baseline" and "global state policy" in blocked.error
    assert "stage" not in backend.events and backend.firewall_config == operator
    backend.firewall_config = {}

    result = reconcile(requested)

    assert (result.verified_revision, result.error) == ("invalid", None)
    managed = backend.named[backend.chain_name]["rule"] if action == "return" else backend.rules
    assert managed["80200"]["state"] == "invalid"


class FakeWanFailover(FakeFirewall):
    def __init__(self):
        super().__init__()
        self.tree = {}

    def read_complete_configuration(self):
        return self.tree

    def show_interfaces(self):
        self.events.append("management")
        return "\n".join(
            f"eth3.{n}: <UP,LOWER_UP>\n    inet 198.18.{n}.1/30" for n in (210, 220)
        )

    def stage_configuration(self, commands, *, confirm_minutes):
        assert confirm_minutes > 0
        self.events.append("stage")
        for command in commands:
            path = command["path"]
            node = self.tree
            if command["op"] == "delete":
                for part in path[:-1]:
                    node = node[part]
                del node[path[-1]]
            else:
                for part in path[:-2]:
                    node = node.setdefault(part, {})
                node[path[-2]] = path[-1]
        if self.tree.get("policy") == {"route": {}}:
            self.tree["policy"] = {}

    def fib(self):
        routes = []
        failover = self.tree.get("protocols", {}).get("failover")
        if failover is not None:
            for gateway, hop in failover["route"]["0.0.0.0/0"]["next-hop"].items():
                routes.append({"dst": "default", "gateway": gateway, "dev": hop["interface"],
                               "metric": int(hop["metric"]), "flags": []})
        return {"routes": routes, "lookup": {**min(routes, key=lambda r: r["metric"]), "protocol": "failover"}
                if routes else None}


def test_wan_default_joins_route_nat_and_fib_verification_in_one_revision(tmp_path, monkeypatch):
    backend = FakeWanFailover()
    monkeypatch.setattr(vyos, "read_failover_fib", lambda _command: backend.fib(), raising=False)
    reconciler = make_reconciler(tmp_path, backend, wan_fib_command="/lab/verified-fib")
    for revision, primary in (("create", "eth0"), ("edit", "eth2"), ("delete", None)):
        result = reconciler.reconcile(intent(revision), wan_intent=WanFailoverIntent(revision, primary))
        assert result.changed and result.verified_revision == revision, result.error
        assert backend.events[-2:] == ["confirm", "save"]
        state = json.loads((tmp_path / "firewall.json").read_text())
        assert state["pending"] is None
        assert bool(state["verified_wan_default"]) == (primary is not None)
        if primary is not None:
            assert "different scope" in make_reconciler(tmp_path, backend).reconcile(intent("disable-too-early")).error
    assert backend.fib() == {"routes": [], "lookup": None}
    assert not backend.tree["nat"]["source"]["rule"]
    assert make_reconciler(tmp_path, backend).reconcile(intent("disabled-after-withdrawal")).verified_revision == "disabled-after-withdrawal"


@pytest.mark.parametrize("fault", [False, True])
def test_policy_route_checks_live_policy_before_acknowledging_and_preserves_its_fallback(tmp_path, monkeypatch, fault):
    from provisioners.uxg_pbr import PolicyRouteError, PolicyRouteIntent
    from provisioners.vyos_pbr import read_policy_route_state

    backend = FakeWanFailover()
    first, second = "198.19.210.243/32", "198.19.210.244/32"
    operator = {"route": {
        first: {"next-hop": {"198.18.210.2": {"interface": "eth3.210"}}},
        second: {"next-hop": {"198.18.210.2": {"interface": "eth3.210"}}},
        "198.19.210.240/29": {"blackhole": {"distance": "254"}},
    }}
    backend.tree["protocols"] = {"static": {"table": {"179": operator}}}
    monkeypatch.setattr(vyos, "read_failover_fib", lambda _command: backend.fib())
    monkeypatch.setattr(vyos, "read_policy_route_fib", lambda _command: read_policy_route_state(backend.tree),
                        raising=False)

    def verify(observed, target, **_):
        backend.events.append("policy verification")
        if observed != target or fault and target is not None:
            raise PolicyRouteError("Unverified live policy route")

    monkeypatch.setattr(vyos, "verify_policy_route_fib", verify, raising=False)
    monkeypatch.setattr(vyos, "verify_policy_route_guard", lambda snapshot, protected: None, raising=False)
    reconciler = make_reconciler(tmp_path, backend, wan_fib_command="/lab/verified-wan",
                                policy_route_fib_command="/lab/verified-policy", commit_proof=lambda **_: "1" * 64)

    def apply(revision, destination):
        return reconciler.reconcile(intent(revision), wan_intent=WanFailoverIntent(revision, "eth2"),
                                    policy_route_intent=PolicyRouteIntent(revision, destination))

    assert apply("baseline", None).verified_revision == "baseline"
    backend.events.clear()
    result = apply("create", first)
    if fault:
        assert result.verified_revision == "baseline"
        assert "Unverified live policy route" in result.error
        assert backend.events.count("confirm") == 1  # Guard preparation completed before the unconfirmed selector.
        assert json.loads((tmp_path / "firewall.json").read_text())["pending"]["policy_route"] == first
        return
    assert result.verified_revision == "create", result.error
    assert [event for event in backend.events if event in {"stage", "confirm", "save"}] == ["stage", "confirm", "save"] * 2
    guard_rules = backend.tree["firewall"]["ipv4"]["forward"]["filter"]["rule"]
    assert guard_rules["1"]["destination"] == {"address": first}
    assert apply("edit", second).verified_revision == "edit"
    assert guard_rules == {"2": guard_rules["2"]}
    assert guard_rules["2"]["destination"] == {"address": second}
    assert apply("delete", None).verified_revision == "delete"
    assert guard_rules == {}
    assert backend.tree["policy"] == {}
    assert backend.tree["protocols"]["static"]["table"]["179"] == operator


@pytest.mark.parametrize("fault", [None, "save", "stage"])
def test_policy_route_prepares_and_saves_the_table_before_staging_its_selector(tmp_path, monkeypatch, fault):
    from provisioners.uxg_pbr import PolicyRouteIntent
    from provisioners.vyos_pbr import read_policy_route_state

    class FakePreparation(FakeWanFailover):
        stage_timeout = False

        def stage_configuration(self, commands, *, confirm_minutes):
            batches.append(commands)
            super().stage_configuration(commands, confirm_minutes=confirm_minutes)
            if self.stage_timeout:
                self.stage_timeout = False
                raise VyOSWriteError("table stage reply timed out")

    backend = FakePreparation()
    batches = []
    monkeypatch.setattr(vyos, "read_failover_fib", lambda _command: backend.fib())

    def snapshot(_command):
        tables = backend.tree.get("protocols", {}).get("static", {}).get("table", {})
        return read_policy_route_state(backend.tree), "179" in tables

    def verify(observed, destination, *, table_present=True, **_):
        assert observed == (destination, table_present)

    monkeypatch.setattr(vyos, "read_policy_route_fib", snapshot)
    monkeypatch.setattr(vyos, "verify_policy_route_fib", verify)
    monkeypatch.setattr(vyos, "verify_policy_route_guard", lambda snapshot, protected: None, raising=False)

    def bridge():
        return make_reconciler(tmp_path, backend, wan_fib_command="/lab/verified-wan",
                              policy_route_fib_command="/lab/verified-policy", commit_proof=lambda **_: "1" * 64)

    def apply(reconciler, revision, destination):
        return reconciler.reconcile(intent(revision), wan_intent=WanFailoverIntent(revision, "eth2"),
                                    policy_route_intent=PolicyRouteIntent(revision, destination))

    assert apply(bridge(), "baseline", None).verified_revision == "baseline"
    baseline = deepcopy(backend.tree)
    baseline_stages = len(batches)
    backend.events.clear()
    backend.save_timeout = fault == "save"
    backend.stage_timeout = fault == "stage"
    first = "198.19.210.243/32"
    result = apply(bridge(), "create", first)
    if fault:
        assert result.verified_revision == "baseline" and result.error
        assert len(batches) == baseline_stages + 1
        assert read_policy_route_state(backend.tree) is None
        backend.save_timeout = False
        if fault == "stage":
            assert "requires recovery" in apply(bridge(), "create", first).error
            assert len(batches) == baseline_stages + 1
            setup = json.loads((tmp_path / "firewall.json").read_text())["policy_table_setup"]
            backend.tree = baseline
            monkeypatch.setattr(vyos.time, "time", lambda: setup["retry_after"] + 1)
        result = apply(bridge(), "create", first)
    assert result.verified_revision == "create", result.error
    assert len(batches) == baseline_stages + (4 if fault == "stage" else 3)
    preparation, guard, selector = batches[-3:]
    assert all(command["path"][:4] == ["protocols", "static", "table", "179"] for command in preparation)
    assert all(command["path"][:6] == ["firewall", "ipv4", "forward", "filter", "rule", "1"] for command in guard)
    assert all(command["path"][0] == "policy" for command in selector)
    assert [event for event in backend.events if event in {"stage", "confirm", "save"}] == (
        (["stage"] if fault == "stage" else []) + ["stage", "confirm", "save"]
        + (["save"] if fault == "save" else []) + 2 * ["stage", "confirm", "save"]
    )


@pytest.mark.parametrize(("prerequisite", "error"), [
    ("commit proof", "commit proof"),
    ("unused guard", "guard slots contain unrelated rules"),
])
def test_policy_route_validates_prerequisites_before_its_first_vyos_write(tmp_path, monkeypatch, prerequisite, error):
    from provisioners.uxg_pbr import PolicyRouteIntent

    backend = FakeWanFailover()
    if prerequisite == "unused guard":
        backend.tree["firewall"] = {"ipv4": {"forward": {"filter": {"rule": {"1": {"action": "accept"}}}}}}
    monkeypatch.setattr(vyos, "read_failover_fib", lambda _: backend.fib())
    bridge = make_reconciler(tmp_path, backend, wan_fib_command="/lab/wan", policy_route_fib_command="/lab/policy",
                            commit_proof=(lambda **_: "1" * 64) if prerequisite == "unused guard" else None)
    result = bridge.reconcile(intent("create"), wan_intent=WanFailoverIntent("create", "eth2"),
                              policy_route_intent=PolicyRouteIntent("create", "198.19.210.243/32"))
    assert result.verified_revision is None and error in result.error
    assert "stage" not in backend.events


@pytest.mark.parametrize("fault", ["save", "confirm", "foreign drift"])
def test_policy_route_edit_recovers_guard_cleanup_before_acknowledging(tmp_path, monkeypatch, fault):
    from provisioners.uxg_pbr import PolicyRouteIntent
    from provisioners.vyos_pbr import read_policy_route_guard, read_policy_route_state

    class FakeGuardCleanup(FakeWanFailover):
        fault = None

        def stage_configuration(self, commands, *, confirm_minutes):
            if (commands[0]["path"][0] == "policy" and commands[0]["op"] == "set"
                    and read_policy_route_state(self.tree) is not None):
                assert read_policy_route_guard(self.saved) == [first, second]
            super().stage_configuration(commands, confirm_minutes=confirm_minutes)
            if self.fault == "foreign drift" and commands[0]["path"][0] == "firewall":
                self.tree["system"] = {"host-name": "concurrent-router-change"}
            self.cleanup = commands[0]["op"] == "delete" and commands[0]["path"][0] == "firewall"

        def confirm_configuration(self):
            super().confirm_configuration()
            if self.fault == "confirm" and self.cleanup:
                raise VyOSWriteError("guard cleanup confirm interrupted")

        def save_configuration(self):
            if self.fault == "save" and self.cleanup:
                raise VyOSWriteError("guard cleanup save interrupted")
            super().save_configuration()
            self.saved = deepcopy(self.tree)

    first, second = "198.19.210.243/32", "198.19.210.244/32"
    backend = FakeGuardCleanup()
    monkeypatch.setattr(vyos, "read_failover_fib", lambda _: backend.fib())
    monkeypatch.setattr(vyos, "read_policy_route_fib", lambda _: deepcopy(backend.tree))
    monkeypatch.setattr(vyos, "verify_policy_route_fib", lambda snapshot, target, **_: (
        target == read_policy_route_state(snapshot) or pytest.fail("incorrect selector")
    ))
    monkeypatch.setattr(vyos, "verify_policy_route_guard", lambda snapshot, protected: (
        protected == read_policy_route_guard(snapshot) or pytest.fail("incorrect forwarding guard")
    ))

    def proof(*, phase):
        return sha256(json.dumps(backend.tree, sort_keys=True).encode()).hexdigest()

    def apply(revision, target):
        bridge = make_reconciler(tmp_path, backend, wan_fib_command="/lab/wan", policy_route_fib_command="/lab/policy",
                                commit_proof=proof)
        return bridge.reconcile(intent(revision), wan_intent=WanFailoverIntent(revision, "eth2"),
                                policy_route_intent=PolicyRouteIntent(revision, target))

    assert apply("create", first).verified_revision == "create"
    backend.fault = fault
    confirmations = backend.events.count("confirm")
    result = apply("edit", second)
    if fault == "foreign drift":
        assert result.verified_revision == "create" and "differs from the requested rules" in result.error
        assert backend.events.count("confirm") == confirmations
        assert read_policy_route_state(backend.saved) == first
        assert read_policy_route_guard(backend.saved) == [first]
        return
    assert result.verified_revision == "create" and result.error == f"guard cleanup {fault} interrupted"
    assert read_policy_route_state(backend.saved) == second
    assert read_policy_route_guard(backend.saved) == [first, second]
    assert read_policy_route_guard(backend.tree) == [second]
    stages = backend.events.count("stage")
    backend.fault = None
    result = apply("edit", second)
    assert result.verified_revision == "edit" and result.error is None
    assert read_policy_route_guard(backend.saved) == [second]
    assert backend.events.count("stage") == stages

@pytest.mark.parametrize("fault", [False, True])
def test_qos_checks_the_kernel_before_confirming_and_preserves_unrelated_firewall_rules(tmp_path, monkeypatch, fault):
    from provisioners.uxg_qos import QosError, QosIntent, QosLimit
    from provisioners.vyos_qos import read_qos_state

    class FakeQos(FakeWanFailover):
        def __init__(self):
            super().__init__()
            self.tree["firewall"] = {"ipv4": {"forward": {"filter": {"rule": self.rules}}}}

        def show_interfaces(self):
            self.events.append("management")
            return "eth3.110: <UP,LOWER_UP>\n    inet 192.168.110.1/24\neth3.210: <UP,LOWER_UP>\n    inet 198.18.210.1/30"

        def stage_configuration(self, commands, *, confirm_minutes):
            paths = [{**command, "path": [*command["path"], command["value"]]} if "value" in command else command
                     for command in commands]
            super().stage_configuration(paths, confirm_minutes=confirm_minutes)
            qos = self.tree.get("qos", {})
            if not any(qos.get("interface", {}).values()) and not qos.get("policy", {}).get("shaper"):
                self.tree.pop("qos", None)

    backend = FakeQos()
    monkeypatch.setattr(vyos, "read_qos_kernel", lambda _command: read_qos_state(backend.tree), raising=False)

    def verify(observed, target, **_):
        backend.events.append("QoS kernel verification")
        if observed != target or fault and target is not None:
            raise QosError("Unverified live QoS")

    monkeypatch.setattr(vyos, "verify_qos_kernel", verify, raising=False)
    reconciler = make_reconciler(tmp_path, backend, qos_kernel_command="/lab/verified-qos")

    def apply(revision, limit):
        return reconciler.reconcile(intent(revision), qos_intent=QosIntent(revision, limit))

    assert apply("baseline", None).verified_revision == "baseline"
    backend.events.clear()
    first, second = QosLimit(8000, 3000), QosLimit(8000, 5000)
    result = apply("create", first)
    if fault:
        assert result.verified_revision == "baseline" and result.error == "Unverified live QoS"
        assert "confirm" not in backend.events
        assert json.loads((tmp_path / "firewall.json").read_text())["pending"]["qos"] == {
            "download_kbps": 8000, "upload_kbps": 3000, "shapers": ["UNIFI_QOS_UP", "UNIFI_QOS_DOWN"],
        }
        return
    assert result.verified_revision == "create", result.error
    assert backend.events[-2:] == ["confirm", "save"]
    assert apply("edit", second).verified_revision == "edit"

    # A policy with equal rates and a different name does not belong to this journal.
    original_qos = deepcopy(backend.tree["qos"])
    shapers = backend.tree["qos"]["policy"]["shaper"]
    for attachment in backend.tree["qos"]["interface"].values():
        name = attachment["egress"]
        foreign_name = name.replace("UNIFI_QOS_", "OPERATOR_QOS_")
        attachment["egress"] = foreign_name
        shapers[foreign_name] = shapers.pop(name)
    backend.events.clear()
    blocked = apply("delete", None)
    assert blocked.verified_revision == "edit" and blocked.error
    assert "stage" not in backend.events

    backend.tree["qos"] = original_qos
    assert apply("delete", None).verified_revision == "delete"
    assert "qos" not in backend.tree
    assert backend.rules == {"20": {"description": "Operator decision", "action": "accept"}}


class FakeDualStackFirewall(FakeLanPolicy):
    def __init__(self):
        super().__init__()
        self.ipv6 = {"90000": {"description": "Unrelated IPv6 rule", "action": "drop"}}
        self.named_ipv6 = {}
        self.ipv6_up = True

    def read_config(self, path):
        if path == ["firewall"]:
            configuration = super().read_config(path)
            ipv6 = configuration.setdefault("ipv6", {})
            ipv6["name"] = deepcopy(self.named_ipv6)
            ipv6.setdefault("forward", {}).setdefault("filter", {})["rule"] = deepcopy(self.ipv6)
            return configuration
        if path[1:2] == ["ipv6"]:
            self.events.append("read-ipv6")
            return {"rule": self.ipv6.copy()}
        return super().read_config(path)

    def stage_configuration(self, commands, *, confirm_minutes):
        ipv4 = [row for row in commands if row["path"][1] == "ipv4"]
        super().stage_configuration(ipv4, confirm_minutes=confirm_minutes)
        for command in commands:
            path = command["path"]
            if path[1] != "ipv6":
                continue
            if path[2] == "name":
                self._apply_leaf(self.named_ipv6, path[3:], command)
            else:
                self._apply_leaf(self.ipv6, path[5:], command)

    def show_interfaces(self):
        self.events.append("management")
        if not self.ipv6_up:
            return "eth3.110: <UP>"
        return "\n".join(
            f"eth3.{n}: <UP,LOWER_UP>\n    inet6 fd42:7891:{n}::1/64 scope global" for n in (110, 120)
        )


def test_ipv6_deny_needs_its_own_map_and_preserves_both_families(tmp_path):
    backend = FakeDualStackFirewall()
    source, dest = (IPv6Network(f"fd42:7891:{n}::/64") for n in (110, 120))
    deny = FirewallRule(10001, source, dest, 18443)
    combined = FirewallIntent("mixed", (*intent("v4", 8443).rules, deny))
    result = make_reconciler(tmp_path, backend).reconcile(combined)
    assert "mapped" in result.error and "stage" not in backend.events

    reconciler = make_reconciler(tmp_path, backend, ipv6_interfaces={source: "eth3.110", dest: "eth3.120"})
    result = reconciler.reconcile(combined)
    assert result.verified_revision == "mixed", result.error
    assert backend.events.count("stage") == 1
    assert backend.rules["80200"]["destination"]["port"] == "8443"
    assert backend.ipv6["80201"]["destination"] == {"address": str(dest), "port": "18443"}
    assert backend.ipv6["80201"]["source"] == {"address": str(source)}
    assert reconciler.reconcile(intent("withdraw-ipv6", 8443)).verified_revision == "withdraw-ipv6"
    assert set(backend.ipv6) == {"90000"}
    assert backend.rules["80200"]["destination"]["port"] == "8443"


def ipv6_allow(source, destination):
    allow = FirewallRule(10003, source, destination, 18443, action="return")
    companion = FirewallRule(30000, destination, source, 18443, action="return",
                             states=("established", "related"), source_port=True, log=False)
    return allow, companion


def test_ipv6_allow_has_independent_chain_and_withdrawal(tmp_path):
    backend = FakeDualStackFirewall()
    source, destination = (IPv6Network(f"fd42:7891:{n}::/64") for n in (110, 120))
    ipv6_map = {source: "eth3.110", destination: "eth3.120"}
    deny = FirewallRule(10002, source, destination, 18443)
    v4 = lan_allow("v4", companion=False).rules
    apply = make_reconciler(tmp_path, backend, ipv6_interfaces=ipv6_map).reconcile
    assert apply(FirewallIntent("existing", (*v4, deny))).verified_revision == "existing"
    before_ipv4 = deepcopy(backend.named)
    combined = FirewallIntent("dual", (*v4, *ipv6_allow(source, destination), deny))

    result = apply(combined)

    assert result.verified_revision == "dual", result.error
    assert backend.rules["80200"]["jump-target"] == backend.chain_name
    assert backend.ipv6["80200"]["jump-target"] == backend.chain_name
    assert backend.ipv6["90000"] == {"description": "Unrelated IPv6 rule", "action": "drop"}
    assert backend.named == before_ipv4
    chain = backend.named_ipv6[backend.chain_name]
    assert chain["default-action"] == "return"
    companion = chain["rule"]["80203"]
    assert companion["source"] == {"address": str(destination), "port": "18443"}
    assert companion["destination"] == {"address": str(source)}
    assert sorted(companion["state"]) == ["established", "related"]
    restarted = make_reconciler(tmp_path, backend, ipv6_interfaces=ipv6_map).reconcile(combined)
    assert restarted.verified_revision == "dual" and restarted.changed is False
    backend.ipv6_up = False
    backend.events.clear()
    lost_path = apply(combined)
    assert lost_path.verified_revision == "dual" and "active VyOS LAN" in lost_path.error
    assert "stage" not in backend.events
    backend.ipv6_up = True
    assert apply(FirewallIntent("withdraw-v6-allow", (*v4, deny))).verified_revision == "withdraw-v6-allow"
    assert backend.named_ipv6 == {} and backend.named == before_ipv4
    assert backend.ipv6["80202"]["action"] == "drop"


def test_ipv6_named_policy_requires_live_mapped_prefixes_before_staging(tmp_path):
    backend = FakeDualStackFirewall()
    backend.ipv6_up = False
    source, destination = (IPv6Network(f"fd42:7891:{n}::/64") for n in (110, 120))
    apply = make_reconciler(tmp_path, backend, ipv6_interfaces={source: "eth3.110", destination: "eth3.120"}).reconcile

    result = apply(FirewallIntent("lost-prefix", ipv6_allow(source, destination)))

    assert result.verified_revision is None and "active VyOS LAN" in result.error
    assert "stage" not in backend.events


def test_ipv6_named_policy_rejects_foreign_ipv6_zone_binding(tmp_path):
    backend = FakeDualStackFirewall()
    source, destination = (IPv6Network(f"fd42:7891:{n}::/64") for n in (110, 120))
    apply = make_reconciler(tmp_path, backend, ipv6_interfaces={source: "eth3.110", destination: "eth3.120"}).reconcile
    managed = FirewallIntent("ipv6", ipv6_allow(source, destination))
    backend.firewall_config["zone"] = {"A": {"default-firewall": {"name": backend.chain_name}}}
    assert apply(managed).verified_revision == "ipv6"
    backend.firewall_config["zone"]["A"]["default-firewall"]["ipv6-name"] = backend.chain_name
    backend.events.clear()

    result = apply(FirewallIntent("withdraw", ()))

    assert result.verified_revision == "ipv6" and "operator firewall zone" in result.error
    assert "stage" not in backend.events


def test_inspection_transition_requires_unchanged_router_configuration(tmp_path):
    backend = FakeFirewall()
    reconciler = make_reconciler(tmp_path, backend)
    assert reconciler.reconcile(intent("current", 8443)).verified_revision == "current"

    def unavailable():
        raise ValueError("Inspection actuator is unavailable")

    incompatible = reconciler.reconcile(intent("mixed", 8444), verify_unchanged=unavailable)
    assert incompatible.verified_revision == "current" and "separate" in incompatible.error
    assert backend.rules["80200"]["destination"]["port"] == "8443"
    assert backend.events.count("stage") == 1
    failed = reconciler.reconcile(intent("mode-only", 8443), verify_unchanged=unavailable)
    assert failed.verified_revision == "current" and "unavailable" in failed.error
    assert json.loads((tmp_path / "firewall.json").read_text())["verified_revision"] == "current"
    verified = []
    result = reconciler.reconcile(intent("mode-only", 8443), verify_unchanged=lambda: verified.append(True))
    assert result.verified_revision == "mode-only"
    assert verified == [True]
    assert backend.events.count("stage") == 1


def test_ambiguous_apply_is_read_back_and_not_retried_after_restart(tmp_path):
    backend = FakeFirewall()
    backend.timeout = True
    result = make_reconciler(tmp_path, backend).reconcile(intent("create", 8443))
    assert result.error and result.verified_revision is None
    assert backend.events == ["read", "stage", "read"]
    assert make_reconciler(tmp_path, backend).reconcile(intent("create", 8443)).error
    assert backend.events == ["read", "stage", "read", "read"]


def test_restart_after_confirm_resume_save_only_after_read_back(tmp_path):
    backend = FakeFirewall()
    backend.save_timeout = True
    result = make_reconciler(tmp_path, backend).reconcile(intent("create", 8443))
    assert result.error and result.verified_revision is None
    backend.save_timeout = False
    result = make_reconciler(tmp_path, backend).reconcile(intent("create", 8443))
    assert result.verified_revision == "create"
    assert backend.events[-3:] == ["read", "management", "save"]
    assert backend.events.count("stage") == 1
    assert backend.events.count("confirm") == 1


def dhcp_snapshot(stage):
    fixtures = Path(__file__).parent / "fixtures/uxg_pro"
    dhcp = json.loads((fixtures / "native-dhcp-snapshots.json").read_text())
    firewall = json.loads((fixtures / "zbf-native-snapshots.json").read_text())["snapshots"]["baseline"]
    document = json.loads(firewall["system_cfg"])
    document["udapi"]["interfaces"] = [dhcp["managed_interface"]]
    servers = [dhcp["default_server"]]
    if dhcp["managed_servers"][stage] is not None:
        servers.append(dhcp["managed_servers"][stage])
    document["udapi"]["services"] = {"dhcpServers": servers}
    return json.dumps(document)


class FakeCombinedConfig(FakeFirewall):
    def __init__(self):
        super().__init__()
        self.networks = {"operator": {"subnet": {"203.0.113.0/24": {"subnet-id": "9"}}}}
        self.dhcp_globals = {}
        self.batches = []

    def read_config(self, path):
        if path == ["service", "dhcp-server", "shared-network-name"]:
            return {"shared-network-name": self.networks.copy()}
        if path == ["service", "dhcp-server"]:
            return {"shared-network-name": self.networks.copy(), **self.dhcp_globals}
        if path == ["interfaces", "ethernet", "eth3", "vif", "110", "address"]:
            return {"address": "192.0.2.1/24"}
        return super().read_config(path)

    def stage_configuration(self, commands, *, confirm_minutes):
        self.batches.append(commands)
        firewall_commands = []
        for command in commands:
            path = command["path"]
            if path[0] == "firewall":
                firewall_commands.append(command)
                continue
            if command == {"op": "delete", "path": ["service", "dhcp-server"]}:
                assert not self.dhcp_globals
                self.networks.clear()
                continue
            assert path[:3] == ["service", "dhcp-server", "shared-network-name"]
            if command["op"] == "delete":
                del self.networks[path[3]]
                continue
            current = self.networks
            for part in path[3:-1]:
                current = current.setdefault(part, {})
            current[path[-1]] = command["value"]
        super().stage_configuration(firewall_commands, confirm_minutes=confirm_minutes)


def test_gateway_scope_reconciles_firewall_and_dhcp_in_one_transaction(tmp_path):
    backend = FakeCombinedConfig()
    scope = DhcpScope("br110", "eth3.110", "unifi-vlan110", 110)
    reconciler = make_reconciler(tmp_path, backend, dhcp_scope=scope)

    create = decode_dhcp_intent(dhcp_snapshot("create"), revision="create", scope=scope)
    assert reconciler.reconcile(intent("create", 8443), dhcp_intent=create).verified_revision == "create"
    assert len(backend.batches) == 1
    assert {command["path"][0] for command in backend.batches[0]} == {"firewall", "service"}
    assert backend.networks["unifi-vlan110"]["subnet"]["192.0.2.0/24"]["lease"] == "3600"
    assert backend.rules["80200"]["destination"]["port"] == "8443"

    removed = decode_dhcp_intent(dhcp_snapshot("delete"), revision="delete", scope=scope)
    assert reconciler.reconcile(intent("delete"), dhcp_intent=removed).verified_revision == "delete"
    assert set(backend.networks) == {"operator"}
    assert set(backend.rules) == {"20"}


def test_dhcp_ownership_conflict_rejects_firewall_change_as_well(tmp_path):
    backend = FakeCombinedConfig()
    scope = DhcpScope("br110", "eth3.110", "unifi-vlan110", 110)
    backend.networks[scope.shared_network] = {"operator": "unverified"}
    reconciler = make_reconciler(tmp_path, backend, dhcp_scope=scope)
    create = decode_dhcp_intent(dhcp_snapshot("create"), revision="create", scope=scope)

    rejected = reconciler.reconcile(intent("create", 8443), dhcp_intent=create)

    assert rejected.error and rejected.verified_revision is None
    assert not backend.batches
    assert set(backend.rules) == {"20"}


@pytest.mark.parametrize("global_settings", [{}, {"listen-address": "192.0.2.1"}])
def test_removing_last_dhcp_network_requires_ownership_of_entire_service(tmp_path, global_settings):
    backend = FakeCombinedConfig()
    backend.networks.clear()
    backend.dhcp_globals = global_settings
    scope = DhcpScope("br110", "eth3.110", "unifi-vlan110", 110)
    reconciler = make_reconciler(tmp_path, backend, dhcp_scope=scope)

    create = decode_dhcp_intent(dhcp_snapshot("create"), revision="create", scope=scope)
    assert reconciler.reconcile(intent("create"), dhcp_intent=create).verified_revision == "create"
    deleted = decode_dhcp_intent(dhcp_snapshot("delete"), revision="delete", scope=scope)
    result = reconciler.reconcile(intent("delete"), dhcp_intent=deleted)

    if global_settings:
        assert result.error and result.verified_revision == "create"
        assert set(backend.networks) == {scope.shared_network}
        assert len(backend.batches) == 1
    else:
        assert not result.error and result.verified_revision == "delete"
        assert backend.batches[-1] == [{"op": "delete", "path": ["service", "dhcp-server"]}]
        assert not backend.networks


def test_dhcp_fingerprint_excludes_only_the_explicit_scope():
    scope = DhcpScope("br110", "eth3.110", "unifi-vlan110", 110)
    fingerprints = {
        unmanaged_config_fingerprint(dhcp_snapshot(stage), revision=stage, dhcp_scope=scope)
        for stage in ("create", "edit", "delete")
    }
    assert len(fingerprints) == 1
    modified = json.loads(dhcp_snapshot("create"))
    modified["udapi"]["services"]["dhcpServers"][0]["leaseTime"] += 1
    assert unmanaged_config_fingerprint(json.dumps(modified), revision="changed", dhcp_scope=scope) not in fingerprints


ROUTE_DESTINATION = "203.0.113.20/32"
ROUTE_SCOPE = StaticRouteScope((ROUTE_DESTINATION,), {"192.0.2.2": "eth3.210", "198.51.100.2": "eth3.220"})


def route_snapshot(stage):
    fixtures = Path(__file__).parent / "fixtures/uxg_pro"
    routes = json.loads((fixtures / "native-static-route-snapshots.json").read_text())["routes"]
    document = json.loads(dhcp_snapshot("delete"))
    document["udapi"]["routes/static"] = routes[stage]
    return json.dumps(document)


class FakeRouteConfig(FakeCombinedConfig):
    def __init__(self):
        super().__init__()
        self.static = {}
        self.report_route_active = True
        self.report_blackhole = True

    def read_config(self, path):
        if path in (["protocols", "static", "route"], ["protocols", "static", "route6"]):
            ipv6 = path[-1] == "route6"
            routes = {prefix: row for prefix, row in self.static.items() if (":" in prefix) == ipv6}
            return {path[-1]: routes} if routes else None
        return super().read_config(path)

    def show_ipv4_routes(self):
        return self._show_routes((("192.0.2.0/30", "eth3.210"), ("198.51.100.0/30", "eth3.220")))

    def show_ipv6_routes(self):
        return self._show_routes((("2001:db8:210::/64", "eth3.210"), ("2001:db8:220::/64", "eth3.220")))

    def _show_routes(self, connected):
        table = {
            cidr: [{"protocol": "connected", "selected": True, "installed": True, "table": 254,
                   "nexthops": [{"fib": True, "active": True, "directlyConnected": True,
                                "interfaceName": interface}]}]
            for cidr, interface in connected
        }
        ipv6 = ":" in connected[0][0]
        for destination, route in self.static.items():
            if (":" in destination) != ipv6:
                continue
            paths = []
            if "blackhole" in route:
                paths.append((int(route["blackhole"]["distance"]),
                              {"blackhole": self.report_blackhole, "unreachable": True}))
            paths.extend((int(params["distance"]), {"directlyConnected": True, "interfaceName": interface})
                         for interface, params in route.get("interface", {}).items())
            paths.extend((int(params["distance"]), {"ip": gateway, "interfaceName": params["interface"]})
                         for gateway, params in route.get("next-hop", {}).items())
            paths = sorted(((distance, hop) for distance, hop in paths if distance < 255), key=lambda item: item[0])
            table[destination] = [
                {"protocol": "static", "selected": index == 0, "installed": index == 0 and self.report_route_active,
                 "table": 254, "distance": distance, "nexthops": [{**hop, "fib": index == 0, "active": True}]}
                for index, (distance, hop) in enumerate(paths)
            ]
        return table

    def stage_configuration(self, commands, *, confirm_minutes):
        remaining = []
        for command in commands:
            path = command["path"]
            if path[:3] not in (["protocols", "static", "route"], ["protocols", "static", "route6"]):
                remaining.append(command)
                continue
            if command["op"] == "delete":
                del self.static[path[3]]
                continue
            current = self.static
            for part in path[3:-1]:
                current = current.setdefault(part, {})
            current[path[-1]] = command["value"]
        super().stage_configuration(remaining, confirm_minutes=confirm_minutes)


def test_add_static_scope_without_resetting_existing_provisioning_journal(tmp_path):
    backend = FakeRouteConfig()
    dhcp_scope = DhcpScope("br110", "eth3.110", "unifi-vlan110", 110)
    previous = make_reconciler(tmp_path, backend, dhcp_scope=dhcp_scope)
    previous_dhcp = decode_dhcp_intent(dhcp_snapshot("create"), revision="before", scope=dhcp_scope)
    assert previous.reconcile(intent("before", 8443), dhcp_intent=previous_dhcp).verified_revision == "before"

    combined = make_reconciler(tmp_path, backend, dhcp_scope=dhcp_scope, route_scope=ROUTE_SCOPE)
    routes = decode_route_intent(route_snapshot("create"), revision="after", scope=ROUTE_SCOPE)
    dhcp = decode_dhcp_intent(dhcp_snapshot("create"), revision="after", scope=dhcp_scope)
    result = combined.reconcile(intent("after", 8443), dhcp_intent=dhcp, route_intent=routes)

    assert result.verified_revision == "after"
    assert backend.static[ROUTE_DESTINATION]["next-hop"]["192.0.2.2"]["interface"] == "eth3.210"
    assert set(backend.networks) == {"operator", "unifi-vlan110"}
    assert backend.rules["80200"]["destination"]["port"] == "8443"


def test_static_route_requires_installed_next_hop_before_acknowledgement(tmp_path):
    backend = FakeRouteConfig()
    backend.report_route_active = False
    reconciler = make_reconciler(tmp_path, backend, route_scope=ROUTE_SCOPE)
    route = decode_route_intent(route_snapshot("create"), revision="create", scope=ROUTE_SCOPE)
    result = reconciler.reconcile(intent("create"), route_intent=route)

    assert result.error and result.verified_revision is None
    assert "confirm" not in backend.events
    assert "save" not in backend.events


def test_static_scope_can_add_an_aggregate_around_an_owned_live_route(tmp_path):
    backend = FakeRouteConfig()
    initial = make_reconciler(tmp_path, backend, route_scope=ROUTE_SCOPE)
    create = route_snapshot("create")
    intent_create = decode_route_intent(create, revision="create", scope=ROUTE_SCOPE)
    assert initial.reconcile(intent("create"), route_intent=intent_create).verified_revision == "create"
    aggregate = "203.0.113.0/24"
    extended = StaticRouteScope((aggregate, *ROUTE_SCOPE.destinations), ROUTE_SCOPE.next_hops)
    recovered = make_reconciler(tmp_path, backend, route_scope=extended)
    document = json.loads(create)
    routes = document["udapi"]["routes/static"]
    routes.append({
        **routes[0], "destination": aggregate, "description": "STATIC_ROUTE:11111111-1111-4111-8111-000000000002",
        "gateway": "198.51.100.2", "distance": 8,
    })
    add = decode_route_intent(json.dumps(document), revision="add", scope=extended)
    result = recovered.reconcile(intent("add"), route_intent=add)
    assert result.verified_revision == "add", result.error
    assert set(backend.static) == {aggregate, ROUTE_DESTINATION}

    repinned = StaticRouteScope(extended.destinations, {**extended.next_hops, "192.0.2.2": "eth3.220"})
    request = decode_route_intent(json.dumps(document), revision="repin", scope=repinned)
    backend.events.clear()
    result = make_reconciler(tmp_path, backend, route_scope=repinned).reconcile(intent("repin"), route_intent=request)
    assert result.error == "VyOS provisioning state belongs to a different scope"
    assert not {"stage", "confirm", "save"}.intersection(backend.events)


def test_interface_route_scope_extends_a_live_journal_and_prevents_repinning(tmp_path):
    backend = FakeRouteConfig()
    initial = make_reconciler(tmp_path, backend, route_scope=ROUTE_SCOPE)
    create = decode_route_intent(route_snapshot("create"), revision="create", scope=ROUTE_SCOPE)
    assert initial.reconcile(intent("create"), route_intent=create).verified_revision == "create"

    extended = StaticRouteScope(ROUTE_SCOPE.destinations, ROUTE_SCOPE.next_hops, {"br220": "eth3.220"})
    document = json.loads(route_snapshot("create"))
    row = document["udapi"]["routes/static"][0]
    row.pop("gateway")
    row.update(type="interface", interface="br220", distance=5)
    recovered = make_reconciler(tmp_path, backend, route_scope=extended)
    route = decode_route_intent(json.dumps(document), revision="direct", scope=extended)
    result = recovered.reconcile(intent("direct"), route_intent=route)
    assert result.verified_revision == "direct", result.error
    assert backend.static[ROUTE_DESTINATION]["interface"] == {"eth3.220": {"distance": "5"}}

    repinned = StaticRouteScope(extended.destinations, extended.next_hops, {"br220": "eth3.210"})
    request = decode_route_intent(json.dumps(document), revision="repin", scope=repinned)
    backend.events.clear()
    result = make_reconciler(tmp_path, backend, route_scope=repinned).reconcile(intent("repin"), route_intent=request)
    assert result.error == "VyOS provisioning state belongs to a different scope"
    assert not {"stage", "confirm", "save"}.intersection(backend.events)


def test_static_route_delete_waits_for_frr_withdrawal_before_acknowledgement(tmp_path, monkeypatch):
    backend = FakeRouteConfig()
    reconciler = make_reconciler(tmp_path, backend, route_scope=ROUTE_SCOPE)
    create = decode_route_intent(route_snapshot("create"), revision="create", scope=ROUTE_SCOPE)
    assert reconciler.reconcile(intent("create"), route_intent=create).verified_revision == "create"
    read_table = backend.show_ipv4_routes
    stale = read_table()[ROUTE_DESTINATION]
    monkeypatch.setattr(backend, "show_ipv4_routes", lambda: {**read_table(), ROUTE_DESTINATION: stale})
    backend.events.clear()
    delete = decode_route_intent(route_snapshot("delete"), revision="delete", scope=ROUTE_SCOPE)
    result = reconciler.reconcile(intent("delete"), route_intent=delete)
    assert result.verified_revision == "create"
    assert result.error == f"Withdrawn static route {ROUTE_DESTINATION} remains in the VyOS route table"
    assert not {"confirm", "save"}.intersection(backend.events)


def test_dual_stack_static_snapshot_requires_ipv6_withdrawal_before_acknowledgement(tmp_path, monkeypatch):
    backend = FakeRouteConfig()
    ipv6_destination = "2001:db8:300::20/128"
    ipv6_gateway = "2001:db8:220::2"
    scope = StaticRouteScope((*ROUTE_SCOPE.destinations, ipv6_destination),
                             {**ROUTE_SCOPE.next_hops, ipv6_gateway: "eth3.220"})
    document = json.loads(route_snapshot("create"))
    rows = document["udapi"]["routes/static"]
    rows.append({**rows[0], "destination": ipv6_destination, "gateway": ipv6_gateway,
                 "description": "STATIC_ROUTE:11111111-1111-4111-8111-000000000002"})
    reconciler = make_reconciler(tmp_path, backend, route_scope=scope)
    create = decode_route_intent(json.dumps(document), revision="create", scope=scope)
    result = reconciler.reconcile(intent("create"), route_intent=create)
    assert result.verified_revision == "create", result.error
    assert set(backend.static) == {ROUTE_DESTINATION, ipv6_destination}

    rows.pop()
    withdraw = decode_route_intent(json.dumps(document), revision="withdraw", scope=scope)
    original_show = backend.show_ipv6_routes
    stale = original_show()[ipv6_destination]
    monkeypatch.setattr(backend, "show_ipv6_routes", lambda: {**original_show(), ipv6_destination: stale})
    backend.events.clear()
    result = reconciler.reconcile(intent("withdraw"), route_intent=withdraw)
    assert result.verified_revision == "create"
    assert result.error == f"Withdrawn static route {ipv6_destination} remains in the VyOS route table"
    assert not {"confirm", "save"}.intersection(backend.events)
    assert set(backend.static) == {ROUTE_DESTINATION}


def test_withdrawing_standby_requires_its_rib_candidate_to_leave_before_acknowledgement(tmp_path, monkeypatch):
    backend = FakeRouteConfig()
    reconciler = make_reconciler(tmp_path, backend, route_scope=ROUTE_SCOPE)
    document = json.loads(route_snapshot("create"))
    rows = document["udapi"]["routes/static"]
    rows.append({**rows[0], "distance": 15, "gateway": "198.51.100.2",
                 "description": "STATIC_ROUTE:11111111-1111-4111-8111-000000000002"})
    create = decode_route_intent(json.dumps(document), revision="create", scope=ROUTE_SCOPE)
    result = reconciler.reconcile(intent("create"), route_intent=create)
    assert result.verified_revision == "create", result.error
    assert len(backend.static[ROUTE_DESTINATION]["next-hop"]) == 2

    rows.pop()
    remove = decode_route_intent(json.dumps(document), revision="remove", scope=ROUTE_SCOPE)
    read_routes = backend.show_ipv4_routes
    old_rows = read_routes()[ROUTE_DESTINATION]
    monkeypatch.setattr(backend, "show_ipv4_routes", lambda: {**read_routes(), ROUTE_DESTINATION: old_rows})
    backend.events.clear()
    restarted = make_reconciler(tmp_path, backend, route_scope=ROUTE_SCOPE)
    result = restarted.reconcile(intent("remove"), route_intent=remove)
    assert result.verified_revision == "create"
    assert result.error == f"Static route {ROUTE_DESTINATION} has an unverified FRR candidate"
    assert not {"confirm", "save"}.intersection(backend.events)


def test_static_route_identity_survives_restart_and_only_reports_verified_configuration(tmp_path):
    backend = FakeRouteConfig()
    document = json.loads(route_snapshot("create"))
    rows = document["udapi"]["routes/static"]
    primary_id = rows[0]["description"].removeprefix("STATIC_ROUTE:")
    standby_id = "11111111-1111-4111-8111-000000000009"
    rows.append({**rows[0], "distance": 15, "gateway": "198.51.100.2", "description": f"STATIC_ROUTE:{standby_id}"})

    def apply(bridge, revision):
        requested = decode_route_intent(json.dumps(document), revision=revision, scope=ROUTE_SCOPE)
        return bridge.reconcile(intent(revision), route_intent=requested)

    initial = make_reconciler(tmp_path, backend, route_scope=ROUTE_SCOPE)
    assert apply(initial, "create").verified_revision == "create"
    restarted = make_reconciler(tmp_path, backend, route_scope=ROUTE_SCOPE)
    assert restarted.read_verified_static_route_state() == (backend.static, {
        ROUTE_DESTINATION: {"10": {"id": primary_id}, "15": {"id": standby_id}},
    })

    replacement = "11111111-1111-4111-8111-000000000010"
    rows[1]["description"] = f"STATIC_ROUTE:{replacement}"
    assert "reused a revision" in apply(restarted, "create").error
    backend.events.clear()
    assert apply(restarted, "relabel").verified_revision == "relabel"
    assert not {"stage", "confirm", "save"}.intersection(backend.events)
    assert restarted.read_verified_static_route_state()[1][ROUTE_DESTINATION]["15"] == {"id": replacement}

    rows[1]["distance"] = 25
    backend.save_timeout = True
    assert apply(restarted, "edit").verified_revision == "relabel"
    assert restarted.read_verified_static_route_state() == ({}, {})
    backend.save_timeout = False
    recovered = make_reconciler(tmp_path, backend, route_scope=ROUTE_SCOPE)
    assert apply(recovered, "edit").verified_revision == "edit"
    assert recovered.read_verified_static_route_state()[1][ROUTE_DESTINATION]["25"] == {"id": replacement}


@pytest.mark.parametrize("verified_drop", [True, False])
def test_static_blackhole_pause_and_resume_require_exact_frr_state(tmp_path, verified_drop):
    backend = FakeRouteConfig()
    backend.report_blackhole = verified_drop
    scope = StaticRouteScope((ROUTE_DESTINATION,), {})
    reconciler = make_reconciler(tmp_path, backend, route_scope=scope)
    document = json.loads(route_snapshot("create"))
    blackhole = document["udapi"]["routes/static"][0]
    original_id = blackhole["description"]
    del blackhole["gateway"]
    blackhole.update(type="blackhole", distance=1)
    wire = json.dumps(document)
    create = decode_route_intent(wire, revision="create", scope=scope)
    result = reconciler.reconcile(intent("create"), route_intent=create)
    if not verified_drop:
        assert result.verified_revision is None
        assert result.error == f"Managed static route {ROUTE_DESTINATION} has no verified installed blackhole"
        assert not {"confirm", "save"}.intersection(backend.events)
        return
    assert result.verified_revision == "create", result.error
    pause = decode_route_intent(route_snapshot("delete"), revision="pause", scope=scope)
    assert reconciler.reconcile(intent("pause"), route_intent=pause).verified_revision == "pause"
    assert backend.static == {}
    resume = decode_route_intent(wire, revision="resume", scope=scope)
    result = reconciler.reconcile(intent("resume"), route_intent=resume)
    assert result.verified_revision == "resume", result.error
    assert backend.static[ROUTE_DESTINATION] == {"description": original_id, "blackhole": {"distance": "1"}}


DNS_SCOPE = DnsScope("uxg-lab.test")


def dns_snapshot(stage):
    fixture = Path(__file__).parent / "fixtures/uxg_pro/native-static-dns-snapshots.json"
    dns = json.loads(fixture.read_text())
    document = json.loads(route_snapshot("delete"))
    document["udapi"]["versionDetail"]["services/dnsForwarder"] = 4
    forwarder = {**dns["forwarder"], "hostRecords": [*dns["unmanaged"], *dns["records"][stage]]}
    document["udapi"]["services"]["dnsForwarder"] = forwarder
    return json.dumps(document)


class FakeDnsConfig(FakeRouteConfig):
    def __init__(self):
        super().__init__()
        self.forwarding = {"listen-address": "192.0.2.1", "allow-from": "192.0.2.0/24",
                           "authoritative-domain": {"unmanaged.test": {"records": {}}}}

    def read_config(self, path):
        if path == ["service", "dns", "forwarding"]:
            return self.forwarding.copy()
        return super().read_config(path)

    def stage_configuration(self, commands, *, confirm_minutes):
        remaining = []
        for command in commands:
            path = command["path"]
            if path[:3] != ["service", "dns", "forwarding"]:
                remaining.append(command)
                continue
            assert path[3:5] == ["authoritative-domain", DNS_SCOPE.zone]
            if command["op"] == "delete":
                del self.forwarding["authoritative-domain"][DNS_SCOPE.zone]
                continue
            current = self.forwarding
            for part in path[3:-1]:
                current = current.setdefault(part, {})
            current[path[-1]] = command["value"]
        super().stage_configuration(remaining, confirm_minutes=confirm_minutes)


def test_dynamic_dns_revision_preserves_operator_dns_and_reuses_transaction(tmp_path):
    backend = FakeDnsConfig()
    reconciler = make_reconciler(tmp_path, backend, dns_scope=DNS_SCOPE)
    dns = decode_dns_intent(dns_snapshot("create"), revision="create", scope=DNS_SCOPE)
    result = reconciler.reconcile(intent("create", 8443), dns_intent=dns)
    assert result.verified_revision == "create"
    assert backend.forwarding["authoritative-domain"][DNS_SCOPE.zone]["records"]["a"]["probe"]["ttl"] == "300"
    assert backend.rules["80200"]["destination"]["port"] == "8443"
    assert "confirm" in backend.events and "save" in backend.events

    dns = decode_dns_intent(dns_snapshot("delete"), revision="delete", scope=DNS_SCOPE)
    result = reconciler.reconcile(intent("delete"), dns_intent=dns)
    assert result.verified_revision == "delete"
    assert set(backend.forwarding["authoritative-domain"]) == {"unmanaged.test"}
    assert backend.forwarding["listen-address"] == "192.0.2.1"


def test_managed_dns_fingerprint_keeps_unmanaged_records():
    create = dns_snapshot("create")
    base = unmanaged_config_fingerprint(create, revision="create", dns_scope=DNS_SCOPE)
    assert unmanaged_config_fingerprint(dns_snapshot("edit"), revision="edit", dns_scope=DNS_SCOPE) == base
    changed = json.loads(create)
    changed["udapi"]["services"]["dnsForwarder"]["hostRecords"][0]["hostName"] = "operator.example.test"
    assert unmanaged_config_fingerprint(json.dumps(changed), revision="changed", dns_scope=DNS_SCOPE) != base


def test_dhcp_discovery_companion_is_owned_only_with_the_matching_vetted_domain():
    dhcp_scope = DhcpScope("br110", "eth3.110", "unifi-vlan110", 110)
    document = json.loads(dns_snapshot("delete"))
    udapi = document["udapi"]
    managed = json.loads(dhcp_snapshot("create"))["udapi"]["services"]["dhcpServers"][1]
    udapi["services"]["dhcpServers"].append(managed)
    hosts = udapi["services"]["dnsForwarder"]["hostRecords"]
    anchor = {"hostName": "unifi.localdomain", "registerNonQualified": True,
              "address": {"address": "192.0.2.53", "version": "v4"}}
    hosts.append(anchor)

    def fingerprint():
        return unmanaged_config_fingerprint(json.dumps(document), revision="revision",
                                            dhcp_scope=dhcp_scope, dns_scope=DNS_SCOPE)

    baseline = fingerprint()
    managed["domain"] = DNS_SCOPE.zone
    with pytest.raises(ValueError, match="discovery"):
        fingerprint()
    derived = {**anchor, "hostName": f"unifi.{DNS_SCOPE.zone}", "registerNonQualified": False}
    hosts.append(derived)
    assert fingerprint() == baseline
    derived["address"] = {"address": "192.0.2.54", "version": "v4"}
    with pytest.raises(ValueError, match="discovery"):
        fingerprint()
    anchor["address"] = derived["address"]
    assert fingerprint() != baseline


NAT_SCOPE = NatScope("192.0.2.0/24", "198.51.100.2", "br120", "eth3.120", 80100, (8443, 8444), ("198.51.100.1",))


def nat_snapshot(stage):
    fixture = Path(__file__).parent / "fixtures/uxg_pro/native-source-nat-snapshots.json"
    nat = json.loads(fixture.read_text())
    doc = json.loads(dns_snapshot("delete"))
    doc["udapi"]["versionDetail"]["firewall/nat"] = 7
    doc["udapi"]["firewall/nat"] = nat["rules"][stage]
    return json.dumps(doc)


class FakeNatConfig(FakeDnsConfig):
    def __init__(self):
        super().__init__()
        self.nat_rules = {}

    def show_interfaces(self):
        super().show_interfaces()
        return "eth3.120@eth3: <BROADCAST,UP,LOWER_UP> mtu 1500\n    inet 198.51.100.1/24\n"

    def read_config(self, path):
        if path == ["nat", "source", "rule"]:
            return {"rule": self.nat_rules.copy()} if self.nat_rules else None
        return super().read_config(path)

    def stage_configuration(self, commands, *, confirm_minutes):
        remaining = []
        for command in commands:
            path = command["path"]
            if path[:3] != ["nat", "source", "rule"]:
                remaining.append(command)
                continue
            if command["op"] == "delete":
                del self.nat_rules[path[3]]
                continue
            current = self.nat_rules
            for part in path[3:-1]:
                current = current.setdefault(part, {})
            current[path[-1]] = command["value"]
        super().stage_configuration(remaining, confirm_minutes=confirm_minutes)


def test_native_nat_transaction_can_share_dns_and_firewall_scope(tmp_path):
    backend = FakeNatConfig()
    reconciler = make_reconciler(tmp_path, backend, dns_scope=DNS_SCOPE, nat_scope=NAT_SCOPE)
    for stage, translation, port in (("create", "masquerade", "8444"), ("edit", "198.51.100.1", "8443")):
        snapshot = nat_snapshot(stage)
        dns = decode_dns_intent(snapshot, revision=stage, scope=DNS_SCOPE, nat=True)
        nat = decode_nat_intent(snapshot, revision=stage, scope=NAT_SCOPE, dns_forwarder=True)
        applied = reconciler.reconcile(intent(stage, 8445), dns_intent=dns, nat_intent=nat)
        assert applied.verified_revision == stage
        assert backend.nat_rules["80100"]["translation"]["address"] == translation
        assert backend.nat_rules["80100"]["destination"]["port"] == port

    snapshot = nat_snapshot("delete")
    dns = decode_dns_intent(snapshot, revision="delete", scope=DNS_SCOPE, nat=True)
    nat = decode_nat_intent(snapshot, revision="delete", scope=NAT_SCOPE, dns_forwarder=True)
    applied = reconciler.reconcile(intent("delete", 8445), dns_intent=dns, nat_intent=nat)
    assert applied.verified_revision == "delete"
    assert not backend.nat_rules
    assert backend.rules["80200"]["destination"]["port"] == "8445"


VPN_SCOPE = WireGuardScope("eth0", "eth3.210", "198.18.210.1/30", "wg119", (51820, 51821),
                            "172.29.91.1/24", "172.29.91.2/32")
VPN_GUARD = WireGuardGuardScope("198.18.210.2", "192.168.120.2", "eth3.120", 8444, 79000)
VPN_SYNTHETIC_KEY = b64encode(bytes(range(1, 33))).decode()


def wireguard_intent(revision, *, active=True):
    fixture = Path(__file__).parent / "fixtures/uxg_pro/native-wireguard-server.json"
    snapshot = json.loads(fixture.read_text())
    udapi = snapshot["udapi"]
    if active:
        server = udapi["vpn/wireguard/servers"][0]
        server["privateKey"] = VPN_SYNTHETIC_KEY
        server["remotePeers"][0]["publicKey"] = b64encode(bytes(range(33, 65))).decode()
    else:
        del udapi["vpn/wireguard/servers"]
    return decode_wireguard_intent(
        json.dumps(snapshot), revision=revision, scope=VPN_SCOPE, dns_forwarder=True, nat=True,
    )


class FakeWireGuardConfig(FakeFirewall):
    def __init__(self):
        super().__init__()
        self.rules.clear()
        self.interfaces = {}
        self.guard_paths = dict(GUARD_PATHS)
        self.guards = {name: {} for name in self.guard_paths}
        self.guards["ipv4/forward"] = self.rules
        self.command_batches = []

    def read_config(self, path):
        if path == ["interfaces", "wireguard"]:
            return {"wireguard": self.interfaces.copy()} if self.interfaces else None
        for name, guard_path in self.guard_paths.items():
            if path == guard_path:
                return {"rule": self.guards[name].copy()}
        return super().read_config(path)

    def show_interfaces(self):
        super().show_interfaces()
        baseline = ("eth3.210@eth3: <BROADCAST,UP,LOWER_UP> mtu 1500\n    inet 198.18.210.1/30\n"
                    "eth3.120@eth3: <BROADCAST,UP,LOWER_UP> mtu 1500\n    inet 192.168.120.1/24\n")
        if self.interfaces:
            baseline += "wg119: <POINTOPOINT,UP,LOWER_UP> mtu 1420\n    inet 172.29.91.1/24\n"
        return baseline

    def stage_configuration(self, commands, *, confirm_minutes):
        self.command_batches.append([command["path"] for command in commands])
        for command in commands:
            path = command["path"]
            if path[:2] == ["interfaces", "wireguard"]:
                tree, keys = self.interfaces, path[2:]
            else:
                name = f"{path[1]}/{path[2]}"
                assert path[:5] == self.guard_paths[name]
                tree, keys = self.guards[name], path[5:]
            for key in keys[:-1]:
                tree = tree.setdefault(key, {})
            if command["op"] == "set":
                tree[keys[-1]] = command.get("value", {})
            else:
                del tree[keys[-1]]


def test_wireguard_stages_interface_and_confinement_in_one_transaction_without_journaling_keys(tmp_path):
    backend = FakeWireGuardConfig()
    reconciler = make_reconciler(tmp_path, backend, wireguard_scope=VPN_SCOPE, wireguard_guard=VPN_GUARD)
    result = reconciler.reconcile(intent("create"), wireguard_intent=wireguard_intent("create"))
    assert result.verified_revision == "create"
    assert {path[0] for path in backend.command_batches[0]} == {"interfaces", "firewall"}
    assert backend.interfaces["wg119"]["private-key"] == VPN_SYNTHETIC_KEY
    assert VPN_SYNTHETIC_KEY not in (tmp_path / "firewall.json").read_text()
    assert "confirm" in backend.events and "save" in backend.events
    result = reconciler.reconcile(intent("remove"), wireguard_intent=wireguard_intent("remove", active=False))
    assert result.verified_revision == "remove"
    assert not backend.interfaces and not any(backend.guards.values())


class FakeIpsecConfig(FakeWireGuardConfig):
    def __init__(self):
        super().__init__()
        self.ipsec = None
        self.nat = None
        self.offload = None
        self.preempt_guard = False
        self.guard_paths.update(IPSEC_GUARD_PATHS)
        self.guards.update({name: {} for name in self.guard_paths.keys() - self.guards.keys()})
        self.routes = FakeRouteConfig()

    def read_config(self, path):
        if path == ["vpn", "ipsec"]:
            return self.ipsec
        if path == ["nat", "source", "rule"]:
            return self.nat
        if path == ["firewall", "flowtable"]:
            return self.offload
        if path == ["firewall", "global-options", "state-policy"]:
            return None
        if path == ["protocols", "static", "route"]:
            return self.routes.read_config(path)
        return super().read_config(path)

    def show_ipv4_routes(self):
        result = self.routes.show_ipv4_routes()
        result["198.18.210.0/30"] = result.pop("192.0.2.0/30")
        return result

    def stage_configuration(self, commands, *, confirm_minutes):
        guard_commands = [command for command in commands if command["path"][0] == "firewall"]
        super().stage_configuration(guard_commands, confirm_minutes=confirm_minutes)
        if self.preempt_guard:
            self.guards["ipv4/forward"]["10"] = {"action": "accept"}
        self.routes.stage_configuration([command for command in commands if command["path"][0] == "protocols"],
                                        confirm_minutes=confirm_minutes)
        self.command_batches[-1] = [command["path"] for command in commands]
        for command in commands:
            path = command["path"]
            if path[0] in {"firewall", "protocols"}:
                continue
            assert path[:2] == ["vpn", "ipsec"]
            if command["op"] == "delete":
                assert len(path) == 2
                self.ipsec = None
                continue
            if self.ipsec is None:
                self.ipsec = {}
            entry = self.ipsec
            for name in path[2:-1]:
                entry = entry.setdefault(name, {})
            if path[-1] == "id":
                entry.setdefault("id", []).append(command["value"])
            else:
                entry[path[-1]] = command["value"]


@pytest.mark.parametrize("fault", [None, "precedence", "route"])
def test_ipsec_stages_confined_policy_and_never_journals_the_key(tmp_path, fault):
    native = json.loads((Path(__file__).parent / "fixtures/uxg_pro/native-ipsec-snapshots.json").read_text())
    envelope = native["envelope"]
    scope = IpsecScope("eth0", "eth3.210", "198.18.210.1/30", "br120", "eth3.120", "192.168.120.1/24",
                       "198.18.210.2", "192.168.120.2/32", "198.19.210.240/32", "UXG-LAB-IPSEC")
    backend = FakeIpsecConfig()
    reconciler = make_reconciler(tmp_path, backend, ipsec_scope=scope, ipsec_guard_base=79200)

    def apply(phase):
        udapi = dict(envelope)
        if native["entries"][phase] is not None:
            udapi["vpn/ipsec/site-to-site"] = native["entries"][phase]
        requested = decode_ipsec_intent(json.dumps({"udapi": udapi}), revision=phase, scope=scope,
                                       expected_versions=envelope["versionDetail"])
        return reconciler.reconcile(intent(phase), ipsec_intent=requested)

    backend.offload = {"name": {"existing": {}}}
    assert "offload" in apply("create").error
    backend.offload = None
    backend.nat = {"rule": {"20": {"translation": {"address": "masquerade"}}}}
    assert "NAT" in apply("create").error
    assert not backend.command_batches
    backend.nat = None
    backend.preempt_guard = fault == "precedence"
    backend.routes.report_route_active = fault != "route"
    result = apply("create")
    if fault is not None:
        assert result.verified_revision is None
        assert ("precede" if fault == "precedence" else "installed next hop") in result.error
        assert "confirm" not in backend.events and "save" not in backend.events
        return
    assert result.verified_revision == "create", result.error
    assert {path[0] for path in backend.command_batches[0]} == {"vpn", "firewall", "protocols"}
    assert backend.routes.static[scope.remote_selector]["next-hop"] == {scope.remote_peer: {
        "distance": "1", "interface": scope.wan_interface,
    }}
    assert backend.events[-2:] == ["confirm", "save"]
    psk = native["entries"]["create"][0]["preSharedKey"]
    assert backend.ipsec["authentication"]["psk"][scope.name]["secret"] == psk
    assert psk not in (tmp_path / "firewall.json").read_text()
    assert apply("edit").verified_revision == "edit"
    assert backend.command_batches[-1] == [["vpn", "ipsec", "esp-group", scope.name, "lifetime"]]
    assert apply("delete").verified_revision == "delete"
    assert backend.ipsec is None and not any(backend.guards[name] for name in IPSEC_GUARD_PATHS)
    assert backend.routes.static == {}


class FakeOpenVpnConfig(FakeIpsecConfig):
    def __init__(self):
        super().__init__()
        self.tree = {"service": {"https": {"note": "Keep operator configuration"}}}
        self.guard_paths.update(OPENVPN_GUARD_PATHS)
        self.guards.update({name: {} for name in self.guard_paths.keys() - self.guards.keys()})

    def read_complete_configuration(self):
        return self.tree

    def stage_configuration(self, commands, *, confirm_minutes):
        guards = [command for command in commands if command["path"][0] == "firewall"]
        super().stage_configuration(guards, confirm_minutes=confirm_minutes)
        self.command_batches[-1] = [command["path"] for command in commands]
        for operation in commands:
            path = operation["path"]
            if path[0] == "firewall":
                continue
            current = self.tree
            flag = path[-1] in {"disable-forwarding", "no-default-link-local"}
            has_value = operation["op"] == "set" and not flag
            for key in path[:-2 if has_value else -1]:
                current = current.setdefault(key, {})
            if operation["op"] == "delete":
                del current[path[-1]]
            elif flag:
                current[path[-1]] = {}
            elif path[-2] == "openvpn-option":
                current.setdefault(path[-2], []).append(path[-1])
            else:
                current[path[-2]] = path[-1]


def test_openvpn_stages_client_credentials_only_after_dedicated_guards_exist(tmp_path):
    scope = OpenVpnScope(server_name="router.example.net")
    guard = OpenVpnGuardScope(scope.interface, scope.tunnel_cidr, scope.tunnel_peer, 79300,
                             scope.wan_interface, scope.local_address, scope.remote_host, scope.remote_ports)
    backend = FakeOpenVpnConfig()
    reconciler = make_reconciler(tmp_path, backend, openvpn_scope=scope, openvpn_guard=guard)
    cert = b"-----BEGIN CERTIFICATE-----\nc3ludGhldGljLWNlcnQ=\n-----END CERTIFICATE-----\n"
    key = b"-----BEGIN PRIVATE KEY-----\nc3ludGhldGljLWtleQ==\n-----END PRIVATE KEY-----\n"
    password = "synthetic-password-in-lab-memory"
    peer = OpenVpnClientIntent("1", scope.remote_host, scope.remote_ports[0], scope.server_name,
                               "lab-user", password, cert, cert, key)

    result = reconciler.reconcile(intent("unguarded"), openvpn_intent=OpenVpnDesired("unguarded", peer))
    assert "pre-installed" in result.error
    assert not backend.command_batches
    empty = {chain: {} for chain in OPENVPN_GUARD_PATHS}
    guarded = plan_openvpn_guards(guard, active=True, current=empty, verified=empty).desired
    backend.guards.update(guarded)

    assert "snapshot" in reconciler.reconcile(intent("missing")).error
    result = reconciler.reconcile(intent("create"), openvpn_intent=OpenVpnDesired("create", peer))
    assert result.verified_revision == "create", result.error
    assert {path[0] for path in backend.command_batches[-1]} == {"interfaces", "pki"}
    assert backend.tree["interfaces"]["openvpn"][scope.interface]["authentication"]["password"] == password
    assert password not in (tmp_path / "firewall.json").read_text()
    assert backend.events[-2:] == ["confirm", "save"]
    backend.guards["ipv4/input"]["70000"] = {"action": "drop"}
    assert "precede" in reconciler.reconcile(intent("drift"), openvpn_intent=OpenVpnDesired("drift", peer)).error
    assert len(backend.command_batches) == 1
    assert reconciler.reconcile(intent("delete"), openvpn_intent=OpenVpnDesired("delete", None)).verified_revision == "delete"
    assert backend.tree["interfaces"]["openvpn"] == {}
    assert backend.tree["service"]["https"]["note"] == "Keep operator configuration"
    assert {name: backend.guards[name] for name in OPENVPN_GUARD_PATHS} == {
        **guarded, "ipv4/input": {**guarded["ipv4/input"], "70000": {"action": "drop"}},
    }


class FakePortForwardConfig(FakeWireGuardConfig):
    def __init__(self):
        super().__init__()
        self.destination_nat = {}

    def read_config(self, path):
        if path == ["nat", "destination", "rule"]:
            return {"rule": self.destination_nat.copy()}
        return super().read_config(path)

    def show_interfaces(self):
        return ("eth3.210@eth3: <BROADCAST,UP,LOWER_UP> mtu 1500\n    inet 192.0.2.1/30\n"
                "eth3.120@eth3: <BROADCAST,UP,LOWER_UP> mtu 1500\n    inet 198.51.100.1/24\n")

    def stage_configuration(self, commands, *, confirm_minutes):
        guard_commands = []
        for command in commands:
            path = command["path"]
            if path[:3] != ["nat", "destination", "rule"]:
                guard_commands.append(command)
                continue
            if command["op"] == "delete":
                del self.destination_nat[path[3]]
            else:
                tree = self.destination_nat
                for key in path[3:-1]:
                    tree = tree.setdefault(key, {})
                tree[path[-1]] = command["value"]
        super().stage_configuration(guard_commands, confirm_minutes=confirm_minutes)
        self.command_batches[-1] = [command["path"] for command in commands]


def test_port_forward_stages_dnat_and_exact_allow_and_preserves_operator_rule(tmp_path):
    fixture = Path(__file__).parent / "fixtures/uxg_pro/native-port-forward-snapshots.json"
    native = json.loads(fixture.read_text())
    scope = PortForwardScope(
        "eth0", "eth3.210", "192.0.2.1/30", "192.0.2.2", "br120", "eth3.120",
        "198.51.100.1/24", "198.51.100.2", 80150, ((18446, 8444), (18447, 8443)),
    )
    backend = FakePortForwardConfig()
    backend.rules["90000"] = {"action": "drop"}
    reconciler = VyOSReconciler(
        backend, state_path=tmp_path / "firewall.json", rule_base=80200,
        interfaces={IPv4Network("198.51.100.0/24"): "eth3.120", IPv4Network("203.0.113.0/24"): "eth3.110"},
        port_forward_scope=scope, port_forward_guard_base=79100,
    )
    for stage, external, internal in (("create", "18446", "8444"), ("edit", "18447", "8443"),
                                      ("baseline", None, None)):
        snapshot = json.dumps({"udapi": {**native["udapi"], **native["snapshots"][stage]}})
        forward = decode_port_forward_intent(snapshot, revision=stage, scope=scope, dns_forwarder=True, wireguard=True)
        result = reconciler.reconcile(intent(stage), port_forward_intent=forward)
        assert result.verified_revision == stage, result.error
        assert {path[0] for path in backend.command_batches[-1]} == {"nat", "firewall"}
        assert backend.rules["90000"] == {"action": "drop"}
        if external is not None:
            assert backend.destination_nat["80150"]["destination"]["port"] == external
            assert backend.rules["79100"]["destination"]["port"] == internal
            assert backend.rules["79100"]["connection-status"] == {"nat": "destination"}
        else:
            assert not backend.destination_nat
            assert set(backend.rules) == {"90000"}
    assert backend.events.count("confirm") == backend.events.count("save") == 3


class FakeVlanConfig(FakeFirewall):
    def __init__(self):
        super().__init__()
        self.ethernet = {"eth3": {"description": "Trunk", "vif": {"110": {"address": "192.168.110.1/24"}}}}

    def read_config(self, path):
        if path == ["interfaces", "ethernet"]:
            return {"ethernet": self.ethernet}
        return super().read_config(path)

    def show_interfaces(self):
        self.events.append("management")
        output = "eth3: <UP,LOWER_UP> mtu 1500\neth3.110@eth3: <UP,LOWER_UP> mtu 1500\n    inet 192.168.110.1/24\n"
        if "130" in self.ethernet["eth3"]["vif"]:
            output += "eth3.130@eth3: <UP,LOWER_UP> mtu 1500\n    inet 192.168.130.1/24\n"
        return output

    def stage_configuration(self, commands, *, confirm_minutes):
        self.events.append("stage")
        assert len(commands) == 1
        command = commands[0]
        path = ["interfaces", "ethernet", "eth3", "vif", "130"]
        if command["op"] == "set":
            assert command["path"] == [*path, "address"]
            self.ethernet["eth3"]["vif"]["130"] = {"address": command["value"]}
        else:
            assert command["path"] == path
            del self.ethernet["eth3"]["vif"]["130"]


def test_vlan_verifies_live_link_before_saving_and_preserves_sibling_vlan(tmp_path):
    scope = VlanScope("eth3", 130, "192.168.130.1/24")
    backend = FakeVlanConfig()
    reconciler = make_reconciler(tmp_path, backend, vlan_scope=scope)
    for revision, present in (("create", True), ("remove", False)):
        vlan = VlanIntent(revision=revision, scope=scope, present=present)
        result = reconciler.reconcile(intent(revision), vlan_intent=vlan)
        assert result.verified_revision == revision, result.error
        assert ("130" in backend.ethernet["eth3"]["vif"]) is present
        assert backend.ethernet["eth3"]["vif"]["110"] == {"address": "192.168.110.1/24"}
        assert backend.events[-3:] == ["management", "confirm", "save"]
        state = json.loads((tmp_path / "firewall.json").read_text())
        assert state["verified_vlan"] == ({"address": scope.address} if present else None)


class FakeMdnsConfig(FakeFirewall):
    def __init__(self):
        super().__init__()
        self.repeater = None
        self.fault = False

    def read_config(self, path):
        if path == ["service", "mdns"]:
            return {"repeater": self.repeater} if self.repeater else None
        return super().read_config(path)

    def has_mdns_listener(self):
        return bool(self.repeater) and not self.fault

    def show_interfaces(self):
        return ("eth3.110: <UP,LOWER_UP,MULTICAST> mtu 1500\n    inet 192.168.110.1/24\n"
                "eth3.120: <UP,LOWER_UP,MULTICAST> mtu 1500\n    inet 192.168.120.1/24\n")

    def stage_configuration(self, commands, *, confirm_minutes):
        self.events.append("stage")
        repeater = ["service", "mdns", "repeater"]
        if commands == [{"op": "delete", "path": repeater[:-1]}]:
            self.repeater = None
            return
        self.repeater = {"interface": []}
        for operation in commands:
            assert operation["op"] == "set" and operation["path"][:3] == repeater
            leaf = operation["path"][-1]
            if leaf == "interface":
                self.repeater[leaf].append(operation["value"])
            else:
                self.repeater[leaf] = operation["value"]


@pytest.mark.parametrize("listener_fault", [True, False])
def test_mdns_confirms_only_with_verified_listener_state(tmp_path, listener_fault):
    scope = MdnsScope(
        {"br110": "eth3.110", "br120": "eth3.120"},
        {"br110": "192.168.110.1/24", "br120": "192.168.120.1/24"},
    )
    backend = FakeMdnsConfig()
    backend.fault = listener_fault
    reconciler = make_reconciler(tmp_path, backend, mdns_scope=scope)
    create = MdnsIntent(revision="create", scope=scope, enabled=True)
    result = reconciler.reconcile(intent("create"), mdns_intent=create)
    if listener_fault:
        assert result.verified_revision is None
        assert result.error == "VyOS mDNS listener state differs from the intended repeater"
        assert "confirm" not in backend.events and "save" not in backend.events
        return
    assert result.verified_revision == "create", result.error
    assert backend.repeater == {"interface": ["eth3.110", "eth3.120"], "ip-version": "ipv4"}

    stages_before = backend.events.count("stage")
    oversized = tuple(f"_{prefix}{'a' * 50}._tcp.local" for prefix in "abcd")
    selection = MdnsIntent(revision="oversized", scope=scope, enabled=True, services=oversized)
    rejected = reconciler.reconcile(intent("oversized"), mdns_intent=selection)
    assert rejected.verified_revision == "create" and "255-byte" in rejected.error
    assert backend.events.count("stage") == stages_before
    assert backend.repeater == {"interface": ["eth3.110", "eth3.120"], "ip-version": "ipv4"}

    remove = MdnsIntent(revision="remove", scope=scope, enabled=False)
    result = reconciler.reconcile(intent("remove"), mdns_intent=remove)
    assert result.verified_revision == "remove", result.error
    assert backend.repeater is None and not backend.has_mdns_listener()


class FakeMdnsContainer(FakeMdnsConfig):
    def __init__(self):
        super().__init__()
        path = Path(__file__).parent / "fixtures" / "uxg_pro" / "stock-vyos-mdns-container.json"
        fixture = json.loads(path.read_text())
        self.path = fixture["retrievePath"]
        self.reference_config = fixture["retrieveData"]
        self.row = fixture["showRows"][0]
        self.services = tuple(self.reference_config["environment"]["UXG_MDNS_FILTERS"]["value"].split(","))
        self.container = None
        self.image_id = self.row["image_id"]
        self.runtime_fault = None
        self.foreign_runtime = []

    def read_config(self, path):
        if path == self.path:
            return deepcopy(self.container)
        return super().read_config(path)

    def show_container_images(self):
        return [{"id": self.image_id, "names": [self.row["image"]]}]

    def show_containers(self):
        if self.container is None:
            return self.foreign_runtime
        row = deepcopy(self.row)
        row["labels"] = {key.replace(".", "_").replace("-", "_"): value["value"]
                         for key, value in self.container["label"].items()}
        if self.runtime_fault == "label":
            row["labels"].clear()
        if self.runtime_fault == "image":
            row["image_id"] = "0" * 64
        if self.runtime_fault == "stopped":
            row.update(state="exited", pid=0)
        return [*self.foreign_runtime, row]

    def has_mdns_listener(self):
        return bool(self.repeater or self.container) and self.runtime_fault != "listener"

    def mdns_multicast_interfaces(self):
        if self.container is None:
            return set()
        if self.runtime_fault == "membership":
            return {"eth3.110"}
        return {"eth3.110", "eth3.120"}

    def stage_configuration(self, commands, *, confirm_minutes):
        if commands[0]["path"][:2] == ["service", "mdns"]:
            return super().stage_configuration(commands, confirm_minutes=confirm_minutes)
        self.events.append("stage")
        for command in commands:
            path = command["path"]
            assert path[:3] == self.path
            if path == self.path:
                assert command["op"] == "delete"
                self.container = None
                continue
            if self.container is None:
                self.container = {}
            parent = self.container
            for key in path[3:-1]:
                parent = parent.setdefault(key, {})
            if command["op"] == "delete":
                del parent[path[-1]]
            else:
                parent[path[-1]] = command.get("value", {})


def mdns_container_reconciler(tmp_path, backend, *, container_engine=True):
    settings = ConfigParser()
    settings.read_dict({
        "firewall": {"interfaces": json.dumps({"192.168.110.0/24": "eth3.110", "192.168.120.0/24": "eth3.120"}),
                     "state_path": str(tmp_path / "firewall.json"), "rule_base": "80200"},
        "mdns": {"enabled": "true", "interfaces": json.dumps({"br110": "eth3.110", "br120": "eth3.120"}),
                 "addresses": json.dumps({"br110": "192.168.110.1/24", "br120": "192.168.120.1/24"})},
    })
    if container_engine:
        settings["mdns"].update(engine="container", container_image=backend.row["image"], container_image_id=backend.row["image_id"])
    collector = SimpleNamespace(backend=backend, ports=[{"type": "lan", "realif": f"eth3.{tag}"} for tag in (110, 120)])
    return VyOSReconciler.from_config(collector, settings["firewall"], mdns_settings=settings["mdns"])


def apply_mdns(reconciler, revision, *, enabled=True, services=()):
    return reconciler.reconcile(intent(revision), mdns_intent=MdnsIntent(revision, reconciler.mdns_scope, enabled, services))


def test_mdns_container_reconciles_large_selections_edits_and_off(tmp_path):
    backend = FakeMdnsContainer()
    reconciler = mdns_container_reconciler(tmp_path, backend)

    result = apply_mdns(reconciler, "large", services=backend.services)
    assert result.changed and result.verified_revision == "large", result.error
    assert backend.container == backend.reference_config
    assert backend.events[-2:] == ["confirm", "save"]
    initial_label = deepcopy(backend.container["label"])
    stages = backend.events.count("stage")
    assert not apply_mdns(reconciler, "large", services=backend.services).changed
    assert backend.events.count("stage") == stages

    assert apply_mdns(reconciler, "all").verified_revision == "all"
    assert backend.container["environment"]["UXG_MDNS_MODE"] == {"value": "all"}
    assert "UXG_MDNS_FILTERS" not in backend.container["environment"]
    assert backend.container["label"] != initial_label
    assert apply_mdns(reconciler, "off", enabled=False).verified_revision == "off"
    assert backend.container is None and backend.rules == {"20": {"description": "Operator decision", "action": "accept"}}


def test_setparam_applies_mdns_v2_and_reports_the_verified_container_revision(tmp_path, monkeypatch):
    backend = FakeMdnsContainer()
    reconciler = mdns_container_reconciler(tmp_path, backend)
    path = Path(__file__).parent / "fixtures" / "uxg_pro" / "native-mdns-snapshots.json"
    snapshots = json.loads(path.read_text())
    for phase in ("off", "custom"):
        versions = snapshots[phase]["versionDetail"]
        for feature in ("services/dnsForwarder", "firewall/nat", "vpn/wireguard/servers"):
            del versions[feature]
        versions["services/mdns"] = 2
    snapshots["custom"]["services"]["mdns"]["reflectFilter"] = list(backend.services)
    baseline = unmanaged_config_fingerprint(json.dumps({"udapi": snapshots["off"]}), revision="off",
                                            mdns_scope=reconciler.mdns_scope)
    config = tmp_path / "gateway.conf"
    config.write_text(f"""[global]
pid_file = {tmp_path}/gateway.pid
[gateway]
device = UXGENT
platform = vyos
is_adopted = true
lan_mac = 02:78:91:00:12:03
lan_ip = 192.0.2.1
url = http://lab.example:8080/inform
ports = []
[vyos_firewall]
enabled = true
unmanaged_baseline_sha256 = {baseline}
""")
    monkeypatch.setattr(unifi_gateway, "CONFIG_FILE", str(config))
    gateway = unifi_gateway.UnifiGateway()
    gateway.vyos_provisioner = reconciler
    gateway.datacollector = SimpleNamespace(data={})
    notifications = []
    monkeypatch.setattr(gateway, "_send_inform", notifications.append)

    gateway._handle_response({"_type": "setparam", "cfgversion": "large", "system_cfg": json.dumps({"udapi": snapshots["custom"]})})

    assert not notifications, gateway._vyos_provisioning_error
    assert json.loads(create_inform(gateway.config, gateway.datacollector))["cfgversion_effective"] == "large"
    assert backend.container["environment"]["UXG_MDNS_FILTERS"]["value"] == ",".join(backend.services)
    del snapshots["custom"]["versionDetail"]["services/mdns"]
    gateway._handle_response({"_type": "setparam", "cfgversion": "missing-version",
                              "system_cfg": json.dumps({"udapi": snapshots["custom"]})})
    assert backend.events.count("stage") == 1
    assert json.loads(notifications[-1])["cfgversion_effective"] == "large"


@pytest.mark.parametrize("failure", ["label", "image", "stopped", "listener", "membership"])
def test_mdns_container_preserves_applied_revision_on_incomplete_runtime(tmp_path, failure):
    backend = FakeMdnsContainer()
    reconciler = mdns_container_reconciler(tmp_path, backend)
    assert apply_mdns(reconciler, "off", enabled=False).verified_revision == "off"
    backend.runtime_fault = failure

    result = apply_mdns(reconciler, "large", services=backend.services)

    assert result.error and result.verified_revision == "off"
    assert "stage" in backend.events and "confirm" not in backend.events and "save" not in backend.events


@pytest.mark.parametrize("conflict", ["stock-repeater", "container", "runtime", "image"])
def test_mdns_container_rejects_unowned_state_before_staging(tmp_path, conflict):
    backend = FakeMdnsContainer()
    reconciler = mdns_container_reconciler(tmp_path, backend)
    if conflict == "stock-repeater":
        backend.repeater = {"interface": ["eth3.120", "eth3.130"]}
    elif conflict == "container":
        backend.container = {"image": "localhost/operator-owned:1"}
    elif conflict == "runtime":
        backend.foreign_runtime = [backend.row]
    else:
        backend.image_id = "0" * 64

    result = apply_mdns(reconciler, "large", services=backend.services)

    assert result.error and result.verified_revision is None
    assert "stage" not in backend.events


def test_mdns_engine_switch_requires_verified_off(tmp_path):
    backend = FakeMdnsContainer()
    stock = mdns_container_reconciler(tmp_path, backend, container_engine=False)
    assert apply_mdns(stock, "stock-all").verified_revision == "stock-all"
    container = mdns_container_reconciler(tmp_path, backend)
    assert "different scope" in apply_mdns(container, "container-all").error
    assert backend.container is None and backend.repeater is not None

    assert apply_mdns(stock, "stock-off", enabled=False).verified_revision == "stock-off"
    assert apply_mdns(container, "container-all").verified_revision == "container-all"
    assert backend.container is not None and backend.repeater is None
    assert "different scope" in apply_mdns(stock, "back-to-stock").error
    assert apply_mdns(container, "container-off", enabled=False).verified_revision == "container-off"
    assert apply_mdns(stock, "back-to-stock").verified_revision == "back-to-stock"


def test_mdns_container_recovers_a_confirmed_save_timeout_only_after_fresh_health_check(tmp_path):
    backend = FakeMdnsContainer()
    reconciler = mdns_container_reconciler(tmp_path, backend)
    assert apply_mdns(reconciler, "off", enabled=False).verified_revision == "off"
    backend.save_timeout = True
    assert apply_mdns(reconciler, "large", services=backend.services).verified_revision == "off"
    assert json.loads((tmp_path / "firewall.json").read_text())["pending"]["confirmed"] is True

    backend.save_timeout = False
    backend.runtime_fault = "membership"
    restarted = mdns_container_reconciler(tmp_path, backend)
    rejected = apply_mdns(restarted, "large", services=backend.services)
    assert rejected.verified_revision == "off" and "memberships" in rejected.error
    assert backend.events.count("save") == 1

    backend.runtime_fault = None
    assert apply_mdns(restarted, "large", services=backend.services).verified_revision == "large"
    assert backend.events.count("stage") == backend.events.count("confirm") == 1
    assert backend.events.count("save") == 2


class FakeOspfConfig(FakeVlanConfig):
    def __init__(self):
        super().__init__()
        self.ethernet["eth3"]["vif"]["120"] = {"address": "192.0.2.1/24"}
        self.ospf = None
        self.stale_router_id = None
        self.ospf_neighbors = 0

    def read_config(self, path):
        if path == ["protocols", "ospf"]:
            return self.ospf
        return super().read_config(path)

    def show_interfaces(self):
        return super().show_interfaces() + "eth3.120@eth3: <UP,LOWER_UP,MULTICAST> mtu 1500\n    inet 192.0.2.1/24\n"

    def show_ipv4_ospf_interfaces(self):
        interface = self.ospf["interface"]["eth3.120"]
        row = {
            "ifUp": True, "ospfEnabled": True, "area": "0.0.0.0", "networkType": "BROADCAST",
            "routerId": self.stale_router_id or self.ospf["parameters"]["router-id"],
            "cost": int(interface["cost"]), "timerMsecs": int(interface["hello-interval"]) * 1000,
            "timerDeadSecs": int(interface["dead-interval"]),
            "nbrCount": self.ospf_neighbors,
        }
        row.update({"timerPassiveIface": True} if "passive" in interface else {"timerHelloInMsecs": 200})
        authentication = interface.get("authentication")
        if authentication:
            row["authentication"] = ("authenticationSimplePassword" if "plaintext-password" in authentication
                                     else "authenticationMessageDigest")
        return {"interfaces": {"eth3.120": row}}

    def stage_configuration(self, commands, *, confirm_minutes):
        self.events.append("stage")
        for command in commands:
            path = command["path"]
            assert path[:2] == ["protocols", "ospf"]
            if command["op"] == "delete" and len(path) == 2:
                self.ospf = None
                continue
            if self.ospf is None:
                self.ospf = {}
            tree = self.ospf
            for key in path[2:-1]:
                tree = tree.setdefault(key, {})
            if command["op"] == "set":
                tree[path[-1]] = command.get("value", {})
            else:
                del tree[path[-1]]


@pytest.mark.parametrize("router_id_edit", ["active", "stale", "established-peer"])
def test_ospf_commits_only_the_pinned_interface_and_withdraws_it(tmp_path, router_id_edit):
    scope = OspfScope(router_id="198.51.100.1", controller_interface="br120",
                      vyos_interface="eth3.120", interface_address="192.0.2.1/24")
    backend = FakeOspfConfig()
    reconciler = VyOSReconciler(
        backend, state_path=tmp_path / "firewall.json", rule_base=80200, ospf_scope=scope,
        interfaces={IPv4Network("192.168.110.0/24"): "eth3.110", IPv4Network("192.0.2.0/24"): "eth3.120"},
    )
    fixture = Path(__file__).parent / "fixtures/uxg_pro/native-ospf-snapshots.json"
    snapshots = json.loads(fixture.read_text())
    passive = snapshots["passive"] = deepcopy(snapshots["create"])
    passive["udapi"]["routes/ospf"]["routerID"] = "198.51.100.9"
    passive["udapi"]["routes/ospf/interfaces"][0]["passiveInterface"] = True
    for revision, cost in (("create", 1), ("edit", 23), ("passive", 1), ("baseline", None)):
        native = decode_ospf_intent(
            json.dumps(snapshots[revision]), revision=revision, scope=scope,
            dns_forwarder=True, nat=True, wireguard=True,
        )
        if revision == "passive":
            event_offset = len(backend.events)
            if router_id_edit == "stale":
                backend.stale_router_id = scope.router_id
            elif router_id_edit == "established-peer":
                backend.ospf_neighbors = 1
        result = reconciler.reconcile(intent(revision), ospf_intent=native)
        if revision == "passive" and router_id_edit == "established-peer":
            assert result.verified_revision == "edit"
            assert result.error == "VyOS OSPF router ID changes require the current neighbors to be withdrawn"
            assert "stage" not in backend.events[event_offset:]
            assert backend.ospf["parameters"]["router-id"] == scope.router_id
            return
        if revision == "passive" and router_id_edit == "stale":
            assert result.verified_revision == "edit"
            assert result.error == "VyOS OSPF has not activated the intended router ID"
            assert "confirm" not in backend.events[event_offset:] and "save" not in backend.events[event_offset:]
            assert backend.ospf["parameters"]["router-id"] == "198.51.100.9"
            return
        assert result.verified_revision == revision, result.error
        assert backend.events[-2:] == ["confirm", "save"]
        if cost is None:
            assert backend.ospf is None
        else:
            assert set(backend.ospf["interface"]) == {"eth3.120"}
            assert backend.ospf["interface"]["eth3.120"]["cost"] == str(cost)
            assert backend.ospf["parameters"]["router-id"] == ("198.51.100.9" if revision == "passive" else scope.router_id)
            assert ("passive" in backend.ospf["interface"]["eth3.120"]) == (revision == "passive")


def test_ospf_authentication_recovers_pending_save_without_journaling_credentials(tmp_path):
    scope = OspfScope(None, "br120", "eth3.120", "192.0.2.1/24")
    backend = FakeOspfConfig()
    options = {
        "state_path": tmp_path / "firewall.json", "rule_base": 80200, "ospf_scope": scope,
        "interfaces": {IPv4Network("192.168.110.0/24"): "eth3.110", IPv4Network("192.0.2.0/24"): "eth3.120"},
    }
    fixture = Path(__file__).parent / "fixtures" / "uxg_pro/native-ospf-snapshots.json"
    wire = json.loads(fixture.read_text())["create"]
    secret = "fit!Key8"
    wire["udapi"]["routes/ospf/interfaces"][0]["authentication"] = {"authType": "plainText", "authKey": secret}
    request = decode_ospf_intent(
        json.dumps(wire), revision="auth", scope=scope, dns_forwarder=True, nat=True, wireguard=True,
    )
    backend.save_timeout = True
    initial = VyOSReconciler(backend, **options).reconcile(intent("auth"), ospf_intent=request)
    assert initial.verified_revision is None and initial.error
    key_file = tmp_path / "firewall.json.ospf-proof-key"
    assert key_file.stat().st_mode & 0o777 == 0o600
    journal = options["state_path"]
    state = json.loads(journal.read_text())
    assert state["pending"]["confirmed"] and "hmac-sha256:" in journal.read_text()
    assert secret not in journal.read_text()
    original_events = backend.events.copy()

    saved_key = key_file.rename(tmp_path / "existing-proof-key")
    restarted = VyOSReconciler(backend, **options)
    result = restarted.reconcile(intent("auth"), ospf_intent=request)
    assert "Restore the OSPF credential proof key" in result.error
    assert not key_file.exists() and backend.events == original_events
    saved_key.rename(key_file)

    backend.save_timeout = False
    result = restarted.reconcile(intent("auth"), ospf_intent=request)
    assert result.verified_revision == "auth" and result.error is None
    assert backend.events.count("stage") == 1 and secret not in journal.read_text()
    state = json.loads(journal.read_text())
    assert state["pending"] is None and "hmac-sha256:" in json.dumps(state["verified_ospf"])

    backend.ospf["interface"]["eth3.120"]["authentication"]["plaintext-password"] = "operator"
    result = restarted.reconcile(intent("auth"), ospf_intent=request)
    assert result.error == "VyOS OSPF root differs from verified ownership"
    assert backend.events.count("stage") == 1


@pytest.mark.parametrize("inspection_backend", [None, "legacy", "stock"])
def test_gateway_acknowledges_only_verified_policy_on_approved_baseline(tmp_path, monkeypatch, inspection_backend):
    fixture = Path(__file__).parent / "fixtures/uxg_pro/zbf-native-snapshots.json"
    snapshots = json.loads(fixture.read_text())["snapshots"]
    original = snapshots["created"]
    config_path = tmp_path / "gateway.conf"
    config_path.write_text(f"""[global]
pid_file = {tmp_path}/gateway.pid
[gateway]
device = UXGENT
platform = vyos
is_adopted = true
lan_mac = 02:78:91:00:12:03
lan_ip = 192.0.2.1
url = http://lab.example:8080/inform
ports = []
[vyos_firewall]
enabled = true
unmanaged_baseline_sha256 = {unmanaged_config_fingerprint(original['system_cfg'], revision=original['cfgversion'])}
""")
    monkeypatch.setattr(unifi_gateway, "CONFIG_FILE", str(config_path))
    gateway = unifi_gateway.UnifiGateway()
    backend = FakeFirewall()
    gateway.datacollector = SimpleNamespace(data={})
    inspection_options = {}
    if inspection_backend == "legacy":
        off = InspectionIntent("off", ())
        gateway.vyos_inspection = SimpleNamespace(normalize=lambda raw: (raw, off), verify=lambda desired: None,
                                                apply=lambda desired: pytest.fail("A healthy actuator must not change"))
    if inspection_backend == "stock":
        engine = FakeInspectionEngine(backend)
        engine.normalize = lambda raw: (raw, InspectionIntent("off", ()))
        gateway.vyos_inspection = engine
        gateway._stock_inspection = True
        gateway._security_event_worker = object()
        inspection_options = {"stock_inspection_policy": FakeInspectionQueue(), "inspection_controller": engine}
    gateway.vyos_provisioner = VyOSReconciler(
        backend, state_path=tmp_path / "firewall.json", rule_base=80200,
        interfaces={IPv4Network("192.0.2.0/24"): "eth3.110", IPv4Network("198.51.100.0/24"): "eth3.120"},
        **inspection_options,
    )
    notifications = []
    monkeypatch.setattr(gateway, "_send_inform", lambda data: notifications.append(json.loads(data)))

    gateway._handle_response({"_type": "setparam", **original})
    revision = original["cfgversion"]
    accepted = json.loads(create_inform(gateway.config, gateway.datacollector))
    assert accepted["cfgversion"] == accepted["cfgversion_effective"] == revision
    assert backend.rules["80200"]["destination"]["port"] == "8443"
    if inspection_backend == "stock":
        assert backend.events.index("save") < backend.events.index("finish-engine")
        digest = sha256(original["system_cfg"].encode()).hexdigest()
        assert gateway.config.get("vyos_applied", "system_cfg_sha256") == digest

    gateway._handle_response({"_type": "setparam", "interval": 15})
    assert gateway.interval == 15
    assert notifications == []

    modified = json.loads(snapshots["edited"]["system_cfg"])
    modified["udapi"]["services"] = {"unexpected": True}
    rejected = {"_type": "setparam", "cfgversion": snapshots["edited"]["cfgversion"],
                "system_cfg": json.dumps(modified)}
    gateway._handle_response(rejected)
    gateway._handle_response(rejected)
    if inspection_backend == "stock":
        assert gateway.config.get("vyos_applied", "system_cfg_sha256") == digest
    assert backend.rules["80200"]["destination"]["port"] == "8443"
    assert len(notifications) == 1
    notice = notifications[0]
    assert notice["cfgversion"] == notice["cfgversion_effective"] == revision
    assert notice["inform_as_notif"] is True and notice["notif_reason"] == "setparam"
    assert "could not be verified" in notice["commit_errors"]


def test_changed_openvpn_certificate_pin_cannot_reuse_another_enrollment_journal(tmp_path):
    ports = [{"type": "lan", "realif": "eth3.110"}, {"type": "lan", "realif": "eth3.120"},
             {"type": "wan", "ifname": "eth0", "realif": "eth3.210"}]
    collector = SimpleNamespace(backend=FakeOpenVpnConfig(), ports=ports)
    settings = ConfigParser()
    settings.read_dict({
        "vyos_firewall": {"interfaces": json.dumps({"192.168.110.0/24": "eth3.110", "192.168.120.0/24": "eth3.120"}),
                          "state_path": str(tmp_path / "firewall.json"), "rule_base": "80200"},
        "vyos_openvpn": {"enabled": "true", "guard_rule_base": "79300"},
    })

    def configured():
        return VyOSReconciler.from_config(collector, settings["vyos_firewall"], openvpn_settings=settings["vyos_openvpn"])

    with pytest.raises(ValueError, match="certificate"):
        configured()
    settings["vyos_openvpn"]["server_name"] = "router.example.net"
    previous = configured()
    assert previous.scope["openvpn"]["server_name"] == "router.example.net"
    empty = {chain: {} for chain in OPENVPN_GUARD_PATHS}
    collector.backend.guards.update(plan_openvpn_guards(previous.openvpn_guard, active=True, current=empty, verified=empty).desired)
    result = previous.reconcile(intent("empty"), openvpn_intent=OpenVpnDesired("empty", None))
    assert result.verified_revision == "empty", result.error
    saved = previous.state_path.read_bytes()
    settings["vyos_openvpn"]["server_name"] = "vpn.example.net"
    changed = configured()
    assert changed.openvpn_scope.server_name == changed.scope["openvpn"]["server_name"] == "vpn.example.net"
    with pytest.raises(ValueError, match="different scope"), changed.locked_state():
        pytest.fail("An active scope must remain bound to its original certificate pin")
    assert changed.state_path.read_bytes() == saved
