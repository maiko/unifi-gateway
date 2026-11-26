import hashlib
import json
import socket
from dataclasses import replace

import pytest

from inspection.suricata import InspectionIntent
from inspection.supervisor import InspectionControlError, InspectionSupervisor
from inspection.vyos_queue import EngineIdentity, LiveVlan, QueueBinding, QueuePeer
from inspection.vyos_readback import (
    EngineClaim,
    ForeignInspectionResource,
    KernelIdentity,
    NftInventory,
    VerifiedListener,
)

VENDOR = "a" * 64
BOOT = KernelIdentity("cc74de35-40e5-4777-a4ce-a2eb32f55d6e", 4026531840)
PID = EngineIdentity(1213, 9891)
HOOK_HANDLE = 874


@pytest.fixture
def api(monkeypatch):
    from inspection import vyos_control

    monkeypatch.setattr(vyos_control, "_require_linux_root", lambda: None)
    monkeypatch.setattr(socket, "gethostname", lambda: "branch-router")
    return vyos_control


class FakeRuntime:
    def __init__(self, api, plan):
        self.api = api
        self.plan = plan
        self.kernel = BOOT
        self.engine = None
        self.hook = None
        self.faults = set()
        self.calls = []
        self.operator_rule = {"accept": None}
        self.socket_inode = 9191

    def _bound(self, deadline):
        self.api._budget(deadline)

    def inventory(self, deadline):
        self._bound(deadline)
        data = {
            "nftables": [
                {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
                {"table": {"family": "ip", "name": "vyos_filter", "handle": 1}},
                {
                    "chain": {
                        "family": "ip",
                        "table": "vyos_filter",
                        "name": "VYOS_FORWARD_filter",
                        "type": "filter",
                        "hook": "forward",
                        "prio": 0,
                        "policy": "accept",
                    }
                },
                {
                    "rule": {
                        "family": "ip",
                        "table": "vyos_filter",
                        "chain": "VYOS_FORWARD_filter",
                        "expr": [self.operator_rule],
                    }
                },
            ]
        }
        if self.hook is not None:
            for i, command in enumerate(self.plan.creation_batch()["nftables"]):
                [entry] = command.values()
                [value] = entry.values()
                value["handle"] = self.hook if i == 0 else i
                data["nftables"].append(entry)
        raw = json.dumps(data, sort_keys=True).encode()
        return NftInventory(self.kernel, hashlib.sha256(raw).hexdigest(), raw)

    def links(self, deadline):
        self._bound(deadline)
        return {
            "eth3.110": LiveVlan(110, "192.168.110.1/24", True),
            "eth3.120": LiveVlan(120, "192.168.120.1/24", True),
        }

    def listener(self, claim, deadline):
        self._bound(deadline)
        if "unverified-post-install" in self.faults and self.hook is not None:
            raise InspectionControlError("Runtime listener readback is unavailable")
        if self.engine is None or self.engine[0] != "block":
            return None
        if claim != EngineClaim(self.kernel, self.engine[1]):
            raise ForeignInspectionResource("Reserved NFQUEUE is bound")
        return VerifiedListener(
            self.kernel,
            QueueBinding(
                622, 0, 2, 128 if "short-copy" in self.faults else 65531, 0, 0, 0
            ),
            QueuePeer(622, self.socket_inode, self.engine[1]),
        )

    def approved_engine_ready(self, receipt, kernel, deadline):
        self._bound(deadline)
        if self.engine is None:
            return None
        if kernel != self.kernel or self.engine != (receipt.mode, receipt.identity):
            raise ForeignInspectionResource("Engine claim differs")
        return True

    def assert_engine_absent(self, deadline):
        self._bound(deadline)
        if self.engine is not None:
            raise ForeignInspectionResource("Existing Suricata process")

    def start_notify_observer(self, generation, kernel, engine, deadline):
        self._bound(deadline)
        assert generation.mode == "notify" and generation.end is None
        assert kernel == BOOT and self.engine == ("notify", engine)
        self.calls.append("observe-notify")
        if "observer-failed" in self.faults:
            raise InspectionControlError("Notification observer was unavailable")

    def test_policy(self, mode, deadline):
        self._bound(deadline)
        self.calls.append("test-" + mode)

    def start(self, mode, kernel, deadline):
        self._bound(deadline)
        assert self.engine is None and self.hook is None and kernel == self.kernel
        self.calls.append("start-" + mode)
        self.engine = mode, PID
        if "rolled-back-start" in self.faults:
            self.engine = None
            raise self.api.EngineStartRolledBack("Child was reaped")
        if "unknown-start" in self.faults:
            raise InspectionControlError("launch outcome is unknown")
        return PID

    def stop(self, receipt, kernel, deadline):
        self._bound(deadline)
        assert self.hook is None and kernel == self.kernel
        assert (receipt.mode, receipt.identity) == self.engine
        self.calls.append("stop-" + receipt.mode)
        self.engine = None

    def check_hook(self, deadline):
        self._bound(deadline)
        self.calls.append("check-hook")

    def install(self, deadline):
        self._bound(deadline)
        assert self.hook is None and self.engine[0] == "block"
        self.calls.append("install")
        self.hook = HOOK_HANDLE
        if "unknown-install" in self.faults:
            raise InspectionControlError("table creation outcome is unknown")
        if "operator-drift" in self.faults:
            self.operator_rule = {"drop": None}

    def delete(self, handle, deadline):
        self._bound(deadline)
        assert handle == self.hook
        self.calls.append(("delete", handle))
        self.hook = None


@pytest.fixture
def inspection_setup(api, tmp_path):
    approval = api.reference_inspection_approval(vendor_controls_sha256=VENDOR)
    directory = tmp_path / "local"
    directory.mkdir(mode=0o700)
    runtime = FakeRuntime(api, approval.plan)
    control = api.LocalVyOSInspectionControl(
        directory, approval=approval, router_hostname="branch-router", _runtime=runtime
    )
    return approval, directory, runtime, control


def intent(mode):
    return InspectionIntent(
        mode,
        ("br110", "br120") if mode != "off" else (),
        VENDOR if mode != "off" else None,
    )


def test_foreign_hook_receipt_is_rejected_without_removing_the_hook(inspection_setup):
    approval, directory, runtime, control = inspection_setup
    supervisor = InspectionSupervisor(control, approval=approval)
    assert supervisor.reconcile(intent("block")).mode == "block"
    path = directory / "ownership.json"
    receipt = json.loads(path.read_text())
    assert receipt["owner"] == "unifi-inspection"
    receipt["owner"] = "another-service"
    path.write_text(json.dumps(receipt))
    runtime.calls.clear()
    assert supervisor.reconcile(intent("off")).mode == "unavailable"
    assert not runtime.calls
    assert json.loads(path.read_text()) == receipt


def test_receipts_resume_existing_inline_engine_and_table_after_restart(api, inspection_setup):
    approval, directory, runtime, control = inspection_setup
    assert (
        InspectionSupervisor(control, approval=approval).reconcile(intent("block")).mode
        == "block"
    )
    assert (directory / "ownership.json").stat().st_mode & 0o777 == 0o600
    stored = json.loads((directory / "ownership.json").read_text())
    assert stored["engine"]["pid"] == PID.pid
    assert stored["engine"]["start_ticks"] == PID.start_ticks
    assert stored["hook_handle"] == HOOK_HANDLE

    runtime.calls.clear()
    restarted = api.LocalVyOSInspectionControl(
        directory, approval=approval, router_hostname="branch-router", _runtime=runtime
    )
    assert (
        InspectionSupervisor(restarted, approval=approval)
        .reconcile(intent("block"))
        .mode
        == "block"
    )
    assert runtime.calls == []
    assert (
        InspectionSupervisor(restarted, approval=approval).reconcile(intent("off")).mode
        == "off"
    )
    assert runtime.calls == [("delete", HOOK_HANDLE), "stop-block"]


def test_stock_phases_pin_listener_across_restart_without_writing_nftables(api, inspection_setup):
    approval, directory, runtime, _ = inspection_setup

    def restart():
        return api.LocalVyOSInspectionControl(directory, approval=approval, router_hostname="branch-router", _runtime=runtime, engine_only=True,
                                              observe_notify=True)

    restart().engine_phase("prepare-engine", intent("block"))
    runtime.operator_rule = {"queue": {"num": 41110, "flags": ["bypass"]}}
    restart().engine_phase("verify-engine", intent("block"))
    assert runtime.calls == ["test-block", "start-block"]

    runtime.socket_inode += 1
    with pytest.raises(InspectionControlError):
        restart().engine_phase("verify-engine", intent("block"))
    assert runtime.calls == ["test-block", "start-block"]

    runtime.socket_inode -= 1
    runtime.operator_rule = {"accept": None}
    restart().engine_phase("apply-engine", intent("notify"))
    restart().engine_phase("verify-engine", intent("notify"))
    restart().engine_phase("apply-engine", intent("off"))
    restart().engine_phase("verify-engine", intent("off"))
    assert runtime.calls == ["test-block", "start-block", "stop-block", "test-notify", "start-notify", "observe-notify", "stop-notify"]


def test_stock_notify_observer_failure_rolls_back_owned_engine(api, inspection_setup):
    approval, directory, runtime, _ = inspection_setup
    runtime.faults.add("observer-failed")
    control = api.LocalVyOSInspectionControl(directory, approval=approval, engine_only=True, observe_notify=True,
                                             router_hostname="branch-router", _runtime=runtime)
    with pytest.raises(InspectionControlError, match="observer was unavailable"):
        control.engine_phase("apply-engine", intent("notify"))
    assert runtime.calls == ["test-notify", "start-notify", "observe-notify", "stop-notify"]
    assert runtime.engine is None and runtime.hook is None
    claim = api._read_ownership(control._files)
    assert claim.engine is None and claim.pending is None


@pytest.mark.parametrize("foreign", ["raw-table", "queue-owner", "unclaimed-passive"])
def test_stock_phase_refuses_foreign_resources_without_mutation(api, inspection_setup, foreign):
    approval, directory, runtime, _ = inspection_setup
    control = api.LocalVyOSInspectionControl(directory, approval=approval, router_hostname="branch-router", _runtime=runtime, engine_only=True)
    if foreign == "raw-table":
        runtime.hook = HOOK_HANDLE
    else:
        runtime.engine = ("block" if foreign == "queue-owner" else "notify"), PID

    with pytest.raises(InspectionControlError):
        control.engine_phase("apply-engine", intent("off"))

    assert runtime.calls == []


@pytest.mark.parametrize("kind", ["foreign-table", "foreign-process", "foreign-queue"])
def test_preexisting_reserved_resources_are_left_intact(inspection_setup, kind):
    approval, _, runtime, control = inspection_setup
    if kind == "foreign-table":
        runtime.hook = HOOK_HANDLE
    elif kind == "foreign-process":
        runtime.engine = "notify", PID
    else:
        runtime.engine = "block", PID
    assert (
        InspectionSupervisor(control, approval=approval).reconcile(intent("block")).mode
        == "unavailable"
    )
    assert runtime.calls == []
    assert (runtime.hook is not None) == (kind == "foreign-table")
    assert (runtime.engine is not None) == (kind != "foreign-table")


def test_stale_inventory_token_prevents_start(inspection_setup):
    approval, _, runtime, control = inspection_setup
    with control.exclusive(timeout=1):
        expected = control.read(timeout=1)
        runtime.operator_rule = {"drop": None}
        with pytest.raises(InspectionControlError, match="changed"):
            control.start_engine(
                approval.engine_spec("block"), expected=expected, timeout=1
            )
    assert runtime.calls == []


def test_handle_replacement_is_never_removed(inspection_setup):
    approval, _, runtime, control = inspection_setup
    supervisor = InspectionSupervisor(control, approval=approval)
    assert supervisor.reconcile(intent("block")).mode == "block"
    runtime.calls.clear()
    runtime.hook = HOOK_HANDLE + 1
    assert supervisor.reconcile(intent("off")).mode == "unavailable"
    assert runtime.calls == []
    assert runtime.hook == HOOK_HANDLE + 1
    assert runtime.engine is not None


def test_outside_drift_during_install_rolls_back_only_new_owned_table(inspection_setup):
    approval, _, runtime, control = inspection_setup
    runtime.faults.add("operator-drift")
    result = InspectionSupervisor(control, approval=approval).reconcile(intent("block"))
    assert result.mode == "unavailable"
    assert runtime.hook is None and runtime.engine is None
    assert runtime.operator_rule == {"drop": None}
    assert runtime.calls[-2:] == [("delete", HOOK_HANDLE), "stop-block"]


@pytest.mark.parametrize("fault", ["unknown-start", "unknown-install"])
def test_uncertain_resources_are_preserved_and_unavailable_after_restart(
    api, inspection_setup, fault
):
    approval, directory, runtime, control = inspection_setup
    runtime.faults.add(fault)
    assert (
        InspectionSupervisor(control, approval=approval).reconcile(intent("block")).mode
        == "unavailable"
    )
    assert json.loads((directory / "ownership.json").read_text())["pending"] is not None

    runtime.calls.clear()
    second = api.LocalVyOSInspectionControl(
        directory, approval=approval, router_hostname="branch-router", _runtime=runtime
    )
    assert (
        InspectionSupervisor(second, approval=approval).reconcile(intent("off")).mode
        == "unavailable"
    )
    assert runtime.calls == []


def test_approval_cannot_expand_tuple_or_substitute_policy(api, inspection_setup):
    approval, directory, runtime, _ = inspection_setup
    altered_plan = replace(
        approval.plan, scope=replace(approval.plan.scope, server_port=9000)
    )
    for changed in (
        replace(approval, plan=altered_plan),
        replace(approval, block_policy_sha256="d" * 64),
    ):
        with pytest.raises(ValueError):
            api.LocalVyOSInspectionControl(
                directory, approval=changed, router_hostname="branch-router", _runtime=runtime
            )


def test_router_rename_invalidates_inspection_readback_before_engine_start(api, inspection_setup, monkeypatch):
    approval, directory, runtime, _ = inspection_setup
    monkeypatch.setattr(socket, "gethostname", lambda: "edge-east")
    control = api.LocalVyOSInspectionControl(directory, approval=approval, _runtime=runtime,
                                             router_hostname="edge-east")
    with control.exclusive(timeout=1):
        observed = control.read(timeout=1)
        monkeypatch.setattr(socket, "gethostname", lambda: "edge-west")
        with pytest.raises(InspectionControlError, match="hostname"):
            control.start_engine(approval.engine_spec("block"), expected=observed, timeout=1)
    assert runtime.engine is None and runtime.hook is None
    assert not (directory / "ownership.json").exists()


def test_proven_launch_rollback_clears_pending_for_later_recovery(api, inspection_setup):
    approval, directory, runtime, control = inspection_setup
    runtime.faults.add("rolled-back-start")
    assert (
        InspectionSupervisor(control, approval=approval).reconcile(intent("block")).mode
        == "unavailable"
    )
    assert json.loads((directory / "ownership.json").read_text())["pending"] is None
    assert runtime.engine is None
    runtime.faults.clear()
    restarted = api.LocalVyOSInspectionControl(
        directory, approval=approval, router_hostname="branch-router", _runtime=runtime
    )
    assert (
        InspectionSupervisor(restarted, approval=approval)
        .reconcile(intent("block"))
        .mode
        == "block"
    )


def test_old_boot_receipt_does_not_own_a_lookalike_current_table(inspection_setup):
    approval, _, runtime, control = inspection_setup
    supervisor = InspectionSupervisor(control, approval=approval)
    assert supervisor.reconcile(intent("block")).mode == "block"
    runtime.kernel = KernelIdentity(
        "4659bb70-e234-42f3-9614-16f4854582be", BOOT.namespace_inode
    )
    runtime.calls.clear()
    assert supervisor.reconcile(intent("off")).mode == "unavailable"
    assert runtime.calls == []
    assert runtime.hook == HOOK_HANDLE


def test_unqualified_queue_copy_range_is_rejected_before_installing_hook(inspection_setup):
    approval, _, runtime, control = inspection_setup
    runtime.faults.add("short-copy")
    assert (
        InspectionSupervisor(control, approval=approval).reconcile(intent("block")).mode
        == "unavailable"
    )
    assert "install" not in runtime.calls
    assert runtime.hook is None and runtime.engine is None


def test_symlinked_receipt_cannot_be_read_or_replaced(inspection_setup, tmp_path):
    approval, directory, runtime, control = inspection_setup
    outside = tmp_path / "operator"
    outside.write_text("operator state")
    (directory / "ownership.json").symlink_to(outside)

    assert (
        InspectionSupervisor(control, approval=approval).reconcile(intent("block")).mode
        == "unavailable"
    )
    assert runtime.calls == []
    assert outside.read_text() == "operator state"
    assert (directory / "ownership.json").is_symlink()


def test_failed_post_install_listener_readback_removes_only_verified_new_hook(inspection_setup):
    approval, _, runtime, control = inspection_setup
    runtime.faults.add("unverified-post-install")
    assert (
        InspectionSupervisor(control, approval=approval).reconcile(intent("block")).mode
        == "unavailable"
    )
    assert runtime.calls[-2:] == [("delete", HOOK_HANDLE), "stop-block"]
    assert runtime.hook is None and runtime.engine is None
    assert runtime.operator_rule == {"accept": None}


@pytest.mark.parametrize("mode", ["notify", "block"])
def test_local_eve_policy_emits_flow_counters_without_payload_or_app_metadata(api, mode):
    config, _, _ = api._policy(mode)
    event_types = (
        config.split(b"      types:\n")[1].split(b"\n\naf-packet:")[0].splitlines()
    )

    assert b"        - flow" in event_types
    for setting in (b"payload", b"payload-printable", b"packet", b"tagged-packets"):
        assert b"            " + setting + b": no" in event_types
    assert b"            metadata:" in event_types
    assert b"              flow: yes" in event_types
    assert b"              app-layer: no" in event_types
    assert b"                metadata: no" in event_types
    assert b"                raw: no" in event_types


def test_notify_signature_applies_to_a_packet_and_block_keeps_stream_matching(api):
    assert b"flow:to_server,established,no_stream;" in api._policy("notify")[1]
    assert b"flow:to_server,established;" in api._policy("block")[1]


def test_stock_cut_is_durable_before_engine_launch_and_sealed_after_off(api, inspection_setup, monkeypatch):
    from inspection.vyos_eve_feed import EveGeneration

    approval, directory, runtime, _ = inspection_setup
    path = directory / "eve.json"
    path.write_bytes(b"old\n")
    path.chmod(0o600)
    original_start = runtime.start
    original_stop = runtime.stop

    def start(mode, kernel, deadline):
        pending = json.loads((directory / "ownership.json").read_text())
        assert pending["pending"] == "start"
        assert pending["eve_generations"][-1]["offset"] == 4
        return original_start(mode, kernel, deadline)

    def stop(receipt, kernel, deadline):
        with path.open("ab") as stream:
            stream.write(b"last\n")
        return original_stop(receipt, kernel, deadline)

    runtime.start, runtime.stop = start, stop
    monkeypatch.setattr(api.LinuxInspectionReader, "_kernel_identity", lambda self: BOOT)
    control = api.LocalVyOSInspectionControl(
        directory, approval=approval, engine_only=True, router_hostname="branch-router", _runtime=runtime
    )
    control.engine_phase("prepare-engine", intent("block"))
    cut = api._read_ownership(control._files).eve_generations[-1]
    assert isinstance(cut, EveGeneration) and cut.offset == 4 and cut.end is None

    control.engine_phase("apply-engine", intent("off"))
    stored = api._read_ownership(control._files)
    assert stored.engine is None and stored.eve_generations[-1] == replace(cut, end=9)
    assert control.read_events(None)["offset"] == 9


def test_block_cut_is_unavailable_without_a_verified_listener_receipt(api, inspection_setup, monkeypatch):
    approval, directory, runtime, _ = inspection_setup
    runtime.faults.add("short-copy")
    monkeypatch.setattr(api.LinuxInspectionReader, "_kernel_identity", lambda self: BOOT)
    control = api.LocalVyOSInspectionControl(
        directory, approval=approval, engine_only=True, router_hostname="branch-router", _runtime=runtime
    )
    with pytest.raises(InspectionControlError):
        control.engine_phase("prepare-engine", intent("block"))
    assert api._read_ownership(control._files).engine.listener is None
    assert control.read_events(None)["generation"] is None

    runtime.faults.clear()
    control.engine_phase("apply-engine", intent("off"))
    assert api._read_ownership(control._files).eve_generations == ()
    assert control.read_events(None)["generation"] is None
