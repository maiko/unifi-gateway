from contextlib import contextmanager
from dataclasses import replace

import pytest

from inspection.suricata import InspectionIntent
from inspection.vyos_queue import (
    BridgeEndpoint,
    EngineIdentity,
    QueueBinding,
    QueueHealth,
    QueuePlan,
    QueueScope,
)


@pytest.fixture
def api():
    from inspection import supervisor

    return supervisor


@pytest.fixture
def approval(api):
    return api.InspectionApproval(
        owner="uxg-inspection",
        plan=QueuePlan(
            QueueScope(
                BridgeEndpoint(
                    "br110", "eth3.110", "192.168.110.1/24", "192.168.110.2"
                ),
                BridgeEndpoint(
                    "br120", "eth3.120", "192.168.120.1/24", "192.168.120.2"
                ),
                18743,
                41110,
            )
        ),
        vendor_controls_sha256="a" * 64,
        notify_policy_sha256="b" * 64,
        block_policy_sha256="c" * 64,
    )


def intent(mode):
    if mode == "off":
        return InspectionIntent("off", ())
    return InspectionIntent(mode, ("br120", "br110"), "a" * 64)


class FakeControl:
    def __init__(self, api):
        self.api = api
        self.state = api.InspectionReadback("boot-1", "1", scope_verified=True)
        self.generation = 1
        self.pid = 100
        self.calls = []
        self.failures = {}
        self.held = False
        self.ready = True

    @contextmanager
    def exclusive(self, *, timeout):
        assert not self.held and timeout > 0
        self.held = True
        try:
            yield
        finally:
            self.held = False

    def read(self, *, timeout):
        assert self.held and timeout > 0
        self.calls.append("read")
        return self.state

    def mutate(self, action, expected, timeout, **values):
        assert self.held and timeout > 0
        assert expected is self.state
        self.calls.append(action)
        if self.failures.get(action) == "before":
            raise self.api.InspectionControlError("redacted")
        self.generation += 1
        self.state = replace(self.state, token=str(self.generation), **values)
        if self.failures.get(action) == "after":
            raise self.api.InspectionControlError("uncertain acknowledgement")

    def start_engine(self, spec, *, expected, timeout):
        assert (
            expected.engine is None
            and expected.hook is None
            and expected.listener is None
        )
        self.pid += 1
        identity = EngineIdentity(self.pid, 1000 + self.pid)
        self.mutate(
            "start-" + spec.mode,
            expected,
            timeout,
            engine=self.api.RunningInspection(identity, spec, self.ready),
            listener=identity if spec.mode == "block" and self.ready else None,
        )

    def stop_engine(self, engine, *, expected, timeout):
        assert expected.hook is None and expected.engine == engine
        self.mutate(
            "stop-" + engine.spec.mode, expected, timeout, engine=None, listener=None
        )

    def install_hook(self, owner, plan, engine, *, expected, timeout):
        assert expected.hook is None and expected.engine == engine
        assert expected.listener == engine.identity and engine.ready
        self.mutate(
            "install",
            expected,
            timeout,
            hook=self.api.OwnedQueueHook(owner, 113, plan),
            hook_health=QueueHealth(
                "attached", "verified", QueueBinding(99, 0, 2, 65531, 0, 0, 0)
            ),
        )

    def remove_hook(self, hook, *, expected, timeout):
        assert hook == expected.hook
        self.mutate("remove", expected, timeout, hook=None, hook_health=None)

    @property
    def operations(self):
        return [action for action in self.calls if action != "read"]


def supervisor(api, control, approval):
    return api.InspectionSupervisor(control, approval=approval)


def test_block_checks_readback_between_operations_and_restarts_without_writes(
    api, approval
):
    control = FakeControl(api)
    result = supervisor(api, control, approval).reconcile(intent("block"))
    assert result.mode == "block"
    assert control.calls == ["read", "start-block", "read", "install", "read"]

    control.calls.clear()
    assert supervisor(api, control, approval).reconcile(intent("block")).mode == "block"
    assert control.calls == ["read"]


def test_notify_off_and_block_transition_order(api, approval):
    control = FakeControl(api)
    controller = supervisor(api, control, approval)
    assert controller.reconcile(intent("notify")).mode == "notify"
    assert controller.reconcile(intent("block")).mode == "block"
    assert controller.reconcile(intent("notify")).mode == "notify"
    assert controller.reconcile(intent("off")).mode == "off"
    assert controller.reconcile(intent("off")).mode == "off"
    assert control.operations == [
        "start-notify",
        "stop-notify",
        "start-block",
        "install",
        "remove",
        "stop-block",
        "start-notify",
        "stop-notify",
    ]


def test_restart_adopts_approved_engine_running_without_hook(api, approval):
    control = FakeControl(api)
    controller = supervisor(api, control, approval)
    spec = approval.engine_spec("block")
    with control.exclusive(timeout=1):
        state = control.read(timeout=1)
        control.start_engine(spec, expected=state, timeout=1)
    control.calls.clear()
    assert controller.reconcile(intent("block")).mode == "block"
    assert control.calls == ["read", "install", "read"]


def test_lost_install_ack_is_cleaned_with_readback_before_retry(api, approval):
    control = FakeControl(api)
    control.failures["install"] = "after"
    result = supervisor(api, control, approval).reconcile(intent("block"))

    assert result.mode == "unavailable"
    assert control.calls == [
        "read",
        "start-block",
        "read",
        "install",
        "read",
        "remove",
        "read",
        "stop-block",
        "read",
    ]
    assert control.state.hook is None and control.state.engine is None
    del control.failures["install"]
    assert supervisor(api, control, approval).reconcile(intent("block")).mode == "block"


def test_off_leaves_engine_attached_when_hook_removal_cannot_be_verified(api, approval):
    control = FakeControl(api)
    controller = supervisor(api, control, approval)
    assert controller.reconcile(intent("block")).mode == "block"
    control.failures["remove"] = "before"
    control.calls.clear()
    assert controller.reconcile(intent("off")).mode == "unavailable"
    assert control.operations == ["remove"]
    assert control.state.engine is not None and control.state.hook is not None


def test_engine_loss_detaches_before_repair_and_reports_unavailable_on_failure(
    api, approval
):
    control = FakeControl(api)
    controller = supervisor(api, control, approval)
    assert controller.reconcile(intent("block")).mode == "block"
    control.state = replace(
        control.state,
        engine=None,
        listener=None,
        hook_health=QueueHealth("bypassing", "listener absent"),
    )
    control.failures["start-block"] = "before"
    control.calls.clear()
    assert controller.reconcile(intent("block")).mode == "unavailable"
    assert control.operations == ["remove", "start-block"]
    assert control.state.hook is None


def test_health_check_reports_bypass_without_starting_or_stopping_engine(api, approval):
    control = FakeControl(api)
    controller = supervisor(api, control, approval)
    assert controller.reconcile(intent("block")).mode == "block"
    control.calls.clear()
    assert controller.verify(intent("block")).mode == "block"
    control.state = replace(
        control.state,
        engine=None,
        listener=None,
        hook_health=QueueHealth("bypassing", "listener absent"),
    )
    assert controller.verify(intent("block")).mode == "unavailable"
    assert control.calls == ["read", "read"]
    assert control.state.hook is not None


def test_unready_or_unconfirmed_process_is_never_routed_into(api, approval):
    control = FakeControl(api)
    control.ready = False
    result = supervisor(api, control, approval).reconcile(intent("block"))
    assert result.mode == "unavailable"
    assert control.operations == ["start-block", "stop-block"]


def test_scope_drift_detaches_an_owned_hook_and_stops_its_engine(api, approval):
    control = FakeControl(api)
    controller = supervisor(api, control, approval)
    assert controller.reconcile(intent("block")).mode == "block"
    control.state = replace(control.state, scope_verified=False)
    control.calls.clear()
    assert controller.reconcile(intent("block")).mode == "unavailable"
    assert control.operations == ["remove", "stop-block"]


def test_unapproved_scope_or_vendor_policy_cannot_change_existing_state(api, approval):
    control = FakeControl(api)
    controller = supervisor(api, control, approval)
    assert controller.reconcile(intent("block")).mode == "block"
    control.calls.clear()
    assert (
        controller.reconcile(InspectionIntent("block", ("br110",), "a" * 64)).mode
        == "unavailable"
    )
    assert (
        controller.reconcile(
            InspectionIntent("notify", ("br110", "br120"), "d" * 64)
        ).mode
        == "unavailable"
    )
    assert control.operations == []


def test_refuses_foreign_hook_and_preserves_unknown_owners(api, approval):
    control = FakeControl(api)
    control.state = replace(
        control.state, hook=api.OwnedQueueHook("other-service", 113, approval.plan)
    )
    controller = supervisor(api, control, approval)
    assert controller.reconcile(intent("off")).mode == "unavailable"
    assert control.operations == []
    assert control.state.hook.owner == "other-service"


def test_boot_change_never_uses_prior_process_claim_for_cleanup(api, approval):
    class Reboot(FakeControl):
        def start_engine(self, spec, *, expected, timeout):
            super().start_engine(spec, expected=expected, timeout=timeout)
            self.state = replace(self.state, boot_id="boot-2")

    control = Reboot(api)
    result = supervisor(api, control, approval).reconcile(intent("block"))
    assert result.mode == "unavailable"
    assert control.operations == ["start-block"]


def test_lost_teardown_ack_continues_only_with_verified_absence(api, approval):
    control = FakeControl(api)
    controller = supervisor(api, control, approval)
    assert controller.reconcile(intent("block")).mode == "block"
    control.failures.update(remove="after", **{"stop-block": "after"})
    control.calls.clear()

    assert controller.reconcile(intent("off")).mode == "off"
    assert control.calls == ["read", "remove", "read", "stop-block", "read"]


def test_activation_deadline_reserves_time_for_owned_cleanup(
    api, approval, monkeypatch
):
    clock = [100.0]
    monkeypatch.setattr(api.time, "monotonic", lambda: clock[0])

    class SlowAttach(FakeControl):
        def install_hook(self, owner, plan, engine, *, expected, timeout):
            super().install_hook(
                owner, plan, engine, expected=expected, timeout=timeout
            )
            clock[0] += timeout

    control = SlowAttach(api)
    result = supervisor(api, control, approval).reconcile(intent("block"))
    assert result.mode == "unavailable"
    assert "cleanup" not in result.reason
    assert control.operations == ["start-block", "install", "remove", "stop-block"]
    assert control.state.engine is None and control.state.hook is None


def test_foreign_listener_is_neither_claimed_nor_stopped(api, approval):
    control = FakeControl(api)
    foreign = EngineIdentity(4242, 6666)
    control.state = replace(control.state, listener=foreign)
    controller = supervisor(api, control, approval)

    for mode in ("off", "notify", "block"):
        assert controller.reconcile(intent(mode)).mode == "unavailable"
    assert control.state.listener == foreign
    assert control.operations == []
