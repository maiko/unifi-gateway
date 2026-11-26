"""Reconcile an approved inspection policy through an independent runtime control."""

import math
import re
import time
from dataclasses import dataclass
from typing import ContextManager, Literal, Protocol

from inspection.suricata import InspectionIntent
from inspection.vyos_queue import EngineIdentity, QueueHealth, QueuePlan, QueueScope

ActiveMode = Literal["notify", "block"]
InspectionMode = Literal["off", "notify", "block", "unavailable"]


class InspectionControlError(RuntimeError):
    """The runtime could not verify or safely perform an inspection operation."""


@dataclass(frozen=True, slots=True)
class EngineSpec:
    owner: str
    mode: ActiveMode
    scope: QueueScope
    policy_sha256: str


@dataclass(frozen=True, slots=True)
class InspectionApproval:
    owner: str
    plan: QueuePlan
    vendor_controls_sha256: str
    notify_policy_sha256: str
    block_policy_sha256: str

    def __post_init__(self):
        if (
            type(self.owner) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.owner) is None
            or not isinstance(self.plan, QueuePlan)
            or not isinstance(self.plan.scope, QueueScope)
            or any(
                type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                for digest in (
                    self.vendor_controls_sha256,
                    self.notify_policy_sha256,
                    self.block_policy_sha256,
                )
            )
        ):
            raise ValueError(
                "Inspection requires an approved owner, queue scope and policy hashes"
            )

    def engine_spec(self, mode: ActiveMode) -> EngineSpec:
        if mode == "notify":
            policy = self.notify_policy_sha256
        elif mode == "block":
            policy = self.block_policy_sha256
        else:
            raise ValueError("Off has no inspection engine")
        return EngineSpec(self.owner, mode, self.plan.scope, policy)


@dataclass(frozen=True, slots=True)
class RunningInspection:
    identity: EngineIdentity
    spec: EngineSpec
    ready: bool


@dataclass(frozen=True, slots=True)
class OwnedQueueHook:
    owner: str
    handle: int
    plan: QueuePlan


@dataclass(frozen=True, slots=True)
class InspectionReadback:
    """An authoritative view of the reserved scope in one router boot and namespace.

    The listener identifies the process holding the reserved queue, including
    a foreign process when identified. An absent entry means verified
    absence. An unavailable or ambiguous read raises InspectionControlError.
    """

    boot_id: str
    token: str
    scope_verified: bool
    engine: RunningInspection | None = None
    hook: OwnedQueueHook | None = None
    listener: EngineIdentity | None = None
    hook_health: QueueHealth | None = None


class InspectionControl(Protocol):
    """Privileged operations supplied by a separate scoped runtime transport.

    Recover ownership from stable runtime metadata and the exact hashes after
    restart. Read from the active namespace, including the expected process
    incarnation, socket inode/queue binding and exact rule content. Scope
    verification includes the approved capture filter and firewall placement.

    Hold a cross-process lock through exclusive(). Each mutator must compare
    the boot and token and recheck ownership and action preconditions at the
    point of mutation. Honor the supplied timeout, including the lock. An
    unresolved pending mutation must make later reads unavailable.
    """

    def exclusive(self, *, timeout: float) -> ContextManager[None]: ...

    def read(self, *, timeout: float) -> InspectionReadback: ...

    def start_engine(
        self, spec: EngineSpec, *, expected: InspectionReadback, timeout: float
    ) -> None: ...

    def stop_engine(
        self, engine: RunningInspection, *, expected: InspectionReadback, timeout: float
    ) -> None: ...

    def install_hook(
        self,
        owner: str,
        plan: QueuePlan,
        engine: RunningInspection,
        *,
        expected: InspectionReadback,
        timeout: float,
    ) -> None: ...

    def remove_hook(
        self, hook: OwnedQueueHook, *, expected: InspectionReadback, timeout: float
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class InspectionStatus:
    mode: InspectionMode
    reason: str | None = None


def _engine_identity(value: EngineIdentity) -> bool:
    return (
        isinstance(value, EngineIdentity)
        and type(value.pid) is int
        and value.pid > 0
        and type(value.start_ticks) is int
        and value.start_ticks > 0
    )


def _remaining(deadline: float) -> float:
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise InspectionControlError("Inspection transition timed out")
    return seconds


def _ready(state: InspectionReadback, desired: EngineSpec | None) -> bool:
    if desired is None:
        return state.engine is None and state.hook is None and state.listener is None
    engine = state.engine
    if (
        not state.scope_verified
        or engine is None
        or engine.spec != desired
        or not engine.ready
    ):
        return False
    if desired.mode == "notify":
        return state.listener is None
    return state.listener == engine.identity


def _verified(state: InspectionReadback, desired: EngineSpec | None) -> bool:
    if not _ready(state, desired):
        return False
    if desired is None or desired.mode == "notify":
        return state.hook is None
    health = state.hook_health
    return (
        state.hook is not None
        and health is not None
        and health.state == "attached"
        and health.queue is not None
    )


class InspectionSupervisor:
    """A single-writer transition driven by live owned resources and readback."""

    def __init__(
        self,
        control: InspectionControl,
        *,
        approval: InspectionApproval,
        timeout: float = 20,
    ):
        if not isinstance(approval, InspectionApproval):
            raise ValueError("Inspection requires a local approval")
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or not 0 < timeout <= 60
        ):
            raise ValueError("Inspection timeout must be between zero and 60 seconds")
        self._control = control
        self._approval = approval
        self._timeout = timeout
        self._approved = (approval.engine_spec("notify"), approval.engine_spec("block"))

    def reconcile(self, intent: InspectionIntent) -> InspectionStatus:
        return self._inspect(intent, verify_only=False)

    def verify(self, intent: InspectionIntent) -> InspectionStatus:
        return self._inspect(intent, verify_only=True)

    def _inspect(self, intent: InspectionIntent, *, verify_only: bool) -> InspectionStatus:
        if not isinstance(intent, InspectionIntent):
            return InspectionStatus("unavailable", "Inspection intent is unavailable")
        if (
            intent.mode == "off"
            and intent.networks == ()
            and intent.vendor_controls_sha256 is None
        ):
            desired = None
        else:
            scope = self._approval.plan.scope
            networks = intent.networks
            if (
                intent.mode not in ("notify", "block")
                or type(networks) is not tuple
                or len(networks) != 2
                or any(type(network) is not str for network in networks)
                or set(networks) != {scope.initiator.bridge, scope.responder.bridge}
                or intent.vendor_controls_sha256
                != self._approval.vendor_controls_sha256
            ):
                return InspectionStatus(
                    "unavailable", "Inspection is outside the approved scope or policy"
                )
            desired = self._approval.engine_spec(intent.mode)

        deadline = time.monotonic() + self._timeout
        try:
            with self._control.exclusive(timeout=_remaining(deadline)):
                if verify_only:
                    if _verified(self._read(deadline), desired):
                        return InspectionStatus(intent.mode)
                    return InspectionStatus("unavailable", "Live inspection is unverified")
                return self._transition(desired, deadline)
        except (InspectionControlError, OSError):
            return InspectionStatus(
                "unavailable", "Inspection control or readback failed"
            )

    def _read(self, deadline: float, boot_id: str | None = None) -> InspectionReadback:
        state = self._control.read(timeout=_remaining(deadline))
        _remaining(deadline)
        if (
            not isinstance(state, InspectionReadback)
            or type(state.boot_id) is not str
            or not state.boot_id
            or (boot_id is not None and state.boot_id != boot_id)
            or type(state.token) is not str
            or not state.token
            or type(state.scope_verified) is not bool
        ):
            raise InspectionControlError(
                "Inspection snapshot changed or is unavailable"
            )
        engine = state.engine
        if engine is not None and (
            not isinstance(engine, RunningInspection)
            or not _engine_identity(engine.identity)
            or engine.spec not in self._approved
            or type(engine.ready) is not bool
        ):
            raise InspectionControlError("Inspection engine ownership is ambiguous")
        hook = state.hook
        if hook is not None and (
            not isinstance(hook, OwnedQueueHook)
            or hook.owner != self._approval.owner
            or hook.plan != self._approval.plan
            or type(hook.handle) is not int
            or hook.handle <= 0
        ):
            raise InspectionControlError("Inspection table ownership is ambiguous")
        if state.listener is not None and not _engine_identity(state.listener):
            raise InspectionControlError("Inspection listener ownership is unavailable")
        if state.hook_health is not None and not isinstance(
            state.hook_health, QueueHealth
        ):
            raise InspectionControlError("Inspection queue health is unavailable")
        return state

    def _mutate(
        self,
        action,
        *args,
        state: InspectionReadback,
        deadline: float,
        verify_absence_after_error: bool = False,
    ) -> InspectionReadback:
        try:
            action(*args, expected=state, timeout=_remaining(deadline))
        except (InspectionControlError, OSError):
            if not verify_absence_after_error:
                raise
        return self._read(deadline, state.boot_id)

    def _detach(self, state: InspectionReadback, deadline: float) -> InspectionReadback:
        if state.hook is not None:
            state = self._mutate(
                self._control.remove_hook,
                state.hook,
                state=state,
                deadline=deadline,
                verify_absence_after_error=True,
            )
            if state.hook is not None:
                raise InspectionControlError("Inspection table removal is unverified")
        return state

    def _stop(self, state: InspectionReadback, deadline: float) -> InspectionReadback:
        if state.engine is not None:
            if state.hook is not None:
                raise InspectionControlError(
                    "Inspection table must be removed before engine shutdown"
                )
            stopped = state.engine.identity
            state = self._mutate(
                self._control.stop_engine,
                state.engine,
                state=state,
                deadline=deadline,
                verify_absence_after_error=True,
            )
            if state.engine is not None or state.listener == stopped:
                raise InspectionControlError("Inspection engine removal is unverified")
        return state

    def _transition(
        self, desired: EngineSpec | None, deadline: float
    ) -> InspectionStatus:
        state = self._read(deadline)
        if _verified(state, desired):
            return InspectionStatus(desired.mode if desired is not None else "off")
        boot_id = state.boot_id
        abnormal_queue = state.hook is not None and (
            state.hook_health is None or state.hook_health.state != "attached"
        )
        try:
            state = self._detach(state, deadline)
            if abnormal_queue or not _ready(state, desired):
                state = self._stop(state, deadline)
        except (InspectionControlError, OSError):
            return InspectionStatus(
                "unavailable", "Inspection shutdown could not be verified"
            )

        if desired is None:
            if not _verified(state, None):
                return InspectionStatus(
                    "unavailable", "The reserved inspection queue is still occupied"
                )
            return InspectionStatus("off")
        if not state.scope_verified:
            return InspectionStatus(
                "unavailable", "Live inspection scope could not be verified"
            )
        if state.listener is not None and not _ready(state, desired):
            return InspectionStatus(
                "unavailable", "The reserved inspection queue is occupied"
            )

        # Leave part of the transition bound for cleanup after an uncertain activation.
        activation_deadline = deadline - min(5.0, self._timeout / 4)
        try:
            if state.engine is None:
                state = self._mutate(
                    self._control.start_engine,
                    desired,
                    state=state,
                    deadline=activation_deadline,
                )
            if not _ready(state, desired):
                raise InspectionControlError(
                    "Inspection engine readiness is unverified"
                )
            if desired.mode == "block":
                state = self._mutate(
                    self._control.install_hook,
                    self._approval.owner,
                    self._approval.plan,
                    state.engine,
                    state=state,
                    deadline=activation_deadline,
                )
            if not _verified(state, desired):
                raise InspectionControlError("Inspection activation is unverified")
        except (InspectionControlError, OSError):
            cleanup = self._cleanup_activation(desired, boot_id, deadline)
            return InspectionStatus(
                "unavailable",
                "Inspection activation failed"
                if cleanup
                else "Inspection activation failed and cleanup is unverified",
            )
        return InspectionStatus(desired.mode)

    def _cleanup_activation(
        self, desired: EngineSpec, boot_id: str, deadline: float
    ) -> bool:
        try:
            state = self._read(deadline, boot_id)
            state = self._detach(state, deadline)
            if state.engine is not None and state.engine.spec == desired:
                state = self._stop(state, deadline)
            return _verified(state, None)
        except (InspectionControlError, OSError):
            return False
