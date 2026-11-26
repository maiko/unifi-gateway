import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from inspection.supervisor import InspectionStatus


VENDOR = "a" * 64
APPROVED_NETS = ["br110", "br120"]
QUEUE_SCOPE = {
    "queue": 41110,
    "server_port": 18743,
    "initiator": {"interface": "eth3.110", "host": "192.168.110.2"},
    "responder": {"interface": "eth3.120", "host": "192.168.120.2"},
}


@pytest.fixture
def api(monkeypatch):
    from inspection import vyos_command

    monkeypatch.setattr(vyos_command, "_require_linux_root", lambda: None)
    monkeypatch.setattr(socket, "gethostname", lambda: "branch-router")
    return vyos_command


@pytest.fixture
def harness(api, tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    cfg = tmp_path / "inspection.json"
    status = runtime / "status.json"
    config = {
        "router_hostname": "branch-router",
        "hook_owner": "unifi-inspection",
        "vendor_controls_sha256": VENDOR,
        "runtime_directory": str(runtime),
        "status_path": str(status),
    }
    cfg.write_text(json.dumps(config))
    cfg.chmod(0o600)
    observed = []
    transitions = []

    class FakeControl:
        def __init__(self, directory, *, approval, router_hostname, engine_only=False, observe_notify=False):
            assert directory == runtime
            assert approval.vendor_controls_sha256 == VENDOR
            assert router_hostname == socket.gethostname()
            self.engine_only = engine_only
            self.observe_notify = observe_notify

        def engine_phase(self, phase, intent):
            assert self.engine_only
            observed.append((phase, intent.mode))

    class FakeSupervisor:
        def __init__(self, control, *, approval):
            assert isinstance(control, FakeControl)
            assert approval.plan.scope.server_port == 18743

        def reconcile(self, intent):
            observed.append(intent)
            transitions.append(json.loads(status.read_text()))
            if intent.mode == "notify":
                return InspectionStatus(
                    "unavailable", "do not expose private engine diagnostics"
                )
            return InspectionStatus(intent.mode)

        def verify(self, intent):
            observed.append(("verify", intent.mode))
            return InspectionStatus("unavailable", "listener absent")

    monkeypatch.setattr(api, "LocalVyOSInspectionControl", FakeControl)
    monkeypatch.setattr(api, "InspectionSupervisor", FakeSupervisor)
    return cfg, status, config, observed, transitions


def payload(mode="block", *, networks=None, digest=VENDOR):
    return json.dumps(
        {
            "mode": mode,
            "networks": ([] if mode == "off" else APPROVED_NETS)
            if networks is None
            else networks,
            "vendor_controls_sha256": None if mode == "off" else digest,
        }
    ).encode()


@pytest.mark.parametrize("mode", ["off", "block"])
def test_verified_mode_is_sanitized_persisted_and_acknowledged(api, harness, mode):
    cfg, status, _, observed, transitions = harness
    code, response = api.submit(payload(mode), config_path=cfg)

    assert code == 0
    assert response == {
        "schema": 1,
        "requested_mode": mode,
        "mode": mode,
        "reason": None,
    }
    assert json.loads(status.read_text()) == response
    assert status.stat().st_mode & 0o777 == 0o600
    assert observed[0].mode == mode
    assert transitions == [
        {
            "schema": 1,
            "requested_mode": mode,
            "mode": "unavailable",
            "reason": "transition-in-progress",
        }
    ]


@pytest.mark.parametrize(("binding", "hostname", "accepted"), [
    ({"router_hostname": "branch-router"}, "branch-router", True),
    ({"router_hostname": "branch-router"}, "other-router", False),
    ({"router_hostname": None}, "branch-router", False),
    ({}, "other-router", False),
    ({}, "branch-router", False),
])
def test_engine_changes_require_the_enrolled_hostname(api, harness, monkeypatch, binding, hostname, accepted):
    cfg, status, config, observed, _ = harness
    config.pop("router_hostname")
    cfg.write_text(json.dumps({**config, **binding}))
    monkeypatch.setattr(socket, "gethostname", lambda: hostname)
    code, _ = api.submit(payload("off"), config_path=cfg)
    assert (code == 0) == accepted
    assert bool(observed) == accepted
    assert status.exists() == accepted


def test_unavailable_is_persisted_without_internal_diagnostics(api, harness):
    cfg, status, _, _, _ = harness
    code, response = api.submit(payload("notify"), config_path=cfg)
    assert code == 1
    assert response == {
        "schema": 1,
        "requested_mode": "notify",
        "mode": "unavailable",
        "reason": "inspection-unavailable",
    }
    assert json.loads(status.read_text()) == response


def test_health_request_is_read_only_and_persists_actual_result(api, harness):
    cfg, status, _, observed, transitions = harness
    code, response = api.submit(json.dumps({**json.loads(payload()), "verify_only": True}).encode(), config_path=cfg)
    assert code == 1 and response["reason"] == "inspection-unavailable"
    assert json.loads(status.read_text()) == response
    assert observed == [("verify", "block")]
    assert transitions == []


@pytest.mark.parametrize(("phase", "mode"), [
    ("prepare-engine", "block"), ("verify-engine", "block"), ("apply-engine", "notify"), ("apply-engine", "off"),
])
def test_stock_command_dispatches_only_an_engine_phase(api, harness, phase, mode):
    cfg, status, config, observed, transitions = harness
    cfg.write_text(json.dumps({**config, "engine_only": True}))
    raw = json.dumps({**json.loads(payload(mode)), "phase": phase, "queue_scope": QUEUE_SCOPE}).encode()

    code, response = api.submit(raw, config_path=cfg)

    assert code == 0
    assert response == {"schema": 1, "phase": phase, "requested_mode": mode, "mode": mode, "reason": None}
    assert json.loads(status.read_text()) == response
    assert observed == [(phase, mode)] and transitions == []


@pytest.mark.parametrize(("engine_only", "mode", "fields"), [
    (True, "block", {}),
    (True, "block", {"verify_only": True}),
    (False, "block", {"phase": "prepare-engine", "queue_scope": QUEUE_SCOPE}),
    (True, "block", {"phase": "prepare-engine", "queue_scope": QUEUE_SCOPE, "verify_only": False}),
    (True, "block", {"phase": "apply-engine", "queue_scope": QUEUE_SCOPE}),
    (True, "notify", {"phase": "prepare-engine", "queue_scope": QUEUE_SCOPE}),
    (True, "off", {"phase": None}),
    (True, "block", {"phase": "prepare-engine"}),
    (True, "block", {"phase": "prepare-engine", "queue_scope": {**QUEUE_SCOPE, "queue": 11}}),
    (True, "block", {"phase": "prepare-engine", "queue_scope": {**QUEUE_SCOPE, "server_port": 18743.0}}),
    (True, "block", {"phase": "prepare-engine", "queue_scope": {**QUEUE_SCOPE, "initiator": QUEUE_SCOPE["responder"]}}),
])
def test_command_rejects_wrong_transport_and_phase_without_dispatch(api, harness, engine_only, mode, fields):
    cfg, status, config, observed, _ = harness
    cfg.write_text(json.dumps({**config, "engine_only": engine_only}))
    raw = json.dumps({**json.loads(payload(mode)), **fields}).encode()

    code, response = api.submit(raw, config_path=cfg)

    assert code == 2 and response["reason"] == "invalid-request"
    assert observed == [] and not status.exists()


def test_private_runtime_is_recreated_after_boot(api, harness):
    cfg, status, _, _, _ = harness
    status.parent.rmdir()
    code, response = api.submit(payload("off"), config_path=cfg)
    assert code == 0 and response["mode"] == "off"
    assert json.loads(status.read_text()) == response
    assert status.parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize(
    "raw",
    [
        b'{"mode":"off","networks":[],"vendor_controls_sha256":null,"exec":"anything"}',
        b'{"mode":"off","mode":"block","networks":[],"vendor_controls_sha256":null}',
        b'{"mode":"off","networks":[],"vendor_controls_sha256":null,"status_path":"/tmp/a"}',
        b'{"mode":"off","networks":[],"vendor_controls_sha256":null,"verify_only":1}',
        b'{"mode":"off","networks":{},"vendor_controls_sha256":null}',
        b'{"mode":"off","networks":[],"vendor_controls_sha256":NaN}',
        b'{"mode":"off","networks":[]}',
        b"\xff",
        b"[]",
        b" " * 4097,
        payload("notify", networks=["br110"]),
        payload(digest="b" * 64),
        payload() + payload("off"),
    ],
)
def test_invalid_inputs_do_not_dispatch_or_change_status(api, harness, raw):
    cfg, status, _, observed, _ = harness
    status.write_text("previous result")
    code, response = api.submit(raw, config_path=cfg)

    assert code == 2
    assert response["mode"] == "unavailable"
    assert response["reason"] == "invalid-request"
    assert observed == []
    assert status.read_text() == "previous result"


def test_writable_config_cannot_authorize_a_transition(api, harness):
    cfg, status, _, observed, _ = harness
    cfg.chmod(0o666)
    code, response = api.submit(payload(), config_path=cfg)

    assert code == 1
    assert response["reason"] == "configuration-unavailable"
    assert observed == []
    assert not status.exists()


@pytest.mark.parametrize("path_type", ["symlink", "owner-record", "command-lock"])
def test_status_never_aliases_a_foreign_or_reserved_path(
    api, harness, tmp_path, path_type
):
    cfg, status, config, observed, _ = harness
    protected = tmp_path / "untouched"
    protected.write_text("old bytes")
    if path_type == "symlink":
        status.symlink_to(protected)
    else:
        config["status_path"] = str(
            status.parent
            / ("ownership.json" if path_type == "owner-record" else "command.lock")
        )
        cfg.write_text(json.dumps(config))
    code, response = api.submit(payload(), config_path=cfg)

    assert code == 1
    assert response["mode"] == "unavailable"
    assert observed == []
    assert protected.read_text() == "old bytes"


def test_gateway_cannot_override_trusted_config_path_through_arguments():
    result = subprocess.run(
        [sys.executable, "-m", "inspection.vyos_command", "--config", "/tmp/arbitrary"],
        input=payload("off"),
        capture_output=True,
        timeout=3,
        cwd=Path(__file__).parents[1],
    )
    assert result.returncode == 2
    assert json.loads(result.stdout)["reason"] == "invalid-request"
    assert result.stderr == b""


def test_stdin_with_no_eof_or_complete_request_times_out(api):
    reading, writing = os.pipe()
    try:
        os.write(writing, b'{"mode":')
        with os.fdopen(reading, "rb") as source, pytest.raises(ValueError):
            api._read_stdin(source, timeout=0.05)
    finally:
        os.close(writing)


def test_read_events_is_scoped_and_does_not_write_transition_status(api, harness, monkeypatch):
    cfg, status, config, _, _ = harness
    cfg.write_text(json.dumps({**config, "engine_only": True}))
    status.write_text("existing inspection status\n")
    status.chmod(0o600)
    (status.parent / "command.lock").touch(mode=0o600)
    observed = []
    response = {
        "schema": 1, "phase": "read-events", "status": "idle",
        "generation": "0" * 32, "offset": 17, "record": None,
    }

    def read_events(self, cursor):
        assert self.engine_only
        observed.append(cursor)
        return response

    monkeypatch.setattr(api.LocalVyOSInspectionControl, "read_events", read_events, raising=False)
    data = {"phase": "read-events", "queue_scope": QUEUE_SCOPE, "cursor": None}
    assert api.submit(json.dumps(data).encode(), config_path=cfg) == (0, response)
    assert observed == [None]
    assert status.read_text() == "existing inspection status\n"
    assert api.submit(json.dumps({**data, "path": "/proc/self/environ"}).encode(), config_path=cfg)[0] == 2
    assert api.submit(json.dumps({**data, "cursor": {"generation": "0"*32, "offset": True}}).encode(), config_path=cfg)[0] == 2


def test_event_feed_absent_runtime_is_idle_but_missing_config_is_error(api, harness):
    cfg, status, config, _, _ = harness
    absent = status.parent.parent / "new-runtime"
    cfg.write_text(json.dumps({**config, "runtime_directory": str(absent), "engine_only": True}))
    request = json.dumps({"phase": "read-events", "queue_scope": QUEUE_SCOPE, "cursor": None}).encode()
    assert api.submit(request, config_path=cfg)[1]["status"] == "idle"
    assert not absent.exists() and not status.exists()
    cfg.unlink()
    assert api.submit(request, config_path=cfg)[0] == 1


def test_inspection_rejects_a_foreign_hook_owner(api, harness):
    cfg, _, config, _, _ = harness
    cfg.write_text(json.dumps({**config, "hook_owner": "another-owner"}))
    with pytest.raises(ValueError, match="configuration fields"):
        api._configuration(cfg)
