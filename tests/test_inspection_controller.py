"""Check the controller's scope and fixed command verification for inspection."""

import json
from pathlib import Path
from subprocess import CompletedProcess
import sys
from threading import Event, Thread
from types import SimpleNamespace

import pytest

from inspection import controller
from inspection.suricata import decode_inspection_intent


QUEUE_SCOPE = {
    "queue": 41110,
    "server_port": 18743,
    "initiator": {"interface": "eth3.110", "host": "192.168.110.2"},
    "responder": {"interface": "eth3.120", "host": "192.168.120.2"},
}


def test_stock_ssh_uses_the_pinned_management_endpoint_and_fixed_argv(monkeypatch):
    argv = ["/usr/bin/ssh", "-o", "BatchMode=yes", "vyos@192.0.2.1", "/bin/false"]
    options = {"ssh_host": "192.0.2.1", "ssh_port": "2222", "ssh_user": "vyos",
               "ssh_key_file": "/private/key", "ssh_known_hosts_file": "/private/pins",
               "networks": '["br110", "br120"]', "vendor_controls_sha256": "a" * 64}

    def command(*args):
        assert args == ("192.0.2.1", 2222, "vyos", "/private/key", "/private/pins")
        return argv

    monkeypatch.setitem(sys.modules, "backends.vyos_ssh",
                        SimpleNamespace(vyos_ssh_command=command))
    scoped = controller.InspectionController.from_config(options, management_host="192.0.2.1",
                                                         stock_queue_scope=QUEUE_SCOPE)

    def run(actual, **kwargs):
        assert actual == argv
        assert kwargs["check"] is False and kwargs["timeout"] == 45 and kwargs["capture_output"] is True
        payload = json.loads(kwargs["input"])
        assert payload["phase"] == "verify-engine" and payload["queue_scope"] == QUEUE_SCOPE
        return CompletedProcess(actual, 0, b'{"schema":1,"requested_mode":"off","mode":"off",'
                                            b'"reason":null,"phase":"verify-engine"}')

    monkeypatch.setattr(controller.subprocess, "run", run)
    scoped.verify_engine(controller.InspectionIntent("off", ()))

    with pytest.raises(ValueError, match="management host"):
        controller.InspectionController.from_config(options, management_host="192.0.2.2",
                                                    stock_queue_scope=QUEUE_SCOPE)
    with pytest.raises(ValueError, match="one inspection transport"):
        controller.InspectionController.from_config({**options, "command": "/bin/false"},
                                                    management_host="192.0.2.1", stock_queue_scope=QUEUE_SCOPE)
    with pytest.raises(ValueError, match="stock"):
        controller.InspectionController.from_config(options, management_host="192.0.2.1")


def test_event_poll_and_engine_verification_do_not_contend_for_router_lock(scoped_launcher, monkeypatch):
    control, _ = scoped_launcher
    reading, cleanup, verifying, requested = Event(), Event(), Event(), Event()
    failures = []

    def run(argv, *, input, **kwargs):
        request = json.loads(input)
        if request["phase"] == "read-events":
            reading.set()
            assert cleanup.wait(2)
            return CompletedProcess(argv, 0, b'{"schema":1,"phase":"read-events","status":"idle",'
                                              b'"generation":null,"offset":0,"record":null}')
        verifying.set()
        return CompletedProcess(argv, 0, b'{"schema":1,"phase":"verify-engine","requested_mode":"off",'
                                          b'"mode":"off","reason":null}')

    def read():
        try:
            control.read_events(None)
        except Exception as error:
            failures.append(error)

    def verify():
        requested.set()
        try:
            control.verify_engine(controller.InspectionIntent("off", ()))
        except Exception as error:
            failures.append(error)

    monkeypatch.setattr(controller.subprocess, "run", run)
    poller, verifier = Thread(target=read), Thread(target=verify)
    poller.start()
    try:
        assert reading.wait(2)
        verifier.start()
        assert requested.wait(2)
        assert not verifying.wait(0.15)
    finally:
        cleanup.set()
        poller.join(2)
        if verifier.ident is not None:
            verifier.join(2)
    assert verifying.is_set() and not failures


@pytest.fixture
def scoped_launcher(tmp_path):
    snapshots = json.loads((Path(__file__).parent / "fixtures/uxg_pro/ids-native-snapshots.json").read_text())
    for mode in ("notify", "block"):
        document = json.loads(snapshots[mode])
        services = document["udapi"]["services"]
        ids = services["idsIps"]
        services["utm"] = {"enabled": True, "eventType": "alert", "optIn": True,
                           "deviceID": ids["deviceID"], "token": ids["token"]}
        snapshots[mode] = json.dumps(document)
    command = tmp_path / "inspection-command"
    command.touch(mode=0o700)
    pin = decode_inspection_intent(snapshots["notify"]).vendor_controls_sha256
    scoped = controller.InspectionController(command, networks=("br110", "br120"), vendor_controls_sha256=pin,
                                             stock_queue_scope=QUEUE_SCOPE)
    return scoped, snapshots


def test_normalizes_the_approved_scope_and_preserves_exclusions_from_other_features(scoped_launcher):
    control, snapshots = scoped_launcher
    document = json.loads(snapshots["notify"])
    document["udapi"]["services"]["unrelated"] = {"enabled": True}
    raw, intent = control.normalize(json.dumps(document))
    observed = json.loads(raw)["udapi"]
    off = json.loads(snapshots["off"])["udapi"]["services"]["idsIps"]
    assert observed["services"] == {"unrelated": {"enabled": True}, "idsIps": off}
    assert "services/idsIps" not in observed["versionDetail"]
    assert intent.mode == "notify" and intent.networks == ("br110", "br120")

    document["udapi"]["services"]["idsIps"]["interfaces"].append("br0")
    document["udapi"]["interfaces"].append({"identification": {"id": "br0", "type": "bridge"},
                                             "status": {"enabled": True}})
    with pytest.raises(ValueError, match="approved"):
        control.normalize(json.dumps(document))


def test_rejects_unknown_companion_settings(scoped_launcher):
    control, snapshots = scoped_launcher
    document = json.loads(snapshots["block"])
    document["udapi"]["services"]["utm"]["token"] = "different"
    with pytest.raises(ValueError, match="companion"):
        control.normalize(json.dumps(document))


@pytest.mark.parametrize("returncode,reported", [(0, "block"), (0, "notify"), (1, "unavailable")])
def test_only_a_matching_live_command_result_verifies_mode(scoped_launcher, monkeypatch, returncode, reported):
    control, snapshots = scoped_launcher
    _, intent = control.normalize(snapshots["block"])

    def run(args, *, input, capture_output, timeout, check):
        assert args == [str(control.command)]
        assert json.loads(input) == {
            "mode": "block", "networks": ["br110", "br120"],
            "vendor_controls_sha256": intent.vendor_controls_sha256,
        }
        assert capture_output and timeout > 0 and check is False
        result = {"schema": 1, "requested_mode": "block", "mode": reported, "reason": None}
        return CompletedProcess(args, returncode, json.dumps(result).encode(), b"")

    monkeypatch.setattr(controller.subprocess, "run", run)
    if reported == "block":
        control.apply(intent)
    else:
        with pytest.raises(controller.InspectionControlError, match="verify"):
            control.apply(intent)


@pytest.mark.parametrize(("method", "phase", "mode"), [
    ("prepare_engine", "prepare-engine", "block"),
    ("verify_engine", "verify-engine", "block"),
    ("apply_engine", "apply-engine", "off"),
])
def test_engine_phases_require_an_exact_phase_ack(scoped_launcher, monkeypatch, method, phase, mode):
    control, snapshots = scoped_launcher
    _, intent = control.normalize(snapshots[mode])
    reply_phase = phase

    def run(args, *, input, capture_output, timeout, check):
        assert args == [str(control.command)]
        assert json.loads(input) == {
            "phase": phase, "mode": mode, "networks": list(intent.networks),
            "vendor_controls_sha256": intent.vendor_controls_sha256, "queue_scope": QUEUE_SCOPE,
        }
        assert capture_output and timeout > 0 and check is False
        result = {"schema": 1, "phase": reply_phase, "requested_mode": mode, "mode": mode, "reason": None}
        return CompletedProcess(args, 0, json.dumps(result).encode(), b"")

    monkeypatch.setattr(controller.subprocess, "run", run)
    getattr(control, method)(intent)

    reply_phase = "legacy"
    with pytest.raises(controller.InspectionControlError, match="verify"):
        getattr(control, method)(intent)


def test_read_events_pins_source_and_cursor(scoped_launcher, monkeypatch):
    control, _ = scoped_launcher
    cursor = {"generation": "a" * 32, "offset": 250}
    response = {"schema": 1, "phase": "read-events", "status": "idle",
                "generation": "a" * 32, "offset": 301, "record": None}

    def run(args, *, input, capture_output, timeout, check):
        assert args == [str(control.command)]
        assert json.loads(input) == {"phase": "read-events", "queue_scope": QUEUE_SCOPE, "cursor": cursor}
        assert capture_output and 0 < timeout <= 15 and check is False
        return CompletedProcess(args, 0, json.dumps(response).encode(), b"")

    monkeypatch.setattr(controller.subprocess, "run", run)
    assert control.read_events(cursor) == response
    response["phase"] = "verify-engine"
    with pytest.raises(controller.InspectionControlError, match="event feed"):
        control.read_events(cursor)


def test_event_feed_is_only_available_in_stock_scope(scoped_launcher, monkeypatch):
    control, _ = scoped_launcher
    legacy = controller.InspectionController(control.command, networks=control.networks,
                                             vendor_controls_sha256=control.vendor_controls_sha256)
    monkeypatch.setattr(controller.subprocess, "run", lambda *args, **kwargs: pytest.fail("Legacy runner was called"))
    with pytest.raises(controller.InspectionControlError, match="queue scope"):
        legacy.read_events(None)


@pytest.mark.parametrize(("status", "verdict", "proof", "valid"), [
    ("records", "alert", True, True),
    ("records", "alert", "true", False),
    ("records", "drop", True, False),
    ("idle", None, True, False),
])
def test_event_feed_accepts_only_literal_proof_for_passive_alerts(scoped_launcher, monkeypatch, status, verdict, proof,
                                                                  valid):
    control, _ = scoped_launcher
    record = {"event_type": "alert", "verdict": {"action": verdict}, "alert": {"action": "allowed"}}
    response = {"schema": 1, "phase": "read-events", "status": status, "generation": "a" * 32, "offset": 301,
                "record": record if verdict else None, "forwarding_observed": proof}

    def run(args, *, input, capture_output, timeout, check):
        assert args == [str(control.command)]
        assert json.loads(input) == {"phase": "read-events", "queue_scope": QUEUE_SCOPE, "cursor": None}
        assert capture_output and 0 < timeout <= 15 and check is False
        return CompletedProcess(args, 0, json.dumps(response).encode(), b"")

    monkeypatch.setattr(controller.subprocess, "run", run)
    if valid:
        assert control.read_events(None) == response
    else:
        with pytest.raises(controller.InspectionControlError, match="event feed"):
            control.read_events(None)


def test_event_feed_rejects_duplicate_forwarding_proof(scoped_launcher, monkeypatch):
    control, _ = scoped_launcher
    raw = (b'{"schema":1,"phase":"read-events","status":"records","generation":null,"offset":0,'
           b'"record":{"event_type":"alert","verdict":{"action":"alert"},"alert":{"action":"allowed"}},'
           b'"forwarding_observed":false,"forwarding_observed":true}')
    monkeypatch.setattr(controller.subprocess, "run", lambda args, **_: CompletedProcess(args, 0, raw, b""))

    with pytest.raises(controller.InspectionControlError, match="event feed"):
        control.read_events(None)
