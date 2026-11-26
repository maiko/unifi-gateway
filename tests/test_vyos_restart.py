from ipaddress import IPv4Network
import json
import time

import pytest

from backends.vyos import VyOSReadError, VyOSWriteError
from gateway_profiles import vyos_restart
from gateway_profiles.vyos_restart import VyOSRestart
from provisioners.vyos import VyOSReconciler
from provisioners.uxg_intent import FirewallIntent


OLD_BOOT = "bb69c2fb-eaac-4d77-8492-6bbaa71579a5"
NEW_BOOT = "f6ef55b6-4656-4fd9-9032-e093e3d7890f"


def test_commit_proof_requires_the_exact_reply_for_each_mode(monkeypatch):
    fingerprint = "a" * 64
    replies = iter((f"uxg-commit-staged {fingerprint}\n".encode(), f"{OLD_BOOT}\n".encode(), f"{OLD_BOOT}\n".encode()))
    commands = []

    def run(argv, *, reader, limit):
        commands.append(argv[-1])
        return next(replies), 0

    monkeypatch.setattr(vyos_restart, "_run_helper", run)
    argv = ["/usr/bin/ssh", "/bin/false"]
    assert vyos_restart._read_commit_fingerprint(argv, phase="staged") == fingerprint
    with pytest.raises(VyOSReadError, match="completed configuration"):
        vyos_restart._read_commit_fingerprint(argv, phase="completed")
    assert vyos_restart._read_commit_fingerprint(argv, phase="saved") == OLD_BOOT
    assert commands == ["/bin/false uxg-commit-snapshot", "/bin/false uxg-commit-proof", "/bin/false"]


def test_saved_commit_proof_returns_the_bound_boot_and_fingerprint(monkeypatch):
    fingerprint = "a" * 64
    replies = iter((f"uxg-commit-saved {OLD_BOOT} {fingerprint}\n".encode(),
                    f"uxg-commit-completed {fingerprint}\n".encode()))

    def run(argv, *, reader, limit, timeout=None):
        assert argv[-1] == "/bin/false uxg-commit-saved" and limit == 128
        assert timeout is not None and timeout >= 7
        return next(replies), 0

    monkeypatch.setattr(vyos_restart, "_run_helper", run)
    argv = ["/usr/bin/ssh", "/bin/false"]
    assert vyos_restart._read_commit_fingerprint(argv, phase="saved_commit") == (OLD_BOOT, fingerprint)
    with pytest.raises(VyOSReadError, match="saved commit"):
        vyos_restart._read_commit_fingerprint(argv, phase="saved_commit")


def test_reboot_timer_proof_rejects_an_ordinary_staged_reply(monkeypatch):
    fingerprint = "a" * 64
    replies = iter(("staged", "staged_reboot"))

    def run(argv, *, reader, limit):
        assert argv[-1] == "/bin/false uxg-commit-snapshot-reboot" and limit == 128
        return f"uxg-commit-{next(replies)} {fingerprint}\n".encode(), 0

    monkeypatch.setattr(vyos_restart, "_run_helper", run)
    argv = ["/usr/bin/ssh", "/bin/false"]
    with pytest.raises(VyOSReadError, match="staged"):
        vyos_restart._read_commit_fingerprint(argv, phase="staged_reboot")
    assert vyos_restart._read_commit_fingerprint(argv, phase="staged_reboot") == fingerprint


class Router:
    def __init__(self, path):
        self.path = path
        self.reconciler = VyOSReconciler(
            self, state_path=path, rule_base=80200,
            interfaces={IPv4Network("192.0.2.0/25"): "eth1", IPv4Network("192.0.2.128/25"): "eth2"},
        )
        self.boot = OLD_BOOT
        self.tree = {"system": {"host-name": "lab"}}
        self.reboot_calls = 0
        self.forwarding = True
        self.timeout = False

    def read_complete_configuration(self):
        return self.tree

    def read_boot(self):
        return self.boot

    def verify_forwarding(self):
        if not self.forwarding:
            raise VyOSReadError("Forwarding probe unavailable")

    def reboot(self):
        with pytest.raises(BlockingIOError):
            with self.reconciler.locked_state():
                pytest.fail("Released the provisioning lock before submitting reboot")
        assert json.loads(self.path.read_text())["restart"]["boot_id"] == OLD_BOOT
        self.reboot_calls += 1
        if self.timeout:
            raise VyOSWriteError("Connection dropped during reboot")


def coordinator(router):
    return VyOSRestart(router.reconciler, preflight=router.read_boot, verify_forwarding=router.verify_forwarding)


def test_restart_timeout_and_daemon_restart_keep_the_same_request_fenced(tmp_path):
    router = Router(tmp_path / "journal.json")
    router.timeout = True
    original = coordinator(router)
    assert original.ready_for_inform()
    requested = time.time_ns() // 1_000_000
    with pytest.raises(VyOSWriteError):
        original.request(str(requested))

    restored = coordinator(router)
    restored.request(str(requested))
    assert router.reboot_calls == 1
    result = router.reconciler.reconcile(FirewallIntent("during-restart", ()))
    assert result.error == "VyOS restart recovery is pending"
    assert not restored.ready_for_inform()
    router.boot = NEW_BOOT
    router.forwarding = False
    assert not restored.ready_for_inform()
    router.forwarding = True
    router.tree = {"system": {"host-name": "unexpected"}}
    assert not restored.ready_for_inform()
    router.tree = {"system": {"host-name": "lab"}}
    assert restored.ready_for_inform()
    restored.accept_response("reboot", str(requested))
    restored.request(str(requested))
    restored.accept_response("urlerror", None)
    assert router.reboot_calls == 1
    assert "restart" in json.loads(router.path.read_text())
    with pytest.raises(ValueError, match="stale"):
        restored.accept_response("noop", str(requested))
    restored.accept_response("noop", str(requested + 1))
    assert "restart" not in json.loads(router.path.read_text())
    with pytest.raises(ValueError, match="stale"):
        coordinator(router).request(str(requested))
    assert router.reboot_calls == 1


def test_pending_provisioning_and_unverified_forwarding_refuse_to_request_a_reboot(tmp_path):
    router = Router(tmp_path / "journal.json")
    with router.reconciler.locked_state() as state:
        state["pending"] = {"revision": "a"}
        router.reconciler._write_state(state)
    original = router.path.read_bytes()
    restart = coordinator(router)
    requested = str(time.time_ns() // 1_000_000)
    with pytest.raises(ValueError, match="pending provisioning"):
        restart.request(requested)
    assert router.reboot_calls == 0
    assert router.path.read_bytes() == original

    with router.reconciler.locked_state() as state:
        state["pending"] = None
        router.reconciler._write_state(state)
    original = router.path.read_bytes()
    router.forwarding = False
    with pytest.raises(VyOSReadError, match="Forwarding probe"):
        restart.request(requested)
    assert router.reboot_calls == 0
    assert router.path.read_bytes() == original
