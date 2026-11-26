import json
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from inspection.notify_capture import NotifyCapture, TcpObservation
from inspection.supervisor import InspectionControlError
from inspection.vyos_eve_feed import EveGeneration
from inspection.vyos_queue import EngineIdentity
from inspection.vyos_readback import KernelIdentity


BOOT = "a263fe32-0e42-4b9d-9852-cacab4122303"
GENERATION = "a91af55d6ff14861b6fcb40bb112abfd"
KERNEL = KernelIdentity(BOOT, 4026531840)
ENGINE = EngineIdentity(245, 625)
OBSERVER = EngineIdentity(311, 727)
ALERT = 1_764_002_381_094_495_000


class Files:
    def __init__(self, root):
        self.root = root
        self.root.mkdir(mode=0o700)

    def read(self, name, limit):
        path = self.root / name
        if not path.exists():
            return None
        data = path.read_bytes()
        if len(data) > limit:
            raise InspectionControlError("test read limit")
        return data

    def write(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        path.chmod(0o600)


@pytest.fixture
def local(tmp_path, monkeypatch):
    from inspection import notify_runtime

    monkeypatch.setattr(notify_runtime, "_current_kernel", lambda: KERNEL)
    monkeypatch.setattr(notify_runtime, "_assert_active", lambda _snapshot: None)
    return notify_runtime, Files(tmp_path / "router")


@pytest.fixture
def observed():
    def packet(when, *, seq, flags, length, ip_id):
        return TcpObservation(when, "eth3.110", "ingress", "192.168.110.2", "192.168.120.2", 41222,
                              18743, seq, 0 if flags == 2 else 21, flags, length, ip_id, 64)

    def forwarded(row):
        return replace(row, timestamp_ns=row.timestamp_ns + 2_000, interface="eth3.120", direction="egress", ttl=63)

    syn = packet(ALERT - 10_000, seq=15, flags=2, length=0, ip_id=31)
    alert = packet(ALERT + 150, seq=16, flags=24, length=18, ip_id=32)
    timestamp = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ALERT // 1000)
    event = {"event_type": "alert", "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
             "proto": "TCP", "direction": "to_server", "pkt_src": "wire/pcap", "in_iface": "eth3.110",
             "src_ip": "192.168.110.2", "dest_ip": "192.168.120.2", "src_port": 41222, "dest_port": 18743,
             "flow_id": 111123, "verdict": {"action": "alert"},
             "alert": {"gid": 1, "rev": 1, "signature_id": 1000043, "action": "allowed"}}
    capture = NotifyCapture(BOOT, GENERATION, ALERT - 20_000, ALERT + 2_000_000_000, 0,
                            (syn, forwarded(syn), alert, forwarded(alert)), True)
    return event, capture


def saved_snapshot(local, capture, *, state="active", updated=None):
    module, files = local
    if updated is None:
        updated = module.time.monotonic_ns()
    module._write_snapshot(files, module._Snapshot(KERNEL, ENGINE, OBSERVER, updated, state, capture))


@pytest.mark.parametrize(("state", "sealed", "coverage", "expected"), [
    ("active", False, 2_000_000_000, True),
    ("active", False, 5_000, None),
    ("sealed", True, 5_000, True),
    ("sealed", True, 1_000, False),
    ("active", True, 2_000_000_000, False),
    ("failed", False, 2_000_000_000, False),
])
def test_proof_is_bound_to_capture_completion_and_sealed_generation(local, observed, state, sealed, coverage, expected):
    module, files = local
    event, capture = observed
    if coverage == 1_000:
        capture = replace(capture, observations=capture.observations[:-1])
    saved_snapshot(local, replace(capture, end_ns=ALERT + coverage), state=state)
    generation = EveGeneration(GENERATION, "notify", 1, 2, 0, 50 if sealed else None)

    assert module.prove_forwarding(files, generation, event, boot_id=BOOT) is expected


def test_missing_untrusted_or_stale_capture_fails_closed(local, observed):
    module, files = local
    event, capture = observed
    generation = EveGeneration(GENERATION, "notify", 1, 2, 0)
    assert module.prove_forwarding(files, generation, event, boot_id=BOOT) is False
    saved_snapshot(local, capture, updated=1)
    assert module.prove_forwarding(files, generation, event, boot_id=BOOT) is False
    saved_snapshot(local, capture)
    assert module.prove_forwarding(files, generation, event, boot_id="b" * 36) is False
    assert module.prove_forwarding(files, replace(generation, id="c" * 32), event, boot_id=BOOT) is False
    assert module.prove_forwarding(files, replace(generation, mode="block"), event, boot_id=BOOT) is False
    path, = files.root.iterdir()
    data = json.loads(path.read_bytes())
    data["capture"]["observations"][0]["payload"] = "untrusted"
    path.write_text(json.dumps(data))
    assert module.prove_forwarding(files, generation, event, boot_id=BOOT) is False


def test_start_waits_for_its_exact_child_and_never_inherits_stdio_or_locks(local, observed, monkeypatch):
    module, files = local
    _, capture = observed

    @contextmanager
    def lifetime(kernel, identity, *, is_engine):
        assert (kernel, identity, is_engine) in {(KERNEL, ENGINE, True), (KERNEL, OBSERVER, False)}
        yield 27

    monkeypatch.setattr(module, "_lifetime", lifetime)
    monkeypatch.setattr(module, "_has_exited", lambda *_: False)
    monkeypatch.setattr(module, "_trusted_code_root", lambda: Path("/opt/inspection.pyz"))
    monkeypatch.setattr(module, "_require_linux_root", lambda: None)

    def spawn(args, **options):
        assert args[1:3] == ["-I", "-c"]
        assert args[4] == "/opt/inspection.pyz"
        assert options["close_fds"] is True and options["start_new_session"] is True
        assert all(options[key] == module.subprocess.DEVNULL for key in ("stdin", "stdout", "stderr"))
        saved_snapshot(local, capture)
        return SimpleNamespace(pid=OBSERVER.pid, poll=lambda: None)

    monkeypatch.setattr(module.subprocess, "Popen", spawn)
    module.start_observer(files, GENERATION, KERNEL, ENGINE, module.time.monotonic() + 1)
    with pytest.raises(InspectionControlError, match="already"):
        module.start_observer(files, GENERATION, KERNEL, ENGINE, module.time.monotonic() + 1)


@pytest.mark.parametrize("healthy", [True, False])
def test_observer_publishes_only_bounded_metadata_and_seals_on_engine_exit(local, observed, monkeypatch, healthy):
    module, files = local
    _, capture = observed
    capture = replace(capture, complete=healthy, dropped=0 if healthy else 1)
    writes = []
    write = files.write

    def capture_write(name, data):
        writes.append(json.loads(data.decode("ascii")))
        write(name, data)

    @contextmanager
    def lifetime(kernel, identity, *, is_engine):
        assert (kernel, identity, is_engine) == (KERNEL, ENGINE, True)
        yield 19

    @contextmanager
    def capture_source(*, capture_id):
        assert capture_id == GENERATION
        yield SimpleNamespace(snapshot=lambda: capture)

    monkeypatch.setattr(files, "write", capture_write)
    monkeypatch.setattr(module, "_lifetime", lifetime)
    monkeypatch.setattr(module, "_has_exited", lambda _, timeout=0: timeout == module._SAMPLE_INTERVAL)
    monkeypatch.setattr(module, "open_notify_capture", capture_source)
    monkeypatch.setattr(module, "LinuxInspectionReader", lambda: SimpleNamespace(_process_identity=lambda _: OBSERVER))

    assert module._observe(files, GENERATION, KERNEL, ENGINE, module.time.monotonic() + 1) == int(not healthy)
    assert [value["state"] for value in writes] == (["active", "sealed"] if healthy else ["failed"])
    assert all("payload" not in row and "packet" not in row for row in writes[-1]["capture"]["observations"])


def test_pruning_retains_bounded_generation_files_and_leaves_other_state(local):
    module, files = local
    files.write("ownership.json", b"previous")
    for value in range(module.MAX_GENERATIONS + 2):
        name = module._name(f"{value:032x}")
        files.write(name, b"complete")
    current = module._name(GENERATION)
    files.write(current, b"current")

    module._prune_history(files, current)

    assert len(list(files.root.glob("notify-*.json"))) == module.MAX_GENERATIONS
    assert (files.root / current).read_bytes() == b"current"
    assert (files.root / "ownership.json").read_bytes() == b"previous"
