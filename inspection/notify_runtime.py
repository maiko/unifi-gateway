"""Run and read the private, generation-bound passive forwarding observer."""

import json
import math
import os
import re
import select
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from inspection.eve_source import _invalid_constant, _unique_fields
from inspection.notify_capture import (
    APPROVED_NOTIFY_SCOPE,
    MAX_OBSERVATIONS,
    NotifyCapture,
    TcpObservation,
    open_notify_capture,
)
from inspection.notify_observation import (
    _MAX_TRANSIT_NS,
    _alert_time_ns,
    _scope_alert,
    _valid_packet,
    forwarding_observed,
)
from inspection.supervisor import InspectionControlError
from inspection.vyos_eve_feed import MAX_GENERATIONS, EveGeneration
from inspection.vyos_queue import EngineIdentity
from inspection.vyos_readback import EngineClaim, KernelIdentity, LinuxInspectionReader


_GENERATION = re.compile(r"[0-9a-f]{32}", re.ASCII)
_BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.ASCII)
_FILENAME = re.compile(r"notify-[0-9a-f]{32}\.json", re.ASCII)
_MAX_BYTES = 2 * 1024 * 1024
_MAX_TIME = (1 << 63) - 1
_ACTIVE_AGE_NS = 2_000_000_000
_RETAINED_AGE_NS = 3_600_000_000_000
_SAMPLE_INTERVAL = 0.25
_START_SETTLE = 0.075
_BOOTSTRAP = (
    "import sys; sys.path.insert(0, sys.argv[1]); "
    "from inspection.notify_runtime import _child; "
    "raise SystemExit(_child(sys.argv[2:]))"
)


@dataclass(frozen=True, slots=True)
class _Snapshot:
    kernel: KernelIdentity
    engine: EngineIdentity
    observer: EngineIdentity
    updated_ns: int
    state: str
    capture: NotifyCapture


def _positive(value, upper=_MAX_TIME):
    return type(value) is int and 0 < value <= upper


def _name(generation_id):
    if type(generation_id) is not str or _GENERATION.fullmatch(generation_id) is None:
        raise ValueError("Invalid Notify observer generation")
    return f"notify-{generation_id}.json"


def _validate_identity(kernel, engine):
    if (type(kernel) is not KernelIdentity or type(kernel.boot_id) is not str
            or _BOOT.fullmatch(kernel.boot_id) is None or not _positive(kernel.namespace_inode)
            or type(engine) is not EngineIdentity or not _positive(engine.pid, (1 << 31) - 1)
            or not _positive(engine.start_ticks)):
        raise ValueError("Invalid Notify observer process or boot identity")


def _validate_capture(capture, kernel, generation_id):
    if (type(capture) is not NotifyCapture or capture.boot_id != kernel.boot_id or capture.capture_id != generation_id
            or not _positive(capture.start_ns) or not _positive(capture.end_ns) or capture.start_ns > capture.end_ns
            or type(capture.complete) is not bool or type(capture.dropped) is not int or capture.dropped < 0
            or type(capture.observations) is not tuple or len(capture.observations) > MAX_OBSERVATIONS):
        raise ValueError("Invalid Notify capture snapshot")
    previous_ns = capture.start_ns
    for packet in capture.observations:
        if not _valid_packet(packet, APPROVED_NOTIFY_SCOPE) or not previous_ns <= packet.timestamp_ns <= capture.end_ns:
            raise ValueError("Invalid Notify capture packet metadata")
        previous_ns = packet.timestamp_ns


def _write_snapshot(files, snapshot):
    return files.write(_name(snapshot.capture.capture_id), json.dumps(
        {"schema": 1, **asdict(snapshot)}, ensure_ascii=True, separators=(",", ":"), allow_nan=False,
    ).encode("ascii"))


def _read_snapshot(files, generation_id):
    raw = files.read(_name(generation_id), _MAX_BYTES)
    if raw is None:
        return None
    if type(raw) is not bytes or len(raw) > _MAX_BYTES:
        raise ValueError("Invalid Notify capture size")
    doc = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    if (type(doc) is not dict or doc.keys() != {"schema", "kernel", "engine", "observer", "updated_ns", "state", "capture"}
            or type(doc["schema"]) is not int or doc["schema"] != 1
            or doc["state"] not in ("active", "sealed", "failed") or not _positive(doc["updated_ns"])):
        raise ValueError("Invalid Notify capture envelope")
    kernel, engine, observer = KernelIdentity(**doc["kernel"]), EngineIdentity(**doc["engine"]), EngineIdentity(**doc["observer"])
    _validate_identity(kernel, engine)
    _validate_identity(kernel, observer)
    if observer.pid == engine.pid:
        raise ValueError("Notify observer and engine identities must differ")
    capture = doc["capture"]
    if (type(capture) is not dict or type(capture.get("observations")) is not list
            or len(capture["observations"]) > MAX_OBSERVATIONS):
        raise ValueError("Invalid Notify capture rows")
    capture["observations"] = tuple(TcpObservation(**packet) for packet in capture["observations"])
    decoded = NotifyCapture(**capture)
    _validate_capture(decoded, kernel, generation_id)
    return _Snapshot(kernel, engine, observer, doc["updated_ns"], doc["state"], decoded)


def _require_linux_root():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise InspectionControlError("The Notify observer requires the local Linux router runtime")


def _private_files(root):
    from inspection.vyos_control import _PrivateFiles

    return _PrivateFiles(root)


def _current_kernel():
    return LinuxInspectionReader()._kernel_identity()


def _has_exited(fd, timeout=0):
    return bool(select.select([fd], [], [], timeout)[0])


@contextmanager
def _lifetime(kernel, identity, *, is_engine):
    """Hold a read-only process handle and reject PID reuse or a foreign namespace."""
    reader = LinuxInspectionReader()
    fd = os.pidfd_open(identity.pid)
    try:
        if _has_exited(fd) or _current_kernel() != kernel:
            raise InspectionControlError("Notify observer process lifetime changed")
        if is_engine:
            reader._check_process(EngineClaim(kernel, identity))
        else:
            proc = Path("/proc") / str(identity.pid)
            if (reader._process_identity(identity.pid) != identity
                    or (proc / "ns/net").stat().st_ino != kernel.namespace_inode
                    or (proc / "exe").readlink() != Path(sys.executable).resolve(strict=True)):
                raise InspectionControlError("Notify observer process identity changed")
        if _has_exited(fd):
            raise InspectionControlError("Notify observer process exited during verification")
        yield fd
    finally:
        os.close(fd)


def _assert_active(snapshot):
    with (_lifetime(snapshot.kernel, snapshot.engine, is_engine=True) as engine_fd,
          _lifetime(snapshot.kernel, snapshot.observer, is_engine=False) as observer_fd):
        if _has_exited(engine_fd) or _has_exited(observer_fd):
            raise InspectionControlError("Notify observer or engine is no longer active")


def _trusted_code_root():
    root = Path(__file__).parent.parent
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise InspectionControlError("Notify observer code path is not canonical")
    info = root.stat()
    if info.st_uid != 0 or info.st_mode & 0o022 or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise InspectionControlError("Notify observer code path is not root-controlled")
    for path in root.parents:
        info = path.stat()
        if info.st_uid != 0 or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
            raise InspectionControlError("Notify observer code parent is not root-controlled")
    return root


def _prune_history(files, current_name):
    entries = []
    with os.scandir(files.root) as children:
        for item in children:
            if _FILENAME.fullmatch(item.name) is None or item.name == current_name:
                continue
            info = item.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise InspectionControlError("Notify observer history contains an unowned file")
            entries.append((info.st_mtime_ns, item.name))
    for _, name in sorted(entries, reverse=True)[MAX_GENERATIONS - 1:]:
        (files.root / name).unlink()


def start_observer(files, generation_id, kernel, engine, deadline):
    """Start a detached observer and wait for a verified generation-ready snapshot."""
    try:
        _require_linux_root()
        _private_files(files.root)
        _validate_identity(kernel, engine)
        name = _name(generation_id)
        if files.read(name, _MAX_BYTES) is not None:
            raise InspectionControlError("A Notify observer already claimed this generation")
        now = time.monotonic()
        if type(deadline) not in (float, int) or not math.isfinite(deadline) or not 0 < deadline - now <= 60:
            raise ValueError("Notify observer startup needs a bounded deadline")
        # Reserve time for the caller to unwind its owned engine after a failed start.
        ready_by = now + min(3, (deadline - now) / 2)
        _prune_history(files, name)
        with _lifetime(kernel, engine, is_engine=True) as engine_fd:
            child = subprocess.Popen(
                [str(Path(sys.executable).resolve(strict=True)), "-I", "-c", _BOOTSTRAP,
                 str(_trusted_code_root()), str(files.root), generation_id, kernel.boot_id, str(kernel.namespace_inode),
                 str(engine.pid), str(engine.start_ticks), repr(ready_by)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                close_fds=True, start_new_session=True,
            )
            while time.monotonic() < ready_by:
                if child.poll() is not None or _has_exited(engine_fd):
                    raise InspectionControlError("Notify observer or engine exited before readiness")
                snapshot = _read_snapshot(files, generation_id)
                if snapshot is not None:
                    if ((snapshot.kernel, snapshot.engine, snapshot.observer.pid) != (kernel, engine, child.pid)
                            or snapshot.state != "active" or not snapshot.capture.complete or snapshot.capture.dropped):
                        raise InspectionControlError("Notify observer readiness differs from the launched capture")
                    with _lifetime(kernel, snapshot.observer, is_engine=False):
                        return
                time.sleep(min(0.025, max(0, ready_by - time.monotonic())))
            raise InspectionControlError("Notify observer did not report readiness before the deadline")
    except (OSError, TypeError, ValueError, AttributeError, RecursionError) as error:
        raise InspectionControlError("Notify observer startup could not be verified") from error


def _observe(files, generation_id, kernel, engine, ready_by):
    observer = LinuxInspectionReader()._process_identity(os.getpid())
    snapshot = None
    try:
        with (_lifetime(kernel, engine, is_engine=True) as fd,
              open_notify_capture(capture_id=generation_id) as capture):
            if _has_exited(fd, _START_SETTLE):
                return 1
            while not _has_exited(fd):
                report = capture.snapshot()
                _validate_capture(report, kernel, generation_id)
                if snapshot is None and time.monotonic() >= ready_by:
                    return 1
                if not report.complete or report.dropped:
                    _write_snapshot(files, _Snapshot(kernel, engine, observer, time.monotonic_ns(), "failed", report))
                    return 1
                if _has_exited(fd):
                    break
                snapshot = _Snapshot(kernel, engine, observer, time.monotonic_ns(), "active", report)
                _write_snapshot(files, snapshot)
                if _has_exited(fd, _SAMPLE_INTERVAL):
                    break
    except (InspectionControlError, OSError, RuntimeError, TypeError, ValueError):
        if snapshot is not None:
            _write_snapshot(files, replace(snapshot, state="failed"))
        raise
    if snapshot is None:
        return 1
    _write_snapshot(files, replace(snapshot, state="sealed"))
    return 0


def _child(args):
    try:
        _require_linux_root()
        root, generation_id, boot_id, namespace, pid, ticks, expiry = args
        files = _private_files(Path(root))
        kernel = KernelIdentity(boot_id, int(namespace))
        engine = EngineIdentity(int(pid), int(ticks))
        _validate_identity(kernel, engine)
        _name(generation_id)
        ready_by = float(expiry)
        if not math.isfinite(ready_by) or not 0 < ready_by - time.monotonic() <= 3:
            return 1
        return _observe(files, generation_id, kernel, engine, ready_by)
    except (InspectionControlError, OSError, RuntimeError, TypeError, ValueError, RecursionError):
        return 1


def prove_forwarding(files, generation, event, *, boot_id):
    """Return a forwarding proof, a pending active window, or a negative result."""
    if type(generation) is not EveGeneration or generation.mode != "notify" or not _scope_alert(event, APPROVED_NOTIFY_SCOPE):
        return False
    alert_ns = _alert_time_ns(event.get("timestamp"))
    if alert_ns is None:
        return False
    try:
        snapshot = _read_snapshot(files, generation.id)
        if snapshot is None or snapshot.kernel.boot_id != boot_id or snapshot.kernel != _current_kernel():
            return False
        state, capture = snapshot.state, snapshot.capture
        sealed = generation.end is not None
        age = time.monotonic_ns() - snapshot.updated_ns
        if (state != ("sealed" if sealed else "active") or not capture.complete or capture.dropped
                or not 0 <= age <= (_RETAINED_AGE_NS if sealed else _ACTIVE_AGE_NS) or alert_ns < capture.start_ns):
            return False
        if not sealed:
            _assert_active(snapshot)
            if capture.end_ns < alert_ns + 999 + _MAX_TRANSIT_NS:
                return None
        return forwarding_observed(event, scope=APPROVED_NOTIFY_SCOPE, capture=capture,
                                   boot_id=boot_id, capture_id=generation.id) is True
    except (InspectionControlError, OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return False
