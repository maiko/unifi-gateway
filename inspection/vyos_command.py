"""Restricted local command for the VyOS inspection supervisor.

Install the command code on a root-controlled import path and invoke Python
in isolated mode at the privilege boundary. Only stdin carries gateway data.
"""

import fcntl
import json
import os
import re
import selectors
import stat
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from inspection.supervisor import InspectionControlError, InspectionSupervisor
from inspection.suricata import InspectionIntent
from inspection.vyos_control import (
    ENGINE_PHASE_MODES,
    LocalVyOSInspectionControl,
    _PrivateFiles,
    _require_linux_root,
    reference_inspection_approval,
    stock_queue_scope_matches,
    verify_router_hostname,
)
from inspection.vyos_eve_feed import RESPONSE_LIMIT, feed_response, valid_cursor
from inspection.vyos_install import INSPECTION_OWNER
from inspection.vyos_readback import _unique_fields

_CONFIG_PATH = Path("/etc/unifi-gateway/inspection.json")
_STDIN_LIMIT = 4096
_STDIN_TIMEOUT = 3.0
_CONFIG_LIMIT = 16_384
_NETWORKS = frozenset({"br110", "br120"})
_RESERVED = frozenset(
    {
        "command.lock",
        "inspection.lock",
        "ownership.json",
        "engine.yaml",
        "marker.rules",
        "engine.log",
        "eve.json",
    }
)


@dataclass(frozen=True, slots=True)
class _Configuration:
    router_hostname: str
    approved_digest: str
    runtime_directory: Path
    status_path: Path
    engine_only: bool
    observe_notify: bool


class _Busy(RuntimeError):
    """A previous command still owns the status transition."""


def _reject_constant(_value):
    raise ValueError("Invalid JSON constant")


def _object(raw: bytes, limit: int) -> dict:
    if type(raw) is not bytes or not raw or len(raw) > limit:
        raise ValueError("Inspection input size is unsupported")
    result = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique_fields,
        parse_constant=_reject_constant,
    )
    if type(result) is not dict:
        raise ValueError("Inspection input requires a JSON object")
    return result


def _valid_digest(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _decode(raw: bytes) -> tuple[InspectionIntent | dict | None, bool, str | None]:
    request = _object(raw, _STDIN_LIMIT)
    if request.get("phase") == "read-events":
        if (
            request.keys() != {"phase", "queue_scope", "cursor"}
            or not stock_queue_scope_matches(request["queue_scope"])
            or not valid_cursor(request["cursor"])
        ):
            raise ValueError("Invalid inspection EVE request")
        return request["cursor"], True, "read-events"
    phase = None
    if "phase" in request:
        phase = request.pop("phase")
        if (
            type(phase) is not str or phase not in ENGINE_PHASE_MODES or "verify_only" in request
            or not stock_queue_scope_matches(request.pop("queue_scope", None))
        ):
            raise ValueError("Invalid stock inspection phase or queue scope")
        verify_only = phase == "verify-engine"
    else:
        verify_only = request.pop("verify_only", False)
    if type(verify_only) is not bool or request.keys() != {"mode", "networks", "vendor_controls_sha256"}:
        raise ValueError("Unexpected inspection request fields")
    mode, networks, digest = (
        request["mode"],
        request["networks"],
        request["vendor_controls_sha256"],
    )
    if phase is not None and mode not in ENGINE_PHASE_MODES[phase]:
        raise ValueError("Inspection mode is invalid for the requested engine phase")
    if mode == "off" and type(networks) is list and not networks and digest is None:
        return InspectionIntent("off", ()), verify_only, phase
    if (
        mode not in ("notify", "block")
        or type(networks) is not list
        or len(networks) != 2
        or any(type(value) is not str for value in networks)
        or set(networks) != _NETWORKS
        or not _valid_digest(digest)
    ):
        raise ValueError("Unsupported inspection request scope or digest")
    return InspectionIntent(mode, tuple(networks), digest), verify_only, phase


def _read_stdin(source, *, timeout: float = _STDIN_TIMEOUT) -> bytes:
    """Read one EOF-terminated request from the local gateway command pipe."""
    deadline = time.monotonic() + timeout
    payload = bytearray()
    descriptor = source.fileno()
    with selectors.SelectSelector() as ready:
        ready.register(descriptor, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not ready.select(remaining):
                raise ValueError("Inspection command input timed out")
            chunk = os.read(descriptor, _STDIN_LIMIT + 1 - len(payload))
            if not chunk:
                return bytes(payload)
            payload.extend(chunk)
            if len(payload) > _STDIN_LIMIT:
                raise ValueError("Inspection command input exceeded its size limit")


def _configuration(path: Path) -> _Configuration:
    # Protect the trust file's parent chain as well as its own descriptor.
    uid = os.geteuid()
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("Inspection configuration path is unavailable")
    for directory in path.parents:
        info = directory.stat()
        if info.st_uid not in {0, uid} or (
            info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX
        ):
            raise ValueError("Inspection configuration parent is not trusted")
    with os.fdopen(
        os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb"
    ) as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
            raise ValueError(
                "Inspection configuration is not root-owned or writable by others"
            )
        config = _object(handle.read(_CONFIG_LIMIT + 1), _CONFIG_LIMIT)
    if config.keys() - {"engine_only", "observe_notify"} != {
        "router_hostname", "hook_owner",
        "vendor_controls_sha256",
        "runtime_directory",
        "status_path",
    } or (
        not _valid_digest(config["vendor_controls_sha256"])
        or config["hook_owner"] != INSPECTION_OWNER
        or type(config["runtime_directory"]) is not str
        or type(config["status_path"]) is not str
        or type(config.get("engine_only", False)) is not bool
        or type(config.get("observe_notify", False)) is not bool
        or config.get("observe_notify", False) and not config.get("engine_only", False)
    ):
        raise ValueError("Inspection configuration fields are invalid")
    runtime = Path(config["runtime_directory"])
    status = Path(config["status_path"])
    if (
        not runtime.is_absolute()
        or not status.is_absolute()
        or status == path
        or status.name in _RESERVED
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", status.name) is None
    ):
        raise ValueError("Inspection status or runtime path is invalid")
    hostname = config["router_hostname"]
    verify_router_hostname(hostname)
    return _Configuration(hostname, config["vendor_controls_sha256"], runtime, status,
                          config.get("engine_only", False), config.get("observe_notify", False))


@contextmanager
def _command_lock(runtime: _PrivateFiles, *, read_only=False):
    flags = os.O_RDONLY if read_only else os.O_RDWR | os.O_CREAT
    fd = runtime.open("command.lock", flags)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise _Busy from None
        yield
    finally:
        os.close(fd)


def _status(requested=None, mode="unavailable", reason=None, *, phase=None) -> dict:
    response = {"schema": 1, "requested_mode": requested, "mode": mode, "reason": reason}
    if phase is not None:
        response["phase"] = phase
    return response


def _status_write(store, name, response):
    store.write(name, (json.dumps(response, separators=(",", ":")) + "\n").encode())


def _submit_events(cursor, config_path):
    empty = feed_response("gap" if cursor is not None else "idle")
    try:
        _require_linux_root()
        try:
            config = _configuration(config_path)
        except FileNotFoundError:
            return 1, feed_response("gap")
        if not config.engine_only:
            return 2, feed_response("gap")
        config.runtime_directory.lstat()
        runtime = _PrivateFiles(config.runtime_directory)
        with _command_lock(runtime, read_only=True):
            approval = reference_inspection_approval(vendor_controls_sha256=config.approved_digest)
            control = LocalVyOSInspectionControl(
                config.runtime_directory, approval=approval, engine_only=True, observe_notify=config.observe_notify,
                router_hostname=config.router_hostname,
            )
            response = control.read_events(cursor)
            if len(json.dumps(response, separators=(",", ":"), allow_nan=False).encode()) >= RESPONSE_LIMIT:
                return 1, feed_response("gap")
            return 0, response
    except FileNotFoundError:
        return 0, empty
    except (InspectionControlError, OSError, ValueError, RecursionError, _Busy):
        return 1, feed_response("gap")


def submit(raw: bytes, *, config_path: Path = _CONFIG_PATH) -> tuple[int, dict]:
    """Validate an intent and publish a fixed, sanitized transition result."""
    try:
        intent, verify_only, phase = _decode(raw)
    except (ValueError, RecursionError):
        return 2, _status(reason="invalid-request")
    if phase == "read-events":
        return _submit_events(intent, config_path)

    try:
        _require_linux_root()
        config = _configuration(config_path)
        if config.engine_only != (phase is not None) or (
            intent.mode != "off"
            and intent.vendor_controls_sha256 != config.approved_digest
        ):
            return 2, _status(intent.mode, reason="invalid-request", phase=phase)
        if not config.runtime_directory.exists():
            parent = config.runtime_directory.parent
            parent_info = parent.stat()
            if (parent.resolve(strict=True) != parent or parent_info.st_uid not in {0, os.geteuid()}
                    or parent_info.st_mode & 0o022):
                raise ValueError("Inspection runtime parent is not trusted")
            config.runtime_directory.mkdir(mode=0o700, exist_ok=True)
        runtime = _PrivateFiles(config.runtime_directory)
        store = _PrivateFiles(config.status_path.parent)
        approval = reference_inspection_approval(
            vendor_controls_sha256=config.approved_digest
        )
        control = LocalVyOSInspectionControl(
            config.runtime_directory, approval=approval, engine_only=config.engine_only,
            observe_notify=config.observe_notify, router_hostname=config.router_hostname,
        )
    except (InspectionControlError, OSError, ValueError, RecursionError):
        return 1, _status(intent.mode, reason="configuration-unavailable", phase=phase)

    try:
        with _command_lock(runtime):
            if not verify_only:
                _status_write(
                    store,
                    config.status_path.name,
                    _status(intent.mode, reason="transition-in-progress", phase=phase),
                )
            try:
                if phase is None:
                    supervisor = InspectionSupervisor(control, approval=approval)
                    outcome = supervisor.verify(intent) if verify_only else supervisor.reconcile(intent)
                    verified = outcome.mode == intent.mode
                else:
                    control.engine_phase(phase, intent)
                    verified = True
            except (InspectionControlError, OSError, ValueError):
                verified = False
            response = (
                _status(intent.mode, intent.mode, phase=phase)
                if verified
                else _status(intent.mode, reason="inspection-unavailable", phase=phase)
            )
            _status_write(store, config.status_path.name, response)
    except _Busy:
        return 1, _status(intent.mode, reason="command-busy", phase=phase)
    except (InspectionControlError, OSError, ValueError):
        return 1, _status(intent.mode, reason="status-unavailable", phase=phase)
    return (0 if verified else 1), response


def main(*, config_path: Path = _CONFIG_PATH) -> int:
    if len(sys.argv) != 1:
        code, response = 2, _status(reason="invalid-request")
    else:
        try:
            raw = _read_stdin(sys.stdin.buffer)
        except (OSError, ValueError):
            code, response = 2, _status(reason="invalid-request")
        else:
            code, response = submit(raw, config_path=config_path)
    print(json.dumps(response, separators=(",", ":")), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
