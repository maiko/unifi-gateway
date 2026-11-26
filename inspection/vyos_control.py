"""Control the Suricata reference policy for a fixed router, host pair and TCP port."""

import fcntl
import hashlib
import ipaddress
import json
import math
import os
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from uuid import UUID

from inspection.supervisor import (
    InspectionApproval,
    InspectionControlError,
    InspectionReadback,
    RunningInspection,
    _ready,
)
from inspection.suricata import InspectionIntent
from inspection.vyos_install import INSPECTION_OWNER, local_router_hostname
from inspection.vyos_eve_feed import (
    EveGeneration,
    feed_response,
    read_events as read_eve_events,
    read_generations,
    seal_generation,
    start_generation,
)
from inspection.vyos_queue import (
    VYOS_VERSION,
    BridgeEndpoint,
    EngineIdentity,
    LiveVlan,
    QueuePlan,
    QueueScope,
    _check_placement,
    _check_scope,
    _in_inspection_table,
    _nft_entries,
    assess_inline_queue,
)
from inspection.vyos_readback import (
    EngineClaim,
    ForeignInspectionResource,
    HookClaim,
    KernelIdentity,
    LinuxInspectionReader,
    VerifiedListener,
    _run_bounded,
    _unique_fields,
)

ENGINE_PHASE_MODES = {
    "prepare-engine": ("block",),
    "verify-engine": ("off", "notify", "block"),
    "apply-engine": ("off", "notify"),
}
_PLAN = QueuePlan(
    QueueScope(
        BridgeEndpoint("br110", "eth3.110", "192.168.110.1/24", "192.168.110.2"),
        BridgeEndpoint("br120", "eth3.120", "192.168.120.1/24", "192.168.120.2"),
        18743,
        41110,
    )
)
_NFT = "/usr/sbin/nft"
_ENGINE = "/usr/bin/suricata"
_OP = "/opt/vyatta/bin/vyatta-op-cmd-wrapper"
_IP = "/usr/sbin/ip"
_STATE_FILE = "ownership.json"
_FSIZE_LIMIT = 8 * 1024 * 1024
_CONFIG = """%YAML 1.1
---
runmode: workers
capture:
  disable-offloading: false
stream:
  inline: auto
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      metadata: no
      types:
        - alert:
            verdict: yes
            payload: no
            payload-printable: no
            packet: no
            tagged-packets: no
            metadata:
              flow: yes
              app-layer: no
              rule:
                metadata: no
                raw: no
        - flow
"""
_PASSIVE = """
af-packet:
  - interface: eth3.110
    threads: 1
    cluster-id: 111
    cluster-type: cluster_flow
    defrag: yes
    bpf-filter: "ip and tcp and ((src host 192.168.110.2 and dst host 192.168.120.2 and dst port 18743) or (src host 192.168.120.2 and dst host 192.168.110.2 and src port 18743))"
"""
_RULE = (
    "tcp 192.168.110.2 any -> 192.168.120.2 18743 "
    '(msg:"UXG isolated post-policy marker"; flow:to_server,established; '
    'content:"UXG-POST-POLICY-LAB-MARKER"; sid:1000043; rev:1;)\n'
)


def _policy(mode):
    if mode == "notify":
        packet_rule = _RULE.replace("flow:to_server,established;", "flow:to_server,established,no_stream;")
        return (
            (_CONFIG + _PASSIVE).encode(),
            ("alert " + packet_rule).encode(),
            ("--af-packet=eth3.110",),
        )
    if mode == "block":
        return _CONFIG.encode(), ("drop " + _RULE).encode(), ("-q", "41110")
    raise ValueError("Unsupported local engine mode")


def reference_policy_sha256(mode: str) -> str:
    config, rules, arguments = _policy(mode)
    return hashlib.sha256(
        config + b"\0" + rules + b"\0" + "\0".join(arguments).encode()
    ).hexdigest()


def reference_inspection_approval(*, vendor_controls_sha256: str) -> InspectionApproval:
    """Bind the approved controller settings to the reference queue and rule digests."""
    return InspectionApproval(
        INSPECTION_OWNER,
        _PLAN,
        vendor_controls_sha256,
        reference_policy_sha256("notify"),
        reference_policy_sha256("block"),
    )


def stock_queue_scope_matches(scope):
    approved = _PLAN.scope
    return type(scope) is dict and _encoded(scope) == _encoded({
        "queue": approved.queue_number,
        "server_port": approved.server_port,
        "initiator": {"interface": approved.initiator.interface, "host": approved.initiator.host},
        "responder": {"interface": approved.responder.interface, "host": approved.responder.host},
    })


class EngineStartRolledBack(InspectionControlError):
    """A launch failed and its exact child has been reaped."""


def _require_linux_root():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise InspectionControlError("Local inspection control requires Linux root")


def verify_router_hostname(expected: str) -> None:
    try:
        hostname = local_router_hostname()
    except ValueError as error:
        raise InspectionControlError("Cannot verify the local inspection hostname") from error
    if hostname != expected:
        raise InspectionControlError("The local hostname differs from the inspection enrollment")


def _deadline(timeout):
    if (
        type(timeout) not in (int, float)
        or not math.isfinite(timeout)
        or not 0 < timeout <= 60
    ):
        raise ValueError("Inspection control requires a bounded timeout")
    return time.monotonic() + timeout


def _budget(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise InspectionControlError("Inspection control timed out")
    return min(remaining, 30)


def _encoded(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _positive(value):
    return type(value) is int and value > 0


class _PrivateFiles:
    def __init__(self, root: Path):
        try:
            info = root.lstat()
            if (
                not root.is_absolute()
                or root.resolve(strict=True) != root
                or (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700
                )
            ):
                raise ValueError
            for ancestor in root.parents:
                parent = ancestor.stat()
                if parent.st_uid not in {0, os.geteuid()} or (
                    parent.st_mode & 0o022 and not parent.st_mode & stat.S_ISVTX
                ):
                    raise ValueError
        except (OSError, ValueError):
            raise ValueError(
                "Inspection state requires an existing private local directory"
            ) from None
        self.root = root

    def open(self, name, flags):
        fd = os.open(self.root / name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            os.close(fd)
            raise InspectionControlError(
                "Inspection file ownership or permissions differ"
            )
        return fd

    def read(self, name, limit):
        try:
            fd = self.open(name, os.O_RDONLY)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, "rb") as stream:
            content = stream.read(limit + 1)
        if len(content) > limit:
            raise InspectionControlError("Inspection state exceeded its size limit")
        return content

    def write(self, name, data):
        try:
            old = self.open(name, os.O_RDONLY)
        except FileNotFoundError:
            pass
        else:
            os.close(old)
        fd, path = tempfile.mkstemp(prefix=".inspection-", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(path, self.root / name)
            directory = os.open(self.root, os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            Path(path).unlink(missing_ok=True)


@dataclass(frozen=True)
class _EngineReceipt:
    mode: str
    policy_sha256: str
    identity: EngineIdentity
    listener: tuple[int, int] | None = None


@dataclass(frozen=True)
class _Ownership:
    kernel: KernelIdentity
    engine: _EngineReceipt | None = None
    hook_handle: int | None = None
    pending: str | None = None
    eve_generations: tuple[EveGeneration, ...] = ()
    owner: str = INSPECTION_OWNER

    @property
    def readable_generations(self):
        if self.engine is not None and self.engine.mode == "block" and self.engine.listener is None:
            return self.eve_generations[:-1]
        return self.eve_generations


def _read_ownership(files):
    text = files.read(_STATE_FILE, 4096)
    if text is None:
        return None
    try:
        data = json.loads(text, object_pairs_hook=_unique_fields)
        if (
            data.keys() - {"eve_generations", "owner"} != {"version", "kernel", "engine", "hook_handle", "pending"}
            or type(data["version"]) is not int
            or data["version"] != 2 or data.get("owner") != INSPECTION_OWNER
        ):
            raise ValueError
        kernel = KernelIdentity(**data["kernel"])
        if str(UUID(kernel.boot_id)) != kernel.boot_id or not _positive(
            kernel.namespace_inode
        ):
            raise ValueError
        pending = data["pending"]
        if pending not in (None, "start", "stop", "install", "remove"):
            raise ValueError
        handle = data["hook_handle"]
        if handle is not None and not _positive(handle):
            raise ValueError
        item = data["engine"]
        engine = None
        if item is not None:
            if item.keys() - {"listener"} != {"mode", "policy_sha256", "pid", "start_ticks"}:
                raise ValueError
            mode, policy = item["mode"], item["policy_sha256"]
            if (
                policy != reference_policy_sha256(mode)
                or not _positive(item["pid"])
                or not _positive(item["start_ticks"])
            ):
                raise ValueError
            listener = item.get("listener")
            if "listener" in item and (
                mode != "block" or type(listener) is not list or len(listener) != 2
                or not all(_positive(value) for value in listener)
            ):
                raise ValueError
            engine = _EngineReceipt(
                mode, policy, EngineIdentity(item["pid"], item["start_ticks"]),
                tuple(listener) if listener is not None else None,
            )
        generations = read_generations(data.get("eve_generations", []))
        if generations and (
            engine is not None and (generations[-1].end is not None or generations[-1].mode != engine.mode)
            or engine is None and pending != "start" and generations[-1].end is None
        ):
            raise ValueError
        return _Ownership(kernel, engine, handle, pending, generations, data["owner"])
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
        raise InspectionControlError("Inspection ownership record is invalid") from None


def _write_ownership(files, receipt):
    value = asdict(receipt)
    value["version"] = 2
    if not receipt.eve_generations:
        del value["eve_generations"]
    if receipt.engine is not None:
        value["engine"].update(value["engine"].pop("identity"))
        if receipt.engine.listener is None:
            del value["engine"]["listener"]
    files.write(_STATE_FILE, _encoded(value))


def _outside(inventory):
    return [
        row
        for row in inventory.snapshot["nftables"]
        if not any(_in_inspection_table(kind, body) for kind, body in row.items())
    ]


def _full_queue(listener):
    if listener is None:
        return False
    queue = listener.binding
    return (
        queue.copy_mode == 2
        and queue.copy_range >= 65531
        and not (queue.queue_dropped or queue.user_dropped)
    )


def _queue_row(listener):
    if listener is None:
        return ""
    q = listener.binding
    return " ".join(
        map(
            str,
            (
                41110,
                q.port_id,
                q.backlog,
                q.copy_mode,
                q.copy_range,
                q.queue_dropped,
                q.user_dropped,
                q.packet_sequence,
                1,
            ),
        )
    )


def _command(argv, deadline, *, stdin=None, allowed=(0,)):
    try:
        result = subprocess.run(
            argv,
            input=stdin,
            stdin=subprocess.DEVNULL if stdin is None else None,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_budget(deadline),
        )
    except (OSError, subprocess.TimeoutExpired):
        raise InspectionControlError(
            "Scoped inspection command failed or timed out"
        ) from None
    if result.returncode not in allowed:
        raise InspectionControlError("Scoped inspection command failed")
    return result.returncode


class _StockRuntime:
    def __init__(self, files):
        self._files = files
        self._reader = LinuxInspectionReader()
        self._children = {}

    def inventory(self, deadline):
        return self._reader.read_inventory(timeout=_budget(deadline))

    def listener(self, claim, deadline):
        return self._reader.read_listener(41110, claim=claim, timeout=_budget(deadline))

    def links(self, deadline):
        version = _run_bounded(
            [_OP, "show", "version"], timeout=_budget(deadline), limit=4096
        )
        if not any(
            line.startswith(b"Version:")
            and line.split(maxsplit=1)[-1] == f"VyOS {VYOS_VERSION}".encode()
            for line in version.splitlines()
        ):
            raise InspectionControlError(
                "Local VyOS version differs from the qualified build"
            )
        result = {}
        for endpoint in (_PLAN.scope.initiator, _PLAN.scope.responder):
            name = endpoint.interface
            try:
                [link] = json.loads(
                    _run_bounded(
                        [_IP, "-j", "-d", "link", "show", "dev", name],
                        timeout=_budget(deadline),
                        limit=8192,
                    )
                )
                [row] = json.loads(
                    _run_bounded(
                        [_IP, "-j", "-4", "addr", "show", "dev", name],
                        timeout=_budget(deadline),
                        limit=8192,
                    )
                )
                [address] = [
                    ipaddress.IPv4Interface(f"{value['local']}/{value['prefixlen']}")
                    for value in row["addr_info"]
                    if value["scope"] == "global"
                ]
                vlan = link["linkinfo"]["info_data"]
                if link["link"] != "eth3" or vlan["protocol"] != "802.1Q":
                    raise ValueError
                result[name] = LiveVlan(
                    vlan["id"],
                    str(address),
                    {"UP", "LOWER_UP"}.issubset(link["flags"]),
                    link["linkinfo"]["info_kind"],
                    link.get("master"),
                )
            except (KeyError, TypeError, ValueError):
                raise InspectionControlError(
                    "Local routed VLAN readback is unavailable"
                ) from None
        return result

    def assert_engine_absent(self, deadline):
        if (
            _command(
                ["/usr/bin/pgrep", "-x", "suricata|Suricata-Main"],
                deadline,
                allowed=(0, 1),
            )
            == 0
        ):
            raise ForeignInspectionResource(
                "Existing Suricata process has no local ownership receipt"
            )

    def start_notify_observer(self, generation, kernel, engine, deadline):
        from inspection.notify_runtime import start_observer

        start_observer(self._files, generation.id, kernel, engine, deadline)

    def prove_notify(self, generation, event, boot_id):
        from inspection.notify_runtime import prove_forwarding

        return prove_forwarding(self._files, generation, event, boot_id=boot_id)

    def _verify_policy(self, mode):
        config, rules, _ = _policy(mode)
        if (
            self._files.read("engine.yaml", 4096) != config
            or self._files.read("marker.rules", 4096) != rules
        ):
            raise InspectionControlError(
                "Local Suricata policy differs from the approved rule and configuration digests"
            )

    def _argv(self, mode, *, live=True):
        _, _, capture = _policy(mode)
        root = self._files.root
        return [
            _ENGINE,
            "-c",
            str(root / "engine.yaml"),
            "-S",
            str(root / "marker.rules"),
            "-l",
            str(root),
            *(capture if live else ()),
        ]

    def test_policy(self, mode, deadline):
        version = _run_bounded([_ENGINE, "-V"], timeout=_budget(deadline), limit=1024)
        if b"Suricata version 7.0.10 RELEASE" not in version:
            raise InspectionControlError(
                "Local Suricata version differs from the qualified build"
            )
        config, rules, _ = _policy(mode)
        self._files.write("engine.yaml", config)
        self._files.write("marker.rules", rules)
        self._files.write("engine.log", b"")
        # Establish ownership of the EVE path without replacing recorded events.
        if self._files.read("eve.json", _FSIZE_LIMIT) is None:
            self._files.write("eve.json", b"")
        _command([*self._argv(mode, live=False), "-T"], deadline)

    def approved_engine_ready(self, receipt, kernel, deadline):
        _budget(deadline)
        self._reader._same_kernel(kernel, deadline)
        pid = receipt.identity.pid
        child = self._children.get(pid)
        if child is not None and child.poll() is not None:
            del self._children[pid]
            return None
        try:
            with _pidfd(pid) as fd:
                if select.select([fd], [], [], 0)[0]:
                    return None
                self._reader._check_process(EngineClaim(kernel, receipt.identity))
                self._verify_policy(receipt.mode)
                log = self._files.read("engine.log", _FSIZE_LIMIT)
                if select.select([fd], [], [], 0)[0]:
                    return None
        except ProcessLookupError:
            return None
        return (
            log is not None
            and b"Engine started." in log
            and (
                receipt.mode != "block"
                or b"NFQ running in standard ACCEPT/DROP mode" in log
            )
        )

    def start(self, mode, kernel, deadline):
        self._verify_policy(mode)
        ready_by = deadline - min(1.0, _budget(deadline) / 5)
        log = self._files.open("engine.log", os.O_WRONLY | os.O_APPEND)
        try:
            process = subprocess.Popen(
                [
                    "/usr/bin/prlimit",
                    f"--fsize={_FSIZE_LIMIT}",
                    "--",
                    *self._argv(mode),
                ],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError:
            raise EngineStartRolledBack("Local engine could not be launched") from None
        finally:
            os.close(log)
        try:
            with _pidfd(process.pid) as fd:
                try:
                    while process.poll() is None:
                        _budget(ready_by)
                        try:
                            running = self._reader._process_identity(process.pid)
                            receipt = _EngineReceipt(
                                mode, reference_policy_sha256(mode), running
                            )
                            if (
                                os.readlink(f"/proc/{process.pid}/exe") == _ENGINE
                                and self.approved_engine_ready(
                                    receipt, kernel, ready_by
                                )
                                and (
                                    mode == "notify"
                                    or _full_queue(
                                        self.listener(
                                            EngineClaim(kernel, running), ready_by
                                        )
                                    )
                                )
                            ):
                                self._children[process.pid] = process
                                return running
                        except FileNotFoundError:
                            pass
                        time.sleep(min(0.05, _budget(ready_by)))
                except (InspectionControlError, OSError):
                    if process.poll() is None:
                        try:
                            signal.pidfd_send_signal(fd, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                try:
                    process.wait(timeout=_budget(deadline))
                except subprocess.TimeoutExpired:
                    raise InspectionControlError(
                        "Owned engine startup cleanup is unverified"
                    ) from None
        except ProcessLookupError:
            if process.poll() is None:
                raise InspectionControlError(
                    "Owned engine startup identity is unavailable"
                ) from None
        raise EngineStartRolledBack("Local inspection engine startup was rolled back")

    def stop(self, receipt, kernel, deadline):
        pid = receipt.identity.pid
        self._reader._same_kernel(kernel, deadline)
        try:
            with _pidfd(pid) as fd:
                if select.select([fd], [], [], 0)[0]:
                    return
                self._reader._check_process(EngineClaim(kernel, receipt.identity))
                self._verify_policy(receipt.mode)
                signal.pidfd_send_signal(fd, signal.SIGTERM)
                if not select.select([fd], [], [], _budget(deadline))[0]:
                    raise InspectionControlError(
                        "Local inspection engine stop is unconfirmed"
                    )
        except ProcessLookupError:
            return

    def check_hook(self, deadline):
        _command(
            [_NFT, "-c", "-j", "-f", "-"],
            deadline,
            stdin=_encoded(_PLAN.creation_batch()),
        )

    def install(self, deadline):
        _command(
            [_NFT, "-j", "-f", "-"], deadline, stdin=_encoded(_PLAN.creation_batch())
        )

    def delete(self, handle, deadline):
        if not _positive(handle):
            raise InspectionControlError("Local nft table handle is invalid")
        _command([_NFT, "delete", "table", "ip", "handle", str(handle)], deadline)


@contextmanager
def _pidfd(pid):
    fd = os.pidfd_open(pid)
    try:
        yield fd
    finally:
        os.close(fd)


@dataclass(frozen=True)
class _Observation:
    readback: InspectionReadback
    receipt: _Ownership
    inventory: object
    listener: VerifiedListener | None


class LocalVyOSInspectionControl:
    """Serialize and compare scoped live state before a fixed privileged action."""

    def __init__(
        self, state_directory: Path, *, approval: InspectionApproval, engine_only=False,
        observe_notify=False, router_hostname, _runtime=None,
    ):
        _require_linux_root()
        if not isinstance(
            approval, InspectionApproval
        ) or approval != reference_inspection_approval(
            vendor_controls_sha256=approval.vendor_controls_sha256
        ):
            raise ValueError(
                "Local inspection requires the reference traffic scope and approved engine policies"
            )
        self._approval = approval
        self._router_hostname = router_hostname
        self._files = _PrivateFiles(state_directory)
        self._runtime = _runtime if _runtime is not None else _StockRuntime(self._files)
        self._engine_only = engine_only
        self._observe_notify = observe_notify
        self._locked = False

    @contextmanager
    def exclusive(self, *, timeout, _read_only=False):
        _deadline(timeout)
        verify_router_hostname(self._router_hostname)
        if self._locked:
            raise InspectionControlError("Inspection ownership lock is already held")
        flags = os.O_RDONLY if _read_only else os.O_RDWR | os.O_CREAT
        fd = self._files.open("inspection.lock", flags)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise InspectionControlError("Inspection control is busy") from None
            self._locked = True
            yield
        finally:
            self._locked = False
            os.close(fd)

    def _ownership(self):
        receipt = _read_ownership(self._files)
        if receipt is not None and receipt.owner != self._approval.owner:
            raise InspectionControlError("Inspection hook owner differs from the installed approval")
        return receipt

    def _observe(self, deadline):
        if not self._locked:
            raise InspectionControlError("Inspection ownership lock is required")
        verify_router_hostname(self._router_hostname)
        inventory = self._runtime.inventory(deadline)
        stored = self._ownership()
        if stored is None or stored.kernel.boot_id != inventory.kernel.boot_id:
            receipt = _Ownership(inventory.kernel, owner=self._approval.owner)
        elif stored.kernel != inventory.kernel or stored.pending is not None:
            raise InspectionControlError(
                "Local inspection ownership or pending action is unresolved"
            )
        else:
            receipt = stored
        if self._engine_only and (receipt.hook_handle is not None or inventory.reserved_table_present):
            raise ForeignInspectionResource("Engine-only inspection requires the legacy table and claim to be absent")
        claim = (
            HookClaim(inventory.kernel, self._approval.owner, receipt.hook_handle)
            if receipt.hook_handle is not None
            else None
        )
        hook = inventory.owned_hook(_PLAN, claim=claim)
        running = receipt.engine
        engine = None
        if running is not None:
            ready = self._runtime.approved_engine_ready(
                running, inventory.kernel, deadline
            )
            if ready is not None:
                engine = RunningInspection(
                    running.identity, self._approval.engine_spec(running.mode), ready
                )
        engine_claim = (
            EngineClaim(inventory.kernel, engine.identity)
            if engine is not None and engine.spec.mode == "block"
            else None
        )
        listener = self._runtime.listener(engine_claim, deadline)
        if self._engine_only and running is not None and running.listener is not None and listener is not None:
            if running.listener != (listener.peer.port_id, listener.peer.socket_inode):
                raise ForeignInspectionResource("Inline listener differs from the prepared engine receipt")
        if (
            engine is not None
            and engine.spec.mode == "block"
            and not _full_queue(listener)
        ):
            engine = replace(engine, ready=False)
        links = {}
        scope_verified = False
        try:
            links = self._runtime.links(deadline)
            _check_scope(_PLAN.scope, links)
            if not self._engine_only:
                _check_placement(
                    _nft_entries(inventory.snapshot, VYOS_VERSION), _PLAN.scope.queue_number
                )
            scope_verified = True
        except (InspectionControlError, OSError, ValueError):
            _budget(deadline)
        health = (
            None
            if hook is None
            else assess_inline_queue(
                _PLAN,
                rule_snapshot=inventory.snapshot,
                queue_status=_queue_row(listener),
                links=links,
                vyos_version=VYOS_VERSION,
                expected_engine=engine.identity if engine is not None else None,
                observed_peers=(listener.peer,) if listener is not None else (),
            )
        )
        token = hashlib.sha256(
            _encoded(
                {
                    "inventory": inventory.digest,
                    "receipt": asdict(receipt),
                    "scope": scope_verified,
                    "engine": asdict(engine) if engine is not None else None,
                    "hook": hook.handle if hook is not None else None,
                    "listener": asdict(listener.peer) if listener is not None else None,
                    "health": health.state if health is not None else None,
                }
            )
        ).hexdigest()
        return _Observation(
            InspectionReadback(
                inventory.kernel.boot_id,
                token,
                scope_verified,
                engine,
                hook,
                listener.peer.owner if listener is not None else None,
                health,
            ),
            receipt,
            inventory,
            listener,
        )

    def engine_phase(self, phase, intent, *, timeout=20):
        """Reconcile just the approved engine while the bridge owns firewall placement."""
        if (
            not self._engine_only or not isinstance(intent, InspectionIntent)
            or intent.mode not in ENGINE_PHASE_MODES.get(phase, ())
        ):
            raise InspectionControlError("Invalid stock inspection engine phase")
        if intent.mode == "off":
            if intent.networks or intent.vendor_controls_sha256 is not None:
                raise InspectionControlError("Off inspection must have no networks or policy digest")
            desired = None
        else:
            if (
                sorted(intent.networks) != sorted((_PLAN.scope.initiator.bridge, _PLAN.scope.responder.bridge))
                or intent.vendor_controls_sha256 != self._approval.vendor_controls_sha256
            ):
                raise InspectionControlError("Engine phase differs from the approved inspection intent")
            desired = self._approval.engine_spec(intent.mode)

        deadline = _deadline(timeout)
        with self.exclusive(timeout=_budget(deadline)):
            current = self._observe(deadline)
            if phase != "verify-engine" and not _ready(current.readback, desired):
                if desired is not None and not current.readback.scope_verified:
                    raise InspectionControlError("Local inspection engine scope could not be verified")
                if current.readback.engine is not None:
                    self.stop_engine(current.readback.engine, expected=current.readback, timeout=_budget(deadline))
                    current = self._observe(deadline)
                if desired is not None:
                    self.start_engine(desired, expected=current.readback, timeout=_budget(deadline))
                    current = self._observe(deadline)
            if not _ready(current.readback, desired):
                raise InspectionControlError("Local inspection engine is unverified")
            if desired is None:
                self._runtime.assert_engine_absent(deadline)
            elif intent.mode == "block" and current.receipt.engine.listener is None:
                if phase != "prepare-engine":
                    raise InspectionControlError("Inline listener has no prepared engine receipt")
                peer = current.listener.peer
                engine = replace(current.receipt.engine, listener=(peer.port_id, peer.socket_inode))
                _write_ownership(self._files, replace(current.receipt, engine=engine))

    def read_events(self, cursor, *, timeout=2):
        """Read protected EVE observations without touching engine or status state."""
        if not self._engine_only:
            raise InspectionControlError("The EVE feed requires engine-only inspection")
        empty = feed_response("gap" if cursor is not None else "idle")
        try:
            with self.exclusive(timeout=timeout, _read_only=True):
                receipt = self._ownership()
                if receipt is None or not receipt.readable_generations:
                    return empty
                if (
                    receipt.pending is not None or receipt.hook_handle is not None
                    or receipt.kernel != LinuxInspectionReader()._kernel_identity()
                ):
                    return feed_response("gap")

                def notify_proof(generation, event):
                    return self._runtime.prove_notify(generation, event, receipt.kernel.boot_id)

                return read_eve_events(self._files, receipt.readable_generations, cursor, scope=_PLAN.scope,
                                       notify_proof=notify_proof if self._observe_notify else None)
        except FileNotFoundError:
            return empty

    def read(self, *, timeout):
        return self._observe(_deadline(timeout)).readback

    def _compare(self, expected, deadline):
        current = self._observe(deadline)
        if not isinstance(expected, InspectionReadback) or (
            current.readback.boot_id,
            current.readback.token,
        ) != (expected.boot_id, expected.token):
            raise InspectionControlError(
                "Local inspection readback changed before mutation"
            )
        return current

    def _pending(self, current, operation):
        _write_ownership(self._files, replace(current.receipt, pending=operation))

    def start_engine(self, spec, *, expected, timeout):
        deadline = _deadline(timeout)
        current = self._compare(expected, deadline)
        state = current.readback
        if (
            spec
            not in (
                self._approval.engine_spec("notify"),
                self._approval.engine_spec("block"),
            )
            or not state.scope_verified
            or state.engine is not None
            or state.hook is not None
            or state.listener is not None
        ):
            raise InspectionControlError("A scoped inspection engine cannot be started")
        self._runtime.assert_engine_absent(deadline)
        self._runtime.test_policy(spec.mode, deadline)
        current = self._compare(expected, deadline)
        self._runtime.assert_engine_absent(deadline)
        generations = current.receipt.eve_generations
        if self._engine_only:
            generations = start_generation(self._files, generations, spec.mode)
        _write_ownership(
            self._files, replace(current.receipt, pending="start", eve_generations=generations)
        )
        try:
            identity = self._runtime.start(spec.mode, current.receipt.kernel, deadline)
        except EngineStartRolledBack:
            observed = self._runtime.inventory(deadline)
            if (
                observed.kernel == current.inventory.kernel
                and not observed.reserved_table_present
            ):
                if self._runtime.listener(None, deadline) is not None:
                    raise InspectionControlError(
                        "Unexpected listener after engine startup cleanup"
                    )
                self._runtime.assert_engine_absent(deadline)
                _write_ownership(
                    self._files, replace(current.receipt, engine=None, pending=None)
                )
            raise
        receipt = _EngineReceipt(spec.mode, spec.policy_sha256, identity)
        _write_ownership(
            self._files, replace(current.receipt, engine=receipt, pending=None, eve_generations=generations)
        )
        after = self._observe(deadline)
        if (
            after.inventory.kernel != current.inventory.kernel
            or after.inventory.digest != current.inventory.digest
            or after.readback.engine != RunningInspection(identity, spec, True)
            or after.readback.listener != (identity if spec.mode == "block" else None)
        ):
            raise InspectionControlError(
                "Local inspection engine startup could not be verified"
            )
        if self._engine_only and self._observe_notify and spec.mode == "notify":
            try:
                self._runtime.start_notify_observer(generations[-1], after.receipt.kernel, identity, deadline)
            except InspectionControlError:
                self.stop_engine(after.readback.engine, expected=after.readback, timeout=_budget(deadline))
                raise

    def stop_engine(self, engine, *, expected, timeout):
        deadline = _deadline(timeout)
        current = self._compare(expected, deadline)
        if (
            engine is None
            or current.readback.engine != engine
            or current.readback.hook is not None
        ):
            raise InspectionControlError(
                "Only the verified detached engine may be stopped"
            )
        self._pending(current, "stop")
        self._runtime.stop(current.receipt.engine, current.receipt.kernel, deadline)
        if (
            self._runtime.approved_engine_ready(
                current.receipt.engine, current.receipt.kernel, deadline
            )
            is not None
        ):
            raise InspectionControlError(
                "Local inspection engine stop could not be verified"
            )
        if self._runtime.listener(None, deadline) is not None:
            raise InspectionControlError(
                "Local queue binding must be absent after shutdown"
            )
        generations = seal_generation(self._files, current.receipt.readable_generations)
        _write_ownership(
            self._files, replace(current.receipt, engine=None, pending=None, eve_generations=generations)
        )

    def install_hook(self, owner, plan, engine, *, expected, timeout):
        if self._engine_only:
            raise InspectionControlError("Engine-only inspection cannot install nftables rules")
        deadline = _deadline(timeout)
        current = self._compare(expected, deadline)
        state = current.readback
        if (
            owner != self._approval.owner
            or plan != _PLAN
            or not state.scope_verified
            or state.hook is not None
            or engine is None
            or state.engine != engine
            or engine.spec.mode != "block"
            or not engine.ready
            or state.listener != engine.identity
        ):
            raise InspectionControlError(
                "The scoped hook requires the approved inline listener"
            )
        self._runtime.check_hook(deadline)
        current = self._compare(expected, deadline)
        self._pending(current, "install")
        self._runtime.install(deadline)
        after = self._runtime.inventory(deadline)
        if after.kernel != current.inventory.kernel:
            raise InspectionControlError("Local kernel changed during hook creation")
        tables = [
            value
            for kind, value in _nft_entries(after.snapshot, VYOS_VERSION)
            if kind == "table" and _in_inspection_table(kind, value)
        ]
        if len(tables) != 1:
            raise InspectionControlError(
                "Created inspection table could not be identified"
            )
        handle = tables[0].get("handle")
        after.owned_hook(_PLAN, claim=HookClaim(after.kernel, self._approval.owner, handle))
        claimed = replace(current.receipt, hook_handle=handle, pending=None)
        _write_ownership(self._files, claimed)
        try:
            observed = self._observe(deadline)
            if _outside(observed.inventory) != _outside(current.inventory) or (
                observed.readback.hook_health is None
                or observed.readback.hook_health.state != "attached"
            ):
                raise InspectionControlError(
                    "Local hook attachment could not be verified"
                )
        except (InspectionControlError, OSError):
            rollback = self._runtime.inventory(deadline)
            if rollback.kernel != claimed.kernel:
                raise InspectionControlError(
                    "Local hook rollback boot identity changed"
                ) from None
            owned = rollback.owned_hook(
                _PLAN, claim=HookClaim(claimed.kernel, self._approval.owner, handle)
            )
            if owned is None:
                _write_ownership(self._files, replace(claimed, hook_handle=None))
            else:
                self._delete_claimed(rollback, claimed, owned, deadline)
            raise InspectionControlError(
                "Local hook verification failed and the owned table was removed"
            ) from None

    def remove_hook(self, hook, *, expected, timeout):
        if self._engine_only:
            raise InspectionControlError("Engine-only inspection cannot remove nftables rules")
        deadline = _deadline(timeout)
        current = self._compare(expected, deadline)
        if hook is None or current.readback.hook != hook:
            raise InspectionControlError(
                "Only the verified inspection table may be removed"
            )
        self._delete_claimed(current.inventory, current.receipt, hook, deadline)

    def _delete_claimed(self, inventory, receipt, hook, deadline):
        current = self._runtime.inventory(deadline)
        if (
            current.kernel != inventory.kernel
            or current.digest != inventory.digest
            or (
                current.owned_hook(
                    _PLAN, claim=HookClaim(receipt.kernel, self._approval.owner, hook.handle)
                )
                != hook
            )
        ):
            raise InspectionControlError(
                "Local inspection table changed before removal"
            )
        _write_ownership(self._files, replace(receipt, pending="remove"))
        try:
            self._runtime.delete(hook.handle, deadline)
        except InspectionControlError:
            # The old handle is the only deletion target even on uncertain acknowledgement.
            pass
        after = self._runtime.inventory(deadline)
        if after.kernel != current.kernel or after.reserved_table_present:
            raise InspectionControlError(
                "Local inspection table removal could not be verified"
            )
        _write_ownership(self._files, replace(receipt, hook_handle=None, pending=None))
        if _outside(after) != _outside(current):
            raise InspectionControlError(
                "Outside forwarding state changed during scoped removal"
            )
