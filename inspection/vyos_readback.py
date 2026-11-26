"""Read VyOS nftables and Suricata state with bounded command time and output."""

import argparse
import hashlib
import json
import math
import os
import re
import selectors
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

from inspection.supervisor import InspectionControlError, OwnedQueueHook
from inspection.vyos_queue import (
    VYOS_VERSION,
    EngineIdentity,
    QueueBinding,
    QueuePeer,
    QueuePlan,
    _expected_objects,
    _in_inspection_table,
    _nft_entries,
    _without_dynamic_fields,
    parse_nfqueue_status,
)

_NFT_LIMIT = 4 * 1024 * 1024
_PROC_QUEUE_LIMIT = 128 * 1024
_PROC_NETLINK_LIMIT = 1024 * 1024
_MAX_ENGINE_FDS = 2048
_NFT = "/usr/sbin/nft"
_MODINFO = "/usr/sbin/modinfo"
_SURICATA = "/usr/bin/suricata"
_QUEUE_MODULE = "nfnetlink_queue"
_QUEUE_MODULE_FILE = re.compile(
    r"/(?:usr/)?lib/modules/[^/\s]+/(?:[^/\s]+/)*nfnetlink_queue\.ko(?:\.(?:xz|gz|zst))?"
)
_NETLINK_COLUMNS = [
    "sk",
    "Eth",
    "Pid",
    "Groups",
    "Rmem",
    "Wmem",
    "Dump",
    "Locks",
    "Drops",
    "Inode",
]
_NETLINK_NETFILTER = 12


class ReadbackUnavailable(InspectionControlError):
    """The required observation was unreadable, incomplete, or unstable."""


class ForeignInspectionResource(InspectionControlError):
    """The reserved resource was occupied outside the supplied ownership proof."""


@dataclass(frozen=True, slots=True)
class KernelIdentity:
    boot_id: str
    namespace_inode: int


@dataclass(frozen=True, slots=True)
class EngineClaim:
    kernel: KernelIdentity
    identity: EngineIdentity


@dataclass(frozen=True, slots=True)
class HookClaim:
    kernel: KernelIdentity
    owner: str
    handle: int


@dataclass(frozen=True, slots=True)
class VerifiedListener:
    kernel: KernelIdentity
    binding: QueueBinding
    peer: QueuePeer


@dataclass(frozen=True, slots=True)
class NftInventory:
    """One stateless nft read. Raw policy stays out of diagnostics."""

    kernel: KernelIdentity
    digest: str
    _snapshot: bytes = field(repr=False)

    @property
    def snapshot(self) -> dict:
        return json.loads(self._snapshot)

    def _inspection_objects(self) -> list[tuple[str, dict]]:
        return [
            (kind, row)
            for kind, row in _nft_entries(self.snapshot, VYOS_VERSION)
            if _in_inspection_table(kind, row)
        ]

    @property
    def reserved_table_present(self) -> bool:
        return bool(self._inspection_objects())

    def owned_hook(
        self, plan: QueuePlan, *, claim: HookClaim | None
    ) -> OwnedQueueHook | None:
        """Require a trusted creation receipt and exact rules to claim this table."""
        objects = self._inspection_objects()
        if not objects:
            return None
        tables = [row for kind, row in objects if kind == "table"]
        if len(tables) != 1 or not _positive(tables[0].get("handle")):
            raise ReadbackUnavailable("Reserved nft table handle is ambiguous")
        handle = tables[0]["handle"]
        if (
            not isinstance(claim, HookClaim)
            or claim.kernel != self.kernel
            or not _positive(claim.handle)
            or claim.handle != handle
            or type(claim.owner) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", claim.owner) is None
        ):
            raise ForeignInspectionResource(
                "Reserved nft table has no matching ownership receipt"
            )
        exact = [_without_dynamic_fields(kind, row) for kind, row in objects]
        if exact != _expected_objects(plan):
            raise ForeignInspectionResource(
                "Reserved nft table shape differs from its approved plan"
            )
        return OwnedQueueHook(claim.owner, handle, plan)


def _positive(value: object) -> bool:
    return type(value) is int and value > 0


def _deadline(timeout: float) -> float:
    if (
        type(timeout) not in (float, int)
        or not math.isfinite(timeout)
        or not 0 < timeout <= 30
    ):
        raise ValueError("Readback requires a positive timeout of at most 30 seconds")
    return time.monotonic() + timeout


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ReadbackUnavailable("Inspection readback timed out")
    return remaining


def _run_bounded(argv: list[str], *, timeout: float, limit: int) -> bytes:
    deadline = _deadline(timeout)
    process = None
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        output = bytearray()
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            while True:
                if not ready.select(_remaining(deadline)):
                    raise ReadbackUnavailable("Inspection readback timed out")
                part = os.read(
                    process.stdout.fileno(), min(65_536, limit + 1 - len(output))
                )
                if not part:
                    break
                output.extend(part)
                if len(output) > limit:
                    raise ReadbackUnavailable(
                        "Inspection readback exceeded its output limit"
                    )
        if process.wait(timeout=_remaining(deadline)) != 0:
            raise ReadbackUnavailable("Inspection read command failed")
        return bytes(output)
    except subprocess.TimeoutExpired:
        raise ReadbackUnavailable("Inspection readback timed out") from None
    except OSError:
        raise ReadbackUnavailable("Inspection read command failed") from None
    finally:
        if process is not None:
            process.stdout.close()
            if process.poll() is None:
                process.kill()
                try:
                    process.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    # A kernel-blocked read must not hold the caller past its bound.
                    pass


def _read_text(path: Path, limit: int) -> str:
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ReadbackUnavailable("Kernel readback exceeded its output limit")
    try:
        return raw.decode("ascii")
    except UnicodeError:
        raise ReadbackUnavailable("Kernel readback is malformed") from None


def _unique_fields(pairs) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate nftables field")
        result[key] = value
    return result


def _netns_inode(value: str) -> int:
    match = re.fullmatch(r"net:\[([0-9]{1,20})\]", value)
    if match is None or int(match[1]) == 0:
        raise ReadbackUnavailable("Network namespace identity is unavailable")
    return int(match[1])


def _start_ticks(text: str, pid: int) -> int:
    head, sep, tail = text.rpartition(") ")
    fields = tail.split()
    if (
        not sep
        or not head.startswith(f"{pid} (")
        or len(fields) < 20
        or fields[0] not in ("R", "S", "D", "T", "t", "I", "P", "W")
        or re.fullmatch(r"[0-9]{1,20}", fields[19]) is None
        or int(fields[19]) == 0
    ):
        raise ReadbackUnavailable("Process start identity is unavailable")
    return int(fields[19])


def _netlink_inode(text: str, port_id: int) -> int:
    rows = text.splitlines()
    if not rows or rows[0].split() != _NETLINK_COLUMNS:
        raise ReadbackUnavailable("Kernel netlink inventory is malformed")
    matched = []
    for line in rows[1:]:
        fields = line.split()
        if len(fields) != len(_NETLINK_COLUMNS) or any(
            re.fullmatch(r"[0-9]{1,20}", fields[index]) is None for index in (1, 2, 9)
        ):
            raise ReadbackUnavailable("Kernel netlink inventory is malformed")
        if int(fields[1]) == _NETLINK_NETFILTER and int(fields[2]) == port_id:
            matched.append(int(fields[9]))
    if len(matched) != 1 or matched[0] <= 0:
        raise ReadbackUnavailable("NFQUEUE netlink socket identity is ambiguous")
    return matched[0]


class LinuxInspectionReader:
    """Read-only operations for the local namespace.

    Claims must come from authenticated local creation/launch receipts, never
    from matching rule names or an arbitrary PID supplied by Network. This
    layer verifies current kernel ownership. Policy and process readiness
    still belong to the privilege-specific InspectionControl implementation.

    A local actuator holds its cross-process lock while comparing the current
    kernel identity, stateless ruleset digest, and exact ownership receipts
    with the supervisor's expected readback. It records the table handle only
    after exclusive creation and records the PID/start pair from its own
    service launch. A pending launch or table operation without conclusive
    readback remains unavailable across restart.
    """

    def __init__(
        self, *, proc_root: Path = Path("/proc"), sys_root: Path = Path("/sys")
    ):
        self._proc = proc_root
        self._sys = sys_root

    def _kernel_identity(self) -> KernelIdentity:
        try:
            boot_id = _read_text(self._proc / "sys/kernel/random/boot_id", 64).strip()
            if str(UUID(boot_id)) != boot_id:
                raise ValueError("Noncanonical boot identity")
            namespace = _netns_inode(os.readlink(self._proc / "self/ns/net"))
        except (OSError, ValueError):
            raise ReadbackUnavailable("Local kernel identity is unavailable") from None
        return KernelIdentity(boot_id, namespace)

    def _same_kernel(self, kernel: KernelIdentity, deadline: float) -> None:
        if self._kernel_identity() != kernel:
            raise ReadbackUnavailable(
                "Kernel or network namespace changed during readback"
            )
        _remaining(deadline)

    def read_inventory(self, *, timeout: float = 5) -> NftInventory:
        deadline = _deadline(timeout)
        kernel = self._kernel_identity()
        raw = _run_bounded(
            [_NFT, "-j", "-s", "list", "ruleset"],
            timeout=_remaining(deadline),
            limit=_NFT_LIMIT,
        )
        try:
            snapshot = json.loads(raw, object_pairs_hook=_unique_fields)
            _nft_entries(snapshot, VYOS_VERSION)
            canonical = json.dumps(
                snapshot, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
        except (ValueError, RecursionError):
            raise ReadbackUnavailable(
                "Nftables inventory is malformed or unsupported"
            ) from None
        self._same_kernel(kernel, deadline)
        return NftInventory(kernel, hashlib.sha256(canonical).hexdigest(), canonical)

    def _queue_record(self, number: int, deadline: float) -> QueueBinding | None:
        _remaining(deadline)
        path = self._proc / "net/netfilter/nfnetlink_queue"
        try:
            raw = _read_text(path, _PROC_QUEUE_LIMIT)
        except FileNotFoundError:
            # On an unloaded modular implementation the proc entry is not created.
            module = (
                _run_bounded(
                    [_MODINFO, "-F", "filename", _QUEUE_MODULE],
                    timeout=_remaining(deadline),
                    limit=1024,
                )
                .decode("ascii", "replace")
                .strip()
            )
            if (
                _QUEUE_MODULE_FILE.fullmatch(module) is None
                or not (self._sys / "module").is_dir()
            ):
                raise ReadbackUnavailable("NFQUEUE proc state is unavailable")
            try:
                (self._sys / "module" / _QUEUE_MODULE).stat()
            except FileNotFoundError:
                try:
                    raw = _read_text(path, _PROC_QUEUE_LIMIT)
                except FileNotFoundError:
                    return None
            else:
                raise ReadbackUnavailable(
                    "Loaded NFQUEUE module has no readable proc state"
                )
        try:
            return parse_nfqueue_status(raw).get(number)
        except ValueError:
            raise ReadbackUnavailable("Kernel NFQUEUE state is malformed") from None

    def _process_identity(self, pid: int) -> EngineIdentity:
        return EngineIdentity(
            pid, _start_ticks(_read_text(self._proc / str(pid) / "stat", 4096), pid)
        )

    def _check_process(self, claim: EngineClaim) -> Path:
        expected = claim.identity
        if (
            not isinstance(expected, EngineIdentity)
            or not _positive(expected.pid)
            or not _positive(expected.start_ticks)
        ):
            raise ForeignInspectionResource("NFQUEUE process claim is invalid")
        proc = self._proc / str(expected.pid)
        if (
            self._process_identity(expected.pid) != expected
            or _netns_inode(os.readlink(proc / "ns/net"))
            != claim.kernel.namespace_inode
            or os.readlink(proc / "exe") != _SURICATA
        ):
            raise ForeignInspectionResource(
                "NFQUEUE listener does not match the approved Suricata process"
            )
        return proc

    def _socket_path(self, proc: Path, inode: int, deadline: float) -> Path:
        with os.scandir(proc / "fd") as entries:
            for index, entry in enumerate(entries):
                _remaining(deadline)
                if index >= _MAX_ENGINE_FDS:
                    raise ReadbackUnavailable(
                        "Suricata descriptor inventory exceeded its limit"
                    )
                try:
                    target = os.readlink(entry.path)
                except FileNotFoundError:
                    continue
                if target == f"socket:[{inode}]":
                    return Path(entry.path)
        raise ForeignInspectionResource(
            "Reserved NFQUEUE socket is absent from the approved process"
        )

    def read_listener(
        self, queue_number: int, *, claim: EngineClaim | None = None, timeout: float = 5
    ) -> VerifiedListener | None:
        """Join the reserved queue's netlink port and socket inode to this process."""
        if type(queue_number) is not int or not 0 <= queue_number <= 65535:
            raise ValueError("NFQUEUE requires a single numeric queue")
        deadline = _deadline(timeout)
        kernel = self._kernel_identity()
        try:
            binding = self._queue_record(queue_number, deadline)
            if binding is None:
                self._same_kernel(kernel, deadline)
                return None
            if not isinstance(claim, EngineClaim) or claim.kernel != kernel:
                raise ForeignInspectionResource(
                    "Reserved NFQUEUE is bound without a current ownership claim"
                )
            proc = self._check_process(claim)
            table = self._proc / "net/netlink"
            inode = _netlink_inode(
                _read_text(table, _PROC_NETLINK_LIMIT), binding.port_id
            )
            descriptor = self._socket_path(proc, inode, deadline)

            self._check_process(claim)
            latest = self._queue_record(queue_number, deadline)
            if (
                latest is None
                or (latest.port_id, latest.copy_mode, latest.copy_range)
                != (binding.port_id, binding.copy_mode, binding.copy_range)
                or _netlink_inode(
                    _read_text(table, _PROC_NETLINK_LIMIT), latest.port_id
                )
                != inode
                or os.readlink(descriptor) != f"socket:[{inode}]"
            ):
                raise ReadbackUnavailable(
                    "NFQUEUE listener changed during ownership verification"
                )
            self._same_kernel(kernel, deadline)
        except OSError:
            raise ReadbackUnavailable(
                "Kernel NFQUEUE readback is unavailable"
            ) from None
        return VerifiedListener(
            kernel, latest, QueuePeer(latest.port_id, inode, claim.identity)
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect the local VyOS nftables and reserved NFQUEUE"
    )
    parser.add_argument("--queue", type=int, required=True)
    args = parser.parse_args(argv)
    reader = LinuxInspectionReader()
    try:
        inventory = reader.read_inventory()
        if inventory.reserved_table_present:
            raise ForeignInspectionResource(
                "Reserved nft table has no ownership receipt"
            )
        reader.read_listener(args.queue)
    except (InspectionControlError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "objects": len(inventory.snapshot["nftables"]),
                "stateless_sha256": inventory.digest,
                "reserved_table_present": inventory.reserved_table_present,
                "reserved_queue": args.queue,
                "listener_bound": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
