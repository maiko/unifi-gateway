#!/usr/bin/python3 -I
"""Check and manage the stock VyOS Shadow Mode eligibility receipt."""

import fcntl
import hashlib
from ipaddress import IPv4Address, ip_interface
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
from time import monotonic


RECEIPT_DIRECTORY = Path("/config/unifi-gateway-shadow")
RECEIPT_NAME = "receipt.json"
SCOPE_NAME = "policy-scope.json"
MAX_RECEIPT_BYTES = 65536
MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 256 * 1024
_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
_SAVED_CONFIG_PATH = Path("/config/config.boot")
_DIGEST = re.compile(r"[a-f0-9]{64}")
_UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}")
_NUMERIC = re.compile(r"[0-9]{1,10}")
_GUARD_PATH = "/config/scripts/unifi-gateway-shadow-policy-eligible.py"
_MANAGED_GROUP = ("high-availability", "vrrp", "group", "UXGSHADOW")
_MANAGED_SYNC = ("high-availability", "vrrp", "sync-group", "UXGHA")
_MANAGED_CONNTRACK = ("service", "conntrack-sync")
_VRRP_PROTOCOL = 112
_VRRP_SAMPLE_COUNT = 2
_REQUEST_FIELDS = {
    "status": {"op"}, "candidate": {"op"}, "revoke": {"op", "receipt_id"}, "observe": {"op"},
    "check-admission": {"op", "boot_id", "config_sha256", "required_paths"},
    "fence": {"op", "generation"},
    "observe-vrrp": {"op", "boot_id", "config_sha256", "generation"},
    "publish": {"op", "transaction", "boot_id", "sha256", "generation", "config_sha256"},
}
_LEGACY_RECEIPT_FIELDS = {"paths", "sha256"}
_MANAGED_RECEIPT_FIELDS = _LEGACY_RECEIPT_FIELDS | {"transaction", "generation"}
_FIRST_GENERATION = "0" * 64
_PATH_COMPONENT = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_POLICY_ROOTS = {
    "firewall", "high-availability", "interfaces", "nat", "policy", "protocols", "qos", "service", "system", "vpn", "vrf",
}


def _unique_object(pairs):
    document = dict(pairs)
    if len(document) != len(pairs):
        raise ValueError("Shadow policy receipt has a duplicate field")
    return document


def _policy_paths(paths):
    if not isinstance(paths, list) or not 1 <= len(paths) <= 512:
        raise ValueError("Shadow policy receipt needs a bounded list of policy paths")
    for path in paths:
        if (not isinstance(path, list) or not 2 <= len(path) <= 20
                or any(not isinstance(component, str) or _PATH_COMPONENT.fullmatch(component) is None for component in path)
                or path[0] not in _POLICY_ROOTS):
            raise ValueError("Shadow policy receipt has an invalid policy path")
    ordered = sorted(tuple(path) for path in paths)
    if len(set(ordered)) != len(ordered):
        raise ValueError("Shadow policy receipt has a duplicate policy path")
    return ordered


def _select(config, path):
    for component in path:
        if not isinstance(config, dict):
            raise ValueError("The VyOS configuration path crossed a value")
        if component not in config:
            return False, None
        config = config[component]
    return True, config


def policy_digest(config, paths):
    """Include absent paths so a verified withdrawal can be checked too."""
    projection = [(path, *_select(config, path)) for path in _policy_paths(paths)]
    if not any(present for _, present, _ in projection):
        raise ValueError("The shadow policy has no configured anchor")
    canonical = json.dumps(projection, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _read_private_json(directory_fd, owner, name):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(name, flags, dir_fd=directory_fd), "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o077
                or not 0 < info.st_size <= MAX_RECEIPT_BYTES):
            raise ValueError("Invalid private Shadow policy file")
        raw = stream.read(MAX_RECEIPT_BYTES + 1)
    if len(raw) != info.st_size:
        raise ValueError("Shadow policy file changed during read")
    return raw, json.loads(raw, object_pairs_hook=_unique_object)


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _read_receipt_state(directory_fd, owner):
    try:
        raw, state = _read_private_json(directory_fd, owner, RECEIPT_NAME)
    except FileNotFoundError:
        return b"", {}
    if isinstance(state, dict) and state.keys() == {"revoked"} and _matches(_DIGEST, state["revoked"]):
        return raw, state
    if not isinstance(state, dict) or state.keys() not in (
        _LEGACY_RECEIPT_FIELDS, _MANAGED_RECEIPT_FIELDS, _MANAGED_RECEIPT_FIELDS | {"config_sha256"},
    ):
        raise ValueError("Invalid Shadow policy receipt fields")
    if (not _matches(_DIGEST, state["sha256"]) or ("transaction" in state and (
            not _matches(_UUID, state["transaction"]) or not _matches(_DIGEST, state["generation"])))
            or ("config_sha256" in state and not _matches(_DIGEST, state["config_sha256"]))):
        raise ValueError("Invalid Shadow policy receipt document")
    _policy_paths(state["paths"])
    return raw, state


def _read_managed_scope(directory_fd, owner):
    try:
        _, scope = _read_private_json(directory_fd, owner, SCOPE_NAME)
    except FileNotFoundError:
        return None
    if not isinstance(scope, dict) or scope.keys() != {"paths"}:
        raise ValueError("Invalid Shadow policy scope document")
    paths = _policy_paths(scope["paths"])
    if (not {_MANAGED_GROUP, _MANAGED_SYNC, _MANAGED_CONNTRACK}.issubset(paths)
            or not any(path[0] == "firewall" for path in paths)):
        raise ValueError("The Shadow policy scope must include the managed election, state sync and firewall")
    return paths


def _verify_managed_configuration(tree):
    group = _select(tree, _MANAGED_GROUP)[1]
    member = _select(tree, (*_MANAGED_SYNC, "member"))[1]
    script = _select(tree, (*_MANAGED_SYNC, "health-check", "script"))[1]
    conntrack = _select(tree, (*_MANAGED_CONNTRACK, "failover-mechanism", "vrrp", "sync-group"))[1]
    if (not isinstance(group, dict) or group.get("vrid") != "42" or group.get("priority") not in ("120", "100")
            or member not in ("UXGSHADOW", ["UXGSHADOW"]) or script != _GUARD_PATH or conntrack != "UXGHA"):
        raise ValueError("VyOS configuration does not contain the guarded Shadow election and state sync")


def _standby_vrrp_scope(tree):
    _verify_managed_configuration(tree)
    group = _select(tree, _MANAGED_GROUP)[1]
    interface = group.get("interface")
    addresses = group.get("address")
    if (not isinstance(interface, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}", interface)
            or group.get("priority") != "100" or group.get("advertise-interval") != "1"
            or {"authentication", "excluded-address", "disable", "rfc3768-compatibility"} & group.keys()
            or not isinstance(addresses, dict) or not 1 <= len(addresses) <= 255):
        raise ValueError("Shadow VRRP observation requires the managed standby election")
    local = IPv4Address(group.get("hello-source-address"))
    peer = group.get("peer-address")
    if isinstance(peer, list) and len(peer) == 1:
        peer, = peer
    peer = IPv4Address(peer)
    version = _select(tree, ("high-availability", "vrrp", "global-parameters", "version"))[1]
    if version not in (None, "2", "3") or local == peer or any(
        address.is_unspecified or address.is_multicast or address.is_loopback for address in (local, peer)
    ):
        raise ValueError("Shadow VRRP observation requires one IPv4 unicast peer")
    vips = {IPv4Address(vip.split("/")[0]).packed for vip in addresses}
    return interface, local, peer, int(version or "2"), vips


def _matches_vrrp_advertisement(packet, local, peer, version, vips):
    if (len(packet) < 28 or packet[0] != 0x45 or int.from_bytes(packet[2:4], "big") != len(packet)
            or int.from_bytes(packet[6:8], "big") & 0xbfff
            or packet[8:10] != bytes((255, _VRRP_PROTOCOL)) or packet[12:20] != peer.packed + local.packed):
        return False
    payload = packet[20:]
    count = len(vips)
    address_end = 8 + 4 * count
    if (payload[:4] != bytes((version << 4 | 1, 42, 120, count))
            or payload[4:6] != (b"\0\1" if version == 2 else b"\0\x64")
            or len(payload) != address_end + (8 if version == 2 else 0)
            or {payload[index:index + 4] for index in range(8, address_end, 4)} != vips):
        return False
    # Stock Keepalived's IPv4 unicast v3 uses the source/destination pseudo-header.
    pseudo = b"" if version == 2 else peer.packed + local.packed + struct.pack("!BBH", 0, _VRRP_PROTOCOL, len(payload))
    data = pseudo + payload
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total > 0xffff:
        total = (total & 0xffff) + (total >> 16)
    return total == 0xffff


def _sample_standby_vrrp(interface, local, peer, version, vips):
    """Observe protocol 112 after INPUT on the exact interface and local IP."""
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, _VRRP_PROTOCOL) as receiver:
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode("ascii") + b"\0")
        receiver.bind((str(local), 0))
        deadline = monotonic() + 3.0
        received = 0
        while received < _VRRP_SAMPLE_COUNT:
            remaining = deadline - monotonic()
            if remaining <= 0:
                break
            receiver.settimeout(remaining)
            try:
                packet = receiver.recv(2048)
            except TimeoutError:
                break
            if _matches_vrrp_advertisement(packet, local, peer, version, vips):
                received += 1
    return received


def _observe_standby_vrrp(request, observe, prove_saved):
    expected = request["boot_id"], request["config_sha256"]
    if prove_saved() != expected:
        raise ValueError("The saved standby election changed before the VRRP observation")
    running, saved = observe()
    scope = _standby_vrrp_scope(running)
    if _standby_vrrp_scope(saved) != scope:
        raise ValueError("Running and saved standby VRRP observations disagree")
    interface, local, peer, version, vips = scope
    received = _sample_standby_vrrp(interface, local, peer, version, vips)
    if prove_saved() != expected:
        raise ValueError("The saved standby election changed during the VRRP observation")
    return {"interface": interface, "local": str(local), "peer": str(peer), "version": version, "received": received}


def _active_configuration_text():
    return subprocess.run(
        ["/bin/cli-shell-api", "--show-active-only", "--show-ignore-edit", "showConfig"],
        capture_output=True, text=True, timeout=0.65, check=True,
        env={**os.environ, "VYATTA_EDIT_LEVEL": "/", "VYATTA_TEMPLATE_LEVEL": "/"},
    ).stdout


def _decode_configuration(text):
    from vyos.configtree import ConfigTree

    if not text.strip():
        raise ValueError("VyOS configuration is unavailable")
    return json.loads(ConfigTree(text).to_json())


def read_configurations():
    """Read explicit active configuration and the installed disk's saved tree."""
    return (_decode_configuration(_active_configuration_text()),
            _decode_configuration(_SAVED_CONFIG_PATH.read_text(encoding="utf-8")))


def _named_items(node):
    if not isinstance(node, dict) or any(not _matches(_NAME, name) for name in node):
        raise ValueError("Invalid Shadow configuration inventory")
    return node.items()


def _as_address(value):
    if not isinstance(value, str) or "%" in value or "/" not in value:
        raise ValueError("Invalid Shadow interface address")
    try:
        return ip_interface(value)
    except ValueError:
        raise ValueError("Invalid Shadow interface address") from None


def _check_ipv4(value):
    if not isinstance(value, str):
        return False
    try:
        return str(IPv4Address(value)) == value
    except ValueError:
        return False


def _project_interface(node):
    if not isinstance(node, dict):
        raise ValueError("Invalid Shadow interface configuration")
    result = {field: {} for field in ("disable", "vrf") if field in node}
    if "address" in node:
        address = node["address"]
        values = [address] if isinstance(address, str) else address
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise ValueError("Invalid Shadow interface address list")
        for value in values:
            if value not in ("dhcp", "dhcpv6"):
                _as_address(value)
        result["address"] = address
    for kind in ("vif", "vif-s", "vif-c"):
        if kind in node:
            result[kind] = {tag: _project_interface(child) for tag, child in _named_items(node[kind])}
    return result


def _checked_fields(node, allowed, label):
    if not isinstance(node, dict) or any(field not in allowed or not allowed[field](value) for field, value in node.items()):
        raise ValueError(f"Unsupported {label} configuration")
    return node


def _name(value):
    return _matches(_NAME, value)


def _numeric(value):
    return _matches(_NUMERIC, value)


def _project_vrrp_group(node, *, managed):
    label = "managed Shadow VRRP" if managed else "operator VRRP"
    if not isinstance(node, dict):
        raise ValueError(f"Invalid {label} group")
    addresses = ("address", "excluded-address")
    fields = {"interface": _name, "vrid": _numeric}
    if managed:
        fields.update({"priority": _numeric, "advertise-interval": _numeric, "hello-source-address": _check_ipv4,
                       "peer-address": _check_ipv4, "no-preempt": lambda value: value == {}})
    values = {key: value for key, value in node.items() if key not in addresses and (managed or key in fields)}
    result = dict(_checked_fields(values, fields, label))
    for kind in addresses:
        if kind not in node:
            continue
        if not isinstance(node[kind], dict):
            raise ValueError(f"Invalid {label} virtual addresses")
        result[kind] = {}
        for cidr, options in node[kind].items():
            _as_address(cidr)
            result[kind][cidr] = _checked_fields(options, {"interface": _name}, label) if managed else {}
    return result


def _members(value):
    if isinstance(value, str):
        return _name(value)
    return isinstance(value, list) and all(_name(name) for name in value)


def _project_sync_group(node, *, managed):
    if not isinstance(node, dict):
        raise ValueError("Invalid Shadow VRRP sync group")
    fields = {"member": _members}
    if managed:
        fields["health-check"] = lambda value: bool(_checked_fields(value, {
            "script": lambda script: script == _GUARD_PATH, "interval": _numeric,
            "timeout": _numeric, "failure-count": _numeric,
        }, "managed Shadow VRRP health check"))
    return _checked_fields({key: value for key, value in node.items() if managed or key == "member"},
                           fields, "Shadow VRRP sync group")


def _project_conntrack(node):
    def interfaces(rows):
        return all(_checked_fields(value, {"peer": _check_ipv4}, "Shadow conntrack interface")
                   for _, value in _named_items(rows))

    return _checked_fields(node, {
        "interface": interfaces, "listen-address": _check_ipv4, "startup-resync": lambda value: value == {},
        "accept-protocol": lambda value: value == "tcp",
        "failover-mechanism": lambda value: value == {"vrrp": {"sync-group": "UXGHA"}},
    }, "Shadow conntrack sync")


def _project_shadow_configuration(tree):
    result = {}
    present, interfaces = _select(tree, ("interfaces",))
    if present:
        result["interfaces"] = {kind: {name: _project_interface(node) for name, node in _named_items(nodes)}
                                for kind, nodes in _named_items(interfaces)}
    present, vrrp = _select(tree, ("high-availability", "vrrp"))
    if present:
        if not isinstance(vrrp, dict):
            raise ValueError("Invalid Shadow VRRP inventory")
        projection = {}
        if "group" in vrrp:
            projection["group"] = {name: _project_vrrp_group(node, managed=name == "UXGSHADOW")
                                   for name, node in _named_items(vrrp["group"])}
        if "sync-group" in vrrp:
            projection["sync-group"] = {name: _project_sync_group(node, managed=name == "UXGHA")
                                        for name, node in _named_items(vrrp["sync-group"])}
        result["high-availability"] = {"vrrp": projection}
    present, conntrack = _select(tree, _MANAGED_CONNTRACK)
    if present:
        result["service"] = {"conntrack-sync": _project_conntrack(conntrack)}
    return result


def _read_shadow_observation():
    boot = _BOOT_ID_PATH.read_text(encoding="ascii").strip()
    if not _matches(_UUID, boot):
        raise ValueError("Invalid boot ID in Shadow configuration observation")
    preimage = _SAVED_CONFIG_PATH.read_bytes()
    running = _project_shadow_configuration(_decode_configuration(_active_configuration_text()))
    saved = _project_shadow_configuration(_decode_configuration(preimage.decode("utf-8")))
    if _BOOT_ID_PATH.read_text(encoding="ascii").strip() != boot or _SAVED_CONFIG_PATH.read_bytes() != preimage:
        raise ValueError("Boot or saved configuration changed during Shadow observation")
    return {"boot_id": boot, "saved_sha256": hashlib.sha256(preimage).hexdigest(), "running": running, "saved": saved}


def _prove_saved():
    result = subprocess.run(
        ["/usr/bin/sg", "vyattacfg", "-c", str(RECEIPT_DIRECTORY / "preflight.vbash")],
        capture_output=True, text=True, timeout=5, check=True,
        env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
             "SSH_ORIGINAL_COMMAND": "/bin/false uxg-commit-saved"},
    )
    match = re.fullmatch(rf"uxg-commit-saved ({_UUID.pattern}) ({_DIGEST.pattern})\n", result.stdout)
    if match is None:
        raise ValueError("VyOS did not return a verified saved commit and boot ID")
    return match.groups()


def _candidate(paths, observe, prove_saved):
    boot, commit = initial = prove_saved()
    if not _matches(_UUID, boot) or not _matches(_DIGEST, commit):
        raise ValueError("VyOS did not return a verified saved commit and boot ID")
    path_list = [list(path) for path in paths]
    active, saved = observe()
    _verify_managed_configuration(active)
    _verify_managed_configuration(saved)
    firewall = [path for path in paths if path[0] == "firewall"]
    if any(not any(_select(tree, path)[0] for path in firewall) for tree in (active, saved)):
        raise ValueError("The verified Shadow scope does not cover a configured firewall path")
    digest = policy_digest(active, path_list)
    if policy_digest(saved, path_list) != digest or prove_saved() != initial:
        raise ValueError("Shadow policy changed during the saved configuration proof")
    return {"boot_id": boot, "sha256": digest, "config_sha256": commit}


def _receipt_status(raw, state):
    record_id = hashlib.sha256(raw).hexdigest() if raw else _FIRST_GENERATION
    receipt = None
    if "paths" in state:
        receipt = {"id": record_id, "sha256": state["sha256"], "transaction": state.get("transaction"),
                   "config_sha256": state.get("config_sha256")}
    return {"receipt": receipt, "generation": state.get("generation", record_id)}


def _write_receipt_state(directory_fd, receipt, *, initial=False):
    raw = (json.dumps(receipt, separators=(",", ":")) + "\n").encode("ascii")
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ValueError("Shadow policy receipt is too large")
    name = f".receipt-{secrets.token_hex(16)}"
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if initial:
            os.link(name, RECEIPT_NAME, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
        else:
            os.replace(name, RECEIPT_NAME, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        try:
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
    return _receipt_status(raw, receipt)


def _request_operation(request):
    action = request.get("op") if isinstance(request, dict) else None
    scoped_candidate = action == "candidate" and request.keys() == {"op", "required_paths"}
    if (not isinstance(action, str) or action not in _REQUEST_FIELDS
            or (not scoped_candidate and request.keys() != _REQUEST_FIELDS[action])
            or any(not _matches(_UUID, request[field]) for field in ("transaction", "boot_id") if field in request)
            or any(not _matches(_DIGEST, request[field])
                   for field in ("sha256", "receipt_id", "generation", "config_sha256") if field in request)):
        raise ValueError("Invalid Shadow receipt request")
    if "required_paths" in request:
        _policy_paths(request["required_paths"])
    return action


def manage_receipt(receipt_directory, owner, request, *, observe, prove_saved):
    action = _request_operation(request)
    directory_fd = os.open(receipt_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        directory = os.fstat(directory_fd)
        if directory.st_uid != owner or directory.st_mode & 0o022:
            raise ValueError("Unsafe Shadow receipt directory")
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
        with os.fdopen(os.open(".receipt.lock", flags, 0o600, dir_fd=directory_fd), "r+") as lock:
            entry = os.fstat(lock.fileno())
            if not stat.S_ISREG(entry.st_mode) or entry.st_uid != owner or entry.st_mode & 0o077:
                raise ValueError("Unsafe Shadow receipt lock")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return _manage_locked(directory_fd, owner, action, request, observe, prove_saved)
    finally:
        os.close(directory_fd)


def _manage_locked(directory_fd, owner, action, request, observe, prove_saved):
    if action == "observe":
        return _read_shadow_observation()
    raw, state = _read_receipt_state(directory_fd, owner)
    status = _receipt_status(raw, state)
    existing = status["receipt"]
    generation = status["generation"]
    if action == "status":
        return status
    if action == "observe-vrrp":
        if existing is not None or request["generation"] != generation:
            raise ValueError("Shadow VRRP observation requires the verified empty receipt slot")
        return _observe_standby_vrrp(request, observe, prove_saved)
    if action == "revoke":
        if existing is not None:
            if request["receipt_id"] != existing["id"]:
                raise ValueError("Shadow receipt changed before revocation")
            return _write_receipt_state(directory_fd, {"revoked": existing["id"]})
        if state.get("revoked") != request["receipt_id"]:
            raise ValueError("Shadow receipt changed before revocation")
        return status
    if action == "fence":
        if existing is not None:
            raise ValueError("Revoke the installed Shadow receipt by ID before fencing its slot")
        target = request["generation"]
        if state.get("revoked") == target:
            return status
        if target != generation:
            raise ValueError("Shadow receipt generation changed before fencing")
        return _write_receipt_state(directory_fd, {"revoked": target}, initial=not raw)
    scope = _read_managed_scope(directory_fd, owner)
    if scope is None:
        raise ValueError("A router-local Shadow policy scope is required")
    if "required_paths" in request:
        if any(not any(path[:len(parent)] == parent for parent in scope)
               for path in _policy_paths(request["required_paths"])):
            raise ValueError("The router-local Shadow policy scope does not cover the required paths")
    if action == "check-admission":
        if existing is not None:
            raise ValueError("Shadow admission requires an empty receipt slot")
        if prove_saved() != (request["boot_id"], request["config_sha256"]):
            raise ValueError("Shadow admission requires the independently verified saved configuration")
        if _read_managed_scope(directory_fd, owner) != scope or _read_receipt_state(directory_fd, owner)[0] != raw:
            raise ValueError("Router-local Shadow receipt state changed during admission")
        return {"ready": True}
    candidate = _candidate(scope, observe, prove_saved)
    if _read_managed_scope(directory_fd, owner) != scope or _read_receipt_state(directory_fd, owner)[0] != raw:
        raise ValueError("Router-local Shadow receipt state changed during verification")
    if action == "candidate":
        return candidate | {"generation": generation}
    if request["generation"] != generation:
        raise ValueError("Shadow receipt generation changed before publication")
    if any(request[field] != value for field, value in candidate.items()):
        raise ValueError("Shadow receipt must match the verified boot, commit and policy")
    if existing is not None:
        if any(existing[field] != request[field] for field in ("sha256", "config_sha256", "transaction")):
            raise ValueError("Revoke the current Shadow receipt before publishing a different receipt")
        if _policy_paths(state["paths"]) != scope:
            raise ValueError("The current Shadow receipt uses a different policy scope")
        return status
    return _write_receipt_state(directory_fd, {
        "paths": scope, "sha256": request["sha256"], "config_sha256": request["config_sha256"],
        "transaction": request["transaction"], "generation": generation,
    }, initial=not raw)


def policy_is_eligible(receipt_directory, owner, observe):
    try:
        directory_fd = os.open(receipt_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            directory = os.fstat(directory_fd)
            if directory.st_uid != owner or directory.st_mode & 0o022:
                return False
            raw, receipt = _read_receipt_state(directory_fd, owner)
            if "paths" not in receipt:
                return False
            scope = _read_managed_scope(directory_fd, owner)
            if ("transaction" in receipt) != (scope is not None) or (
                    scope is not None and _policy_paths(receipt["paths"]) != scope):
                return False
            active, saved = observe()
            if any(policy_digest(tree, receipt["paths"]) != receipt["sha256"] for tree in (active, saved)):
                return False
            current = os.stat(receipt_directory, follow_symlinks=False)
            return (os.path.samestat(directory, current) and _read_receipt_state(directory_fd, owner)[0] == raw
                    and _read_managed_scope(directory_fd, owner) == scope)
        finally:
            os.close(directory_fd)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        return False


def main():
    if len(sys.argv) == 1:
        return int(not policy_is_eligible(RECEIPT_DIRECTORY, 0, read_configurations))
    if sys.argv[1:] != ["--manage"] or os.geteuid() != 0:
        return 1
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if not 0 < len(raw) <= MAX_REQUEST_BYTES:
            raise ValueError("Shadow receipt request size is invalid")
        request = json.loads(raw, object_pairs_hook=_unique_object)
        result = manage_receipt(RECEIPT_DIRECTORY, 0, request, observe=read_configurations, prove_saved=_prove_saved)
        encoded = json.dumps(result, separators=(",", ":"))
        if len(encoded) + 1 > MAX_RESPONSE_BYTES:
            raise ValueError("Shadow observation response is too large")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print("VyOS Shadow receipt request could not be verified", file=sys.stderr)
        return 1
    print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
