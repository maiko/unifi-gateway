"""Read VyOS kernel routes and verify the forwarding lookup for a fixed probe."""

from contextlib import suppress
from ipaddress import IPv4Address, IPv4Network
import json
import os
import re
from selectors import DefaultSelector, EVENT_READ
import signal
import subprocess
import time
from urllib.parse import urlsplit

from backends.vyos import VyOSReadError
from backends.vyos_ssh import vyos_ssh_command


_PROBE = {"destination": "198.19.210.242", "source": "192.168.120.2", "interface": "eth3.120"}
_TIMEOUT_SECONDS = 5
_MAX_BYTES = 256 * 1024
_INVENTORY_FIELDS = {"dst", "gateway", "dev", "metric", "flags"}
_LOOKUP_FIELDS = _INVENTORY_FIELDS | {"table", "protocol", "type", "scope", "prefsrc"}
_LOCAL_ROUTE_TYPES = {"local", "broadcast", "multicast", "unicast"}
_TERMINAL_ROUTE_TYPES = {"blackhole", "unreachable", "prohibit", "throw"}
_FAILOVER_PROTOCOLS = {111, "111", "failover"}
_ROUTING_REQUESTS = {"wan": "/bin/false uxg-wan-fib", "policy": "/bin/false uxg-policy-route-fib"}


class VyOSRoutingSSH:
    """Read a fixed routing snapshot on the same pinned host as the VyOS API."""

    def __init__(self, host, port, user, key_file, known_hosts_file):
        self._ssh = vyos_ssh_command(host, port, user, key_file, known_hosts_file)
        self.endpoint = {"host": host, "port": port, "user": user}

    @classmethod
    def from_config(cls, config):
        settings = config["vyos_routing_ssh"]
        host = urlsplit(config["vyos"]["api_url"]).hostname
        return cls(host, settings.getint("ssh_port", 22), settings["ssh_user"],
                   settings["ssh_key_file"], settings["ssh_known_hosts_file"])

    def read(self, kind):
        body, status = _run_helper([*self._ssh[:-1], _ROUTING_REQUESTS[kind]], reader="VyOS routing SSH reader")
        if status != 0:
            raise VyOSReadError("VyOS routing SSH reader exited unsuccessfully")
        return body


def read_failover_fib(command: str | VyOSRoutingSSH) -> dict:
    """Read bounded JSON containing the pinned probe, its fibmatch, and all-table protocol 111 rows.

    The helper takes no arguments. The result has exactly three keys: ``probe``
    contains the pinned destination, source, and interface, ``routes`` is an
    array of IPv4 ``ip -j route show table all proto 111`` rows, and ``lookup``
    is a single ``ip -j route get fibmatch`` row or null when no route exists.
    The caller compares the inventory with the routes it owns.
    """
    if isinstance(command, VyOSRoutingSSH):
        body = command.read("wan")
    else:
        if not isinstance(command, str) or not os.path.isabs(command) or "\x00" in command:
            raise VyOSReadError("VyOS failover reader requires an absolute executable path")
        body = _read_helper(command)
    try:
        snapshot = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except (ValueError, RecursionError):
        raise VyOSReadError("VyOS failover reader returned invalid JSON") from None
    if (
        not isinstance(snapshot, dict) or snapshot.keys() != {"probe", "routes", "lookup"}
        or snapshot["probe"] != _PROBE or not isinstance(snapshot["routes"], list)
    ):
        raise VyOSReadError("VyOS failover reader returned an invalid snapshot envelope")

    try:
        routes = snapshot["routes"]
        for row in routes:
            _validate_row(row, lookup=False)
        lookup = snapshot["lookup"]
        if lookup is not None:
            network = _validate_row(lookup, lookup=True)
            if IPv4Address(_PROBE["destination"]) not in network:
                raise ValueError("Lookup does not cover the pinned destination")
            if lookup["protocol"] in _FAILOVER_PROTOCOLS and not any(
                _route_identity(lookup) == _route_identity(row) for row in routes
            ):
                raise ValueError("The selected failover route is absent from the inventory")
    except ValueError:
        raise VyOSReadError("VyOS failover reader returned an invalid or inconsistent route snapshot") from None
    return snapshot


def _read_helper(command, *, reader="VyOS failover reader"):
    body, status = _run_helper([command], reader=reader)
    if status != 0:
        raise VyOSReadError(f"{reader} exited unsuccessfully")
    return body


def _run_helper(argv, *, reader, limit=_MAX_BYTES, merge_stderr=False, stdin=subprocess.DEVNULL, timeout=_TIMEOUT_SECONDS):
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(
            argv, stdin=stdin, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge_stderr else subprocess.DEVNULL,
            bufsize=0, start_new_session=True,
        )
    except (OSError, ValueError):
        raise VyOSReadError(f"{reader} could not start") from None

    body = bytearray()
    with process:
        try:
            with DefaultSelector() as selector:
                selector.register(process.stdout, EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise subprocess.TimeoutExpired(argv, timeout)
                    chunk = process.stdout.read(min(65536, limit - len(body) + 1))
                    if not chunk:
                        break
                    body.extend(chunk)
                    if len(body) > limit:
                        raise VyOSReadError(f"{reader} response exceeds the size limit")
            status = process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise VyOSReadError(f"{reader} timed out") from None
        except OSError:
            raise VyOSReadError(f"{reader} output could not be read") from None
        finally:
            if process.returncode is None:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
    return body, status


def _validate_row(row, *, lookup):
    required = {"dst", "protocol", "flags"} if lookup else _INVENTORY_FIELDS
    allowed = _LOOKUP_FIELDS if lookup else _INVENTORY_FIELDS | {"table"}
    if not isinstance(row, dict) or not required <= row.keys() <= allowed:
        raise ValueError("Unexpected route fields")
    destination = _prefix(row["dst"])
    flags = row["flags"]
    if not isinstance(flags, list) or any(not _token(flag) for flag in flags) or len(flags) != len(set(flags)):
        raise ValueError("Invalid route flags")
    if "table" in row and not (_token(row["table"]) or _integer(row["table"], 1, 0xFFFFFFFF)):
        raise ValueError("Invalid route table")
    if "metric" in row and not _integer(row["metric"], 0, 0xFFFFFFFF):
        raise ValueError("Invalid route metric")
    if "dev" in row and not _token(row["dev"], max_length=15):
        raise ValueError("Invalid route device")
    for field in ("gateway", "prefsrc"):
        if field in row and (not isinstance(row[field], str) or str(IPv4Address(row[field])) != row[field]):
            raise ValueError("Invalid route address")
    if lookup:
        protocol = row["protocol"]
        route_type = row.get("type", "unicast")
        if not (_token(protocol) or _integer(protocol, 0, 255)) or not isinstance(route_type, str):
            raise ValueError("Invalid FIB route protocol or type")
        if route_type in _LOCAL_ROUTE_TYPES:
            if "dev" not in row:
                raise ValueError("Missing FIB route device")
        elif route_type not in _TERMINAL_ROUTE_TYPES or "dev" in row or "gateway" in row:
            raise ValueError("Invalid terminal FIB route")
        if "scope" in row and not _token(row["scope"]):
            raise ValueError("Invalid FIB route scope")
    return destination


def _prefix(value):
    if not isinstance(value, str):
        raise ValueError("IPv4 destination must be a string")
    network = IPv4Network("0.0.0.0/0" if value == "default" else value)
    if value not in {"default", str(network)} and (network.prefixlen != 32 or value != str(network.network_address)):
        raise ValueError("Noncanonical IPv4 destination")
    return network


def _route_identity(row):
    table = row.get("table", "main")
    return (_prefix(row["dst"]), row.get("gateway"), row.get("dev"), row.get("metric"),
            254 if table in {"main", "254"} else table)


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _token(value, *, max_length=32):
    return isinstance(value, str) and 1 <= len(value) <= max_length and re.fullmatch(r"[A-Za-z0-9_.-]+", value)


def _unique_fields(pairs):
    data = dict(pairs)
    if len(data) != len(pairs):
        raise ValueError("Duplicate payload field")
    return data


def _invalid_constant(_value):
    raise ValueError("Non-JSON numeric constant")
