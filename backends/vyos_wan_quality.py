"""Read measured WAN reachability from fixed operator-owned VyOS helpers."""

from dataclasses import dataclass
from ipaddress import IPv4Address
import json
import os
import re
from urllib.parse import urlsplit

from backends.vyos import VyOSReadError
from backends.vyos_failover import _invalid_constant, _read_helper, _run_helper, _unique_fields
from backends.vyos_wan_ping import decode_ping
from backends.vyos_ssh import vyos_ssh_command


_WAN_GROUPS = {"wan": "WAN", "wan2": "WAN2", "wan3": "WAN3"}
_FIELDS = {"interface", "target", "sent", "received", "latency_ms"}


@dataclass(frozen=True)
class WanProbe:
    interface: str
    target: str
    command: str | tuple[str, ...]

    def read(self):
        if isinstance(self.command, tuple):
            body, status = _run_helper(self.command, reader="VyOS WAN SSH probe", limit=4096, merge_stderr=True)
            if status == 255:
                raise VyOSReadError("VyOS WAN SSH transport failed before a verified probe result (OpenSSH exit 255)")
            try:
                sent, received, latency = decode_ping(body, self.interface, self.target, status)
            except ValueError as error:
                raise VyOSReadError("VyOS WAN SSH probe returned an invalid or mismatched measurement") from error
            return {"interface": self.interface, "target": self.target, "sent": sent,
                    "received": received, "latency_ms": latency}

        body = _read_helper(self.command, reader="VyOS WAN probe")
        try:
            row = json.loads(body, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
            if (type(row) is not dict or row.keys() != _FIELDS or row["interface"] != self.interface
                    or row["target"] != self.target):
                raise ValueError
            sent, received, latency = (row[name] for name in ("sent", "received", "latency_ms"))
            if type(sent) is not int or sent != 3 or type(received) is not int or not 0 <= received <= sent:
                raise ValueError
            if received == 0:
                if latency is not None:
                    raise ValueError
            elif type(latency) not in (int, float) or not 0 <= latency <= 4000:
                raise ValueError
        except (ValueError, RecursionError):
            raise VyOSReadError("VyOS WAN probe returned an invalid or mismatched measurement") from None
        return row


def configured_wan_probes(section, ports, *, api_url=""):
    """Bind each opt-in probe to one explicitly mapped WAN and one IPv4 target."""
    try:
        raw = json.loads(section["probes"], object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
        if type(raw) is not dict or not 1 <= len(raw) <= len(_WAN_GROUPS):
            raise ValueError
        mapping = {}
        for name, options in raw.items():
            matches = [port for port in ports if port["ifname"] == name]
            if len(matches) != 1 or type(options) is not dict or options.keys() not in (
                {"target", "command"}, {"target", "ssh_key_file"},
            ):
                raise ValueError
            port = matches[0]
            group = _WAN_GROUPS[port["type"]]
            interface, target = port["realif"], options["target"]
            if (group in mapping or type(interface) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", interface)
                    or type(target) is not str):
                raise ValueError
            address = IPv4Address(target)
            if address.packed[0] == 0 or address.is_multicast or address.is_reserved or address.is_loopback:
                raise ValueError
            mapping[group] = (name, interface, options)
    except (KeyError, ValueError, RecursionError):
        raise ValueError("WAN probes require unique mapped WAN groups and literal IPv4 targets") from None

    probes = {}
    for group, (name, interface, options) in mapping.items():
        if "command" in options:
            command = options["command"]
            if type(command) is not str or not os.path.isabs(command) or "\x00" in command:
                raise ValueError("A WAN probe command must be an absolute executable path")
        else:
            host = urlsplit(api_url).hostname
            if not host or section.get("ssh_host", host) != host:
                raise ValueError("WAN probe SSH must use the same VyOS management host as HTTPS")
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,14}", interface):
                raise ValueError("WAN probe SSH requires a stock interface name starting with a letter or underscore")
            port = int(section.get("ssh_port", "22"), 10)
            command = tuple(vyos_ssh_command(
                host, port, section.get("ssh_user"), options["ssh_key_file"], section.get("ssh_known_hosts_file"),
            ))
        probes[group] = (name, WanProbe(interface, options["target"], command))
    return probes
