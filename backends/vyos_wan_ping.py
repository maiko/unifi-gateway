#!/usr/bin/env python3
"""Measure a three-packet IPv4 ICMP sample on one stock VyOS interface."""

from ipaddress import IPv4Address
import json
import re
import subprocess
import sys


_PACKET_COUNT = 3
_MAX_OUTPUT = 4096
_INTERFACE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,14}")
_PACKETS = re.compile(
    r"([0-9]{1,4}) packets transmitted, ([0-9]{1,4}) received"
    r"(?:, \+[0-9]+ (?:duplicates|corrupted|errors))*"
    r", [0-9]+(?:\.[0-9]+)?% packet loss, time [0-9]+ms"
)
_MS = r"[0-9]{1,8}\.[0-9]{3}"
_RTT = re.compile(rf"rtt min/avg/max/mdev = ({_MS})/({_MS})/({_MS})/{_MS} ms(?:, pipe [0-9]+)?")


def decode_ping(output, interface, target, result_code, *, source=None):
    try:
        lines = [line for line in output.decode("ascii").splitlines() if line]
    except UnicodeDecodeError:
        raise ValueError("WAN probe returned non-ASCII ping statistics") from None
    if (
        not 3 <= len(lines) <= 4
        or not lines[0].startswith(f"PING {target} ({target}) from ")
        or not lines[0].endswith(f" {interface}: 56(84) bytes of data.")
        or lines[1] != f"--- {target} ping statistics ---"
    ):
        raise ValueError("WAN probe returned invalid interface or peer statistics")
    if source is not None and lines[0] != f"PING {target} ({target}) from {source} {interface}: 56(84) bytes of data.":
        raise ValueError("Ping statistics did not use the verified source address")

    packets = _PACKETS.fullmatch(lines[2])
    if packets is None:
        raise ValueError("WAN probe did not return a packet summary")
    sent, received = map(int, packets.groups())
    if sent != _PACKET_COUNT or received > sent or result_code != (0 if received else 1):
        raise ValueError("WAN probe returned inconsistent packet counts or exit status")
    if not received:
        if len(lines) == 4 and re.fullmatch(r"pipe [0-9]+", lines[3]) is None:
            raise ValueError("WAN probe reported latency without replies")
        return sent, received, None

    rtt = _RTT.fullmatch(lines[3]) if len(lines) == 4 else None
    if rtt is None:
        raise ValueError("WAN probe did not return RTT statistics for the replies")
    lowest, average, highest = map(float, rtt.groups())
    if not lowest <= average <= highest:
        raise ValueError("WAN probe returned inconsistent RTT statistics")
    return sent, received, average


def probe(interface, target):
    if _INTERFACE.fullmatch(interface) is None:
        raise ValueError("WAN probe requires a valid VyOS interface name")
    try:
        address = IPv4Address(target)
    except ValueError:
        raise ValueError("WAN probe requires a literal unicast IPv4 target") from None
    if address.packed[0] == 0 or address.is_loopback or address.is_multicast or address.is_reserved:
        raise ValueError("WAN probe requires a literal unicast IPv4 target")
    target = str(address)

    # With -w, ping can continue past -c until it receives three replies.
    command = ["/usr/bin/ping", "-4", "-n", "-q", "-I", interface, "-c", str(_PACKET_COUNT),
               "-i", "0.2", "-W", "2", target]
    try:
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=4, env={"LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired:
        raise ValueError("WAN probe timed out before returning ping statistics") from None
    except OSError:
        raise ValueError("WAN probe could not start stock /usr/bin/ping") from None

    if result.returncode not in (0, 1) or result.stderr:
        raise ValueError("WAN probe could not complete ping on the specified interface")
    if len(result.stdout) > _MAX_OUTPUT:
        raise ValueError("WAN probe exceeded the ping output limit")
    sent, received, latency = decode_ping(result.stdout, interface, target, result.returncode)
    return {"interface": interface, "target": target, "sent": sent, "received": received, "latency_ms": latency}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: vyos_wan_ping.py INTERFACE IPV4_TARGET")
    try:
        print(json.dumps(probe(*sys.argv[1:])))
    except ValueError as error:
        raise SystemExit(str(error)) from None
