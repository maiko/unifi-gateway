#!/usr/bin/python3 -I
"""Run fixed Shadow Mode observations from a restricted SSH key on stock VyOS."""

from ipaddress import IPv4Address, IPv4Network
import json
import os
import re
import subprocess
import sys


PEERS = {
    "/bin/false uxg-shadow-peer-primary": ("169.254.254.2", "169.254.254.3"),
    "/bin/false uxg-shadow-peer-secondary": ("169.254.254.3", "169.254.254.2"),
}
LAN_SOURCE = "/bin/false uxg-shadow-lan-source"
LAN_PEER = "/bin/false uxg-shadow-lan-peer"
IP_ROUTE = ("/usr/sbin/ip", "-j", "-4", "route", "get")
MAX_OUTPUT = 4096


def read_route(*arguments):
    result = subprocess.run(
        [*IP_ROUTE, *arguments], check=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=1.5, env={"LC_ALL": "C"},
    )
    if len(result.stdout) > MAX_OUTPUT:
        raise ValueError("Unexpected route output size")
    routes = json.loads(result.stdout)
    if not isinstance(routes, list) or len(routes) != 1 or not isinstance(routes[0], dict):
        raise ValueError("Expected a single kernel route")
    return routes[0]


def lan_host(interconnect, interface, network_text, target_text):
    if interface == interconnect or re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}", interface) is None:
        raise ValueError("Expected a separate configured LAN interface")
    network = IPv4Network(network_text)
    target = IPv4Address(target_text)
    if (str(network) != network_text or target not in network or not 0 < network.prefixlen < 32
            or target.is_multicast or target.is_unspecified or target.is_loopback
            or (network.prefixlen < 31 and target in (network.network_address, network.broadcast_address))):
        raise ValueError("Expected a host in the configured IPv4 LAN prefix")
    return network, target


def read_lan_source(interconnect, interface, network_text, target_text):
    network, target = lan_host(interconnect, interface, network_text, target_text)
    fib = read_route("fibmatch", str(target))
    route = read_route(str(target))
    if fib.get("dst") != str(network) or route.get("dst") != str(target) or any(
            row.get("dev") != interface for row in (fib, route)):
        raise ValueError("Kernel routes disagree with the configured LAN prefix or interface")
    body = json.dumps({"fib": fib, "route": route}, separators=(",", ":"))
    if len(body) + 1 > MAX_OUTPUT:
        raise ValueError("Unexpected route output size")
    print(body)


def ping(interface, source, target):
    executable = "/usr/bin/ping"
    # A ping deadline overrides the count when no replies arrive.
    os.execve(executable, [executable, "-4", "-n", "-q", "-I", interface, "-I", source,
                           "-c", "3", "-i", "0.2", "-W", "1", target], {"LC_ALL": "C"})


def main():
    if len(sys.argv) not in (2, 5, 7) or re.fullmatch(r"eth[0-9]{1,11}", sys.argv[1]) is None:
        raise SystemExit("Shadow Mode probe requires the configured physical interface")
    request = os.environ.get("SSH_ORIGINAL_COMMAND")
    if request == LAN_SOURCE and len(sys.argv) in (5, 7):
        try:
            read_lan_source(*sys.argv[1:5])
        except (OSError, subprocess.SubprocessError, ValueError):
            raise SystemExit("VyOS Shadow LAN source is unavailable") from None
        return
    if request == LAN_PEER and len(sys.argv) == 7:
        interconnect, interface, prefix, probe, local, peer = sys.argv[1:]
        try:
            endpoints = [lan_host(interconnect, interface, prefix, value)[1] for value in (probe, local, peer)]
            if len(set(endpoints)) != 3:
                raise ValueError("Shadow LAN endpoints must be distinct")
        except ValueError:
            raise SystemExit("Invalid pinned VyOS Shadow LAN peer") from None
        ping(interface, str(endpoints[1]), str(endpoints[2]))
        return
    peer = PEERS.get(request)
    if peer is None:
        raise SystemExit("Unsupported Shadow Mode probe request")
    source, target = peer
    ping(sys.argv[1], source, target)


if __name__ == "__main__":
    main()
