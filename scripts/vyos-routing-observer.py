#!/usr/bin/env python3
"""Read IPv4 failover routes and policy-routing state from the VyOS kernel."""

import json
import os
import subprocess
import sys


_WAN_PROBE = {"destination": "198.19.210.242", "source": "192.168.120.2", "interface": "eth3.120"}


def read_json(command, *, missing_nft_table=False, missing_ipv4_table=False):
    result = subprocess.run(command, check=False, capture_output=True, timeout=2)
    if (missing_nft_table and result.returncode == 1 and not result.stdout
            and result.stderr.startswith(b"Error: No such file or directory\n")):
        return {"nftables": []}
    if (missing_ipv4_table and result.returncode == 2 and result.stdout == b"[]\n"
            and result.stderr == b"Error: ipv4: FIB table does not exist.\nDump terminated\n"):
        return []
    result.check_returncode()
    return json.loads(result.stdout)


def read_wan_fib():
    ip = ["/usr/sbin/ip", "-j", "-4", "route"]
    routes = read_json([*ip, "show", "table", "all", "proto", "111"])
    if not isinstance(routes, list):
        raise ValueError("The VyOS WAN route inventory must be an array")
    command = [*ip, "get", "fibmatch", _WAN_PROBE["destination"],
               "from", _WAN_PROBE["source"], "iif", _WAN_PROBE["interface"]]
    result = subprocess.run(command, check=False, capture_output=True, timeout=2, env={**os.environ, "LC_ALL": "C"})
    if result.returncode == 2 and not result.stdout and result.stderr == b"RTNETLINK answers: Network is unreachable\n":
        return {"probe": _WAN_PROBE, "routes": routes, "lookup": None}
    result.check_returncode()
    lookup = json.loads(result.stdout)
    if not isinstance(lookup, list) or len(lookup) != 1 or not isinstance(lookup[0], dict):
        raise ValueError("The VyOS WAN route lookup must return one route")
    return {"probe": _WAN_PROBE, "routes": routes, "lookup": lookup[0]}


def read_policy_route_fib(*, ssh):
    ip = ["/usr/sbin/ip", "-j", "-N"]
    nft = ["/usr/bin/sudo", "-n"] if ssh else []
    nft.extend(["/usr/sbin/nft", "-j", "list"])
    return {
        "ipv4_rules": read_json([*ip, "-4", "rule", "show"]),
        "ipv6_rules": read_json([*ip, "-6", "rule", "show"]),
        "table": read_json([*ip, "-4", "route", "show", "table", "179"], missing_ipv4_table=True),
        "nft": read_json([*nft, "table", "ip", "vyos_mangle"], missing_nft_table=True),
        "forward": read_json([*nft, "chain", "ip", "vyos_filter", "VYOS_FORWARD_filter"], missing_nft_table=True),
    }


if __name__ == "__main__":
    if len(sys.argv) == 1:
        snapshot = read_policy_route_fib(ssh=False)
    elif sys.argv[1:] == ["--ssh-observer"]:
        request = os.environ.get("SSH_ORIGINAL_COMMAND")
        if request == "/bin/false uxg-wan-fib":
            snapshot = read_wan_fib()
        elif request == "/bin/false uxg-policy-route-fib":
            snapshot = read_policy_route_fib(ssh=True)
        else:
            raise SystemExit("Unexpected VyOS routing observation request")
    else:
        raise SystemExit("Unexpected VyOS routing reader arguments")
    print(json.dumps(snapshot))
