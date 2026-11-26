#!/usr/bin/env python3
"""Read qdiscs on eth3.110 and eth3.210 and the VyOS IPv4 forwarding chain."""

import json
import subprocess
import sys


def unique_fields(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("Duplicate field in the VyOS QoS read-back")
    return fields


def read_json(command, *, missing_forward_chain=False):
    result = subprocess.run(command, check=False, capture_output=True, timeout=2)
    if (missing_forward_chain and result.returncode == 1 and not result.stdout
            and result.stderr.startswith(b"Error: No such file or directory\n")):
        return None
    result.check_returncode()
    return json.loads(result.stdout, object_pairs_hook=unique_fields)


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("The fixed QoS reader takes no arguments")
    managed = ("eth3.110", "eth3.210")
    devices = {row["ifname"] for row in read_json(["/usr/sbin/ip", "-j", "link", "show"])}
    all_qdiscs = read_json(["/usr/sbin/tc", "-j", "-d", "qdisc", "show"])
    if devices != {row["dev"] for row in all_qdiscs} or not set(managed).issubset(devices):
        raise SystemExit("The kernel queue inventory does not cover the live router interfaces")
    print(json.dumps({
        "interfaces": {
            interface: {kind: read_json(["/usr/sbin/tc", "-j", "-d", kind, "show", "dev", interface])
                        for kind in ("qdisc", "class", "filter")}
            for interface in managed
        },
        "other_qdiscs": [row for row in all_qdiscs if row["dev"] not in managed],
        "forward": read_json(["/usr/sbin/nft", "-j", "list", "chain", "ip", "vyos_filter", "VYOS_FORWARD_filter"],
                             missing_forward_chain=True),
    }))
