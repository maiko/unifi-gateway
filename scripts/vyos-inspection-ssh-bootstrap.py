#!/usr/bin/env python3
"""Render a fixed SSH key for a VyOS bridge operation.

Use a dedicated ED25519 key pair. The source address is the bridge's management
IPv4 address as seen by VyOS. Choose an existing VyOS account and check that
the reserved key label is free or already belongs to this bridge.

Supply --listen-address only to add an address to an existing explicit list of
SSH listeners. Verify the management firewall and retain independent console
access. In VyOS configuration mode, review the commands and use commit-confirm.
Confirm and save after verifying the bridge and existing management access.
"""

import argparse
from base64 import b64decode
from binascii import Error as Base64Error
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
import re


_KEY_LABEL = "unifi-gateway-inspection"
_WIRE_PREFIX = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
_RUNNER = "sudo -n /opt/unifi-gateway-vyos-inspection/run"
_RESTART_PREFLIGHT = "/usr/bin/sg vyattacfg -c /config/scripts/vyos-restart-preflight.vbash"
_ROUTING_OBSERVER = "/usr/bin/python3 -I /config/scripts/vyos-routing-observer.py --ssh-observer"
_SHADOW_OBSERVER = "/usr/bin/python3 -I /config/scripts/vyos-shadow-peer.py"
_SHADOW_RECEIPT_CONTROL = "/usr/bin/sudo -n /usr/bin/python3 -I /config/unifi-gateway-shadow/policy.py --manage"
_WAN_SLOTS = {"WAN": "unifi-gateway-wan1-probe",
              "WAN2": "unifi-gateway-wan2-probe",
              "WAN3": "unifi-gateway-wan3-probe"}
_WAN_INTERFACE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,14}")


def _unicast(value: str, label: str) -> IPv4Address:
    problem = f"Use one unicast IPv4 address for the {label}"
    try:
        address = IPv4Address(value)
    except ValueError:
        raise ValueError(problem) from None
    if address.packed[0] == 0 or address.is_loopback or address.is_multicast or address.is_reserved:
        raise ValueError(problem)
    return address


def _read_public_key(path: Path) -> str:
    with path.open("rb") as source:
        raw = source.read(8193)
    lines = raw.splitlines()
    if len(raw) <= 8192 and len(lines) == 1:
        fields = lines[0].split(maxsplit=2)
        if len(fields) >= 2 and fields[0] == b"ssh-ed25519" and len(fields[1]) == 68:
            try:
                wire = b64decode(fields[1], validate=True)
            except Base64Error:
                wire = b""
            if wire.startswith(_WIRE_PREFIX) and len(wire) == len(_WIRE_PREFIX) + 32:
                return fields[1].decode("ascii")
    raise ValueError("Supply one OpenSSH ED25519 public key")


def _shadow_runner(interconnect, interface, prefix, probe, local, peer):
    if interconnect is None or not re.fullmatch(r"eth[0-9]{1,11}", interconnect):
        raise ValueError("Shadow Mode needs one physical --shadow-interconnect interface")
    runner = f"{_SHADOW_OBSERVER} {interconnect}"
    if (interface, prefix, probe, local, peer) == (None, None, None, None, None):
        return runner
    if interface is None or prefix is None or probe is None:
        raise ValueError("Supply the Shadow LAN interface, prefix and probe together")
    if interface == interconnect or re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}", interface) is None:
        raise ValueError("Use a separate VyOS interface for the Shadow LAN")
    network = IPv4Network(prefix)
    destination = _unicast(probe, "Shadow LAN probe")
    if (str(network) != prefix or not 0 < network.prefixlen < 32 or destination not in network
            or (network.prefixlen < 31 and destination in (network.network_address, network.broadcast_address))):
        raise ValueError("Use a Shadow LAN probe host within the exact configured IPv4 prefix")
    runner = f"{runner} {interface} {network} {destination}"
    if local is None and peer is None:
        return runner
    if local is None or peer is None:
        raise ValueError("Supply both Shadow LAN election addresses together")
    endpoints = (_unicast(local, "Shadow LAN local"), _unicast(peer, "Shadow LAN peer"))
    if (endpoints[0] == endpoints[1] or any(address not in network or address == destination
            or (network.prefixlen < 31 and address in (network.network_address, network.broadcast_address)) for address in endpoints)):
        raise ValueError("Shadow LAN election addresses must be distinct hosts in the configured prefix")
    return f"{runner} {endpoints[0]} {endpoints[1]}"


def render(
    user: str, source_ip: str, public_key: Path, listen_address: str | None = None,
    *, wan_group: str | None = None, wan_interface: str | None = None, wan_target: str | None = None,
    restart_preflight: bool = False, routing_observer: bool = False,
    shadow_interconnect: str | None = None, shadow_lan_interface: str | None = None,
    shadow_lan_prefix: str | None = None, shadow_lan_probe: str | None = None,
    shadow_lan_local: str | None = None, shadow_lan_peer: str | None = None,
    shadow_receipt_control: bool = False,
) -> str:
    if user == "root" or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        raise ValueError("Use an existing non-root VyOS management account")
    source = _unicast(source_ip, "bridge source")
    listener = _unicast(listen_address, "SSH listener") if listen_address is not None else None
    if listener == source:
        raise ValueError("The SSH listener and bridge source must be distinct IPv4 addresses")

    key_label, runner = _KEY_LABEL, _RUNNER
    wan_probe = any(value is not None for value in (wan_group, wan_interface, wan_target))
    shadow_scope = (shadow_interconnect, shadow_lan_interface, shadow_lan_prefix, shadow_lan_probe, shadow_lan_local, shadow_lan_peer)
    shadow = any(value is not None for value in shadow_scope)
    if sum((restart_preflight, routing_observer, wan_probe, shadow, shadow_receipt_control)) > 1:
        raise ValueError("Use separate keys for each router management operation")
    if restart_preflight:
        key_label, runner = "unifi-gateway-restart-preflight", _RESTART_PREFLIGHT
    elif routing_observer:
        key_label, runner = "unifi-gateway-routing-observer", _ROUTING_OBSERVER
    elif shadow:
        key_label, runner = "unifi-gateway-shadow-observer", _shadow_runner(*shadow_scope)
    elif shadow_receipt_control:
        key_label, runner = "unifi-gateway-shadow-receipt", _SHADOW_RECEIPT_CONTROL
    elif wan_probe:
        if wan_group not in _WAN_SLOTS or wan_interface is None or wan_target is None:
            raise ValueError("WAN probes require --wan-group, --wan-interface and --wan-target together")
        if _WAN_INTERFACE.fullmatch(wan_interface) is None:
            raise ValueError("Use one VyOS interface name for the WAN probe")
        target = _unicast(wan_target, "WAN probe target")
        key_label = _WAN_SLOTS[wan_group]
        runner = f"/usr/bin/env LC_ALL=C /usr/bin/ping -4 -n -q -I {wan_interface} -c 3 -i 0.2 -W 2 {target}"

    key = _read_public_key(public_key)
    options = f"restrict,from=&quot;{source}/32&quot;,command=&quot;{runner}&quot;"
    prefix = f"set system login user '{user}' authentication public-keys '{key_label}'"
    commands = [f"{prefix} type 'ssh-ed25519'", f"{prefix} key '{key}'", f"{prefix} options '{options}'"]
    if listener is not None:
        commands.append(f"set service ssh listen-address '{listener}'")
    return "\n".join(commands) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--user", required=True, help="Existing non-root VyOS management account")
    parser.add_argument("--source-ip", required=True, help="Bridge management IPv4 address as seen by VyOS")
    parser.add_argument("--public-key", required=True, type=Path, help="Dedicated OpenSSH ED25519 public key")
    parser.add_argument("--listen-address", help="Add one IPv4 address alongside existing explicit SSH listeners")
    parser.add_argument("--wan-group", choices=tuple(_WAN_SLOTS), help="Render a key for this WAN group")
    parser.add_argument("--wan-interface", help="VyOS interface that sends the WAN probe")
    parser.add_argument("--wan-target", help="Literal IPv4 destination for the WAN probe")
    parser.add_argument("--restart-preflight", action="store_true", help="Render a key for the read-only restart guard")
    parser.add_argument("--routing-observer", action="store_true", help="Render a key for the fixed routing state reader")
    parser.add_argument("--shadow-interconnect", help="Render a Shadow Mode key for this physical interconnect")
    parser.add_argument("--shadow-lan-interface", help="Pin the routed default LAN for source verification")
    parser.add_argument("--shadow-lan-prefix", help="Pin the connected IPv4 LAN prefix")
    parser.add_argument("--shadow-lan-probe", help="Pin the unbound route lookup destination on the Shadow LAN")
    parser.add_argument("--shadow-lan-local", help="Pin the local Shadow LAN election address for readiness")
    parser.add_argument("--shadow-lan-peer", help="Pin the opposite Shadow LAN election address for readiness")
    parser.add_argument("--shadow-receipt-control", action="store_true", help="Render a key for the fixed Shadow receipt manager")
    args = parser.parse_args()
    try:
        print(render(
            args.user, args.source_ip, args.public_key, args.listen_address,
            wan_group=args.wan_group, wan_interface=args.wan_interface, wan_target=args.wan_target,
            restart_preflight=args.restart_preflight, routing_observer=args.routing_observer,
            shadow_interconnect=args.shadow_interconnect, shadow_lan_interface=args.shadow_lan_interface,
            shadow_lan_prefix=args.shadow_lan_prefix, shadow_lan_probe=args.shadow_lan_probe,
            shadow_lan_local=args.shadow_lan_local, shadow_lan_peer=args.shadow_lan_peer,
            shadow_receipt_control=args.shadow_receipt_control,
        ), end="")
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
