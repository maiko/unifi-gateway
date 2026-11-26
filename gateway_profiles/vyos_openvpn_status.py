"""Project the observed reachability of the pinned OpenVPN client."""

from ipaddress import IPv4Address, IPv4Interface, IPv4Network
import re

from collectors.vyos import interface_details, interface_ipv4_addresses
from provisioners.vyos_openvpn import OpenVpnScope


class OpenVpnStatusError(ValueError):
    """The router does not prove the scoped OpenVPN path."""


def project_openvpn_status(native_id, scope, backend):
    if (not isinstance(native_id, str) or re.fullmatch(r"[1-9][0-9]{0,9}", native_id) is None
            or not isinstance(scope, OpenVpnScope)):
        raise OpenVpnStatusError("OpenVPN telemetry needs the verified client identity and scope")
    row = {"id": f"/vpn/openvpn/raws/{native_id}", "remotes": []}
    link = interface_details(backend.show_interfaces()).get(scope.interface)
    if link is None or not {"UP", "LOWER_UP"}.issubset(link[0]):
        return [row]
    local = IPv4Interface(scope.tunnel_cidr)
    if interface_ipv4_addresses(link[1]) != [local] or backend.read_config(["policy"]) is not None:
        raise OpenVpnStatusError("OpenVPN tunnel address or policy routing differs from the verified scope")

    routes = backend.show_ipv4_routes()
    for length in range(local.network.prefixlen + 1, 33):
        prefix = IPv4Network(f"{scope.tunnel_peer}/{length}", strict=False)
        if routes.get(str(prefix)):
            raise OpenVpnStatusError("A more specific route could divert the OpenVPN peer probe")
    connected = routes.get(str(local.network))
    if not isinstance(connected, list) or len(connected) != 1:
        raise OpenVpnStatusError("OpenVPN probe needs one connected route through the tunnel")
    route = connected[0]
    hops = route.get("nexthops") if isinstance(route, dict) else None
    if (not isinstance(hops, list) or len(hops) != 1 or not isinstance(hops[0], dict)
            or route.get("protocol") != "connected" or route.get("table") != 254
            or route.get("selected") is not True or route.get("installed") is not True
            or hops[0].get("interfaceName") != scope.interface or hops[0].get("ip") is not None
            or hops[0].get("fib") is not True or hops[0].get("active") is not True):
        raise OpenVpnStatusError("The installed route does not prove the OpenVPN probe path")

    if backend.ping_ipv4_once(IPv4Address(scope.tunnel_peer)):
        row["local"] = {"tunnel_ip": str(local.ip)}
        row["remotes"] = [{"ip": scope.remote_host}]
    return [row]
