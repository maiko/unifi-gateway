"""Bounded replies to the Network controller's live routing queries."""

from copy import deepcopy
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, ip_address, ip_network
import re

from provisioners.vyos_ospf import OspfScope
from provisioners.vyos_routes import RouteIntentError, observed_static_routes


ROUTE_QUERY_CAPABILITY = 0x800000
# Network's installed ordinary network and VPN allocators both start at 178.
FIRST_UNIFI_NETWORK_TABLE = 178

_COMMAND = "get-udapi-blocks"
_REQUEST_FIELDS = {"_type", "cmd", "request_id", "udapi_blocks"}
_CONTROLLER_METADATA = {"_id", "device_id", "datetime", "time", "server_time_in_utc"}
_REQUEST_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_ROUTES = {"id": "get-routes", "method": "GET", "endpoint": "/routes"}
_NEIGHBORS = {"id": "get-ospf-neighbors", "method": "GET", "endpoint": "/routes/ospf", "filter": ["neighbors"]}
_RESULT_KEYS = {"get-routes": "items", "get-ospf-neighbors": "neighbors"}
_FIB_ORIGINS = {"connected": "Kernel", "static": "Static", "bgp": "BGP"}


class RouteQueryError(ValueError):
    """The native route query or its reply falls outside the supported contract."""


@dataclass(frozen=True, slots=True)
class RouteQuery:
    request_id: str
    block_id: str

    def __post_init__(self):
        if not isinstance(self.request_id, str) or _REQUEST_ID.fullmatch(self.request_id) is None:
            raise RouteQueryError("Route query requires a controller UUID")
        if not isinstance(self.block_id, str) or self.block_id not in _RESULT_KEYS:
            raise RouteQueryError("Unsupported route query block")


def decode_route_query(response: dict) -> RouteQuery:
    """Accept the two exact single-block read commands emitted by Network."""
    if (
        not isinstance(response, dict)
        or response.keys() - _CONTROLLER_METADATA != _REQUEST_FIELDS
        or response["_type"] != "cmd"
        or response["cmd"] != _COMMAND
    ):
        raise RouteQueryError("Unsupported route query envelope")
    blocks = response["udapi_blocks"]
    if not isinstance(blocks, list) or len(blocks) != 1 or blocks[0] not in (_ROUTES, _NEIGHBORS):
        raise RouteQueryError("Unsupported route query block")
    return RouteQuery(response["request_id"], blocks[0]["id"])


def build_route_query_notification(query: RouteQuery, rows: list[dict]) -> dict:
    """Build notification fields for an immediate authenticated inform."""
    if not isinstance(query, RouteQuery) or not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise RouteQueryError("Route query reply requires a decoded query and a list of rows")
    return {
        "inform_as_notif": True,
        "notif_reason": "cmd",
        "notif_payload": {
            "event_string": _COMMAND,
            "request_id": query.request_id,
            "udapi_blocks": {query.block_id: {_RESULT_KEYS[query.block_id]: deepcopy(rows)}},
        },
    }


def project_installed_routes(snapshot, *, version, interfaces, table=254, managed_prefixes=frozenset(), include_bgp=False):
    """Project observed FIB routes whose protocol and egress can be reported."""
    if not isinstance(snapshot, dict):
        raise RouteQueryError("FRR route snapshot is invalid")
    rows = []
    for prefix, candidates in snapshot.items():
        if prefix == "fe80::/64":
            continue
        if not isinstance(candidates, list) or any(not isinstance(route, dict) for route in candidates):
            raise RouteQueryError("FRR route candidates are invalid")
        if table != 254 and any(route.get("table") != table for route in candidates):
            raise RouteQueryError("FRR alternate route snapshot has a different table identity")
        installed = [route for route in candidates if route.get("table") == table
                     and route.get("selected") is True and route.get("installed") is True]
        route = next((candidate for candidate in installed if (
            candidate.get("protocol") == "connected"
            or (candidate.get("protocol") == "static" and prefix not in managed_prefixes)
            or (include_bgp and candidate.get("protocol") == "bgp")
        )), None)
        if route is None:
            continue
        connected = route["protocol"] == "connected"
        hops = route.get("nexthops")
        if not isinstance(hops, list) or any(not isinstance(hop, dict) for hop in hops):
            raise RouteQueryError("FRR route nexthops are invalid")
        active = [hop for hop in hops if hop.get("active") is True and hop.get("fib") is True]
        if not active:
            raise RouteQueryError(f"Route {prefix} has no active FIB nexthop")
        blackhole = any(hop.get("blackhole") is True for hop in active)
        if blackhole:
            if connected or len(active) != 1 or "ip" in active[0] or "interfaceName" in active[0]:
                raise RouteQueryError(f"FRR route {prefix} has an invalid blackhole nexthop")
            nexthops = []
        else:
            nexthops = _installed_unicast_hops(
                active, protocol=route["protocol"], version=version, interfaces=interfaces,
            )
            if nexthops is None:
                continue
        if len(installed) != 1:
            raise RouteQueryError(f"Route {prefix} has multiple installed candidates")
        try:
            network = ip_network(prefix)
        except ValueError:
            raise RouteQueryError("FRR route prefix is invalid") from None
        distance = route.get("distance")
        if (
            network.version != version or str(network) != prefix or route.get("prefix") != prefix
            or type(route.get("prefixLen")) is not int or route["prefixLen"] != network.prefixlen
            or route.get("vrfId") != 0 or route.get("vrfName") != "default"
            or type(distance) is not int or not (distance == 0 if connected else 1 <= distance < 255)
        ):
            raise RouteQueryError("FRR route fields are inconsistent")
        # Stock IPv4 connected routes have link scope. Stock IPv6 connected routes have global scope.
        rows.append({"description": "", "destination": prefix, "distance": distance,
                     "origin": _FIB_ORIGINS[route["protocol"]], "scope": 253 if connected and version == 4 else 0,
                     "table": table, "type": "blackhole" if blackhole else "unicast", "nexthops": nexthops})
    return rows


def _installed_unicast_hops(active, *, protocol, version, interfaces):
    nexthops = []
    for hop in active:
        egress = hop.get("interfaceName")
        if not isinstance(egress, str):
            raise RouteQueryError("FRR route has an invalid egress interface")
        interface = interfaces.get(egress)
        if interface is None or {egress, interface}.intersection({"lo", "dummy0"}):
            return None
        weight = hop.get("weight")
        if type(weight) is not int or not 0 < weight <= 255:
            raise RouteQueryError("FRR installed route nexthop weight is invalid")
        entry = {"interface": interface, "weight": weight, "inUse": True}
        if "ip" in hop and protocol != "connected":
            try:
                gateway = ip_address(hop["ip"])
            except ValueError:
                raise RouteQueryError("FRR installed route gateway is invalid") from None
            extended_nexthop = (
                protocol == "bgp" and version == 4 and gateway.version == 6
                and hop.get("afi") == "ipv6" and gateway.scope_id is None and gateway.ipv4_mapped is None
            )
            if (gateway.version != version and not extended_nexthop) or str(gateway) != hop["ip"]:
                raise RouteQueryError("FRR installed route gateway has an inconsistent address family or format")
            entry["gateway"] = str(gateway)
        elif "ip" in hop or hop.get("directlyConnected") is not True:
            raise RouteQueryError("FRR installed route has an invalid direct nexthop")
        nexthops.append(entry)
    return nexthops


def project_ospf_routes(snapshot: dict, *, scope: OspfScope) -> list[dict]:
    """Project selected, single-hop OSPF routes installed on the scoped LAN."""
    local = _local_interface(snapshot, scope)
    rows = []
    for prefix, candidates in snapshot.items():
        if not isinstance(candidates, list) or any(not isinstance(route, dict) for route in candidates):
            raise RouteQueryError("FRR IPv4 route candidates are invalid")
        for route in candidates:
            if (
                route.get("protocol") != "ospf" or route.get("table") != 254
                or route.get("vrfId") != 0 or route.get("vrfName") != "default"
                or route.get("selected") is not True or route.get("installed") is not True
            ):
                continue
            hops = route.get("nexthops")
            if not isinstance(hops, list) or any(not isinstance(hop, dict) for hop in hops):
                raise RouteQueryError("FRR OSPF nexthops are invalid")
            if len(hops) != 1:
                continue
            hop = hops[0]
            if (hop.get("interfaceName") != scope.vyos_interface or hop.get("afi") != "ipv4"
                    or hop.get("active") is not True or hop.get("fib") is not True):
                continue
            if sum(row.get("table") == 254 and row.get("selected") is True and row.get("installed") is True
                   for row in candidates) > 1:
                raise RouteQueryError(f"FRR OSPF prefix {prefix} has multiple installed candidates")
            try:
                network = IPv4Network(prefix) if isinstance(prefix, str) else None
            except ValueError:
                raise RouteQueryError("FRR OSPF prefix is invalid") from None
            distance, weight = route.get("distance"), hop.get("weight")
            if (
                network is None or str(network) != prefix or route.get("prefix") != prefix
                or route.get("prefixLen") != network.prefixlen
                or type(distance) is not int or not 0 < distance < 255
                or type(weight) is not int or not 0 < weight <= 255
            ):
                raise RouteQueryError("FRR OSPF route fields are inconsistent")
            gateway = _on_link_peer(hop.get("ip"), local)
            rows.append({
                "description": "", "destination": prefix, "distance": distance, "origin": "OSPF",
                "scope": 0, "table": 254, "type": "unicast",
                "nexthops": [{
                    "gateway": str(gateway), "inUse": True, "interface": scope.controller_interface, "weight": weight,
                }],
            })
    return rows


def project_static_routes(snapshot, *, owned, identities, interfaces):
    """Report only live FRR candidates that match verified managed static paths."""
    items = []
    try:
        for prefix, kind, target, route, in_use, fallback in observed_static_routes(snapshot, owned):
            distance = route["distance"]
            identity = identities.get(prefix, {}).get(str(distance), {})
            description = f"STATIC_ROUTE:{identity['id']}" if identity else fallback
            nexthops = []
            if kind == "blackhole":
                # Network treats a row with no hops as installed.
                if not in_use:
                    continue
                route_type = "blackhole"
            else:
                hop = route["nexthops"][0]
                interface = identity.get("interface") or interfaces.get(hop["interfaceName"])
                if interface is None:
                    continue
                weight = hop.get("weight")
                if type(weight) is not int or not 0 < weight <= 255:
                    raise RouteQueryError("FRR static route next-hop weight is invalid")
                entry = {"interface": interface, "inUse": in_use, "weight": weight}
                if kind == "next-hop":
                    entry["gateway"] = target
                nexthops.append(entry)
                route_type = "unicast"
            items.append({"description": description, "destination": prefix, "distance": distance, "origin": "Static",
                          "scope": 0, "table": 254, "type": route_type, "nexthops": nexthops})
    except RouteIntentError as error:
        raise RouteQueryError(str(error)) from error
    return items


def project_ospf_neighbors(snapshot: dict, *, scope: OspfScope) -> list[dict]:
    """Project only Full IPv4 adjacencies observed on the scoped LAN."""
    local = _local_interface(snapshot, scope)
    neighbors = snapshot.get("neighbors", {})
    if not isinstance(neighbors, dict) or snapshot.keys() - {"neighbors"}:
        raise RouteQueryError("FRR OSPF neighbor table is invalid")
    interface_prefix = f"{scope.vyos_interface}:"
    rows = []
    for router_id, sightings in neighbors.items():
        if not isinstance(sightings, list) or any(not isinstance(neighbor, dict) for neighbor in sightings):
            raise RouteQueryError("FRR OSPF adjacency records are invalid")
        for neighbor in sightings:
            interface = neighbor.get("ifaceName")
            if not isinstance(interface, str) or not interface.startswith(interface_prefix):
                continue
            state = neighbor.get("nbrState")
            if not isinstance(state, str) or not state.startswith("Full/"):
                continue
            role, priority = neighbor.get("role"), neighbor.get("nbrPriority")
            if (
                not isinstance(role, str) or re.fullmatch(r"[A-Za-z]{1,16}", role) is None
                or state != f"Full/{role}" or neighbor.get("converged") != "Full"
                or interface != f"{interface_prefix}{local.ip}"
                or type(priority) is not int or not 0 <= priority <= 255
            ):
                raise RouteQueryError("FRR Full OSPF adjacency fields are inconsistent")
            peer_id = _canonical_address(router_id)
            if peer_id.is_unspecified or peer_id.is_multicast or str(peer_id) == scope.router_id:
                raise RouteQueryError("FRR OSPF neighbor ID is invalid")
            remote = _on_link_peer(neighbor.get("ifaceAddress"), local)
            rows.append({
                "interface": scope.controller_interface, "localAddress": str(local.ip), "neighborID": str(peer_id),
                "priority": priority, "remoteAddress": str(remote), "role": role, "state": "Full",
            })
    return rows


def _local_interface(snapshot: dict, scope: OspfScope) -> IPv4Interface:
    if not isinstance(snapshot, dict) or not isinstance(scope, OspfScope):
        raise RouteQueryError("Route query projection requires an FRR object and an OSPF scope")
    return IPv4Interface(scope.interface_address)


def _canonical_address(value: str) -> IPv4Address:
    try:
        address = IPv4Address(value) if isinstance(value, str) else None
    except ValueError:
        raise RouteQueryError("FRR OSPF IPv4 address is invalid") from None
    if address is None or str(address) != value:
        raise RouteQueryError("FRR OSPF IPv4 address is invalid")
    return address


def _on_link_peer(value: str, local: IPv4Interface) -> IPv4Address:
    address = _canonical_address(value)
    if address == local.ip or not local.network.network_address < address < local.network.broadcast_address:
        raise RouteQueryError("FRR OSPF peer address is outside the scoped LAN")
    return address
