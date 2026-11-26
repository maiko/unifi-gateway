"""Decode and plan explicitly owned VyOS static routes."""

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
import json
import re
from uuid import UUID

from provisioners.uxg_schema import selected_schema

_ROUTE_FIELDS = {"enabled", "type", "destination", "distance", "description"}
_INACTIVE_DISTANCE = 255


class RouteIntentError(ValueError):
    """The gateway configuration does not establish an owned static route."""


def _valid_ethernet(interface):
    if not isinstance(interface, str) or len(interface) > 15:
        return False
    port = re.fullmatch(r"eth[0-9]+(?:\.([1-9][0-9]{0,3}))?", interface)
    return port is not None and (port[1] is None or int(port[1]) <= 4094)


@dataclass(frozen=True)
class StaticRouteScope:
    destinations: tuple[str, ...]
    next_hops: dict[str, str]
    interface_ids: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if not isinstance(self.destinations, (list, tuple)) or not self.destinations:
            raise RouteIntentError("Route ownership needs explicit IP destinations")
        prefixes = set()
        for destination in self.destinations:
            network = _prefix(destination)
            if network.prefixlen == 0 or network in prefixes:
                raise RouteIntentError("Managed destinations must be distinct and nondefault")
            prefixes.add(network)
        if not isinstance(self.next_hops, dict):
            raise RouteIntentError("Route ownership needs explicit IP next-hop pins")
        for value, interface in self.next_hops.items():
            if not isinstance(value, str):
                raise RouteIntentError("Route ownership needs explicit IP next-hop pins")
            address, separator, zone = value.partition("%")
            gateway = _gateway(address)
            if _link_local(gateway):
                if not separator or zone != interface:
                    raise RouteIntentError("An IPv6 link-local next-hop pin needs its VyOS interface as a zone")
            elif separator:
                raise RouteIntentError("Only IPv6 link-local next-hop pins can include an interface zone")
            if any(gateway in network for network in prefixes):
                raise RouteIntentError("A managed destination must exclude its pinned next hops")
            if not _valid_ethernet(interface):
                raise RouteIntentError("Each route next hop needs a pinned VyOS Ethernet interface")
        if not isinstance(self.interface_ids, dict):
            raise RouteIntentError("Route ownership needs a map of controller interface IDs")
        for interface_id, interface in self.interface_ids.items():
            if (not isinstance(interface_id, str) or re.fullmatch(r"(?:eth|br)[0-9]+", interface_id) is None
                    or not _valid_ethernet(interface)):
                raise RouteIntentError("Each controller route interface needs a pinned VyOS Ethernet interface")
        object.__setattr__(self, "destinations", tuple(self.destinations))
        object.__setattr__(self, "next_hops", dict(self.next_hops))
        object.__setattr__(self, "interface_ids", dict(self.interface_ids))


@dataclass(frozen=True)
class StaticRoute:
    destination: IPv4Network | IPv6Network
    gateway: IPv4Address | IPv6Address | None
    distance: int
    controller_route_id: UUID
    interface_id: str | None = None


@dataclass(frozen=True)
class StaticRouteIntent:
    revision: str
    scope: StaticRouteScope
    routes: tuple[StaticRoute, ...]


@dataclass(frozen=True)
class StaticRoutePlan:
    desired_routes: dict
    commands: tuple[dict, ...]


def static_route_identities(intent):
    identities = {}
    if intent is not None:
        for route in intent.routes:
            path = {"id": str(route.controller_route_id)}
            if route.interface_id is not None:
                path["interface"] = route.interface_id
            identities.setdefault(str(route.destination), {})[str(route.distance)] = path
    return identities


def validate_static_route_identities(identities, owned, scope):
    if not isinstance(identities, dict) or identities.keys() != owned.keys() or (identities and scope is None):
        raise RouteIntentError("Invalid saved controller static route identities")
    ids = set()
    for prefix, entries in identities.items():
        tree = owned[prefix]
        _verify_owned_tree(tree, scope, _prefix(prefix))
        paths = {settings["distance"]: (coordinate, settings) for coordinate, settings in _route_paths(tree).items()}
        if not isinstance(entries, dict) or entries.keys() != paths.keys():
            raise RouteIntentError("Controller static route identities differ from verified VyOS paths")
        for distance, identity in entries.items():
            if not isinstance(identity, dict) or identity.keys() not in ({"id"}, {"id", "interface"}):
                raise RouteIntentError("Invalid saved controller static route identity")
            route_id = _route_id(f"STATIC_ROUTE:{identity['id']}")
            if route_id in ids:
                raise RouteIntentError("Duplicate saved controller static route identity")
            ids.add(route_id)
            (kind, target), settings = paths[distance]
            requires_interface = kind == "interface" or (kind == "next-hop" and _link_local(_gateway(target)))
            if ("interface" in identity) != requires_interface:
                raise RouteIntentError("Saved controller static route identity has an inconsistent interface field")
            if requires_interface:
                interface = settings.get("interface", target)
                if not isinstance(identity["interface"], str) or scope.interface_ids.get(identity["interface"]) != interface:
                    raise RouteIntentError("Saved controller static route interface differs from its VyOS pin")
        if tree["description"] != f"STATIC_ROUTE:{min(identity['id'] for identity in entries.values())}":
            raise RouteIntentError("Saved controller static route identities differ from prefix ownership")


def extends_static_route_scope(scope, saved):
    if not isinstance(saved, dict) or saved.keys() not in (
        {"destinations", "next_hops"}, {"destinations", "next_hops", "interface_ids"},
    ):
        return False
    try:
        previous = StaticRouteScope(**saved)
    except RouteIntentError:
        return False
    return (set(previous.destinations).issubset(scope.destinations)
            and previous.next_hops.items() <= scope.next_hops.items()
            and previous.interface_ids.items() <= scope.interface_ids.items())


def decode_route_intent(
    system_cfg: str, *, revision: str, scope: StaticRouteScope,
    message_broker=False, dns_forwarder=False, nat=False, wireguard=False,
) -> StaticRouteIntent:
    """Decode the observed complete static route section for the configured scope."""
    if not isinstance(revision, str) or not revision:
        raise RouteIntentError("Route snapshot needs a controller revision")
    if not isinstance(scope, StaticRouteScope) or not isinstance(system_cfg, str):
        raise RouteIntentError("Route snapshot needs a configured scope and a JSON string")
    try:
        document = json.loads(system_cfg, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except RouteIntentError:
        raise
    except (ValueError, RecursionError) as error:
        raise RouteIntentError("Route snapshot is not valid JSON") from error

    udapi = document.get("udapi") if isinstance(document, dict) else None
    versions = udapi.get("versionDetail") if isinstance(udapi, dict) else None
    expected_versions = selected_schema(message_broker=message_broker, dns_forwarder=dns_forwarder,
                                        nat=nat, wireguard=wireguard)
    if (versions != expected_versions or any(type(value) is not int for value in versions.values())
            or type(udapi.get("version")) is not int or udapi["version"] != 48 or udapi.get("versionFormat") != "v2"):
        raise RouteIntentError("Unsupported UDAPI static route schema")
    entries = udapi.get("routes/static")
    if not isinstance(entries, list):
        raise RouteIntentError("Route snapshot needs an explicit static route list")

    routes = []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("enabled") is not True:
            raise RouteIntentError("Static route row needs the observed enabled state")
        kind = entry.get("type")
        gateway = interface_id = None
        if kind == "gateway" and entry.keys() in (_ROUTE_FIELDS | {"gateway"}, _ROUTE_FIELDS | {"gateway", "interface"}):
            gateway = _gateway(entry["gateway"], wire=True)
        elif kind == "interface" and entry.keys() == _ROUTE_FIELDS | {"interface"}:
            pass
        elif kind != "blackhole" or entry.keys() != _ROUTE_FIELDS:
            raise RouteIntentError("Unsupported static route type or fields")
        if "interface" in entry:
            interface_id = entry["interface"]
            if not isinstance(interface_id, str):
                raise RouteIntentError("Controller static route needs an approved interface ID")
        routes.append(StaticRoute(
            _prefix(entry["destination"], wire=True), gateway, _distance(entry["distance"]),
            _route_id(entry["description"]), interface_id,
        ))
    _group_intent_routes(routes, scope)
    return StaticRouteIntent(revision, scope, tuple(routes))


def plan_route_commands(
    intent: StaticRouteIntent,
    *,
    scope: StaticRouteScope,
    connected_routes: dict,
    current_routes: dict,
    verified_routes: dict,
    require_connected=False,
) -> StaticRoutePlan:
    """Plan against the complete static prefix map and fresh FRR route tables."""
    if not isinstance(intent, StaticRouteIntent) or intent.scope != scope:
        raise RouteIntentError("Route intent belongs to another configured scope")
    groups = _group_intent_routes(intent.routes, scope)
    if not isinstance(current_routes, dict) or not isinstance(verified_routes, dict):
        raise RouteIntentError("Route planning needs the complete VyOS static prefix map and verified ownership")
    if not set(verified_routes).issubset(scope.destinations):
        raise RouteIntentError("Verified static route ownership escapes the configured destinations")
    for destination, tree in verified_routes.items():
        _verify_owned_tree(tree, scope, _prefix(destination))
    owned = {name: tree for name, tree in current_routes.items() if name in scope.destinations}
    if owned != verified_routes:
        raise RouteIntentError("VyOS static route subtree differs from verified ownership")

    installed = _selected_routes(connected_routes)
    operators = {_prefix(name) for name in current_routes if name not in owned}
    desired = {}
    for destination, paths in groups.items():
        network = _prefix(destination)
        if any(prefix.prefixlen and prefix.overlaps(network) for prefix in operators):
            raise RouteIntentError(f"Managed destination {destination} overlaps an operator static route")
        _check_installed_overlap(network, installed, owned)
        owner_id = min(route.controller_route_id for route in paths.values())
        tree = {"description": f"STATIC_ROUTE:{owner_id}"}
        previous = _route_paths(owned.get(destination, {}))
        for (kind, target), route in paths.items():
            settings = {"distance": str(route.distance)}
            if kind == "next-hop":
                interface = scope.next_hops[_next_hop_pin(route, scope)]
                settings["interface"] = interface
                known_path = not require_connected and previous.get((kind, target)) == settings
                if route.distance != _INACTIVE_DISTANCE and not known_path:
                    _prove_connected(route.gateway, interface, installed, connected_routes)
            if target is None:
                tree[kind] = settings
            else:
                tree.setdefault(kind, {})[target] = settings
        desired[destination] = tree

    commands = []
    for name in scope.destinations:
        before, after = owned.get(name), desired.get(name)
        if before == after:
            continue
        family_node = "route6" if ":" in name else "route"
        path = ["protocols", "static", family_node, name]
        if before is not None:
            commands.append({"op": "delete", "path": path})
        if after is not None:
            commands.append({"op": "set", "path": path + ["description"], "value": after["description"]})
            for (kind, target), settings in sorted(_route_paths(after).items()):
                node = path + [kind] if target is None else path + [kind, target]
                for key, value in settings.items():
                    commands.append({"op": "set", "path": node + [key], "value": value})
    return StaticRoutePlan(desired, tuple(commands))


def verify_route_forwarding(operational, desired, withdrawn, *, read_interfaces=None, previous_static=None):
    if not isinstance(operational, dict):
        raise RouteIntentError("VyOS returned an invalid static route table")
    installed = _selected_routes(operational) if desired else ()
    interfaces = None

    def interface_up(target):
        nonlocal interfaces
        if interfaces is None:
            interfaces = read_interfaces() if read_interfaces is not None else {}
        if "lo" not in interfaces or target not in interfaces:
            raise RouteIntentError(f"VyOS has no verified link state for {target}")
        flags, _ = interfaces[target]
        return {"UP", "LOWER_UP"}.issubset(flags)

    for prefix in desired.keys() | withdrawn:
        candidates = operational.get(prefix, [])
        if not isinstance(candidates, list) or any(
            not isinstance(row, dict) or type(row.get("table")) is not int for row in candidates
        ):
            raise RouteIntentError("VyOS returned an invalid static route table")
        if prefix in withdrawn:
            if any(row.get("table") == 254 and row.get("protocol") == "static" for row in candidates):
                raise RouteIntentError(f"Withdrawn static route {prefix} remains in the VyOS route table")
            continue
        selected = [row for row in candidates if row.get("table") == 254
                    and row.get("selected") is True and row.get("installed") is True]
        route = desired[prefix]
        paths = _route_paths(route)
        known = _route_paths((previous_static or {}).get(prefix, {}))
        if len(paths) == 1:
            coordinate, settings = next(iter(paths.items()))
            kind, target = coordinate
            distance = int(settings["distance"])
            missing = f"Managed static route {prefix} has no verified installed {kind.replace('-', ' ')}"
            if distance == _INACTIVE_DISTANCE:
                if any(row.get("protocol") == "static" for row in selected):
                    raise RouteIntentError(f"Static route {prefix} with distance 255 is unexpectedly installed")
            elif selected and (len(selected) != 1 or not _matches_installed_route(selected[0], route)):
                raise RouteIntentError(missing)
            elif not selected and not _known_down_path(coordinate, settings, known, interface_up):
                raise RouteIntentError(missing)
            rows = _verify_candidate_rows(prefix, candidates, paths)
            if distance != _INACTIVE_DISTANCE:
                if not selected:
                    if _only_hop(rows.get(distance, {})).get("active") is True:
                        raise RouteIntentError(missing)
                elif kind == "next-hop" and known.get(coordinate) == settings:
                    _prove_connected(_gateway(target), settings["interface"], installed, operational)
                elif len(known) > 1 and _known_down_path(coordinate, settings, known, interface_up):
                    raise RouteIntentError(f"Static route {prefix} reports an installed path on a down link")
        else:
            rows = _verify_candidate_rows(prefix, candidates, paths)
            preferences = []
            for coordinate, settings in paths.items():
                kind, target = coordinate
                distance = int(settings["distance"])
                if distance == _INACTIVE_DISTANCE:
                    continue
                row = rows.get(distance, {})
                active = _only_hop(row).get("active") is True
                reachable = True
                if kind == "next-hop":
                    reachable = _gateway_connected(_gateway(target), settings["interface"], installed, operational)
                elif kind == "interface":
                    reachable = interface_up(target)
                if reachable != active:
                    raise RouteIntentError(f"Static route {prefix} has inconsistent candidate state at distance {distance}")
                if active:
                    preferences.append(distance)
            if not preferences and not selected:
                valid = all(_known_down_path(coordinate, settings, known, interface_up)
                            for coordinate, settings in paths.items() if int(settings["distance"]) != _INACTIVE_DISTANCE)
            else:
                valid = bool(preferences and len(selected) == 1 and selected[0] == rows[min(preferences)]
                             and _matches_installed_route(selected[0], route))
            if not valid:
                raise RouteIntentError(f"Managed static route {prefix} has no verified preferred path")
        _check_installed_overlap(_prefix(prefix), installed, desired)


def _known_down_path(coordinate, settings, known, interface_up):
    kind, target = coordinate
    if kind == "blackhole" or known.get(coordinate) != settings:
        return False
    interface = settings["interface"] if kind == "next-hop" else target
    return not interface_up(interface)


def _verify_candidate_rows(prefix, candidates, paths):
    by_distance = {int(settings["distance"]): (coordinate, settings) for coordinate, settings in paths.items()}
    observed = {}
    for row in candidates:
        if row["table"] != 254 or row.get("protocol") != "static":
            continue
        distance = row.get("distance")
        if (type(distance) is not int or distance in observed
                or distance not in by_distance or row.get("metric", 0) != 0
                or (distance == _INACTIVE_DISTANCE and row.get("selected") is True)
                or (row.get("selected") is True) != (row.get("installed") is True)):
            raise RouteIntentError(f"Static route {prefix} has an unverified FRR candidate")
        coordinate, settings = by_distance[distance]
        if not _matches_hop(_only_hop(row), coordinate, settings):
            raise RouteIntentError(f"Static route {prefix} has an unverified FRR candidate at distance {distance}")
        observed[distance] = row
    return observed


def observed_static_routes(snapshot, owned):
    """Yield main-table FRR observations that agree with the verified static configuration."""
    if not isinstance(snapshot, dict):
        raise RouteIntentError("VyOS returned an invalid static route table")
    for prefix, tree in sorted(owned.items()):
        candidates = snapshot.get(prefix, [])
        if not isinstance(candidates, list) or any(
            not isinstance(row, dict) or type(row.get("table")) is not int for row in candidates
        ):
            raise RouteIntentError("VyOS returned an invalid static route table")
        paths = _route_paths(tree)
        records = _verify_candidate_rows(prefix, candidates, paths)
        installed = [row for row in records.values() if row.get("selected") is True]
        if sum(row["table"] == 254 and row.get("selected") is True and row.get("installed") is True
               for row in candidates) > 1:
            raise RouteIntentError(f"Static route {prefix} has multiple installed candidates")
        if installed and not _only_fib_hop(installed[0]):
            raise RouteIntentError(f"Static route {prefix} reports installation without an active FIB hop")
        network = _prefix(prefix)
        for (kind, target), settings in sorted(paths.items(), key=lambda path: int(path[1]["distance"])):
            row = records.get(int(settings["distance"]))
            if row is None:
                continue
            if (row.get("prefix") != prefix or type(row.get("prefixLen")) is not int
                    or row["prefixLen"] != network.prefixlen):
                raise RouteIntentError("FRR static route prefix fields are inconsistent")
            in_use = row.get("selected") is True
            yield prefix, kind, target, row, in_use, tree["description"] if len(paths) == 1 else ""


def _unique_fields(pairs):
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise RouteIntentError("Route snapshot contains a duplicate JSON field")
        fields[key] = value
    return fields


def _invalid_constant(_value):
    raise RouteIntentError("Route snapshot contains a non-JSON constant")


def _prefix(value, *, wire=False):
    try:
        network = ip_network(value)
    except ValueError as error:
        raise RouteIntentError("Static route needs a canonical IP destination CIDR") from error
    if str(network) != value and not (wire and network.version == 6 and isinstance(value, str) and "/" in value):
        raise RouteIntentError("Static route needs a canonical IP destination CIDR")
    return network


def _gateway(value, *, wire=False):
    try:
        address = ip_address(value)
    except ValueError as error:
        raise RouteIntentError("Static route needs a unicast IP next hop") from error
    acceptable_text = isinstance(value, str) and (str(address) == value or (wire and address.version == 6))
    if (not acceptable_text or address.is_unspecified or address.is_multicast
            or address.is_loopback or address.is_reserved or "%" in value
            or (isinstance(address, IPv6Address) and address.ipv4_mapped is not None)):
        raise RouteIntentError("Static route needs a unicast IP next hop")
    return address


def _link_local(address):
    return address.version == 6 and address.is_link_local


def _next_hop_pin(route, scope):
    if not _link_local(route.gateway):
        return str(route.gateway)
    if route.interface_id not in scope.interface_ids:
        raise RouteIntentError("Controller link-local gateway needs an approved interface ID")
    return f"{route.gateway}%{scope.interface_ids[route.interface_id]}"


def _distance(value):
    if type(value) is not int or not 1 <= value <= _INACTIVE_DISTANCE:
        raise RouteIntentError("Route distance must be an integer from 1 to 255")
    return value


def _route_id(description):
    if not isinstance(description, str) or not description.startswith("STATIC_ROUTE:"):
        raise RouteIntentError("Static route needs a native controller route ID")
    text = description.removeprefix("STATIC_ROUTE:")
    try:
        route_id = UUID(text)
    except ValueError as error:
        raise RouteIntentError("Static route needs a native controller route ID") from error
    if not route_id.int or str(route_id) != text:
        raise RouteIntentError("Static route needs a canonical controller route ID")
    return route_id


def _group_intent_routes(routes, scope):
    groups, ids = {}, set()
    for route in routes:
        name = str(route.destination)
        if name not in scope.destinations:
            raise RouteIntentError("Controller static route does not match an approved destination and gateway")
        if route.gateway is not None:
            gateway = _gateway(str(route.gateway))
            if gateway.version != route.destination.version:
                raise RouteIntentError("Static route destination and gateway need the same address family")
            if route.interface_id is not None and not _link_local(gateway):
                raise RouteIntentError("Only an IPv6 link-local gateway can carry an interface ID")
            if _next_hop_pin(route, scope) not in scope.next_hops:
                raise RouteIntentError("Controller static route does not match an approved destination and gateway")
            coordinate = ("next-hop", str(gateway))
        elif route.interface_id is not None:
            if route.interface_id not in scope.interface_ids:
                raise RouteIntentError("Controller static route needs an approved interface ID")
            coordinate = ("interface", scope.interface_ids[route.interface_id])
        else:
            coordinate = ("blackhole", None)
        _distance(route.distance)
        _route_id(f"STATIC_ROUTE:{route.controller_route_id}")
        if route.controller_route_id in ids:
            raise RouteIntentError("Controller static routes have duplicate IDs")
        paths = groups.setdefault(name, {})
        if coordinate in paths:
            raise RouteIntentError(f"Static routes for {name} share one VyOS path")
        if any(previous.distance == route.distance for previous in paths.values()):
            raise RouteIntentError(f"Static routes for {name} have the same effective distance")
        paths[coordinate] = route
        ids.add(route.controller_route_id)
    return groups


def _verify_owned_tree(tree, scope, destination):
    if (not isinstance(tree, dict) or len(tree) < 2 or "description" not in tree
            or not tree.keys() <= {"description", "next-hop", "blackhole", "interface"}):
        raise RouteIntentError("Invalid verified VyOS static route subtree")
    _route_id(tree["description"])
    if any(not isinstance(values, dict) or not values for key, values in tree.items() if key != "description"):
        raise RouteIntentError("Invalid verified VyOS static route subtree")
    distances = set()
    for (kind, target), settings in _route_paths(tree).items():
        keys = {"distance", "interface"} if kind == "next-hop" else {"distance"}
        if not isinstance(settings, dict) or settings.keys() != keys:
            raise RouteIntentError("Invalid verified VyOS static route path")
        distance = _stored_distance(settings["distance"])
        if distance in distances:
            raise RouteIntentError("Invalid equal distances in verified VyOS static route paths")
        distances.add(distance)
        if kind == "interface" and target not in scope.interface_ids.values():
            raise RouteIntentError("Invalid verified VyOS static interface subtree")
        if kind == "next-hop":
            address = _gateway(target)
            interface = settings["interface"]
            pin = f"{target}%{interface}" if _link_local(address) else target
            if address.version != destination.version or not isinstance(interface, str) or scope.next_hops.get(pin) != interface:
                raise RouteIntentError("Invalid verified VyOS static next-hop subtree")


def _stored_distance(value):
    if not isinstance(value, str) or re.fullmatch(r"[1-9][0-9]{0,2}", value) is None:
        raise RouteIntentError("Invalid verified VyOS static route distance")
    return _distance(int(value))


def _route_paths(route):
    paths = {}
    if "blackhole" in route:
        paths["blackhole", None] = route["blackhole"]
    for kind in ("interface", "next-hop"):
        paths.update({(kind, target): settings for target, settings in route.get(kind, {}).items()})
    return paths


def _selected_routes(table):
    if not isinstance(table, dict):
        raise RouteIntentError("Route planning needs the fresh VyOS route table")
    routes = []
    for name, candidates in table.items():
        prefix = _prefix(name)
        if not isinstance(candidates, list) or any(
            not isinstance(route, dict) or type(route.get("table")) is not int for route in candidates
        ):
            raise RouteIntentError("VyOS returned an invalid IP route table")
        routes.extend((prefix, route) for route in candidates if (
            route["table"] == 254 and route.get("selected") is True and route.get("installed") is True
        ))
    return routes


def _only_hop(route):
    hops = route.get("nexthops")
    if not isinstance(hops, list) or len(hops) != 1:
        return {}
    hop = hops[0]
    return hop if isinstance(hop, dict) else {}


def _only_fib_hop(route):
    hop = _only_hop(route)
    return hop if hop.get("fib") is True and hop.get("active") is True else {}


def _prove_connected(gateway, interface, installed, table):
    if _gateway_connected(gateway, interface, installed, table):
        return
    if _link_local(gateway):
        raise RouteIntentError(f"IPv6 link-local next hop {gateway} has no active connected route on {interface}")
    raise RouteIntentError(f"Next hop {gateway} has no selected directly connected route on {interface}")


def _gateway_connected(gateway, interface, installed, table):
    if _link_local(gateway):
        # FRR can install the same link-local prefix on multiple interfaces and mark only one selected.
        for prefix, candidates in table.items():
            network = _prefix(prefix)
            if network.network_address.is_link_local and gateway in network and any(
                route["table"] == 254 and route.get("installed") is True and _is_connected_on(route, interface)
                for route in candidates
            ):
                return True
        return False
    matching = [(network, route) for network, route in installed if gateway in network]
    if matching:
        longest = max(network.prefixlen for network, _ in matching)
        best = [(network, route) for network, route in matching if network.prefixlen == longest]
        if len(best) == 1 and 0 < longest < gateway.max_prefixlen:
            network, route = best[0]
            if (_is_connected_on(route, interface)
                    and (gateway.version == 6 or longest == 31 or network.network_address < gateway < network.broadcast_address)):
                return True
    return False


def _is_connected_on(route, interface):
    hop = _only_fib_hop(route)
    return (route.get("protocol") == "connected" and hop.get("directlyConnected") is True
            and hop.get("interfaceName") == interface)


def _check_installed_overlap(destination, installed, owned):
    for prefix, route in installed:
        if not prefix.prefixlen or not prefix.overlaps(destination):
            continue
        previous = owned.get(str(prefix))
        if previous is not None and _matches_installed_route(route, previous):
            continue
        raise RouteIntentError(f"Managed destination {destination} overlaps an unverified installed route")


def _matches_installed_route(record, route):
    distance = record.get("distance")
    if (record.get("protocol") != "static" or type(distance) is not int or distance == _INACTIVE_DISTANCE
            or record.get("metric", 0) != 0):
        return False
    hop = _only_fib_hop(record)
    return any(int(settings["distance"]) == distance and _matches_hop(hop, coordinate, settings)
               for coordinate, settings in _route_paths(route).items())


def _matches_hop(hop, coordinate, settings):
    kind, target = coordinate
    if kind == "blackhole":
        return hop.get("blackhole") is True and "ip" not in hop and "interfaceName" not in hop
    if kind == "interface":
        return (hop.get("blackhole") is not True and "ip" not in hop and hop.get("directlyConnected") is True
                and hop.get("interfaceName") == target)
    return (hop.get("blackhole") is not True and hop.get("ip") == target
            and hop.get("interfaceName") == settings["interface"])
