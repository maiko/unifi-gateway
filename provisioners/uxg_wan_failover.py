"""Decode UniFi WAN priorities and plan the corresponding VyOS failover route."""

from dataclasses import dataclass
from ipaddress import IPv4Interface
import json

from collectors.vyos import interface_ipv4_addresses


_VERSION = "services/wanFailover"
WAN_FAILOVER_VERSIONS = {_VERSION: 11}
WAN_FAILOVER_CAPABILITY = 0x4
_SUPPORTED_WANS = {
    "eth0": (201, "eth3.210", "198.18.210.1/30", "198.18.210.2"),
    "eth2": (202, "eth3.220", "198.18.220.1/30", "198.18.220.2"),
}
_PROBE_DESTINATION = "198.19.210.242"
_HOST_ROUTE = f"{_PROBE_DESTINATION}/32"
DEFAULT_ROUTE = "0.0.0.0/0"
_CONFIG_PATH = ("protocols", "failover")
_STATISTICS_MONITOR = {"interval": 60, "timePeriod": 86400, "target": "ping.ui.com"}
_DEFAULT_MONITORS = (
    {"interval": 3, "timePeriod": 60, "target": "ping.ui.com", "alert": {"lossThreshold": 50}},
    *({"interval": 10, "timePeriod": 30, "target": target, "type": "dns", "domain": "ui.com",
       "alert": {"latencyThreshold": 1500, "lossThreshold": 100}}
      for target in ("1.1.1.1", "8.8.8.8")),
    _STATISTICS_MONITOR,
)


class WanFailoverError(ValueError):
    """The WAN configuration or route ownership is incompatible with this failover policy."""


@dataclass(frozen=True, slots=True)
class WanFailoverIntent:
    revision: str
    primary: str | None


@dataclass(frozen=True, slots=True)
class WanFailoverPlan:
    expected: dict | None
    commands: tuple[dict, ...]


def _distinct_keys(pairs):
    data = dict(pairs)
    if len(data) != len(pairs):
        raise WanFailoverError("WAN failover snapshot contains a duplicate field")
    return data


def _invalid_constant(_value):
    raise WanFailoverError("WAN failover snapshot contains an invalid JSON constant")


def _exact(left, right):
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True)


def _native_wan(wan_id, metric, monitors, health=False):
    row = {"interface": {"id": wan_id}, "routingTable": _SUPPORTED_WANS[wan_id][0],
           "monitors": monitors, "metric": metric, "weight": 50}
    if health:
        row["monitorHealthThreshold"] = 1
    return row


def decode_wan_failover(system_cfg: str, *, revision: str) -> WanFailoverIntent:
    """Recognize the exact single-WAN baseline or the two pinned binary ICMP SLAs."""
    if not isinstance(system_cfg, str) or not isinstance(revision, str) or not revision:
        raise WanFailoverError("WAN failover requires a complete snapshot and a revision")
    try:
        data = json.loads(system_cfg, object_pairs_hook=_distinct_keys, parse_constant=_invalid_constant)
        udapi = data["udapi"]
        section = udapi["services"]["wanFailover"]
        rows = section["wanInterfaces"]
        version = udapi["versionDetail"][_VERSION]
    except (KeyError, TypeError, ValueError, RecursionError) as error:
        raise WanFailoverError("WAN failover snapshot is incomplete or invalid") from error
    if (type(udapi.get("version")) is not int or udapi["version"] != 48 or udapi.get("versionFormat") != "v2"
            or type(version) is not int or version != 11
            or not isinstance(section, dict) or section.keys() != {"enabled", "wanInterfaces"}
            or section["enabled"] is not True or not isinstance(rows, list)):
        raise WanFailoverError("Unsupported native WAN failover schema")

    baseline = [_native_wan("eth0", 1, [{**item, "id": i} for i, item in enumerate(_DEFAULT_MONITORS, start=1)])]
    if _exact(rows, baseline):
        return WanFailoverIntent(revision, None)
    if len(rows) != len(_SUPPORTED_WANS):
        raise WanFailoverError("WAN failover needs both explicitly mapped WANs")

    priorities = {}
    seen = set()
    for index, row in enumerate(rows):
        interface = row.get("interface") if isinstance(row, dict) else None
        wan_id = interface.get("id") if isinstance(interface, dict) else None
        if not isinstance(wan_id, str) or wan_id not in _SUPPORTED_WANS or wan_id in seen:
            raise WanFailoverError("WAN failover requires two distinct pinned interface identities")
        seen.add(wan_id)
        metric = row.get("metric")
        if type(metric) is not int or metric not in (1, 2) or metric in priorities:
            raise WanFailoverError("WAN failover needs unique primary and backup priorities")
        monitor = {"id": 2 * index + 1, "interval": 3, "timePeriod": 7, "target": _SUPPORTED_WANS[wan_id][3],
                   "type": "icmp", "alert": {"lossThreshold": 99}}
        history = {**_STATISTICS_MONITOR, "id": 2 * index + 2}
        if not _exact(row, _native_wan(wan_id, metric, [monitor, history], health=True)):
            raise WanFailoverError("WAN failover needs the pinned local ICMP SLA and default statistics monitor")
        priorities[metric] = wan_id
    return WanFailoverIntent(revision, priorities[1])


def _configuration(primary, destination):
    if primary is None:
        return None
    hops = {}
    for wan_id, (_, interface, _, peer) in _SUPPORTED_WANS.items():
        hops[peer] = {"interface": interface, "metric": "10" if wan_id == primary else "20",
                      "check": {"target": {peer: {"interface": interface}}, "timeout": "1", "type": "icmp"}}
    return {"route": {destination: {"next-hop": hops}}}


def _verify_kernel_routes(rows, configuration, destination):
    if not isinstance(rows, list):
        raise WanFailoverError("Failover planning needs an all-table protocol 111 route snapshot")
    known = set()
    if configuration is not None:
        known = {(gateway, hop["interface"], int(hop["metric"]))
                 for gateway, hop in configuration["route"][destination]["next-hop"].items()}
    label = "default" if destination == DEFAULT_ROUTE else _PROBE_DESTINATION
    for route in rows:
        if (not isinstance(route, dict) or route.keys() - {"dst", "gateway", "dev", "metric", "flags", "table"}
                or route.get("dst") != label or route.get("table", "main") != "main"
                or type(route.get("metric")) is not int or route.get("flags") not in ([], ["linkdown"])
                or not isinstance(route.get("gateway"), str) or not isinstance(route.get("dev"), str)):
            raise WanFailoverError("Foreign protocol 111 route could be removed by VyOS")
        identity = (route["gateway"], route["dev"], route["metric"])
        if identity not in known:
            raise WanFailoverError("Foreign or duplicate protocol 111 route could be removed by VyOS")
        known.remove(identity)


def plan_failover_route(intent, *, current, verified, kernel_routes, live_interfaces, destination=_HOST_ROUTE):
    """Plan an owned default or probe route over the two supported uplinks."""
    if (not isinstance(intent, WanFailoverIntent) or not isinstance(intent.revision, str) or not intent.revision
            or intent.primary not in (None, *_SUPPORTED_WANS)):
        raise WanFailoverError("Failover planning needs a verified, scoped native intent")
    if destination not in (_HOST_ROUTE, DEFAULT_ROUTE):
        raise WanFailoverError("WAN failover supports only the default route and the configured probe host route")
    if current != verified or current not in (None, *(_configuration(wan_id, destination) for wan_id in _SUPPORTED_WANS)):
        raise WanFailoverError("The global VyOS failover configuration differs from verified ownership")
    _verify_kernel_routes(kernel_routes, current, destination)
    desired = _configuration(intent.primary, destination)
    if desired is None:
        commands = ({"op": "delete", "path": list(_CONFIG_PATH)},) if current is not None else ()
        return WanFailoverPlan(desired, commands)

    commands = []
    for _, interface, local, peer in _SUPPORTED_WANS.values():
        record = live_interfaces.get(interface) if isinstance(live_interfaces, dict) else None
        if (not isinstance(record, tuple) or len(record) != 2 or not isinstance(record[0], (list, tuple))
                or not isinstance(record[1], str)
                or not {"UP", "LOWER_UP"}.issubset(record[0])
                or interface_ipv4_addresses(record[1]) != [IPv4Interface(local)]):
            raise WanFailoverError("The VyOS failover WAN does not match its pinned active IPv4 link")
        hop = [*_CONFIG_PATH, "route", destination, "next-hop", peer]
        metric = "10" if peer == _SUPPORTED_WANS[intent.primary][3] else "20"
        if current is None:
            for leaf in (("interface", interface), ("check", "type", "icmp"), ("check", "timeout", "1"),
                         ("check", "target", peer, "interface", interface)):
                commands.append({"op": "set", "path": [*hop, *leaf]})
        if current != desired:
            commands.append({"op": "set", "path": [*hop, "metric", metric]})
    return WanFailoverPlan(desired, tuple(commands))
