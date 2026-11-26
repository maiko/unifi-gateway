"""Validate UniFi policy generated for the supported dual-WAN configuration."""

import json
from uuid import UUID

from provisioners.uxg_wan_failover import (
    WanFailoverError, _DEFAULT_MONITORS, _SUPPORTED_WANS, _VERSION, _exact, _native_wan, decode_wan_failover,
)


_REMAINING_INTERFACE_ORDER = ("eth1", "eth1.120", "eth1.110", "eth3", "eth3.120", "eth3.110", "br0", "br120", "br110")
_BRIDGES = {"br0": 0, "br120": 120, "br110": 110}


def _uuid(value):
    try:
        identity = UUID(value) if isinstance(value, str) else None
    except ValueError:
        identity = None
    return identity is not None and identity.version == 4 and str(identity) == value


def _check_origin(entry, expected, reason):
    origin = entry.get("originId") if isinstance(entry, dict) else None
    if not _uuid(origin) or not _exact(entry, {**expected, "originId": origin}):
        raise WanFailoverError(reason)


def _normalize_default_routes(udapi, wan_order):
    routes = udapi.get("routes/static")
    system = udapi.get("system")
    if not isinstance(routes, list) or not isinstance(system, dict) or "defaultGateway" in system:
        raise WanFailoverError("Dual WAN needs the observed pair of table-specific defaults")
    defaults = [row for row in routes if isinstance(row, dict) and row.get("destination") == "0.0.0.0/0"]
    if len(defaults) != 2:
        raise WanFailoverError("Dual WAN needs exactly two generated default routes")
    origins = set()
    for row, wan_id in zip(defaults, wan_order):
        table, _, _, gateway = _SUPPORTED_WANS[wan_id]
        label = row.get("description")
        origin = label.removeprefix("WAN_DEFAULT_GATEWAY:") if isinstance(label, str) else None
        if not _uuid(origin) or origin in origins or not _exact(row, {
            "enabled": True, "type": "gateway", "destination": "0.0.0.0/0", "distance": 1, "table": table,
            "description": f"WAN_DEFAULT_GATEWAY:{origin}", "gateway": gateway,
        }):
            raise WanFailoverError("Unexpected dual-WAN default route properties")
        origins.add(origin)
    udapi["routes/static"] = [row for row in routes if row not in defaults]
    system["defaultGateway"] = [{"type": "static", "address": _SUPPORTED_WANS["eth0"][3], "version": "v4"}]


def _normalize_nat(udapi, wan_order):
    rows = udapi.get("firewall/nat")
    if not isinstance(rows, list) or len(rows) != 2:
        raise WanFailoverError("Dual WAN requires the observed pair of automatic IPv4 masquerades")
    for index, (row, wan_id) in enumerate(zip(rows, wan_order), start=1):
        _check_origin(row, {"id": index, "chain": "POSTROUTING", "target": "MASQUERADE", "ipVersion": "v4only",
                            "enabled": True, "log": False, "outInterface": {"id": wan_id},
                            "source": {"sets": [f"!ALL_ADDRv4_{wan_id}"]}},
                      "Unexpected dual-WAN masquerade policy")
    del rows[wan_order.index("eth2")]
    rows[0]["id"] = 1


def _normalize_firewall(udapi, wan_order):
    filters = udapi.get("firewall/filter")
    if not isinstance(filters, list):
        raise WanFailoverError("Dual WAN needs the observed firewall chains")
    for name, direction, wan, lan in (("INPUT", "inInterface", "WAN_LOCAL", "LAN_LOCAL"),
                                      ("OUTPUT", "outInterface", "LOCAL_WAN", "LOCAL_LAN"),
                                      ("FORWARD_IN", "inInterface", "WAN_IN", "LAN_IN")):
        chains = [chain for chain in filters if isinstance(chain, dict) and isinstance(chain.get("config"), dict)
                  and chain["config"].get("name") == name]
        rows = chains[0].get("rules") if len(chains) == 1 else None
        if not isinstance(rows, list) or len(rows) != 5:
            raise WanFailoverError("Unexpected ordered dual-WAN firewall chains")
        targets = [(interface, wan) for interface in wan_order] + [(bridge, lan) for bridge in ("br0", "br110", "br120")]
        for index, (row, (interface, target)) in enumerate(zip(rows, targets)):
            _check_origin(row, {"id": 30000 + index, "target": target,
                                "description": f"{target} jump (interface: {interface})", "log": False,
                                direction: {"id": interface}, "ipVersion": "both"},
                          "Unexpected dual-WAN firewall jump")
        del rows[wan_order.index("eth2")]
        for index, row in enumerate(rows):
            row["id"] = 30000 + index


def _normalize_interfaces(udapi, wan_order):
    rows = udapi.get("interfaces")
    if not isinstance(rows, list):
        raise WanFailoverError("Dual WAN needs the observed interface and bridge layout")
    ids = tuple(row.get("identification", {}).get("id") if isinstance(row, dict)
                and isinstance(row.get("identification"), dict) else None for row in rows)
    if ids != ("lo", *wan_order, *_REMAINING_INTERFACE_ORDER):
        raise WanFailoverError("Dual WAN interface order or scope differs from the observed layout")
    for index, wan_id in enumerate(wan_order, start=1):
        role = "WAN" if wan_id == "eth0" else "WAN2"
        if not _exact(rows[index], {
            "identification": {"id": wan_id, "type": "ethernet"}, "ethernet": {"lldp": {"enabled": False}},
            "status": {"enabled": True, "comment": role, "baseReachableTime": 30},
            "addresses": [{"version": "v4", "type": "static", "cidr": _SUPPORTED_WANS[wan_id][2]}],
        }):
            raise WanFailoverError("Dual WAN interface addresses or features differ from the pinned scope")

    def member(port, tag):
        return f"{port}.{tag}" if tag else port

    for name, tag in _BRIDGES.items():
        row = rows[ids.index(name)]
        bridge = row.get("bridge")
        expected = {"interfaces": [{"id": member(port, tag)} for port in ("eth1", "eth3")], "id": tag}
        if not _exact(bridge, expected):
            raise WanFailoverError("Unexpected bridge membership after assigning WAN2")
        bridge["interfaces"].insert(1, {"id": member("eth2", tag)})

    del rows[1 + wan_order.index("eth2")]
    additions = [{"identification": {"id": "eth2", "type": "ethernet"}, "status": {"enabled": True}}]
    for tag in (120, 110):
        additions.append({"identification": {"id": member("eth2", tag), "type": "vlan"}, "status": {"enabled": True},
                          "vlan": {"id": tag, "interface": {"id": "eth2"}}})
    rows[5:5] = additions


def normalize_wan_failover_policy(system_cfg, *, revision):
    """Validate the generated WAN effects and recover the other settings for separate validation."""
    intent = decode_wan_failover(system_cfg, revision=revision)
    document = json.loads(system_cfg)
    udapi = document["udapi"]
    if intent.primary is not None:
        wan_order = tuple(row["interface"]["id"] for row in udapi["services"]["wanFailover"]["wanInterfaces"])
        _normalize_default_routes(udapi, wan_order)
        _normalize_nat(udapi, wan_order)
        _normalize_firewall(udapi, wan_order)
        _normalize_interfaces(udapi, wan_order)
    del udapi["versionDetail"][_VERSION]
    monitors = [{**_DEFAULT_MONITORS[0], "id": 1}, {**_DEFAULT_MONITORS[-1], "id": 2}]
    udapi["services"]["wanFailover"] = {"enabled": True, "wanInterfaces": [_native_wan("eth0", 1, monitors)]}
    return json.dumps(document), intent
