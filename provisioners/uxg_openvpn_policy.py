"""Normalize the exact generated policy of the observed TLS VPN client."""

from copy import deepcopy
import json
import re
from uuid import UUID

from provisioners.uxg_openvpn import (
    OPENVPN_CLIENT_CAPABILITY,
    OPENVPN_VERSIONS,
    decode_openvpn_intent,
)


OPENVPN_CLIENT_VERSION = "vpn/openvpn/raws"
_TUNNEL_REFERENCE = re.compile(r"tunovpnc|OPENVPN_CLIENT", re.IGNORECASE)


def normalize_openvpn_payload(system_cfg, *, server_name):
    intent = decode_openvpn_intent(system_cfg, udapi_caps=OPENVPN_CLIENT_CAPABILITY, server_name=server_name)
    document = json.loads(system_cfg)
    document["udapi"] = scrub_openvpn_policy(document["udapi"], client_id=intent.native_id if intent else None)
    return json.dumps(document), intent


def scrub_openvpn_policy(udapi: dict, *, client_id: str | None) -> dict:
    """Remove only the companion policy for the pinned native client."""
    if not isinstance(udapi, dict) or client_id not in {None, "1"}:
        raise ValueError("Unsupported native OpenVPN scope")
    result = deepcopy(udapi)
    versions = result.get("versionDetail")
    if not isinstance(versions, dict) or type(versions.get(OPENVPN_CLIENT_VERSION)) is not int:
        raise ValueError("Native OpenVPN schema is unavailable")
    if versions.pop(OPENVPN_CLIENT_VERSION) != OPENVPN_VERSIONS[OPENVPN_CLIENT_VERSION]:
        raise ValueError("Unsupported native OpenVPN schema")
    if any(key.startswith("vpn/openvpn/") and key != OPENVPN_CLIENT_VERSION for key in result):
        raise ValueError("Unsupported native OpenVPN feature alongside the scoped client")
    if client_id is not None:
        clients = result.pop(OPENVPN_CLIENT_VERSION, None)
        if (not isinstance(clients, list) or len(clients) != 1 or not isinstance(clients[0], dict)
                or clients[0].get("id") != client_id or clients[0].get("enabled") is not True):
            raise ValueError("Native OpenVPN client differs from the authorized scope")
        _scrub_gateway_jumps(result.get("firewall/filter"))
        _scrub_masquerade(result.get("firewall/nat"))
        _scrub_wan_monitor(result.get("services"))
    elif OPENVPN_CLIENT_VERSION in result:
        raise ValueError("Native OpenVPN snapshot disagrees with the absent client")
    if _TUNNEL_REFERENCE.search(json.dumps(result)):
        raise ValueError("An unmanaged policy still refers to the scoped OpenVPN tunnel")
    return result


def _exact(value, expected):
    return json.dumps(value, sort_keys=True) == json.dumps(expected, sort_keys=True)


def _require_rule(rule, expected):
    origin = rule.get("originId") if isinstance(rule, dict) else None
    try:
        identity = UUID(origin) if isinstance(origin, str) else None
    except ValueError:
        identity = None
    if identity is None or identity.version != 4 or str(identity) != origin:
        raise ValueError("OpenVPN jump lacks a native rule origin")
    if not _exact(rule, {**expected, "originId": origin}):
        raise ValueError("OpenVPN jump differs from the observed generated rule")


def _chain_rules(chains, index, name):
    if not isinstance(chains, list) or len(chains) <= index:
        raise ValueError("OpenVPN companion lacks its ordered native chains")
    chain = chains[index]
    if (not isinstance(chain, dict) or not isinstance(chain.get("config"), dict)
            or chain["config"].get("name") != name or not isinstance(chain.get("rules"), list)
            or len(chain["rules"]) != 5):
        raise ValueError("OpenVPN companion differs from the observed native chains")
    return chain["rules"]


def _scrub_gateway_jumps(chains):
    for index, chain, target, direction in (
        (0, "INPUT", "WAN_LOCAL", "inInterface"), (6, "OUTPUT", "LOCAL_WAN", "outInterface"),
    ):
        rules = _chain_rules(chains, index, chain)
        _require_rule(rules[-1], {
            "id": 30004, "target": target, "negateInInterface": False, "negateOutInterface": False,
            "description": f"Forward OPENVPN_CLIENT traffic to {target}", "log": False, "protocol": "all",
            "connectionState": [], direction: {"id": "tunovpnc+"}, "ipVersion": "both",
        })
        rules.pop()
    forward = _chain_rules(chains, 13, "FORWARD_IN")
    _require_rule(forward[1], {
        "id": 30001, "target": "WAN_IN", "description": "WAN_IN client jump (interface: tunovpnc1)",
        "log": False, "inInterface": {"id": "tunovpnc1"}, "ipVersion": "both",
    })
    for index, bridge in enumerate(("br0", "br110", "br120"), start=2):
        _require_rule(forward[index], {
            "id": 30000 + index, "target": "LAN_IN", "description": f"LAN_IN jump (interface: {bridge})",
            "log": False, "inInterface": {"id": bridge}, "ipVersion": "both",
        })
        forward[index]["id"] -= 1
    del forward[1]


def _scrub_masquerade(rules):
    if not isinstance(rules, list) or len(rules) != 2 or not _exact(rules[-1], {
        "id": 2, "chain": "POSTROUTING", "target": "MASQUERADE", "enabled": True, "log": False,
        "outInterface": {"id": "tunovpnc+"}, "ipVersion": "v4only",
    }):
        raise ValueError("OpenVPN companion lacks its exact native tunnel masquerade")
    rules.pop()


def _scrub_wan_monitor(services):
    failover = services.get("wanFailover") if isinstance(services, dict) else None
    interfaces = failover.get("wanInterfaces") if isinstance(failover, dict) else None
    if not isinstance(interfaces, list) or len(interfaces) != 2 or not _exact(interfaces[-1], {
        "interface": "tunovpnc1", "routingTable": 178, "monitors": [], "metric": 230, "weight": 10,
    }):
        raise ValueError("OpenVPN companion lacks its exact native tunnel monitoring placeholder")
    interfaces.pop()
