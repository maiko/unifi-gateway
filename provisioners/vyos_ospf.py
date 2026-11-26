"""Normalize native OSPF and plan one owned VyOS IPv4 OSPF process."""

from copy import deepcopy
from dataclasses import dataclass, field
from functools import partial
import hmac
from ipaddress import IPv4Address, IPv4Interface, ip_interface
import json
import re

from collectors.vyos import interface_ipv4_addresses
from provisioners.uxg_schema import OSPF_VERSIONS, selected_schema

_OSPF_PATH = ("protocols", "ospf")
_ROUTER = "routes/ospf"
_AREAS = "routes/ospf/areas"
_INTERFACES = "routes/ospf/interfaces"
_LAN_PORTS = ("eth1", "eth2", "eth3")
_PLAIN = "plaintext-password"
_FRR_AUTH_MODES = {_PLAIN: "authenticationSimplePassword", "md5": "authenticationMessageDigest"}


class OspfIntentError(ValueError):
    """The gateway configuration does not establish the owned OSPF process."""


@dataclass(frozen=True, slots=True)
class OspfScope:
    router_id: str | None
    controller_interface: str
    vyos_interface: str
    interface_address: str

    def __post_init__(self):
        bridge = re.fullmatch(r"br([1-9][0-9]{0,3})", self.controller_interface) if isinstance(
            self.controller_interface, str
        ) else None
        if (
            bridge is None or int(bridge[1]) > 4094 or not isinstance(self.vyos_interface, str)
            or len(self.vyos_interface) > 15 or re.fullmatch(rf"eth[0-9]+\.{bridge[1]}", self.vyos_interface) is None
        ):
            raise OspfIntentError("OSPF needs one routed controller LAN bridge mapped to the same VyOS VLAN")
        try:
            router_id = IPv4Address(self.router_id) if isinstance(self.router_id, str) else None
            gateway = IPv4Interface(self.interface_address) if isinstance(self.interface_address, str) else None
        except ValueError:
            raise OspfIntentError("OSPF needs valid pinned IPv4 identities") from None
        if self.router_id is not None and (router_id is None or str(router_id) != self.router_id or not _unicast(router_id)):
            raise OspfIntentError("OSPF needs a canonical unicast router ID")
        if (
            gateway is None or str(gateway) != self.interface_address or not _unicast(gateway.ip)
            or gateway.network.prefixlen == 0
            or not gateway.network.network_address < gateway.ip < gateway.network.broadcast_address
        ):
            raise OspfIntentError("OSPF needs a canonical routed LAN IPv4 address")


@dataclass(frozen=True, slots=True)
class OspfSettings:
    router_id: str
    cost: int
    hello_interval: int
    dead_interval: int
    passive: bool
    plaintext_password: str | None = field(default=None, repr=False)
    md5_keys: tuple[tuple[int, str], ...] = field(default=(), repr=False)

    def __post_init__(self):
        try:
            address = IPv4Address(self.router_id) if isinstance(self.router_id, str) else None
        except ValueError:
            address = None
        if address is None or str(address) != self.router_id or address.is_unspecified:
            raise OspfIntentError("OSPF needs a canonical nonzero IPv4 router ID")
        for name, value in (("cost", self.cost), ("hello interval", self.hello_interval), ("dead interval", self.dead_interval)):
            if type(value) is not int or not 1 <= value <= 65535:
                raise OspfIntentError(f"OSPF {name} must be an integer from 1 to 65535")
        if self.dead_interval <= self.hello_interval:
            raise OspfIntentError("OSPF dead interval must exceed the hello interval")
        if type(self.passive) is not bool:
            raise OspfIntentError("OSPF passive interface needs a boolean value")
        if self.passive and (self.plaintext_password is not None or self.md5_keys):
            raise OspfIntentError("OSPF passive interface must use the controller's authentication-off mode")

    @property
    def has_authentication(self):
        return self.plaintext_password is not None or bool(self.md5_keys)


@dataclass(frozen=True, slots=True)
class OspfIntent:
    revision: str
    scope: OspfScope
    settings: OspfSettings | None
    _versions: tuple[tuple[str, int], ...]

    @property
    def enabled(self) -> bool:
        return self.settings is not None

    @property
    def cost(self) -> int | None:
        return self.settings.cost if self.settings is not None else None


@dataclass(frozen=True, slots=True)
class OspfPlan:
    desired_ospf: dict | None
    commands: tuple[dict, ...] = field(repr=False)


def decode_ospf_intent(
    system_cfg: str, *, revision: str, scope: OspfScope,
    message_broker=False, dns_forwarder=False, nat=False, wireguard=False,
) -> OspfIntent:
    """Decode a single-interface OSPF process in a normal area."""
    if not isinstance(revision, str) or not revision:
        raise OspfIntentError("OSPF snapshot needs a controller revision")
    if not isinstance(scope, OspfScope) or not isinstance(system_cfg, str):
        raise OspfIntentError("OSPF snapshot needs a configured scope and a JSON string")
    try:
        document = json.loads(system_cfg, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except OspfIntentError:
        raise
    except (ValueError, RecursionError):
        raise OspfIntentError("OSPF snapshot is not valid JSON") from None
    versions = selected_schema(
        message_broker=message_broker, dns_forwarder=dns_forwarder, nat=nat, wireguard=wireguard,
    ) | OSPF_VERSIONS
    udapi = document.get("udapi") if isinstance(document, dict) else None
    _require_schema(udapi, versions)
    return OspfIntent(revision, scope, _native_settings(udapi, scope), tuple(versions.items()))


def scrub_ospf_policy(udapi: dict, intent: OspfIntent) -> dict:
    """Remove the three validated OSPF sections and their version declarations."""
    if not isinstance(intent, OspfIntent):
        raise OspfIntentError("OSPF policy needs a matched UDAPI snapshot and intent")
    _require_schema(udapi, dict(intent._versions))
    if _native_settings(udapi, intent.scope) != intent.settings:
        raise OspfIntentError("OSPF snapshot differs from the decoded intent")
    normalized = deepcopy(udapi)
    for key in OSPF_VERSIONS:
        normalized.pop(key, None)
        del normalized["versionDetail"][key]
    return normalized


def plan_ospf_commands(
    intent: OspfIntent, *, scope: OspfScope, current_ospf: dict | None, verified_ospf: dict | None,
    current_ethernet: dict, live_interfaces: dict, proof_key: bytes | None = None,
) -> OspfPlan:
    """Plan against the complete default-VRF OSPF root and current LAN evidence."""
    if not isinstance(intent, OspfIntent) or not isinstance(scope, OspfScope) or intent.scope != scope:
        raise OspfIntentError("OSPF intent belongs to another configured scope")
    _require_owned_tree(scope, verified_ospf)
    if current_ospf != verified_ospf:
        raise OspfIntentError("VyOS OSPF root differs from verified ownership")
    if not intent.enabled:
        commands = () if current_ospf is None else ({"op": "delete", "path": list(_OSPF_PATH)},)
        return OspfPlan(None, commands)

    _require_active_lan(scope, current_ethernet, live_interfaces)
    raw = _desired_tree(scope, intent.settings)
    desired = redact_ospf_config(raw, scope=scope, proof_key=proof_key)
    if current_ospf == desired:
        return OspfPlan(desired, ())
    interface = [*_OSPF_PATH, "interface", scope.vyos_interface]
    observed = current_ospf or {"parameters": {}, "interface": {}}
    commands = []
    if observed["parameters"] != desired["parameters"]:
        commands.append({"op": "set", "path": [*_OSPF_PATH, "parameters", "router-id"], "value": intent.settings.router_id})
    previous = observed["interface"].get(scope.vyos_interface, {})
    target = desired["interface"][scope.vyos_interface]
    for name, value in target.items():
        if name == "authentication":
            continue
        if previous.get(name) != value:
            command = {"op": "set", "path": [*interface, name]}
            if isinstance(value, str):
                command["value"] = value
            commands.append(command)
    if "passive" in previous and "passive" not in target:
        commands.append({"op": "delete", "path": [*interface, "passive"]})
    commands.extend(_auth_commands(
        [*interface, "authentication"], previous.get("authentication"), target.get("authentication"),
        raw["interface"][scope.vyos_interface].get("authentication"),
    ))
    return OspfPlan(desired, tuple(commands))


def verify_ospf_state(
    *, scope: OspfScope, expected_ospf: dict | None, current_ospf: dict | None,
    current_ethernet: dict, live_interfaces: dict,
) -> None:
    """Check the exact configured process and its active IPv4 interface."""
    if not isinstance(scope, OspfScope):
        raise OspfIntentError("OSPF read-back needs a configured scope")
    _require_owned_tree(scope, expected_ospf)
    if current_ospf != expected_ospf:
        raise OspfIntentError("VyOS OSPF read-back differs from the intended root")
    if expected_ospf is not None:
        _require_active_lan(scope, current_ethernet, live_interfaces)


def verify_ospf_runtime(scope: OspfScope, expected: dict, observed: dict) -> None:
    interfaces = observed.get("interfaces")
    row = interfaces.get(scope.vyos_interface) if isinstance(interfaces, dict) else None
    if not isinstance(row, dict) or row.get("ifUp") is not True or row.get("ospfEnabled") is not True:
        raise OspfIntentError("VyOS OSPF interface is unavailable")
    if row.get("routerId") != expected["parameters"]["router-id"]:
        raise OspfIntentError("VyOS OSPF has not activated the intended router ID")
    settings = expected["interface"][scope.vyos_interface]
    fields = {
        "area": "0.0.0.0", "networkType": "BROADCAST", "cost": int(settings["cost"]),
        "timerMsecs": int(settings["hello-interval"]) * 1000, "timerDeadSecs": int(settings["dead-interval"]),
    }
    passive = "passive" in settings
    if (
        any(not _matches(row.get(key), value) for key, value in fields.items())
        or row.get("timerPassiveIface", False) is not passive
        or (not passive and type(row.get("timerHelloInMsecs")) is not int)
    ):
        raise OspfIntentError("VyOS OSPF interface differs from the intended cost, timers or passive mode")
    authentication = settings.get("authentication")
    expected_mode = _FRR_AUTH_MODES[next(iter(authentication))] if authentication else "authenticationNone"
    if row.get("authentication", "authenticationNone") != expected_mode:
        raise OspfIntentError("VyOS OSPF interface differs from the intended authentication mode")


def verify_ospf_router_id_edit(scope: OspfScope, current: dict, observed: dict) -> None:
    verify_ospf_runtime(scope, current, observed)
    count = observed["interfaces"][scope.vyos_interface].get("nbrCount")
    if type(count) is not int or count < 0:
        raise OspfIntentError("VyOS OSPF neighbor count is unavailable for the router ID edit")
    if count:
        raise OspfIntentError("VyOS OSPF router ID changes require the current neighbors to be withdrawn")


def _unicast(address):
    return not (address.is_unspecified or address.is_multicast or address.is_loopback
                or address.is_link_local or address.is_reserved)


def _unique_fields(pairs):
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise OspfIntentError("OSPF snapshot contains a duplicate JSON field")
        fields[key] = value
    return fields


def _invalid_constant(_value):
    raise OspfIntentError("OSPF snapshot contains a non-JSON constant")


def _matches(value, expected):
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return value.keys() == expected.keys() and all(_matches(value[key], item) for key, item in expected.items())
    if isinstance(expected, list):
        return len(value) == len(expected) and all(_matches(a, b) for a, b in zip(value, expected))
    return value == expected


def _require_schema(udapi, versions):
    if (
        not isinstance(udapi, dict) or not _matches(udapi.get("versionDetail"), versions)
        or not _matches(udapi.get("version"), 48) or udapi.get("versionFormat") != "v2"
    ):
        raise OspfIntentError("Unsupported UDAPI OSPF schema")


def _native_settings(udapi, scope):
    ospf_keys = {key for key in udapi if isinstance(key, str) and (key == _ROUTER or key.startswith(_ROUTER + "/"))}
    if not ospf_keys:
        return None
    if ospf_keys != OSPF_VERSIONS.keys():
        raise OspfIntentError("OSPF snapshot needs the required router, area and interface sections with no additional settings")
    configured = udapi[_ROUTER]
    if not isinstance(configured, dict):
        raise OspfIntentError("OSPF snapshot needs a router configuration object")
    router = {
        "enabled": True,
        "routerID": configured.get("routerID"),
        "redistributeStatic": {"enabled": False, "metric": 10, "metricType": "type1"},
        "redistributeConnected": {"enabled": False, "metric": 10, "metricType": "type1"},
        "redistributeBGP": {"enabled": False, "metric": 10, "metricType": "type2"},
        "announceDefaultRoute": False,
        "passiveInterfaces": False,
    }
    areas = [{
        "areaID": "0.0.0.0",
        "areaType": "normal",
        "authentication": "off",
        "networks": [{"source": "static", "address": str(IPv4Interface(scope.interface_address).network)}],
    }]
    if not _matches(udapi[_ROUTER], router) or not _matches(udapi[_AREAS], areas):
        raise OspfIntentError("OSPF router or area differs from the pinned no-redistribution LAN scope")
    rows = udapi[_INTERFACES]
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise OspfIntentError("OSPF needs exactly one configured LAN interface")
    row = rows[0]
    settings = OspfSettings(
        router["routerID"], row.get("cost"), row.get("helloInterval"), row.get("deadInterval"), row.get("passiveInterface"),
        *_decode_authentication(row.get("authentication")),
    )
    interface = {
        "id": scope.controller_interface,
        "cost": settings.cost,
        "authentication": row.get("authentication"),
        "helloInterval": settings.hello_interval,
        "deadInterval": settings.dead_interval,
        "passiveInterface": settings.passive,
    }
    if not _matches(row, interface):
        raise OspfIntentError("OSPF interface differs from the pinned LAN binding")
    _require_controller_lan(udapi.get("interfaces"), scope)
    return settings


def _require_controller_lan(rows, scope):
    name = scope.controller_interface
    vlan = int(name[2:])
    members = {f"{port}.{vlan}": port for port in _LAN_PORTS}
    expected = {
        **{
            port: {"identification": {"id": port, "type": "ethernet"}, "status": {"enabled": True}}
            for port in _LAN_PORTS
        },
        name: {
            "identification": {"id": name, "type": "bridge"},
            "status": {"enabled": True, "comment": "LAN"},
            "addresses": [{"type": "static", "cidr": scope.interface_address, "version": "v4"}],
            "bridge": {"id": vlan, "interfaces": [{"id": member} for member in members]},
        },
        **{
            member: {
                "identification": {"id": member, "type": "vlan"},
                "status": {"enabled": True},
                "vlan": {"id": vlan, "interface": {"id": port}},
            }
            for member, port in members.items()
        },
    }
    if not isinstance(rows, list):
        raise OspfIntentError("OSPF needs complete controller interface topology")
    observed = {}
    for row in rows:
        identity = row.get("identification") if isinstance(row, dict) else None
        row_name = identity.get("id") if isinstance(identity, dict) else None
        if not isinstance(row_name, str) or not row_name or row_name in observed:
            raise OspfIntentError("OSPF snapshot contains ambiguous controller interface topology")
        observed[row_name] = row
    if any(not _matches(observed.get(key), value) for key, value in expected.items()):
        raise OspfIntentError("OSPF controller topology differs from the pinned routed LAN")


def _desired_tree(scope, settings):
    interface = {
        "area": "0", "network": "broadcast", "hello-interval": str(settings.hello_interval),
        "dead-interval": str(settings.dead_interval), "cost": str(settings.cost),
    }
    if settings.passive:
        interface["passive"] = {}
    if settings.plaintext_password is not None:
        interface["authentication"] = {_PLAIN: settings.plaintext_password}
    elif settings.md5_keys:
        interface["authentication"] = {
            "md5": {"key-id": {str(key_id): {"md5-key": key} for key_id, key in settings.md5_keys}},
        }
    return {
        "parameters": {"router-id": settings.router_id},
        "interface": {scope.vyos_interface: interface},
    }


def _check_credential(value, max_bytes):
    # The stock FRR template renders these values unquoted.
    if not isinstance(value, str) or len(value) > max_bytes or re.fullmatch(r"[A-Za-z0-9._~!@%+=,:?-]+", value) is None:
        raise OspfIntentError("OSPF authentication key is empty, has unsupported characters or exceeds the stock limit")
    return value


def _decode_authentication(value):
    if value == {"authType": "off"}:
        return None, ()
    if isinstance(value, dict) and value.keys() == {"authType", "authKey"} and value["authType"] == "plainText":
        return _check_credential(value["authKey"], 8), ()
    if isinstance(value, dict) and value.keys() == {"authType", "authKeysMD5"} and value["authType"] == "md5":
        entries = value["authKeysMD5"]
        if isinstance(entries, list) and 1 <= len(entries) <= 255:
            keys = {}
            for entry in entries:
                if not isinstance(entry, dict) or entry.keys() != {"id", "key"}:
                    break
                key_id = entry["id"]
                if type(key_id) is not int or not 1 <= key_id <= 255 or key_id in keys:
                    break
                keys[key_id] = _check_credential(entry["key"], 16)
            else:
                return None, tuple(sorted(keys.items()))
    raise OspfIntentError("Unsupported or incomplete OSPF interface authentication")


def _credential_proof(proof_key, index, value, max_bytes):
    if not isinstance(proof_key, bytes) or len(proof_key) != 32:
        raise OspfIntentError("OSPF credential proof key is unavailable")
    key = _check_credential(value, max_bytes)
    digest = hmac.digest(proof_key, f"ospf-auth/{index}\0{key}".encode(), "sha256").hex()
    return f"hmac-sha256:{digest}"


def _existing_proof(_index, value, _max_bytes):
    if not isinstance(value, str) or re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", value) is None:
        raise OspfIntentError("Saved OSPF authentication has an invalid credential proof")
    return value


def _checked_authentication(node, normalize):
    if isinstance(node, dict) and node.keys() == {_PLAIN}:
        return {_PLAIN: normalize("plain", node[_PLAIN], 8)}
    if isinstance(node, dict) and node.keys() == {"md5"}:
        md5 = node["md5"]
        keys = md5.get("key-id") if isinstance(md5, dict) and md5.keys() == {"key-id"} else None
        if isinstance(keys, dict) and 1 <= len(keys) <= 255:
            verified = {}
            for index, config in keys.items():
                if (
                    not isinstance(index, str) or re.fullmatch(r"[1-9][0-9]{0,2}", index) is None or int(index) > 255
                    or not isinstance(config, dict) or config.keys() != {"md5-key"}
                ):
                    break
                verified[index] = {"md5-key": normalize(f"md5/{index}", config["md5-key"], 16)}
            else:
                return {"md5": {"key-id": verified}}
    raise OspfIntentError("VyOS OSPF authentication falls outside verified ownership")


def redact_ospf_config(tree: dict | None, *, scope: OspfScope, proof_key: bytes | None) -> dict | None:
    """Return the exact owned tree with keyed proofs in place of credentials."""
    return _checked_ospf_tree(scope, tree, partial(_credential_proof, proof_key))


def ospf_config_has_authentication(scope: OspfScope, tree: dict | None) -> bool:
    interfaces = tree.get("interface") if isinstance(tree, dict) else None
    interface = interfaces.get(scope.vyos_interface) if isinstance(interfaces, dict) else None
    return isinstance(interface, dict) and "authentication" in interface


def _require_owned_tree(scope, tree):
    _checked_ospf_tree(scope, tree, _existing_proof)


def _checked_ospf_tree(scope, tree, normalize):
    if tree is None:
        return
    try:
        interface = tree["interface"][scope.vyos_interface]
        fields = [interface[name] for name in ("cost", "hello-interval", "dead-interval")]
        if any(not isinstance(field, str) or re.fullmatch(r"[1-9][0-9]{0,4}", field) is None for field in fields):
            raise ValueError
        cost, hello, dead = map(int, fields)
        settings = OspfSettings(tree["parameters"]["router-id"], cost, hello, dead, "passive" in interface)
    except (ValueError, KeyError, TypeError):
        raise OspfIntentError("Stored OSPF root falls outside verified ownership") from None
    expected = _desired_tree(scope, settings)
    expected_interface = expected["interface"][scope.vyos_interface]
    if "authentication" in interface and not settings.passive:
        expected_interface["authentication"] = interface["authentication"]
    if not _matches(tree, expected):
        raise OspfIntentError("Stored OSPF root falls outside verified ownership")
    if "authentication" in expected_interface:
        expected_interface["authentication"] = _checked_authentication(interface["authentication"], normalize)
    return expected


def _auth_commands(path, previous, target, raw):
    if previous == target:
        return
    if previous and (not target or previous.keys() != target.keys()):
        yield {"op": "delete", "path": path}
        previous = None
    if not target:
        return
    if _PLAIN in target:
        yield {"op": "set", "path": [*path, _PLAIN], "value": raw[_PLAIN]}
        return
    old_keys = previous["md5"]["key-id"] if previous else {}
    target_keys = target["md5"]["key-id"]
    for key_id in sorted(old_keys.keys() - target_keys.keys(), key=int):
        yield {"op": "delete", "path": [*path, "md5", "key-id", key_id]}
    for key_id, proof in target_keys.items():
        if old_keys.get(key_id) != proof:
            yield {"op": "set", "path": [*path, "md5", "key-id", key_id, "md5-key"],
                   "value": raw["md5"]["key-id"][key_id]["md5-key"]}


def _require_active_lan(scope, ethernet, live):
    parent, tag = scope.vyos_interface.split(".")
    parent_config = ethernet.get(parent) if isinstance(ethernet, dict) else None
    vifs = parent_config.get("vif") if isinstance(parent_config, dict) else None
    child = vifs.get(tag) if isinstance(vifs, dict) else None
    if not isinstance(child, dict) or {"disable", "vrf"} & (parent_config.keys() | child.keys()):
        raise OspfIntentError("OSPF needs an enabled VyOS Ethernet VLAN in the default VRF")
    values = child.get("address")
    if isinstance(values, str):
        values = [values]
    link = live.get(scope.vyos_interface) if isinstance(live, dict) else None
    if (
        not isinstance(values, list) or any(not isinstance(value, str) for value in values)
        or not isinstance(link, (tuple, list)) or len(link) != 2
        or not isinstance(link[0], (tuple, list)) or not isinstance(link[1], str)
        or any(not isinstance(flag, str) for flag in link[0])
        or not {"UP", "LOWER_UP", "MULTICAST"}.issubset(link[0])
    ):
        raise OspfIntentError("OSPF needs an active multicast-capable VyOS link and static address evidence")
    try:
        configured = [address for address in map(ip_interface, values) if address.version == 4]
        operational = interface_ipv4_addresses(link[1])
    except ValueError:
        raise OspfIntentError("OSPF interface contains an invalid or dynamic configured address") from None
    if configured != [IPv4Interface(scope.interface_address)] or operational != configured:
        raise OspfIntentError("OSPF interface must have exactly its pinned configured and live IPv4 address")
