"""Map the UniFi mDNS settings to the managed VyOS repeater."""

from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from ipaddress import IPv4Interface
import json
import re
from uuid import UUID

from collectors.vyos import interface_ipv4_addresses
from provisioners.uxg_schema import selected_schema


_REPEATER_PATH = ("service", "mdns", "repeater")
MDNS_SERVICE_VERSION = {"services/mdns": 2}
_SERVICE_TYPE = re.compile(r"_[a-z0-9](?:[a-z0-9_-]{0,60}[a-z0-9])?\._(?:tcp|udp)\.local", re.IGNORECASE | re.ASCII)
# These Network presets omit the multicast DNS domain. Pass a complete
# service name to Avahi because its filters match substrings.
_LOCAL_PRESET_ALIASES = frozenset({
    "_amazonecho-remote._tcp", "_hap._tcp", "_hap._udp", "_matter._tcp",
    "_matter_gateway._tcp", "_matterc._udp", "_matterd._udp", "_scanner._tcp",
})
# VyOS joins all filters on one line, and Avahi 0.8 reads it in a 256-byte buffer.
_AVAHI_FILTER_LINE_LIMIT = 255
_CONTAINER_LABEL = "unifi.gateway.mdns-config"
_CONTAINER_RUNTIME_LABEL = "unifi_gateway_mdns_config"  # VyOS normalizes operational JSON keys.
_CONTAINER_IMAGE = re.compile(
    r"[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/[a-z0-9]+(?:[._/-][a-z0-9]+)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}|@sha256:[0-9a-f]{64})"
)
MDNS_CONTAINER_NAME = "uxg-mdns-reflector"
MDNS_CONTAINER_PATH = ("container", "name", MDNS_CONTAINER_NAME)
_CONTROLLER_LAN_PORTS = ("eth1", "eth2", "eth3")
_ADDRESS_SET = "mdns_addresses_name"
_PORT_SET = "mdns_ports_name"
_RULE_DESCRIPTION = "[LAN_LOCAL]Allow mDNS"
_GENERATED_SETS = [
    {"identification": {"name": _ADDRESS_SET, "type": "address"}, "description": "mDNS addresses",
     "entries": ["224.0.0.251", "ff02::fb"]},
    {"identification": {"name": _PORT_SET, "type": "port"}, "description": "mDNS ports", "entries": ["5353"]},
]


class MdnsIntentError(ValueError):
    """The gateway configuration does not establish the owned mDNS repeater."""


@dataclass(frozen=True, slots=True)
class MdnsScope:
    interfaces: dict[str, str]
    addresses: dict[str, str]

    def __post_init__(self):
        if (
            not isinstance(self.interfaces, dict) or len(self.interfaces) != 2
            or not isinstance(self.addresses, dict) or self.addresses.keys() != self.interfaces.keys()
        ):
            raise MdnsIntentError("mDNS needs two explicitly mapped and addressed LANs")
        networks = []
        for bridge, name in self.interfaces.items():
            match = re.fullmatch(r"br([1-9][0-9]{0,3})", bridge) if isinstance(bridge, str) else None
            if (
                match is None or int(match[1]) > 4094 or not isinstance(name, str) or len(name) > 15
                or re.fullmatch(rf"eth[0-9]+\.{match[1]}", name) is None
            ):
                raise MdnsIntentError("mDNS needs LAN bridges mapped to their exact tagged VyOS interfaces")
            gateway = _gateway(self.addresses[bridge])
            if any(gateway.network.overlaps(network) for network in networks):
                raise MdnsIntentError("mDNS LANs must have nonoverlapping IPv4 subnets")
            networks.append(gateway.network)
        object.__setattr__(self, "interfaces", dict(self.interfaces))
        object.__setattr__(self, "addresses", dict(self.addresses))


@dataclass(frozen=True, slots=True)
class MdnsPlan:
    desired_repeater: dict | None
    commands: tuple[dict, ...]


@dataclass(frozen=True, slots=True)
class MdnsIntent:
    revision: str
    scope: MdnsScope
    enabled: bool
    services: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MdnsContainerImage:
    reference: str
    image_id: str

    def __post_init__(self):
        if (not isinstance(self.reference, str) or len(self.reference) > 255
                or not _CONTAINER_IMAGE.fullmatch(self.reference)
                or not (self.reference.startswith("localhost/") or "@sha256:" in self.reference)
                or not isinstance(self.image_id, str) or not re.fullmatch(r"[0-9a-f]{64}", self.image_id)):
            raise MdnsIntentError("mDNS needs an explicit local image tag or registry digest and a pinned image ID")

    def require_preloaded(self, images):
        matches = [row for row in images if any(
            isinstance(row.get(key), list) and self.reference in row[key] for key in ("names", "repo_tags", "repo_digests")
        )]
        if len(matches) != 1 or matches[0].get("id") not in (self.image_id, f"sha256:{self.image_id}"):
            raise MdnsIntentError("VyOS mDNS container image is missing or differs from its pinned image ID")

    def configuration(self, scope, services):
        environment = {
            "UXG_MDNS_INTERFACES": {"value": ",".join(sorted(scope.interfaces.values()))},
            "UXG_MDNS_MODE": {"value": "specific" if services else "all"},
        }
        if services:
            environment["UXG_MDNS_FILTERS"] = {"value": ",".join(services)}
        configuration = {"image": self.reference, "allow-host-networks": {}, "uid": "65532", "gid": "65532",
                         "memory": "64", "cpu-quota": "0.25", "environment": environment}
        fingerprint = sha256(json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
        configuration["label"] = {_CONTAINER_LABEL: {"value": fingerprint}}
        return configuration

    def plan(self, intent, current, verified, live_interfaces):
        if current != verified:
            raise MdnsIntentError("VyOS mDNS container differs from verified ownership")
        if verified is not None:
            self._verify_configuration(intent.scope, verified)
        services = _service_types(intent.services)
        if type(intent.enabled) is not bool or (not intent.enabled and services):
            raise MdnsIntentError("mDNS planning needs an explicit enabled or disabled intent")
        if intent.enabled:
            _require_live_lans(intent.scope, live_interfaces)
        desired = self.configuration(intent.scope, services) if intent.enabled else None
        path = list(MDNS_CONTAINER_PATH)
        if desired == verified:
            return desired, ()
        if desired is None:
            return None, ({"op": "delete", "path": path},)

        commands = []
        if verified is None:
            commands.append({"op": "set", "path": path + ["allow-host-networks"]})
            commands.extend({"op": "set", "path": path + [key], "value": desired[key]}
                            for key in ("image", "uid", "gid", "memory", "cpu-quota"))
        previous = verified["environment"] if verified else {}
        environment = desired["environment"]
        commands.extend({"op": "delete", "path": path + ["environment", key]} for key in sorted(previous.keys() - environment.keys()))
        commands.extend({"op": "set", "path": path + ["environment", key, "value"], "value": entry["value"]}
                        for key, entry in sorted(environment.items()) if previous.get(key) != entry)
        commands.append({"op": "set", "path": path + ["label", _CONTAINER_LABEL, "value"],
                         "value": desired["label"][_CONTAINER_LABEL]["value"]})
        return desired, tuple(commands)

    def _verify_configuration(self, scope, configuration):
        try:
            filtered = configuration["environment"].get("UXG_MDNS_FILTERS")
            services = _service_types(filtered["value"].split(",")) if filtered is not None else ()
            if configuration == self.configuration(scope, services):
                return
        except (AttributeError, KeyError, TypeError, MdnsIntentError):
            pass
        raise MdnsIntentError("Verified VyOS mDNS container is outside its configured image and LAN scope")

    def verify(self, scope, expected, current, live_interfaces, backend):
        if expected != current:
            raise MdnsIntentError("VyOS mDNS container read-back differs from the intended configuration")
        rows = []
        for row in backend.show_containers():
            names = row.get("names")
            if not isinstance(names, list) or any(not isinstance(name, str) for name in names):
                raise MdnsIntentError("VyOS returned invalid container names")
            if MDNS_CONTAINER_NAME in names:
                rows.append(row)
        _verify_operation(scope, expected is not None, live_interfaces, backend.has_mdns_listener())
        memberships = backend.mdns_multicast_interfaces()
        if expected is None:
            if rows or memberships:
                raise MdnsIntentError("VyOS still has an mDNS container or multicast membership")
            return
        self._verify_configuration(scope, expected)
        fingerprint = expected["label"][_CONTAINER_LABEL]["value"]
        if len(rows) != 1 or not (
            rows[0]["names"] == [MDNS_CONTAINER_NAME] and rows[0].get("state") == "running"
            and rows[0].get("image_id") in (self.image_id, f"sha256:{self.image_id}")
            and type(rows[0].get("pid")) is int and rows[0]["pid"] > 0
            and isinstance(rows[0].get("labels"), dict) and rows[0]["labels"].get(_CONTAINER_RUNTIME_LABEL) == fingerprint
            and rows[0].get("mounts") == [] and rows[0].get("networks") == [] and rows[0].get("ports") is None
        ):
            raise MdnsIntentError("VyOS has no running mDNS container matching the pinned image and configuration")
        if memberships != set(scope.interfaces.values()):
            raise MdnsIntentError("VyOS mDNS container multicast memberships differ from the intended LANs")


def normalize_mdns_service_version(system_cfg: str) -> str:
    """Validate the mDNS extension before decoding shared gateway sections."""
    document = _decode_document(system_cfg)
    udapi = document["udapi"]
    _verify_service_version(udapi)
    if "services/mdns" not in udapi["versionDetail"]:
        return system_cfg
    del udapi["versionDetail"]["services/mdns"]
    return json.dumps(document)


def decode_mdns_intent(
    system_cfg: str, *, revision: str, scope: MdnsScope,
    message_broker=False, dns_forwarder=False, nat=False, wireguard=False,
) -> MdnsIntent:
    """Decode Off or two-LAN Custom mode after verifying native topology."""
    if not isinstance(revision, str) or not revision:
        raise MdnsIntentError("mDNS snapshot needs a controller revision")
    if not isinstance(scope, MdnsScope) or not isinstance(system_cfg, str):
        raise MdnsIntentError("mDNS snapshot needs a configured scope and a JSON string")
    udapi = _decode_document(system_cfg)["udapi"]
    versions = udapi["versionDetail"]
    expected = selected_schema(
        message_broker=message_broker, dns_forwarder=dns_forwarder, nat=nat, wireguard=wireguard,
    )
    if "services/mdns" in versions:
        expected.update(MDNS_SERVICE_VERSION)
    if (
        versions != expected or any(type(version) is not int for version in versions.values())
        or type(udapi.get("version")) is not int or udapi["version"] != 48 or udapi.get("versionFormat") != "v2"
    ):
        raise MdnsIntentError("Unsupported UDAPI mDNS schema")
    enabled, services = _native_mdns(udapi, scope)
    return MdnsIntent(revision, scope, enabled, services)


def scrub_mdns_policy(udapi: dict, intent: MdnsIntent) -> dict:
    """Exclude the mDNS service and its generated firewall rules after validation."""
    if not isinstance(udapi, dict) or not isinstance(intent, MdnsIntent):
        raise MdnsIntentError("mDNS policy needs a matched UDAPI snapshot and intent")
    if _native_mdns(udapi, intent.scope) != (intent.enabled, intent.services):
        raise MdnsIntentError("mDNS snapshot differs from the decoded intent")
    normalized = deepcopy(udapi)
    normalized["versionDetail"].pop("services/mdns", None)
    rules = _lan_local_rules(normalized.get("firewall/filter"))
    sets = normalized.get("firewall/sets")
    if not isinstance(sets, list):
        raise MdnsIntentError("mDNS snapshot needs its complete firewall set collection")
    origin = None
    if intent.enabled:
        origin = _remove_mdns_rule(rules)
        if sets[17:19] != _GENERATED_SETS:
            raise MdnsIntentError("Generated mDNS firewall set differs from the expected rule set")
        del sets[17:19]
        del normalized["services"]["mdns"]
    _reject_mdns_references(normalized, origin)
    return normalized


def _unique_fields(pairs):
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise MdnsIntentError("mDNS snapshot contains a duplicate JSON field")
        fields[key] = value
    return fields


def _invalid_constant(_value):
    raise MdnsIntentError("mDNS snapshot contains a non-JSON constant")


def _decode_document(system_cfg):
    try:
        document = json.loads(system_cfg, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except MdnsIntentError:
        raise
    except (TypeError, ValueError, RecursionError):
        raise MdnsIntentError("mDNS snapshot is not valid JSON") from None
    udapi = document.get("udapi") if isinstance(document, dict) else None
    if not isinstance(udapi, dict) or not isinstance(udapi.get("versionDetail"), dict):
        raise MdnsIntentError("Unsupported UDAPI mDNS schema")
    return document


def _verify_service_version(udapi):
    versions = udapi["versionDetail"]
    services = udapi.get("services")
    mdns = services.get("mdns") if isinstance(services, dict) else None
    if "services/mdns" in versions:
        version = versions["services/mdns"]
        if type(version) is int and version == MDNS_SERVICE_VERSION["services/mdns"]:
            return
    elif not isinstance(mdns, dict) or not mdns.get("reflectFilter"):
        return
    raise MdnsIntentError("Unsupported UDAPI mDNS service-list schema")


def _native_mdns(udapi, scope):
    _require_controller_lans(udapi.get("interfaces"), scope)
    services = udapi.get("services")
    if not isinstance(services, dict):
        raise MdnsIntentError("mDNS snapshot needs its complete service collection")
    if "mdns" not in services:
        return False, ()
    mdns = services["mdns"]
    expected_interfaces = [{"id": name} for name in sorted(scope.interfaces)]
    if (not isinstance(mdns, dict) or mdns.keys() != {"enabled", "interfaces", "reflectFilter"}
            or mdns["enabled"] is not True or mdns["interfaces"] != expected_interfaces
            or not isinstance(mdns["reflectFilter"], list)):
        raise MdnsIntentError("Custom mDNS intent exceeds the supported two-LAN scope")
    return True, _service_types(mdns["reflectFilter"], expand_presets=True)


def _service_types(values, *, expand_presets=False):
    if (not isinstance(values, (list, tuple)) or len(values) > 512
            or any(not isinstance(value, str) or not (
                _SERVICE_TYPE.fullmatch(value) or (expand_presets and value in _LOCAL_PRESET_ALIASES)
            ) for value in values)):
        raise MdnsIntentError("Invalid mDNS service scope. Expected local DNS-SD service types")
    if len({name.lower() for name in values}) != len(values):
        raise MdnsIntentError("mDNS service scope contains duplicate types")
    if expand_presets:
        values = {value + ".local" if value in _LOCAL_PRESET_ALIASES else value for value in values}
        if len({name.lower() for name in values}) != len(values):
            raise MdnsIntentError("mDNS service scope has a preset alias that conflicts with a differently cased type")
    return tuple(sorted(values))


def _require_controller_lans(interfaces, scope):
    if not isinstance(interfaces, list):
        raise MdnsIntentError("mDNS snapshot needs its complete controller interface topology")
    indexed = {}
    for item in interfaces:
        identity = item.get("identification") if isinstance(item, dict) else None
        name = identity.get("id") if isinstance(identity, dict) else None
        if not isinstance(name, str) or not name or name in indexed:
            raise MdnsIntentError("mDNS snapshot has ambiguous controller interface topology")
        indexed[name] = item
    for name in _CONTROLLER_LAN_PORTS:
        if not _active_controller_iface(indexed.get(name), name, "ethernet"):
            raise MdnsIntentError("mDNS topology lacks a known active controller LAN port")
    for bridge, address in scope.addresses.items():
        _require_controller_bridge(indexed, bridge, address)


def _active_controller_iface(item, name, kind):
    if not isinstance(item, dict) or item.get("identification") != {"id": name, "type": kind}:
        return False
    status = item.get("status")
    return isinstance(status, dict) and status.get("enabled") is True


def _require_controller_bridge(indexed, bridge, address):
    tag = int(bridge[2:])
    members = {f"{port}.{tag}": port for port in _CONTROLLER_LAN_PORTS}
    row = indexed.get(bridge)
    expected = {
        "identification": {"id": bridge, "type": "bridge"},
        "status": {"enabled": True, "comment": "LAN"},
        "addresses": [{"type": "static", "cidr": address, "version": "v4"}],
        "bridge": {"id": tag, "interfaces": [{"id": name} for name in members]},
    }
    if row != expected or row["status"]["enabled"] is not True or type(row["bridge"]["id"]) is not int:
        raise MdnsIntentError("mDNS topology differs from the mapped routed LAN bridge")
    for name, port in members.items():
        child = indexed.get(name)
        expected_vlan = {
            "identification": {"id": name, "type": "vlan"},
            "status": {"enabled": True}, "vlan": {"id": tag, "interface": {"id": port}},
        }
        if child != expected_vlan or child["status"]["enabled"] is not True or type(child["vlan"]["id"]) is not int:
            raise MdnsIntentError("mDNS topology differs from the mapped tagged LAN member")


def _lan_local_rules(chains):
    if not isinstance(chains, list):
        raise MdnsIntentError("mDNS snapshot needs its complete firewall rule collection")
    local = [
        item["rules"] for item in chains
        if isinstance(item, dict) and isinstance(item.get("config"), dict)
        and item["config"].get("name") == "LAN_LOCAL" and isinstance(item.get("rules"), list)
    ]
    if len(local) != 1:
        raise MdnsIntentError("mDNS snapshot needs its unique LAN_LOCAL rules")
    return local[0]


def _remove_mdns_rule(rules):
    rule = rules[0] if rules else None
    origin = rule.get("originId") if isinstance(rule, dict) else None
    expected = {
        "id": 30000, "target": "ACCEPT", "description": _RULE_DESCRIPTION, "log": False, "protocol": "udp",
        "source": {"sets": [_PORT_SET]}, "destination": {"sets": [_ADDRESS_SET, _PORT_SET]},
        "ipVersion": "both", "originId": origin,
    }
    if (
        rule != expected or rule["log"] is not False or type(rule["id"]) is not int or not _canonical_id(origin)
        or any(isinstance(row, dict) and row.get("id") == 30000 for row in rules[1:])
    ):
        raise MdnsIntentError("Generated mDNS firewall rule differs from the expected LAN_LOCAL rule")
    rules.pop(0)
    return origin


def _canonical_id(value):
    if not isinstance(value, str):
        return False
    try:
        identifier = UUID(value)
    except ValueError:
        return False
    return bool(identifier.int and str(identifier) == value)


def _reject_mdns_references(udapi, origin):
    reserved = (_ADDRESS_SET, _PORT_SET, _RULE_DESCRIPTION.lower())
    pending = [udapi]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            value = item.lower()
            if value == origin or any(term in value for term in reserved):
                raise MdnsIntentError("Unmanaged UDAPI contains a reference to generated mDNS policy")


def plan_mdns_commands(
    *, scope: MdnsScope, enabled: bool, current_mdns: dict | None, verified_repeater: dict | None,
    live_interfaces: dict, listener_present: bool, services: tuple[str, ...] = (),
) -> MdnsPlan:
    """Plan against the whole VyOS mDNS tree and fresh operational evidence."""
    expected = _validate_inputs(scope, live_interfaces, listener_present)
    services = _service_types(services)
    if type(enabled) is not bool or (not enabled and services):
        raise MdnsIntentError("mDNS planning needs an explicit enabled or disabled intent")
    if services and len("reflect-filters=" + ", ".join(services)) > _AVAHI_FILTER_LINE_LIMIT:
        raise MdnsIntentError(f"Stock VyOS mDNS selection exceeds Avahi's {_AVAHI_FILTER_LINE_LIMIT}-byte filter line")
    if verified_repeater is not None:
        _verify_repeater_scope(verified_repeater, expected)
    if current_mdns != _mdns_tree(verified_repeater):
        raise MdnsIntentError("VyOS mDNS service differs from verified ownership")
    if verified_repeater is None and listener_present:
        raise MdnsIntentError("VyOS has an mDNS listener without verified ownership")

    desired = expected if enabled else None
    if services:
        desired = {**expected, "allow-service": _service_leaf(services)}
    if desired == verified_repeater:
        _verify_operation(scope, enabled, live_interfaces, listener_present)
        return MdnsPlan(desired, ())
    path = list(_REPEATER_PATH)
    if desired is None:
        # VyOS cannot read an empty mDNS service root. The exact ownership
        # comparison above guarantees that removing the root has no other effect.
        return MdnsPlan(None, ({"op": "delete", "path": path[:-1]},))
    _require_live_lans(scope, live_interfaces)
    commands = []
    if verified_repeater is None:
        commands.extend({"op": "set", "path": path + ["interface"], "value": name} for name in desired["interface"])
        commands.append({"op": "set", "path": path + ["ip-version"], "value": "ipv4"})
    elif "allow-service" in verified_repeater:
        commands.append({"op": "delete", "path": path + ["allow-service"]})
    commands.extend({"op": "set", "path": path + ["allow-service"], "value": service} for service in services)
    return MdnsPlan(desired, tuple(commands))


def verify_mdns_state(
    *, scope: MdnsScope, expected_repeater: dict | None, current_mdns: dict | None,
    live_interfaces: dict, listener_present: bool,
) -> None:
    """Check exact configured interfaces and the expected UDP listener presence."""
    expected = _validate_inputs(scope, live_interfaces, listener_present)
    if expected_repeater is not None:
        _verify_repeater_scope(expected_repeater, expected)
    if current_mdns != _mdns_tree(expected_repeater):
        raise MdnsIntentError("VyOS mDNS read-back differs from the intended repeater")
    _verify_operation(scope, expected_repeater is not None, live_interfaces, listener_present)


def _gateway(address):
    try:
        gateway = IPv4Interface(address) if isinstance(address, str) else None
    except ValueError:
        gateway = None
    if (
        gateway is None or str(gateway) != address or gateway.network.prefixlen == 0
        or gateway.ip.is_multicast or gateway.ip.is_loopback or gateway.ip.is_link_local
        or gateway.ip.is_reserved or not gateway.network.network_address < gateway.ip < gateway.network.broadcast_address
    ):
        raise MdnsIntentError("mDNS needs a canonical IPv4 gateway address on each LAN")
    return gateway


def _validate_inputs(scope, live_interfaces, listener_present):
    if not isinstance(scope, MdnsScope) or not isinstance(live_interfaces, dict) or type(listener_present) is not bool:
        raise MdnsIntentError("mDNS needs a configured scope and fresh interface and listener observations")
    return {"interface": sorted(scope.interfaces.values()), "ip-version": "ipv4"}


def _mdns_tree(repeater):
    return None if repeater is None else {"repeater": repeater}


def _verify_repeater_scope(repeater, unfiltered):
    base = dict(repeater) if isinstance(repeater, dict) else {}
    try:
        if "allow-service" in base:
            leaf = base.pop("allow-service")
            services = _service_types((leaf,) if isinstance(leaf, str) else leaf)
            if not services or leaf != _service_leaf(services):
                raise MdnsIntentError("Invalid VyOS allow-service leaf")
        if base == unfiltered:
            return
    except MdnsIntentError as error:
        raise MdnsIntentError("Verified mDNS ownership is outside the configured repeater scope") from error
    raise MdnsIntentError("Verified mDNS ownership is outside the configured repeater scope")


def _service_leaf(services):
    # VyOS retrieve represents a single multi-value leaf as a scalar.
    return services[0] if len(services) == 1 else list(services)


def _verify_operation(scope, enabled, live_interfaces, listener_present):
    if enabled:
        _require_live_lans(scope, live_interfaces)
    if listener_present is not enabled:
        raise MdnsIntentError("VyOS mDNS listener state differs from the intended repeater")


def _require_live_lans(scope, live_interfaces):
    for bridge, name in scope.interfaces.items():
        link = live_interfaces.get(name)
        if (
            not isinstance(link, (tuple, list)) or len(link) != 2
            or not isinstance(link[0], (tuple, list)) or not isinstance(link[1], str)
            or not {"UP", "LOWER_UP", "MULTICAST"}.issubset(link[0])
        ):
            raise MdnsIntentError("mDNS needs an active multicast-capable VyOS interface for each LAN")
        try:
            addresses = interface_ipv4_addresses(link[1])
        except ValueError:
            raise MdnsIntentError("Invalid IPv4 address in VyOS mDNS interface read-back") from None
        if addresses != [IPv4Interface(scope.addresses[bridge])]:
            raise MdnsIntentError("mDNS interface does not have its exact pinned IPv4 address")
