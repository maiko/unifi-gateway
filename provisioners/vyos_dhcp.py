"""Decode one owned UniFi DHCPv4 scope and plan a VyOS Kea transaction."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
import json
import re


_NETWORK_PATH = ("service", "dhcp-server", "shared-network-name")
_SERVER_FIELDS = {
    "enabled", "interfaces", "name", "leaseTime", "ipVersion", "rangeStart",
    "dnsServers", "gatewayAddress", "rangeStop", "ipv4Netmask",
}
_MAX_SUBNET_ID = 4_294_967_294
_MAX_LEASE = 4_294_967_295
_MAX_RESERVATIONS = 32
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_BOOT_FILENAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)*")


class DhcpIntentError(ValueError):
    """The input cannot safely determine the owned DHCPv4 configuration."""


@dataclass(frozen=True)
class DhcpScope:
    bridge: str
    interface: str
    shared_network: str
    subnet_id: int

    def __post_init__(self):
        bridge = re.fullmatch(r"br([1-9][0-9]{0,3})", self.bridge) if isinstance(self.bridge, str) else None
        if bridge is None or int(bridge[1]) > 4094:
            raise DhcpIntentError("DHCP ownership needs an explicit tagged controller bridge")
        if (not isinstance(self.interface, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", self.interface)
                or not self.interface.endswith("." + bridge[1])):
            raise DhcpIntentError("DHCP ownership needs a mapped VyOS VLAN interface")
        if (not isinstance(self.shared_network, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", self.shared_network)):
            raise DhcpIntentError("DHCP ownership needs an explicit VyOS shared network name")
        if type(self.subnet_id) is not int or not 1 <= self.subnet_id <= _MAX_SUBNET_ID:
            raise DhcpIntentError("DHCP ownership needs a valid VyOS subnet ID")


@dataclass(frozen=True)
class DhcpReservation:
    mac: str
    address: IPv4Address


@dataclass(frozen=True)
class DhcpBoot:
    server: IPv4Address
    filename: str


@dataclass(frozen=True)
class DhcpServer:
    router: IPv4Address
    dns: tuple[IPv4Address, ...]
    start: IPv4Address
    stop: IPv4Address
    lease_seconds: int
    reservations: tuple[DhcpReservation, ...] = ()
    ntp_servers: tuple[IPv4Address, ...] = ()
    domain: str | None = None
    tftp_server: str | None = None
    boot: DhcpBoot | None = None


@dataclass(frozen=True)
class DhcpIntent:
    revision: str
    scope: DhcpScope
    interface: IPv4Interface
    server: DhcpServer | None


@dataclass(frozen=True)
class DhcpPlan:
    desired_network: dict | None
    commands: tuple[dict, ...]


def decode_dhcp_intent(system_cfg: str, *, revision: str, scope: DhcpScope) -> DhcpIntent:
    """Read an explicit DHCP server list and the mapped bridge's IPv4 address."""
    if not isinstance(revision, str) or not revision.strip():
        raise DhcpIntentError("DHCP snapshot needs a controller revision")
    if not isinstance(system_cfg, str):
        raise DhcpIntentError("DHCP snapshot must be a JSON string")
    try:
        document = json.loads(system_cfg, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except DhcpIntentError:
        raise
    except (ValueError, RecursionError, TypeError) as error:
        raise DhcpIntentError("DHCP snapshot is not valid JSON") from error

    udapi = document.get("udapi") if isinstance(document, dict) else None
    versions = udapi.get("versionDetail") if isinstance(udapi, dict) else None
    if (not isinstance(versions, dict)
            or type(udapi.get("version")) is not int or udapi["version"] != 48
            or udapi.get("versionFormat") != "v2"
            or type(versions.get("interfaces")) is not int or versions["interfaces"] != 8
            or type(versions.get("services/dhcpServers", 2)) is not int
            or versions.get("services/dhcpServers", 2) != 2):
        raise DhcpIntentError("Unsupported UDAPI DHCP or interface schema")

    interface = _read_bridge(udapi.get("interfaces"), scope.bridge)
    services = udapi.get("services")
    entries = services.get("dhcpServers") if isinstance(services, dict) else None
    if not isinstance(entries, list):
        raise DhcpIntentError("DHCP snapshot needs an explicit server list")
    server = _read_server(entries, scope.bridge, interface)
    return DhcpIntent(revision=revision, scope=scope, interface=interface, server=server)


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DhcpIntentError("DHCP snapshot contains a duplicate JSON field")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise DhcpIntentError("DHCP snapshot contains a non-JSON constant")


def _read_bridge(entries, bridge):
    if not isinstance(entries, list):
        raise DhcpIntentError("DHCP snapshot needs an explicit interface list")
    interfaces = {}
    for entry in entries:
        identity = entry.get("identification") if isinstance(entry, dict) else None
        name = identity.get("id") if isinstance(identity, dict) else None
        if not isinstance(name, str) or not name or name in interfaces:
            raise DhcpIntentError("DHCP snapshot has an invalid or duplicate interface ID")
        interfaces[name] = entry
    entry = interfaces.get(bridge)
    if entry is None:
        raise DhcpIntentError("DHCP snapshot does not describe the mapped bridge")
    status, info = entry.get("status"), entry.get("bridge")
    if (entry["identification"].get("type") != "bridge"
            or not isinstance(status, dict) or status.get("enabled") is not True
            or not isinstance(info, dict) or type(info.get("id")) is not int
            or info["id"] != int(bridge[2:])):
        raise DhcpIntentError("Mapped controller interface must be the enabled VLAN bridge")
    addresses = entry.get("addresses")
    if not isinstance(addresses, list) or len(addresses) != 1:
        raise DhcpIntentError("Mapped bridge needs one static IPv4 interface CIDR")
    address = addresses[0]
    if (not isinstance(address, dict) or address.get("type") != "static"
            or address.get("version") != "v4" or not isinstance(address.get("cidr"), str)
            or "/" not in address["cidr"]):
        raise DhcpIntentError("Mapped bridge needs one static IPv4 interface CIDR")
    try:
        interface = IPv4Interface(address["cidr"])
    except ValueError as error:
        raise DhcpIntentError("Mapped bridge has an invalid IPv4 CIDR") from error
    if not _is_host(interface.ip, interface.network):
        raise DhcpIntentError("Mapped bridge has no usable IPv4 gateway address")
    return interface


def _read_server(entries, bridge, interface):
    matched = []
    for entry in entries:
        references = entry.get("interfaces") if isinstance(entry, dict) else None
        if not isinstance(references, list) or not references:
            raise DhcpIntentError("DHCP server has no explicit interface references")
        if any(not isinstance(ref, dict) or not isinstance(ref.get("id"), str) or not ref["id"]
               for ref in references):
            raise DhcpIntentError("DHCP server has an invalid interface reference")
        if any(ref["id"] == bridge for ref in references):
            matched.append(entry)
    if not matched:
        return None
    if len(matched) != 1:
        raise DhcpIntentError("Mapped bridge has more than one DHCP server")
    entry = matched[0]
    if (entry.keys() - {"staticLeases", "domain", "options", "dhcpBoot"} != _SERVER_FIELDS
            or entry["enabled"] is not True or entry["ipVersion"] != "v4"
            or entry["interfaces"] != [{"id": bridge}]
            or not isinstance(entry["name"], str) or not entry["name"].strip()):
        raise DhcpIntentError("Mapped bridge has an unsupported DHCP server configuration")

    network = interface.network
    if type(entry["ipv4Netmask"]) is not int or entry["ipv4Netmask"] != network.prefixlen:
        raise DhcpIntentError("DHCP netmask does not match the mapped bridge")
    router = _ipv4_address(entry["gatewayAddress"], "default router")
    if router != interface.ip:
        raise DhcpIntentError("DHCP default router does not match the mapped bridge address")
    start = _ipv4_address(entry["rangeStart"], "pool start")
    stop = _ipv4_address(entry["rangeStop"], "pool end")
    if not _is_host(start, network) or not _is_host(stop, network) or start > stop or start <= router <= stop:
        raise DhcpIntentError("DHCP pool must be ordered, usable, and exclude the gateway")

    lease = entry["leaseTime"]
    if type(lease) is not int or not 1 <= lease <= _MAX_LEASE:
        raise DhcpIntentError("DHCP lease must be a positive VyOS lease time in seconds")
    if not isinstance(entry["dnsServers"], list) or not 1 <= len(entry["dnsServers"]) <= 4:
        raise DhcpIntentError("DHCP server needs one to four ordered IPv4 DNS servers")
    dns = tuple(_ipv4_address(value, "DNS server") for value in entry["dnsServers"])
    if len(set(dns)) != len(dns):
        raise DhcpIntentError("DHCP DNS servers contain a duplicate address")
    reservations = _read_reservations(entry.get("staticLeases", []), network, router, start, stop)
    domain = _dns_name(entry["domain"], "domain name") if "domain" in entry else None
    options = _read_options(entry["options"]) if "options" in entry else {}
    ntp_servers = _ntp_addresses(options[42].split(",")) if 42 in options else ()
    tftp_server = _tftp_server(options[66]) if 66 in options else None
    boot = _read_boot(entry["dhcpBoot"]) if "dhcpBoot" in entry else None
    if boot is not None and tftp_server is not None and tftp_server != str(boot.server):
        raise DhcpIntentError("Network Boot conflicts with a different standalone TFTP server")
    return DhcpServer(router=router, dns=dns, start=start, stop=stop, lease_seconds=lease,
                      reservations=reservations, ntp_servers=ntp_servers, domain=domain, tftp_server=tftp_server,
                      boot=boot)


def _read_boot(value):
    if not isinstance(value, dict) or value.keys() != {"serverIP", "filename"}:
        raise DhcpIntentError("Network Boot needs the native server and filename fields")
    server = _ipv4_address(value["serverIP"], "boot server")
    filename = value["filename"]
    if not isinstance(filename, str) or len(filename) > 127 or not _BOOT_FILENAME.fullmatch(filename):
        raise DhcpIntentError("Network Boot needs a portable relative filename within the 128-byte BOOTP field")
    return DhcpBoot(server, filename)


def _read_options(options):
    if not isinstance(options, list) or not options:
        raise DhcpIntentError("DHCP options need an explicit nonempty list")
    values = {}
    for option in options:
        if (not isinstance(option, dict) or option.keys() != {"optionNumber", "value"}
                or type(option["optionNumber"]) is not int or option["optionNumber"] not in (42, 66)
                or not isinstance(option["value"], str)):
            raise DhcpIntentError("Managed DHCP supports only native NTP and standalone TFTP option entries")
        code = option["optionNumber"]
        if code in values:
            raise DhcpIntentError("DHCP options contain a duplicate code")
        values[code] = option["value"]
    return values


def _dns_name(value, field):
    if not isinstance(value, str) or len(value) > 253 or any(
        not _DNS_LABEL.fullmatch(label) for label in value.split(".")
    ):
        raise DhcpIntentError(f"DHCP {field} needs a conventional DNS name")
    return value


def _tftp_server(value):
    if isinstance(value, str) and re.fullmatch(r"[0-9.]+", value):
        return str(_ipv4_address(value, "TFTP server"))
    return _dns_name(value, "TFTP server")


def _ntp_addresses(values):
    if not isinstance(values, list) or not 1 <= len(values) <= 2:
        raise DhcpIntentError("DHCP NTP needs one or two IPv4 server addresses")
    addresses = tuple(_ipv4_address(value, "NTP server") for value in values)
    if len(set(addresses)) != len(addresses):
        raise DhcpIntentError("DHCP NTP servers contain a duplicate address")
    return addresses


def _read_reservations(entries, network, router, start, stop):
    if not isinstance(entries, list) or len(entries) > _MAX_RESERVATIONS:
        raise DhcpIntentError(f"DHCP static leases must be a list of at most {_MAX_RESERVATIONS} reservations")
    pairs = []
    for entry in entries:
        if (not isinstance(entry, dict) or entry.keys() != {"id", "addresses"}
                or not isinstance(entry["addresses"], list) or len(entry["addresses"]) != 1):
            raise DhcpIntentError("Each DHCP static lease needs one client MAC and one IPv4 address")
        pairs.append((entry["id"], entry["addresses"][0]))
    return _validate_reservations(pairs, network, router, start, stop)


def _validate_reservations(pairs, network, router, start, stop):
    reservations = {}
    used_addresses = set()
    for client, address in pairs:
        if not isinstance(client, str) or not re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", client):
            raise DhcpIntentError("DHCP static lease needs a colon-separated client MAC")
        mac = client.lower()
        if mac == "00:00:00:00:00:00" or int(mac[:2], 16) & 1:
            raise DhcpIntentError("DHCP static lease needs a nonzero unicast client MAC")
        ip = _ipv4_address(address, "static lease address")
        if not _is_host(ip, network) or ip == router or start <= ip <= stop:
            raise DhcpIntentError("DHCP static lease must be a usable subnet address outside the dynamic pool and gateway")
        if mac in reservations or ip in used_addresses:
            raise DhcpIntentError("DHCP static leases contain a duplicate client MAC or address")
        reservations[mac] = DhcpReservation(mac=mac, address=ip)
        used_addresses.add(ip)
    return tuple(reservations[mac] for mac in sorted(reservations))


def _ipv4_address(value, field):
    if not isinstance(value, str):
        raise DhcpIntentError(f"DHCP {field} must be an IPv4 address")
    try:
        address = IPv4Address(value)
    except ValueError as error:
        raise DhcpIntentError(f"DHCP {field} must be an IPv4 address") from error
    if address.is_multicast or address.is_unspecified or address == IPv4Address("255.255.255.255"):
        raise DhcpIntentError(f"DHCP {field} must be a unicast IPv4 address")
    return address


def _is_host(address, network):
    return network.network_address < address < network.broadcast_address


def plan_dhcp_commands(
    intent: DhcpIntent,
    *,
    scope: DhcpScope,
    live_interface_addresses: dict,
    current_networks: dict,
    verified_network: dict | None,
) -> DhcpPlan:
    """Plan a batch against freshly read interface and Kea ownership state.

    Pass every shared network under VyOS service dhcp-server and the last
    read-back of the owned subtree. The caller owns locking and revalidation.
    """
    if intent.scope != scope:
        raise DhcpIntentError("DHCP intent belongs to another configured scope")
    addresses = live_interface_addresses.get(scope.interface) if isinstance(live_interface_addresses, dict) else None
    if not isinstance(addresses, (list, tuple)) or str(intent.interface) not in addresses:
        raise DhcpIntentError("Mapped VyOS interface lacks the controller's static IPv4 CIDR")
    if not isinstance(current_networks, dict):
        raise DhcpIntentError("DHCP planning needs the complete VyOS shared-network collection")
    current = current_networks.get(scope.shared_network)
    if (current != verified_network
            or scope.shared_network in current_networks and not isinstance(current, dict)):
        raise DhcpIntentError("VyOS DHCP network differs from verified ownership")

    network = intent.interface.network
    if current is not None:
        _check_verified_network(current, intent.interface, scope.subnet_id)
    if intent.server is not None:
        _check_operator_networks(current_networks, scope, network)

    desired = None if intent.server is None else _desired_network(intent.server, scope.subnet_id, network)
    if current == desired:
        return DhcpPlan(desired_network=desired, commands=())

    path = [*_NETWORK_PATH, scope.shared_network]
    commands = []
    if current is not None:
        commands.append({"op": "delete", "path": path})
    if intent.server is not None:
        base = path + ["subnet", str(network)]
        commands.extend(
            {"op": "set", "path": base + suffix, "value": value}
            for suffix, value in _command_leaves(intent.server, scope.subnet_id)
        )
    return DhcpPlan(desired_network=desired, commands=tuple(commands))


def _check_verified_network(tree, interface, subnet_id):
    network = interface.network
    subnets = tree.get("subnet")
    if tree.keys() != {"subnet"} or not isinstance(subnets, dict) or subnets.keys() != {str(network)}:
        raise DhcpIntentError("Verified VyOS DHCP network differs from the scoped subnet")
    subnet = subnets[str(network)]
    if _subnet_id(subnet) != subnet_id:
        raise DhcpIntentError("Verified VyOS DHCP network differs from the scoped subnet ID")
    option, ranges = subnet.get("option"), subnet.get("range")
    pool = ranges.get("0") if isinstance(ranges, dict) and ranges.keys() == {"0"} else None
    if (subnet.keys() - {"static-mapping"} != {"subnet-id", "lease", "option", "range"}
            or not isinstance(option, dict)
            or option.keys() - {"ntp-server", "domain-name", "tftp-server-name", "bootfile-server", "bootfile-name"}
            != {"default-router", "name-server"}
            or not isinstance(pool, dict)
            or pool.keys() != {"start", "stop"}):
        raise DhcpIntentError("Verified VyOS DHCP network contains configuration outside the owned scope")
    if "ntp-server" in option:
        leaf = option["ntp-server"]
        addresses = _ntp_addresses([leaf] if isinstance(leaf, str) else leaf)
        if leaf != _vyos_address_leaf(addresses):
            raise DhcpIntentError("Verified VyOS DHCP NTP option does not match stock read-back")
    if "domain-name" in option:
        _dns_name(option["domain-name"], "verified domain name")
    if "tftp-server-name" in option:
        _tftp_server(option["tftp-server-name"])
    if "bootfile-server" in option or "bootfile-name" in option:
        boot = _read_boot({"serverIP": option.get("bootfile-server"), "filename": option.get("bootfile-name")})
        if option.get("tftp-server-name") != str(boot.server):
            raise DhcpIntentError("Verified VyOS Network Boot options require the same TFTP and boot server")
    if "static-mapping" in subnet:
        _check_verified_reservations(subnet["static-mapping"], interface, option, pool)


def _check_verified_reservations(mappings, interface, option, pool):
    if not isinstance(mappings, dict) or not 1 <= len(mappings) <= _MAX_RESERVATIONS:
        raise DhcpIntentError("Verified VyOS DHCP static mappings have an invalid count or shape")
    pairs = []
    for mapping in mappings.values():
        if not isinstance(mapping, dict) or mapping.keys() != {"mac", "ip-address"}:
            raise DhcpIntentError("Verified VyOS DHCP static mappings contain an unsupported node")
        pairs.append((mapping["mac"], mapping["ip-address"]))
    try:
        router = _ipv4_address(option["default-router"], "verified default router")
        start = _ipv4_address(pool["start"], "verified pool start")
        stop = _ipv4_address(pool["stop"], "verified pool end")
        network = interface.network
        if (router != interface.ip or not _is_host(start, network) or not _is_host(stop, network)
                or start > stop or start <= router <= stop):
            raise DhcpIntentError("Invalid verified DHCP pool or router")
        reservations = _validate_reservations(pairs, network, router, start, stop)
    except DhcpIntentError as error:
        raise DhcpIntentError("Verified VyOS DHCP static mappings conflict with the scope, pool, or each other") from error
    if mappings != _static_mappings(reservations):
        raise DhcpIntentError("Verified VyOS DHCP static mappings contain a non-owned identifier")


def _check_operator_networks(current_networks, scope, network):
    for name, tree in current_networks.items():
        if name == scope.shared_network:
            continue
        subnets = tree.get("subnet") if isinstance(tree, dict) else None
        if not isinstance(subnets, dict):
            raise DhcpIntentError("Cannot establish VyOS DHCP ownership from a malformed shared network")
        for cidr, subnet in subnets.items():
            try:
                if not isinstance(cidr, str) or "/" not in cidr:
                    raise ValueError("missing IPv4 CIDR")
                existing = IPv4Network(cidr)
            except ValueError as error:
                raise DhcpIntentError("Cannot establish VyOS DHCP ownership from an invalid subnet") from error
            if _subnet_id(subnet) == scope.subnet_id or existing.overlaps(network):
                raise DhcpIntentError("Owned DHCP subnet or ID conflicts with another VyOS network")


def _subnet_id(subnet):
    value = subnet.get("subnet-id") if isinstance(subnet, dict) else None
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,10}", value):
        value = int(value)
    if type(value) is not int or not 1 <= value <= _MAX_SUBNET_ID:
        raise DhcpIntentError("Cannot establish VyOS DHCP ownership without a valid subnet ID")
    return value


def _desired_network(server, subnet_id, network):
    subnet = {
        "subnet-id": str(subnet_id),
        "lease": str(server.lease_seconds),
        "option": _stock_options(server),
        "range": {"0": {"start": str(server.start), "stop": str(server.stop)}},
    }
    if server.reservations:
        subnet["static-mapping"] = _static_mappings(server.reservations)
    return {"subnet": {str(network): subnet}}


def _stock_options(server):
    options = {"default-router": str(server.router), "name-server": _vyos_address_leaf(server.dns)}
    if server.ntp_servers:
        options["ntp-server"] = _vyos_address_leaf(server.ntp_servers)
    if server.domain is not None:
        options["domain-name"] = server.domain
    if server.tftp_server is not None:
        options["tftp-server-name"] = server.tftp_server
    if server.boot is not None:
        server_address = str(server.boot.server)
        options.update({"tftp-server-name": server_address, "bootfile-server": server_address,
                        "bootfile-name": server.boot.filename})
    return options


def _vyos_address_leaf(addresses):
    values = [str(address) for address in addresses]
    # /retrieve showConfig serializes one value of a multi-valued node as a string.
    return values[0] if len(values) == 1 else values


def _static_mappings(reservations):
    return {
        "unifi-" + reservation.mac.replace(":", ""): {
            "mac": reservation.mac,
            "ip-address": str(reservation.address),
        }
        for reservation in reservations
    }


def _command_leaves(server, subnet_id):
    return [
        (["subnet-id"], str(subnet_id)),
        (["lease"], str(server.lease_seconds)),
        *[
            (["option", leaf], value)
            for leaf, values in _stock_options(server).items()
            for value in (values if isinstance(values, list) else [values])
        ],
        (["range", "0", "start"], str(server.start)),
        (["range", "0", "stop"], str(server.stop)),
        *[
            (["static-mapping", name, key], value)
            for name, mapping in _static_mappings(server.reservations).items()
            for key, value in mapping.items()
        ],
    ]
