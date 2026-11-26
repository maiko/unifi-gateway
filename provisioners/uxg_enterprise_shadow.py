"""Translate the native phase-one Shadow interconnect into one owned address."""

from ipaddress import IPv4Interface, ip_interface
import json
import re

from backends.vyos_failover import _invalid_constant, _unique_fields


SHADOW_ADDRESSES = ("169.254.254.2/24", "169.254.254.3/24")
SHADOW_SERVICE_VERSIONS = {"services/vrrp": 5, "services/stunnel": 1}
_SHADOW_IPS = {address.split("/")[0] for address in SHADOW_ADDRESSES}
_SHADOW_NETWORK = IPv4Interface(SHADOW_ADDRESSES[0]).network
_PORT = {"id": "eth1", "type": "ethernet"}
_COMMENT = "MGMT_SHADOW"


def _management_row(row):
    status = row.get("status")
    return isinstance(status, dict) and status.get("comment") == _COMMENT


def _ordinary_port(row):
    return (isinstance(row, dict) and row.keys() == {"identification", "status"} and row["identification"] == _PORT
            and isinstance(row["status"], dict) and row["status"].keys() == {"enabled"}
            and type(row["status"]["enabled"]) is bool)


def shadow_management_port(address):
    return {"identification": _PORT.copy(), "status": {"enabled": True, "comment": _COMMENT},
            "addresses": [{"type": "static", "cidr": address, "version": "v4"}]}


def _bridge_members(rows):
    bridges = {}
    for row in rows:
        identity = row.get("identification")
        if not isinstance(identity, dict) or identity.get("type") != "bridge":
            continue
        name = identity.get("id")
        bridge = row.get("bridge")
        members = bridge.get("interfaces") if isinstance(bridge, dict) else None
        if (not isinstance(name, str) or name in bridges or not isinstance(members, list)
                or any(not isinstance(member, dict) or member.keys() != {"id"}
                       or not isinstance(member["id"], str) for member in members)):
            raise ValueError("Invalid Shadow Mode bridge membership")
        bridges[name] = bridge
    return bridges


def _ordinary_lan_addresses(rows):
    for row in rows:
        identity = row.get("identification")
        if isinstance(identity, dict) and (identity.get("id"), identity.get("type")) == ("br0", "bridge"):
            addresses = row.get("addresses")
            break
    else:
        return None
    if not isinstance(addresses, list) or not addresses:
        return None
    for index, entry in enumerate(addresses):
        if (not isinstance(entry, dict) or entry.keys() != {"type", "cidr", "version"}
                or entry["type"] != "static" or not isinstance(entry["cidr"], str) or "%" in entry["cidr"]):
            return None
        try:
            address = ip_interface(entry["cidr"])
        except ValueError:
            return None
        if (str(address) != entry["cidr"] or entry["version"] != f"v{address.version}"
                or (index == 0 and address.version != 4)):
            return None
    return addresses


def normalize_shadow_interconnect(system_cfg, reference):
    """Restore the approved ordinary eth1 row for comparison against the unmanaged baseline."""
    if not isinstance(system_cfg, str):
        raise ValueError("Shadow Mode requires a complete controller snapshot")
    try:
        document = json.loads(system_cfg, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except (ValueError, RecursionError) as error:
        raise ValueError("Shadow Mode requires an unambiguous controller snapshot") from error
    udapi = document.get("udapi") if isinstance(document, dict) else None
    normalized = False
    if isinstance(udapi, dict):
        services = udapi.get("services", {})
        if not isinstance(services, dict):
            raise ValueError("Invalid Shadow Mode service inventory")
        election = services.get("vrrp", {"enabled": False, "instances": []})
        tunnel = services.get("stunnel", {"enabled": False, "clients": [], "servers": []})
        if election != {"enabled": False, "instances": []} or election["enabled"] is not False:
            from provisioners.vyos_shadow_complete import decode_shadow_vrrp

            versions = udapi.get("versionDetail")
            decode_shadow_vrrp(election, version=versions.get("services/vrrp") if isinstance(versions, dict) else None)
            raise ValueError("Shadow Mode completion requires verified paired takeover")
        if tunnel != {"enabled": False, "clients": [], "servers": []} or tunnel["enabled"] is not False:
            raise ValueError("Shadow Mode peer tunnel requires verified paired takeover")
        versions = udapi.get("versionDetail", {})
        if not isinstance(versions, dict):
            raise ValueError("Invalid Shadow Mode service versions")
        shadow_services = any(name in services for name in ("vrrp", "stunnel"))
        for name, version in SHADOW_SERVICE_VERSIONS.items():
            field = name.split("/", 1)[1]
            if name in versions:
                if type(versions[name]) is not int or versions[name] != version:
                    raise ValueError("Unsupported inactive Shadow Mode service version")
                del versions[name]
                normalized = True
            if field in services:
                del services[field]
                normalized = True
        if shadow_services and not services:
            del udapi["services"]
    rows = udapi.get("interfaces") if isinstance(udapi, dict) else None
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("Shadow Mode requires a complete controller interface inventory")
    matching = [index for index, row in enumerate(rows) if isinstance(row.get("identification"), dict)
                and row["identification"].get("id") == "eth1"]
    if len(matching) != 1 or any(_management_row(row) for index, row in enumerate(rows) if index != matching[0]):
        raise ValueError("Shadow Mode requires a single native eth1 interconnect")
    position = matching[0]
    row = rows[position]
    identification = row["identification"]
    if identification.get("type") != "ethernet":
        raise ValueError("Shadow Mode requires a native Ethernet port")
    bridges = _bridge_members(rows)
    if not _management_row(row):
        if not _ordinary_port(row):
            raise ValueError("The ordinary Shadow Mode port must have a recognized inactive configuration")
        memberships = {name: bridge["interfaces"] for name, bridge in bridges.items() if {"id": "eth1"} in bridge["interfaces"]}
        if any(member["id"].startswith("eth1.") for bridge in bridges.values() for member in bridge["interfaces"]):
            raise ValueError("The Shadow Mode interconnect must not carry tagged bridge membership")
        ordinary = {"port": row, "memberships": memberships}
        lan_addresses = _ordinary_lan_addresses(rows)
        if lan_addresses is not None:
            ordinary["lan_preimage"] = {"addresses": lan_addresses}
        return (json.dumps(document) if normalized else system_cfg), None, ordinary

    addresses = row.get("addresses")
    entry = addresses[0] if isinstance(addresses, list) and len(addresses) == 1 else None
    address = entry.get("cidr") if isinstance(entry, dict) else None
    if (address not in SHADOW_ADDRESSES or row != shadow_management_port(address)
            or row["status"]["enabled"] is not True):
        raise ValueError("Unsupported Shadow Mode interconnect configuration")
    if (not isinstance(reference, dict) or not _ordinary_port(reference.get("port"))
            or not isinstance(reference.get("memberships"), dict)):
        raise ValueError("Verify an ordinary controller revision before preparing Shadow Mode")
    for name, members in reference["memberships"].items():
        if not isinstance(members, list) or members.count({"id": "eth1"}) != 1 or name not in bridges:
            raise ValueError("Shadow Mode changed the approved bridge topology")
        bridge = bridges[name]
        detached = [member for member in members if member != {"id": "eth1"}]
        if bridge["interfaces"] not in (members, detached):
            raise ValueError("Shadow Mode changed unrelated bridge members")
        bridge["interfaces"] = members
    rows[position] = reference["port"]
    return json.dumps(document), address, None


def validate_shadow_interface(interface):
    if not isinstance(interface, str) or re.fullmatch(r"eth[0-9]{1,11}", interface) is None:
        raise ValueError("Shadow Mode requires a dedicated VyOS Ethernet interface")


def read_interconnect(backend, interface):
    current = backend.read_config(["interfaces", "ethernet", interface])
    if not isinstance(current, dict) or {"vif", "vrf", "disable"} & current.keys():
        raise ValueError("The Shadow Mode interconnect is unavailable or in use")
    addresses = current.get("address", [])
    if isinstance(addresses, str):
        addresses = [addresses]
    if not isinstance(addresses, list) or any(not isinstance(address, str) for address in addresses):
        raise ValueError("Invalid VyOS interconnect address configuration")
    owned, others = [], []
    for address in addresses:
        if address.split("/")[0] in _SHADOW_IPS:
            if address not in SHADOW_ADDRESSES:
                raise ValueError("A reserved Shadow Mode address uses a different prefix")
            owned.append(address)
        else:
            others.append(address)
    if len(owned) > 1:
        raise ValueError("The interconnect contains ambiguous Shadow Mode addresses")
    remaining = {key: value for key, value in current.items() if key != "address"}
    return (owned[0] if owned else None), (remaining, others)


def verify_interconnect(backend, interface, expected, *, reserve_prefix=False, require_carrier=False):
    rows = backend.show_kernel_interfaces()
    links = [row for row in rows if row["ifname"] == interface]
    if len(links) != 1 or links[0].get("master") is not None:
        raise ValueError("VyOS did not report an independent Shadow Mode interconnect")
    if require_carrier and not {"UP", "LOWER_UP"}.issubset(links[0]["flags"]):
        raise ValueError("The mapped VyOS Shadow Mode interconnect has no carrier")
    reserved = []
    for row in rows:
        for addr in row["addr_info"]:
            if addr.get("family") != "inet":
                continue
            if addr["local"] in _SHADOW_IPS:
                reserved.append((row["ifname"], addr["local"], addr["prefixlen"]))
            if ((expected is not None or reserve_prefix) and row["ifname"] != interface
                    and _SHADOW_NETWORK.overlaps(IPv4Interface(f'{addr["local"]}/{addr["prefixlen"]}').network)):
                raise ValueError("A different VyOS interface already covers the Shadow Mode interconnect subnet")
    wanted = []
    if expected is not None:
        address = IPv4Interface(expected)
        wanted.append((interface, str(address.ip), address.network.prefixlen))
    if reserved != wanted:
        raise ValueError("VyOS kernel interconnect addresses differ from Shadow Mode intent")


def verify_no_vrrp_interconnect_conflict(backend):
    configured = backend.read_config(["high-availability", "vrrp"])
    if configured is None:
        return
    groups = configured.get("group", {})
    if not isinstance(groups, dict) or any(not isinstance(group, dict) for group in groups.values()):
        raise ValueError("VyOS returned an invalid VRRP configuration")
    for group in groups.values():
        for key in ("address", "excluded-address"):
            addresses = group.get(key, {})
            if not isinstance(addresses, dict):
                raise ValueError("VyOS returned an invalid VRRP address configuration")
            if any(address.split("/")[0] in _SHADOW_IPS for address in addresses):
                raise ValueError("A VyOS VRRP group already reserves a Shadow Mode interconnect address")


def interconnect_commands(interface, current, desired):
    if current == desired:
        return []
    if current is not None and desired is not None:
        raise ValueError("Withdraw the verified Shadow Mode role before changing addresses")
    path = ["interfaces", "ethernet", interface, "address"]
    if desired is None:
        return [{"op": "delete", "path": [*path, current]}]
    return [{"op": "set", "path": [*path, desired]}]
