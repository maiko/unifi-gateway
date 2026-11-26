"""Project the stock VyOS Shadow sync group's live role and VIP ownership."""

from collections import defaultdict
from ipaddress import ip_interface
import re


SHADOW_SYNC_GROUP = "UXGHA"
_GROUP_NAME = re.compile(r"[A-Za-z0-9_-]+")
_INTERFACE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}")
_STATE = {"MASTER": "master", "BACKUP": "backup", "FAULT": "fault", "INIT": "init"}
_DETAIL_KEYS = {"State", "Interface", "Virtual Router ID"}


def _group_configuration(config):
    """Return expected instance identities and the address-to-device mapping."""
    if config is None:
        return {}, {}
    sync_groups = config.get("sync-group")
    if sync_groups is None or (isinstance(sync_groups, dict) and SHADOW_SYNC_GROUP not in sync_groups):
        return {}, {}
    if not isinstance(sync_groups, dict) or not isinstance(sync_groups[SHADOW_SYNC_GROUP], dict):
        raise ValueError("Invalid Shadow Mode sync group")
    members = sync_groups[SHADOW_SYNC_GROUP].get("member")
    if isinstance(members, str):
        members = [members]
    if (not isinstance(members, list) or not members
            or any(not isinstance(name, str) or _GROUP_NAME.fullmatch(name) is None for name in members)
            or len(set(members)) != len(members) or not isinstance(config.get("group"), dict)):
        raise ValueError("Invalid Shadow Mode sync group membership")

    identities = {}
    virtual = {}
    for name in members:
        group = config["group"].get(name)
        if not isinstance(group, dict) or {"disable", "rfc3768-compatibility"} & group.keys():
            raise ValueError("Shadow Mode sync group includes an unavailable or unsupported VRRP instance")
        interface, vrid = group.get("interface"), group.get("vrid")
        if (not isinstance(interface, str) or _INTERFACE.fullmatch(interface) is None
                or not isinstance(vrid, str) or re.fullmatch(r"[1-9][0-9]{0,2}", vrid) is None or int(vrid) > 255):
            raise ValueError("Invalid Shadow Mode VRRP instance identity")
        identities[name] = (interface, vrid)
        groups = [group.get(kind, {}) for kind in ("address", "excluded-address")]
        if not all(isinstance(rows, dict) for rows in groups) or not any(groups):
            raise ValueError("Missing Shadow Mode VRRP address configuration")
        for rows in groups:
            for cidr, options in rows.items():
                vip = ip_interface(cidr)
                if (str(vip) != cidr or not isinstance(options, dict) or options.keys() - {"interface"}
                        or str(vip.ip) in virtual):
                    raise ValueError("Ambiguous Shadow Mode virtual address")
                owner = options.get("interface", interface)
                if not isinstance(owner, str) or _INTERFACE.fullmatch(owner) is None:
                    raise ValueError("Invalid Shadow Mode virtual address interface")
                family = "inet" if vip.version == 4 else "inet6"
                virtual[str(vip.ip)] = (owner, family, vip.network.prefixlen)
    if len(set(identities.values())) != len(identities):
        raise ValueError("Duplicate Shadow Mode VRRP instance identity")
    return identities, virtual


def _instance_roles(detail, identities):
    roles = {}
    for section in re.split(r"(?m)^[ \t]*VRRP Instance:[ \t]+", detail)[1:]:
        name, _, fields = section.partition("\n")
        name = name.strip()
        if name not in identities:
            continue
        values = {}
        for line in fields.splitlines():
            key, _, value = line.strip().partition(": ")
            if key in _DETAIL_KEYS:
                if key in values:
                    raise ValueError("Duplicate Shadow Mode VRRP operational field")
                values[key] = value
        interface, vrid = identities[name]
        if (name in roles or values.keys() != _DETAIL_KEYS or values["Interface"] != interface
                or values["Virtual Router ID"] != vrid or values["State"] not in _STATE):
            raise ValueError("VyOS VRRP detail disagrees with the Shadow Mode instance identity")
        roles[name] = _STATE[values["State"]]
    return roles


def _has_expected_ownership(rows, virtual, *, master):
    by_name = {}
    assigned = defaultdict(list)
    for row in rows:
        name = row["ifname"]
        if name in by_name:
            raise ValueError("VyOS returned duplicate kernel interfaces")
        by_name[name] = row["flags"]
        for address in row["addr_info"]:
            local = address.get("local")
            if isinstance(local, str) and local in virtual:
                usable = all(address.get(flag, False) is False for flag in ("tentative", "dadfailed"))
                assigned[local].append((name, address.get("family"), address.get("prefixlen"),
                                        usable))
    for ip, expected in virtual.items():
        owner = expected[0]
        if owner not in by_name:
            return False
        if master:
            if assigned[ip] != [(*expected, True)] or not {"UP", "LOWER_UP"}.issubset(by_name[owner]):
                return False
        elif assigned[ip]:
            return False
    return True


def observe_shadow_role(backend):
    """Require agreement among configured members, live election, and kernel addresses."""
    identities, virtual = _group_configuration(backend.read_config(["high-availability", "vrrp"]))
    if not identities:
        return "unknown"
    roles = _instance_roles(backend.show_vrrp_detail(), identities)
    addresses = backend.show_kernel_interfaces()
    distinct = set(roles.values())
    if roles.keys() != identities.keys() or len(distinct) != 1:
        return "unknown"
    state = distinct.pop()
    return state if _has_expected_ownership(addresses, virtual, master=state == "master") else "unknown"
