"""Translate restricted Enterprise FRR uploads into typed stock VyOS BGP resources."""

from base64 import b64decode
from binascii import Error as Base64Error
from dataclasses import dataclass, field
import hmac
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
import json
import re

from backends.vyos_failover import _invalid_constant, _unique_fields
from provisioners.vyos_firewall_commands import _set_commands


class BgpIntentError(ValueError):
    """The controller upload does not describe a supported, explicit policy."""


@dataclass(frozen=True, slots=True)
class BgpPeer:
    address: IPv4Address | IPv6Address
    remote_as: int
    address_families: tuple[tuple[int, bool], ...]
    description: str | None = None
    password: str | None = field(default=None, repr=False)
    timers: tuple[int, int] | None = None
    connect_retry: int | None = None


@dataclass(frozen=True, slots=True)
class BgpIntent:
    local_as: int
    router_id: IPv4Address
    peers: tuple[BgpPeer, ...]
    networks: tuple[IPv4Network | IPv6Network, ...]
    imports: tuple[IPv4Network | IPv6Network, ...]
    exports: tuple[IPv4Network | IPv6Network, ...]


@dataclass(frozen=True, slots=True)
class BgpProvisioningIntent:
    revision: str
    policy: BgpIntent | None


@dataclass(frozen=True, slots=True)
class BgpScope:
    peers: frozenset[IPv4Address | IPv6Address]
    imports: frozenset[IPv4Network | IPv6Network]
    exports: frozenset[IPv4Network | IPv6Network]
    dual_stack_peers: frozenset[IPv4Address | IPv6Address] = frozenset()

    def __post_init__(self):
        if (not isinstance(self.peers, frozenset) or not self.peers
                or any(not isinstance(peer, (IPv4Address, IPv6Address)) for peer in self.peers)) or any(
            not isinstance(prefixes, frozenset) or not prefixes
            or any(not isinstance(prefix, (IPv4Network, IPv6Network)) for prefix in prefixes)
            for prefixes in (self.imports, self.exports)
        ):
            raise BgpIntentError("Managed BGP requires approved peers and exact prefixes")
        if not isinstance(self.dual_stack_peers, frozenset) or not self.dual_stack_peers <= self.peers:
            raise BgpIntentError("Dual-stack BGP peers must be approved peers")
        families = {4, 6} if self.dual_stack_peers else {peer.version for peer in self.peers}
        versions = {prefix.version for prefix in self.imports}
        if versions != families or versions != {prefix.version for prefix in self.exports}:
            raise BgpIntentError("Managed BGP requires import and export prefixes for every approved peer family")

    def require(self, intent):
        if (not self.peers.issuperset(peer.address for peer in intent.peers) or not self.imports.issuperset(intent.imports)
                or not self.exports.issuperset(intent.exports) or not self.exports.issuperset(intent.networks)):
            raise BgpIntentError("Controller BGP intent exceeds the approved peer or prefixes")
        for peer in intent.peers:
            for version, _ in peer.address_families:
                if version != peer.address.version and peer.address not in self.dual_stack_peers:
                    raise BgpIntentError(f"An IPv{peer.address.version} BGP peer is not approved for IPv{version}")

    def accepts_existing_scope(self, previous):
        """Allow adding approved peers while retaining the journal's exact filter scope."""
        if not isinstance(previous, dict):
            return False
        fields = previous.keys() - {"dual_stack_peers"}
        if fields == {"peer", "imports", "exports"}:
            addresses = [previous["peer"]]
        elif fields == {"peers", "imports", "exports"}:
            addresses = previous["peers"]
        else:
            return False
        if (not isinstance(addresses, list) or not addresses or any(not isinstance(address, str) for address in addresses)
                or len(set(addresses)) != len(addresses) or not set(map(str, self.peers)).issuperset(addresses)):
            return False
        dual = previous.get("dual_stack_peers", [])
        if (not isinstance(dual, list) or any(not isinstance(address, str) or address not in addresses for address in dual)
                or len(set(dual)) != len(dual) or not set(map(str, self.dual_stack_peers)).issuperset(dual)):
            return False
        try:
            versions = {ip_network(prefix).version for prefix in previous["imports"]}
        except (TypeError, ValueError):
            return False
        if not versions:
            return False
        return all(previous[key] == sorted(str(prefix) for prefix in prefixes if prefix.version in versions)
                   for key, prefixes in (("imports", self.imports), ("exports", self.exports)))

    @classmethod
    def from_config(cls, settings):
        try:
            if ("peer" in settings) == ("peers" in settings):
                raise ValueError
            addresses = [settings["peer"]] if "peer" in settings else json.loads(settings["peers"])
            if not isinstance(addresses, list) or any(not isinstance(value, str) for value in addresses):
                raise ValueError
            peers = frozenset(_peer_address(address) for address in addresses)
            if len(addresses) != len(peers):
                raise ValueError
            prefixes = [json.loads(settings[key]) for key in ("import_prefixes", "export_prefixes")]
            if any(not isinstance(rows, list) or any(not isinstance(value, str) for value in rows) for rows in prefixes):
                raise ValueError
            approved = [frozenset(_prefix(value) for value in rows) for rows in prefixes]
            if any(len(rows) != len(allowed) for rows, allowed in zip(prefixes, approved, strict=True)):
                raise ValueError
            dual = json.loads(settings.get("dual_stack_peers", "[]"))
            if not isinstance(dual, list) or any(not isinstance(address, str) for address in dual):
                raise ValueError
            dual_stack_peers = frozenset(_peer_address(address) for address in dual)
            if len(dual) != len(dual_stack_peers):
                raise ValueError
            return cls(peers, *approved, dual_stack_peers=dual_stack_peers)
        except (KeyError, ValueError, RecursionError):
            raise BgpIntentError("Managed BGP requires approved peers and exact import and export prefixes for each family") from None


_NAME = r"[A-Za-z][A-Za-z0-9_-]{0,31}"
_DESCRIPTION = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .,():/_-]{0,79}")
_PASSWORD = re.compile(r"[A-Za-z0-9_.!@%+=:/-]{1,80}")
_RAW_LIMIT = 16_384
BGP_UPLOAD_KEY = "routes/bgp/raw"
BGP_UPLOAD_VERSION = 1
BGP_UPLOAD_CAPABILITY = 0x00400000
_BGP_PATH = ("protocols", "bgp")
_FILTER_PATHS = {
    4: (("policy", "prefix-list", "UNIFI-BGP4-IN"), ("policy", "prefix-list", "UNIFI-BGP4-OUT")),
    6: (("policy", "prefix-list6", "UNIFI-BGP6-IN"), ("policy", "prefix-list6", "UNIFI-BGP6-OUT")),
}
_OWNED_PATHS = (_BGP_PATH, *_FILTER_PATHS[4], *_FILTER_PATHS[6])
_CHECKPOINT_PATHS = dict(zip(("process", "import", "export", "import6", "export6"), _OWNED_PATHS, strict=True))
_VALID_CHECKPOINT_KEYS = (
    {"process", "import", "export"}, {"process", "import6", "export6"}, set(_CHECKPOINT_PATHS),
)


def _number(value, maximum):
    if not re.fullmatch(r"[1-9][0-9]{0,9}", value) or int(value) > maximum:
        raise ValueError
    return int(value)


def _prefix(value, *, version=None):
    network = ip_network(value)
    if network.prefixlen == 0 or network.is_multicast or network.is_loopback or network.is_link_local:
        raise ValueError
    if isinstance(network, IPv6Network) and network.network_address.scope_id:
        raise ValueError
    if version is not None and network.version != version:
        raise ValueError
    return network


def _peer_address(value):
    peer = ip_address(value)
    if isinstance(peer, IPv6Address) and (peer.scope_id or peer.ipv4_mapped or peer.is_link_local):
        raise ValueError
    return peer


def _parse_policy(rows):
    maps, lists = {}, {}
    while rows:
        row, *rows = rows
        route_map = re.fullmatch(rf"route-map ({_NAME}) permit ([0-9]+)", row)
        prefix = re.fullmatch(rf"(ip|ipv6) prefix-list ({_NAME}) seq ([0-9]+) permit ([0-9A-Fa-f:.]+/[0-9]+)", row)
        if route_map and len(rows) >= 2:
            name, sequence = route_map.groups()
            match = re.fullmatch(rf"match (ip|ipv6) address prefix-list ({_NAME})", rows[0])
            if name in maps or match is None or rows[1] != "exit":
                raise ValueError
            _number(sequence, 65_535)
            maps[name] = ("ipv4" if match[1] == "ip" else "ipv6", match[2])
            rows = rows[2:]
        elif prefix:
            keyword, name, sequence, address = prefix.groups()
            family = "ipv4" if keyword == "ip" else "ipv6"
            rules = lists.setdefault((family, name), {})
            order = _number(sequence, 4_294_967_295)
            network = _prefix(address, version=int(family[-1]))
            if order in rules or network in rules.values():
                raise ValueError
            rules[order] = network
        else:
            raise ValueError
    return maps, {name: tuple(sorted(rules.values())) for name, rules in lists.items()}


def _add_peer_setting(neighbors, row):
    fields = row.split(maxsplit=3)
    if len(fields) != 4:
        raise ValueError
    _, address, setting, value = fields
    peer = _peer_address(address)
    options = neighbors.setdefault(peer, {})
    if setting == "timers" and value.startswith("connect "):
        setting, value = "connect-retry", _number(value.removeprefix("connect "), 65_535)
    elif setting == "timers":
        keepalive, holdtime = (0 if part == "0" else _number(part, 65_535) for part in value.split())
        if holdtime in (1, 2) or (holdtime and not keepalive):
            raise ValueError
        value = (keepalive, holdtime)
    elif setting == "remote-as":
        value = _number(value, 4_294_967_294)
    elif setting == "capability" and value == "extended-nexthop" and peer.version == 6:
        value = True
    elif not ((setting == "description" and _DESCRIPTION.fullmatch(value))
              or (setting == "password" and _PASSWORD.fullmatch(value))):
        raise ValueError
    if setting in options:
        raise ValueError
    options[setting] = value


def _peer_family(rows, neighbors, maps, lists):
    settings = {}
    for row in rows:
        fields = row.split(maxsplit=2)
        if len(fields) != 3 or fields[0] != "neighbor":
            raise ValueError
        address, command = ip_address(fields[1]), fields[2]
        if address not in neighbors:
            raise ValueError
        options = settings.setdefault(address, {})
        match = re.fullmatch(rf"route-map ({_NAME}) (in|out)", command)
        if match:
            name, key = match.groups()
            value = name
        elif command in {"activate", "soft-reconfiguration inbound"}:
            key, value = command, True
        else:
            raise ValueError
        if key in options:
            raise ValueError
        options[key] = value

    required = {"activate", "in", "out"}
    if any(not required <= options.keys() for options in settings.values()):
        raise ValueError
    if {options[key] for options in settings.values() for key in ("in", "out")} != set(maps) or set(maps.values()) != set(lists):
        raise ValueError
    filters = {(lists[maps[options["in"]]], lists[maps[options["out"]]]) for options in settings.values()}
    if len(filters) != 1:
        raise ValueError
    return {address: options.get("soft-reconfiguration inbound", False) for address, options in settings.items()}, filters.pop()


def _parse_router(rows):
    local = re.fullmatch(r"router bgp ([0-9]+)", rows[0])
    if local is None:
        raise ValueError
    local_as = _number(local[1], 4_294_967_294)
    family = next(index for index, row in enumerate(rows) if re.fullmatch(r"address-family ipv[46](?: unicast)?", row))
    router_id = None
    neighbors = {}
    networks = set()
    no_default_ipv4 = False
    for row in rows[1:family]:
        match row.split():
            case ["bgp", "router-id", value] if router_id is None:
                router_id = IPv4Address(value)
            case ["neighbor", *_]:
                _add_peer_setting(neighbors, row)
            case ["no", "bgp", "default", "ipv4-unicast"] if not no_default_ipv4 and not neighbors:
                no_default_ipv4 = True
            case ["network", address, "mask", mask]:
                network = _prefix((address, mask))
                if str(network.network_address) != address or str(network.netmask) != mask or network in networks:
                    raise ValueError
                networks.add(network)
            case ["network", address] if "/" in address:
                network = _prefix(address, version=4)
                if network in networks:
                    raise ValueError
                networks.add(network)
            case _:
                raise ValueError
    if (router_id is None or router_id in neighbors or not neighbors
            or router_id.is_link_local or any(options.get("remote-as") in (None, local_as) for options in neighbors.values())
            or any(value.is_unspecified or value.is_multicast or value.is_loopback or value.is_reserved
                   for value in (router_id, *neighbors))):
        raise ValueError
    sections = {}
    while family < len(rows) and (header := re.fullmatch(r"address-family (ipv[46])(?: unicast)?", rows[family])):
        name = header[1]
        if name in sections or name == "ipv6" and not no_default_ipv4:
            raise ValueError
        end = rows.index("exit-address-family", family)
        peer_rows = []
        for row in rows[family + 1:end]:
            fields = row.split()
            if len(fields) == 2 and fields[0] == "network" and "/" in fields[1]:
                network = _prefix(fields[1], version=int(name[-1]))
                if network in networks:
                    raise ValueError
                networks.add(network)
            else:
                peer_rows.append(row)
        sections[name] = peer_rows
        family = end + 1
    if rows[family:family + 1] != ["exit"]:
        raise ValueError
    maps, lists = _parse_policy(rows[family + 1:])
    if {f"ipv{entry.version}" for entry in networks} != sections.keys():
        raise ValueError
    if {name for name, _ in maps.values()} != sections.keys() or {name for name, _ in lists} != sections.keys():
        raise ValueError
    families = {peer: {} for peer in neighbors}
    imports, exports = [], []
    for name, peer_rows in sorted(sections.items()):
        version = int(name[-1])
        family_peers, (family_imports, family_exports) = _peer_family(
            peer_rows, neighbors,
            {key: value for key, (family_name, value) in maps.items() if family_name == name},
            {key: value for (family_name, key), value in lists.items() if family_name == name},
        )
        if not set(family_exports) <= networks:
            raise ValueError
        for address, soft in family_peers.items():
            families[address][version] = soft
        imports.extend(family_imports)
        exports.extend(family_exports)
    if any(address.version not in enabled for address, enabled in families.items()):
        raise ValueError
    if any(("capability" in neighbors[address]) != (address.version == 6 and 4 in enabled)
           for address, enabled in families.items()):
        raise ValueError
    peers = tuple(BgpPeer(
        address, options["remote-as"], tuple(families[address].items()), options.get("description"), options.get("password"),
        timers=options.get("timers"), connect_retry=options.get("connect-retry"),
    ) for address, options in sorted(neighbors.items(), key=lambda item: (item[0].version, item[0])))
    ordered_networks = sorted(networks, key=lambda network: (network.version, network))
    return BgpIntent(local_as, router_id, peers, tuple(ordered_networks), tuple(imports), tuple(exports))


def _normalize_frr_line(line):
    fields = line.split(maxsplit=3)
    if len(fields) == 4 and fields[0] == "neighbor" and fields[2] == "description":
        return " ".join(fields)
    return " ".join(line.split())


def decode_bgp_intent(upload):
    """Decode a complete upload. Only an explicit disabled block means withdrawal."""
    if (not isinstance(upload, dict) or upload.keys() != {"enabled", "config"}
            or type(upload["enabled"]) is not bool or not isinstance(upload["config"], str)
            or len(upload["config"]) > _RAW_LIMIT):
        raise BgpIntentError("Invalid Enterprise BGP upload block")
    if not upload["enabled"]:
        return None
    try:
        raw = b64decode(upload["config"], validate=True).decode("ascii")
        if any(not 32 <= ord(char) <= 126 and char not in "\t\r\n" for char in raw):
            raise ValueError
        rows = [_normalize_frr_line(line.strip()) for line in raw.splitlines()
                if line.strip() and not line.lstrip().startswith("!")]
        if not 1 <= len(rows) <= 128:
            raise ValueError
        return _parse_router(rows)
    except (Base64Error, ValueError, StopIteration):
        raise BgpIntentError("Enterprise BGP requires a supported eBGP upload with exact import and export policy") from None


def normalize_bgp_policy(system_cfg, *, revision):
    """Separate the exact versioned upload without altering adjacent controller intent."""
    if not isinstance(system_cfg, str) or not isinstance(revision, str) or not revision:
        raise BgpIntentError("Enterprise BGP requires a complete snapshot and controller revision")
    try:
        document = json.loads(system_cfg, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except (ValueError, RecursionError):
        raise BgpIntentError("Invalid Enterprise BGP snapshot JSON") from None
    udapi = document.get("udapi") if isinstance(document, dict) else None
    versions = udapi.get("versionDetail") if isinstance(udapi, dict) else None
    if not isinstance(versions, dict):
        raise BgpIntentError("Enterprise BGP requires a versioned configuration snapshot")
    if BGP_UPLOAD_KEY not in versions and BGP_UPLOAD_KEY not in udapi:
        return system_cfg, None
    version = versions.get(BGP_UPLOAD_KEY)
    if type(version) is not int or version != BGP_UPLOAD_VERSION:
        raise BgpIntentError("Invalid Enterprise BGP upload schema")
    desired = None
    if BGP_UPLOAD_KEY in udapi:
        desired = BgpProvisioningIntent(revision, decode_bgp_intent(udapi.pop(BGP_UPLOAD_KEY)))
    del versions[BGP_UPLOAD_KEY]
    return json.dumps(document), desired


def vyos_bgp_configuration(intent):
    """Return stock VyOS subtrees for a separately verified ownership transaction."""
    if intent is None:
        return {}
    neighbors = {}
    for peer in intent.peers:
        families = {}
        for version, soft in peer.address_families:
            import_path, export_path = _FILTER_PATHS[version]
            family = {"prefix-list": {"import": import_path[-1], "export": export_path[-1]}}
            if soft:
                family["soft-reconfiguration"] = {"inbound": {}}
            families[f"ipv{version}-unicast"] = family
        neighbor = {"remote-as": str(peer.remote_as), "address-family": families}
        if peer.address.version == 6 and "ipv4-unicast" in families:
            neighbor["capability"] = {"extended-nexthop": {}}
        if peer.description is not None:
            neighbor["description"] = peer.description
        if peer.password is not None:
            neighbor["password"] = peer.password
        timers = {}
        if peer.timers is not None:
            keepalive, holdtime = peer.timers
            timers["holdtime"] = str(holdtime)
            # VyOS emits the FRR override only when both leaves exist.
            # It accepts a positive keepalive leaf, while holdtime 0 disables the exchange.
            timers["keepalive"] = str(keepalive or 1)
        if peer.connect_retry is not None:
            timers["connect"] = str(peer.connect_retry)
        if timers:
            neighbor["timers"] = timers
        neighbors[str(peer.address)] = neighbor
    versions = sorted({version for peer in intent.peers for version, _ in peer.address_families})
    address_families = {
        f"ipv{version}-unicast": {"network": {str(network): {} for network in intent.networks if network.version == version}}
        for version in versions
    }
    filters = {}
    for version in versions:
        for path, prefixes in zip(_FILTER_PATHS[version], (intent.imports, intent.exports), strict=True):
            family_prefixes = (prefix for prefix in prefixes if prefix.version == version)
            filters[path] = {"rule": {str(index * 10): {"action": "permit", "prefix": str(network)}
                                      for index, network in enumerate(family_prefixes, 1)}}
    return {
        _BGP_PATH: {
            "system-as": str(intent.local_as),
            "parameters": {"router-id": str(intent.router_id), "network-import-check": {}},
            "address-family": address_families,
            "neighbor": neighbors,
        },
        **filters,
    }


def read_bgp_configuration(backend):
    """Read only the stock resource paths reserved by the BGP translator."""
    observed = {}
    for path in _OWNED_PATHS:
        tree = backend.read_config(list(path))
        if tree is not None:
            observed[path] = tree
    return observed


def bgp_checkpoint(resources):
    """Encode owned resources with stable JSON journal keys."""
    return {name: resources[path] for name, path in _CHECKPOINT_PATHS.items() if path in resources}


def bgp_checkpoint_resources(checkpoint):
    """Require an empty or complete verified journal checkpoint."""
    if (not isinstance(checkpoint, dict)
            or checkpoint and checkpoint.keys() not in _VALID_CHECKPOINT_KEYS
            or any(not isinstance(tree, dict) or not tree for tree in checkpoint.values())):
        raise BgpIntentError("Invalid VyOS BGP ownership checkpoint")
    if checkpoint:
        families = checkpoint["process"].get("address-family")
        expected = {family for key, family in (("import", "ipv4-unicast"), ("import6", "ipv6-unicast")) if key in checkpoint}
        if not isinstance(families, dict) or families.keys() != expected:
            raise BgpIntentError("Invalid VyOS BGP ownership checkpoint address families")
    resources = {_CHECKPOINT_PATHS[name]: tree for name, tree in checkpoint.items()}
    if any(not isinstance(value, dict) or value.keys() != {"hmac_sha256"}
           or not isinstance(value["hmac_sha256"], str) or re.fullmatch("[0-9a-f]{64}", value["hmac_sha256"]) is None
           for _, value in _bgp_passwords(resources)):
        raise BgpIntentError("Invalid VyOS BGP password proof in the journal")
    return resources


def _bgp_passwords(resources):
    neighbors = resources.get(_BGP_PATH, {}).get("neighbor", {})
    if not isinstance(neighbors, dict) or any(not isinstance(node, dict) for node in neighbors.values()):
        raise BgpIntentError("Invalid VyOS BGP neighbor configuration")
    return [(peer, node["password"]) for peer, node in neighbors.items() if "password" in node]


def bgp_checkpoint_has_password(checkpoint):
    return bool(_bgp_passwords(bgp_checkpoint_resources(checkpoint)))


def redact_bgp_configuration(resources, proof_key):
    """Keep password values out of journal comparisons and checkpoints."""
    passwords = _bgp_passwords(resources)
    if not passwords:
        return resources
    if not isinstance(proof_key, bytes) or len(proof_key) != 32:
        raise BgpIntentError("VyOS BGP password verification requires the private BGP credential proof key")
    process = resources[_BGP_PATH]
    neighbors = process["neighbor"].copy()
    for peer, password in passwords:
        if not isinstance(password, str) or _PASSWORD.fullmatch(password) is None:
            raise BgpIntentError("VyOS did not expose a supported BGP neighbor password for read-back")
        digest = hmac.digest(proof_key, f"bgp-auth/{peer}\0{password}".encode(), "sha256").hex()
        neighbors[peer] = neighbors[peer] | {"password": {"hmac_sha256": digest}}
    return resources | {_BGP_PATH: process | {"neighbor": neighbors}}


def _update_process(commands, path, before, after, raw):
    if before == after:
        return
    if after is None:
        commands.append({"op": "delete", "path": path})
    elif isinstance(before, dict) and before and isinstance(after, dict) and after and isinstance(raw, dict):
        for key in sorted(before.keys() | after.keys()):
            _update_process(commands, [*path, key], before.get(key), after.get(key), raw.get(key))
    else:
        _set_commands(commands, path, raw)


def plan_bgp_commands(intent, *, current, verified, proof_key=None):
    """Plan an atomic change only over the three exactly verified resources."""
    raw = vyos_bgp_configuration(intent)
    desired = redact_bgp_configuration(raw, proof_key)
    if (current != verified or not isinstance(verified, dict)
            or verified and bgp_checkpoint(verified).keys() not in _VALID_CHECKPOINT_KEYS
            or any(path not in _OWNED_PATHS for path in verified)
            or any(not isinstance(tree, dict) or not tree for tree in verified.values())):
        raise BgpIntentError("VyOS BGP configuration differs from verified ownership")
    changed = {path for path in _OWNED_PATHS if current.get(path) != desired.get(path)}
    update_process = _BGP_PATH in current and _BGP_PATH in desired
    commands = [{"op": "delete", "path": list(path)} for path in _OWNED_PATHS if path in changed and path in current
                and not (path == _BGP_PATH and update_process)]
    for path in (*_OWNED_PATHS[1:], _BGP_PATH):
        if path in changed and path in desired:
            if path == _BGP_PATH and update_process:
                _update_process(commands, list(path), current[path], desired[path], raw[path])
            else:
                _set_commands(commands, list(path), raw[path])
    return tuple(commands)
