"""Decode the observed policy-based IPv4 IPsec tunnel and plan owned VyOS commands."""

from dataclasses import dataclass, field
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
import json
import re
from uuid import UUID

from collectors.vyos import interface_ipv4_addresses


_SECTION = "vpn/ipsec/site-to-site"
_GLOBAL_SECTION = "vpn/ipsec"
_PATH = ("vpn", "ipsec")
_LIFETIMES = (3600, 4200)
_CIPHER = {"encryption": "aes256", "hash": "sha256", "dhGroup": 14}
_SECRET = re.compile(r"[0-9a-f]{48}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class IpsecIntentError(ValueError):
    """The gateway configuration does not establish the owned IPsec configuration."""


@dataclass(frozen=True, slots=True)
class IpsecScope:
    wan_id: str
    wan_interface: str
    wan_cidr: str
    lan_id: str
    lan_interface: str
    lan_cidr: str
    remote_peer: str
    local_selector: str
    remote_selector: str
    name: str

    def __post_init__(self):
        bridge = re.fullmatch(r"br([1-9][0-9]{0,3})", self.lan_id) if isinstance(self.lan_id, str) else None
        wan = re.fullmatch(r"eth[0-9]+(?:\.([1-9][0-9]{0,3}))?", self.wan_interface) if isinstance(
            self.wan_interface, str
        ) else None
        if (
            not isinstance(self.wan_id, str) or re.fullmatch(r"eth[0-9]{1,10}", self.wan_id) is None
            or wan is None or len(self.wan_interface) > 15 or (wan[1] is not None and int(wan[1]) > 4094)
            or bridge is None or int(bridge[1]) > 4094 or not isinstance(self.lan_interface, str)
            or len(self.lan_interface) > 15 or re.fullmatch(rf"eth[0-9]+\.{bridge[1]}", self.lan_interface) is None
            or self.wan_interface == self.lan_interface
            or not isinstance(self.name, str) or re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{1,30}", self.name) is None
        ):
            raise IpsecIntentError("IPsec requires distinct pinned WAN and LAN interfaces and a VyOS name")
        wan_address, lan_address = (_ipv4_interface(value) for value in (self.wan_cidr, self.lan_cidr))
        peer = _ipv4_host(self.remote_peer)
        local = _selector(self.local_selector)
        remote = _selector(self.remote_selector)
        if (
            wan_address.network.overlaps(lan_address.network)
            or not _on_link(wan_address.ip, wan_address) or not _on_link(lan_address.ip, lan_address)
            or peer == wan_address.ip or not _on_link(peer, wan_address)
            or local == lan_address.ip or not _on_link(local, lan_address)
            or remote in wan_address.network or remote in lan_address.network
        ):
            raise IpsecIntentError("IPsec requires an on-link WAN peer and two distinct host selectors")

    @property
    def local_ip(self) -> str:
        return self.wan_cidr.partition("/")[0]


@dataclass(frozen=True, slots=True)
class IpsecPeer:
    native_id: str
    esp_lifetime: int
    _secret: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class IpsecIntent:
    revision: str
    scope: IpsecScope
    peer: IpsecPeer | None


@dataclass(frozen=True, slots=True)
class IpsecPlan:
    desired_config: dict | None
    commands: tuple[dict, ...] = field(repr=False)


def decode_ipsec_intent(
    system_cfg: str, *, revision: str, scope: IpsecScope, expected_versions: dict,
) -> IpsecIntent:
    """Read only the IPsec entry and the pinned interface layout from a full native snapshot."""
    if not isinstance(revision, str) or not revision or not isinstance(scope, IpsecScope):
        raise IpsecIntentError("IPsec snapshot needs a controller revision and a configured scope")
    if not isinstance(system_cfg, str) or not isinstance(expected_versions, dict) or not expected_versions:
        raise IpsecIntentError("IPsec decoding requires a complete snapshot and pinned schema")
    try:
        document = json.loads(system_cfg, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except IpsecIntentError:
        raise
    except (ValueError, RecursionError):
        raise IpsecIntentError("IPsec snapshot is not valid JSON") from None

    udapi = document.get("udapi") if isinstance(document, dict) else None
    if not isinstance(udapi, dict):
        raise IpsecIntentError("IPsec snapshot lacks a complete UDAPI envelope")
    versions = udapi.get("versionDetail")
    if (
        versions != expected_versions or any(type(version) is not int for version in versions.values())
        or type(udapi.get("version")) is not int or udapi["version"] != 48 or udapi.get("versionFormat") != "v2"
        or any(key.startswith(_GLOBAL_SECTION) for key in versions)
        or any(key.startswith(_GLOBAL_SECTION) and key != _SECTION for key in udapi)
    ):
        raise IpsecIntentError("Unsupported UDAPI IPsec schema")
    _prove_controller_interfaces(udapi.get("interfaces"), scope)
    if _SECTION not in udapi:
        return IpsecIntent(revision, scope, None)

    entries = udapi[_SECTION]
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        raise IpsecIntentError("IPsec snapshot must contain exactly one configured tunnel when present")
    return IpsecIntent(revision, scope, _decode_peer(entries[0], scope))


def redact_ipsec_config(tree: dict | None, *, scope: IpsecScope) -> dict | None:
    """Validate a raw ownership read-back and replace its PSK with a digest."""
    return _checked_config(tree, scope, _secret_digest)


def plan_ipsec_commands(
    intent: IpsecIntent, *, scope: IpsecScope, current_config: dict | None,
    verified_config: dict | None, live_interfaces: dict,
) -> IpsecPlan:
    """Plan one exclusively owned IPsec tree for a transaction that also confines its traffic."""
    if not isinstance(intent, IpsecIntent) or not isinstance(scope, IpsecScope) or intent.scope != scope:
        raise IpsecIntentError("IPsec intent belongs to another configured scope")
    current = redact_ipsec_config(current_config, scope=scope)
    if current != _checked_config(verified_config, scope, _existing_digest):
        raise IpsecIntentError("VyOS IPsec root differs from verified ownership")
    if intent.peer is None:
        commands = ({"op": "delete", "path": list(_PATH)},) if current is not None else ()
        return IpsecPlan(None, commands)
    if not isinstance(intent.peer, IpsecPeer):
        raise IpsecIntentError("IPsec intent lacks an exact peer")

    _prove_live_interfaces(live_interfaces, scope)
    raw = _config(scope, intent.peer.esp_lifetime, intent.peer._secret)
    desired = redact_ipsec_config(raw, scope=scope)
    old_leaves = dict(_leaves(current or {}, _PATH))
    raw_leaves = dict(_leaves(raw, _PATH))
    commands = []
    for path, value in _leaves(desired, _PATH):
        if old_leaves.get(path) == value:
            continue
        raw_value = raw_leaves[path]
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        commands.extend({"op": "set", "path": list(path), "value": entry} for entry in values)
    return IpsecPlan(desired, tuple(commands))


def _decode_peer(value, scope):
    expected = {
        "enabled": True, "type": "tunnel", "ikeVersion": "v2", "aggressiveMode": False,
        "localAddress": {"source": "static", "address": scope.local_ip}, "remotePeer": scope.remote_peer,
        "localSubnets": [scope.local_selector], "remoteSubnets": [scope.remote_selector],
        "ikeCiphers": [_CIPHER], "espCiphers": [_CIPHER], "ikeLifetime": 28800,
        "dpdAction": "restart", "dpdDelay": 30, "dpdTimeout": 120, "startupAction": "start", "fragmentation": "yes",
    }
    variable = {"id", "espLifetime", "preSharedKey"}
    if (
        value.keys() != expected.keys() | variable
        or any(value[key] != expected[key] for key in expected)
        or any(type(value[key]) is not int for key in ("ikeLifetime", "espLifetime", "dpdDelay", "dpdTimeout"))
        or value["enabled"] is not True or value["aggressiveMode"] is not False
        or type(value["ikeCiphers"][0]["dhGroup"]) is not int or type(value["espCiphers"][0]["dhGroup"]) is not int
        or value["espLifetime"] not in _LIFETIMES
    ):
        raise IpsecIntentError("IPsec tunnel differs from the supported single-peer IKEv2 configuration")
    try:
        identity = UUID(value["id"]) if isinstance(value["id"], str) else None
    except ValueError:
        identity = None
    if identity is None or identity.version != 4 or str(identity) != value["id"]:
        raise IpsecIntentError("IPsec peer lacks a canonical native UUID")
    _secret_digest(value["preSharedKey"])
    return IpsecPeer(str(identity), value["espLifetime"], value["preSharedKey"])


def _prove_controller_interfaces(interfaces, scope):
    if not isinstance(interfaces, list) or any(not isinstance(entry, dict) for entry in interfaces):
        raise IpsecIntentError("IPsec needs a complete controller interface snapshot")
    for name, kind, cidr in ((scope.wan_id, "ethernet", scope.wan_cidr), (scope.lan_id, "bridge", scope.lan_cidr)):
        rows = [row for row in interfaces if isinstance(row.get("identification"), dict)
                and row["identification"].get("id") == name]
        if (
            len(rows) != 1 or rows[0]["identification"] != {"id": name, "type": kind}
            or rows[0].get("addresses") != [{"cidr": cidr, "type": "static", "version": "v4"}]
        ):
            raise IpsecIntentError("IPsec controller interfaces differ from their pinned IPv4 addresses")


def _prove_live_interfaces(live, scope):
    if not isinstance(live, dict):
        raise IpsecIntentError("IPsec needs a current VyOS interface snapshot")
    expected = {scope.wan_interface: scope.wan_cidr, scope.lan_interface: scope.lan_cidr}
    if not expected.keys() <= live.keys():
        raise IpsecIntentError("Pinned VyOS IPsec interfaces are missing")
    remote = _selector(scope.remote_selector)
    for name, entry in live.items():
        if (not isinstance(entry, (tuple, list)) or len(entry) != 2
                or not isinstance(entry[0], (tuple, list)) or not isinstance(entry[1], str)):
            raise IpsecIntentError("Unexpected live VyOS interface read-back")
        try:
            addresses = interface_ipv4_addresses(entry[1])
        except ValueError:
            raise IpsecIntentError("Invalid live VyOS interface address") from None
        if any(remote in address.network for address in addresses):
            raise IpsecIntentError("IPsec remote selector overlaps a live VyOS interface")
        if name in expected and (
            not {"UP", "LOWER_UP"}.issubset(entry[0]) or [str(address) for address in addresses] != [expected[name]]
        ):
            raise IpsecIntentError("Pinned VyOS IPsec interface lacks its exact active IPv4 address")


def _checked_config(tree, scope, redact):
    if tree is None:
        return None
    if not isinstance(scope, IpsecScope) or not isinstance(tree, dict):
        raise IpsecIntentError("Unexpected VyOS IPsec ownership root")
    try:
        lifetime = tree["esp-group"][scope.name]["lifetime"]
        secret = tree["authentication"]["psk"][scope.name]["secret"]
    except (KeyError, TypeError):
        raise IpsecIntentError("Unexpected VyOS IPsec ownership root") from None
    if lifetime not in tuple(map(str, _LIFETIMES)) or tree != _config(scope, int(lifetime), secret):
        raise IpsecIntentError("Unexpected VyOS IPsec ownership root")
    return _config(scope, int(lifetime), redact(secret))


def _config(scope, lifetime, secret):
    return {
        "interface": scope.wan_interface,
        "authentication": {"psk": {scope.name: {"id": [scope.local_ip, scope.remote_peer], "secret": secret}}},
        "ike-group": {scope.name: {
            "key-exchange": "ikev2", "lifetime": "28800",
            "dead-peer-detection": {"action": "restart", "interval": "30", "timeout": "120"},
            "proposal": {"10": {"encryption": "aes256", "hash": "sha256", "dh-group": "14"}},
        }},
        "esp-group": {scope.name: {
            "mode": "tunnel", "pfs": "dh-group14", "lifetime": str(lifetime),
            "proposal": {"10": {"encryption": "aes256", "hash": "sha256"}},
        }},
        "site-to-site": {"peer": {scope.name: {
            "local-address": scope.local_ip, "remote-address": scope.remote_peer, "connection-type": "initiate",
            "authentication": {"mode": "pre-shared-secret", "local-id": scope.local_ip, "remote-id": scope.remote_peer},
            "ike-group": scope.name, "default-esp-group": scope.name,
            "tunnel": {"0": {"local": {"prefix": scope.local_selector}, "remote": {"prefix": scope.remote_selector}}},
        }}},
    }


def _leaves(tree, path):
    for key, value in tree.items():
        leaf = path + (key,)
        if isinstance(value, dict):
            yield from _leaves(value, leaf)
        else:
            yield leaf, value


def _ipv4_interface(value):
    try:
        parsed = IPv4Interface(value) if isinstance(value, str) else None
    except ValueError:
        parsed = None
    if parsed is None or str(parsed) != value or not _unicast(parsed.ip) or parsed.network.prefixlen == 0:
        raise IpsecIntentError("IPsec needs canonical IPv4 interface addresses")
    return parsed


def _ipv4_host(value):
    try:
        parsed = IPv4Address(value) if isinstance(value, str) else None
    except ValueError:
        parsed = None
    if parsed is None or str(parsed) != value or not _unicast(parsed):
        raise IpsecIntentError("IPsec needs a canonical unicast IPv4 peer")
    return parsed


def _selector(value):
    try:
        network = IPv4Network(value) if isinstance(value, str) else None
    except ValueError:
        network = None
    if network is None or str(network) != value or network.prefixlen != 32 or not _unicast(network.network_address):
        raise IpsecIntentError("IPsec requires two explicit IPv4 /32 traffic selectors")
    return network.network_address


def _unicast(address):
    return not (address.is_multicast or address.is_loopback or address.is_unspecified
                or address.is_reserved or address.is_link_local)


def _on_link(address, interface):
    return interface.network.network_address < address < interface.network.broadcast_address


def _secret_digest(secret):
    if not isinstance(secret, str) or _SECRET.fullmatch(secret) is None:
        raise IpsecIntentError("IPsec PSK needs a 48-character hexadecimal value")
    return "sha256:" + sha256(secret.encode("ascii")).hexdigest()


def _existing_digest(digest):
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise IpsecIntentError("Verified IPsec ownership needs a redacted PSK digest")
    return digest


def _unique_fields(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise IpsecIntentError("IPsec snapshot contains a duplicate JSON field")
        result[name] = value
    return result


def _invalid_constant(_value):
    raise IpsecIntentError("IPsec snapshot contains a non-JSON constant")
