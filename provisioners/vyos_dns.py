"""Decode and plan explicitly owned VyOS authoritative DNS records."""

from dataclasses import dataclass
from ipaddress import ip_address
import json
import re

from provisioners.uxg_schema import selected_schema

_ZONE_PATH = ("service", "dns", "forwarding", "authoritative-domain")
_RECORD_TYPES = {"v4": "a", "v6": "aaaa"}
_MAX_TTL = 2147483647
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class DnsIntentError(ValueError):
    """The gateway configuration does not establish an owned DNS zone."""


@dataclass(frozen=True, slots=True)
class DnsScope:
    zone: str

    def __post_init__(self):
        zone = _hostname(self.zone)
        if len(zone) > 63 or not (
            zone.endswith((".test", ".internal")) or _within(zone, "home.arpa")
        ):
            raise DnsIntentError("DNS ownership needs an explicit local authoritative zone")
        object.__setattr__(self, "zone", zone)


@dataclass(frozen=True, slots=True)
class DnsRecord:
    name: str
    kind: str
    address: str
    ttl: int | None


@dataclass(frozen=True, slots=True)
class DnsIntent:
    revision: str
    scope: DnsScope
    records: tuple[DnsRecord, ...]


@dataclass(frozen=True, slots=True)
class DnsPlan:
    desired_zone: dict | None
    commands: tuple[dict, ...]


def decode_dns_intent(
    system_cfg: str, *, revision: str, scope: DnsScope, message_broker=False, nat=False, wireguard=False,
    dhcp_domain: str | None = None,
) -> DnsIntent:
    """Return the records owned within an explicit zone from a complete snapshot."""
    if not isinstance(revision, str) or not revision:
        raise DnsIntentError("DNS snapshot needs a controller revision")
    if not isinstance(scope, DnsScope) or not isinstance(system_cfg, str):
        raise DnsIntentError("DNS snapshot needs a configured scope and a JSON string")
    try:
        document = json.loads(system_cfg, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except DnsIntentError:
        raise
    except (ValueError, RecursionError) as error:
        raise DnsIntentError("DNS snapshot is not valid JSON") from error

    udapi = document.get("udapi") if isinstance(document, dict) else None
    versions = udapi.get("versionDetail") if isinstance(udapi, dict) else None
    expected_versions = selected_schema(message_broker=message_broker, dns_forwarder=True,
                                        nat=nat, wireguard=wireguard)
    if (
        versions != expected_versions or any(type(value) is not int for value in versions.values())
        or type(udapi.get("version")) is not int or udapi["version"] != 48 or udapi.get("versionFormat") != "v2"
    ):
        raise DnsIntentError("Unsupported UDAPI DNS schema")

    services = udapi.get("services")
    forwarder = services.get("dnsForwarder") if isinstance(services, dict) else None
    if not isinstance(forwarder, dict) or forwarder.get("enabled") is not True:
        raise DnsIntentError("DNS snapshot needs an enabled DNS forwarder")
    scoped, outside = _partition(forwarder.get("hostRecords"), scope)
    companion = _discovery_companion(scoped, outside, scope, dhcp_domain)
    records = tuple(_decode_record(record, scope) for record in scoped if record != companion)
    if companion is not None:
        records += (DnsRecord("unifi", "a", companion["address"]["address"], None),)
    _record_tree(records)
    return DnsIntent(revision, scope, records)


def outside_dns_records(records: list, scope: DnsScope) -> list:
    """Retain untouched non-owned records for the caller's controller baseline check."""
    _, outside = _partition(records, scope)
    return outside


def plan_dns_commands(
    intent: DnsIntent, *, scope: DnsScope, current_forwarding: dict | None, verified_zone: dict | None,
) -> DnsPlan:
    """Plan one zone against the fresh forwarding tree and whole-zone ownership."""
    if not isinstance(intent, DnsIntent) or not isinstance(scope, DnsScope) or intent.scope != scope:
        raise DnsIntentError("DNS intent belongs to another configured scope")
    if current_forwarding is None:
        current_forwarding = {}
    if not isinstance(current_forwarding, dict):
        raise DnsIntentError("DNS planning needs the complete VyOS forwarding tree")

    authoritative = _zone_map(current_forwarding, "authoritative-domain")
    current_zone = authoritative.get(scope.zone)
    if current_zone != verified_zone or (scope.zone in authoritative and current_zone is None):
        raise DnsIntentError("VyOS DNS zone differs from verified ownership")
    if verified_zone is not None:
        _verify_owned_zone(verified_zone)

    desired_zone = _record_tree(intent.records)
    if (current_zone is not None or desired_zone is not None) and not all(
        current_forwarding.get(key) for key in ("listen-address", "allow-from")
    ):
        raise DnsIntentError("DNS planning needs a preconfigured VyOS resolver and client access")
    if desired_zone is not None:
        _check_operator_zones(current_forwarding, scope)
    if current_zone == desired_zone:
        return DnsPlan(desired_zone, ())

    path = [*_ZONE_PATH, scope.zone]
    commands = []
    if current_zone is not None:
        commands.append({"op": "delete", "path": path})
    if desired_zone is not None:
        for kind, records in desired_zone["records"].items():
            for name, fields in records.items():
                for key, value in fields.items():
                    commands.append({"op": "set", "path": path + ["records", kind, name, key], "value": value})
    return DnsPlan(desired_zone, tuple(commands))


def _unique_fields(pairs):
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise DnsIntentError("DNS snapshot contains a duplicate JSON field")
        fields[key] = value
    return fields


def _invalid_constant(_value):
    raise DnsIntentError("DNS snapshot contains a non-JSON constant")


def _partition(records, scope):
    if not isinstance(scope, DnsScope) or not isinstance(records, list):
        raise DnsIntentError("DNS snapshot needs an explicit host record list and scope")
    scoped, outside = [], []
    for record in records:
        name = record.get("hostName") if isinstance(record, dict) else None
        if not isinstance(name, str) or not name or any(char.isspace() for char in name):
            raise DnsIntentError("DNS snapshot includes a host record without an identifiable name")
        group = scoped if _within(name.lower().rstrip("."), scope.zone) else outside
        group.append(record)
    return scoped, outside


def _within(name, zone):
    return name == zone or name.endswith("." + zone)


def _discovery_companion(scoped, outside, scope, dhcp_domain):
    if dhcp_domain is None:
        return None
    if _hostname(dhcp_domain) != scope.zone:
        raise DnsIntentError("DHCP controller discovery needs a matching owned DNS zone")
    anchors = []
    for row in outside:
        address = row.get("address")
        if (row.keys() == {"hostName", "registerNonQualified", "address"}
                and row["hostName"].startswith("unifi.") and row["registerNonQualified"] is True
                and isinstance(address, dict) and address.keys() == {"address", "version"}
                and address["version"] == "v4"):
            anchors.append(_address(address["address"], "a"))
    if len(anchors) != 1:
        raise DnsIntentError("DHCP controller discovery needs one existing controller address record")
    companion = {
        "hostName": f"unifi.{scope.zone}", "registerNonQualified": False,
        "address": {"address": anchors[0], "version": "v4"},
    }
    if scoped.count(companion) != 1:
        raise DnsIntentError("DHCP controller discovery record does not match the existing controller address")
    return companion


def _hostname(value):
    if not isinstance(value, str) or not value.isascii():
        raise DnsIntentError("DNS name must be an ASCII hostname")
    name = value.lower().removesuffix(".")
    if len(name) > 253 or any(_LABEL.fullmatch(label) is None for label in name.split(".")):
        raise DnsIntentError("DNS name contains an unsupported label")
    return name


def _relative_name(name):
    # VyOS interprets the literal "any" node as a wildcard.
    if len(name) > 63 or name == "any" or _hostname(name) != name:
        raise DnsIntentError("DNS record needs a named relative owner supported by VyOS")
    return name


def _decode_record(record, scope):
    if (
        record.keys() != {"hostName", "address", "ttl", "registerNonQualified"}
        or record["registerNonQualified"] is not False
    ):
        raise DnsIntentError("Static DNS host records require a manual TTL and the supported address record format")
    hostname = _hostname(record["hostName"])
    if hostname == scope.zone:
        raise DnsIntentError("DNS record must be below the owned zone apex")
    name = _relative_name(hostname.removesuffix("." + scope.zone))
    address = record["address"]
    if (
        not isinstance(address, dict) or address.keys() != {"address", "origin", "version"}
        or address["origin"] is not None or address["version"] not in ("v4", "v6")
    ):
        raise DnsIntentError("DNS record needs a native static IPv4 or IPv6 address")
    kind = _RECORD_TYPES[address["version"]]
    return DnsRecord(name, kind, _address(address["address"], kind), _ttl(record["ttl"]))


def _address(value, kind):
    if not isinstance(value, str) or "%" in value:
        raise DnsIntentError("DNS record needs a single unscoped IP address")
    try:
        address = ip_address(value)
    except ValueError as error:
        raise DnsIntentError("DNS record needs a valid IP address") from error
    if (
        address.version != {"a": 4, "aaaa": 6}[kind] or address.is_unspecified
        or address.is_multicast or str(address) == "255.255.255.255"
    ):
        raise DnsIntentError("DNS record needs a unicast address matching its record type")
    return str(address)


def _ttl(value):
    if type(value) is not int or not 1 <= value <= _MAX_TTL:
        raise DnsIntentError("DNS record needs an explicit TTL from 1 to 2147483647 seconds")
    return value


def _record_tree(records):
    tree = {}
    for record in sorted(records, key=lambda item: (item.kind, item.name)):
        name, kind = _relative_name(record.name), record.kind
        if kind not in _RECORD_TYPES.values():
            raise DnsIntentError("DNS record needs type A or AAAA")
        entries = tree.setdefault(kind, {})
        if name in entries:
            raise DnsIntentError("DNS snapshot contains a duplicate owner and record type")
        fields = {"address": _address(record.address, kind)}
        if record.ttl is not None:
            fields["ttl"] = str(_ttl(record.ttl))
        elif (kind, name) != ("a", "unifi"):
            raise DnsIntentError("Only the generated controller discovery record can use the stock DNS TTL")
        entries[name] = fields
    return {"records": tree} if tree else None


def _verify_owned_zone(zone):
    if not isinstance(zone, dict) or zone.keys() != {"records"}:
        raise DnsIntentError("Invalid saved VyOS DNS ownership")
    records = zone["records"]
    if not isinstance(records, dict) or not records or not set(records).issubset(_RECORD_TYPES.values()):
        raise DnsIntentError("Invalid saved VyOS DNS ownership")
    for kind, entries in records.items():
        if not isinstance(entries, dict) or not entries:
            raise DnsIntentError("Invalid saved VyOS DNS ownership")
        for name, fields in entries.items():
            if not isinstance(fields, dict) or fields.keys() not in ({"address"}, {"address", "ttl"}):
                raise DnsIntentError("Invalid saved VyOS DNS ownership")
            _relative_name(name)
            if "ttl" in fields:
                ttl = fields["ttl"]
                if not isinstance(ttl, str) or re.fullmatch(r"[1-9][0-9]{0,9}", ttl) is None:
                    raise DnsIntentError("Invalid saved VyOS DNS ownership")
                _ttl(int(ttl))
            elif (kind, name) != ("a", "unifi"):
                raise DnsIntentError("Invalid saved VyOS DNS ownership")
            if _address(fields["address"], kind) != fields["address"]:
                raise DnsIntentError("Invalid saved VyOS DNS ownership")


def _zone_map(forwarding, key):
    zones = forwarding.get(key, {})
    if not isinstance(zones, dict):
        raise DnsIntentError("Unexpected VyOS DNS zone collection")
    return zones


def _check_operator_zones(forwarding, scope):
    for key in ("authoritative-domain", "domain", "zone-cache"):
        for name in _zone_map(forwarding, key):
            if key == "authoritative-domain" and name == scope.zone:
                continue
            if name in (".", "@", "any"):
                raise DnsIntentError("Owned DNS zone overlaps a VyOS operator domain")
            name = _hostname(name)
            if _within(name, scope.zone) or _within(scope.zone, name):
                raise DnsIntentError("Owned DNS zone overlaps a VyOS operator domain")
