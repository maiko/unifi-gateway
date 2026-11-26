"""Exercise native DNS intent and exact VyOS authoritative-zone ownership."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from provisioners.vyos_dns import (
    DnsIntentError,
    DnsScope,
    decode_dns_intent,
    outside_dns_records,
    plan_dns_commands,
)


ZONE = "uxg-lab.test"
ZONE_PATH = ["service", "dns", "forwarding", "authoritative-domain", ZONE]
CREATE = {"records": {"a": {"probe": {"address": "192.0.2.42", "ttl": "300"}}}}


@pytest.fixture
def native():
    fixture = Path(__file__).parent / "fixtures" / "uxg_pro" / "native-static-dns-snapshots.json"
    data = json.loads(fixture.read_text())
    version = {key: data[key] for key in ("version", "versionFormat", "versionDetail")}
    return {
        stage: {"udapi": {
            **deepcopy(version),
            "services": {"dnsForwarder": {
                **deepcopy(data["forwarder"]),
                "hostRecords": deepcopy(data["unmanaged"]) + records,
            }},
        }}
        for stage, records in data["records"].items()
    }


@pytest.fixture
def scope():
    return DnsScope(ZONE)


@pytest.fixture
def forwarding():
    return {
        "listen-address": "192.0.2.1",
        "allow-from": ["192.0.2.0/24", "2001:db8::/64"],
        "system": {},
        "authoritative-domain": {
            "operator.test": {"records": {"txt": {"service": {"value": "preserve", "ttl": "300"}}}},
        },
        "domain": {"forwarded.test": {"name-server": {"192.0.2.53": {}}}},
        "zone-cache": {"cached.test": {"source": {"url": "https://example.test/zone"}}},
    }


def _records(document):
    return document["udapi"]["services"]["dnsForwarder"]["hostRecords"]


def _decode(document, scope):
    return decode_dns_intent(json.dumps(document), revision="revision", scope=scope, nat=True)


def _plan(document, scope, forwarding, verified=None):
    return plan_dns_commands(
        _decode(document, scope), scope=scope, current_forwarding=forwarding, verified_zone=verified,
    )


def test_native_create_filters_exact_zone_and_preserves_other_records(native, scope, forwarding):
    before = deepcopy(forwarding)
    assert _decode(native["create"], scope).revision == "revision"
    assert outside_dns_records(_records(native["create"]), scope) == _records(native["delete"])
    plan = _plan(native["create"], scope, forwarding)

    assert plan.desired_zone == CREATE
    assert plan.commands == (
        {"op": "set", "path": ZONE_PATH + ["records", "a", "probe", "address"], "value": "192.0.2.42"},
        {"op": "set", "path": ZONE_PATH + ["records", "a", "probe", "ttl"], "value": "300"},
    )
    assert forwarding == before


def test_edit_replaces_the_whole_verified_zone(native, scope, forwarding):
    forwarding["authoritative-domain"][ZONE] = deepcopy(CREATE)
    plan = _plan(native["edit"], scope, forwarding, verified=CREATE)

    assert plan.desired_zone == {"records": {"a": {"probe": {"address": "198.51.100.42", "ttl": "450"}}}}
    assert plan.commands == (
        {"op": "delete", "path": ZONE_PATH},
        {"op": "set", "path": ZONE_PATH + ["records", "a", "probe", "address"], "value": "198.51.100.42"},
        {"op": "set", "path": ZONE_PATH + ["records", "a", "probe", "ttl"], "value": "450"},
    )


def test_native_aaaa_and_a_compile_as_distinct_types(native, scope, forwarding):
    plan = _plan(native["aaaa"], scope, forwarding)

    assert plan.desired_zone == {"records": {
        "a": {"probe": {"address": "198.51.100.42", "ttl": "450"}},
        "aaaa": {"probe-v6": {"address": "2001:db8::42", "ttl": "360"}},
    }}
    assert plan.commands[-2:] == (
        {"op": "set", "path": ZONE_PATH + ["records", "aaaa", "probe-v6", "address"], "value": "2001:db8::42"},
        {"op": "set", "path": ZONE_PATH + ["records", "aaaa", "probe-v6", "ttl"], "value": "360"},
    )


def test_native_removal_deletes_only_verified_zone(native, scope, forwarding):
    forwarding["authoritative-domain"] = {ZONE: deepcopy(CREATE)}
    plan = _plan(native["delete"], scope, forwarding, verified=CREATE)

    assert plan.desired_zone is None
    assert plan.commands == ({"op": "delete", "path": ZONE_PATH},)


def test_dhcp_controller_discovery_projects_one_a_record_with_stock_ttl(native, scope, forwarding):
    document = native["create"]
    records = _records(document)
    anchor, companion = _records(native["dhcp-discovery"])[-2:]
    records.extend((anchor, companion))

    intent = decode_dns_intent(json.dumps(document), revision="create", nat=True, scope=scope, dhcp_domain=ZONE)
    plan = plan_dns_commands(intent, scope=scope, current_forwarding=forwarding, verified_zone=None)
    assert plan.desired_zone == {"records": {"a": {**CREATE["records"]["a"], "unifi": {"address": "192.0.2.53"}}}}
    assert plan.commands[-1] == {
        "op": "set", "path": ZONE_PATH + ["records", "a", "unifi", "address"], "value": "192.0.2.53",
    }
    forwarding["authoritative-domain"][ZONE] = plan.desired_zone
    records.remove(companion)
    withdrawn = _plan(document, scope, forwarding, verified=plan.desired_zone)
    assert withdrawn.desired_zone == CREATE


def test_verified_zone_is_idempotent(native, scope, forwarding):
    forwarding["authoritative-domain"][ZONE] = deepcopy(CREATE)
    assert _plan(native["create"], scope, forwarding, verified=CREATE).commands == ()


@pytest.mark.parametrize("patch", [
    {"hostName": ZONE}, {"hostName": "any." + ZONE}, {"hostName": "*." + ZONE},
    {"hostName": "foo.." + ZONE}, {"hostName": "a " + ZONE}, {"hostName": "K." + ZONE},
    {"hostName": ".".join(("a" * 63, "b", ZONE))}, {"registerNonQualified": True}, {"ttl": 0},
    {"ttl": True}, {"ttl": 2147483648}, {"cname": "other.test"},
    {"address": {"version": "v6", "origin": None, "address": "192.0.2.42"}},
    {"address": {"version": "v6", "origin": None, "address": "fe80::1%eth3"}},
    {"address": {"version": "v4", "origin": None, "address": "255.255.255.255"}},
    {"address": {"version": "v4", "origin": "dynamic", "address": "192.0.2.42"}},
])
def test_unsupported_scoped_record_cannot_yield_commands(native, scope, patch):
    _records(native["create"])[-1].update(patch)

    with pytest.raises(DnsIntentError):
        _decode(native["create"], scope)


def test_duplicate_owner_with_same_type_cannot_create_rrset(native, scope):
    records = _records(native["create"])
    records.append({
        **records[-1],
        "hostName": "PROBE.UXG-LAB.TEST.",
        "address": {"version": "v4", "origin": None, "address": "192.0.2.43"},
    })

    with pytest.raises(DnsIntentError, match="duplicate"):
        _decode(native["create"], scope)


@pytest.mark.parametrize("change", [
    lambda forwarder: forwarder.pop("hostRecords"),
    lambda forwarder: forwarder.update(hostRecords=None),
    lambda forwarder: forwarder.update(enabled=False),
    lambda forwarder: forwarder["hostRecords"].append({"address": {"address": "192.0.2.99"}}),
])
def test_incomplete_or_disabled_snapshot_cannot_remove_zone(native, scope, change):
    change(native["delete"]["udapi"]["services"]["dnsForwarder"])

    with pytest.raises(DnsIntentError):
        _decode(native["delete"], scope)


@pytest.mark.parametrize("nat, broker, patch, valid", [
    (True, False, {}, True),
    (False, False, {"firewall/nat": None}, True),
    (True, True, {"services/messageBroker": 3}, True),
    (False, True, {"firewall/nat": None, "services/messageBroker": 3}, True),
    (False, False, {}, False),
    (True, True, {}, False),
    (True, False, {"firewall/nat": 8}, False),
    (True, False, {"services/dnsForwarder": 3}, False),
    (True, False, {"firewall/sets": True}, False),
    (True, False, {"future": 1}, False),
])
def test_schema_requires_exact_explicit_capability_pins(native, scope, nat, broker, patch, valid):
    document = native["create"]
    versions = document["udapi"]["versionDetail"]
    for key, value in patch.items():
        if value is None:
            del versions[key]
        else:
            versions[key] = value

    def decode():
        return decode_dns_intent(
            json.dumps(document), revision="revision", scope=scope, nat=nat, message_broker=broker,
        )

    if valid:
        assert decode().revision == "revision"
    else:
        with pytest.raises(DnsIntentError, match="schema"):
            decode()


@pytest.mark.parametrize("collection, name", [
    ("authoritative-domain", ZONE),
    ("authoritative-domain", "child." + ZONE),
    ("authoritative-domain", "test"),
    ("authoritative-domain", "UXG-LAB.TEST."),
    ("domain", "child." + ZONE),
    ("domain", "."),
    ("zone-cache", ZONE),
])
def test_refuses_creation_overlapping_unverified_vyos_zones(native, scope, forwarding, collection, name):
    forwarding[collection][name] = {"operator-only": {}}

    with pytest.raises(DnsIntentError):
        _plan(native["create"], scope, forwarding)


@pytest.mark.parametrize("field", ["listen-address", "allow-from"])
def test_preconfigured_resolver_required(native, scope, forwarding, field):
    del forwarding[field]

    with pytest.raises(DnsIntentError, match="resolver"):
        _plan(native["create"], scope, forwarding)


def test_equal_zone_still_requires_preconfigured_resolver(native, scope, forwarding):
    forwarding["authoritative-domain"][ZONE] = deepcopy(CREATE)
    del forwarding["listen-address"]

    with pytest.raises(DnsIntentError, match="resolver"):
        _plan(native["create"], scope, forwarding, verified=CREATE)


@pytest.mark.parametrize("drift", [
    {"disable": {}},
    {"records": {"a": {"probe": {"address": ["192.0.2.42", "192.0.2.43"], "ttl": "300"}}}},
])
def test_refuses_to_remove_drifted_live_zone(native, scope, forwarding, drift):
    forwarding["authoritative-domain"][ZONE] = {**CREATE, **drift}
    with pytest.raises(DnsIntentError, match="ownership"):
        _plan(native["delete"], scope, forwarding, verified=CREATE)


def test_refuses_unrecognized_verified_zone_tree(native, scope, forwarding):
    unsupported = {"records": {"cname": {"probe": {"target": "outside.test", "ttl": "300"}}}}
    forwarding["authoritative-domain"][ZONE] = unsupported

    with pytest.raises(DnsIntentError, match="ownership"):
        _plan(native["delete"], scope, forwarding, verified=unsupported)


@pytest.mark.parametrize("zone", [
    "", ".", "@", "test", "in-addr.arpa", "*.test", "foo..test", "any", "private.example.com",
])
def test_scope_rejects_root_reverse_or_ambiguous_zones(zone):
    with pytest.raises(DnsIntentError):
        DnsScope(zone)
