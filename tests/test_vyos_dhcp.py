"""Qualify the owned DHCPv4 projection and the resulting VyOS command paths."""

from copy import deepcopy
from ipaddress import IPv4Address, IPv4Interface
import json
from pathlib import Path

import pytest

from provisioners.vyos_dhcp import DhcpIntentError, DhcpScope, decode_dhcp_intent, plan_dhcp_commands


@pytest.fixture
def native():
    path = Path(__file__).parent / "fixtures" / "uxg_pro" / "native-dhcp-snapshots.json"
    data = json.loads(path.read_text())
    snapshots = {}
    for stage, server in data["managed_servers"].items():
        servers = [data["default_server"]] if server is None else [data["default_server"], server]
        snapshots[stage] = {
            "udapi": {
                "version": 48,
                "versionFormat": "v2",
                "versionDetail": deepcopy(data["versions"]),
                "interfaces": [deepcopy(data["managed_interface"])],
                "services": {"dhcpServers": deepcopy(servers)},
            }
        }
    for stage, options in data["ntp_options"].items():
        snapshot = deepcopy(snapshots["reservation"])
        snapshot["udapi"]["services"]["dhcpServers"][1]["options"] = deepcopy(options)
        snapshots[f"ntp-{stage}"] = snapshot
    for stage, fields in data["managed_option_excerpts"].items():
        snapshot = deepcopy(snapshots["reservation"])
        snapshot["udapi"]["services"]["dhcpServers"][1].update(deepcopy(fields))
        snapshots[stage] = snapshot
    return snapshots


@pytest.fixture
def scope():
    return DhcpScope("br110", "eth3.110", "unifi-vlan110", 110)


def decode(native, scope):
    return decode_dhcp_intent(json.dumps(native), revision="redacted-revision", scope=scope)


def plan(intent, scope, *, current, verified, addresses=None):
    return plan_dhcp_commands(
        intent,
        scope=scope,
        live_interface_addresses={"eth3.110": ["192.0.2.1/24"]} if addresses is None else addresses,
        current_networks=current,
        verified_network=verified,
    )


def test_native_create_selects_only_mapped_bridge_and_plans_kea_nodes(native, scope):
    document = native["create"]
    intent = decode(document, scope)
    assert intent.revision == "redacted-revision"
    assert intent.interface == IPv4Interface("192.0.2.1/24")
    assert intent.server.router == IPv4Address("192.0.2.1")
    assert intent.server.dns == (IPv4Address("192.0.2.1"),)

    operator = {"subnet": {"203.0.113.0/24": {"subnet-id": "2"}}}
    current = {"operator-lan": operator}
    result = plan(intent, scope, current=current, verified=None)
    prefix = ["service", "dhcp-server", "shared-network-name", "unifi-vlan110", "subnet", "192.0.2.0/24"]
    leaves = [
        (["subnet-id"], "110"),
        (["lease"], "3600"),
        (["option", "default-router"], "192.0.2.1"),
        (["option", "name-server"], "192.0.2.1"),
        (["range", "0", "start"], "192.0.2.100"),
        (["range", "0", "stop"], "192.0.2.150"),
    ]
    assert result.commands == tuple({"op": "set", "path": prefix + path, "value": value} for path, value in leaves)
    assert result.desired_network["subnet"]["192.0.2.0/24"]["option"]["name-server"] == "192.0.2.1"
    assert current == {"operator-lan": operator}
    assert plan(intent, scope, current={scope.shared_network: result.desired_network},
                verified=result.desired_network).commands == ()


def test_native_edit_replaces_only_verified_owned_network(native, scope):
    initial = decode(native["create"], scope)
    old = plan(initial, scope, current={}, verified=None).desired_network
    updated = decode(native["edit"], scope)
    result = plan(updated, scope, current={scope.shared_network: old}, verified=old)
    assert updated.server.dns == (IPv4Address("198.51.100.2"),)
    assert result.commands[0] == {
        "op": "delete", "path": ["service", "dhcp-server", "shared-network-name", "unifi-vlan110"],
    }
    new = result.desired_network["subnet"]["192.0.2.0/24"]
    assert new["lease"] == "7200"
    assert new["range"]["0"] == {"start": "192.0.2.101", "stop": "192.0.2.151"}
    assert new["option"]["name-server"] == "198.51.100.2"


def test_absent_server_in_explicit_snapshot_removes_only_verified_network(native, scope):
    initial = decode(native["create"], scope)
    old = plan(initial, scope, current={}, verified=None).desired_network
    intent = decode(native["delete"], scope)
    assert intent.server is None
    result = plan(intent, scope, current={scope.shared_network: old}, verified=old)
    assert result.desired_network is None
    assert result.commands == ({
        "op": "delete", "path": ["service", "dhcp-server", "shared-network-name", "unifi-vlan110"],
    },)


def test_multi_dns_uses_ordered_values_and_matches_vyos_readback(native, scope):
    document = native["create"]
    values = ["198.51.100.2", "192.0.2.1"]
    document["udapi"]["services"]["dhcpServers"][1]["dnsServers"] = values

    result = plan(decode(document, scope), scope, current={}, verified=None)

    assert result.desired_network["subnet"]["192.0.2.0/24"]["option"]["name-server"] == values
    assert [cmd["value"] for cmd in result.commands if cmd["path"][-1] == "name-server"] == values


@pytest.mark.parametrize(("stage", "addresses"), [
    ("ntp-one", ("192.0.2.2",)), ("ntp-two", ("192.0.2.2", "198.51.100.2")),
])
def test_native_dhcp_option_42_uses_ordered_kea_ntp_addresses(native, scope, stage, addresses):
    base = native["reservation"]
    original = plan(decode(base, scope), scope, current={}, verified=None).desired_network
    desired = decode(native[stage], scope)
    assert desired.server.ntp_servers == tuple(map(IPv4Address, addresses))
    added = plan(desired, scope, current={scope.shared_network: original}, verified=original)
    subtree = added.desired_network["subnet"]["192.0.2.0/24"]
    assert subtree["option"]["ntp-server"] == (addresses[0] if len(addresses) == 1 else list(addresses))
    assert [op["value"] for op in added.commands if op["path"][-1] == "ntp-server"] == list(addresses)
    assert subtree["static-mapping"] == original["subnet"]["192.0.2.0/24"]["static-mapping"]
    restored = plan(decode(base, scope), scope, current={scope.shared_network: added.desired_network},
                    verified=added.desired_network)
    assert restored.desired_network == original


@pytest.mark.parametrize(("stage", "host", "ntp"), [
    ("domain-host", "boot.edge-lab.test", []),
    ("domain-ip-ntp", "198.51.100.2", ["192.0.2.2", "198.51.100.2"]),
])
def test_domain_and_tftp_options_reconcile_and_withdraw_with_existing_lease_controls(native, scope, stage, host, ntp):
    baseline = native["reservation"]
    original = plan(decode(baseline, scope), scope, current={}, verified=None).desired_network
    intent = decode(native[stage], scope)
    added = plan(intent, scope, current={scope.shared_network: original}, verified=original)
    old_subnet = original["subnet"]["192.0.2.0/24"]
    options = {**old_subnet["option"], "domain-name": "uxg-lab.test", "tftp-server-name": host}
    if ntp:
        options["ntp-server"] = ntp
    assert added.desired_network == {"subnet": {"192.0.2.0/24": {**old_subnet, "option": options}}}
    for leaf, value in options.items():
        assert [step["value"] for step in added.commands if step["path"][-1] == leaf] == (
            value if isinstance(value, list) else [value]
        )
    withdrawn = plan(decode(baseline, scope), scope, current={scope.shared_network: added.desired_network},
                     verified=added.desired_network)
    assert withdrawn.desired_network == original


@pytest.mark.parametrize("options", [
    [], {"optionNumber": 42, "value": "192.0.2.2"},
    [{"optionNumber": "42", "value": "192.0.2.2"}], [{"optionNumber": 42, "value": ["192.0.2.2"]}],
    [{"optionNumber": 42, "value": "192.0.2.2, 198.51.100.2"}],
    [{"optionNumber": 42, "value": "192.0.2.2,192.0.2.2"}],
    [{"optionNumber": 42, "value": "192.0.2.2,192.0.2.3,192.0.2.4"}],
    [{"optionNumber": 42, "value": "2001:db8::2"}],
    [{"optionNumber": 42, "value": "192.0.2.2"}, {"optionNumber": 67, "value": "example.test"}],
    [{"optionNumber": 66, "value": "one.test"}, {"optionNumber": 66, "value": "two.test"}],
    [{"optionNumber": 66, "value": "tftp://example.test/path"}],
    [{"optionNumber": 66, "value": "224.0.0.1"}],
    [{"optionNumber": 66, "value": "192.0.2.999"}],
])
def test_malformed_or_mixed_dhcp_options_fail_closed(native, scope, options):
    native["create"]["udapi"]["services"]["dhcpServers"][1]["options"] = options
    with pytest.raises(DhcpIntentError):
        decode(native["create"], scope)


@pytest.mark.parametrize("domain", [None, "", "example.test,evil.test", "a..test", "two words", "_unstable.test"])
def test_dhcp_rejects_unsupported_domain_fields(native, scope, domain):
    native["create"]["udapi"]["services"]["dhcpServers"][1]["domain"] = domain
    with pytest.raises(DhcpIntentError):
        decode(native["create"], scope)


def test_native_network_boot_provisions_both_requested_options_and_bootp_fields(native, scope):
    baseline = native["reservation"]
    original = plan(decode(baseline, scope), scope, current={}, verified=None).desired_network
    edited = native["network-boot"]
    row = edited["udapi"]["services"]["dhcpServers"][1]

    added = plan(decode(edited, scope), scope, current={scope.shared_network: original}, verified=original)
    boot_options = {"bootfile-server": "198.51.100.2", "tftp-server-name": "198.51.100.2",
                    "bootfile-name": "uxg-pro-fixture.bin"}
    source_subnet = original["subnet"]["192.0.2.0/24"]
    assert added.desired_network == {"subnet": {"192.0.2.0/24": {
        **source_subnet, "option": {**source_subnet["option"], **boot_options},
    }}}
    assert {command["path"][-1]: command["value"] for command in added.commands
            if command["path"][-1] in boot_options} == boot_options
    withdrawn = plan(decode(baseline, scope), scope, current={scope.shared_network: added.desired_network},
                     verified=added.desired_network)
    assert withdrawn.desired_network == original

    row["options"] = [{"optionNumber": 66, "value": "198.51.100.2"}]
    assert plan(decode(edited, scope), scope, current={scope.shared_network: original}, verified=original) == added
    row["options"][0]["value"] = "198.51.100.3"
    with pytest.raises(DhcpIntentError, match="conflicts"):
        decode(edited, scope)


@pytest.mark.parametrize("boot", [
    {"serverIP": "192.0.2.5"}, {"serverIP": "boot.example.test", "filename": "boot.efi"},
    {"serverIP": "0.0.0.0", "filename": "boot.efi"}, {"serverIP": "192.0.2.5", "filename": "../boot.efi"},
    {"serverIP": "192.0.2.5", "filename": "a" * 128}, {"serverIP": "192.0.2.5", "filename": "boot\n.efi"},
])
def test_unsupported_native_boot_parameters_fail_closed(native, scope, boot):
    native["create"]["udapi"]["services"]["dhcpServers"][1]["dhcpBoot"] = boot
    with pytest.raises(DhcpIntentError):
        decode(native["create"], scope)


def test_native_reservation_add_readback_and_removal(native, scope):
    old = plan(decode(native["edit"], scope), scope, current={}, verified=None).desired_network
    intent = decode(native["reservation"], scope)
    result = plan(intent, scope, current={scope.shared_network: old}, verified=old)
    expected = {"unifi-020000000042": {"mac": "02:00:00:00:00:42", "ip-address": "192.0.2.42"}}
    assert result.desired_network["subnet"]["192.0.2.0/24"]["static-mapping"] == expected
    assert result.commands[-2:] == tuple(
        {"op": "set", "path": ["service", "dhcp-server", "shared-network-name", scope.shared_network,
                              "subnet", "192.0.2.0/24", "static-mapping", "unifi-020000000042", key],
         "value": value}
        for key, value in expected["unifi-020000000042"].items()
    )
    verified = result.desired_network
    current = {scope.shared_network: verified}
    assert plan(intent, scope, current=current, verified=verified).commands == ()
    restored = plan(decode(native["edit"], scope), scope, current=current, verified=verified)
    assert restored.desired_network == old
    assert restored.commands[0]["op"] == "delete"


def test_reservations_are_normalized_and_ordered_by_mac(native, scope):
    document = native["reservation"]
    entries = document["udapi"]["services"]["dhcpServers"][1]["staticLeases"]
    entries.extend([
        {"id": "02:BA:00:00:00:01", "addresses": ["192.0.2.43"]},
        {"id": "02:00:00:00:00:02", "addresses": ["192.0.2.41"]},
    ])
    first = plan(decode(document, scope), scope, current={}, verified=None)
    entries.reverse()
    assert plan(decode(document, scope), scope, current={}, verified=None) == first
    mappings = first.desired_network["subnet"]["192.0.2.0/24"]["static-mapping"]
    assert list(mappings) == ["unifi-020000000002", "unifi-020000000042", "unifi-02ba00000001"]
    assert mappings["unifi-02ba00000001"]["mac"] == "02:ba:00:00:00:01"


@pytest.mark.parametrize("record", [
    {"id": "01:00:00:00:00:43", "addresses": ["192.0.2.43"]},
    {"id": "00:00:00:00:00:00", "addresses": ["192.0.2.43"]},
    {"id": "02-00-00-00-00-43", "addresses": ["192.0.2.43"]},
    {"id": "02:00:00:00:00:42", "addresses": ["192.0.2.43"]},
    {"id": "02:00:00:00:00:43", "addresses": ["192.0.2.42"]},
    {"id": "02:00:00:00:00:43", "addresses": ["192.0.2.101"]},
    {"id": "02:00:00:00:00:43", "addresses": ["192.0.2.151"]},
    {"id": "02:00:00:00:00:43", "addresses": ["192.0.2.1"]},
    {"id": "02:00:00:00:00:43", "addresses": ["192.0.2.255"]},
    {"id": "02:00:00:00:00:43", "addresses": ["198.51.100.2"]},
    {"id": "02:00:00:00:00:43", "addresses": ["2001:db8::1"]},
    {"id": "02:00:00:00:00:43", "addresses": ["192.0.2.43", "192.0.2.44"]},
    {"id": "02:00:00:00:00:43", "addresses": ["192.0.2.43"], "name": "unknown-shape"},
])
def test_reject_invalid_or_conflicting_native_reservation(native, scope, record):
    document = native["reservation"]
    document["udapi"]["services"]["dhcpServers"][1]["staticLeases"].append(record)
    with pytest.raises(DhcpIntentError):
        decode(document, scope)


def test_bound_native_reservation_count(native, scope):
    document = native["reservation"]
    document["udapi"]["services"]["dhcpServers"][1]["staticLeases"] = [
        {"id": f"02:00:00:00:00:{value:02x}", "addresses": [f"192.0.2.{value}"]}
        for value in range(2, 35)
    ]
    with pytest.raises(DhcpIntentError, match="32"):
        decode(document, scope)


@pytest.mark.parametrize(("other_prefix", "other_ip", "overlaps"), [
    ("203.0.113.0/24", "203.0.113.42", False),
    ("192.0.2.0/25", "192.0.2.42", True),
])
def test_shared_network_reservation_collision_follows_subnet_scope(native, scope, other_prefix, other_ip, overlaps):
    intent = decode(native["reservation"], scope)
    current = {"operator": {"subnet": {other_prefix: {
        "subnet-id": "12", "static-mapping": {"client": {"mac": "02:00:00:00:00:42", "ip-address": other_ip}},
    }}}}
    if overlaps:
        with pytest.raises(DhcpIntentError, match="conflicts"):
            plan(intent, scope, current=current, verified=None)
    else:
        result = plan(intent, scope, current=current, verified=None)
        assert all(cmd["path"][3] == scope.shared_network for cmd in result.commands)


@pytest.mark.parametrize("mapping", [
    {"operator-name": {"mac": "02:00:00:00:00:42", "ip-address": "192.0.2.42"}},
    {"unifi-020000000042": {"mac": "02:00:00:00:00:42", "ip-address": "192.0.2.101"}},
    {"unifi-020000000042": {"duid": "00:01", "ip-address": "192.0.2.42"}},
])
def test_malformed_verified_reservation_tree_cannot_be_replaced(native, scope, mapping):
    old = plan(decode(native["edit"], scope), scope, current={}, verified=None).desired_network
    old["subnet"]["192.0.2.0/24"]["static-mapping"] = mapping
    with pytest.raises(DhcpIntentError, match="Verified"):
        plan(decode(native["delete"], scope), scope, current={scope.shared_network: old}, verified=old)


@pytest.mark.parametrize("change", [
    {"ipVersion": "v6"},
    {"enabled": False},
    {"rangeStart": "192.0.2.151"},
    {"rangeStart": "192.0.2.0"},
    {"rangeStop": "192.0.2.255"},
    {"rangeStart": "192.0.3.100"},
    {"rangeStart": "192.0.2.1"},
    {"gatewayAddress": "192.0.2.2"},
    {"ipv4Netmask": 25},
    {"leaseTime": True},
    {"leaseTime": 0},
    {"dnsServers": []},
    {"dnsServers": ["239.1.2.3"]},
    {"interfaces": [{"id": "br110"}, {"id": "br0"}]},
    {"relay": {"servers": ["192.0.2.2"]}},
    {"staticLeases": None},
])
def test_reject_unsupported_or_invalid_managed_server(native, scope, change):
    document = native["create"]
    document["udapi"]["services"]["dhcpServers"][1].update(change)
    with pytest.raises(DhcpIntentError):
        decode(document, scope)


@pytest.mark.parametrize("mutation", ["missing-section", "duplicate-interface", "duplicate-server",
                                      "wrong-interface", "wrong-schema", "no-address"])
def test_reject_incomplete_or_ambiguous_snapshots(native, scope, mutation):
    document = native["create"]
    udapi = document["udapi"]
    if mutation == "missing-section":
        udapi["services"].pop("dhcpServers")
    elif mutation == "duplicate-interface":
        udapi["interfaces"].append(deepcopy(udapi["interfaces"][0]))
    elif mutation == "duplicate-server":
        udapi["services"]["dhcpServers"].append(deepcopy(udapi["services"]["dhcpServers"][1]))
    elif mutation == "wrong-interface":
        udapi["interfaces"][0]["bridge"]["id"] = 111
    elif mutation == "wrong-schema":
        udapi["versionDetail"]["services/dhcpServers"] = 1
    else:
        udapi["interfaces"][0]["addresses"].clear()

    with pytest.raises(DhcpIntentError):
        decode(document, scope)


def test_reject_duplicate_json_field(native, scope):
    document = native["create"]
    duplicated = json.dumps(document).replace('"leaseTime": 3600', '"leaseTime": 0, "leaseTime": 3600')
    with pytest.raises(DhcpIntentError):
        decode_dhcp_intent(duplicated, revision="redacted-revision", scope=scope)


@pytest.mark.parametrize("current", [
    {"unifi-vlan110": {"subnet": {"192.0.2.0/24": {"subnet-id": "110"}}}},
    {"operator": {"subnet": {"203.0.113.0/24": {"subnet-id": "110"}}}},
    {"operator": {"subnet": {"192.0.2.0/25": {"subnet-id": "12"}}}},
    {"operator": {"subnet": {"203.0.113.0/24": {"subnet-id": "unknown"}}}},
])
def test_reject_unsafe_operator_ownership_snapshot(native, scope, current):
    document = native["create"]
    with pytest.raises(DhcpIntentError):
        plan(decode(document, scope), scope, current=current, verified=None)


def test_reject_owned_tree_drift_and_wrong_live_interface(native, scope):
    document = native["create"]
    intent = decode(document, scope)
    prior = plan(intent, scope, current={}, verified=None).desired_network
    modified = deepcopy(prior)
    modified["subnet"]["192.0.2.0/24"]["lease"] = "86400"
    with pytest.raises(DhcpIntentError, match="verified"):
        plan(intent, scope, current={scope.shared_network: modified}, verified=prior)
    with pytest.raises(DhcpIntentError, match="interface"):
        plan(intent, scope, current={}, verified=None, addresses={"eth3.120": ["192.0.2.1/24"]})


def test_unknown_nodes_are_outside_verified_ownership(native, scope):
    old = plan(decode(native["create"], scope), scope, current={}, verified=None).desired_network
    old["subnet"]["192.0.2.0/24"]["option"]["time-server"] = "192.0.2.2"

    with pytest.raises(DhcpIntentError, match="Verified"):
        plan(decode(native["delete"], scope), scope, current={scope.shared_network: old}, verified=old)
