"""Exercise native route intent against captured wire and FRR shapes."""

from copy import deepcopy
from ipaddress import IPv4Address, IPv4Network
import json
from pathlib import Path

import pytest

from provisioners.vyos_routes import (
    RouteIntentError,
    StaticRouteScope,
    decode_route_intent,
    plan_route_commands,
    verify_route_forwarding,
)


DESTINATION = "203.0.113.20/32"
ROUTE_PATH = ["protocols", "static", "route", DESTINATION]
DESCRIPTION = "STATIC_ROUTE:11111111-1111-4111-8111-000000000001"


@pytest.fixture
def native():
    path = Path(__file__).parent / "fixtures" / "uxg_pro" / "native-static-route-snapshots.json"
    seed = json.loads(path.read_text())
    version = {key: seed[key] for key in ("version", "versionFormat", "versionDetail")}
    return {stage: {"udapi": {**deepcopy(version), "routes/static": routes}}
            for stage, routes in seed["routes"].items()}


@pytest.fixture
def scope():
    return StaticRouteScope((DESTINATION,), {"192.0.2.2": "eth3.210", "198.51.100.2": "eth3.220"})


def _connected(interface):
    return {
        "protocol": "connected", "selected": True, "installed": True, "table": 254,
        "nexthops": [{"fib": True, "active": True, "directlyConnected": True, "interfaceName": interface}],
    }


@pytest.fixture
def route_table():
    return {"192.0.2.0/30": [_connected("eth3.210")], "198.51.100.0/30": [_connected("eth3.220")]}


def _decode(document, scope):
    return decode_route_intent(json.dumps(document), revision="observed-revision", scope=scope)


def _plan(document, scope, table, *, current=None, verified=None):
    return plan_route_commands(
        _decode(document, scope), scope=scope, connected_routes=table,
        current_routes={} if current is None else current,
        verified_routes={} if verified is None else verified,
    )


def test_native_route_create_keeps_operator_route_and_pins_next_hop(native, scope, route_table):
    intent = _decode(native["create"], scope)
    assert intent.revision == "observed-revision"
    assert intent.routes[0].destination == IPv4Network(DESTINATION)
    assert intent.routes[0].gateway == IPv4Address("192.0.2.2")
    operator = {"0.0.0.0/0": {"next-hop": {"192.0.2.2": {}}}}
    result = _plan(native["create"], scope, route_table, current=operator)

    assert result.desired_routes == {
        DESTINATION: {"description": DESCRIPTION, "next-hop": {"192.0.2.2": {"distance": "10", "interface": "eth3.210"}}}
    }
    assert result.commands == (
        {"op": "set", "path": ROUTE_PATH + ["description"], "value": DESCRIPTION},
        {"op": "set", "path": ROUTE_PATH + ["next-hop", "192.0.2.2", "distance"], "value": "10"},
        {"op": "set", "path": ROUTE_PATH + ["next-hop", "192.0.2.2", "interface"], "value": "eth3.210"},
    )
    assert operator == {"0.0.0.0/0": {"next-hop": {"192.0.2.2": {}}}}


def test_native_edit_replaces_owned_gateway_without_ecmp(native, scope, route_table):
    previous = _plan(native["create"], scope, route_table).desired_routes
    plan = _plan(native["edit"], scope, route_table, current=previous, verified=previous)

    assert plan.commands[0] == {"op": "delete", "path": ROUTE_PATH}
    assert plan.commands[-2:] == (
        {"op": "set", "path": ROUTE_PATH + ["next-hop", "198.51.100.2", "distance"], "value": "15"},
        {"op": "set", "path": ROUTE_PATH + ["next-hop", "198.51.100.2", "interface"], "value": "eth3.220"},
    )
    assert set(plan.desired_routes[DESTINATION]["next-hop"]) == {"198.51.100.2"}


def test_native_delete_removes_only_the_verified_route(native, scope, route_table):
    previous = _plan(native["create"], scope, route_table).desired_routes
    current = {**previous, "203.0.113.40/32": {"blackhole": {}}}
    plan = _plan(native["delete"], scope, {}, current=current, verified=previous)

    assert plan.desired_routes == {}
    assert plan.commands == ({"op": "delete", "path": ROUTE_PATH},)


def test_native_blackhole_can_replace_and_withdraw_an_owned_gateway_route(native, scope, route_table):
    previous = _plan(native["create"], scope, route_table).desired_routes
    row = native["create"]["udapi"]["routes/static"][0]
    row.pop("gateway")
    row.update(type="blackhole", distance=5)
    plan = _plan(native["create"], scope, route_table, current=previous, verified=previous)

    assert plan.desired_routes == {DESTINATION: {"description": DESCRIPTION, "blackhole": {"distance": "5"}}}
    assert plan.commands == (
        {"op": "delete", "path": ROUTE_PATH},
        {"op": "set", "path": ROUTE_PATH + ["description"], "value": DESCRIPTION},
        {"op": "set", "path": ROUTE_PATH + ["blackhole", "distance"], "value": "5"},
    )
    assert _plan(native["delete"], scope, {}, current=plan.desired_routes, verified=plan.desired_routes).commands == (
        {"op": "delete", "path": ROUTE_PATH},
    )
    row["gateway"] = "192.0.2.2"
    with pytest.raises(RouteIntentError):
        _decode(native["create"], scope)


def test_interface_route_replaces_gateway_and_verifies_direct_l2_egress(native, scope, route_table):
    scope = StaticRouteScope(scope.destinations, scope.next_hops, {"br220": "eth3.220"})
    previous = _plan(native["create"], scope, route_table).desired_routes
    row = native["create"]["udapi"]["routes/static"][0]
    row.pop("gateway")
    row.update(type="interface", interface="br220", distance=5)

    plan = _plan(native["create"], scope, route_table, current=previous, verified=previous)

    assert plan.desired_routes == {
        DESTINATION: {"description": DESCRIPTION, "interface": {"eth3.220": {"distance": "5"}}},
    }
    assert plan.commands == (
        {"op": "delete", "path": ROUTE_PATH},
        {"op": "set", "path": ROUTE_PATH + ["description"], "value": DESCRIPTION},
        {"op": "set", "path": ROUTE_PATH + ["interface", "eth3.220", "distance"], "value": "5"},
    )
    direct = {**_connected("eth3.220"), "protocol": "static", "distance": 5}
    verify_route_forwarding({**route_table, DESTINATION: [direct]}, plan.desired_routes, set())
    direct["nexthops"][0]["ip"] = "198.51.100.2"
    with pytest.raises(RouteIntentError, match="no verified installed interface"):
        verify_route_forwarding({**route_table, DESTINATION: [direct]}, plan.desired_routes, set())
    withdrawal = _plan(native["delete"], scope, route_table, current=plan.desired_routes, verified=plan.desired_routes)
    assert withdrawal.commands == ({"op": "delete", "path": ROUTE_PATH},)

    row["interface"] = "br210"
    with pytest.raises(RouteIntentError, match="approved interface"):
        _decode(native["create"], scope)
    row.update(interface="br220", table=201)
    with pytest.raises(RouteIntentError, match="Unsupported static route"):
        _decode(native["create"], scope)


def test_ipv6_gateway_route_keeps_its_family_and_requires_the_pinned_connected_next_hop(native):
    destination = "2001:db8:300::20/128"
    gateway = "2001:db8:220::2"
    scope = StaticRouteScope((destination,), {gateway: "eth3.220"})
    document = native["create"]
    document["udapi"]["routes/static"][0].update(
        destination="2001:0DB8:0300:0000:0000:0000:0000:0020/128",
        gateway="2001:0DB8:0220:0000:0000:0000:0000:0002",
    )
    table = {"2001:db8:220::/64": [_connected("eth3.220")]}

    plan = _plan(document, scope, table)

    assert plan.commands == (
        {"op": "set", "path": ["protocols", "static", "route6", destination, "description"], "value": DESCRIPTION},
        {"op": "set", "path": ["protocols", "static", "route6", destination, "next-hop", gateway, "distance"],
         "value": "10"},
        {"op": "set", "path": ["protocols", "static", "route6", destination, "next-hop", gateway, "interface"],
         "value": "eth3.220"},
    )
    with pytest.raises(RouteIntentError, match="directly connected route"):
        _plan(document, scope, {"2001:db8:220::/64": [_connected("eth3.210")]})
    document["udapi"]["routes/static"][0]["gateway"] = "192.0.2.2"
    with pytest.raises(RouteIntentError, match="same address family"):
        _decode(document, scope)


@pytest.mark.parametrize("interface", ["eth3.220", "eth3"])
def test_ipv6_link_local_gateway_requires_the_native_interface_and_matching_pin(native, interface):
    destination = "2001:db8:300::20/128"
    scope = StaticRouteScope((destination,), {f"fe80::17%{interface}": interface}, {"br220": interface})
    document = native["create"]
    row = document["udapi"]["routes/static"][0]
    row.update(destination=destination, gateway="fe80::17", interface="br220")
    local_on_wan = _connected(interface)
    local_on_wan.pop("selected")
    table = {"fe80::/64": [_connected("lo"), local_on_wan]}

    plan = _plan(document, scope, table)

    assert plan.desired_routes[destination]["next-hop"] == {
        "fe80::17": {"distance": "10", "interface": interface},
    }
    with pytest.raises(RouteIntentError, match="no active connected route"):
        _plan(document, scope, {"2001:db8:220::/64": [_connected(interface)]})
    row.pop("interface")
    with pytest.raises(RouteIntentError, match="link-local gateway needs an approved interface"):
        _decode(document, scope)
    row["interface"] = "br210"
    with pytest.raises(RouteIntentError, match="approved interface"):
        _decode(document, scope)


def test_forwarding_readback_rejects_a_more_specific_route_that_appears_after_staging():
    aggregate = "203.0.113.0/24"
    desired = {aggregate: {"description": DESCRIPTION, "blackhole": {"distance": "1"}}}
    table = {aggregate: [{
        "protocol": "static", "table": 254, "selected": True, "installed": True, "distance": 1,
        "nexthops": [{"active": True, "fib": True, "blackhole": True}],
    }]}
    verify_route_forwarding(table, desired, set())
    table[DESTINATION] = [_connected("eth3.110")]
    with pytest.raises(RouteIntentError, match="overlaps an unverified installed route"):
        verify_route_forwarding(table, desired, set())


def test_equal_live_and_verified_route_has_no_commands(native, scope, route_table):
    known = _plan(native["create"], scope, route_table).desired_routes
    route_table[DESTINATION] = [{
        "protocol": "static", "selected": True, "installed": True, "table": 254, "distance": 10,
        "nexthops": [{"fib": True, "active": True, "interfaceName": "eth3.210", "ip": "192.0.2.2"}],
    }]

    assert _plan(native["create"], scope, route_table, current=known, verified=known).commands == ()


@pytest.mark.parametrize("patch", [
    {"enabled": False}, {"enabled": 1}, {"type": "interface"}, {"distance": "10"}, {"distance": 256},
    {"destination": "0.0.0.0/0"}, {"destination": "203.0.113.21/32"},
    {"destination": "203.0.113.20"}, {"gateway": "192.0.2.3"},
    {"description": "user supplied string"}, {"interface": "eth3.210"}, {"bfd": True},
])
def test_reject_unsupported_or_unapproved_route(native, scope, patch):
    native["create"]["udapi"]["routes/static"][0].update(patch)

    with pytest.raises(RouteIntentError):
        _decode(native["create"], scope)


def test_missing_route_list_cannot_delete_verified_routes(native, scope):
    native["delete"]["udapi"].pop("routes/static")

    with pytest.raises(RouteIntentError):
        _decode(native["delete"], scope)


def test_distance_255_keeps_route_configuration_without_installed_forwarding(native, scope):
    native["create"]["udapi"]["routes/static"][0]["distance"] = 255
    plan = _plan(native["create"], scope, {})
    assert plan.desired_routes[DESTINATION]["next-hop"]["192.0.2.2"]["distance"] == "255"
    verify_route_forwarding({}, plan.desired_routes, set())
    static = {"protocol": "static", "table": 254, "selected": True, "installed": True}
    with pytest.raises(RouteIntentError, match="distance 255"):
        verify_route_forwarding({DESTINATION: [static]}, plan.desired_routes, set())


@pytest.mark.parametrize(("tag", "opted_in", "is_supported"), [
    (None, False, True), (3, True, True), (3, False, False), (None, True, False), (2, True, False),
])
def test_message_broker_version_tag_requires_explicit_opt_in(native, scope, tag, opted_in, is_supported):
    document = native["create"]
    if tag is not None:
        document["udapi"]["versionDetail"]["services/messageBroker"] = tag

    def decode():
        return decode_route_intent(
            json.dumps(document), revision="observed-revision", scope=scope, message_broker=opted_in,
        )

    if is_supported:
        assert decode().routes[0].destination == IPv4Network(DESTINATION)
    else:
        with pytest.raises(RouteIntentError, match="schema"):
            decode()


def test_duplicate_destinations_cannot_create_ecmp(native, scope):
    routes = native["create"]["udapi"]["routes/static"]
    routes.append({**routes[0], "gateway": "198.51.100.2", "description": DESCRIPTION[:-1] + "2"})

    with pytest.raises(RouteIntentError):
        _decode(native["create"], scope)


def _gateway_alternative(gateway, interface, distance, *, preferred=False, active=True):
    return {
        "protocol": "static", "table": 254, "distance": distance, "metric": 0,
        "selected": preferred, "installed": preferred,
        "nexthops": [{"ip": gateway, "interfaceName": interface, "active": active, "fib": preferred}],
    }


def test_same_prefix_gateway_preferences_keep_both_paths_and_verify_failover(native, scope, route_table):
    document = native["create"]
    rows = document["udapi"]["routes/static"]
    rows.append({**rows[0], "gateway": "198.51.100.2", "distance": 15, "description": DESCRIPTION[:-1] + "2"})
    primary = _gateway_alternative("192.0.2.2", "eth3.210", 10, preferred=True)
    standby = _gateway_alternative("198.51.100.2", "eth3.220", 15)

    plan = _plan(document, scope, route_table)

    assert plan.desired_routes[DESTINATION] == {"description": DESCRIPTION, "next-hop": {
        "192.0.2.2": {"distance": "10", "interface": "eth3.210"},
        "198.51.100.2": {"distance": "15", "interface": "eth3.220"},
    }}
    rows.reverse()
    assert _plan(document, scope, route_table) == plan
    verify_route_forwarding({**route_table, DESTINATION: [primary, standby]}, plan.desired_routes, set())
    owned = plan.desired_routes
    active_backup = _gateway_alternative("198.51.100.2", "eth3.220", 15, preferred=True)
    ready_primary = _gateway_alternative("192.0.2.2", "eth3.210", 10)
    with pytest.raises(RouteIntentError):
        verify_route_forwarding({**route_table, DESTINATION: [ready_primary, active_backup]}, owned, set())

    degraded = {"198.51.100.0/30": route_table["198.51.100.0/30"], DESTINATION: [active_backup]}
    assert _plan(document, scope, degraded, current=owned, verified=owned).commands == ()
    verify_route_forwarding(degraded, owned, set())

    rows.pop()
    updated = _plan(document, scope, route_table, current=owned, verified=owned).desired_routes
    verify_route_forwarding({**route_table, DESTINATION: [active_backup]}, updated, set())
    with pytest.raises(RouteIntentError):
        verify_route_forwarding({**route_table, DESTINATION: [ready_primary, active_backup]}, updated, set())


def test_distance_255_candidate_can_remain_in_frr_without_becoming_preferred(native, scope, route_table):
    document = native["create"]
    rows = document["udapi"]["routes/static"]
    rows.append({**rows[0], "gateway": "198.51.100.2", "distance": 255, "description": DESCRIPTION[:-1] + "2"})
    desired = _plan(document, scope, route_table).desired_routes
    live = _gateway_alternative("192.0.2.2", "eth3.210", 10, preferred=True)
    inactive = _gateway_alternative("198.51.100.2", "eth3.220", 255)
    inactive["nexthops"][0]["fib"] = True
    verify_route_forwarding({**route_table, DESTINATION: [inactive, live]}, desired, set())
    inactive.update(selected=True, installed=True)
    with pytest.raises(RouteIntentError, match="unverified FRR candidate"):
        verify_route_forwarding({**route_table, DESTINATION: [inactive, live]}, desired, set())


def test_preferred_interface_requires_independent_link_state_before_using_either_path(native, scope, route_table):
    scope = StaticRouteScope(scope.destinations, scope.next_hops, {"br210": "eth3.210"})
    document = native["create"]
    rows = document["udapi"]["routes/static"]
    rows[0].pop("gateway")
    rows[0].update(type="interface", interface="br210", distance=5)
    rows.append({**rows[0], "type": "blackhole", "distance": 20, "description": DESCRIPTION[:-1] + "2"})
    rows[-1].pop("interface")
    desired = _plan(document, scope, route_table).desired_routes
    operational = {DESTINATION: [{"protocol": "static", "table": 254, "selected": True, "installed": True,
                                  "distance": 20, "nexthops": [{"active": True, "fib": True, "blackhole": True}]}]}

    with pytest.raises(RouteIntentError, match="inconsistent candidate state at distance 5"):
        verify_route_forwarding(operational, desired, set(),
                                read_interfaces=lambda: {"lo": (["UP"], ""), "eth3.210": (["UP", "LOWER_UP"], "")})
    verify_route_forwarding(operational, desired, set(),
                            read_interfaces=lambda: {"lo": (["UP"], ""), "eth3.210": (["UP"], "")})
    standby = {**operational[DESTINATION][0], "selected": False, "installed": False}
    stale = {"protocol": "static", "table": 254, "selected": True, "installed": True, "distance": 5,
             "nexthops": [{"active": True, "fib": True, "directlyConnected": True, "interfaceName": "eth3.210"}]}
    with pytest.raises(RouteIntentError, match="inconsistent candidate state at distance 5"):
        verify_route_forwarding({DESTINATION: [stale, standby]}, desired, set(),
                                read_interfaces=lambda: {"lo": (["UP"], ""), "eth3.210": (["UP"], "")})
    with pytest.raises(RouteIntentError, match="no verified link state for eth3.210"):
        verify_route_forwarding(operational, desired, set(), read_interfaces=lambda: {"lo": (["UP"], "")})


def test_withdrawing_live_standby_can_leave_a_verified_offline_primary(native, scope, route_table):
    document = native["create"]
    rows = document["udapi"]["routes/static"]
    backup = {**rows[0], "gateway": "198.51.100.2", "distance": 15, "description": DESCRIPTION[:-1] + "2"}
    rows.append(backup)
    previous = _plan(document, scope, route_table).desired_routes
    rows.pop()
    standby = _gateway_alternative("198.51.100.2", "eth3.220", 15, preferred=True)
    down_rib = {"198.51.100.0/30": route_table["198.51.100.0/30"]}
    plan = _plan(document, scope, {**down_rib, DESTINATION: [standby]}, current=previous, verified=previous)

    def links():
        return {"lo": (["UP"], ""), "eth3.210": (["UP"], ""), "eth3.220": (["UP", "LOWER_UP"], "")}

    verify_route_forwarding(down_rib, plan.desired_routes, set(), read_interfaces=links, previous_static=previous)
    with pytest.raises(RouteIntentError):
        verify_route_forwarding({**down_rib, DESTINATION: [standby]}, plan.desired_routes, set(),
                                read_interfaces=links, previous_static=previous)
    with pytest.raises(RouteIntentError):
        verify_route_forwarding(down_rib, plan.desired_routes, set(), read_interfaces=links)


def test_two_rows_cannot_share_a_vyos_next_hop_key(native, scope):
    rows = native["create"]["udapi"]["routes/static"]
    rows.append({**rows[0], "distance": 15, "description": DESCRIPTION[:-1] + "2"})

    with pytest.raises(RouteIntentError):
        _decode(native["create"], scope)


def test_scope_rejects_duplicate_destinations():
    with pytest.raises(RouteIntentError):
        StaticRouteScope((DESTINATION, DESTINATION), {"192.0.2.2": "eth3.210"})


def test_can_add_edit_and_withdraw_an_explicit_more_specific_route(native, route_table):
    aggregate = "203.0.113.0/24"
    scope = StaticRouteScope((aggregate, DESTINATION), {"192.0.2.2": "eth3.210", "198.51.100.2": "eth3.220"})
    document = native["create"]
    host = deepcopy(document["udapi"]["routes/static"][0])
    parent = {**host, "destination": aggregate, "description": DESCRIPTION[:-1] + "2"}
    document["udapi"]["routes/static"] = [parent]
    known = _plan(document, scope, route_table).desired_routes
    route_table[aggregate] = [{
        "protocol": "static", "selected": True, "installed": True, "table": 254, "distance": 10,
        "nexthops": [{"fib": True, "active": True, "interfaceName": "eth3.210", "ip": "192.0.2.2"}],
    }]
    host.update(gateway="198.51.100.2", distance=254)
    document["udapi"]["routes/static"].append(host)
    add = _plan(document, scope, route_table, current=known, verified=known)
    assert add.desired_routes[aggregate] == known[aggregate]
    assert add.commands[-2:] == (
        {"op": "set", "path": ROUTE_PATH + ["next-hop", "198.51.100.2", "distance"], "value": "254"},
        {"op": "set", "path": ROUTE_PATH + ["next-hop", "198.51.100.2", "interface"], "value": "eth3.220"},
    )
    route_table[DESTINATION] = [{
        "protocol": "static", "selected": True, "installed": True, "table": 254, "distance": 254,
        "nexthops": [{"fib": True, "active": True, "interfaceName": "eth3.220", "ip": "198.51.100.2"}],
    }]
    document["udapi"]["routes/static"] = [parent]
    delete = _plan(document, scope, route_table, current=add.desired_routes, verified=add.desired_routes)
    assert delete.commands == ({"op": "delete", "path": ROUTE_PATH},)
    assert delete.desired_routes == known

    route_table[DESTINATION][0]["distance"] = 15
    with pytest.raises(RouteIntentError, match="unverified installed route"):
        _plan(document, scope, route_table, current=add.desired_routes, verified=add.desired_routes)


@pytest.mark.parametrize("current", [
    {DESTINATION: {"description": DESCRIPTION, "next-hop": {"192.0.2.2": {"distance": "10", "interface": "eth3.210"}}}},
    {"203.0.113.0/24": {"blackhole": {}}},
])
def test_refuses_unverified_existing_or_overlapping_operator_route(native, scope, route_table, current):
    with pytest.raises(RouteIntentError):
        _plan(native["create"], scope, route_table, current=current)


def test_refuses_modified_owned_vyos_subtree(native, scope, route_table):
    known = _plan(native["create"], scope, route_table).desired_routes
    drifted = deepcopy(known)
    drifted[DESTINATION]["next-hop"]["192.0.2.2"]["bfd"] = {}

    with pytest.raises(RouteIntentError):
        _plan(native["delete"], scope, route_table, current=drifted, verified=known)


@pytest.mark.parametrize("mutate", [
    lambda route: route.update(selected=False),
    lambda route: route.update(installed=False),
    lambda route: route.update(table=100),
    lambda route: route.update(protocol="static"),
    lambda route: route["nexthops"][0].update(fib=False),
    lambda route: route["nexthops"][0].update(interfaceName="eth3.220"),
])
def test_gateway_requires_live_selected_connected_egress(native, scope, route_table, mutate):
    mutate(route_table["192.0.2.0/30"][0])

    with pytest.raises(RouteIntentError):
        _plan(native["create"], scope, route_table)


def test_more_specific_route_cannot_shadow_gateway_reachability(native, scope, route_table):
    route_table["192.0.2.2/32"] = [_connected("eth3.220")]

    with pytest.raises(RouteIntentError):
        _plan(native["create"], scope, route_table)
