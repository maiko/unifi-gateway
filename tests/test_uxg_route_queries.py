"""Wire contract for Network's live Routing Table and OSPF Neighbors queries."""

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from backends.vyos import VyOSBackend, VyOSReadError
from gateway_profiles import uxg_route_queries
from gateway_profiles.uxg_route_queries import (
    ROUTE_QUERY_CAPABILITY,
    RouteQueryError,
    build_route_query_notification,
    decode_route_query,
    project_installed_routes,
    project_ospf_neighbors,
    project_ospf_routes,
)
from provisioners.vyos_ospf import OspfScope
from unifi_gateway import UnifiGateway


_REQUEST_ID = "12345678-90ab-4def-8123-4567890abcde"
_ROUTES = {"id": "get-routes", "method": "GET", "endpoint": "/routes"}
_NEIGHBORS = {"id": "get-ospf-neighbors", "method": "GET", "endpoint": "/routes/ospf", "filter": ["neighbors"]}
_OSPF_SCOPE = OspfScope("198.19.120.1", "br120", "eth3.120", "192.168.120.1/24")
_PREFIX = "198.19.120.42/32"
_NEIGHBOR_ID = "198.19.120.42"
_FRR_ROUTE = {
    "protocol": "ospf", "selected": True, "destSelected": True, "installed": True,
    "distance": 110, "metric": 1, "prefix": _PREFIX, "prefixLen": 32,
    "table": 254, "vrfId": 0, "vrfName": "default",
    "nexthops": [{
        "fib": True, "active": True, "ip": "192.168.120.2", "afi": "ipv4", "interfaceName": "eth3.120", "weight": 1,
    }],
}
_FRR_NEIGHBOR = {
    "ifaceAddress": "192.168.120.2", "ifaceName": "eth3.120:192.168.120.1",
    "converged": "Full", "nbrPriority": 1, "nbrState": "Full/Backup", "role": "Backup",
    "routerDeadIntervalTimerDueMsec": 30840,
}


def _command(*blocks):
    return {"_type": "cmd", "cmd": "get-udapi-blocks", "request_id": _REQUEST_ID, "udapi_blocks": list(blocks)}


@pytest.mark.parametrize(
    ("block", "list_key", "row"),
    [
        (_ROUTES, "items", {"destination": "198.19.120.240/32", "origin": "OSPF"}),
        (_NEIGHBORS, "neighbors", {"neighborID": "198.19.120.2", "state": "Full"}),
    ],
)
def test_replies_to_each_controller_query_in_a_command_notification(block, list_key, row):
    query = decode_route_query(_command(block))

    assert ROUTE_QUERY_CAPABILITY == 0x800000
    assert query.request_id == _REQUEST_ID
    assert query.block_id == block["id"]
    assert build_route_query_notification(query, [row]) == {
        "inform_as_notif": True,
        "notif_reason": "cmd",
        "notif_payload": {
            "event_string": "get-udapi-blocks",
            "request_id": _REQUEST_ID,
            "udapi_blocks": {block["id"]: {list_key: [row]}},
        },
    }


@pytest.mark.parametrize(
    "command",
    [
        None,
        _command(),
        _command(_ROUTES, _NEIGHBORS),
        _command(_ROUTES, _ROUTES),
        _command({**_ROUTES, "method": "POST"}),
        _command({**_ROUTES, "endpoint": "/routes?debug=true"}),
        _command({**_ROUTES, "payload": {}}),
        _command({**_ROUTES, "filter": []}),
        _command({**_NEIGHBORS, "filter": ["neighbors", "other"]}),
        _command({**_NEIGHBORS, "filter": "neighbors"}),
        _command({**_NEIGHBORS, "id": "get-routes"}),
        _command({**_NEIGHBORS, "endpoint": "/routes/../interfaces"}),
        {**_command(_ROUTES), "udapi_blocks": {"get-routes": _ROUTES}},
        {**_command(_ROUTES), "request_id": _REQUEST_ID.upper()},
        {**_command(_ROUTES), "request_id": "not-a-controller-request-id"},
        {**_command(_ROUTES), "cmd": "get-routes"},
        {**_command(_ROUTES), "_type": "setparam"},
        {**_command(_ROUTES), "payload": {}},
    ],
)
def test_rejects_requests_outside_the_two_controller_read_operations(command):
    with pytest.raises(RouteQueryError):
        decode_route_query(command)


def test_controller_task_and_inform_metadata_cannot_change_the_query():
    response = {
        **_command(_ROUTES),
        "_id": "0123456789abcdef01234567",
        "device_id": "0123456789abcdef01234568",
        "datetime": 1795537800000,
        "time": 1795537800,
        "server_time_in_utc": "1795537800000",
    }

    query = decode_route_query(response)

    assert query == decode_route_query(_command(_ROUTES))
    assert set(build_route_query_notification(query, [])["notif_payload"]) == {
        "event_string", "request_id", "udapi_blocks",
    }


def test_a_valid_empty_result_completes_the_query():
    query = decode_route_query(_command(_NEIGHBORS))

    assert build_route_query_notification(query, [])["notif_payload"]["udapi_blocks"] == {
        "get-ospf-neighbors": {"neighbors": []},
    }


def test_notification_does_not_share_route_rows_with_the_caller():
    query = decode_route_query(_command(_ROUTES))
    rows = [{"destination": "198.19.120.240/32", "nexthops": [{"interface": "br120"}]}]
    original = deepcopy(rows)

    notification = build_route_query_notification(query, rows)
    rows[0]["nexthops"].clear()

    assert notification["notif_payload"]["udapi_blocks"]["get-routes"]["items"] == original


def test_live_frr_ospf_kernel_route_projects_to_the_network_route_query():
    assert project_ospf_routes({_PREFIX: [_FRR_ROUTE]}, scope=_OSPF_SCOPE) == [
        {
            "description": "", "destination": _PREFIX, "distance": 110, "origin": "OSPF", "scope": 0,
            "table": 254, "type": "unicast",
            "nexthops": [{"gateway": "192.168.120.2", "inUse": True, "interface": "br120", "weight": 1}],
        }
    ]


@pytest.mark.parametrize("distance", [20, 200, 105])
def test_bgp_routing_view_uses_fib_distance_and_the_native_origin(distance):
    route = {**_FRR_ROUTE, "protocol": "bgp", "distance": distance}
    snapshot = {_PREFIX: [route, {**route, "selected": False, "installed": False}]}
    interfaces = {"eth3.120": "br120"}
    assert project_installed_routes(snapshot, version=4, interfaces=interfaces) == []
    assert project_installed_routes(snapshot, version=4, interfaces=interfaces, include_bgp=True) == [{
        "description": "", "destination": _PREFIX, "distance": distance, "origin": "BGP", "scope": 0,
        "table": 254, "type": "unicast",
        "nexthops": [{"gateway": "192.168.120.2", "interface": "br120", "inUse": True, "weight": 1}],
    }]


@pytest.mark.parametrize(("protocol", "afi"), [("bgp", "ipv6"), ("bgp", "ipv4"), ("static", "ipv6")])
def test_ipv4_routing_view_requires_a_bgp_ipv6_nexthop(protocol, afi):
    gateway = "fe80::1"
    hop = {**_FRR_ROUTE["nexthops"][0], "ip": gateway, "afi": afi}
    route = {**_FRR_ROUTE, "protocol": protocol, "nexthops": [hop]}
    snapshot = {_PREFIX: [route]}
    interfaces = {"eth3.120": "br120"}
    if (protocol, afi) != ("bgp", "ipv6"):
        with pytest.raises(RouteQueryError, match="inconsistent address family"):
            project_installed_routes(snapshot, version=4, interfaces=interfaces, include_bgp=True)
        return
    rows = project_installed_routes(snapshot, version=4, interfaces=interfaces, include_bgp=True)
    assert rows[0]["destination"] == _PREFIX
    assert rows[0]["nexthops"] == [{"gateway": gateway, "interface": "br120", "inUse": True, "weight": 1}]


@pytest.mark.parametrize("stale", ["uninstalled", "unmapped", "different_table"])
def test_bgp_routing_view_omits_unverified_paths(stale):
    route = {**_FRR_ROUTE, "protocol": "bgp", "distance": 20}
    if stale == "uninstalled":
        route["installed"] = False
    elif stale == "different_table":
        route["table"] = 80
    interfaces = {} if stale == "unmapped" else {"eth3.120": "br120"}
    assert project_installed_routes({_PREFIX: [route]}, version=4, interfaces=interfaces, include_bgp=True) == []


@pytest.mark.parametrize("family", [4, 6])
def test_native_routing_table_reply_reports_installed_bgp_on_enterprise(gateway_config, family):
    gateway_config.read_dict({"gateway": {
        "device": "UXGENT", "platform": "vyos", "url": "http://lab.example:8080/inform",
        "lan_mac": "02:78:91:00:12:03", "lan_ip": "192.0.2.1", "is_adopted": True, "ports": "[]",
    }})
    gateway = object.__new__(UnifiGateway)
    gateway.config = gateway_config
    gateway.vyos_provisioner = None
    prefix, gateway_ip, length = (_PREFIX, "192.168.120.2", 32) if family == 4 else ("2001:db8:99::/64", "fe80::2", 64)
    route = {**_FRR_ROUTE, "protocol": "bgp", "distance": 20, "prefix": prefix, "prefixLen": length,
             "nexthops": [{**_FRR_ROUTE["nexthops"][0], "afi": f"ipv{family}", "ip": gateway_ip}]}
    snapshot = {prefix: [route]}
    gateway.datacollector = SimpleNamespace(data={}, ports=[{"ifname": "br120", "realif": "eth3.120"}], backend=SimpleNamespace(
        show_ipv4_routes=lambda: snapshot if family == 4 else {}, show_ipv6_routes=lambda: snapshot if family == 6 else {},
        configured_static_route_tables=lambda: {},
    ))
    payloads = []

    def send(payload):
        payloads.append(json.loads(payload))
        return {}

    gateway._send_inform = send
    gateway._handle_cmd(_command(_ROUTES))
    items = payloads[0]["notif_payload"]["udapi_blocks"]["get-routes"]["items"]
    assert [row["origin"] for row in items] == ["BGP"]
    assert items[0]["destination"] == prefix
    assert items[0]["nexthops"][0]["gateway"] == gateway_ip


@pytest.mark.parametrize(
    "change",
    [
        {"protocol": "static"},
        {"selected": False},
        {"installed": False},
        {"table": 127},
        {"vrfName": "operator"},
        {"nexthops": [{**_FRR_ROUTE["nexthops"][0], "fib": False}]},
        {"nexthops": [{**_FRR_ROUTE["nexthops"][0], "interfaceName": "eth3.110"}]},
        {"nexthops": [*_FRR_ROUTE["nexthops"], {**_FRR_ROUTE["nexthops"][0], "ip": "192.168.120.3"}]},
    ],
)
def test_routes_withdrawn_or_outside_the_supported_fib_scope_are_omitted(change):
    assert project_ospf_routes({_PREFIX: [{**_FRR_ROUTE, **change}]}, scope=_OSPF_SCOPE) == []


def test_route_projection_rejects_an_inconsistent_owned_prefix_or_gateway():
    with pytest.raises(RouteQueryError):
        project_ospf_routes({_PREFIX: [{**_FRR_ROUTE, "prefixLen": 24}]}, scope=_OSPF_SCOPE)
    with pytest.raises(RouteQueryError):
        off_link = {**_FRR_ROUTE["nexthops"][0], "ip": "192.168.110.2"}
        project_ospf_routes({_PREFIX: [{**_FRR_ROUTE, "nexthops": [off_link]}]}, scope=_OSPF_SCOPE)
    with pytest.raises(RouteQueryError, match="multiple installed candidates"):
        project_ospf_routes({_PREFIX: [_FRR_ROUTE, {**_FRR_ROUTE, "protocol": "static"}]}, scope=_OSPF_SCOPE)


def _connected_route(prefix, interface):
    return {
        "protocol": "connected", "table": 254, "vrfId": 0, "vrfName": "default", "distance": 0,
        "prefix": prefix, "prefixLen": int(prefix.rsplit("/", 1)[1]), "selected": True, "installed": True,
        "nexthops": [{"interfaceName": interface, "directlyConnected": True, "active": True, "fib": True, "weight": 1}],
    }


@pytest.mark.parametrize(("version", "destination", "scope"), [
    (4, "192.168.120.0/24", 253),
    (6, "2001:db8:120::/64", 0),
])
def test_live_connected_route_reports_only_the_mapped_direct_subnet(version, destination, scope):
    direct = _connected_route(destination, "eth3.120")
    interfaces = {"eth3.120": "br120"}
    snapshot = {destination: [direct], "fe80::/64": [_connected_route("fe80::/64", "eth3.120")]}
    project = uxg_route_queries.project_installed_routes

    assert project(snapshot, version=version, interfaces=interfaces) == [
        {"description": "", "destination": destination, "distance": 0, "origin": "Kernel", "scope": scope,
         "table": 254, "type": "unicast", "nexthops": [{"interface": "br120", "inUse": True, "weight": 1}]},
    ]
    direct["installed"] = False
    assert project(snapshot, version=version, interfaces=interfaces) == []
    direct["installed"] = True
    assert project(snapshot, version=version, interfaces={}) == []
    assert project(snapshot, version=version, interfaces={"eth3.120": "lo"}) == []
    with pytest.raises(RouteQueryError, match="multiple installed candidates"):
        project({destination: [direct, {**direct, "protocol": "static"}]}, version=version, interfaces=interfaces)


def test_operator_static_routes_appear_without_fabricating_a_controller_identity():
    prefix = "2001:db8:99::/64"
    route = _connected_route(prefix, "eth3.120")
    route.update(protocol="static", distance=7, nexthops=[
        {"interfaceName": "eth3.120", "ip": "2001:db8:120::2", "active": True, "fib": True, "weight": 1},
        {"interfaceName": "eth3.110", "ip": "2001:db8:110::2", "active": True, "fib": True, "weight": 1},
    ])
    table = {prefix: [route]}
    interfaces = {"eth3.120": "br120", "eth3.110": "br110"}
    project = uxg_route_queries.project_installed_routes
    assert project(table, version=6, interfaces=interfaces) == [
        {"description": "", "destination": prefix, "distance": 7, "origin": "Static", "scope": 0,
         "table": 254, "type": "unicast", "nexthops": [
             {"interface": "br120", "gateway": "2001:db8:120::2", "inUse": True, "weight": 1},
             {"interface": "br110", "gateway": "2001:db8:110::2", "inUse": True, "weight": 1},
         ]},
    ]
    assert project(table, version=6, interfaces=interfaces, managed_prefixes={prefix}) == []
    assert project(table, version=6, interfaces={"eth3.120": "br120"}) == []
    route["nexthops"] = [{"active": True, "fib": True, "blackhole": True}]
    assert project(table, version=6, interfaces={}) == [
        {"description": "", "destination": prefix, "distance": 7, "origin": "Static", "scope": 0,
         "table": 254, "type": "blackhole", "nexthops": []},
    ]


@pytest.mark.parametrize(("version", "family", "prefix", "first", "second"), [
    (4, "ip", "203.0.116.0/24", "192.0.2.2", "198.51.100.2"),
    (6, "ipv6", "2001:db8:33::/64", "2001:db8:210::2", "2001:db8:220::2"),
])
def test_stock_table_read_preserves_table_identity_and_installed_multipath(version, family, prefix, first, second):
    backend = object.__new__(VyOSBackend)
    calls = []

    def show(path):
        calls.append(path)
        return (f"IPv{version} unicast table 117:\n"
                f"S>* {prefix} [1/0] via {first}, eth3.210, weight 1, 00:00:04\n"
                f"  *                via {second}, eth3.220, weight 1, 00:00:04\n")

    backend._show = show
    snapshot = backend.show_static_route_table(117, version=version)
    assert calls == [[family, "route", "table", "117"]]
    rows = uxg_route_queries.project_installed_routes(
        snapshot, version=version, table=117, interfaces={"eth3.210": "eth0", "eth3.220": "eth2"},
    )
    assert rows == [{"description": "", "destination": prefix, "distance": 1, "origin": "Static",
                     "scope": 0, "table": 117, "type": "unicast", "nexthops": [
                         {"interface": "eth0", "weight": 1, "gateway": first, "inUse": True},
                         {"interface": "eth2", "weight": 1, "gateway": second, "inUse": True},
                     ]}]
    with pytest.raises(VyOSReadError, match="table identity"):
        backend.show_static_route_table(118, version=version)


def test_static_table_discovery_reports_only_configured_families():
    backend = object.__new__(VyOSBackend)
    calls = []

    def read_config(path):
        calls.append(path)
        return {"table": {"117": {"route": {"203.0.113.0/24": {}}, "route6": {"2001:db8::/64": {}}},
                          "178": {"route6": {"2001:db8:12::/64": {}}}, "119": {}}}

    backend.read_config = read_config
    assert backend.configured_static_route_tables() == {117: (4, 6), 178: (6,)}
    assert calls == [["protocols", "static", "table"]]


def test_live_static_routes_report_the_installed_winner_and_the_named_standby():
    prefix = "2001:db8:99::/64"
    primary_id = "11111111-1111-4111-8111-000000000001"
    backup_id = "11111111-1111-4111-8111-000000000002"
    owned = {prefix: {"description": f"STATIC_ROUTE:{primary_id}", "next-hop": {
        "fe80::17": {"distance": "5", "interface": "eth3.210"},
        "2001:db8:220::2": {"distance": "15", "interface": "eth3.220"},
    }}}
    identities = {prefix: {"5": {"id": primary_id, "interface": "br210"}, "15": {"id": backup_id}}}

    def observed(ip, interface, distance, selected):
        return {"protocol": "static", "table": 254, "selected": selected, "installed": selected, "metric": 0,
                "distance": distance, "prefix": prefix, "prefixLen": 64,
                "nexthops": [{"ip": ip, "interfaceName": interface, "active": True, "fib": True, "weight": 1}]}

    before = {prefix: [observed("2001:db8:220::2", "eth3.220", 15, False),
                       observed("fe80::17", "eth3.210", 5, True)]}
    interfaces = {"eth3.210": "eth0", "eth3.220": "eth2"}
    rows = uxg_route_queries.project_static_routes(before, owned=owned, identities=identities, interfaces=interfaces)
    assert rows == [
        {"destination": prefix, "description": f"STATIC_ROUTE:{primary_id}", "distance": 5,
         "origin": "Static", "scope": 0, "table": 254, "type": "unicast",
         "nexthops": [{"gateway": "fe80::17", "interface": "br210", "inUse": True, "weight": 1}]},
        {"destination": prefix, "description": f"STATIC_ROUTE:{backup_id}", "distance": 15,
         "origin": "Static", "scope": 0, "table": 254, "type": "unicast",
         "nexthops": [{"gateway": "2001:db8:220::2", "interface": "eth2", "inUse": False, "weight": 1}]},
    ]
    conflicting = {prefix: [{**before[prefix][0], "selected": True, "installed": True}, before[prefix][1]]}
    with pytest.raises(RouteQueryError, match="multiple installed candidates"):
        uxg_route_queries.project_static_routes(conflicting, owned=owned, identities=identities, interfaces=interfaces)
    after = {prefix: [observed("2001:db8:220::2", "eth3.220", 15, True)]}
    assert uxg_route_queries.project_static_routes(after, owned=owned, identities=identities, interfaces=interfaces) == [
        {**rows[1], "nexthops": [{**rows[1]["nexthops"][0], "inUse": True}]},
    ]


def test_live_static_blackhole_requires_an_installed_discard_and_uses_no_fabricated_interface():
    description = "STATIC_ROUTE:11111111-1111-4111-8111-000000000001"
    owned = {_PREFIX: {"description": description, "blackhole": {"distance": "5"}}}
    record = {"protocol": "static", "table": 254, "prefix": _PREFIX, "prefixLen": 32, "distance": 5,
              "metric": 0, "selected": True, "installed": True,
              "nexthops": [{"blackhole": True, "active": True, "fib": True}]}
    project = uxg_route_queries.project_static_routes
    assert project({_PREFIX: [record]}, owned=owned, identities={}, interfaces={}) == [
        {"destination": _PREFIX, "description": description, "distance": 5, "origin": "Static",
         "scope": 0, "table": 254, "type": "blackhole", "nexthops": []},
    ]
    record.update(selected=False, installed=False)
    assert project({_PREFIX: [record]}, owned=owned, identities={}, interfaces={}) == []


def test_live_route_command_keeps_healthy_ospf_when_ipv6_static_reporting_fails(gateway_config):
    gateway_config.read_dict({
        "gateway": {"device": "UXGENT", "platform": "vyos", "url": "http://lab.example:8080/inform",
                    "lan_mac": "02:78:91:00:12:03", "lan_ip": "192.0.2.1", "is_adopted": True, "ports": "[]"},
        "vyos_firewall": {"enabled": True}, "vyos_static_routes": {"enabled": True},
        "vyos_ospf": {"enabled": True, "report_routes": True},
    })
    gateway = object.__new__(UnifiGateway)
    gateway.config = gateway_config
    payloads = []

    def send(payload):
        payloads.append(json.loads(payload))
        return {}

    def read_ipv6():
        raise VyOSReadError("IPv6 read timed out")

    snapshot = {_PREFIX: [_FRR_ROUTE]}
    backend = SimpleNamespace(show_ipv4_routes=lambda: snapshot, show_ipv6_routes=read_ipv6,
                              configured_static_route_tables=lambda: {})
    gateway.datacollector = SimpleNamespace(data={}, ports=[], backend=backend)
    gateway._send_inform = send
    gateway.vyos_provisioner = SimpleNamespace(
        route_scope=SimpleNamespace(destinations=("2001:db8:99::/64",)), ospf_scope=_OSPF_SCOPE, backend=backend,
        read_verified_static_route_state=lambda: ({"2001:db8:99::/64": {}}, {}),
    )
    gateway._handle_cmd(_command(_ROUTES))
    assert len(payloads) == 1
    assert payloads[0]["notif_payload"]["udapi_blocks"]["get-routes"]["items"] == project_ospf_routes(
        snapshot, scope=_OSPF_SCOPE,
    )
    gateway_config.set("vyos_ospf", "report_routes", "false")
    gateway._handle_cmd(_command(_ROUTES))
    assert len(payloads) == 1


def test_adopted_vyos_profile_answers_live_connected_route_request_without_provisioning(gateway_config):
    destination = "192.168.120.0/24"
    gateway_config.read_dict({
        "gateway": {"device": "UXGENT", "platform": "vyos", "url": "http://lab.example:8080/inform",
                    "lan_mac": "02:78:91:00:12:03", "lan_ip": "192.0.2.1", "is_adopted": True, "ports": "[]"},
    })
    gateway = object.__new__(UnifiGateway)
    gateway.config = gateway_config
    gateway.vyos_provisioner = None
    table_reads = []

    def read_static_table(table, *, version):
        table_reads.append((table, version))
        route = _connected_route(destination, "eth3.120")
        route.update(protocol="static", distance=1, table=table)
        return {destination: [route]}

    gateway.datacollector = SimpleNamespace(
        data={}, ports=[{"realif": "eth3.120", "ifname": "br120"}],
        backend=SimpleNamespace(show_ipv4_routes=lambda: {destination: [_connected_route(destination, "eth3.120")]},
                                show_ipv6_routes=lambda: {}, configured_static_route_tables=lambda: {117: (4,), 179: (4,)},
                                show_static_route_table=read_static_table),
    )
    payloads = []
    gateway._send_inform = lambda payload: payloads.append(json.loads(payload)) or {}
    gateway._record_unhandled = lambda *args: None
    gateway._handle_cmd(_command(_ROUTES))
    assert len(payloads) == 1
    items = payloads[0]["notif_payload"]["udapi_blocks"]["get-routes"]["items"]
    assert [(row["destination"], row["table"], row["origin"]) for row in items] == [
        (destination, 254, "Kernel"), (destination, 117, "Static"),
    ]
    assert table_reads == [(117, 4)]
    assert payloads[0]["udapi_caps"] == ROUTE_QUERY_CAPABILITY
    assert "udapi_version" not in payloads[0]
    gateway_config.set("gateway", "is_adopted", "false")
    gateway._handle_cmd(_command(_ROUTES))
    assert len(payloads) == 1


def test_live_frr_full_neighbor_projects_to_the_network_neighbor_query():
    assert project_ospf_neighbors({"neighbors": {_NEIGHBOR_ID: [_FRR_NEIGHBOR]}}, scope=_OSPF_SCOPE) == [
        {
            "interface": "br120", "localAddress": "192.168.120.1", "neighborID": _NEIGHBOR_ID,
            "priority": 1, "remoteAddress": "192.168.120.2", "role": "Backup", "state": "Full",
        }
    ]


@pytest.mark.parametrize("snapshot", [{}, {"neighbors": {}}])
def test_stopped_ospf_or_no_live_neighbors_produces_empty_rows(snapshot):
    assert project_ospf_neighbors(snapshot, scope=_OSPF_SCOPE) == []


@pytest.mark.parametrize(
    "change", [{"ifaceName": "eth3.110:192.168.110.1"}, {"nbrState": "ExStart/Backup"}],
)
def test_neighbors_outside_the_supported_full_adjacency_are_omitted(change):
    snapshot = {"neighbors": {_NEIGHBOR_ID: [{**_FRR_NEIGHBOR, **change}]}}
    assert project_ospf_neighbors(snapshot, scope=_OSPF_SCOPE) == []


@pytest.mark.parametrize("change", [
    {"role": "DR"}, {"ifaceName": "eth3.120:192.168.120.3"}, {"converged": "Init"}, {"nbrPriority": True},
])
def test_inconsistent_full_adjacency_does_not_produce_live_state(change):
    snapshot = {"neighbors": {_NEIGHBOR_ID: [{**_FRR_NEIGHBOR, **change}]}}
    with pytest.raises(RouteQueryError):
        project_ospf_neighbors(snapshot, scope=_OSPF_SCOPE)
