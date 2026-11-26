"""Exercise the request contract of the lab's VyOS configuration API."""
import io
from ipaddress import IPv4Address, IPv6Address
import json
import ssl
from urllib.parse import parse_qs
import urllib.request

import pytest

from backends.vyos import VyOSBackend, VyOSReadError, VyOSWriteError


@pytest.fixture
def backend(tmp_path, monkeypatch):
    key = tmp_path / "key"
    key.write_text("lab-key")
    monkeypatch.setattr(ssl, "create_default_context", lambda **_: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    return VyOSBackend(api_url="https://lab.example", ca_file="lab-ca.pem", key_file=key)


def test_reboot_uses_stock_https_endpoint_and_surfaces_a_missing_response(backend, monkeypatch):
    def lost_response(_opener, request, *, timeout):
        assert request.full_url == "https://lab.example/reboot"
        form = parse_qs(request.data.decode())
        assert form["key"] == ["lab-key"]
        assert json.loads(form["data"][0]) == {"op": "reboot", "path": ["now"]}
        raise TimeoutError

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", lost_response)
    with pytest.raises(VyOSWriteError, match="reboot request failed"):
        backend.reboot()


def test_read_and_stage_firewall_with_confirm_and_save(backend, monkeypatch):
    requests = []
    timeouts = []
    prefix = ["firewall", "ipv4", "forward", "filter", "rule", "80200"]
    rule = {"action": "drop", "protocol": "tcp", "destination": {"port": "8443"}}
    replies = iter([
        False, True, rule, None, "Reload timer stopped", None,
    ])

    def respond(_opener, request, *, timeout):
        form = parse_qs(request.data.decode())
        assert form["key"] == ["lab-key"]
        requests.append((request.selector, json.loads(form["data"][0])))
        timeouts.append(timeout)
        return io.BytesIO(json.dumps({"success": True, "data": next(replies)}).encode())

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", respond)
    commands = [
        {"op": "set", "path": prefix + ["action", "drop"]},
        {"op": "set", "path": prefix + ["protocol", "tcp"]},
        {"op": "set", "path": prefix + ["destination", "port", "8443"]},
    ]

    assert backend.read_config(prefix) is None
    assert backend.read_config(prefix) == rule
    backend.stage_configuration(commands, confirm_minutes=2)
    backend.confirm_configuration()
    backend.save_configuration()

    assert requests == [
        ("/retrieve", {"op": "exists", "path": prefix}),
        ("/retrieve", {"op": "exists", "path": prefix}),
        ("/retrieve", {"op": "showConfig", "path": prefix}),
        ("/configure", {"commands": commands, "confirm_time": 2}),
        ("/config-file", {"op": "confirm"}),
        ("/config-file", {"op": "save"}),
    ]
    assert timeouts == [8, 8, 8, 30, 8, 8]


def test_config_read_does_not_treat_unavailable_as_absent(backend, monkeypatch):
    def respond(_opener, request, *, timeout):
        raise TimeoutError

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", respond)

    with pytest.raises(VyOSReadError, match="retrieve"):
        backend.read_config(["firewall"])


def test_bgp_soft_reset_uses_exact_stock_https_operation(backend, monkeypatch):
    requests = []

    def respond(_opener, request, *, timeout):
        form = parse_qs(request.data.decode())
        requests.append((request.selector, json.loads(form["data"][0])))
        return io.BytesIO(b'{"success":true,"data":""}')

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", respond)
    backend.soft_refresh_bgp_ipv4(IPv4Address("192.0.2.2"), direction="in")
    backend.soft_refresh_bgp_ipv6(IPv6Address("2001:db8::2"), direction="out")
    backend.soft_refresh_bgp_ipv6(IPv4Address("192.0.2.2"), direction="in")
    backend.soft_refresh_bgp_ipv4(IPv6Address("2001:db8::2"), direction="in")
    with pytest.raises(ValueError):
        backend.soft_refresh_bgp_ipv4(IPv4Address("192.0.2.2"), direction="hard")
    with pytest.raises(ValueError):
        backend.soft_refresh_bgp_ipv6(IPv6Address("fe80::2%eth3"), direction="in")
    with pytest.raises(ValueError):
        backend.soft_refresh_bgp_ipv4(IPv6Address("fe80::2"), direction="in")
    assert requests == [
        ("/reset", {"op": "reset", "path": ["bgp", "ipv4", "192.0.2.2", "soft", "in"]}),
        ("/reset", {"op": "reset", "path": ["bgp", "ipv6", "2001:db8::2", "soft", "out"]}),
        ("/reset", {"op": "reset", "path": ["bgp", "ipv6", "192.0.2.2", "soft", "in"]}),
        ("/reset", {"op": "reset", "path": ["bgp", "ipv4", "2001:db8::2", "soft", "in"]}),
    ]


def test_confirm_with_no_pending_timer_does_not_verify_the_transaction(backend, monkeypatch):
    def respond(_opener, request, *, timeout):
        assert request.selector == "/config-file"
        return io.BytesIO(b'{"success":true,"data":"No confirm pending\\n"}')

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", respond)
    with pytest.raises(VyOSWriteError, match="active commit-confirm"):
        backend.confirm_configuration()


@pytest.mark.parametrize("local,peer,expected", [
    ("0.0.0.0:mdns", "0.0.0.0:*", True),
    ("[::]:5353", "[::]:*", True),
    ("192.0.2.1:123", "192.0.2.2:mdns", False),
])
def test_mdns_socket_check_uses_only_the_local_port(backend, monkeypatch, local, peer, expected):
    def show(path):
        assert path == ["system", "connections", "udp"]
        return f"State Recv-Q Send-Q Local Address:Port Peer Address:Port\nUNCONN 0 0 {local} {peer}\n"

    monkeypatch.setattr(backend, "_show", show)
    assert backend.has_mdns_listener() is expected


def test_mdns_socket_check_rejects_unrecognized_operational_output(backend, monkeypatch):
    monkeypatch.setattr(backend, "_show", lambda _path: "Network command unavailable")
    with pytest.raises(VyOSReadError, match="UDP socket table"):
        backend.has_mdns_listener()


def test_mdns_memberships_read_the_stock_group_table_after_connection_rows(backend, monkeypatch):
    def show(path):
        assert path == ["ip", "groups"]
        return (
            "Active Internet connections (w/o servers)\n"
            "Proto Recv-Q Send-Q Local Address Foreign Address State\n"
            "tcp 0 0 192.0.2.1:443 192.0.2.2:48556 ESTABLISHED\n"
            "IPv6/IPv4 Group Memberships\nInterface       RefCnt Group\n"
            "--------------- ------ ---------------------\n"
            "eth3.110        1      224.0.0.251\n"
            "eth3.120        1      224.0.0.251\n"
            "eth3.130        1      224.0.0.1\n"
            "eth3.130        1      ff02::fb\n"
        )

    monkeypatch.setattr(backend, "_show", show)
    assert backend.mdns_multicast_interfaces() == {"eth3.110", "eth3.120"}


def test_reads_ipv4_ospf_neighbors_from_supported_show_endpoint(backend, monkeypatch):
    def show(path):
        assert path == ["ip", "ospf", "neighbor", "json"]
        return '{"neighbors":{}}'

    monkeypatch.setattr(backend, "_show", show)
    assert backend.show_ipv4_ospf_neighbors() == {"neighbors": {}}
    monkeypatch.setattr(backend, "_show", lambda _path: "VyOS show output unavailable")
    with pytest.raises(VyOSReadError, match="JSON OSPF neighbors"):
        backend.show_ipv4_ospf_neighbors()


def test_ambiguous_stage_is_never_retried_or_confirmed(backend, monkeypatch):
    requests = []

    def respond(_opener, request, *, timeout):
        requests.append(request.selector)
        raise TimeoutError

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", respond)
    commands = [{"op": "delete", "path": ["firewall", "ipv4", "forward", "filter", "rule", "80200"]}]

    with pytest.raises(VyOSWriteError, match="configure"):
        backend.stage_configuration(commands, confirm_minutes=1)

    assert requests == ["/configure"]
