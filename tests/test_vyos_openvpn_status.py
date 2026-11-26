import pytest

from gateway_profiles.vyos_openvpn_status import OpenVpnStatusError, project_openvpn_status
from provisioners.vyos_openvpn import OpenVpnScope


SCOPE = OpenVpnScope(server_name="router.example.net")
LINK = "vtun246: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500\n    inet 172.29.94.2/29\n"
DOWN = "vtun246: <NO-CARRIER,POINTOPOINT,MULTICAST,NOARP,UP> mtu 1500\n"


class Router:
    def __init__(self, detail=LINK):
        self.detail = detail
        self.routes = {"172.29.94.0/29": [{
            "protocol": "connected", "selected": True, "installed": True, "table": 254,
            "nexthops": [{"interfaceName": "vtun246", "active": True, "fib": True}],
        }]}
        self.policy = None
        self.pings = []
        self.reachable = True

    def show_interfaces(self):
        return self.detail

    def show_ipv4_routes(self):
        return self.routes

    def read_config(self, path):
        assert path == ["policy"]
        return self.policy

    def ping_ipv4_once(self, address):
        self.pings.append(str(address))
        return self.reachable


def test_openvpn_uses_real_probe_and_omits_unavailable_uptime():
    router = Router()
    assert project_openvpn_status("1", SCOPE, router) == [{
        "id": "/vpn/openvpn/raws/1",
        "local": {"tunnel_ip": "172.29.94.2"},
        "remotes": [{"ip": "198.18.210.2"}],
    }]
    assert router.pings == ["172.29.94.1"]


def test_openvpn_reports_disconnected_when_down_or_peer_does_not_respond():
    router = Router(DOWN)
    disconnected = [{"id": "/vpn/openvpn/raws/1", "remotes": []}]
    assert project_openvpn_status("1", SCOPE, router) == disconnected
    assert not router.pings
    router.detail = LINK
    router.reachable = False
    assert project_openvpn_status("1", SCOPE, router) == disconnected


@pytest.mark.parametrize("drift", ["next-hop", "more-specific", "policy", "address", "identity"])
def test_openvpn_does_not_probe_an_unverified_path(drift):
    router = Router()
    native_id = "1"
    if drift == "next-hop":
        router.routes["172.29.94.0/29"][0]["nexthops"][0]["interfaceName"] = "eth3.210"
    elif drift == "more-specific":
        router.routes["172.29.94.0/30"] = router.routes["172.29.94.0/29"]
    elif drift == "policy":
        router.policy = {"route": {"other": {}}}
    elif drift == "address":
        router.detail = LINK.replace("172.29.94.2", "172.29.94.3")
    else:
        native_id = "01"
    with pytest.raises(OpenVpnStatusError):
        project_openvpn_status(native_id, SCOPE, router)
    assert not router.pings
