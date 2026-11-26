"""Behavioral checks for the Gateway Enterprise identity and VyOS telemetry."""
import io
import json
from pathlib import Path
import ssl
from types import SimpleNamespace
from urllib.parse import parse_qs
import urllib.request

import pytest

import unifi_gateway
from collectors.vyos import VyOSCollector
from unifi_protocol import create_inform


def test_uxg_enterprise_keeps_identity_and_advertises_only_enabled_provisioning(gateway_config):
    gateway_config.read_dict({
        "gateway": {"device": "UXGENT", "platform": "vyos", "url": "http://lab.example:8080/inform",
                    "lan_mac": "02:78:91:00:12:04", "lan_ip": "192.0.2.1", "is_adopted": False, "ports": "[]"},
        "vyos_firewall": {"enabled": True}, "vyos_mdns": {"enabled": True},
    })
    collector = SimpleNamespace(data={})
    discovery = json.loads(create_inform(gateway_config, collector))
    gateway_config.set("gateway", "is_adopted", "true")
    adopted = json.loads(create_inform(gateway_config, collector))

    for payload in (discovery, adopted):
        assert (payload["model"], payload["model_display"], payload["type"], payload["version"]) == (
            "UXGENT", "Gateway Enterprise", "uxg", "6.0.17",
        )
        assert payload["mac"] == "02:78:91:00:12:04"
    assert "udapi_version" not in discovery
    assert adopted["udapi_version"]["versionDetail"]["services/mdns"] == 2
    assert "routes/bgp/raw" not in adopted["udapi_version"]["versionDetail"]
    assert (adopted["udapi_caps"] & 0x00400000) == 0
    assert (adopted.get("usg2_caps", 0) & 0x40000000) == 0


@pytest.mark.parametrize("condition", ["prepared", "disabled", "no-opt-in", "no-recovery", "unauthenticated", "unadopted"])
def test_bgp_upload_advertisement_requires_an_opted_in_prepared_enterprise(gateway_config, condition):
    gateway_config.read_dict({
        "gateway": {"device": "UXGENT", "platform": "vyos",
                    "url": "http://lab.example:8080/inform", "lan_mac": "02:78:91:00:12:04", "lan_ip": "192.0.2.1",
                    "is_adopted": condition != "unadopted", "use_aes_gcm": condition != "unauthenticated", "ports": "[]"},
        "vyos_firewall": {"enabled": True},
        "vyos_restart": {"recover_provisioning": condition != "no-recovery"},
        "vyos_bgp": {"enabled": condition != "disabled", "advertise": condition != "no-opt-in"},
    })
    payload = json.loads(create_inform(gateway_config, SimpleNamespace(data={})))
    versions = payload.get("udapi_version", {}).get("versionDetail", {})
    assert bool(payload.get("udapi_caps", 0) & 0x00400000) is (condition == "prepared")
    assert versions.get("routes/bgp/raw") == (1 if condition == "prepared" else None)


def test_vyos_inform_preserves_secondary_ipv4_addresses_for_observed_ports(gateway_config, monkeypatch):
    from collectors.vyos import VyOSCollector

    interface_detail = (
        "eth5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
        "    inet 192.0.2.5/24 scope global eth5\n"
        "    inet 169.254.254.3/24 scope link eth5\n"
        "    inet6 fe80::5/64 scope link\n"
        "eth7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
        "    inet 169.254.254.2/24 scope link eth7\n"
    )
    gateway_config.read_dict({
        "gateway": {"device": "UXGENT", "platform": "vyos", "url": "http://lab.example:8080/inform",
                    "lan_mac": "02:78:91:00:12:04", "lan_ip": "192.0.2.1", "is_adopted": True,
                    "ports": json.dumps([
                        {"ifname": "eth1", "name": "LAN", "type": "lan", "realif": "eth5", "port_idx": 2},
                    ])},
        "vyos": {"api_url": "https://lab.example", "ca_file": "lab-ca.test", "key_file": "lab-key.test"},
    })
    backend = SimpleNamespace(
        show_interfaces=lambda: interface_detail, show_ethernet_physical=lambda _: "",
        show_ipv4_routes=lambda: {}, show_ipv6_routes=lambda: {},
        show_ipv4_neighbors=lambda: "", show_ipv6_neighbors=lambda: "", show_dhcpv4_leases=lambda: "",
        show_uptime=lambda: "Uptime: 3m\n", show_cpu_states=lambda: "", show_memory_detail=lambda: "",
    )
    monkeypatch.setattr("collectors.vyos.VyOSBackend", lambda **_: backend)
    collector = VyOSCollector(gateway_config)
    payload = json.loads(create_inform(gateway_config, collector))

    assert payload["network_table"] == [{
        "name": "eth1", "up": True, "address": "192.0.2.5/24",
        "addresses": ["192.0.2.5/24", "169.254.254.3/24", "fe80::5/64"],
    }]
    assert payload["if_table"][0]["ip"] == "192.0.2.5"

    interface_detail = interface_detail.replace("    inet 169.254.254.3/24 scope link eth5\n", "")
    collector.update()
    payload = json.loads(create_inform(gateway_config, collector))
    assert payload["network_table"][0]["addresses"] == ["192.0.2.5/24", "fe80::5/64"]


def test_enterprise_sample_reports_the_observed_default_lan_for_the_shadow_peer_guard(gateway_config, monkeypatch):
    from collectors.vyos import VyOSCollector

    sample = Path(__file__).parents[1] / "conf" / "uxg-enterprise.sample.conf"
    assert gateway_config.read(sample)
    gateway_config.read_dict({"gateway": {"lan_mac": "02:78:91:00:12:04", "is_adopted": True},
                              "vyos": {"ca_file": "lab-ca.test", "key_file": "lab-key.test"}})
    interface_detail = (
        "br0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
        "    inet 192.0.2.1/24 scope global br0\n"
        "    inet6 fe80::2/64 scope link\n"
        "    inet6 fe80::3/64 scope link tentative\n"
        "eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
        "    inet6 fe80::100/64 scope link\n"
    )
    backend = SimpleNamespace(
        show_interfaces=lambda: interface_detail, show_ipv4_routes=lambda: {}, show_ipv6_routes=lambda: {},
        show_ipv4_neighbors=lambda: "", show_ipv6_neighbors=lambda: "", show_dhcpv4_leases=lambda: "",
        show_uptime=lambda: "Uptime: 3m\n", show_cpu_states=lambda: "", show_memory_detail=lambda: "",
    )
    monkeypatch.setattr("collectors.vyos.VyOSBackend", lambda **_: backend)
    collector = VyOSCollector(gateway_config)
    payload = json.loads(create_inform(gateway_config, collector))

    assert payload["network_table"] == [{
        "name": "br0", "up": True, "address": "192.0.2.1/24", "addresses": ["192.0.2.1/24", "fe80::2/64"],
    }]
    assert [port["ifname"] for port in payload["config_port_table"]] == [f"eth{i}" for i in range(6)]
    assert payload["port_table"] == []
    assert (payload.get("usg2_caps", 0) & 0x40000000) == 0
    gateway_config.read_dict({"vyos_shadow": {"provisioning_enabled": True}})
    collector.data["links"]["eth1"] = {"enable": True, "up": True}
    payload = json.loads(create_inform(gateway_config, collector))
    assert payload["port_table"] == [{"name": "eth1", "ifname": "eth1", "port_idx": 2, "enable": True, "up": True}]


def test_native_ipsec_status_requires_an_applied_revision_and_a_fresh_measurement(gateway_config):
    gateway_config.read_dict({
        "gateway": {"device": "UXGENT", "platform": "vyos", "url": "http://lab.example:8080/inform",
                    "lan_mac": "02:78:91:00:12:03", "lan_ip": "192.0.2.1", "is_adopted": True, "ports": "[]"},
        "vyos_firewall": {"enabled": True}, "vyos_ipsec": {"enabled": True},
    })
    observed = [{"id": "/vpn/ipsec/site-to-site/48202d42-baa5-480f-b61f-5816b91045d1", "remotes": []}]
    collector = SimpleNamespace(data={"ipsec_status": observed})
    assert "vpn" not in json.loads(create_inform(gateway_config, collector))
    gateway_config.read_dict({"vyos_applied": {"cfgversion": "verified"}})
    assert json.loads(create_inform(gateway_config, collector))["vpn"] == observed
    collector.data.clear()
    assert "vpn" not in json.loads(create_inform(gateway_config, collector))


def test_policy_based_routing_uses_its_own_opt_in_inform_capability(gateway_config):
    gateway_config.read_dict({
        "gateway": {"device": "UXGENT", "platform": "vyos", "url": "http://lab.example:8080/inform",
                    "lan_mac": "02:78:91:00:12:03", "lan_ip": "192.0.2.1", "is_adopted": True, "ports": "[]"},
        "vyos_firewall": {"enabled": True}, "vyos_wan_failover": {"enabled": True},
    })
    collector = SimpleNamespace(data={})
    baseline = json.loads(create_inform(gateway_config, collector))
    assert "usg_caps" not in baseline
    assert "firewall/pbr" not in baseline["udapi_version"]["versionDetail"]

    gateway_config.read_dict({"vyos_policy_route": {"enabled": True}})
    active = json.loads(create_inform(gateway_config, collector))
    assert active["usg_caps"] == 0x00800000
    assert active["udapi_caps"] == baseline["udapi_caps"] == 0x800004
    assert active["udapi_version"]["versionDetail"]["firewall/pbr"] == 12


def test_static_routes_advertise_live_routing_without_enabling_ospf(gateway_config):
    gateway_config.read_dict({
        "gateway": {"device": "UXGENT", "platform": "vyos", "url": "http://lab.example:8080/inform",
                    "lan_mac": "02:78:91:00:12:03", "lan_ip": "192.0.2.1", "is_adopted": True, "ports": "[]"},
        "vyos_firewall": {"enabled": True}, "vyos_static_routes": {"enabled": True},
    })
    active = json.loads(create_inform(gateway_config, SimpleNamespace(data={})))
    assert active["udapi_caps"] == 0x800000
    assert "routes/ospf" not in active["udapi_version"]["versionDetail"]


def test_native_qos_uses_capability_flag_without_changing_the_negotiated_schema(gateway_config):
    gateway_config.read_dict({
        "gateway": {"device": "UXGENT", "platform": "vyos", "url": "http://lab.example:8080/inform",
                    "lan_mac": "02:78:91:00:12:03", "lan_ip": "192.0.2.1", "is_adopted": True, "ports": "[]"},
        "vyos_firewall": {"enabled": True}, "vyos_wan_failover": {"enabled": True},
    })
    collector = SimpleNamespace(data={})
    baseline = json.loads(create_inform(gateway_config, collector))
    gateway_config.read_dict({"vyos_qos": {"enabled": True}})
    configured = json.loads(create_inform(gateway_config, collector))

    assert configured["udapi_caps"] == baseline["udapi_caps"] | 0x100
    assert configured["udapi_version"] == baseline["udapi_version"]


def test_mdns_service_scope_negotiation_requires_managed_mdns(gateway_config):
    gateway_config.read_dict({
        "gateway": {"device": "UXGENT", "platform": "vyos", "url": "http://lab.example:8080/inform",
                    "lan_mac": "02:78:91:00:12:03", "lan_ip": "192.0.2.1", "is_adopted": True, "ports": "[]"},
        "vyos_firewall": {"enabled": True},
    })
    collector = SimpleNamespace(data={})
    baseline = json.loads(create_inform(gateway_config, collector))["udapi_version"]["versionDetail"]

    gateway_config.read_dict({"vyos_mdns": {"enabled": True}})
    enabled = json.loads(create_inform(gateway_config, collector))["udapi_version"]["versionDetail"]

    assert "services/mdns" not in baseline
    assert enabled == baseline | {"services/mdns": 2}


def test_controller_firmware_request_preserves_enrollment(tmp_path, monkeypatch):
    path = tmp_path / "gateway.conf"
    path.write_text("[gateway]\ndevice = UXGENT\nplatform = vyos\n")
    original = path.read_bytes()
    monkeypatch.setattr(unifi_gateway, "CONFIG_FILE", str(path))
    gateway = unifi_gateway.UnifiGateway()

    gateway._handle_response({"_type": "upgrade", "version": "99.0.0"})

    assert path.read_bytes() == original
    assert not gateway.config.has_option("gateway", "firmware")


def test_enterprise_inform_keeps_identity_and_unavailable_telemetry_separate(gateway_config):
    for key, value in {
        "device": "UXGENT",
        "platform": "vyos",
        "lan_mac": "02:78:91:00:12:02",
        "lan_ip": "192.168.110.1",
        "url": "http://192.168.77.2:8080/inform",
        "ports": json.dumps([
            {"ifname": "eth0", "name": "WAN", "type": "wan", "realif": "eth3.210", "port_idx": 1},
            {"ifname": "eth1", "name": "LAN", "type": "lan", "realif": "eth3.110", "port_idx": 2},
            {"ifname": "eth2", "name": "WAN2", "type": "wan2", "realif": "eth3.220", "port_idx": 3},
            {"ifname": "eth3", "name": "LAN2", "type": "lan2", "realif": "eth3.120", "port_idx": 4},
            {"ifname": "br130", "name": "VLAN 130", "type": "lan", "realif": "eth3.130"},
        ]),
    }.items():
        gateway_config.set("gateway", key, value)
    gateway_config.set("provisioned", "cfgversion", "controller-desired-revision")
    collector = SimpleNamespace(data={
        "links": {"eth0": {"enable": True, "up": True}, "eth1": {"enable": False, "up": False},
                  "br130": {"enable": True, "up": True}},
        "ifstat": {"eth0": {"rx_bytes": "2670", "tx_bytes": "953"}},
        "macs": {"eth1": "02:00:00:00:00:99"},
        "ip": {"eth1": {"address": "192.168.110.1", "netmask": "255.255.255.0"},
               "br130": {"address": "192.168.130.1", "netmask": "255.255.255.0"}},
        "ipv6": {"eth1": ["fe80::8/64"]},
        "uptime": 302,
        "routes": [{"pfx": "192.168.110.0/24", "nh": [{"intf": "eth1", "t": "C>*"}]}],
    })

    initial = json.loads(create_inform(gateway_config, SimpleNamespace(data={})))
    adopted = json.loads(create_inform(gateway_config, collector))
    gateway_config.set("gateway", "is_adopted", "false")
    discovery = json.loads(create_inform(gateway_config, collector))

    assert discovery["state"] == 0
    assert discovery["default"] is True
    assert discovery["model"] == adopted["model"] == "UXGENT"
    assert discovery["model_display"] == adopted["model_display"] == "Gateway Enterprise"
    assert discovery["version"] == adopted["version"] == "6.0.17"
    assert discovery["type"] == adopted["type"] == "uxg"
    assert discovery["mac"] == adopted["mac"] == "02:78:91:00:12:02"
    assert adopted["state"] == 2
    assert adopted["cfgversion"] == ""
    assert [port["type"] for port in adopted["config_port_table"]] == ["wan", "lan", "wan2", "lan2"]
    assert all("realif" not in port for port in adopted["config_port_table"])
    assert adopted["if_table"] == [
        {"name": "eth0", "enable": True, "up": True, "rx_bytes": "2670", "tx_bytes": "953"},
        {"name": "eth1", "enable": False, "up": False,
         "mac": "02:00:00:00:00:99", "ip": "192.168.110.1", "netmask": "255.255.255.0"},
        {"name": "br130", "enable": True, "up": True, "ip": "192.168.130.1", "netmask": "255.255.255.0"},
    ]
    assert initial["if_table"] == []
    assert initial["port_table"] == []
    assert "uptime" not in initial
    assert adopted["uptime"] == 302
    assert adopted["port_table"] == [
        {"name": "eth0", "port_idx": 1, "enable": True, "up": True, "rx_bytes": "2670", "tx_bytes": "953"},
        {"name": "eth1", "port_idx": 2, "enable": False, "up": False,
         "mac": "02:00:00:00:00:99", "num_port": 1},
    ]
    assert adopted["network_table"] == [
        {"name": "eth1", "address": "192.168.110.1/24", "addresses": ["192.168.110.1/24", "fe80::8/64"],
         "up": False, "mac": "02:00:00:00:00:99"},
        {"name": "br130", "address": "192.168.130.1/24", "addresses": ["192.168.130.1/24"], "up": True},
    ]
    assert adopted["routes"] == collector.data["routes"]
    assert "speedtest-status" not in adopted
    assert "udapi_caps" not in discovery
    assert adopted["udapi_caps"] == 0x800000

    gateway_config.set("gateway", "is_adopted", "true")
    gateway_config.read_dict({"vyos_firewall": {"enabled": "true"}, "vyos_ospf": {"enabled": "true"}})
    ospf = json.loads(create_inform(gateway_config, collector))
    assert ospf["udapi_caps"] == 0x840000
    advertised = ospf["udapi_version"]["versionDetail"]
    assert {name: version for name, version in advertised.items() if name.startswith("routes/ospf")} == {
        "routes/ospf": 2, "routes/ospf/areas": 2, "routes/ospf/interfaces": 2,
    }
    gateway_config.set("vyos_ospf", "report_routes", "true")
    assert json.loads(create_inform(gateway_config, collector))["udapi_caps"] == 0x840000
    gateway_config.read_dict({"vyos_openvpn": {"enabled": True}})
    vpn = json.loads(create_inform(gateway_config, collector))
    assert vpn["udapi_caps"] == 0x840080
    assert vpn["udapi_version"]["versionDetail"]["vpn/openvpn/raws"] == 6


@pytest.fixture
def uxg_speedtest_config(gateway_config):
    gateway_config.read_dict({
        "gateway": {"device": "UXGENT", "platform": "vyos", "url": "http://lab.example:8080/inform",
                    "lan_mac": "02:78:91:00:12:03", "lan_ip": "192.0.2.1", "is_adopted": True, "ports": "[]"},
    })
    return gateway_config


def test_enterprise_publishes_only_measured_host_health(uxg_speedtest_config):
    collector = SimpleNamespace(data={"system_stats": {"cpu": 0.0}, "uptime": 300})
    payload = json.loads(create_inform(uxg_speedtest_config, collector))
    assert payload["system-stats"] == {"cpu": 0.0, "uptime": 300}
    assert payload["uptime"] == 300
    collector.data.pop("system_stats")
    assert "system-stats" not in json.loads(create_inform(uxg_speedtest_config, collector))


def test_enterprise_exposes_observed_half_duplex_and_speed_on_the_port(uxg_speedtest_config):
    uxg_speedtest_config["gateway"]["ports"] = (
        '[{"ifname":"eth0","name":"WAN","type":"wan","realif":"eth2","port_idx":1}]'
    )
    collector = SimpleNamespace(data={
        "links": {"eth0": {"up": True, "enable": True}},
        "port_media": {"eth0": {"speed": 1000, "full_duplex": False}},
    })
    payload = json.loads(create_inform(uxg_speedtest_config, collector))
    for table in ("port_table", "if_table"):
        port = payload[table][0]
        assert port["speed"] == 1000 and port["full_duplex"] is False


def test_enterprise_reports_an_explicit_third_wan_as_the_observed_uplink(uxg_speedtest_config):
    uxg_speedtest_config["gateway"]["ports"] = json.dumps([
        {"ifname": "eth0", "name": "WAN", "type": "wan", "realif": "eth3.210", "port_idx": 1},
        {"ifname": "eth4", "name": "WAN3", "type": "wan3", "realif": "eth3.230", "port_idx": 5},
    ])
    collector = SimpleNamespace(data={
        "links": {"eth0": {"enable": True, "up": True}, "eth4": {"enable": True, "up": True}},
        "routes": [{"pfx": "0.0.0.0/0", "nh": [{"intf": "eth4", "t": "S>*", "via": "198.18.230.2"}]}],
    })

    assert json.loads(create_inform(uxg_speedtest_config, collector))["uplink"] == "eth4"
    collector.data["links"]["eth4"]["up"] = False
    assert "uplink" not in json.loads(create_inform(uxg_speedtest_config, collector))


def test_uxg_wan_health_merges_measured_quality_and_removes_unavailable_monitor(uxg_speedtest_config):
    collector = SimpleNamespace(data={
        "wan_failover": {"uplink": "eth0", "uptime_stats": {"WAN": {"uptime": 18, "downtime": 0}}},
        "wan_health": {
            "WAN": {"target": "198.18.210.2", "sent": 3, "received": 2, "latency_ms": 24.6},
            "WAN2": None,
            "WAN3": {"target": "198.18.230.2", "sent": 3, "received": 0, "latency_ms": None},
        },
        "wan_health_durations": {"WAN3": {"uptime": 0, "downtime": 12}},
    })
    assert json.loads(create_inform(uxg_speedtest_config, collector))["uptime_stats"] == {
        "WAN": {"uptime": 18, "downtime": 0, "alerting_monitors": [
            {"type": "icmp", "target": "198.18.210.2", "availability": 67, "latency_average": 25},
        ]},
        "WAN3": {"uptime": 0, "downtime": 12, "alerting_monitors": [
            {"type": "icmp", "target": "198.18.230.2", "availability": 0},
        ]},
    }
    assert collector.data["wan_failover"]["uptime_stats"]["WAN"] == {"uptime": 18, "downtime": 0}


def test_uxg_speedtest_reports_completed_measured_result_only(uxg_speedtest_config):
    result = {"ping": 17.6, "download": 385.25, "upload": 290.5, "lastrun": 1795604061}
    collector = SimpleNamespace(data={"uxg_speedtest": result})
    assert json.loads(create_inform(uxg_speedtest_config, collector))["speedtest-status"] == {
        "latency": 17, "rundate": 1795604061, "runtime": 0,
        "status_download": 2, "status_ping": 2, "status_summary": 2, "status_upload": 2,
        "xput_download": 385.25, "xput_upload": 290.5,
    }
    uxg_speedtest_config.set("gateway", "is_adopted", "false")
    assert "speedtest-status" not in json.loads(create_inform(uxg_speedtest_config, collector))


@pytest.mark.parametrize("stage,download,upload", [("download", 1, 0), ("upload", 2, 1)])
def test_uxg_speedtest_reports_measured_progress_by_phase(uxg_speedtest_config, stage, download, upload):
    result = {"ping": 17.6, "download": 385.25, "upload": 290.5, "lastrun": 1795604061}
    collector = SimpleNamespace(data={"uxg_speedtest": result, "uxg_speedtest_stage": stage})
    status = json.loads(create_inform(uxg_speedtest_config, collector))["speedtest-status"]
    assert status["status_ping"] == 2 and status["status_summary"] == 1
    assert (status["status_download"], status["status_upload"]) == (download, upload)
    assert status["rundate"] == result["lastrun"]
    assert (status["xput_download"], status["xput_upload"]) == (result["download"], result["upload"])
    assert status[f"{stage}-progress"] == [
        {"id": 1, "records": [[result["lastrun"], round(result[stage] * 100)]]},
    ]
    other_stage = "upload" if stage == "download" else "download"
    assert f"{other_stage}-progress" not in status


def test_uxg_speedtest_live_download_omits_unmeasured_upload(uxg_speedtest_config):
    result = {"ping": 17.6, "download": 385.25, "lastrun": 1795604061}
    collector = SimpleNamespace(data={"uxg_speedtest": result, "uxg_speedtest_stage": "download"})
    status = json.loads(create_inform(uxg_speedtest_config, collector))["speedtest-status"]
    assert status["status_upload"] == 0
    assert "xput_upload" not in status
    assert status["download-progress"] == [{"id": 1, "records": [[1795604061, 38525]]}]


@pytest.mark.parametrize("stage", ["download", "upload", "complete"])
def test_uxg_speedtest_reports_the_configured_measurement_endpoint(uxg_speedtest_config, stage):
    uxg_speedtest_config.read_dict({
        "vyos_speedtest": {"server_provider": "Lab WAN peer", "server_location": "Isolated lab"},
    })
    result = {"ping": 17.6, "download": 385.25, "upload": 290.5, "lastrun": 1795604061}
    collector = SimpleNamespace(data={"uxg_speedtest": result, "uxg_speedtest_stage": stage})
    status = json.loads(create_inform(uxg_speedtest_config, collector))["speedtest-status"]
    assert status["server"] == {"provider": "Lab WAN peer", "country": "Isolated lab"}


@pytest.mark.parametrize("change", [
    {"download": float("nan")}, {"upload": float("inf")}, {"ping": True},
    {"ping": -1}, {"upload": 0}, {"lastrun": "1795604061"}, {"lastrun": 0},
])
def test_uxg_speedtest_ignores_invalid_or_legacy_measurements(uxg_speedtest_config, change):
    result = {"ping": 17.6, "download": 385.25, "upload": 290.5, "lastrun": 1795604061}
    collector = SimpleNamespace(data={"uxg_speedtest": {**result, **change}, "speedtest": result})
    assert "speedtest-status" not in json.loads(create_inform(uxg_speedtest_config, collector))


def test_vyos_collector_reports_live_port_state_and_clears_it_on_timeout(
    gateway_config, tmp_path, monkeypatch
):
    key_file = tmp_path / "vyos.key"
    key_file.write_text("test-lab-token\n")
    gateway_config["gateway"]["ports"] = json.dumps([
        {"ifname": "eth0", "name": "WAN", "type": "wan", "realif": "enp0s3"},
        {"ifname": "eth1", "name": "LAN", "type": "lan", "realif": "enp0s8"},
    ])
    gateway_config.read_dict({"vyos": {
        "api_url": "https://192.168.77.1",
        "key_file": str(key_file),
        "ca_file": "lab-ca.pem",
    }})
    detail = """
enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    link/ether 02:78:91:00:12:02 brd ff:ff:ff:ff:ff:ff
    inet 198.18.210.1/30 brd 198.18.210.3 scope global enp0s3
    RX: bytes packets errors dropped overrun mcast
          476       9      0       1       0     2
    TX: bytes packets errors dropped carrier collisions
          928      10      0       0       0          0
enp0s8: <BROADCAST,MULTICAST> mtu 1500 state DOWN
eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet 192.168.77.1/24 brd 192.168.77.255 scope global eth2
"""
    interface_reads = 0

    def route(protocol, interface, *, installed=True, gateway=None):
        hop = {"fib": True, "active": True, "interfaceName": interface}
        if gateway:
            hop["ip"] = gateway
        return {
            "protocol": protocol, "selected": True, "installed": installed,
            "table": 254, "distance": 1, "metric": 20, "nexthops": [hop],
        }

    routes = {
        "0.0.0.0/0": [
            route("static", "enp0s3", installed=False, gateway="198.18.210.3"),
            route("static", "enp0s3", gateway="198.18.210.2"),
        ],
        "198.18.210.0/30": [route("connected", "enp0s3")],
        "192.168.77.0/24": [route("connected", "eth2")],
    }
    ipv6_routes = {
        "2001:db8:99::/64": [
            route("static", "enp0s8", installed=False, gateway="2001:db8:7::2"),
            route("static", "enp0s3", gateway="fe80::2"),
        ],
    }

    def open_request(_opener, request, *, timeout):
        nonlocal interface_reads
        assert request.full_url == "https://192.168.77.1/show"
        assert timeout > 0
        form = parse_qs(request.data.decode())
        assert form["key"] == ["test-lab-token"]
        operation = json.loads(form["data"][0])
        assert operation["op"] == "show"
        if operation["path"] == ["interfaces", "detail"]:
            interface_reads += 1
            if interface_reads > 2:
                raise TimeoutError
            body = detail
        elif operation["path"] == ["ip", "route", "json"]:
            body = json.dumps(routes)
        elif operation["path"] == ["ipv6", "route", "json"]:
            if interface_reads == 2:
                raise TimeoutError
            body = json.dumps(ipv6_routes)
        elif operation["path"] in (["ip", "neighbors"], ["ipv6", "neighbors"]):
            body = "Address    Interface    Link layer address    State\n---------  -----------  --------------------  -------\n"
        elif operation["path"] == ["system", "uptime"]:
            body = "Uptime: 5m\n"
        elif operation["path"] == ["system", "processes", "extensive"]:
            body = "%Cpu(s): 4.0 us, 1.0 sy, 0.0 ni, 95.0 id, 0.0 wa, 0.0 hi, 0.0 si, 0.0 st\n"
        elif operation["path"] == ["system", "memory", "detail"]:
            body = "MemTotal: 4000000 kB\nMemAvailable: 3000000 kB\n"
        else:
            assert operation["path"] == ["dhcp", "server", "leases"]
            body = "DHCP server is not configured\n"
        return io.BytesIO(json.dumps({"success": True, "data": body}).encode())

    def create_context(*, cafile):
        assert cafile == "lab-ca.pem"
        return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", open_request)
    monkeypatch.setattr(ssl, "create_default_context", create_context)

    collector = VyOSCollector(gateway_config)
    assert collector.data["links"] == {
        "eth0": {"enable": True, "up": True},
        "eth1": {"enable": False, "up": False},
    }
    assert collector.data["ifstat"]["eth0"]["rx_bytes"] == "476"
    assert collector.data["ifstat"]["eth0"]["tx_bytes"] == "928"
    assert collector.data["system_stats"] == {"cpu": 5.0, "mem": 25.0}
    assert collector.data["ip"] == {"eth0": {"address": "198.18.210.1", "netmask": "255.255.255.252"}}
    assert "eth1" not in collector.data["ifstat"]
    assert collector.data["routes"] == [
        {"pfx": "0.0.0.0/0", "nh": [{"intf": "eth0", "t": "S>*", "via": "198.18.210.2", "metric": "1/20"}]},
        {"pfx": "198.18.210.0/30", "nh": [{"intf": "eth0", "t": "C>*"}]},
        {"pfx": "2001:db8:99::/64", "nh": [{"intf": "eth0", "t": "S>*", "via": "fe80::2", "metric": "1/20"}]},
    ]

    collector.update()
    assert [row["pfx"] for row in collector.data["routes"]] == ["0.0.0.0/0", "198.18.210.0/30"]
    collector.update()
    assert collector.data == {}
