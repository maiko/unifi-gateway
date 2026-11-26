"""Exercise VyOS client telemetry with the lab's operational table formats."""

from configparser import ConfigParser
import json
from types import SimpleNamespace

import pytest

from backends.vyos import VyOSReadError
from backends import vyos_wan_quality
from collectors import vyos


INTERFACES = """\
eth3.110@eth3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet 192.168.110.1/24 scope global eth3.110
    inet 192.168.111.1/24 scope global secondary eth3.110
    inet6 fe80::78:91ff:fe00:1202/64 scope link
    inet6 fd00:110::1/64 scope global
    inet6 fd00:110::2/64 scope global tentative
eth3.120@eth3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet 192.168.120.1/24 scope global eth3.120
eth3.220@eth3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet 198.18.220.1/30 scope global eth3.220
eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet 192.168.77.1/24 scope global eth2
    inet6 fd00:77::1/64 scope global
"""
ARP = """\
Address        Interface    Link layer address    State
-------------  -----------  --------------------  ---------
192.168.110.2  eth3.110     02:78:91:00:11:03     STALE
192.168.120.2  eth3.120     02:78:91:00:11:03     REACHABLE
192.168.120.3  eth3.120                           FAILED
192.168.77.2   eth2         02:78:91:00:11:02     REACHABLE
198.18.220.2   eth3.220     02:78:91:00:11:02     REACHABLE
"""
NDP = """\
Address                  Interface    Link layer address    State
-----------------------  -----------  --------------------  ---------
fe80::78:91ff:fe00:1103  eth3.110     02:78:91:00:11:03     STALE
fe80::78:91ff:fe00:1103  eth3.220     02:78:91:00:11:03     STALE
"""
LEASES = """\
IP Address     MAC address        State    Lease start          Lease expiration     Remaining    Pool      Hostname      Origin
-------------  -----------------  -------  -------------------  -------------------  -----------  --------  ------------  --------
192.168.110.2  02:78:91:00:11:03  active   2026-11-24 14:00:00  2026-11-24 15:00:00  0:59:27      inside    wired-client  local
192.168.120.3  02:78:91:00:11:04  active   2026-11-24 14:00:00  2026-11-24 15:00:00  0:59:27                              remote
192.168.111.4  02:78:91:00:11:05  active   2026-11-24 14:00:00  2026-11-24 15:00:00  0:59:27      Guest AP                local
192.168.120.6  02:78:91:00:11:06  expired  2026-11-24 13:00:00  2026-11-24 14:00:00  0:00:00      inside    expired       local
192.168.77.2   02:78:91:00:11:02  active   2026-11-24 14:00:00  2026-11-24 15:00:00  0:59:27      mgmt      mgmt-host     local
"""
PORTS = [
    {"ifname": "eth1", "name": "LAN", "type": "lan", "realif": "eth3.110"},
    {"ifname": "eth3", "name": "LAN2", "type": "lan2", "realif": "eth3.120"},
    {"ifname": "eth2", "name": "WAN2", "type": "wan2", "realif": "eth3.220"},
]


def _uptime_response(duration):
    return (
        f"Uptime: {duration}\n\nLoad averages:\n"
        "1  minute:   7.5%\n5  minutes:  17.0%\n15 minutes:  10.5%\n"
    )


def _make_collector(monkeypatch, *, ports=PORTS, **options):
    backend = SimpleNamespace(
        show_interfaces=lambda: INTERFACES,
        show_ipv4_routes=lambda: {},
        show_ipv6_routes=lambda: {},
        show_ipv4_neighbors=lambda: ARP,
        show_ipv6_neighbors=lambda: NDP,
        show_dhcpv4_leases=lambda: LEASES,
        show_uptime=lambda: _uptime_response("5m"),
        show_cpu_states=lambda: "header\n%Cpu(s): 7.4 us, 2.3 sy, 0.0 ni, 86.4 id, 2.0 wa, 0.0 hi, 0.9 si, 1.0 st\n",
        show_memory_detail=lambda: "MemTotal: 4000000 kB\nMemFree: 1000000 kB\nMemAvailable: 3250000 kB\n",
        show_ethernet_physical=lambda name: f"Settings for {name}:\n\tSpeed: 1000Mb/s\n\tDuplex: Half\n\tLink detected: yes\n",
    )
    monkeypatch.setattr(vyos, "VyOSBackend", lambda **_: backend)
    config = ConfigParser()
    config.read_dict({
        "gateway": {"ports": repr(ports)},
        "vyos": {"api_url": "unused", "ca_file": "unused", "key_file": "unused"},
        **options,
    })
    return vyos.VyOSCollector(config), backend


def test_media_reports_ethernet_negotiation_only_and_withdraws_unknown_fields(monkeypatch):
    direct = {"ifname": "eth0", "name": "WAN", "type": "wan", "realif": "eth2"}
    collector, backend = _make_collector(monkeypatch, ports=[direct, *PORTS])
    assert collector.data["port_media"] == {"eth0": {"speed": 1000, "full_duplex": False}}

    backend.show_ethernet_physical = lambda name: (
        f"Settings for {name}:\n\tSpeed: Unknown!\n\tDuplex: Unknown! (255)\n\tLink detected: yes\n"
    )
    collector.update()
    assert not collector.data.get("port_media")

    backend.show_ethernet_physical = lambda name: (
        f"Settings for {name}:\n\tSpeed: 1000Mb/s\n\tDuplex: Full\n\tLink detected: no\n"
    )
    collector.update()
    assert not collector.data.get("port_media")


def test_host_health_reports_measured_cpu_and_memory_and_clears_each_source(monkeypatch):
    collector, backend = _make_collector(monkeypatch)
    assert collector.data["system_stats"] == {"cpu": 11.6, "mem": 18.8}

    backend.show_cpu_states = lambda: "%Cpu(s): 0.0 us, 0.0 sy, 0.0 ni, 100.0 id, 0.0 wa, 0.0 hi, 0.0 si, 0.0 st"
    backend.show_memory_detail = lambda: "MemTotal: 100 kB\nMemAvailable: 110 kB\n"
    collector.update()
    assert collector.data["system_stats"] == {"cpu": 0.0}

    backend.show_cpu_states = lambda: "%Cpu0: 100.0 us, 0.0 id"
    collector.update()
    assert "system_stats" not in collector.data
    assert collector.data["links"]["eth2"]["up"] is True


def test_wan_health_uses_mapped_interface_and_withdraws_after_source_loss(monkeypatch):
    observation = {
        "interface": "eth3.220", "target": "198.18.220.2", "sent": 3, "received": 3, "latency_ms": 0.576,
    }
    calls = []
    now = [10.0]

    def read(command, **_):
        calls.append(command)
        return json.dumps(observation)

    monkeypatch.setattr(vyos_wan_quality, "_read_helper", read)
    monkeypatch.setattr(vyos, "time", SimpleNamespace(monotonic=lambda: now[0]))
    collector, backend = _make_collector(monkeypatch, vyos_wan_health={
        "enabled": "true",
        "probes": json.dumps({"eth2": {"target": "198.18.220.2", "command": "/opt/wan2-probe"}}),
    })
    assert collector.data["wan_health"] == {"WAN2": observation}
    assert collector.data["wan_health_durations"] == {"WAN2": {"uptime": 0, "downtime": 0}}
    assert calls == ["/opt/wan2-probe"]

    now[0] += 12
    collector.update()
    assert collector.data["wan_health_durations"] == {"WAN2": {"uptime": 12, "downtime": 0}}

    observation["interface"] = "eth3.210"
    collector.update()
    assert collector.data["wan_health"] == {"WAN2": None}
    assert collector.data["wan_health_durations"] == {}

    def unavailable():
        raise VyOSReadError("TLS connection unavailable")

    backend.show_interfaces = unavailable
    collector.update()
    assert collector.data == {"wan_health": {"WAN2": None}}
    assert calls == ["/opt/wan2-probe"] * 3


def test_wan_health_rejects_a_management_or_lan_probe_mapping(monkeypatch):
    with pytest.raises(ValueError, match="mapped WAN groups"):
        _make_collector(monkeypatch, vyos_wan_health={
            "enabled": "true",
            "probes": json.dumps({"eth1": {"target": "192.168.110.2", "command": "/opt/wan2-probe"}}),
        })


def test_wan_rates_use_real_counter_deltas_and_discard_discontinuities(monkeypatch):
    now = [10.0]
    monkeypatch.setattr(vyos, "time", SimpleNamespace(monotonic=lambda: now[0]))
    collector, backend = _make_collector(monkeypatch)

    def snapshot(rx, tx):
        backend.show_interfaces = lambda: INTERFACES.replace(
            "    inet 198.18.220.1/30 scope global eth3.220",
            "    inet 198.18.220.1/30 scope global eth3.220\n"
            f"    RX: bytes packets errors dropped missed mcast\n    {rx} 1 0 0 0 0\n"
            f"    TX: bytes packets errors dropped carrier collsns\n    {tx} 1 0 0 0 0",
        )

    def rates():
        return {key: value for key, value in collector.data["ifstat"]["eth2"].items() if key.endswith("_rate")}

    snapshot(1000, 2000)
    collector.update()
    assert rates() == {}

    now[0] += 2
    snapshot(2000, 7000)
    collector.update()
    assert rates() == {"rx_rate": 4000, "tx_rate": 20000}

    now[0] += 2
    snapshot(100, 200)
    collector.update()
    assert rates() == {}

    now[0] += 65
    snapshot(2100, 1200)
    collector.update()
    assert rates() == {}

    now[0] += 2
    backend.show_uptime = lambda: _uptime_response("3s")
    snapshot(3100, 2200)
    collector.update()
    assert rates() == {}


def test_mapped_neighbor_tables_keep_same_mac_on_distinct_lans(monkeypatch):
    collector, _ = _make_collector(monkeypatch)

    assert collector.data["neighbors"] == {
        "eth1": [
            {"ip": "192.168.110.2", "mac": "02:78:91:00:11:03", "state": "STALE"},
            {"ip": "fe80::78:91ff:fe00:1103", "mac": "02:78:91:00:11:03", "state": "STALE"},
        ],
        "eth3": [{"ip": "192.168.120.2", "mac": "02:78:91:00:11:03", "state": "REACHABLE"}],
    }


def test_dhcp_leases_scope_to_mapped_lans_with_blank_columns_intact(monkeypatch):
    collector, _ = _make_collector(monkeypatch)

    assert collector.data["dhcp_leases"] == [
        {"ip": "192.168.110.2", "mac": "02:78:91:00:11:03", "ifname": "eth1", "hostname": "wired-client"},
        {"ip": "192.168.120.3", "mac": "02:78:91:00:11:04", "ifname": "eth3"},
        {"ip": "192.168.111.4", "mac": "02:78:91:00:11:05", "ifname": "eth1"},
    ]


def test_ipv6_addresses_exclude_tentative_and_unmapped_addresses(monkeypatch):
    collector, _ = _make_collector(monkeypatch)

    assert collector.data["ipv6"] == {"eth1": ["fe80::78:91ff:fe00:1202/64", "fd00:110::1/64"]}


def test_unrecognized_ipv6_address_keeps_other_interface_telemetry(monkeypatch, caplog):
    collector, backend = _make_collector(monkeypatch)
    backend.show_interfaces = lambda: INTERFACES.replace("fd00:110::1/64", "not-an-address")

    collector.update()

    assert collector.data["ip"]["eth1"] == {"address": "192.168.110.1", "netmask": "255.255.255.0"}
    assert collector.data["ipv6"]["eth1"] == ["fe80::78:91ff:fe00:1202/64"]
    assert "VyOS IPv6 interface telemetry returned an invalid address for eth1" in caplog.text


def test_optional_read_failure_drops_stale_ipv6_neighbors_but_retains_ipv4(monkeypatch):
    collector, backend = _make_collector(monkeypatch)

    def failed_neighbors():
        raise VyOSReadError("request failed")

    backend.show_ipv6_neighbors = failed_neighbors
    backend.show_dhcpv4_leases = lambda: "DHCP server is not configured\n"
    collector.update()

    assert collector.data["neighbors"]["eth1"] == [
        {"ip": "192.168.110.2", "mac": "02:78:91:00:11:03", "state": "STALE"},
    ]
    assert collector.data["dhcp_leases"] == []


@pytest.mark.parametrize(("duration", "seconds"), [
    ("", 0), ("18s", 18), ("5m", 300), ("6m 51s", 411), ("5h 4s", 18004),
    ("1y 2w 3d 4h 5m 6s", 33041106),
])
def test_live_uptime_uses_router_duration(monkeypatch, duration, seconds):
    collector, backend = _make_collector(monkeypatch)
    backend.show_uptime = lambda: _uptime_response(duration)

    collector.update()

    assert collector.data["uptime"] == seconds


@pytest.mark.parametrize("output", ["", "Uptime: \n", "Uptime: 5m unknown", "Uptime: 5m 1m", None])
def test_unavailable_uptime_clears_previous_value_and_retains_interfaces(monkeypatch, caplog, output):
    collector, backend = _make_collector(monkeypatch)
    assert collector.data["uptime"] == 300

    def show_uptime():
        if output is None:
            raise VyOSReadError("unavailable")
        return output

    backend.show_uptime = show_uptime
    collector.update()

    assert "uptime" not in collector.data
    assert collector.data["links"]["eth1"]["up"] is True
    assert "VyOS uptime telemetry unavailable" in caplog.text
