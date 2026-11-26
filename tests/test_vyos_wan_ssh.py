import json

import pytest

from backends import vyos_wan_quality
from backends.vyos import VyOSReadError


PORT = {"ifname": "eth0", "type": "wan", "realif": "eth3.210"}
TARGET = "198.18.210.2"
ORIGIN = "https://192.168.77.1:8443"
HEADER = (
    b"PING 198.18.210.2 (198.18.210.2) from 198.18.210.1 eth3.210: 56(84) bytes of data.\n\n"
    b"--- 198.18.210.2 ping statistics ---\n"
)


def options():
    return {
        "ssh_user": "vyos", "ssh_known_hosts_file": "/etc/lab/known-wan",
        "probes": json.dumps({"eth0": {"target": TARGET, "ssh_key_file": "/etc/lab/wan1-key"}}),
    }


@pytest.mark.parametrize(("reply", "status", "received", "latency"), [
    (b"3 packets transmitted, 3 received, 0% packet loss, time 405ms\n"
     b"rtt min/avg/max/mdev = 0.403/0.459/0.539/0.057 ms\n", 0, 3, 0.459),
    (b"3 packets transmitted, 0 received, 100% packet loss, time 409ms\n", 1, 0, None),
])
def test_direct_wan_probe_uses_the_pinned_router_and_parses_exit_one_as_measured_loss(
    monkeypatch, reply, status, received, latency,
):
    argv = ["/usr/bin/ssh", "192.168.77.1", "/bin/false"]

    def pinned(host, port, user, key, known):
        assert (host, port, user, key, known) == (
            "192.168.77.1", 22, "vyos", "/etc/lab/wan1-key", "/etc/lab/known-wan",
        )
        return argv

    monkeypatch.setattr(vyos_wan_quality, "vyos_ssh_command", pinned, raising=False)
    monkeypatch.setattr(vyos_wan_quality, "_run_helper", lambda command, **_: (HEADER + reply, status), raising=False)
    name, probe = vyos_wan_quality.configured_wan_probes(options(), [PORT], api_url=ORIGIN)["WAN"]
    assert name == "eth0"
    assert probe.read() == {
        "interface": "eth3.210", "target": TARGET, "sent": 3, "received": received, "latency_ms": latency,
    }


def test_direct_wan_probe_rejects_a_different_management_host_and_unrelated_reply(monkeypatch):
    monkeypatch.setattr(vyos_wan_quality, "vyos_ssh_command", lambda *_: ["ssh"], raising=False)
    monkeypatch.setattr(vyos_wan_quality, "_run_helper", lambda *_, **_kw: (b"shell disabled\n", 1), raising=False)
    with pytest.raises(ValueError, match="same VyOS management host"):
        vyos_wan_quality.configured_wan_probes(options() | {"ssh_host": "192.168.77.2"}, [PORT], api_url=ORIGIN)

    _, probe = vyos_wan_quality.configured_wan_probes(options(), [PORT], api_url=ORIGIN)["WAN"]
    with pytest.raises(VyOSReadError, match="invalid or mismatched"):
        probe.read()


def test_direct_wan_probe_reports_ssh_failure_without_exposing_command_output(monkeypatch):
    monkeypatch.setattr(vyos_wan_quality, "vyos_ssh_command", lambda *_: ["ssh"], raising=False)
    monkeypatch.setattr(
        vyos_wan_quality, "_run_helper",
        lambda *_, **_kw: (b"Warning from a private SSH endpoint", 255), raising=False,
    )
    _, probe = vyos_wan_quality.configured_wan_probes(options(), [PORT], api_url=ORIGIN)["WAN"]

    with pytest.raises(VyOSReadError, match="SSH transport failed.*exit 255") as error:
        probe.read()
    assert "private SSH endpoint" not in str(error.value)
