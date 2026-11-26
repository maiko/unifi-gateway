"""Verify the stock Linux ping observations exposed by the VyOS probe."""

from pathlib import Path
import runpy
import subprocess

import pytest


_SCRIPT = Path(__file__).resolve().parents[1] / "backends" / "vyos_wan_ping.py"
_TARGET = "198.18.210.2"
_INTERFACE = "eth3.210"
_HEADER = (
    b"PING 198.18.210.2 (198.18.210.2) from 198.18.210.1 eth3.210: 56(84) bytes of data.\n\n"
    b"--- 198.18.210.2 ping statistics ---\n"
)
_GOOD = b"3 packets transmitted, 3 received, 0% packet loss, time 405ms\n"
_LOSS = b"3 packets transmitted, 0 received, 100% packet loss, time 409ms\n"
_RTT = b"rtt min/avg/max/mdev = 0.403/0.459/0.539/0.057 ms\n"


@pytest.fixture
def probe():
    return runpy.run_path(str(_SCRIPT))["probe"]


@pytest.mark.parametrize(("summary", "code", "received", "latency"), [
    (_GOOD + _RTT, 0, 3, 0.459),
    (b"3 packets transmitted, 2 received, 33.3333% packet loss, time 410ms\n" + _RTT, 0, 2, 0.459),
    (_LOSS, 1, 0, None),
])
def test_reads_counts_and_latency_from_the_pinned_interface(monkeypatch, probe, summary, code, received, latency):
    def run(command, **kwargs):
        assert command == ["/usr/bin/ping", "-4", "-n", "-q", "-I", _INTERFACE,
                           "-c", "3", "-i", "0.2", "-W", "2", _TARGET]
        assert kwargs["timeout"] == 4
        assert kwargs["env"] == {"LC_ALL": "C"}
        return subprocess.CompletedProcess(command, code, _HEADER + summary, b"")

    monkeypatch.setattr(subprocess, "run", run)
    assert probe(_INTERFACE, _TARGET) == {
        "interface": _INTERFACE, "target": _TARGET, "sent": 3, "received": received, "latency_ms": latency,
    }


@pytest.mark.parametrize(("output", "code", "stderr"), [
    (_HEADER + _LOSS, 2, b"ping: SO_BINDTODEVICE eth3.210: No such device\n"),
    (_HEADER + _GOOD + _RTT, 0, b"WARNING: source address might be selected on another device\n"),
    (_HEADER + b"0 packets transmitted, 0 received, 0% packet loss, time 2ms\n", 1, b""),
    (_HEADER + b"2 packets transmitted, 0 received, 100% packet loss, time 203ms\n", 1, b""),
    (_HEADER + _GOOD, 0, b""),
    (_HEADER + _LOSS + _RTT, 1, b""),
    (_HEADER + _GOOD + _RTT, 1, b""),
    (_HEADER.replace(b"198.18.210.2", b"198.18.220.2") + _GOOD + _RTT, 0, b""),
    (_HEADER + _GOOD + _RTT.replace(b"0.459", b"9.123"), 0, b""),
    (_HEADER + b"a" * 4097, 0, b""),
])
def test_incomplete_or_inconsistent_output_is_unavailable(monkeypatch, probe, output, code, stderr):
    monkeypatch.setattr(subprocess, "run", lambda cmd, **_kw: subprocess.CompletedProcess(cmd, code, output, stderr))
    with pytest.raises(ValueError, match="WAN probe"):
        probe(_INTERFACE, _TARGET)


@pytest.mark.parametrize(("interface", "target"), [
    ("--help", _TARGET), ("192.168.1.2", _TARGET), ("eth0 long", _TARGET), ("eth0;false", _TARGET),
    (_INTERFACE, "localhost"), (_INTERFACE, "::1"), (_INTERFACE, "127.0.0.1"), (_INTERFACE, "224.0.0.1"),
    (_INTERFACE, "255.255.255.255"), (_INTERFACE, "0.0.0.1"),
])
def test_rejects_non_interface_and_non_unicast_arguments_before_start(monkeypatch, probe, interface, target):
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_kw: pytest.fail("Invalid arguments reached ping"))
    with pytest.raises(ValueError, match="WAN probe"):
        probe(interface, target)


def test_process_timeout_is_not_packet_loss(monkeypatch, probe):
    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], _HEADER + _LOSS)

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(ValueError, match="timed out"):
        probe(_INTERFACE, _TARGET)
