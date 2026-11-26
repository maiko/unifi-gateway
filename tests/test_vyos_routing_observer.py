"""Exercise the installed router observer's fixed command surface."""

import json
from pathlib import Path
import runpy
import subprocess
import sys

import pytest


_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "vyos-routing-observer.py"
_PROBE = {"destination": "198.19.210.242", "source": "192.168.120.2", "interface": "eth3.120"}
_WAN_INVENTORY = ["/usr/sbin/ip", "-j", "-4", "route", "show", "table", "all", "proto", "111"]
_WAN_LOOKUP = ["/usr/sbin/ip", "-j", "-4", "route", "get", "fibmatch", _PROBE["destination"],
               "from", _PROBE["source"], "iif", _PROBE["interface"]]
_POLICY_IP = [
    ["/usr/sbin/ip", "-j", "-N", "-4", "rule", "show"],
    ["/usr/sbin/ip", "-j", "-N", "-6", "rule", "show"],
    ["/usr/sbin/ip", "-j", "-N", "-4", "route", "show", "table", "179"],
]
_POLICY_NFT = [
    ["/usr/sbin/nft", "-j", "list", "table", "ip", "vyos_mangle"],
    ["/usr/sbin/nft", "-j", "list", "chain", "ip", "vyos_filter", "VYOS_FORWARD_filter"],
]


def _run_observer(monkeypatch, request, responses, *, argv=None):
    if argv is None:
        argv = ("--ssh-observer",) if request is not None else ()
    if request is None:
        monkeypatch.delenv("SSH_ORIGINAL_COMMAND", raising=False)
    else:
        monkeypatch.setenv("SSH_ORIGINAL_COMMAND", request)

    def run(command, *, check, capture_output, timeout, **_):
        assert check is False and capture_output is True and timeout == 2
        assert responses, f"Unexpected command: {command}"
        expected, returncode, stdout, stderr = responses.pop(0)
        assert command == expected
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(sys, "argv", [str(_SCRIPT), *argv])
    runpy.run_path(str(_SCRIPT), run_name="__main__")
    assert not responses


@pytest.mark.parametrize(("request_command", "argv"), [
    (None, ()), ("legacy direct execution", ()), ("/bin/false uxg-policy-route-fib", ("--ssh-observer",)),
])
def test_policy_mode_preserves_readback_and_elevates_only_fixed_ssh_nft_reads(monkeypatch, capsys, request_command, argv):
    nft_prefix = ["/usr/bin/sudo", "-n"] if argv else []
    responses = [
        (_POLICY_IP[0], 0, b'[{"priority":0}]\n', b""),
        (_POLICY_IP[1], 0, b"[]\n", b""),
        (_POLICY_IP[2], 2, b"[]\n", b"Error: ipv4: FIB table does not exist.\nDump terminated\n"),
        ([*nft_prefix, *_POLICY_NFT[0]], 1, b"", b"Error: No such file or directory\nlist table ip vyos_mangle\n"),
        ([*nft_prefix, *_POLICY_NFT[1]], 0, b'{"nftables":[{"chain":{}}]}\n', b""),
    ]
    _run_observer(monkeypatch, request_command, responses, argv=argv)
    assert json.loads(capsys.readouterr().out) == {
        "ipv4_rules": [{"priority": 0}], "ipv6_rules": [], "table": [],
        "nft": {"nftables": []}, "forward": {"nftables": [{"chain": {}}]},
    }


def test_wan_mode_returns_the_full_inventory_and_single_fibmatch_row(monkeypatch, capsys):
    selected = {"dst": "default", "gateway": "198.18.220.2", "dev": "eth3.220", "metric": 20, "flags": []}
    other_table = {**selected, "dst": "203.0.113.0/24", "table": "100"}
    lookup = {**selected, "protocol": "failover"}
    responses = [
        (_WAN_INVENTORY, 0, json.dumps([selected, other_table]).encode(), b""),
        (_WAN_LOOKUP, 0, json.dumps([lookup]).encode(), b""),
    ]
    _run_observer(monkeypatch, "/bin/false uxg-wan-fib", responses)
    assert json.loads(capsys.readouterr().out) == {"probe": _PROBE, "routes": [selected, other_table], "lookup": lookup}


def test_wan_mode_reports_null_for_the_exact_stock_unreachable_lookup(monkeypatch, capsys):
    responses = [
        (_WAN_INVENTORY, 0, b"[]\n", b""),
        (_WAN_LOOKUP, 2, b"", b"RTNETLINK answers: Network is unreachable\n"),
    ]
    _run_observer(monkeypatch, "/bin/false uxg-wan-fib", responses)
    assert json.loads(capsys.readouterr().out) == {"probe": _PROBE, "routes": [], "lookup": None}


@pytest.mark.parametrize(("status", "stdout", "stderr"), [
    (1, b"", b"RTNETLINK answers: Network is unreachable\n"),
    (2, b"[]\n", b"RTNETLINK answers: Network is unreachable\n"),
    (2, b"", b"Cannot find device eth3.120\n"),
])
def test_wan_mode_rejects_every_other_failed_lookup(monkeypatch, capsys, status, stdout, stderr):
    with pytest.raises(subprocess.CalledProcessError):
        _run_observer(monkeypatch, "/bin/false uxg-wan-fib", [
            (_WAN_INVENTORY, 0, b"[]\n", b""), (_WAN_LOOKUP, status, stdout, stderr),
        ])
    assert not capsys.readouterr().out


@pytest.mark.parametrize("output", [b"[]\n", b"[{},{}]\n", b"[null]\n"])
def test_wan_mode_rejects_invalid_successful_lookup_shapes(monkeypatch, capsys, output):
    with pytest.raises(ValueError, match="one route"):
        _run_observer(monkeypatch, "/bin/false uxg-wan-fib", [
            (_WAN_INVENTORY, 0, b"[]\n", b""), (_WAN_LOOKUP, 0, output, b""),
        ])
    assert not capsys.readouterr().out


@pytest.mark.parametrize(("request_command", "argv"), [
    (None, ("--ssh-observer",)),
    ("", ("--ssh-observer",)),
    ("/bin/false", ("--ssh-observer",)),
    ("/bin/false uxg-wan-fib ", ("--ssh-observer",)),
    ("/bin/false uxg-policy-route-fib\n", ("--ssh-observer",)),
    ("/bin/false uxg-wan-fib; true", ("--ssh-observer",)),
    ("/bin/false uxg-wan-fib", ("extra",)),
    (None, ("extra",)),
])
def test_observer_rejects_unapproved_commands_and_arguments_before_any_subprocess(monkeypatch, request_command, argv):
    with pytest.raises(SystemExit):
        _run_observer(monkeypatch, request_command, [], argv=argv)
