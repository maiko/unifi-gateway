"""Exercise the bounded, read-only VyOS failover helper with real processes."""

import json
from configparser import RawConfigParser
import sys

import pytest

from backends import vyos_failover
from backends.vyos import VyOSReadError


PROBE = {"destination": "198.19.210.242", "source": "192.168.120.2", "interface": "eth3.120"}
PRIMARY = {"dst": "198.19.210.242", "gateway": "198.18.210.2", "dev": "eth3.210", "metric": 10, "flags": []}
BACKUP = {"dst": "198.19.210.242", "gateway": "198.18.220.2", "dev": "eth3.220", "metric": 20, "flags": []}


def _helper(tmp_path, source):
    path = tmp_path / "failover reader"
    path.write_text(f"#!{sys.executable}\n{source}\n", encoding="utf-8")
    path.chmod(0o700)
    return str(path)


def _helper_payload(tmp_path, payload):
    return _helper(tmp_path, f"print({json.dumps(payload)!r})")


def test_reads_inventory_and_lookup_from_one_executable_invocation(tmp_path):
    payload = {"probe": PROBE, "routes": [PRIMARY, BACKUP], "lookup": {**PRIMARY, "protocol": "failover"}}
    command = _helper(tmp_path, f"import sys\nassert len(sys.argv) == 1\nprint({json.dumps(payload)!r})")
    assert vyos_failover.read_failover_fib(command) == payload


def test_pinned_routing_ssh_selects_only_the_fixed_snapshot_commands(monkeypatch):
    from provisioners.vyos_pbr import read_policy_route_fib

    config = RawConfigParser()
    config.read_dict({"vyos": {"api_url": "https://192.0.2.5:8443"}, "vyos_routing_ssh": {
        "ssh_port": "2222", "ssh_user": "vyos", "ssh_key_file": "/run/routing-key", "ssh_known_hosts_file": "/run/routing-pin",
    }})
    argv = ["/usr/bin/ssh", "-i", "/run/routing-key", "--", "192.0.2.5", "/bin/false"]

    def ssh(host, port, user, key, pin):
        assert (host, port, user, key, pin) == ("192.0.2.5", 2222, "vyos", "/run/routing-key", "/run/routing-pin")
        return argv

    wan = {"probe": PROBE, "routes": [PRIMARY], "lookup": {**PRIMARY, "protocol": "failover"}}
    policy = {"ipv4_rules": [], "ipv6_rules": [], "table": [], "nft": {"nftables": []}, "forward": {"nftables": []}}

    def run(command, *, reader):
        assert command[:-1] == argv[:-1]
        data = {"/bin/false uxg-wan-fib": wan, "/bin/false uxg-policy-route-fib": policy}[command[-1]]
        return json.dumps(data).encode(), 0

    monkeypatch.setattr(vyos_failover, "vyos_ssh_command", ssh, raising=False)
    monkeypatch.setattr(vyos_failover, "_run_helper", run)
    observer = vyos_failover.VyOSRoutingSSH.from_config(config)
    assert observer.endpoint == {"host": "192.0.2.5", "port": 2222, "user": "vyos"}
    assert vyos_failover.read_failover_fib(observer) == wan
    assert read_policy_route_fib(observer) == policy


def test_preserves_foreign_route_evidence_for_the_owner_check(tmp_path):
    foreign = {**BACKUP, "dst": "203.0.113.0/24", "table": "100"}
    payload = {"probe": PROBE, "routes": [foreign], "lookup": None}
    assert vyos_failover.read_failover_fib(_helper_payload(tmp_path, payload)) == payload


def test_distinguishes_no_failover_route_from_a_default_fib_fallback(tmp_path):
    lookup = {"dst": "default", "gateway": "198.18.220.2", "dev": "eth3.220", "protocol": "static", "flags": []}
    payload = {"probe": PROBE, "routes": [], "lookup": lookup}
    assert vyos_failover.read_failover_fib(_helper_payload(tmp_path, payload)) == payload


def test_accepts_a_selected_protocol_111_default_route_for_the_same_probe(tmp_path):
    route = {**PRIMARY, "dst": "default"}
    lookup = {**route, "protocol": "failover"}
    payload = {"probe": PROBE, "routes": [route], "lookup": lookup}
    assert vyos_failover.read_failover_fib(_helper_payload(tmp_path, payload)) == payload


@pytest.mark.parametrize("payload", [
    {"probe": PROBE, "routes": [], "lookup": [], "extra": "ignored"},
    {"probe": {**PROBE, "source": "192.168.120.3"}, "routes": [], "lookup": None},
    {"probe": PROBE, "routes": [{**PRIMARY, "metric": True}], "lookup": None},
    {"probe": PROBE, "routes": [{**PRIMARY, "protocol": "static"}], "lookup": None},
    {"probe": PROBE, "routes": [{**PRIMARY, "multipath": [BACKUP]}], "lookup": None},
    {"probe": PROBE, "routes": [PRIMARY], "lookup": {**BACKUP, "protocol": "failover"}},
    {"probe": PROBE, "routes": [], "lookup": {**PRIMARY, "dst": "203.0.113.1", "protocol": "static"}},
])
def test_rejects_incomplete_wrong_probe_or_inconsistent_snapshots(tmp_path, payload):
    with pytest.raises(VyOSReadError, match="snapshot"):
        vyos_failover.read_failover_fib(_helper_payload(tmp_path, payload))


@pytest.mark.parametrize("output", ["sensitive-not-json", '{"probe":0,"probe":1}', '{"routes":NaN}'])
def test_invalid_json_errors_do_not_expose_helper_output(tmp_path, output):
    command = _helper(tmp_path, f"print({output!r})")
    with pytest.raises(VyOSReadError, match="JSON") as caught:
        vyos_failover.read_failover_fib(command)
    assert output not in str(caught.value)
    assert caught.value.__suppress_context__


def test_requires_absolute_executable_paths():
    with pytest.raises(VyOSReadError, match="absolute executable"):
        vyos_failover.read_failover_fib("read-failover")


def test_cannot_start_missing_helper(tmp_path):
    with pytest.raises(VyOSReadError, match="could not start"):
        vyos_failover.read_failover_fib(str(tmp_path / "missing"))


def test_failed_exit_never_exposes_stdout_or_stderr(tmp_path, capfd):
    command = _helper(tmp_path, "import sys\nprint('private-output')\nprint('private-error', file=sys.stderr)\nsys.exit(4)")
    with pytest.raises(VyOSReadError, match="exited unsuccessfully") as caught:
        vyos_failover.read_failover_fib(command)
    assert "private-" not in str(caught.value)
    assert capfd.readouterr() == ("", "")


def test_stops_oversized_output_without_waiting_for_the_helper_to_finish(tmp_path):
    command = _helper(tmp_path, "import sys, time\nsys.stdout.write('x' * 262145)\nsys.stdout.flush()\ntime.sleep(10)")
    with pytest.raises(VyOSReadError, match="size limit"):
        vyos_failover.read_failover_fib(command)


def test_times_out_if_helper_closes_stdout_without_exiting(tmp_path, monkeypatch):
    monkeypatch.setattr(vyos_failover, "_TIMEOUT_SECONDS", 0.2)
    command = _helper(tmp_path, "import os, time\nos.close(1)\ntime.sleep(10)")
    with pytest.raises(VyOSReadError, match="timed out"):
        vyos_failover.read_failover_fib(command)
