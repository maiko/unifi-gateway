"""Exercise the console renderer with real SSH public-key wire data."""

from base64 import b64encode
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/vyos-inspection-ssh-bootstrap.py"
WIRE_KEY = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
KEY_DATA = b64encode(WIRE_KEY).decode("ascii")
PUBLIC_KEY = f"ssh-ed25519 {KEY_DATA} bridge-inspection\n"


def render(tmp_path, *, user="vyos", source="192.0.2.2", public_key=PUBLIC_KEY, arguments=()):
    origin = tmp_path / "inspection.pub"
    origin.write_bytes(public_key.encode("utf-8"))
    return subprocess.run(
        [sys.executable, str(SCRIPT), f"--user={user}", f"--source-ip={source}",
         "--public-key", str(origin), *arguments],
        capture_output=True, text=True, check=False,
    )


def test_renders_one_key_for_the_fixed_inspection_command_and_source(tmp_path):
    result = render(tmp_path, public_key=f"ssh-ed25519 {KEY_DATA} ignored 'comment'\r\n")
    prefix = "set system login user 'vyos' authentication public-keys 'unifi-gateway-inspection'"
    options = (
        "restrict,from=&quot;192.0.2.2/32&quot;,"
        "command=&quot;sudo -n /opt/unifi-gateway-vyos-inspection/run&quot;"
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        f"{prefix} type 'ssh-ed25519'",
        f"{prefix} key '{KEY_DATA}'",
        f"{prefix} options '{options}'",
    ]


def test_optionally_adds_one_explicit_router_listener(tmp_path):
    result = render(tmp_path, arguments=("--listen-address", "192.0.2.15"))
    assert result.returncode == 0, result.stderr
    service_changes = [line for line in result.stdout.splitlines() if "set service" in line]
    assert service_changes == ["set service ssh listen-address '192.0.2.15'"]


def test_restart_key_runs_only_the_saved_state_preflight(tmp_path):
    result = render(tmp_path, arguments=("--restart-preflight",))
    prefix = "set system login user 'vyos' authentication public-keys 'unifi-gateway-restart-preflight'"
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        f"{prefix} type 'ssh-ed25519'",
        f"{prefix} key '{KEY_DATA}'",
        f"{prefix} options 'restrict,from=&quot;192.0.2.2/32&quot;,command=&quot;"
        "/usr/bin/sg vyattacfg -c /config/scripts/vyos-restart-preflight.vbash&quot;'",
    ]


def test_routing_observer_key_runs_only_the_fixed_read_only_reader(tmp_path):
    result = render(tmp_path, arguments=("--routing-observer",))
    prefix = "set system login user 'vyos' authentication public-keys 'unifi-gateway-routing-observer'"
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        f"{prefix} type 'ssh-ed25519'",
        f"{prefix} key '{KEY_DATA}'",
        f"{prefix} options 'restrict,from=&quot;192.0.2.2/32&quot;,command=&quot;"
        "/usr/bin/python3 -I /config/scripts/vyos-routing-observer.py --ssh-observer&quot;'",
    ]


@pytest.mark.parametrize(("settings", "suffix"), [
    ((), ""),
    (("--shadow-lan-interface", "eth3.110", "--shadow-lan-prefix", "192.0.2.0/24",
      "--shadow-lan-probe", "192.0.2.7"), " eth3.110 192.0.2.0/24 192.0.2.7"),
    (("--shadow-lan-interface", "br0", "--shadow-lan-prefix", "192.0.2.0/24", "--shadow-lan-probe", "192.0.2.7",
      "--shadow-lan-local", "192.0.2.2", "--shadow-lan-peer", "192.0.2.3"),
     " br0 192.0.2.0/24 192.0.2.7 192.0.2.2 192.0.2.3"),
])
def test_shadow_key_pins_the_router_local_observer_scope(tmp_path, settings, suffix):
    result = render(tmp_path, arguments=("--shadow-interconnect", "eth2", *settings))
    prefix = "set system login user 'vyos' authentication public-keys 'unifi-gateway-shadow-observer'"
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        f"{prefix} type 'ssh-ed25519'",
        f"{prefix} key '{KEY_DATA}'",
        f"{prefix} options 'restrict,from=&quot;192.0.2.2/32&quot;,command=&quot;"
        f"/usr/bin/python3 -I /config/scripts/vyos-shadow-peer.py eth2{suffix}&quot;'",
    ]


def test_shadow_receipt_key_runs_only_the_fixed_manager_from_the_bridge_source(tmp_path):
    result = render(tmp_path, user="shadow-bridge", source="192.0.2.28", arguments=("--shadow-receipt-control",))
    prefix = "set system login user 'shadow-bridge' authentication public-keys 'unifi-gateway-shadow-receipt'"
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        f"{prefix} type 'ssh-ed25519'",
        f"{prefix} key '{KEY_DATA}'",
        f"{prefix} options 'restrict,from=&quot;192.0.2.28/32&quot;,command=&quot;"
        "/usr/bin/sudo -n /usr/bin/python3 -I /config/unifi-gateway-shadow/policy.py --manage&quot;'",
    ]


@pytest.mark.parametrize("other_mode", [
    ("--restart-preflight",),
    ("--routing-observer",),
    ("--wan-group", "WAN", "--wan-interface", "eth3.210", "--wan-target", "198.18.210.2"),
    ("--shadow-interconnect", "eth2"),
    ("--shadow-lan-probe", "192.0.2.7"),
])
def test_shadow_receipt_control_requires_a_separate_key(tmp_path, other_mode):
    result = render(tmp_path, arguments=("--shadow-receipt-control", *other_mode))
    assert result.returncode != 0
    assert not result.stdout
    assert "separate keys" in result.stderr


@pytest.mark.parametrize("settings", [
    ("--shadow-interconnect", "eth2;false"),
    ("--shadow-interconnect", "eth2", "--restart-preflight"),
    ("--shadow-interconnect", "eth2", "--shadow-lan-interface", "eth3"),
    ("--shadow-lan-interface", "eth3", "--shadow-lan-prefix", "192.0.2.0/24", "--shadow-lan-probe", "192.0.2.7"),
    ("--shadow-interconnect", "eth2", "--shadow-lan-interface", "eth2",
     "--shadow-lan-prefix", "192.0.2.0/24", "--shadow-lan-probe", "192.0.2.7"),
    ("--shadow-interconnect", "eth2", "--shadow-lan-interface", "eth3",
     "--shadow-lan-prefix", "192.0.2.0/24", "--shadow-lan-probe", "192.0.2.255"),
    ("--shadow-interconnect", "eth2", "--shadow-lan-interface", "eth3",
     "--shadow-lan-prefix", "192.0.2.0/24", "--shadow-lan-probe", "198.18.0.7"),
])
def test_invalid_shadow_observer_scope_renders_no_key(tmp_path, settings):
    result = render(tmp_path, arguments=settings)
    assert result.returncode == 1
    assert not result.stdout


@pytest.mark.parametrize("other_mode", [
    ("--restart-preflight",),
    ("--wan-group", "WAN", "--wan-interface", "eth3.210", "--wan-target", "198.18.210.2"),
    ("--wan-target", "198.18.210.2"),
])
def test_routing_observer_key_mode_is_mutually_exclusive(tmp_path, other_mode):
    result = render(tmp_path, arguments=("--routing-observer", *other_mode))
    assert result.returncode != 0
    assert not result.stdout
    assert "separate keys" in result.stderr


@pytest.mark.parametrize(("group", "slot"), [
    ("WAN", "wan1"), ("WAN2", "wan2"), ("WAN3", "wan3"),
])
def test_wan_key_runs_only_the_fixed_source_bound_probe(tmp_path, group, slot):
    result = render(tmp_path, arguments=(
        "--wan-group", group, "--wan-interface", "eth3.210", "--wan-target", "198.18.210.2",
        "--listen-address", "192.0.2.15",
    ))
    prefix = f"set system login user 'vyos' authentication public-keys 'unifi-gateway-{slot}-probe'"
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        f"{prefix} type 'ssh-ed25519'",
        f"{prefix} key '{KEY_DATA}'",
        f"{prefix} options 'restrict,from=&quot;192.0.2.2/32&quot;,command=&quot;"
        "/usr/bin/env LC_ALL=C /usr/bin/ping -4 -n -q -I eth3.210 -c 3 -i 0.2 -W 2 198.18.210.2&quot;'",
        "set service ssh listen-address '192.0.2.15'",
    ]


@pytest.mark.parametrize(("arguments", "message"), [
    (("--wan-group", "WAN", "--wan-interface", "eth0"), "require"),
    (("--wan-interface", "eth0", "--wan-target", "192.0.2.5"), "require"),
    (("--wan-group", "WAN4", "--wan-interface", "eth0", "--wan-target", "192.0.2.5"), "invalid choice"),
    (("--wan-group", "WAN", "--wan-interface", "eth0;false", "--wan-target", "192.0.2.5"), "interface"),
    (("--wan-group", "WAN", "--wan-interface", "192.0.2.5", "--wan-target", "192.0.2.5"), "interface"),
    (("--wan-group", "WAN", "--wan-interface", "eth0", "--wan-target", "router.example"), "unicast IPv4"),
])
def test_invalid_wan_probe_input_yields_no_commands(tmp_path, arguments, message):
    result = render(tmp_path, arguments=arguments)
    assert result.returncode != 0
    assert not result.stdout
    assert message in result.stderr


def test_accepts_the_transport_username_length_limit(tmp_path):
    assert render(tmp_path, user="a" * 32).returncode == 0
    assert render(tmp_path, user="a" * 33).returncode != 0


@pytest.mark.parametrize("user", ["root", "a'b", "bad user", "bad\nnext", "-other"])
def test_rejects_unsafe_or_root_account_names(tmp_path, user):
    result = render(tmp_path, user=user)
    assert result.returncode != 0
    assert not result.stdout
    assert "account" in result.stderr


@pytest.mark.parametrize("address", ["0.0.0.0", "0.0.0.1", "127.0.0.1", "224.1.2.3", "255.255.255.255",
                                     "192.0.2.0/24", "::1", "192.0.2.2,192.0.2.3"])
def test_rejects_sources_other_than_one_unicast_ipv4_address(tmp_path, address):
    result = render(tmp_path, source=address)
    assert result.returncode != 0
    assert not result.stdout
    assert "unicast IPv4" in result.stderr


@pytest.mark.parametrize("public_key", [
    PUBLIC_KEY + PUBLIC_KEY,
    f"ssh-rsa {KEY_DATA}",
    f"ssh-ed25519 {KEY_DATA[:-1]}?",
    f"ssh-ed25519 {b64encode(WIRE_KEY[:-1]).decode('ascii')}",
    f"ssh-ed25519 {b64encode(WIRE_KEY.replace(b'ssh-ed25519', b'dsa-ed25519')).decode('ascii')}",
    "-----BEGIN OPENSSH PRIVATE KEY-----\nprivate material\n-----END OPENSSH PRIVATE KEY-----",
])
def test_rejects_malformed_mismatched_or_private_keys(tmp_path, public_key):
    result = render(tmp_path, public_key=public_key)
    assert result.returncode != 0
    assert not result.stdout
    assert "ED25519 public key" in result.stderr
    assert "private material" not in result.stderr


@pytest.mark.parametrize("address", ["0.0.0.0", "192.0.2.2"])
def test_requires_an_explicit_distinct_listener_when_requested(tmp_path, address):
    result = render(tmp_path, arguments=("--listen-address", address))
    assert result.returncode != 0
    assert not result.stdout
    assert "listener" in result.stderr
