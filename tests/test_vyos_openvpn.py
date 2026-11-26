import base64
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from provisioners.uxg_openvpn import OpenVpnClientIntent
from provisioners.vyos_openvpn import (
    OpenVpnPlanError,
    OpenVpnScope,
    plan_openvpn,
    read_openvpn_state,
)


SCOPE = OpenVpnScope(server_name="router.example.net")
LIVE = {"eth3.210": (["UP", "LOWER_UP"], "\n    inet 198.18.210.1/30\n")}
USER = "synthetic-lab-username"
PASSWORD = "synthetic-lab-password"


def _pem(label, value):
    return (
        f"-----BEGIN {label}-----\n".encode()
        + base64.b64encode(value)
        + f"\n-----END {label}-----\n".encode()
    )


CLIENT = OpenVpnClientIntent(
    "1",
    "198.18.210.2",
    19443,
    "router.example.net",
    USER,
    PASSWORD,
    _pem("CERTIFICATE", b"synthetic ca body"),
    _pem("CERTIFICATE", b"synthetic client certificate body"),
    _pem("PRIVATE KEY", b"synthetic client private key body"),
)


def _apply(config, commands):
    """Apply the plan's API operations to an in-memory config tree."""
    result = deepcopy(config)
    for command in commands:
        path = command["path"]
        if command["op"] == "delete":
            node = result
            for part in path[:-1]:
                node = node[part]
            del node[path[-1]]
            continue
        node = result
        is_flag = path[-1] in {"disable-forwarding", "no-default-link-local"}
        for part in path[: -1 if is_flag else -2]:
            node = node.setdefault(part, {})
        if is_flag:
            node[path[-1]] = {}
            continue
        key, value = path[-2:]
        if key == "openvpn-option":
            node.setdefault(key, []).append(value)
        else:
            node[key] = value
    return result


def _plan(intent=CLIENT, *, current=None, previous=None, live=LIVE):
    return plan_openvpn(
        intent, SCOPE, current=current, previous=previous, live_interfaces=live
    )


def test_create_uses_stock_pki_leaves_and_confined_tls_client_options():
    plan = _plan()
    tree = _apply({}, plan.commands)
    interface = tree["interfaces"]["openvpn"]["vtun246"]
    assert interface["mode"] == "client"
    assert interface["device-type"] == "tun"
    assert (interface["ip-version"], interface["protocol"]) == ("ipv4", "udp")
    assert (interface["remote-host"], interface["remote-port"]) == ("198.18.210.2", "19443")
    assert interface["tls"] == {
        "ca-certificate": SCOPE.ca_name,
        "certificate": SCOPE.certificate_name,
        "tls-version-min": "1.2",
    }
    assert interface["encryption"] == {"data-ciphers": "aes256gcm"}
    assert interface["hash"] == "sha256"
    assert interface["authentication"] == {"username": USER, "password": PASSWORD}
    assert "local-host" not in interface
    assert interface["ipv6"] == {"disable-forwarding": {}}
    assert {
        "--bind-dev eth3.210",
        "--remote-cert-tls server",
        "--verify-x509-name router.example.net name",
        "--topology subnet",
        "--ifconfig 172.29.94.2 255.255.255.248",
        "--route-nopull",
        "--route-noexec",
        "--pull-filter ignore ifconfig",
        "--pull-filter ignore topology",
        "--pull-filter ignore route",
        "--pull-filter ignore redirect-",
        "--pull-filter ignore dhcp-option",
        "--pull-filter ignore dns",
        "--pull-filter ignore bind-dev",
    } <= set(interface["openvpn-option"])
    assert tree["pki"]["ca"][SCOPE.ca_name] == {
        "certificate": "c3ludGhldGljIGNhIGJvZHk=",
    }
    assert tree["pki"]["certificate"][SCOPE.certificate_name]["private"] == {
        "key": "c3ludGhldGljIGNsaWVudCBwcml2YXRlIGtleSBib2R5",
    }
    assert read_openvpn_state(tree, SCOPE) == plan.expected


def test_readback_normalizes_stock_leaf_lists_and_redacts_secrets():
    plan = _plan()
    tree = _apply({}, plan.commands)
    interface = tree["interfaces"]["openvpn"]["vtun246"]
    interface["remote-host"] = [interface["remote-host"]]
    interface["encryption"]["data-ciphers"] = ["aes256gcm"]
    interface["tls"]["ca-certificate"] = [SCOPE.ca_name]
    interface["openvpn-option"].reverse()
    state = read_openvpn_state(tree, SCOPE)
    assert state == plan.expected
    assert json.loads(json.dumps(state)) == state
    displayed = repr(plan) + json.dumps(state)
    for raw in (USER, PASSWORD, "c3ludGhldGljIGNsaWVudCBwcml2YXRlIGtleSBib2R5"):
        assert raw not in displayed
    assert "sha256:" in displayed
    assert _plan(current=state, previous=state).commands == ()


def test_edit_and_removal_preserve_unrelated_vyos_objects():
    outside = {
        "interfaces": {"openvpn": {"vtun5": {"mode": "server"}}},
        "pki": {
            "ca": {"operator-ca": {"certificate": "operator CA"}},
            "certificate": {"operator-cert": {"certificate": "operator certificate"}},
        },
    }
    first = _plan()
    tree = _apply(outside, first.commands)
    edited = _plan(
        replace(CLIENT, remote_port=19444, password="changed-lab-password"),
        current=first.expected,
        previous=first.expected,
    )
    assert {tuple(command["path"][3:-1]) for command in edited.commands} == {
        ("remote-port",),
        ("authentication", "password"),
    }
    tree = _apply(tree, edited.commands)
    assert read_openvpn_state(tree, SCOPE) == edited.expected
    removed = _plan(None, current=edited.expected, previous=edited.expected, live={})
    assert removed.expected is None
    assert _apply(tree, removed.commands) == outside
    assert read_openvpn_state(outside, SCOPE) is None


def test_owned_readback_rejects_foreign_references_and_partial_configuration():
    tree = _apply({}, _plan().commands)
    foreign = deepcopy(tree)
    foreign["interfaces"]["openvpn"]["vtun1"] = {"tls": {"ca-certificate": [SCOPE.ca_name]}}
    with pytest.raises(OpenVpnPlanError, match="referenced"):
        read_openvpn_state(foreign, SCOPE)
    del tree["pki"]["certificate"][SCOPE.certificate_name]
    with pytest.raises(OpenVpnPlanError, match="incomplete"):
        read_openvpn_state(tree, SCOPE)


def test_owned_readback_rejects_options_or_secret_drift_before_edit_or_removal():
    initial = _plan()
    tree = _apply({}, initial.commands)
    interface = tree["interfaces"]["openvpn"]["vtun246"]
    interface["openvpn-option"].append("--redirect-gateway")
    with pytest.raises(OpenVpnPlanError, match="interface"):
        read_openvpn_state(tree, SCOPE)
    interface["openvpn-option"].pop()
    interface["authentication"]["password"] = "operator-secret"
    drift = read_openvpn_state(tree, SCOPE)
    for intent in (CLIENT, None):
        with pytest.raises(OpenVpnPlanError, match="verified ownership") as error:
            _plan(intent, current=drift, previous=initial.expected)
        assert "operator-secret" not in str(error.value)
    with pytest.raises(OpenVpnPlanError, match="verified ownership"):
        _plan(current=initial.expected)


@pytest.mark.parametrize(
    "live",
    [
        {},
        {"eth3.210": (["UP"], "\n    inet 198.18.210.1/30\n")},
        {"eth3.210": (["UP", "LOWER_UP"], "\n    inet 198.18.210.1/24\n")},
        {**LIVE, "eth5": (["UP", "LOWER_UP"], "\n    inet 198.18.210.2/30\n")},
    ],
)
def test_active_intent_requires_unambiguous_live_wan(live):
    with pytest.raises(OpenVpnPlanError, match="WAN"):
        _plan(live=live)


def test_orphan_active_interface_prevents_adoption_or_cleanup():
    with pytest.raises(OpenVpnPlanError, match="live interface"):
        _plan(None, live={**LIVE, "vtun246": (["UP"], "")})


def test_fixed_tunnel_prefix_cannot_overlap_another_interface():
    live = {**LIVE, "eth5": (["UP", "LOWER_UP"], "\n    inet 172.29.94.6/32\n")}
    with pytest.raises(OpenVpnPlanError, match="overlaps"):
        _plan(live=live)


@pytest.mark.parametrize(
    "changes",
    [
        {"remote_host": "198.18.220.2"},
        {"remote_port": 1194},
        {"server_name": "router.example.net name-prefix"},
        {"password": "multi\nline"},
        {"client_private_key_pem": b"invalid secret material"},
    ],
)
def test_untrusted_values_never_become_vyos_commands(changes):
    with pytest.raises(OpenVpnPlanError):
        _plan(replace(CLIENT, **changes))
