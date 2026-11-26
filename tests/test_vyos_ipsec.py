"""Qualify the captured single-peer, policy-based IPv4 IPsec shape."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import pytest

from provisioners.vyos_ipsec import (
    IpsecIntentError,
    IpsecScope,
    decode_ipsec_intent,
    plan_ipsec_commands,
    redact_ipsec_config,
)
from provisioners.uxg_ipsec_policy import scrub_ipsec_policy


_WIRE = json.loads((Path(__file__).parent / "fixtures/uxg_pro/native-ipsec-snapshots.json").read_text())
_POLICY = json.loads((Path(__file__).parent / "fixtures/uxg_pro/native-ipsec-policy-snapshots.json").read_text())
_SECTION = "vpn/ipsec/site-to-site"
_NAME = "UXG-LAB-IPSEC"
_SCOPE = IpsecScope(
    "eth0", "eth3.210", "198.18.210.1/30", "br120", "eth3.120", "192.168.120.1/24",
    "198.18.210.2", "192.168.120.2/32", "198.19.210.240/32", _NAME,
)
_READBACK = {
    "eth3.210": (["UP", "LOWER_UP"], "    inet 198.18.210.1/30 scope global eth3.210"),
    "eth3.120": (["UP", "LOWER_UP"], "    inet 192.168.120.1/24 scope global eth3.120"),
}
_SECRET = _WIRE["entries"]["create"][0]["preSharedKey"]


def _snapshot(phase):
    udapi = deepcopy(_WIRE["envelope"])
    if _WIRE["entries"][phase] is not None:
        udapi[_SECTION] = deepcopy(_WIRE["entries"][phase])
    return {"udapi": udapi}


def _decode(phase, *, snapshot=None):
    return decode_ipsec_intent(
        json.dumps(snapshot if snapshot is not None else _snapshot(phase)), revision=phase, scope=_SCOPE,
        expected_versions=_WIRE["envelope"]["versionDetail"],
    )


def _plan(phase, *, current=None, verified=None, live=_READBACK):
    return plan_ipsec_commands(
        _decode(phase), scope=_SCOPE, current_config=current, verified_config=verified, live_interfaces=live,
    )


def _raw_config(plan):
    raw = deepcopy(plan.desired_config)
    raw["authentication"]["psk"][_NAME]["secret"] = _SECRET
    return raw


def test_native_create_owns_one_ikev2_peer_and_never_reprs_the_psk():
    intent = _decode("create")
    plan = _plan("create")
    config = plan.desired_config
    assert config["authentication"]["psk"][_NAME] == {
        "id": ["198.18.210.1", "198.18.210.2"],
        "secret": "sha256:" + sha256(_SECRET.encode("ascii")).hexdigest(),
    }
    assert config["ike-group"][_NAME] == {
        "key-exchange": "ikev2", "lifetime": "28800",
        "dead-peer-detection": {"action": "restart", "interval": "30", "timeout": "120"},
        "proposal": {"10": {"encryption": "aes256", "hash": "sha256", "dh-group": "14"}},
    }
    assert config["esp-group"][_NAME] == {
        "mode": "tunnel", "pfs": "dh-group14", "lifetime": "3600",
        "proposal": {"10": {"encryption": "aes256", "hash": "sha256"}},
    }
    assert config["interface"] == "eth3.210"
    assert config["site-to-site"]["peer"][_NAME] == {
        "local-address": "198.18.210.1", "remote-address": "198.18.210.2", "connection-type": "initiate",
        "authentication": {"mode": "pre-shared-secret", "local-id": "198.18.210.1", "remote-id": "198.18.210.2"},
        "ike-group": _NAME, "default-esp-group": _NAME,
        "tunnel": {"0": {"local": {"prefix": "192.168.120.2/32"}, "remote": {"prefix": "198.19.210.240/32"}}},
    }
    assert {"op": "set", "path": ["vpn", "ipsec", "authentication", "psk", _NAME, "secret"],
            "value": _SECRET} in plan.commands
    assert all(command["path"][:2] == ["vpn", "ipsec"] for command in plan.commands)
    assert _SECRET not in repr(intent) + repr(plan)
    assert redact_ipsec_config(_raw_config(plan), scope=_SCOPE) == config


def test_native_edit_updates_only_the_esp_lifetime_and_is_idempotent():
    created = _plan("create")
    edit = _plan("edit", current=_raw_config(created), verified=created.desired_config)
    assert edit.commands == ({
        "op": "set", "path": ["vpn", "ipsec", "esp-group", _NAME, "lifetime"], "value": "4200",
    },)
    assert not _plan("edit", current=_raw_config(edit), verified=edit.desired_config).commands


def test_delete_only_removes_the_proven_owned_ipsec_root():
    created = _plan("create")
    removed = _plan("delete", current=_raw_config(created), verified=created.desired_config)
    assert removed.desired_config is None
    assert removed.commands == ({"op": "delete", "path": ["vpn", "ipsec"]},)
    assert not _plan("off").commands


def test_planner_rejects_foreign_drift_and_unavailable_physical_links():
    created = _plan("create")
    with pytest.raises(IpsecIntentError):
        _plan("create", current=_raw_config(created))
    changed = _raw_config(created)
    changed["site-to-site"]["peer"]["OperatorVPN"] = {}
    with pytest.raises(IpsecIntentError):
        _plan("delete", current=changed, verified=created.desired_config)
    with pytest.raises(IpsecIntentError):
        _plan("edit", current=_raw_config(created), verified=created.desired_config, live={})


@pytest.mark.parametrize(
    "change",
    [
        {"enabled": False},
        {"localAddress": {"source": "interface", "id": "eth0", "ipVersion": "v4"}},
        {"remotePeer": "198.18.220.2"},
        {"remoteSubnets": ["0.0.0.0/0"]},
        {"localSubnets": ["192.168.120.0/24"]},
        {"ikeVersion": "v1"},
        {"ikeCiphers": [{"encryption": "aes128", "hash": "sha256", "dhGroup": 14}]},
        {"espCiphers": [{"encryption": "aes256", "hash": "sha256"}]},
        {"espLifetime": 3900},
        {"preSharedKey": "short"},
        {"vti": {"id": "vti0"}},
    ],
)
def test_decoder_rejects_different_peer_scope_or_unqualified_ipsec_options(change):
    snapshot = _snapshot("create")
    snapshot["udapi"][_SECTION][0].update(change)
    with pytest.raises(IpsecIntentError):
        _decode("create", snapshot=snapshot)


def test_decoder_rejects_multiple_peers_and_any_loss_of_pinned_topology_or_schema():
    changes = (
        lambda u: u[_SECTION].append(deepcopy(u[_SECTION][0])),
        lambda u: u["interfaces"][0]["addresses"][0].update(cidr="198.18.210.3/30"),
        lambda u: u["versionDetail"].update({"vpn/ipsec/site-to-site": 4}),
        lambda u: u.update({"vpn/ipsec": {"ikev2Reauth": True}}),
    )
    for change in changes:
        snapshot = _snapshot("create")
        change(snapshot["udapi"])
        with pytest.raises(IpsecIntentError):
            _decode("create", snapshot=snapshot)


def _with_companion(phase):
    udapi = _snapshot(phase)["udapi"]
    udapi.update(deepcopy(_POLICY["create" if phase in {"create", "edit"} else "off"]))
    return udapi


@pytest.mark.parametrize("phase", ["off", "create", "edit", "delete"])
def test_native_policy_is_scrubbed_to_the_verified_off_baseline(phase):
    wire = _with_companion(phase)
    before = deepcopy(wire)
    assert scrub_ipsec_policy(wire, _decode(phase)) == _with_companion("off")
    assert wire == before


def test_scrub_preserves_an_unrelated_scope_change_for_the_unmanaged_fingerprint():
    wire = _with_companion("create")
    wire["firewall/filter"][2]["unmanaged"] = True
    result = scrub_ipsec_policy(wire, _decode("create"))
    assert result["firewall/filter"][2]["unmanaged"] is True
    assert result != _with_companion("off")


@pytest.mark.parametrize(
    "change",
    [
        lambda u: u["firewall/filter"][0]["rules"].pop(),
        lambda u: u["firewall/filter"][1]["rules"][2].update(ipVersion="both"),
        lambda u: u["firewall/filter"][1]["rules"][4].update(id=30002),
        lambda u: u["firewall/filter"][13]["rules"][4]["inInterface"].update(id="vti0"),
        lambda u: u["firewall/filter"][18]["rules"][0].pop("ipsecPolicy"),
        lambda u: u["firewall/filter"][2]["rules"].append({"source": {"sets": ["ipsec_remote_subnets"]}}),
        lambda u: u["firewall/filter"][2]["rules"].append({"destination": {"sets": ["!VPN_subnets"]}}),
        lambda u: u.setdefault("firewall/mangle", []).append({"source": {"sets": ["remote_site_vpn_network"]}}),
        lambda u: u["firewall/nat"].reverse(),
        lambda u: u["firewall/nat"][0]["outInterface"].update(id="eth2"),
        lambda u: u["firewall/sets"][9]["entries"].append("10.0.0.0/8"),
        lambda u: u["firewall/sets"][-2]["entries"].reverse(),
    ],
)
def test_scrub_rejects_unproven_generated_firewall_set_or_nat_changes(change):
    wire = _with_companion("create")
    change(wire)
    with pytest.raises(IpsecIntentError):
        scrub_ipsec_policy(wire, _decode("create"))
