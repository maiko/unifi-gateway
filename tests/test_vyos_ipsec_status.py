"""Native state is reported only for the verified VyOS IKE and CHILD SAs."""

import configparser
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from backends.vyos import VyOSReadError
from gateway_profiles.vyos_ipsec_status import IpsecStatusError, project_ipsec_status
from provisioners.vyos_ipsec import IpsecScope, decode_ipsec_intent
from unifi_gateway import UnifiGateway


_FIXTURES = Path(__file__).parent / "fixtures/uxg_pro"
_WIRE = json.loads((_FIXTURES / "native-ipsec-snapshots.json").read_text())
_OPERATIONS = json.loads((_FIXTURES / "native-ipsec-status-vyos.json").read_text())
_SCOPE = IpsecScope(
    "eth0", "eth3.210", "198.18.210.1/30", "br120", "eth3.120", "192.168.120.1/24",
    "198.18.210.2", "192.168.120.2/32", "198.19.210.240/32", "UXG-LAB-IPSEC",
)
_UUID = _WIRE["entries"]["create"][0]["id"]
_STATUS_ID = f"/vpn/ipsec/site-to-site/{_UUID}"


def _intent(phase):
    envelope = dict(_WIRE["envelope"])
    entries = _WIRE["entries"][phase]
    if entries is not None:
        envelope["vpn/ipsec/site-to-site"] = entries
    return decode_ipsec_intent(
        json.dumps({"udapi": envelope}), revision=phase, scope=_SCOPE,
        expected_versions=envelope["versionDetail"],
    )


def _status(*, connections=_OPERATIONS["connections"], sas=_OPERATIONS["sas"], revision="create"):
    return project_ipsec_status(_intent("create"), applied_revision=revision, connections=connections, sas=sas)


def test_verified_child_sa_reports_real_peer_and_uptime_using_native_id():
    assert _status() == [{"id": _STATUS_ID, "remotes": [{"ip": "198.18.210.2", "uptime": 19}]}]


def test_native_ipsec_reports_the_initial_child_sa_before_its_first_rekey():
    assert _status(connections=_OPERATIONS["initial_connections"], sas=_OPERATIONS["initial_sas"]) == [
        {"id": _STATUS_ID, "remotes": [{"ip": "198.18.210.2", "uptime": 60}]},
    ]


@pytest.mark.parametrize(("shown", "seconds"), [("1m19s", 79), ("1h5m", 3900), ("2m", 120)])
def test_uses_the_actual_elapsed_child_sa_age(shown, seconds):
    sas = _OPERATIONS["sas"].replace("19s", shown)
    result = project_ipsec_status(
        _intent("edit"), applied_revision="edit", connections=_OPERATIONS["connections"], sas=sas,
    )
    assert result[0]["remotes"][0]["uptime"] == seconds


@pytest.mark.parametrize("reported", ["N/A", "", "0s", "5m72s", "5h", "1m1m"])
def test_does_not_guess_an_unknown_or_impossible_child_age(reported):
    sas = _OPERATIONS["sas"].replace("19s", reported)
    with pytest.raises(IpsecStatusError):
        _status(sas=sas)


def test_confirmed_missing_child_sa_is_reported_as_disconnected():
    down = _OPERATIONS["connections"].replace("up       IPsec", "down     IPsec")
    assert _status(connections=down, sas=_OPERATIONS["no_sas"]) == [{"id": _STATUS_ID, "remotes": []}]


@pytest.mark.parametrize(
    ("source", "old", "new"),
    [
        ("connections", "192.168.120.2/32", "192.168.120.3/32"),
        ("connections", "198.19.210.240/32", "198.19.210.241/32"),
        ("connections", "198.18.210.1", "198.18.210.9"),
        ("connections", "IKEv2", "IKEv1"),
        ("connections", "up       IPsec", "down     IPsec"),
        ("sas", "198.18.210.2", "198.18.210.3"),
        ("sas", "UXG-LAB-IPSEC-tunnel-0", "UXG-LAB-IPSEC-tunnel-1"),
        ("sas", "MODP_2048", "MODP_1024"),
        ("sas", "up", "down"),
    ],
)
def test_rejects_state_from_wrong_or_inconsistent_sa(source, old, new):
    with pytest.raises(IpsecStatusError):
        _status(**{source: _OPERATIONS[source].replace(old, new)})


def test_omits_unconfigured_tunnel_and_rejects_stale_or_unsuccessful_readback():
    assert project_ipsec_status(_intent("off"), applied_revision="off", connections=None, sas=None) == []
    with pytest.raises(IpsecStatusError):
        _status(revision="old")
    with pytest.raises(IpsecStatusError):
        _status(sas="VPN IPSec site-to-site is not configured, aborting")
    with pytest.raises(IpsecStatusError):
        _status(sas=_OPERATIONS["no_sas"])


def test_daemon_omits_stale_tunnel_status_when_live_readback_fails():
    config = configparser.RawConfigParser()
    config.read_dict({"vyos_applied": {"cfgversion": "create"}})
    backend = SimpleNamespace(show_ipsec_connections=lambda: _OPERATIONS["connections"],
                              show_ipsec_sas=lambda: _OPERATIONS["sas"])
    data = {"uptime": 120}
    gateway = SimpleNamespace(_verified_ipsec=_intent("create"), config=config,
                              datacollector=SimpleNamespace(data=data, backend=backend))
    UnifiGateway._update_ipsec_status(gateway)
    assert data["ipsec_status"] == _status()

    def unavailable():
        raise VyOSReadError("Management unavailable")

    backend.show_ipsec_sas = unavailable
    UnifiGateway._update_ipsec_status(gateway)
    assert data == {"uptime": 120}
