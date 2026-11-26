"""Native OpenVPN emits a tightly bounded companion delta for a managed TLS client."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from provisioners.uxg_openvpn_policy import scrub_openvpn_policy


_WIRE = json.loads((Path(__file__).parent / "fixtures/uxg_pro/native-openvpn-companions.json").read_text())


@pytest.mark.parametrize("phase", ["create", "edit", "delete"])
def test_only_the_observed_companions_are_removed_from_the_native_snapshot(phase):
    observed = deepcopy(_WIRE[phase])
    expected = deepcopy(_WIRE["delete"])
    expected["versionDetail"].clear()
    actual = scrub_openvpn_policy(observed, client_id=None if phase == "delete" else "1")
    assert actual == expected
    assert observed == _WIRE[phase]


@pytest.mark.parametrize("fault", [
    lambda wire: wire["versionDetail"].update({"vpn/openvpn/raws": 5}),
    lambda wire: wire["vpn/openvpn/raws"][0].update(id="2"),
    lambda wire: wire["services"]["wanFailover"]["wanInterfaces"][-1].update(metric=1),
    lambda wire: wire["firewall/filter"][0]["rules"][-1].update(ipVersion="v4only"),
    lambda wire: wire["firewall/filter"][13]["rules"][2].update(id=30015),
    lambda wire: wire["firewall/nat"][-1].update(source={"address": "0.0.0.0/0"}),
    lambda wire: wire.setdefault("firewall/mangle", []).append({"outInterface": {"id": "tunovpnc1"}}),
])
def test_unknown_generated_options_or_placement_are_rejected(fault):
    observed = deepcopy(_WIRE["create"])
    fault(observed)
    with pytest.raises(ValueError, match="OpenVPN"):
        scrub_openvpn_policy(observed, client_id="1")


def test_absent_intent_cannot_hide_an_orphaned_traffic_rule():
    observed = deepcopy(_WIRE["delete"])
    observed["firewall/nat"].append(_WIRE["create"]["firewall/nat"][-1])
    with pytest.raises(ValueError, match="OpenVPN"):
        scrub_openvpn_policy(observed, client_id=None)
