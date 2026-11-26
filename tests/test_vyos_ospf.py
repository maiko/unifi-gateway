"""Check captured native gateway OSPF and exact scoped VyOS ownership."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from provisioners.vyos_ospf import (
    OspfIntentError,
    OspfScope,
    decode_ospf_intent,
    plan_ospf_commands,
    redact_ospf_config,
    scrub_ospf_policy,
    verify_ospf_state,
)


ROUTER = "routes/ospf"
AREAS = "routes/ospf/areas"
INTERFACES = "routes/ospf/interfaces"
BINDING = ["protocols", "ospf", "interface", "eth3.120"]
SCHEMA = {"dns_forwarder": True, "nat": True, "wireguard": True}


@pytest.fixture
def native():
    path = Path(__file__).parent / "fixtures" / "uxg_pro" / "native-ospf-snapshots.json"
    return json.loads(path.read_text())


@pytest.fixture
def scope():
    return OspfScope("198.51.100.1", "br120", "eth3.120", "192.0.2.1/24")


@pytest.fixture
def topology():
    return {
        "current_ethernet": {"eth3": {"vif": {"120": {"address": "192.0.2.1/24"}}}},
        "live_interfaces": {
            "eth3.120": (("UP", "LOWER_UP", "MULTICAST"), "    inet 192.0.2.1/24\n")
        },
    }


def _decode(document, scope, **schema):
    return decode_ospf_intent(json.dumps(document), revision="rev", scope=scope, **{**SCHEMA, **schema})


def test_create_consumes_only_verified_ospf_wire_sections(native, scope):
    intent = _decode(native["create"], scope)
    assert intent.revision == "rev"
    assert intent.scope == scope
    assert intent.cost == 1

    wire = native["create"]["udapi"]
    unrelated = {"custom": ["another subsystem", {"description": "OSPF documentation"}]}
    expected = deepcopy(native["baseline"]["udapi"])
    expected["services"] = wire["services"] = unrelated
    for branch in (ROUTER, AREAS, INTERFACES):
        del expected["versionDetail"][branch]

    result = scrub_ospf_policy(wire, intent)

    assert result == expected
    assert wire[ROUTER]["enabled"] is True
    assert result["services"] is not unrelated


def test_plan_create_uses_an_interface_selector_and_exact_vyos_readback(native, scope, topology):
    intent = _decode(native["create"], scope)
    plan = plan_ospf_commands(intent, scope=scope, current_ospf=None, verified_ospf=None, **topology)
    assert plan.desired_ospf == {
        "parameters": {"router-id": "198.51.100.1"},
        "interface": {
            "eth3.120": {
                "area": "0", "network": "broadcast", "hello-interval": "10", "dead-interval": "40", "cost": "1",
            },
        },
    }
    assert plan.commands == (
        {"op": "set", "path": ["protocols", "ospf", "parameters", "router-id"], "value": "198.51.100.1"},
        *({"op": "set", "path": BINDING + [field], "value": value}
          for field, value in plan.desired_ospf["interface"]["eth3.120"].items()),
    )
    verify_ospf_state(
        scope=scope, expected_ospf=plan.desired_ospf, current_ospf=deepcopy(plan.desired_ospf), **topology
    )
    repeat = plan_ospf_commands(
        intent, scope=scope, current_ospf=plan.desired_ospf, verified_ospf=plan.desired_ospf, **topology,
    )
    assert repeat.commands == ()


def test_plan_cost_edit_and_delete_follow_verified_config(native, scope, topology):
    create = _decode(native["create"], scope)
    known = plan_ospf_commands(create, scope=scope, current_ospf=None, verified_ospf=None, **topology).desired_ospf
    edit = native["edit"]

    plan = plan_ospf_commands(
        _decode(edit, scope), scope=scope, current_ospf=known, verified_ospf=known, **topology,
    )
    assert plan.commands == ({"op": "set", "path": BINDING + ["cost"], "value": "23"},)

    off = _decode(native["delete"], scope)
    assert off.cost is None
    policy = scrub_ospf_policy(native["delete"]["udapi"], off)
    assert policy == scrub_ospf_policy(native["baseline"]["udapi"], _decode(native["baseline"], scope))
    assert policy == scrub_ospf_policy(edit["udapi"], _decode(edit, scope))
    deletion = plan_ospf_commands(
        off, scope=scope, current_ospf=plan.desired_ospf, verified_ospf=plan.desired_ospf,
        current_ethernet={}, live_interfaces={},
    )
    assert deletion.desired_ospf is None
    assert deletion.commands == ({"op": "delete", "path": ["protocols", "ospf"]},)


def test_native_router_id_timers_and_passive_edit_and_recovery(native, scope, topology):
    original = _decode(native["create"], scope)
    known = plan_ospf_commands(original, scope=scope, current_ospf=None, verified_ospf=None, **topology).desired_ospf
    edit = deepcopy(native["create"])
    edit["udapi"][ROUTER]["routerID"] = "198.51.100.9"
    edit["udapi"][INTERFACES][0].update(helloInterval=3, deadInterval=12)
    changed = _decode(edit, scope)
    active = plan_ospf_commands(changed, scope=scope, current_ospf=known, verified_ospf=known, **topology)
    assert active.commands == (
        {"op": "set", "path": ["protocols", "ospf", "parameters", "router-id"], "value": "198.51.100.9"},
        {"op": "set", "path": BINDING + ["hello-interval"], "value": "3"},
        {"op": "set", "path": BINDING + ["dead-interval"], "value": "12"},
    )
    assert scrub_ospf_policy(edit["udapi"], changed) == scrub_ospf_policy(native["create"]["udapi"], original)

    edit["udapi"][INTERFACES][0].update(helloInterval=10, deadInterval=40, passiveInterface=True)
    passive = plan_ospf_commands(
        _decode(edit, scope), scope=scope, current_ospf=active.desired_ospf, verified_ospf=active.desired_ospf, **topology,
    )
    assert passive.commands == (
        {"op": "set", "path": BINDING + ["hello-interval"], "value": "10"},
        {"op": "set", "path": BINDING + ["dead-interval"], "value": "40"},
        {"op": "set", "path": BINDING + ["passive"]},
    )
    assert passive.desired_ospf["interface"]["eth3.120"]["passive"] == {}
    restored = plan_ospf_commands(
        original, scope=scope, current_ospf=passive.desired_ospf, verified_ospf=passive.desired_ospf, **topology,
    )
    assert restored.commands[-1] == {"op": "delete", "path": BINDING + ["passive"]}
    assert restored.desired_ospf == known


def test_native_authentication_rotation_and_withdrawal(native, scope, topology):
    proof_key = bytes(range(32))
    row = native["create"]["udapi"][INTERFACES][0]
    row["authentication"] = {"authType": "plainText", "authKey": "firstKey"}
    plain = _decode(native["create"], scope)
    start = plan_ospf_commands(plain, scope=scope, current_ospf=None, verified_ospf=None,
                               proof_key=proof_key, **topology)
    path = [*BINDING, "authentication"]
    assert start.commands[-1] == {"op": "set", "path": [*path, "plaintext-password"], "value": "firstKey"}
    assert "firstKey" not in repr(plain) + repr(start) + json.dumps(start.desired_ospf)
    raw = deepcopy(start.desired_ospf)
    raw["interface"]["eth3.120"]["authentication"]["plaintext-password"] = "firstKey"
    assert redact_ospf_config(raw, scope=scope, proof_key=proof_key) == start.desired_ospf

    row["authentication"] = {"authType": "md5", "authKeysMD5": [{"id": 1, "key": "older-md5"}]}
    md5 = _decode(native["create"], scope)
    converted = plan_ospf_commands(md5, scope=scope, current_ospf=start.desired_ospf, verified_ospf=start.desired_ospf,
                                   proof_key=proof_key, **topology)
    assert converted.commands == (
        {"op": "delete", "path": path},
        {"op": "set", "path": [*path, "md5", "key-id", "1", "md5-key"], "value": "older-md5"},
    )
    row["authentication"]["authKeysMD5"].insert(0, {"id": 2, "key": "newer-md5"})
    edit = _decode(native["create"], scope)
    rotated = plan_ospf_commands(edit, scope=scope, current_ospf=converted.desired_ospf, verified_ospf=converted.desired_ospf,
                                 proof_key=proof_key, **topology)
    assert rotated.commands == (
        {"op": "set", "path": [*path, "md5", "key-id", "2", "md5-key"], "value": "newer-md5"},
    )
    row["authentication"]["authKeysMD5"].pop()
    remove_old = plan_ospf_commands(
        _decode(native["create"], scope), scope=scope, current_ospf=rotated.desired_ospf, verified_ospf=rotated.desired_ospf,
        proof_key=proof_key, **topology,
    )
    assert remove_old.commands == ({"op": "delete", "path": [*path, "md5", "key-id", "1"]},)
    row["authentication"] = {"authType": "off"}
    off = plan_ospf_commands(
        _decode(native["create"], scope), scope=scope, current_ospf=remove_old.desired_ospf,
        verified_ospf=remove_old.desired_ospf, proof_key=proof_key, **topology,
    )
    assert off.commands == ({"op": "delete", "path": path},)


@pytest.mark.parametrize(
    ("key", "patch"),
    [
        (ROUTER, {"announceDefaultRoute": True}),
        (ROUTER, {"enabled": 1}),
        (ROUTER, {"routerID": "198.51.100.256"}),
        (ROUTER, {"redistributeConnected": {"enabled": True, "metric": 10, "metricType": "type1"}}),
        (AREAS, {"networks": [{"source": "static", "address": "0.0.0.0/0"}]}),
        (AREAS, {"areaType": "nssa"}),
        (INTERFACES, {"id": "br110"}),
        (INTERFACES, {"authentication": {"authType": "plainText", "authKey": "too-long!"}}),
        (INTERFACES, {"authentication": {"authType": "md5", "authKeysMD5": [{"id": True, "key": "value"}]}}),
        (INTERFACES, {"authentication": {"authType": "md5", "authKeysMD5": [
            {"id": 6, "key": "value"}, {"id": 6, "key": "other"},
        ]}}),
        (INTERFACES, {"deadInterval": 0}),
        (INTERFACES, {"passiveInterface": 1}),
        (INTERFACES, {"cost": True}),
        (INTERFACES, {"cost": 65536}),
        (INTERFACES, {"priority": 1}),
    ],
)
def test_refuses_scope_or_policy_changes(native, scope, key, patch):
    row = native["create"]["udapi"][key]
    (row[0] if isinstance(row, list) else row).update(patch)

    with pytest.raises(OspfIntentError):
        _decode(native["create"], scope)


def test_refuses_incomplete_native_snapshot_and_unexpected_ospf_branch(native, scope):
    document = deepcopy(native["create"])
    del document["udapi"][AREAS]
    with pytest.raises(OspfIntentError):
        _decode(document, scope)

    native["baseline"]["udapi"]["routes/ospf/neighbor"] = []
    with pytest.raises(OspfIntentError):
        _decode(native["baseline"], scope)


def test_refuses_changed_native_vlan_or_schema(native, scope):
    document = deepcopy(native["create"])
    row = next(item for item in document["udapi"]["interfaces"] if item["identification"]["id"] == "br120")
    row["addresses"][0]["cidr"] = "192.0.2.9/24"
    with pytest.raises(OspfIntentError):
        _decode(document, scope)

    document = deepcopy(native["create"])
    document["udapi"]["versionDetail"][INTERFACES] = 3
    with pytest.raises(OspfIntentError):
        _decode(document, scope)


def test_refuses_missing_controller_bridge_parent(native, scope):
    interfaces = native["create"]["udapi"]["interfaces"]
    interfaces[:] = [item for item in interfaces if item["identification"]["id"] != "eth3"]
    with pytest.raises(OspfIntentError, match="topology"):
        _decode(native["create"], scope)


def test_scrub_revalidates_cost_and_pins(native, scope):
    intent = _decode(native["create"], scope)
    udapi = native["create"]["udapi"]
    udapi[INTERFACES][0]["cost"] = 23
    with pytest.raises(OspfIntentError):
        scrub_ospf_policy(udapi, intent)
    udapi[INTERFACES][0]["cost"] = 1
    del udapi["versionDetail"][AREAS]
    with pytest.raises(OspfIntentError):
        scrub_ospf_policy(udapi, intent)


def test_plan_refuses_operator_ospf_root_even_if_it_looks_exact(native, scope, topology):
    intent = _decode(native["create"], scope)
    known = plan_ospf_commands(intent, scope=scope, current_ospf=None, verified_ospf=None, **topology).desired_ospf
    with pytest.raises(OspfIntentError, match="verified ownership"):
        plan_ospf_commands(intent, scope=scope, current_ospf=known, verified_ospf=None, **topology)
    with pytest.raises(OspfIntentError, match="verified ownership"):
        plan_ospf_commands(
            intent, scope=scope, current_ospf={**known, "redistribute": {"connected": {}}},
            verified_ospf=known, **topology,
        )


@pytest.mark.parametrize("bad", ["disabled", "secondary", "missing-multicast"])
def test_plan_refuses_live_or_configured_link_drift(native, scope, topology, bad):
    if bad == "disabled":
        topology["current_ethernet"]["eth3"]["vif"]["120"]["disable"] = {}
    elif bad == "secondary":
        topology["live_interfaces"]["eth3.120"] = (
            ("UP", "LOWER_UP", "MULTICAST"), "    inet 192.0.2.1/24\n    inet 198.51.100.7/24\n"
        )
    else:
        topology["live_interfaces"]["eth3.120"] = (("UP", "LOWER_UP"), "    inet 192.0.2.1/24\n")

    with pytest.raises(OspfIntentError):
        plan_ospf_commands(
            _decode(native["create"], scope), scope=scope, current_ospf=None, verified_ospf=None, **topology,
        )
