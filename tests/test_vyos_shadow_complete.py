"""Translate the pinned Shadow Mode election and verify exact VyOS ownership."""

from copy import deepcopy
from ipaddress import ip_interface, IPv4Interface, IPv4Network
import json

import pytest


def _wire():
    return {"enabled": True, "instances": [{
        "interface": "eth1", "vrid": 42, "priority": 120, "advertisementInterval": 1, "useVmac": False,
        "unicastAdvertise": {"sourceIP": "169.254.254.2", "peerIP": "169.254.254.3"},
        "virtualIPs": [
            {"interface": "br0", "address": "192.0.2.1/24"},
            {"interface": "br120", "address": "198.18.240.1/24"},
        ],
    }]}


def _compiler():
    from provisioners.vyos_shadow_complete import build_vyos_shadow, decode_shadow_vrrp

    return build_vyos_shadow, decode_shadow_vrrp


def test_vrrp_intent_compiles_one_election_and_exact_per_vip_devices():
    build, decode = _compiler()
    intent = decode(_wire(), version=5)
    desired = build(intent, interconnect="eth2", local_address="169.254.254.2/24",
                    interfaces={"br0": "eth3", "br120": "eth1"})

    assert desired.group["interface"] == "eth2"
    assert desired.group["vrid"] == "42"
    assert desired.group["hello-source-address"] == "169.254.254.2"
    assert desired.group["peer-address"] == "169.254.254.3"
    assert desired.group["address"] == {"192.0.2.1/24": {"interface": "eth3"}, "198.18.240.1/24": {"interface": "eth1"}}
    assert desired.conntrack["failover-mechanism"] == {"vrrp": {"sync-group": "UXGHA"}}
    assert desired.conntrack["interface"] == {"eth2": {"peer": "169.254.254.3"}}
    assert [command for command in desired.create_commands() if command["path"][-1] == "script"] == [
        {"op": "set", "path": ["high-availability", "vrrp", "sync-group", "UXGHA", "health-check", "script"],
         "value": "/config/scripts/unifi-gateway-shadow-policy-eligible.py"},
    ]


@pytest.mark.parametrize("change", [
    {"interface": "eth2"}, {"priority": True}, {"advertisementInterval": True}, {"useVmac": True},
    {"virtualIPs": []}, {"virtualIPs": [{"interface": "br0", "address": "2001:db8::1/64"}]},
    {"unicastAdvertise": {"sourceIP": "169.254.254.2", "peerIP": "169.254.254.2"}},
    {"virtualIPs": [{"interface": "br0", "address": "169.254.254.1/24"}]},
    {"virtualIPs": [{"interface": "br0", "address": "192.0.2.1/0"}]},
    {"virtualIPs": [{"interface": "br0", "address": "192.0.2.255/24"}]},
    {"virtualIPs": [{"interface": "br0", "address": "192.0.2.1/24"},
                    {"interface": "br120", "address": "192.0.2.129/25"}]},
])
def test_rejects_complete_options_that_cannot_be_applied_safely(change):
    _, decode = _compiler()
    raw = _wire()
    raw["instances"][0].update(change)
    with pytest.raises(ValueError):
        decode(raw, version=5)


def test_standby_cannot_compile_without_the_independent_primary_guard():
    build, decode = _compiler()
    raw = _wire()
    instance = raw["instances"][0]
    instance["priority"] = 100
    instance["unicastAdvertise"] = {"sourceIP": "169.254.254.3", "peerIP": "169.254.254.2"}
    instance["masterGuard"] = {"peerLan": {"address": "fe80::2", "interface": "br0"}}
    standby = decode(raw, version=5)
    assert standby.peer_lan == ("br0", "fe80::2")
    with pytest.raises(ValueError, match="independent"):
        build(standby, interconnect="eth2", local_address="169.254.254.3/24", interfaces={"br0": "eth3", "br120": "eth1"})


def test_phase_one_cannot_acknowledge_a_complete_election():
    from provisioners.uxg_enterprise_shadow import normalize_shadow_interconnect

    ordinary = {"identification": {"id": "eth1", "type": "ethernet"}, "status": {"enabled": True}}
    raw = {"udapi": {
        "versionDetail": {"services/vrrp": 5}, "services": {"vrrp": _wire()},
        "interfaces": [ordinary],
    }}
    with pytest.raises(ValueError, match="verified paired"):
        normalize_shadow_interconnect(json.dumps(raw), None)


def _lan_election_pair():
    from provisioners.vyos_shadow_complete import ShadowNode, decode_shadow_vrrp

    raw = _wire()
    primary = decode_shadow_vrrp(raw, version=5)
    raw["instances"][0].update(
        priority=100,
        unicastAdvertise={"sourceIP": "169.254.254.3", "peerIP": "169.254.254.2"},
        masterGuard={"peerLan": {"interface": "br0", "address": "fe80::2"}},
    )
    standby = decode_shadow_vrrp(raw, version=5)
    nodes = (
        ShadowNode("eth2", "169.254.254.2/24", {"br0": "eth3", "br120": "eth1"}, "192.0.2.2/24"),
        ShadowNode("eth4", "169.254.254.3/24", {"br0": "eth5", "br120": "eth6"}, "192.0.2.3/24"),
    )
    return primary, standby, nodes


def test_paired_election_uses_reciprocal_lan_addresses_and_dedicated_sync_links():
    from provisioners.vyos_shadow_complete import build_vyos_shadow_pair

    primary, standby, nodes = _lan_election_pair()
    plans = build_vyos_shadow_pair(primary, standby, nodes=nodes)
    for index, (plan, node) in enumerate(zip(plans, nodes, strict=True)):
        assert plan.group["interface"] == node.interfaces["br0"]
        assert plan.group["hello-source-address"] == node.lan_address.split("/")[0]
        assert plan.group["peer-address"] == nodes[1 - index].lan_address.split("/")[0]
        assert plan.group["no-preempt"] == {}
        assert plan.group["priority"] == ("120", "100")[index]
        assert plan.conntrack["listen-address"] == node.local_address.split("/")[0]
        assert plan.conntrack["interface"] == {
            node.interconnect: {"peer": nodes[1 - index].local_address.split("/")[0]},
        }
        assert plan.group["address"] == {
            "192.0.2.1/24": {"interface": node.interfaces["br0"]},
            "198.18.240.1/24": {"interface": node.interfaces["br120"]},
        }


def test_paired_election_requires_kernel_proof_of_the_lan_and_interconnect_identities():
    from provisioners.vyos_shadow_complete import build_vyos_shadow_pair

    primary, standby, nodes = _lan_election_pair()
    first, second = build_vyos_shadow_pair(primary, standby, nodes=nodes)
    primary_kernel = {
        "eth2": (ip_interface("169.254.254.2/24"),),
        "eth3": (ip_interface("192.0.2.2/24"), ip_interface("fe80::2/64")),
        "eth1": (),
    }
    first.verify_empty(None, None, primary_kernel)
    second.verify_empty(None, None, {
        "eth4": (ip_interface("169.254.254.3/24"),), "eth5": (ip_interface("192.0.2.3/24"),), "eth6": (),
    })
    for kernel in (
        {**primary_kernel, "eth3": (ip_interface("192.0.2.2/24"),)},
        {**primary_kernel, "eth3": (ip_interface("192.0.2.2/24"), ip_interface("fe80::3/64"))},
        {**primary_kernel, "eth1": (ip_interface("fe80::2/64"),), "eth3": (ip_interface("192.0.2.2/24"),)},
        {**primary_kernel, "eth3": (ip_interface("192.0.2.3/24"), ip_interface("fe80::2/64"))},
        {**primary_kernel, "eth3": (*primary_kernel["eth3"], ip_interface("192.0.2.3/24"))},
        {**primary_kernel, "eth3": (ip_interface("192.0.2.2/32"), ip_interface("fe80::2/64"))},
    ):
        with pytest.raises(ValueError):
            first.verify_empty(None, None, kernel)
    with pytest.raises(ValueError, match="VRID 42"):
        first.verify_empty({"group": {"operator": {"interface": "eth3", "vrid": "42"}}}, None, primary_kernel)


def test_paired_election_rejects_unmatched_intent_or_non_unique_local_addresses():
    from dataclasses import replace

    from provisioners.vyos_shadow_complete import build_vyos_shadow_pair

    primary, standby, nodes = _lan_election_pair()
    for left, right, pair in (
        (primary, replace(standby, peer_lan=None), nodes),
        (primary, replace(standby, virtual_ips=standby.virtual_ips[:1]), nodes),
        (standby, primary, nodes),
        (replace(primary, priority=255), standby, nodes),
        (primary, standby, (nodes[0], replace(nodes[1], lan_address=nodes[0].lan_address))),
        (primary, standby, (nodes[0], replace(nodes[1], lan_address="192.0.2.1/24"))),
        (primary, standby, (nodes[0], replace(nodes[1], lan_address="192.0.2.3/25"))),
        (primary, standby, (nodes[0], replace(nodes[1], lan_address="192.0.2.255/24"))),
        (primary, standby, (nodes[0], replace(nodes[1], interfaces={"br0": "eth4", "br120": "eth6"}))),
    ):
        with pytest.raises(ValueError):
            build_vyos_shadow_pair(left, right, nodes=pair)


def test_initial_setup_priority_compiles_to_the_same_stock_pair_as_the_steady_revision():
    from dataclasses import replace

    from provisioners.vyos_shadow_complete import build_vyos_shadow_pair

    primary, standby, nodes = _lan_election_pair()
    setup = build_vyos_shadow_pair(replace(primary, priority=255), standby, nodes=nodes, initial_setup=True)
    steady = build_vyos_shadow_pair(primary, standby, nodes=nodes)

    assert setup == steady


def test_primary_activation_compiles_the_eventual_lan_election_before_the_standby_snapshot():
    from dataclasses import replace

    from provisioners.vyos_shadow_complete import build_vyos_shadow_pair, build_vyos_shadow_primary_activation

    primary, standby, nodes = _lan_election_pair()
    initial = replace(primary, priority=255)
    expected, _ = build_vyos_shadow_pair(primary, standby, nodes=nodes)
    assert build_vyos_shadow_primary_activation(initial, nodes=nodes, primary_lan_link_local="fe80::2") == expected

    for election, pair, link_local in (
        (primary, nodes, "fe80::2"),
        (standby, nodes, "fe80::2"),
        (initial, nodes, "2001:db8::2"),
        (initial, nodes, "fe80::2%eth3"),
        (initial, (nodes[0], replace(nodes[1], local_address=nodes[0].local_address)), "fe80::2"),
        (initial, (nodes[0], replace(nodes[1], lan_address=nodes[0].lan_address)), "fe80::2"),
        (initial, (nodes[0], replace(nodes[1], interfaces={"br0": "eth4"})), "fe80::2"),
    ):
        with pytest.raises(ValueError):
            build_vyos_shadow_primary_activation(election, nodes=pair, primary_lan_link_local=link_local)


@pytest.mark.parametrize("drift", [None, "owned-vip", "extra-group-member", "saved-candidate", "operator-vrrp",
                                  "lost-lan-source", "unpersisted-sync", "backup-before-receipt"])
def test_standby_candidate_compiles_the_paired_election_and_verifies_its_fence(drift):
    from provisioners.vyos_shadow_complete import (
        SHADOW_SYNC_GROUP, SHADOW_VRRP_GROUP, ShadowStockState, build_vyos_shadow_pair, build_vyos_shadow_standby_candidate,
        standby_election_commands, verify_standby_election_candidate,
    )
    from provisioners.vyos_shadow_receipt import ShadowHandoffObservation

    primary, standby, nodes = _lan_election_pair()
    _, expected = build_vyos_shadow_pair(primary, standby, nodes=nodes)
    candidate = build_vyos_shadow_standby_candidate(standby, nodes=nodes)
    assert candidate == expected
    initial = {"interfaces": {"ethernet": {"eth4": {"address": "169.254.254.3/24"}, "eth5": {"address": "192.0.2.3/24"}}}}
    running = initial | {"high-availability": {"vrrp": {
        "group": {SHADOW_VRRP_GROUP: deepcopy(candidate.group)},
        "sync-group": {SHADOW_SYNC_GROUP: deepcopy(candidate.sync_group)},
    }}, "service": {"conntrack-sync": candidate.conntrack}}
    kernel = {"eth4": (ip_interface("169.254.254.3/24"),), "eth5": (ip_interface("192.0.2.3/24"),), "eth6": ()}
    saved = initial
    if drift == "owned-vip":
        kernel["eth6"] = (ip_interface("198.18.240.1/24"),)
    elif drift == "extra-group-member":
        running["high-availability"]["vrrp"]["sync-group"][SHADOW_SYNC_GROUP]["member"] = [SHADOW_VRRP_GROUP, "operator"]
    elif drift == "saved-candidate":
        saved = running
    elif drift == "operator-vrrp":
        running["high-availability"]["vrrp"]["group"]["operator"] = {"interface": "eth5", "vrid": "42"}
    elif drift == "lost-lan-source":
        kernel["eth5"] = ()
    elif drift == "unpersisted-sync":
        saved = {"interfaces": {"ethernet": {"eth4": {"address": "dhcp"}, "eth5": {"address": "192.0.2.3/24"}}}}
    role = "backup" if drift == "backup-before-receipt" else "fault"
    observed = ShadowHandoffObservation(
        ShadowStockState(running, saved, kernel), role, "boot", "saved", "candidate", "reboot", "staged_reboot",
    )
    if drift is None:
        verify_standby_election_candidate(candidate, observed)
        from dataclasses import replace

        preimage = replace(observed, phase="saved_commit", role="unknown", state=ShadowStockState(initial, initial, kernel))
        assert standby_election_commands(candidate, preimage) == expected.create_commands()
        with pytest.raises(ValueError, match="preimages disagree"):
            standby_election_commands(candidate, replace(preimage, state=observed.state))
        with pytest.raises(ValueError, match="resources are already in use"):
            standby_election_commands(candidate, replace(preimage, state=ShadowStockState(running, running, kernel)))
        saved_observation = replace(observed, phase="saved_commit", state=ShadowStockState(running, running, kernel))
        verify_standby_election_candidate(candidate, saved_observation)
        from provisioners.vyos_shadow_complete import verify_standby_backup

        verify_standby_backup(candidate, replace(saved_observation, role="backup"))
        for unsafe in (saved_observation, replace(saved_observation, role="master"), replace(observed, role="backup")):
            with pytest.raises(ValueError, match="BACKUP"):
                verify_standby_backup(candidate, unsafe)
    else:
        with pytest.raises(ValueError):
            verify_standby_election_candidate(candidate, observed)


@pytest.mark.parametrize("fault", [None, "existing-ha", "existing-vrrp", "lost-reply", "operator-drift", "receipt", "no-carrier",
                                  "lost-confirm", "lost-save", "changed-after-confirm", "cold-saved", "cold-lost-save",
                                  "cold-saved-raw-drift", "rollback-reboot", "rollback-drift", "rollback-receipt",
                                  "guard", "guard-collision", "guard-drift", "guard-bypass"])
def test_timed_standby_election_stages_once_and_remains_fenced(fault):
    from unittest.mock import Mock

    from backends.vyos import VyOSWriteError
    from provisioners.vyos_shadow_complete import (
        SHADOW_SYNC_GROUP, SHADOW_VRRP_GROUP, ShadowStockState, build_vyos_shadow_standby_candidate,
    )
    from provisioners.vyos_shadow_guard import ShadowManagementGuard
    from provisioners.vyos_shadow_receipt import ShadowHandoffObservation, ShadowReceiptStatus
    from provisioners.vyos_shadow_standby import (
        STANDBY_ELECTION, STANDBY_POLICY, advance_standby_election, stage_standby_election,
    )

    _, standby, nodes = _lan_election_pair()
    election = build_vyos_shadow_standby_candidate(standby, nodes=nodes)
    guard = ShadowManagementGuard(("192.0.2.0/24",), ("169.254.254.3", "169.254.254.2")) if (
        fault is not None and fault.startswith("guard")
    ) else None
    boot = "158dd3a3-dc93-4ae3-94b1-489e4f6ecc6d"
    current_boot = boot
    rolled_back = False
    saved_sha, before, after, generation = ("a" * 64, "b" * 64, "c" * 64, "d" * 64)
    final_saved_sha = "e" * 64
    persisted = False
    initial = {"interfaces": {"ethernet": {"eth4": {"address": "169.254.254.3/24"}, "eth5": {"address": "192.0.2.3/24"}}},
               "system": {"host-name": "standby"}}
    ancestry = ["high-availability"]
    if fault == "existing-ha":
        initial["high-availability"] = {}
        ancestry.append("vrrp")
    elif fault == "existing-vrrp":
        initial["high-availability"] = {"vrrp": {}}
        ancestry = []
    if fault == "guard-collision":
        initial["firewall"] = {"ipv4": {"input": {"filter": {"rule": {"1": {"action": "accept"}}}}}}
    elif fault == "guard-bypass":
        initial["firewall"] = {"global-options": {"state-policy": {"established": {"action": "accept"}}}}
    kernel = {"eth4": (ip_interface("169.254.254.3/24"),), "eth5": (ip_interface("192.0.2.3/24"),), "eth6": ()}
    preimage = ShadowHandoffObservation(
        ShadowStockState(initial, initial, kernel), "unknown", boot, saved_sha, before, "reboot", "saved_commit",
    )
    running = initial | {"high-availability": {"vrrp": {
        "group": {SHADOW_VRRP_GROUP: election.group}, "sync-group": {SHADOW_SYNC_GROUP: election.sync_group},
    }}, "service": {"conntrack-sync": election.conntrack}}
    if guard is not None and fault == "guard":
        running["firewall"] = {"ipv4": {"input": {"filter": {"default-action": "accept"}}}}
        initial["firewall"] = deepcopy(running["firewall"])
        for command in guard.create_commands():
            *parents, key = command["path"]
            tree = running
            for parent in parents:
                tree = tree.setdefault(parent, {})
            value = command["value"]
            tree[key] = [tree[key], value] if key in tree else value
    writer, receipt = Mock(), Mock()
    writer.backend.management_origin = receipt.management_identity.https_origin = "https://standby.test"
    writer.backend.read_config.return_value = {}
    writer.backend.read_complete_configuration.return_value = initial
    writer.backend.show_kernel_interfaces.return_value = [{
        "ifname": "eth4", "flags": ["UP"] if fault == "no-carrier" else ["UP", "LOWER_UP"],
        "addr_info": [{"family": "inet", "local": "169.254.254.3", "prefixlen": 24}],
    }]
    writer.commit_proof.side_effect = lambda *, phase: (
        (current_boot, after if persisted else before) if phase == "saved_commit" else after
    )
    receipt.status.return_value = ShadowReceiptStatus(generation, object() if fault == "receipt" else None)
    state = {STANDBY_POLICY: {"phase": "unchanged", "boot_id": boot, "config_sha256": before,
                             "saved_sha256": saved_sha, "receipt_generation": generation}}
    def observe(_backend, _proof, *, phase, expected_boot_id, expected_saved_sha256):
        assert expected_boot_id == current_boot
        digest = final_saved_sha if persisted else saved_sha
        if expected_saved_sha256 not in (None, digest):
            raise ValueError("Saved digest changed")
        if rolled_back:
            return ShadowHandoffObservation(ShadowStockState(initial, initial, kernel), "unknown", current_boot,
                                            digest, before, "reboot", phase)
        assert phase != "saved_commit" or persisted
        return ShadowHandoffObservation(ShadowStockState(running, running if persisted else initial, kernel), "fault",
                                        current_boot, digest, after, "reboot", phase)

    receipt.observe_handoff_state.side_effect = observe

    def stage(commands, *, confirm_minutes):
        assert state[STANDBY_ELECTION]["phase"] == "armed" and confirm_minutes > 0
        assert state[STANDBY_ELECTION]["created_vrrp_parent"] == ancestry
        writer._write_state.assert_called_once()
        assert commands == election.create_commands() + (guard.create_commands() if guard else [])
        writer.backend.read_complete_configuration.return_value = (
            running | {"system": {"host-name": "operator-edit"}} if fault == "operator-drift" else running
        )
        if fault == "lost-reply":
            raise VyOSWriteError("stage reply lost")

    writer.backend.stage_configuration.side_effect = stage
    verify_primary = Mock()

    def run(saved):
        return stage_standby_election(writer, state, receipt, election, preimage=saved, verify_primary=verify_primary,
                                      management_guard=guard)

    if fault in ("receipt", "no-carrier", "operator-drift", "guard-collision", "guard-drift", "guard-bypass"):
        with pytest.raises(ValueError):
            run(preimage)
        assert writer.backend.stage_configuration.call_count == (1 if fault in ("operator-drift", "guard-drift") else 0)
    else:
        if fault == "lost-reply":
            with pytest.raises(VyOSWriteError, match="reply lost"):
                run(preimage)
        else:
            assert run(preimage).role == "fault"
        assert run(None).config_sha256 == after
        assert state[STANDBY_ELECTION]["phase"] == "staged"
        assert writer.backend.stage_configuration.call_count == 1
    def confirm():
        if fault == "lost-confirm":
            raise VyOSWriteError("confirm reply lost")
        if fault == "changed-after-confirm":
            writer.backend.read_complete_configuration.return_value = running | {"system": {"host-name": "operator-edit"}}

    def save():
        nonlocal persisted
        persisted = True
        if fault in ("lost-save", "cold-lost-save"):
            raise VyOSWriteError("save reply lost")

    writer.backend.confirm_configuration.side_effect = confirm
    writer.backend.save_configuration.side_effect = save

    def finish():
        return advance_standby_election(writer, state, receipt, election, preimage=None, verify_primary=verify_primary,
                                        management_guard=guard)

    if fault in ("rollback-reboot", "rollback-drift", "rollback-receipt"):
        current_boot = "3ae81880-6675-4a28-971b-5a451036cfb2"
        rolled_back = True
        writer.backend.read_complete_configuration.return_value = (
            initial | {"system": {"host-name": "operator-edit"}} if fault == "rollback-drift" else initial
        )
        if fault == "rollback-receipt":
            receipt.status.return_value = ShadowReceiptStatus("f" * 64, None)
        if fault == "rollback-reboot":
            with pytest.raises(ValueError, match="rolled back"):
                finish()
            assert state[STANDBY_ELECTION]["phase"] == "rolled_back"
            with pytest.raises(ValueError, match="rolled back"):
                finish()
        else:
            with pytest.raises(ValueError, match="receipt fence" if fault == "rollback-receipt" else "preimage"):
                finish()
            assert state[STANDBY_ELECTION]["phase"] == "staged"
        writer.backend.confirm_configuration.assert_not_called()
        writer.backend.save_configuration.assert_not_called()
    elif fault in ("receipt", "no-carrier", "operator-drift", "guard-collision", "guard-drift", "guard-bypass"):
        writer.backend.confirm_configuration.assert_not_called()
        writer.backend.save_configuration.assert_not_called()
    else:
        if fault in ("lost-confirm", "lost-save", "cold-lost-save"):
            with pytest.raises(VyOSWriteError, match="reply lost"):
                finish()
        if fault in ("cold-saved", "cold-saved-raw-drift"):
            assert finish().saved_sha256 == final_saved_sha
        if fault in ("cold-saved", "cold-lost-save", "cold-saved-raw-drift"):
            current_boot = "3ae81880-6675-4a28-971b-5a451036cfb2"
        if fault == "changed-after-confirm":
            with pytest.raises(ValueError, match="differs"):
                finish()
            writer.backend.save_configuration.assert_not_called()
        elif fault == "cold-saved-raw-drift":
            record = state[STANDBY_ELECTION].copy()
            final_saved_sha = "f" * 64
            with pytest.raises(ValueError, match="Saved digest changed"):
                finish()
            assert state[STANDBY_ELECTION] == record
            writer.backend.save_configuration.assert_called_once_with()
        else:
            assert finish().boot_id == current_boot
            assert finish().saved_sha256 == final_saved_sha
            assert state[STANDBY_ELECTION]["phase"] == "saved"
            writer.backend.save_configuration.assert_called_once_with()
        writer.backend.confirm_configuration.assert_called_once_with()
    receipt.publish.assert_not_called()


@pytest.mark.parametrize("fault", [None, "lost-reply", "unreachable", "foreign-receipt", "generation", "missing-guard",
                                  "cold-empty", "wait-backup", "dual-master", "lost-revoke", "lingering-vips",
                                  "release-drift", "release-generation", "revoke-not-applied"])
def test_standby_receipt_publication_is_bound_to_the_saved_election(fault, monkeypatch):
    from unittest.mock import Mock

    from provisioners import vyos_shadow_standby as provisioning
    from provisioners.vyos_shadow_complete import build_vyos_shadow_standby_candidate
    from provisioners.vyos_shadow_receipt import (
        ShadowPolicyReceipt, ShadowReceiptCandidate, ShadowReceiptError, ShadowReceiptStatus,
    )

    _, standby, nodes = _lan_election_pair()
    election = build_vyos_shadow_standby_candidate(standby, nodes=nodes)
    transaction = "6303a0a3-d505-4782-93e1-0639a40dd670"
    boot = "158dd3a3-dc93-4ae3-94b1-489e4f6ecc6d"
    standby_policy = {"phase": "unchanged", "boot_id": boot, "receipt_generation": "1" * 64,
                      "controller_revision": "standby-complete"}
    candidate = ShadowReceiptCandidate(boot, "2" * 64, ("f" if fault == "generation" else "1") * 64, "3" * 64)
    installed = ShadowPolicyReceipt("4" * 64, candidate.sha256, transaction, candidate.config_sha256)
    management_guard = Mock(eligibility_paths=(("firewall", "ipv4", "input"),))
    management_guard.create_commands.return_value = [{"op": "set", "path": ["firewall", "ipv4", "input", "filter", "rule", "1"]}]
    state = {provisioning.SHADOW_HANDOFF: {"phase": "standby", "transaction": transaction},
             provisioning.STANDBY_POLICY: standby_policy, provisioning.STANDBY_ELECTION: {
                 "phase": "saved", "candidate_sha256": candidate.config_sha256, "final_saved_sha256": "5" * 64,
                 "policy_sha256": provisioning._digest(standby_policy),
                 "plan_sha256": provisioning._election_plan_sha(election, management_guard),
                 "outside_sha256": "6" * 64,
             }}
    writer, receipt = Mock(ipv6_interfaces={}), Mock()
    writer.backend.management_origin = receipt.management_identity.https_origin = "https://standby.test"
    writer.commit_proof.return_value = (boot, candidate.config_sha256)
    receipt.status.return_value = ShadowReceiptStatus("1" * 64, installed if fault == "foreign-receipt" else None)
    receipt.candidate.return_value = candidate
    verify_saved = Mock()
    monkeypatch.setattr(provisioning, "_verify_election_candidate", verify_saved)
    verify_primary = Mock()
    verify_ready = Mock(return_value=fault != "unreachable")
    if fault == "missing-guard":
        management_guard.verify_stock.side_effect = ValueError("Native management guard is missing")

    def publish(serial, proof):
        record = state[provisioning.STANDBY_ELECTION]
        assert record["phase"] == "publishing" and record["receipt_policy_sha256"] == proof.sha256
        assert record["boot_id"] == proof.boot_id
        assert writer._write_state.call_count == receipt.publish.call_count
        assert (serial, proof.sha256, proof.config_sha256) == (transaction, candidate.sha256, candidate.config_sha256)
        if fault == "cold-empty" and receipt.publish.call_count == 1:
            raise ShadowReceiptError("Publication reply lost")
        receipt.status.return_value = ShadowReceiptStatus(candidate.generation, installed)
        if fault == "lost-reply":
            raise ShadowReceiptError("Publication reply lost")
        return installed

    receipt.publish.side_effect = publish

    def run():
        return provisioning.publish_standby_election(
            writer, state, receipt, election, management_guard=management_guard,
            verify_primary=verify_primary, verify_ready=verify_ready,
        )

    if fault in ("unreachable", "foreign-receipt", "generation", "missing-guard"):
        with pytest.raises(ValueError):
            run()
        receipt.publish.assert_not_called()
        assert state[provisioning.STANDBY_ELECTION]["phase"] == "saved"
        return
    if fault in ("lost-reply", "cold-empty"):
        with pytest.raises(ShadowReceiptError, match="reply lost"):
            run()
    if fault == "cold-empty":
        new_boot = "3ae81880-6675-4a28-971b-5a451036cfb2"
        writer.commit_proof.return_value = (new_boot, candidate.config_sha256)
        receipt.candidate.return_value = ShadowReceiptCandidate(
            new_boot, candidate.sha256, candidate.generation, candidate.config_sha256,
        )
    assert run() == installed
    assert run() == installed
    assert state[provisioning.STANDBY_ELECTION]["phase"] == "published"
    assert receipt.publish.call_count == receipt.candidate.call_count == (2 if fault == "cold-empty" else 1)
    final_candidate = receipt.candidate.return_value
    verify_ready.assert_called_with(boot_id=final_candidate.boot_id, config_sha256=final_candidate.config_sha256,
                                    generation=final_candidate.generation)
    assert ("firewall", "ipv4", "forward", "filter") in receipt.candidate.call_args.kwargs["required_paths"]
    assert ("interfaces", "ethernet", "eth5") in receipt.candidate.call_args.kwargs["required_paths"]
    assert ("interfaces", "ethernet", "eth6") in receipt.candidate.call_args.kwargs["required_paths"]
    assert ("firewall", "ipv4", "input") in receipt.candidate.call_args.kwargs["required_paths"]

    def verify():
        return provisioning.verify_published_standby_election(
            writer, state, receipt, election, management_guard=management_guard, verify_primary=verify_primary,
            inform_binding_sha256="8" * 64,
        )

    if fault == "wait-backup":
        verify_saved.side_effect = provisioning.ShadowStandbyPending("Waiting for BACKUP")
        with pytest.raises(provisioning.ShadowStandbyPending):
            verify()
        receipt.revoke.assert_not_called()
        assert state[provisioning.STANDBY_ELECTION]["phase"] == "published"
        assert "inform_binding_sha256" not in state[provisioning.STANDBY_ELECTION]
        return
    if fault in ("dual-master", "lost-revoke", "lingering-vips", "release-drift", "release-generation", "revoke-not-applied"):
        from provisioners.vyos_shadow_complete import SHADOW_VRRP_GROUP, ShadowStockState

        verify_saved.side_effect = provisioning._ShadowConcurrentMaster("Both nodes own the addresses")
        config = {"high-availability": {"vrrp": {"group": {SHADOW_VRRP_GROUP: election.group}}}}
        live = Mock(role="fault", phase="saved_commit", boot_id=boot, config_sha256=candidate.config_sha256,
                    saved_sha256="5" * 64, state=ShadowStockState(config, config, {
                        "eth5": (ip_interface("192.0.2.1/24"),) if fault == "lingering-vips" else (),
                    }))
        def observe(*_args, **_kwargs):
            if fault == "release-drift":
                live.saved_sha256 = "6" * 64
            if fault == "release-generation":
                receipt.status.return_value = ShadowReceiptStatus("9" * 64, None)
            return live

        receipt.observe_handoff_state.side_effect = observe

        def revoke(receipt_id):
            assert receipt_id == installed.id
            assert state[provisioning.STANDBY_ELECTION]["phase"] == "revoking"
            if fault == "revoke-not-applied":
                raise ShadowReceiptError("Revocation did not reach router")
            fenced = ShadowReceiptStatus("7" * 64, None)
            receipt.status.return_value = fenced
            if fault == "lost-revoke" and receipt.revoke.call_count == 1:
                raise ShadowReceiptError("Revocation reply lost")
            return fenced

        receipt.revoke.side_effect = revoke
        if fault == "revoke-not-applied":
            with pytest.raises(ShadowReceiptError, match="did not reach router"):
                verify()
            verify_primary.reset_mock()
            receipt.revoke.reset_mock()
            provisioning.verify_revoked_standby_release(writer, state, receipt)
            verify_primary.assert_not_called()
            receipt.revoke.assert_not_called()
            assert state[provisioning.STANDBY_ELECTION]["phase"] == "revoking"
            return
        if fault == "lost-revoke":
            with pytest.raises(ShadowReceiptError, match="Revocation reply lost"):
                verify()
            verify_primary.reset_mock()
            provisioning.verify_revoked_standby_release(writer, state, receipt)
            verify_primary.assert_not_called()
            assert state[provisioning.STANDBY_ELECTION]["phase"] == "released"
        if fault == "lingering-vips":
            with pytest.raises(provisioning.ShadowStandbyPending, match="VIP"):
                verify()
            assert state[provisioning.STANDBY_ELECTION]["phase"] == "revoked"
            receipt.revoke.assert_called_once()
            live.state = ShadowStockState(config, config, {"eth5": ()})
            provisioning.verify_revoked_standby_release(writer, state, receipt)
        if fault in ("release-drift", "release-generation"):
            with pytest.raises(ValueError, match="saved proof changed" if fault == "release-drift" else "receipt fence"):
                verify()
            assert state[provisioning.STANDBY_ELECTION]["phase"] == "revoked"
            receipt.revoke.assert_called_once()
            return
        with pytest.raises(ValueError, match="released its virtual IPs"):
            verify()
        assert state[provisioning.STANDBY_ELECTION]["phase"] == "released"
        with pytest.raises(ValueError, match="released its virtual IPs"):
            verify()
        assert receipt.revoke.call_count == (2 if fault == "lost-revoke" else 1)
        return

    assert verify() is verify_saved.return_value
    assert verify_saved.call_args.kwargs["installed_receipt"] == installed
    live_boot = writer.commit_proof.return_value[0]
    live = Mock(role="backup", phase="saved_commit", boot_id=live_boot, config_sha256=candidate.config_sha256,
                saved_sha256="5" * 64)
    receipt.observe_handoff_state.return_value = live
    assert state[provisioning.STANDBY_ELECTION]["inform_binding_sha256"] == "8" * 64
    assert provisioning.verify_standby_inform(writer, state, receipt, inform_binding_sha256="8" * 64) == "standby-complete"
    with pytest.raises(ValueError, match="verified BACKUP acknowledgement"):
        provisioning.verify_standby_inform(writer, state, receipt, inform_binding_sha256="7" * 64)
    live.role = "master"
    with pytest.raises(ValueError, match="current BACKUP"):
        provisioning.verify_standby_inform(writer, state, receipt, inform_binding_sha256="8" * 64)
    assert provisioning.verify_standby_inform(
        writer, state, receipt, inform_binding_sha256="8" * 64, expected_role="master",
    ) == "standby-complete"
    receipt.revoke.assert_not_called()
    receipt.status.return_value = ShadowReceiptStatus("7" * 64, None)
    with pytest.raises(ValueError, match="recorded publication"):
        verify()


@pytest.mark.parametrize("role", ["fault", "master", "master-after-primary-loss"])
def test_published_standby_needs_fresh_primary_proof_to_classify_concurrent_master(role, monkeypatch):
    from unittest.mock import Mock

    from provisioners import vyos_shadow_standby as provisioning
    from provisioners.vyos_shadow_complete import build_vyos_shadow_standby_candidate
    from provisioners.vyos_shadow_receipt import ShadowReceiptStatus

    _, standby, nodes = _lan_election_pair()
    election = build_vyos_shadow_standby_candidate(standby, nodes=nodes)
    boot = "158dd3a3-dc93-4ae3-94b1-489e4f6ecc6d"
    writer, receipt, observation = Mock(), Mock(), Mock(
        phase="saved_commit", role="fault" if role == "fault" else "master", boot_id=boot,
        saved_sha256="a" * 64, config_sha256="b" * 64,
    )
    writer.commit_proof.return_value = (boot, observation.config_sha256)
    activation_receipt = Mock()
    receipt.status.return_value = ShadowReceiptStatus("d" * 64, activation_receipt)
    receipt.observe_handoff_state.return_value = observation
    policy = {"boot_id": boot, "receipt_generation": "d" * 64, "config_sha256": "e" * 64, "saved_sha256": "f" * 64}
    record = {"outside_sha256": "1" * 64, "candidate_sha256": observation.config_sha256}
    interconnect = Mock(side_effect=ValueError("Sync link down") if role == "master" else None)
    monkeypatch.setattr(provisioning, "verify_interconnect", interconnect)
    monkeypatch.setattr(provisioning, "verify_no_vrrp_interconnect_conflict", Mock())
    monkeypatch.setattr(provisioning, "_election_outside", Mock(return_value=record["outside_sha256"]))
    primary_lost = ValueError("Primary is unavailable")
    verify_primary = Mock(side_effect=[None, primary_lost] if role == "master-after-primary-loss" else None)
    expected = {
        "fault": provisioning.ShadowStandbyPending,
        "master": provisioning._ShadowConcurrentMaster,
        "master-after-primary-loss": ValueError,
    }[role]
    with pytest.raises(expected) as error:
        provisioning._verify_election_candidate(
            writer, receipt, election, policy, record, verify_primary, phase="saved_commit",
            saved_sha256=observation.saved_sha256, installed_receipt=activation_receipt,
        )
    if role == "master-after-primary-loss":
        assert error.value is primary_lost
    if role == "master":
        interconnect.assert_not_called()
    assert verify_primary.call_count == (1 if role == "fault" else 2)


def _lan_handoff():
    from provisioners.vyos_shadow_complete import build_vyos_shadow_pair

    primary, standby, nodes = _lan_election_pair()
    left, right = build_vyos_shadow_pair(primary, standby, nodes=nodes)
    extras = [
        {"type": "static", "cidr": "192.0.2.9/24", "version": "v4"},
        {"type": "static", "cidr": "2001:db8::1/64", "version": "v6"},
    ]
    ordinary = [{"type": "static", "cidr": "192.0.2.1/24", "version": "v4"}, *extras]
    complete = [{"type": "dynamic", "cidr": None, "origin": "vrrp", "eui64": False, "version": "v4"}, *extras]
    kernel = {
        "eth1": (),
        "eth2": (ip_interface("169.254.254.2/24"),),
        "eth3": tuple(map(ip_interface, ("192.0.2.2/24", "192.0.2.9/24", "2001:db8::1/64", "fe80::2/64", "192.0.2.1/24"))),
    }
    return left, right, ordinary, complete, kernel


def _handoff_state(lan, kernel, *, saved_lan=None, plan=None, saved_plan=None, interface="eth3"):
    from provisioners.vyos_shadow_complete import ShadowStockState

    def tree(addresses, election):
        result = {"interfaces": {"ethernet": {interface: addresses}}}
        if election is not None:
            result["high-availability"] = {"vrrp": {"group": {"UXGSHADOW": election.group},
                                                     "sync-group": {"UXGHA": election.sync_group}}}
            result["service"] = {"conntrack-sync": election.conntrack}
        return result

    return ShadowStockState(tree(lan, plan), tree(lan if saved_lan is None else saved_lan, saved_plan), kernel)


def _standby_state(**options):
    kernel = {"eth4": (ip_interface("169.254.254.3/24"),), "eth5": (ip_interface("192.0.2.3/24"),), "eth6": ()}
    return _handoff_state({"address": "192.0.2.3/24"}, kernel, interface="eth5", **options)


def test_initial_primary_handoff_requires_the_standby_to_stay_fenced_at_every_phase():
    from dataclasses import replace

    from provisioners.vyos_shadow_complete import prepare_shadow_primary_lan_handoff

    primary, _, nodes = _lan_election_pair()
    left, right, ordinary, complete, kernel = _lan_handoff()
    original = {"address": ["192.0.2.1/24", "192.0.2.2/24", "192.0.2.9/24", "2001:db8::1/64"]}
    peer = _standby_state()
    args = dict(nodes=nodes, primary_lan_link_local="fe80::2", ordinary=ordinary, complete=complete,
                local=_handoff_state(original, kernel), peer=peer, route_source="192.0.2.1")
    handoff = prepare_shadow_primary_lan_handoff(replace(primary, priority=255), **args)
    assert handoff.create_commands() == [
        {"op": "delete", "path": ["interfaces", "ethernet", "eth3", "address", "192.0.2.1/24"]},
        *left.create_commands(),
    ]

    withdrawn = {"address": original["address"][1:]}
    no_vip = kernel | {"eth3": kernel["eth3"][:-1]}
    staged = _handoff_state(withdrawn, no_vip, saved_lan=original, plan=left)
    saved = _handoff_state(withdrawn, no_vip, plan=left, saved_plan=left)
    master_kernel = kernel | {"eth1": (ip_interface("198.18.240.1/24"),)}
    master = replace(saved, kernel=master_kernel)
    handoff.verify_staged_transfer(staged, peer=peer, role="fault")
    handoff.verify_saved_transfer(saved, peer=peer, role="fault")
    handoff.verify_primary_master(master, peer=peer, role="master")
    assert handoff.restore_commands(local=saved, peer=peer)[-1]["value"] == "192.0.2.1/24"

    unsafe_peer = _standby_state(saved_plan=right)
    with pytest.raises(ValueError):
        prepare_shadow_primary_lan_handoff(replace(primary, priority=255), **(args | {"peer": unsafe_peer}))
    for proof, state, role in (
        (handoff.verify_staged_transfer, staged, "fault"),
        (handoff.verify_saved_transfer, saved, "fault"),
        (handoff.verify_primary_master, master, "master"),
    ):
        with pytest.raises(ValueError):
            proof(state, peer=unsafe_peer, role=role)
    with pytest.raises(ValueError):
        handoff.verify_saved_transfer(staged, peer=peer, role="fault")
    with pytest.raises(ValueError):
        handoff.verify_primary_master(master, peer=peer, role="backup")
    for live in (kernel, master_kernel | {"eth2": (*kernel["eth2"], ip_interface("198.18.240.1/24"))}):
        with pytest.raises(ValueError):
            handoff.verify_primary_master(replace(master, kernel=live), peer=peer, role="master")
    for foreign in (
        {"interface": "eth3", "vrid": "42"},
        {"interface": "eth7", "vrid": "55", "address": {"192.0.2.1/24": {}}},
    ):
        drifted = deepcopy(master.saved)
        drifted["high-availability"]["vrrp"]["group"]["OPERATOR"] = foreign
        with pytest.raises(ValueError, match="VRID 42|already owns"):
            handoff.verify_primary_master(replace(master, saved=drifted), peer=peer, role="master")


@pytest.mark.parametrize("saved_only", ["192.0.2.1/24", "192.0.2.50/25", "198.18.240.8/24"])
def test_shadow_handoff_rejects_an_offline_standby_interface_that_conflicts_after_boot(saved_only):
    from provisioners.vyos_shadow_complete import prepare_shadow_lan_handoff

    left, right, ordinary, complete, kernel = _lan_handoff()
    local = _handoff_state({"address": ["192.0.2.1/24", "192.0.2.2/24", "192.0.2.9/24", "2001:db8::1/64"]}, kernel)
    peer = _standby_state()
    peer.saved["interfaces"]["dummy"] = {"dum0": {"address": saved_only}}

    with pytest.raises(ValueError, match="configured interface"):
        prepare_shadow_lan_handoff(
            left, right, ordinary=(ordinary, ordinary), complete=(complete, complete),
            local=local, peer=peer, route_source="192.0.2.1",
        )


def test_handoff_moves_only_the_verified_primary_static_gateway():
    from provisioners.vyos_shadow_complete import prepare_shadow_lan_handoff

    left, right, ordinary, complete, kernel = _lan_handoff()
    running = {"address": ["192.0.2.1/24", "192.0.2.2/24", "192.0.2.9/24", "2001:db8::1/64"], "description": "LAN"}
    handoff = prepare_shadow_lan_handoff(
        left, right, ordinary=(ordinary, ordinary), complete=(complete, complete),
        local=_handoff_state(running, kernel), peer=_standby_state(), route_source="192.0.2.1",
    )
    commands = handoff.create_commands()
    assert commands[0] == {"op": "delete", "path": ["interfaces", "ethernet", "eth3", "address", "192.0.2.1/24"]}
    assert commands[1:] == left.create_commands()
    post = running | {"address": running["address"][1:]}
    no_vip = kernel | {"eth3": kernel["eth3"][:-1]}
    handoff.verify_address(post, post, no_vip, static=False)
    with pytest.raises(ValueError):
        handoff.verify_address(post, post | {"address": post["address"][:-1]}, no_vip, static=False)
    with pytest.raises(ValueError):
        handoff.verify_address(post, post, kernel, static=False)
    with pytest.raises(ValueError):
        handoff.verify_address(post, post, no_vip | {"eth3": no_vip["eth3"][:1]}, static=False)


def test_handoff_rejects_alias_drift_and_ambiguous_static_ownership():
    from provisioners.vyos_shadow_complete import prepare_shadow_lan_handoff

    left, right, ordinary, complete, kernel = _lan_handoff()
    config = {"address": ["192.0.2.1/24", "192.0.2.2/24", "192.0.2.9/24"]}
    for second_complete, running, saved, live in (
        ([complete[0], *complete[:0:-1]], config, config, kernel),
        ([complete[0] | {"eui64": 0}, *complete[1:]], config, config, kernel),
        (complete, config, {"address": config["address"][1:]}, kernel),
        (complete, {"address": config["address"][1:]}, config, kernel),
        (complete, config, config, kernel | {"eth3": kernel["eth3"][:-1] + (ip_interface("192.0.2.1/25"),)}),
        (complete, config, config, kernel | {"eth1": (ip_interface("192.0.2.1/24"),)}),
    ):
        with pytest.raises(ValueError):
            prepare_shadow_lan_handoff(
                left, right, ordinary=(ordinary, ordinary), complete=(complete, second_complete),
                local=_handoff_state(running, live, saved_lan=saved), peer=_standby_state(), route_source="192.0.2.1",
            )
    with pytest.raises(ValueError, match="standby"):
        prepare_shadow_lan_handoff(
            left, right, ordinary=(ordinary, ordinary), complete=(complete, complete),
            local=_handoff_state(config, kernel),
            peer=_standby_state(saved_lan={"address": ["192.0.2.3/24", "192.0.2.1/24"]}),
            route_source="192.0.2.1",
        )


def test_handoff_restores_static_ip_only_after_peer_withdrawal_and_no_live_vip():
    from provisioners.vyos_shadow_complete import prepare_shadow_lan_handoff

    left, right, ordinary, complete, kernel = _lan_handoff()
    config = {"address": ["192.0.2.1/24", "192.0.2.2/24", "192.0.2.9/24"]}
    handoff = prepare_shadow_lan_handoff(
        left, right, ordinary=(ordinary, ordinary), complete=(complete, complete),
        local=_handoff_state(config, kernel), peer=_standby_state(), route_source="192.0.2.1",
    )
    no_vip = kernel | {"eth3": kernel["eth3"][:-1]}
    active = {"group": {"UXGSHADOW": left.group}, "sync-group": {"UXGHA": left.sync_group}}
    post = {"address": config["address"][1:]}
    args = dict(local=_handoff_state(post, no_vip, plan=left, saved_plan=left), peer=_standby_state())
    commands = handoff.restore_commands(**args)
    assert commands[:-1] == [
        {"op": "delete", "path": ["service", "conntrack-sync"]},
        {"op": "delete", "path": ["high-availability"]},
    ]
    assert commands[-1] == {"op": "set", "path": ["interfaces", "ethernet", "eth3", "address"], "value": "192.0.2.1/24"}
    from dataclasses import replace

    historical = replace(handoff, created_vrrp_parent=())
    assert historical.restore_commands(**args)[:-1] == left.withdraw_commands(active, left.conntrack)

    projected = replace(args["local"], projected=True)
    with pytest.raises(ValueError, match="complete running and saved"):
        handoff.restore_commands(**(args | {"local": projected}))

    peer = args["peer"]
    for change in (
        {"peer": _standby_state(saved_plan=right)}, {"peer": _standby_state(plan=right)},
        {"peer": replace(peer, kernel=peer.kernel | {"eth5": (*peer.kernel["eth5"], ip_interface("192.0.2.1/24"))})},
        {"local": _handoff_state(post, kernel, plan=left, saved_plan=left)},
        {"local": _handoff_state(post, no_vip, plan=left)},
        {"local": _handoff_state(post, no_vip, plan=left, saved_plan=left, saved_lan=config)},
    ):
        with pytest.raises(ValueError):
            handoff.restore_commands(**(args | change))


def test_restored_handoff_checks_the_connected_route_source_against_the_original():
    from provisioners.vyos_shadow_complete import prepare_shadow_lan_handoff

    left, right, ordinary, complete, kernel = _lan_handoff()
    config = {"address": ["192.0.2.1/24", "192.0.2.2/24", "192.0.2.9/24"]}
    local = _handoff_state(config, kernel)
    handoff = prepare_shadow_lan_handoff(
        left, right, ordinary=(ordinary, ordinary), complete=(complete, complete),
        local=local, peer=_standby_state(), route_source="192.0.2.1",
    )
    handoff.verify_restored(local, route_source="192.0.2.1")
    with pytest.raises(ValueError, match="preferred source"):
        handoff.verify_restored(local, route_source="192.0.2.9")
    with pytest.raises(ValueError):
        handoff.verify_restored(_handoff_state(config, kernel, saved_plan=left), route_source="192.0.2.1")


def test_reboot_handoff_rejects_reload_and_requires_the_original_boot_preimage_after_expiry():
    from dataclasses import replace
    from provisioners.vyos_shadow_complete import prepare_shadow_lan_handoff
    from provisioners.vyos_shadow_receipt import ShadowHandoffObservation

    left, right, ordinary, complete, kernel = _lan_handoff()
    addresses = ["192.0.2.1/24", "192.0.2.9/24", "192.0.2.2/24"]
    local = _handoff_state({"address": addresses}, kernel)
    peer = _standby_state()
    source = "192.0.2.1"
    handoff = prepare_shadow_lan_handoff(
        left, right, ordinary=(ordinary, ordinary), complete=(complete, complete),
        local=local, peer=peer, route_source=source,
    )
    boot = "158dd3a3-dc93-4ae3-94b1-489e4f6ecc6d"
    new_boot = "6303a0a3-d505-4782-93e1-0639a40dd670"
    preimage = ShadowHandoffObservation(local, "unknown", boot, "a" * 64, "b" * 64, "reboot", "saved_commit")
    assert handoff.reboot_safe_transfer_commands(preimage, peer=peer, route_source=source) == handoff.create_commands()
    with pytest.raises(ValueError, match="rollback action"):
        handoff.reboot_safe_transfer_commands(replace(preimage, rollback_action="reload"), peer=peer, route_source=source)
    with pytest.raises(ValueError, match="settled"):
        handoff.reboot_safe_transfer_commands(replace(preimage, phase="staged"), peer=peer, route_source=source)

    restored = replace(preimage, boot_id=new_boot)
    handoff.verify_reboot_rollback(preimage, restored, peer=peer, route_source=source)
    reordered = _handoff_state({"address": addresses[::-1]}, kernel)
    for wrong, reason in (
        (preimage, "reboot"),
        (replace(restored, saved_sha256="d" * 64), "preimage"),
        (replace(restored, config_sha256="e" * 64), "preimage"),
        (replace(restored, state=reordered), "address order"),
        (replace(restored, phase="staged"), "settled"),
    ):
        with pytest.raises(ValueError, match=reason):
            handoff.verify_reboot_rollback(preimage, wrong, peer=peer, route_source=source)
    with pytest.raises(ValueError, match="preferred source"):
        handoff.verify_reboot_rollback(preimage, restored, peer=peer, route_source="192.0.2.9")
    with pytest.raises(ValueError):
        handoff.verify_reboot_rollback(preimage, restored, peer=_standby_state(plan=right), route_source=source)


@pytest.mark.parametrize("outcome", [
    "rollback", "lost-stage", "saved", "lost-confirm", "lost-save", "occupied-receipt", "operator-edit",
    "activate", "lost-publish", "publication-not-sent", "wrong-receipt", "forwarding-failure",
    "controller-drift", "drift-before-stage", "drift-before-save", "drift-before-activation", "resume-first-complete",
    "rebuild-after-save",
])
def test_pair_handoff_recovers_from_ambiguous_writes(tmp_path, outcome):
    from dataclasses import replace
    from unittest.mock import Mock
    from backends.vyos import VyOSReadError, VyOSWriteError
    from gateway_profiles.vyos_restart import VyOSRestart
    from provisioners.vyos_shadow_binding import ShadowEnrolledNode, ShadowEnrollmentPair, ShadowManagementIdentity
    from provisioners.vyos_shadow_complete import prepare_shadow_lan_handoff
    from provisioners.vyos_shadow_handoff import ShadowPrimaryTransfer, read_shadow_lan_preimage
    from provisioners.vyos_shadow_receipt import (
        ShadowHandoffObservation, ShadowPolicyReceipt, ShadowReceiptCandidate, ShadowReceiptError, ShadowReceiptStatus,
    )
    from provisioners.vyos import VyOSReconciler

    left, right, ordinary, complete, kernel = _lan_handoff()
    local = _handoff_state({"address": ["192.0.2.1/24", "192.0.2.9/24", "192.0.2.2/24"]}, kernel)
    peer = _standby_state()
    source = "192.0.2.1"
    handoff = prepare_shadow_lan_handoff(
        left, right, ordinary=(ordinary, ordinary), complete=(complete, complete),
        local=local, peer=peer, route_source=source,
    )
    boot = "158dd3a3-dc93-4ae3-94b1-489e4f6ecc6d"
    preimage = ShadowHandoffObservation(local, "unknown", boot, "a" * 64, "b" * 64, "reboot", "saved_commit")
    nodes = tuple(ShadowEnrolledNode(f"dev-{i}", ShadowManagementIdentity(f"02:00:00:00:00:0{i}",
                        f"https://192.0.2.2{i}", f"pin-{i}"), f"rev-{i}") for i in (1, 2))
    pair = ShadowEnrollmentPair("lab", "6.0.17", *nodes)
    handoff = replace(handoff, complete_snapshot_sha256="7" * 64, complete_binding=pair)
    if outcome == "rebuild-after-save":
        from provisioners.vyos_shadow_guard import ShadowManagementGuard

        guard = ShadowManagementGuard(("192.0.2.0/24",), ("169.254.254.2", "169.254.254.3"))
        handoff = replace(handoff, management_guard=guard, guard_containers=guard.created_containers(local.saved),
                          standby_resources_sha256="5" * 64, site_policy_sha256="4" * 64)
    read_controller_pair = Mock(return_value=pair)
    changed_controller_pair = replace(pair, primary=replace(pair.primary, desired_revision="new-head"))
    routers = [Mock(management_origin=node.management.https_origin) for node in nodes]
    routers[0].read_complete_configuration.return_value = local.running | {"system": {"host-name": "operator"}}
    paths = [tmp_path / name for name in ("primary.json", "standby.json")]
    receipt = Mock(management_identity=nodes[0].management)
    receipt.status.return_value = ShadowReceiptStatus("e" * 64, None)

    def fence(generation):
        assert generation == "e" * 64
        fenced = ShadowReceiptStatus("f" * 64, None)
        receipt.status.return_value = fenced
        return fenced

    receipt.fence.side_effect = fence

    def reconciler(i):
        return VyOSReconciler(routers[i], state_path=paths[i], rule_base=80200,
                                  interfaces={IPv4Network("192.0.2.0/24"): "eth1",
                                              IPv4Network("198.18.240.0/24"): "eth2"})

    def transfer(*observations, plan=handoff):
        return ShadowPrimaryTransfer(
            reconciler(0), reconciler(1), pair, plan, observe_primary=Mock(side_effect=observations),
            observe_standby=lambda: peer, read_route_source=lambda: source, receipt_client=receipt,
            read_controller_pair=read_controller_pair,
        )

    def stage_backend(commands, *, confirm_minutes):
        assert commands == handoff.create_commands() and confirm_minutes == 1
        assert all("shadow_handoff" in json.loads(path.read_text()) for path in paths)
        if outcome == "lost-stage":
            raise VyOSWriteError("stage reply lost")
        routers[0].read_complete_configuration.return_value = current_stage

    routers[0].stage_configuration.side_effect = stage_backend
    if outcome == "occupied-receipt":
        receipt.status.return_value = ShadowReceiptStatus("d" * 64, object())
        with pytest.raises(ValueError, match="receipt slot"):
            transfer(preimage).stage()
        assert not receipt.fence.called and not routers[0].stage_configuration.called
        return
    if outcome == "drift-before-stage":
        read_controller_pair.return_value = changed_controller_pair
        with pytest.raises(ValueError, match="controller"):
            transfer(preimage).stage()
        assert not routers[0].stage_configuration.called and not receipt.fence.called
        assert all(not path.exists() for path in paths)
        return
    if outcome == "lost-stage":
        with pytest.raises(VyOSWriteError, match="reply lost"):
            transfer(preimage).stage()
    else:
        ordinary_lan = local.saved["interfaces"]["ethernet"]["eth3"]
        no_vip = kernel | {"eth3": kernel["eth3"][:-1]}
        candidate = _handoff_state({"address": ordinary_lan["address"][1:]}, no_vip, saved_lan=ordinary_lan, plan=left)
        if outcome == "rebuild-after-save":
            for command in handoff.management_guard.create_commands():
                *parents, key = command["path"]
                tree = candidate.running
                for parent in parents:
                    tree = tree.setdefault(parent, {})
                value = command["value"]
                tree[key] = [tree[key], value] if key in tree else value
        staged = replace(preimage, state=candidate, role="fault", config_sha256="c" * 64, phase="staged_reboot")
        current_stage = candidate.running | {"system": {"host-name": "operator"}}
        if outcome == "resume-first-complete":
            with pytest.raises(VyOSReadError, match="timed observation lost"):
                transfer(preimage, VyOSReadError("timed observation lost")).stage()
            assert json.loads(paths[0].read_text())["shadow_handoff"]["phase"] == "armed"
        else:
            assert transfer(preimage, staged).stage() == staged

    if outcome == "resume-first-complete":
        completed = replace(staged, phase="completed")
        saved_state = replace(candidate, saved=candidate.running)
        saved = replace(staged, state=saved_state, phase="saved_commit", saved_sha256="d" * 64)
        master = replace(saved, role="master", state=replace(saved_state, kernel=kernel | {
            "eth1": (ip_interface("198.18.240.1/24"),),
        }))
        receipt.candidate.return_value = ShadowReceiptCandidate(boot, "9" * 64, "f" * 64, saved.config_sha256)

        def publish(transaction, signing_candidate):
            installed = ShadowPolicyReceipt("8" * 64, signing_candidate.sha256, transaction, saved.config_sha256)
            receipt.status.return_value = ShadowReceiptStatus(signing_candidate.generation, installed)
            return installed

        receipt.publish.side_effect = publish
        assert transfer(staged, staged, completed, saved, saved, master, master).advance_primary(
            verify_forwarding=Mock(),
        ) == master
        assert json.loads(paths[0].read_text())["shadow_handoff"]["phase"] == "primary_active"
        assert routers[0].stage_configuration.call_count == routers[0].confirm_configuration.call_count == 1
        assert routers[0].save_configuration.call_count == receipt.publish.call_count == 1
        return

    if outcome == "operator-edit":
        routers[0].read_complete_configuration.return_value = current_stage | {"system": {"host-name": "changed"}}
        with pytest.raises(ValueError, match="outside"):
            transfer(staged).confirm_and_save()
        assert not routers[0].confirm_configuration.called
        return

    if outcome == "controller-drift":
        read_controller_pair.return_value = changed_controller_pair
        with pytest.raises(ValueError, match="controller"):
            transfer(staged).confirm_and_save()
        assert not routers[0].confirm_configuration.called and not routers[0].save_configuration.called
        return

    activation = outcome in {
        "activate", "lost-publish", "publication-not-sent", "wrong-receipt", "forwarding-failure", "drift-before-activation",
        "rebuild-after-save",
    }
    if activation or outcome in {"saved", "lost-confirm", "lost-save", "drift-before-save"}:
        completed = replace(staged, phase="completed")
        saved_state = replace(candidate, saved=candidate.running)
        saved = replace(staged, state=saved_state, phase="saved_commit", saved_sha256="d" * 64)

        def confirm():
            record = json.loads(paths[0].read_text())["shadow_handoff"]
            assert record["phase"] == "confirming" and record["staged_sha256"] == staged.config_sha256
            if outcome == "drift-before-save":
                read_controller_pair.return_value = changed_controller_pair
            if outcome == "lost-confirm":
                raise VyOSWriteError("confirmation reply lost")

        routers[0].confirm_configuration.side_effect = confirm
        if outcome == "lost-save":
            routers[0].save_configuration.side_effect = VyOSWriteError("save reply lost")
        attempt = transfer(staged, completed, saved)
        if outcome == "drift-before-save":
            with pytest.raises(ValueError, match="controller"):
                attempt.confirm_and_save()
            assert routers[0].confirm_configuration.call_count == 1 and not routers[0].save_configuration.called
            return
        if activation or outcome == "saved":
            assert attempt.confirm_and_save() == saved
        else:
            with pytest.raises(VyOSWriteError, match="reply lost"):
                attempt.confirm_and_save()
            if outcome == "lost-save":
                assert json.loads(paths[0].read_text())["shadow_handoff"]["phase"] == "saving"
                with pytest.raises(ValueError, match="evidence differs"):
                    transfer(preimage).confirm_and_save()
                assert transfer(saved).confirm_and_save() == saved
            else:
                assert transfer(completed, saved).confirm_and_save() == saved
        assert routers[0].confirm_configuration.call_count == routers[0].save_configuration.call_count == 1
        assert json.loads(paths[0].read_text())["shadow_handoff"]["phase"] == "saved"
        assert json.loads(paths[1].read_text())["shadow_handoff"]["phase"] == "standby"
        if activation:
            if outcome == "rebuild-after-save":
                from provisioners.vyos_shadow_complete import prepare_shadow_primary_lan_handoff

                reservation = json.loads(paths[0].read_text())["shadow_handoff"]
                persisted = read_shadow_lan_preimage(reservation)
                assert json.loads(paths[1].read_text())["shadow_handoff"]["lan_preimage"] == reservation["lan_preimage"]
                assert persisted.addresses == handoff.ordinary_address_order
                assert persisted.route_source == source
                assert persisted.guard_containers == handoff.guard_containers
                assert persisted.created_vrrp_parent == handoff.created_vrrp_parent == ("high-availability",)
                old_preimage = {key: value for key, value in reservation["lan_preimage"].items()
                                if key != "created_vrrp_parent"}
                assert read_shadow_lan_preimage(reservation | {"lan_preimage": old_preimage}).created_vrrp_parent == ()
                with pytest.raises(ValueError, match="LAN preimage"):
                    read_shadow_lan_preimage(reservation | {"lan_preimage": old_preimage | {
                        "created_vrrp_parent": ["service"],
                    }})
                assert "192.0.2.1/24" not in saved.state.saved["interfaces"]["ethernet"]["eth3"]["address"]
                election, _, shadow_nodes = _lan_election_pair()
                recovered = prepare_shadow_primary_lan_handoff(
                    replace(election, priority=255), nodes=shadow_nodes, primary_lan_link_local="fe80::2",
                    ordinary=ordinary, complete=complete, local=saved.state, peer=peer, route_source=None,
                    recovery=persisted,
                )
                recovered = replace(recovered, complete_snapshot_sha256=handoff.complete_snapshot_sha256,
                                    complete_binding=pair, management_guard=handoff.management_guard,
                                    standby_resources_sha256=handoff.standby_resources_sha256,
                                    site_policy_sha256=handoff.site_policy_sha256)
                assert recovered == handoff
                with pytest.raises(ValueError, match="matching reservations"):
                    transfer(plan=replace(recovered, guard_containers=())).activate_primary(verify_forwarding=Mock())
                with pytest.raises(ValueError, match="matching reservations"):
                    transfer(plan=replace(recovered, created_vrrp_parent=())).activate_primary(verify_forwarding=Mock())
                with pytest.raises(ValueError, match="matching reservations"):
                    transfer(plan=replace(recovered, standby_resources_sha256="9" * 64)).activate_primary(verify_forwarding=Mock())
                with pytest.raises(ValueError, match="matching reservations"):
                    transfer(plan=replace(recovered, site_policy_sha256="9" * 64)).activate_primary(verify_forwarding=Mock())
                assert not receipt.publish.called
                handoff = recovered
            changed = replace(handoff, complete_snapshot_sha256="6" * 64)
            with pytest.raises(ValueError, match="matching reservations"):
                transfer(plan=changed).activate_primary(verify_forwarding=Mock())
            assert not receipt.publish.called
            receipt.candidate.return_value = ShadowReceiptCandidate(boot, "9" * 64, "f" * 64, saved.config_sha256)
            if outcome == "drift-before-activation":
                read_controller_pair.return_value = changed_controller_pair
                with pytest.raises(ValueError, match="controller"):
                    transfer(saved).activate_primary(verify_forwarding=Mock())
                assert not receipt.publish.called
                assert json.loads(paths[0].read_text())["shadow_handoff"]["phase"] == "saved"
                return
            master = replace(saved, role="master", state=replace(saved_state, kernel=kernel | {
                "eth1": (ip_interface("198.18.240.1/24"),),
            }))
            check_forwarding = Mock()

            def publish(transaction, signing_candidate):
                pending = json.loads(paths[0].read_text())["shadow_handoff"]
                assert pending["phase"] == "publishing" and pending["policy_sha256"] == signing_candidate.sha256
                if outcome == "publication-not-sent" and receipt.publish.call_count == 1:
                    raise ShadowReceiptError("publication reply lost")
                installed = ShadowPolicyReceipt("8" * 64, signing_candidate.sha256, transaction, saved.config_sha256)
                if outcome == "wrong-receipt":
                    installed = replace(installed, transaction=boot)
                receipt.status.return_value = ShadowReceiptStatus(signing_candidate.generation, installed)
                if outcome == "lost-publish":
                    raise ShadowReceiptError("publication reply lost")
                return installed

            receipt.publish.side_effect = publish
            attempt = transfer(saved, master, master)
            if outcome in {"lost-publish", "publication-not-sent"}:
                with pytest.raises(ShadowReceiptError, match="reply lost"):
                    attempt.activate_primary(verify_forwarding=check_forwarding)
                observations = (saved, master, master) if outcome == "publication-not-sent" else (master, master)
                assert transfer(*observations).activate_primary(verify_forwarding=check_forwarding) == master
            elif outcome == "wrong-receipt":
                with pytest.raises(ValueError, match="receipt"):
                    attempt.activate_primary(verify_forwarding=check_forwarding)
                assert not check_forwarding.called
            elif outcome == "forwarding-failure":
                check_forwarding.side_effect = ValueError("forwarding unavailable")
                with pytest.raises(ValueError, match="forwarding unavailable"):
                    attempt.activate_primary(verify_forwarding=check_forwarding)
            else:
                assert attempt.activate_primary(verify_forwarding=check_forwarding) == master
            if outcome == "publication-not-sent":
                first, retry = receipt.publish.call_args_list
                assert first == retry
            else:
                assert receipt.publish.call_count == 1
            expected_phase = "publishing" if outcome in {"wrong-receipt", "forwarding-failure"} else "primary_active"
            active_record = json.loads(paths[0].read_text())["shadow_handoff"]
            assert active_record["phase"] == expected_phase
            if expected_phase == "primary_active":
                assert active_record["complete_snapshot_sha256"] == handoff.complete_snapshot_sha256
                if outcome == "rebuild-after-save":
                    assert active_record["standby_resources_sha256"] == handoff.standby_resources_sha256
                    assert active_record["site_policy_sha256"] == handoff.site_policy_sha256
            assert json.loads(paths[1].read_text())["shadow_handoff"]["phase"] == "standby"
            with pytest.raises(ValueError, match="recovery"):
                transfer().recover_rollback()
        return

    with pytest.raises(ValueError, match="pending"):
        transfer(preimage).stage()
    for i in (0, 1):
        reconciler_after_restart = reconciler(i)
        assert "Shadow Mode handoff" in reconciler_after_restart.reconcile(None).error
        with pytest.raises(ValueError, match="pending provisioning"):
            VyOSRestart(reconciler_after_restart, preflight=Mock(), verify_forwarding=Mock()).request(None)
    with pytest.raises(ValueError, match="verified reboot"):
        transfer(preimage).recover_rollback()
    assert routers[0].stage_configuration.call_count == 1
    restored = replace(preimage, boot_id="6303a0a3-d505-4782-93e1-0639a40dd670")
    recovering = transfer(restored)
    persist = recovering.primary._write_state

    def interrupted_cleanup(state, *, durable):
        if "shadow_handoff" not in state:
            raise OSError("interrupted before primary journal cleanup")
        persist(state, durable=durable)

    recovering.primary._write_state = interrupted_cleanup
    previous_standby = json.loads(paths[1].read_text())["shadow_handoff"]
    with pytest.raises(OSError, match="primary journal cleanup"):
        recovering.recover_rollback()
    assert json.loads(paths[0].read_text())["shadow_handoff"]["phase"] == "rolled_back"
    assert "shadow_handoff" not in json.loads(paths[1].read_text())
    standby = reconciler(1)
    new_reservation = previous_standby | {"transaction": restored.boot_id, "target": "d" * 64}
    with standby.locked_state() as state:
        state["shadow_handoff"] = new_reservation
        standby._write_state(state, durable=True)
    transfer().recover_rollback()
    assert "shadow_handoff" not in json.loads(paths[0].read_text())
    assert json.loads(paths[1].read_text())["shadow_handoff"] == new_reservation
    with pytest.raises(ValueError, match="already rolled back"):
        transfer(restored).stage()
    legacy = transfer(plan=replace(handoff, created_vrrp_parent=()))
    with legacy.primary.locked_state() as state:
        state["last_shadow_rollback"] = legacy._revision
        legacy.primary._write_state(state, durable=True)
    with pytest.raises(ValueError, match="already rolled back"):
        transfer(restored).stage()
    assert routers[0].stage_configuration.call_count == 1
    assert not routers[0].confirm_configuration.called
    assert not routers[1].stage_configuration.called


def test_staged_handoff_requires_fenced_running_vrrp_and_saved_static_preimage():
    from provisioners.vyos_shadow_complete import prepare_shadow_lan_handoff

    left, right, ordinary, complete, kernel = _lan_handoff()
    ordinary_lan = {"address": ["192.0.2.1/24", "192.0.2.2/24", "192.0.2.9/24"]}
    handoff = prepare_shadow_lan_handoff(
        left, right, ordinary=(ordinary, ordinary), complete=(complete, complete),
        local=_handoff_state(ordinary_lan, kernel), peer=_standby_state(), route_source="192.0.2.1",
    )
    transferred = {"address": ordinary_lan["address"][1:]}
    no_vip = kernel | {"eth3": kernel["eth3"][:-1]}
    staged = _handoff_state(transferred, no_vip, saved_lan=ordinary_lan, plan=left)
    handoff.verify_staged_transfer(staged, peer=_standby_state(), role="fault")
    with pytest.raises(ValueError, match="fenced"):
        handoff.verify_staged_transfer(staged, peer=_standby_state(), role="backup")
    for unsafe in (
        _handoff_state(transferred, no_vip, saved_lan=ordinary_lan),
        _handoff_state(transferred, kernel, saved_lan=ordinary_lan, plan=left),
        _handoff_state(transferred, no_vip | {"eth1": (ip_interface("198.18.240.1/24"),)},
                       saved_lan=ordinary_lan, plan=left),
        _handoff_state(transferred, no_vip, plan=left, saved_plan=left),
    ):
        with pytest.raises(ValueError):
            handoff.verify_staged_transfer(unsafe, peer=_standby_state(), role="fault")
    reordered = {"address": ordinary_lan["address"][::-1]}
    with pytest.raises(ValueError, match="saved ordinary address order"):
        handoff.verify_staged_transfer(
            _handoff_state(transferred, no_vip, saved_lan=reordered, plan=left), peer=_standby_state(), role="fault",
        )


def test_staged_restoration_rejects_a_source_change_before_saving():
    from provisioners.vyos_shadow_complete import prepare_shadow_lan_handoff

    left, right, ordinary, complete, kernel = _lan_handoff()
    ordinary_lan = {"address": ["192.0.2.1/24", "192.0.2.2/24", "192.0.2.9/24"]}
    handoff = prepare_shadow_lan_handoff(
        left, right, ordinary=(ordinary, ordinary), complete=(complete, complete),
        local=_handoff_state(ordinary_lan, kernel), peer=_standby_state(), route_source="192.0.2.1",
    )
    paired_lan = {"address": ordinary_lan["address"][1:]}
    staged = _handoff_state(ordinary_lan, kernel, saved_lan=paired_lan, saved_plan=left)
    handoff.verify_staged_restoration(staged, route_source="192.0.2.1")
    with pytest.raises(ValueError, match="preferred source"):
        handoff.verify_staged_restoration(staged, route_source="192.0.2.9")
    with pytest.raises(ValueError):
        handoff.verify_staged_restoration(
            _handoff_state(ordinary_lan, kernel, saved_lan=paired_lan), route_source="192.0.2.1",
        )
    with pytest.raises(ValueError):
        handoff.verify_staged_restoration(
            _handoff_state(ordinary_lan, kernel, saved_lan=paired_lan, plan=left, saved_plan=left),
            route_source="192.0.2.1",
        )


@pytest.mark.parametrize(("ordinary_ha", "operator_branch", "expected_path"), [
    (None, None, ["high-availability"]),
    ({}, None, ["high-availability", "vrrp"]),
    ({"vrrp": {}}, None, ["high-availability", "vrrp", "group", "UXGSHADOW"]),
    (None, {"group": {"operator": {"interface": "eth7", "vrid": "39"}}},
     ["high-availability", "vrrp", "group", "UXGSHADOW"]),
])
def test_restoration_prunes_only_proven_shadow_vrrp_ancestors(ordinary_ha, operator_branch, expected_path):
    from dataclasses import replace

    from provisioners.vyos_shadow_complete import prepare_shadow_lan_handoff

    left, right, ordinary, complete, kernel = _lan_handoff()
    config = {"address": ["192.0.2.1/24", "192.0.2.2/24", "192.0.2.9/24"]}
    preimage = _handoff_state(config, kernel)
    if ordinary_ha is not None:
        preimage = replace(preimage, running=preimage.running | {"high-availability": ordinary_ha},
                           saved=preimage.saved | {"high-availability": ordinary_ha})
    peer = _standby_state()
    handoff = prepare_shadow_lan_handoff(left, right, ordinary=(ordinary, ordinary), complete=(complete, complete),
                                         local=preimage, peer=peer, route_source="192.0.2.1")
    paired = _handoff_state({"address": config["address"][1:]}, kernel | {"eth3": kernel["eth3"][:-1]},
                           plan=left, saved_plan=left)
    if operator_branch is not None:
        # Even a saved-only operator group prevents deletion of its parent.
        groups = paired.saved["high-availability"]["vrrp"]["group"]
        groups.update(operator_branch["group"])
    commands = handoff.restore_commands(local=paired, peer=peer)
    assert {"op": "delete", "path": expected_path} in commands
    if expected_path[-1] == "UXGSHADOW":
        assert all(command["path"] not in (["high-availability"], ["high-availability", "vrrp"])
                   for command in commands)


def test_maintenance_candidate_replays_the_saved_lan_address_order():
    from dataclasses import replace

    from provisioners.vyos_shadow_complete import prepare_shadow_lan_handoff

    left, right, ordinary, complete, kernel = _lan_handoff()
    ordered = ["192.0.2.1/24", "192.0.2.9/24", "192.0.2.2/24"]
    ordinary_lan = {"address": ordered}
    handoff = prepare_shadow_lan_handoff(
        left, right, ordinary=(ordinary, ordinary), complete=(complete, complete),
        local=_handoff_state(ordinary_lan, kernel), peer=_standby_state(), route_source="192.0.2.1",
    )
    paired_lan = {"address": ordered[1:]}
    no_vip = kernel | {"eth3": kernel["eth3"][:-1]}
    local = _handoff_state(paired_lan, no_vip, plan=left, saved_plan=left)
    peer = _standby_state()
    path = ["interfaces", "ethernet", "eth3", "address"]
    assert handoff.maintenance_restore_commands(local=local, peer=peer) == [
        *handoff.restore_commands(local=local, peer=peer)[:-1],
        *({"op": "delete", "path": [*path, address]} for address in ordered[1:]),
        *({"op": "set", "path": path, "value": address} for address in ordered),
    ]
    candidate = _handoff_state(ordinary_lan, kernel, saved_lan=paired_lan, saved_plan=left)
    handoff.verify_staged_maintenance_restoration(candidate)
    preexisting_root = replace(handoff, created_vrrp_parent=("high-availability", "vrrp"))
    with pytest.raises(ValueError, match="pre-existing high-availability"):
        preexisting_root.verify_staged_maintenance_restoration(candidate)
    preexisting_root.verify_staged_maintenance_restoration(replace(
        candidate, running=candidate.running | {"high-availability": {}},
    ))
    with pytest.raises(ValueError, match="empty Shadow Mode VRRP parent"):
        handoff.verify_staged_maintenance_restoration(replace(
            candidate, running=candidate.running | {"high-availability": {"vrrp": {}}},
        ))
    with pytest.raises(ValueError, match="outside Shadow Mode"):
        handoff.verify_staged_maintenance_restoration(replace(
            candidate, running=candidate.running | {"system": {"host-name": "unexpected-router"}},
        ))
    with pytest.raises(ValueError, match="complete running and saved"):
        handoff.verify_staged_maintenance_restoration(replace(candidate, projected=True))
    reordered = _handoff_state({"address": ordered[::-1]}, kernel, saved_lan=paired_lan, saved_plan=left)
    with pytest.raises(ValueError, match="address order"):
        handoff.verify_staged_maintenance_restoration(reordered)
    unsafe = prepare_shadow_lan_handoff(
        left, right, ordinary=(ordinary, ordinary), complete=(complete, complete),
        local=_handoff_state({"address": ordered[::-1]}, kernel), peer=peer, route_source="192.0.2.1",
    )
    with pytest.raises(ValueError, match="does not explain"):
        unsafe.maintenance_restore_commands(local=local, peer=peer)


@pytest.mark.parametrize(("ancestry", "fault", "expected"), [
    (["high-availability"], None, ["high-availability"]),
    (["high-availability", "vrrp"], None, ["high-availability", "vrrp"]),
    (None, None, ["high-availability", "vrrp", "group", "UXGSHADOW"]),
    (["high-availability"], "operator", ["high-availability", "vrrp", "group", "UXGSHADOW"]),
    (["high-availability"], "role", None),
    (["high-availability"], "vip", None),
    (["high-availability"], "receipt", None),
    (["high-availability"], "commit", None),
    (["high-availability"], "marker", None),
])
def test_standby_withdrawal_plans_only_from_a_current_released_election(ancestry, fault, expected):
    from unittest.mock import Mock

    from provisioners import vyos_shadow_standby as standby
    from provisioners.vyos_shadow_complete import ShadowStockState, build_vyos_shadow_standby_candidate
    from provisioners.vyos_shadow_receipt import ShadowReceiptStatus

    _, election, nodes = _lan_election_pair()
    plan = build_vyos_shadow_standby_candidate(election, nodes=nodes)
    live = _standby_state(plan=plan, saved_plan=plan)
    stock = live.running
    if fault == "operator":
        stock["high-availability"]["vrrp"]["group"]["operator"] = {"interface": "eth6", "vrid": "39"}
    boot_id = "158dd3a3-dc93-4ae3-94b1-489e4f6ecc6d"
    policy = {"phase": "unchanged", "target": "1" * 64, "receipt_generation": "2" * 64}
    record = {
        "phase": "released", "policy_sha256": standby._digest(policy), "outside_sha256": "3" * 64,
        "plan_sha256": standby._election_plan_sha(plan, created_vrrp_parent=ancestry), "candidate_sha256": "4" * 64,
        "final_saved_sha256": "5" * 64, "receipt_policy_sha256": "6" * 64,
        "receipt_id": "7" * 64, "revoked_generation": "8" * 64,
    }
    if ancestry is not None:
        record["created_vrrp_parent"] = ancestry if fault != "marker" else []
    state = {standby.SHADOW_HANDOFF: {"phase": "standby", "target": policy["target"]},
             standby.STANDBY_POLICY: policy, standby.STANDBY_ELECTION: record}
    writer, receipt = Mock(), Mock()
    writer.backend.management_origin = receipt.management_identity.https_origin = "https://standby.test"
    writer.backend.read_complete_configuration.return_value = stock
    writer.commit_proof.side_effect = [(boot_id, record["candidate_sha256"]),
                                       (boot_id, ("0" * 64 if fault == "commit" else record["candidate_sha256"]))]
    receipt.status.return_value = ShadowReceiptStatus("9" * 64 if fault == "receipt" else record["revoked_generation"], None)
    kernel = dict(live.kernel)
    if fault == "vip":
        kernel["eth5"] += (ip_interface("192.0.2.1/24"),)
    receipt.observe_handoff_state.return_value = Mock(
        phase="saved_commit", role="backup" if fault == "role" else "fault", boot_id=boot_id,
        config_sha256=record["candidate_sha256"], saved_sha256=record["final_saved_sha256"],
        state=ShadowStockState({}, {}, kernel, projected=True),
    )
    if expected is None:
        with pytest.raises(ValueError):
            standby.standby_election_withdrawal_commands(writer, state, receipt, plan)
    else:
        commands = standby.standby_election_withdrawal_commands(writer, state, receipt, plan)
        assert {"op": "delete", "path": expected} in commands
        assert all(command["op"] == "delete" for command in commands)
        if expected[-1] == "UXGSHADOW":
            assert all(command["path"] not in (["high-availability"], ["high-availability", "vrrp"])
                       for command in commands)
    writer.backend.stage_configuration.assert_not_called()
    writer._write_state.assert_not_called()


def test_create_and_withdrawal_preserve_other_vrrp_groups_and_reject_operator_drift():
    build, decode = _compiler()
    desired = build(decode(_wire(), version=5), interconnect="eth2", local_address="169.254.254.2/24",
                    interfaces={"br0": "eth3", "br120": "eth1"})
    foreign = {"group": {"Another": {"vrid": "41", "interface": "eth3", "address": {"192.0.2.8/24": {}}}}}
    kernel = {"eth2": (IPv4Interface("169.254.254.2/24"),), "eth3": (), "eth1": ()}
    desired.verify_empty(foreign, None, kernel)
    for vrrp, conntrack, current in (
        (foreign, {"interface": "operator"}, kernel),
        ({"group": {"Another": {"interface": "eth2", "vrid": "42"}}}, None, kernel),
        ({"group": {"Another": {"excluded-address": {"192.0.2.1/24": {}}}}}, None, kernel),
        (foreign, None, {**kernel, "eth3": (IPv4Interface("192.0.2.1/24"),)}),
        (foreign, None, {**kernel, "eth9": (IPv4Interface("192.0.2.4/24"),)}),
        (foreign, None, {"eth2": kernel["eth2"], "eth1": ()}),
        (foreign, None, {**kernel, "eth2": (IPv4Interface("169.254.254.2/25"),)}),
        (foreign, None, {**kernel, "eth3": (IPv4Interface("169.254.254.3/24"),)}),
    ):
        with pytest.raises(ValueError):
            desired.verify_empty(vrrp, conntrack, current)

    active = deepcopy(foreign)
    active["group"]["UXGSHADOW"] = deepcopy(desired.group)
    active["sync-group"] = {"UXGHA": deepcopy(desired.sync_group)}
    commands = desired.withdraw_commands(active, deepcopy(desired.conntrack))
    assert [command["path"] for command in commands] == [
        ["service", "conntrack-sync"], ["high-availability", "vrrp", "sync-group", "UXGHA"],
        ["high-availability", "vrrp", "group", "UXGSHADOW"],
    ]
    active["group"]["UXGSHADOW"]["priority"] = "101"
    with pytest.raises(ValueError):
        desired.withdraw_commands(active, deepcopy(desired.conntrack))
