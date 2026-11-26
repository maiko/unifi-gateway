"""Promotion requires the same verified policy in running and saved VyOS state."""

import importlib.util
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
from subprocess import TimeoutExpired
from unittest.mock import Mock

import pytest


@pytest.fixture(scope="module")
def guard():
    script = Path(__file__).resolve().parents[1] / "scripts/vyos-shadow-policy-eligible.py"
    spec = importlib.util.spec_from_file_location("vyos_shadow_policy_eligible", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


POLICY_PATHS = [
    ["firewall", "ipv4", "forward", "filter", "default-action"],
    ["firewall", "ipv4", "forward", "filter", "rule", "42000"],
    ["nat", "source", "rule", "42000"],
]
MANAGED_ANCHORS = [
    ["high-availability", "vrrp", "group", "UXGSHADOW"],
    ["high-availability", "vrrp", "sync-group", "UXGHA"],
    ["service", "conntrack-sync"],
]
BOOT_ID = "158dd3a3-dc93-4ae3-94b1-489e4f6ecc6d"
TRANSACTION = "6303a0a3-d505-4782-93e1-0639a40dd670"
COMMIT = "c" * 64
EMPTY = {"receipt": None, "generation": "0" * 64}


def _config(port=8443, *, source_nat=True, hostname="test-a"):
    return {
        "firewall": {"ipv4": {"forward": {"filter": {
            "default-action": "drop", "rule": {"42000": {"destination": {"port": str(port)}}},
        }}}},
        "nat": {"source": {"rule": {"42000": {"translation": {"address": "198.18.240.1"}}} if source_nat else {}}},
        "system": {"host-name": hostname},
    }


def _receipt(guard, directory, *, config=None, paths=POLICY_PATHS):
    path = directory / "receipt.json"
    path.write_text(json.dumps({"paths": paths, "sha256": guard.policy_digest(config or _config(), paths)}))
    path.chmod(0o600)
    return path


@pytest.fixture
def controller(guard, tmp_path):
    config = _config() | {
        "high-availability": {"vrrp": {"group": {"UXGSHADOW": {"vrid": "42", "priority": "120"}},
                                       "sync-group": {"UXGHA": {"member": "UXGSHADOW", "health-check": {
                                           "script": "/config/scripts/unifi-gateway-shadow-policy-eligible.py",
                                       }}}}},
        "service": {"conntrack-sync": {"failover-mechanism": {"vrrp": {"sync-group": "UXGHA"}}}},
    }
    scope = tmp_path / "policy-scope.json"
    scope.write_text(json.dumps({"paths": [*POLICY_PATHS, *MANAGED_ANCHORS]}))
    scope.chmod(0o600)

    def execute(request, *, active=config, saved=config, boot=BOOT_ID, commit=COMMIT, proof=None):
        return guard.manage_receipt(tmp_path, os.geteuid(), request, observe=lambda: (active, saved),
                                    prove_saved=proof or (lambda: (boot, commit)))

    return execute, config


def test_publish_and_revoke_the_exact_verified_receipt(guard, tmp_path, controller):
    execute, config = controller
    assert execute({"op": "status"}) == EMPTY
    candidate = execute({"op": "candidate"})
    assert candidate == {"boot_id": BOOT_ID, "config_sha256": COMMIT,
                         "sha256": guard.policy_digest(config, [*POLICY_PATHS, *MANAGED_ANCHORS]),
                         "generation": "0" * 64}
    publish = {"op": "publish", "transaction": TRANSACTION, **candidate}
    first = execute(publish)
    assert first == execute(publish) == execute({"op": "status"})
    assert first["receipt"]["transaction"] == TRANSACTION
    assert first["receipt"]["sha256"] == candidate["sha256"]
    assert first["receipt"]["config_sha256"] == COMMIT
    assert guard.policy_is_eligible(tmp_path, os.geteuid(), lambda: (config, config))
    assert (tmp_path / "receipt.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="receipt"):
        execute({"op": "revoke", "receipt_id": "a" * 64})
    with pytest.raises(ValueError, match="receipt"):
        execute(publish | {"transaction": BOOT_ID})
    revoke = {"op": "revoke", "receipt_id": first["receipt"]["id"]}
    revoked = execute(revoke)
    assert revoked == execute(revoke) == execute({"op": "status"})
    assert revoked["receipt"] is None and revoked["generation"] != candidate["generation"]
    assert not guard.policy_is_eligible(tmp_path, os.geteuid(), lambda: (config, config))
    with pytest.raises(ValueError, match="generation"):
        execute(publish)
    fresh = execute({"op": "candidate"})
    assert fresh["generation"] != candidate["generation"]
    next_receipt = execute({"op": "publish", "transaction": BOOT_ID, **fresh})
    assert next_receipt["receipt"]["transaction"] == BOOT_ID
    with pytest.raises(ValueError, match="receipt changed"):
        execute(revoke)


def test_publication_refuses_boot_policy_or_scope_drift(guard, tmp_path, controller):
    execute, config = controller
    publish = {"op": "publish", "transaction": TRANSACTION, **execute({"op": "candidate"})}
    for request, observed in (
        (publish | {"boot_id": TRANSACTION}, {}),
        (publish | {"sha256": "a" * 64}, {}),
        (publish, {"saved": config | _config(port=8444)}),
        (publish | {"paths": POLICY_PATHS}, {}),
        (publish, {"active": config | {"service": {}}}),
    ):
        with pytest.raises(ValueError):
            execute(request, **observed)
        assert execute({"op": "status"}) == EMPTY

    execute(publish)
    scope = tmp_path / "policy-scope.json"
    scope.write_text(json.dumps({"paths": [*POLICY_PATHS[1:], *MANAGED_ANCHORS]}))
    assert not guard.policy_is_eligible(tmp_path, os.geteuid(), lambda: (config, config))


def test_managed_scope_fences_a_legacy_receipt_until_replaced(guard, tmp_path, controller):
    execute, config = controller
    _receipt(guard, tmp_path, config=config)
    assert not guard.policy_is_eligible(tmp_path, os.geteuid(), lambda: (config, config))
    prior = execute({"op": "status"})["receipt"]
    assert prior["transaction"] is None and prior["config_sha256"] is None
    assert execute({"op": "revoke", "receipt_id": prior["id"]})["receipt"] is None


def test_admission_checks_the_empty_slot_scope_and_saved_proof_before_election(guard, tmp_path, controller):
    execute, config = controller
    request = {"op": "check-admission", "boot_id": BOOT_ID, "config_sha256": COMMIT,
               "required_paths": [POLICY_PATHS[0]]}
    ordinary = _config()
    assert execute(request, active=ordinary, saved=ordinary) == {"ready": True}
    assert not guard.policy_is_eligible(tmp_path, os.geteuid(), lambda: (config, config))
    with pytest.raises(ValueError, match="saved configuration"):
        execute(request, commit="d" * 64)
    with pytest.raises(ValueError, match="does not cover"):
        execute(request | {"required_paths": [["interfaces", "bridge", "br0"]]})
    assert execute({"op": "status"}) == EMPTY

    candidate = execute({"op": "candidate"})
    execute({"op": "publish", "transaction": TRANSACTION, **candidate})
    with pytest.raises(ValueError, match="empty receipt"):
        execute(request)
    (tmp_path / "receipt.json").unlink()
    (tmp_path / "policy-scope.json").unlink()
    with pytest.raises(ValueError, match="router-local Shadow policy scope"):
        execute(request)


def test_same_boot_change_outside_policy_scope_invalidates_publication(controller):
    execute, config = controller
    initial = execute({"op": "candidate"})
    publish = {"op": "publish", "transaction": TRANSACTION, **initial}
    changed = config | {"system": {"host-name": "operator-changed-it"}}
    with pytest.raises(ValueError, match="verified.*commit"):
        execute(publish, active=changed, saved=changed, commit="d" * 64)
    assert execute({"op": "status"}) == EMPTY
    new = execute({"op": "candidate"}, active=changed, saved=changed, commit="d" * 64)
    assert new["sha256"] == initial["sha256"] and new["config_sha256"] != initial["config_sha256"]
    proof = iter(((BOOT_ID, COMMIT), (BOOT_ID, "d" * 64)))
    with pytest.raises(ValueError, match="changed during"):
        execute({"op": "candidate"}, proof=lambda: next(proof))

    published = execute(publish)
    assert published["receipt"]["config_sha256"] == COMMIT
    with pytest.raises(ValueError, match="current Shadow receipt"):
        execute(publish | new, active=changed, saved=changed, commit="d" * 64)


def test_empty_slot_fencing_invalidates_an_in_flight_publication(controller):
    execute, _ = controller
    candidate = execute({"op": "candidate"})
    publish = {"op": "publish", "transaction": TRANSACTION, **candidate}
    cancel = {"op": "fence", "generation": candidate["generation"]}
    fenced = execute(cancel)
    assert fenced == execute(cancel) == execute({"op": "status"})
    assert fenced["receipt"] is None and fenced["generation"] != candidate["generation"]
    with pytest.raises(ValueError, match="generation"):
        execute(publish)
    current = execute(publish | execute({"op": "candidate"}))
    with pytest.raises(ValueError, match="receipt"):
        execute({"op": "fence", "generation": current["generation"]})


def test_shadow_guard_requires_router_local_coverage_before_receipt_publication(tmp_path, controller):
    execute, _ = controller
    input_rule = ["firewall", "ipv4", "input", "filter", "rule", "1"]
    required = {"op": "candidate", "required_paths": [*POLICY_PATHS, input_rule]}
    with pytest.raises(ValueError, match="does not cover the required paths"):
        execute(required)

    scope = tmp_path / "policy-scope.json"
    scope.write_text(json.dumps({"paths": [["firewall", "ipv4"], POLICY_PATHS[-1], *MANAGED_ANCHORS]}))
    candidate = execute(required)

    scope.write_text(json.dumps({"paths": [*POLICY_PATHS, *MANAGED_ANCHORS]}))
    with pytest.raises(ValueError, match="must match the verified boot, commit and policy"):
        execute({"op": "publish", "transaction": TRANSACTION, **candidate})
    assert execute({"op": "status"}) == EMPTY


def test_managed_scope_requires_an_actual_firewall_anchor(tmp_path, controller):
    execute, _ = controller
    scope = tmp_path / "policy-scope.json"
    scope.write_text(json.dumps({"paths": [["firewall", "missing"], *MANAGED_ANCHORS]}))
    with pytest.raises(ValueError, match="firewall"):
        execute({"op": "candidate"})


def test_shadow_observation_only_returns_handoff_evidence(guard, controller):
    _, base = controller
    config = deepcopy(base)
    config["interfaces"] = {"wireguard": {"wg0": {"address": "198.51.100.2/24", "private-key": "operator-key"}},
                            "ethernet": {"eth3": {"address": ["192.0.2.9/24", "192.0.2.1/24"], "vrf": "other",
                                                   "vif-s": {"100": {"vif-c": {"101": {"address": "192.0.2.50/25",
                                                                                      "disable": {}}}}}}}}
    config["vpn"] = {"ipsec": {"authentication": "operator-key"}}
    vrrp = config["high-availability"]["vrrp"]
    vrrp["group"]["operator"] = {"interface": "eth9", "vrid": "88", "address": {"192.0.2.123/24": {}},
                                 "authentication": {"password": "operator-key"}}
    vrrp["sync-group"]["operator"] = {"member": ["operator", "another"], "health-check": {"script": "/operator-key"}}

    projection = guard._project_shadow_configuration(config)

    assert projection.keys() == {"interfaces", "service", "high-availability"}
    assert "operator-key" not in json.dumps(projection)
    assert projection["interfaces"]["wireguard"]["wg0"] == {"address": "198.51.100.2/24"}
    lan = projection["interfaces"]["ethernet"]["eth3"]
    assert lan["address"] == ["192.0.2.9/24", "192.0.2.1/24"] and lan["vrf"] == {}
    assert lan["vif-s"]["100"]["vif-c"]["101"] == {"address": "192.0.2.50/25", "disable": {}}
    projected_vrrp = projection["high-availability"]["vrrp"]
    assert projected_vrrp["group"]["operator"] == {"interface": "eth9", "vrid": "88", "address": {"192.0.2.123/24": {}}}
    assert projected_vrrp["sync-group"]["operator"] == {"member": ["operator", "another"]}
    assert projected_vrrp["group"]["UXGSHADOW"] == vrrp["group"]["UXGSHADOW"]
    assert projection["service"]["conntrack-sync"] == config["service"]["conntrack-sync"]

    vrrp["group"]["UXGSHADOW"]["authentication"] = {"password": "operator-key"}
    with pytest.raises(ValueError, match="managed Shadow VRRP") as error:
        guard._project_shadow_configuration(config)
    assert "operator-key" not in str(error.value)


def test_shadow_observation_binds_the_saved_preimage_without_a_settled_proof(guard, tmp_path, monkeypatch):
    boot = tmp_path / "boot-id"
    boot.write_text(BOOT_ID + "\n")
    saved = tmp_path / "config.boot"
    raw = b'{"interfaces":{"ethernet":{"eth3":{"address":["192.0.2.9/24","192.0.2.1/24"]}}}}\n'
    saved.write_bytes(raw)
    monkeypatch.setattr(guard, "_BOOT_ID_PATH", boot)
    monkeypatch.setattr(guard, "_SAVED_CONFIG_PATH", saved)
    monkeypatch.setattr(guard, "_decode_configuration", json.loads)
    monkeypatch.setattr(guard, "_active_configuration_text", lambda: '{"interfaces":{"ethernet":{"eth3":{"address":"192.0.2.9/24"}}}}')

    def execute():
        return guard.manage_receipt(tmp_path, os.geteuid(), {"op": "observe"},
                                    observe=lambda: pytest.fail("Unexpected policy read"),
                                    prove_saved=lambda: pytest.fail("The rollback timer may be active"))

    observation = execute()
    assert observation["saved_sha256"] == sha256(raw).hexdigest() and observation["boot_id"] == BOOT_ID
    assert observation["running"]["interfaces"]["ethernet"]["eth3"]["address"] == "192.0.2.9/24"
    assert observation["saved"]["interfaces"]["ethernet"]["eth3"]["address"] == ["192.0.2.9/24", "192.0.2.1/24"]

    def changing_read():
        saved.write_text("{}")
        return "{}"

    monkeypatch.setattr(guard, "_active_configuration_text", changing_read)
    with pytest.raises(ValueError, match="saved configuration changed"):
        execute()


@pytest.mark.parametrize(("active", "saved", "eligible"), [
    (_config(), _config(hostname="operator-has-changed-it"), True),
    (_config(port=8444), _config(), False),
    (_config(), _config(port=8444), False),
    (_config(port=8444), _config(port=8444), False),
    (_config(), _config(source_nat=False), False),
])
def test_both_configurations_must_match_the_local_receipt(guard, tmp_path, active, saved, eligible):
    _receipt(guard, tmp_path)

    assert guard.policy_is_eligible(tmp_path, os.geteuid(), lambda: (active, saved)) is eligible


def test_withdrawn_policy_can_match_a_verified_absence(guard, tmp_path):
    absent = _config(source_nat=False)
    _receipt(guard, tmp_path, config=absent)

    assert guard.policy_is_eligible(tmp_path, os.geteuid(), lambda: (absent, absent))
    assert not guard.policy_is_eligible(tmp_path, os.geteuid(), lambda: (_config(), _config()))


def test_a_receipt_needs_a_policy_anchor_before_the_node_can_promote(guard, tmp_path):
    paths = [["nat", "source", "rule", "42000"]]
    projection = json.dumps([[paths[0], False, None]], separators=(",", ":"))
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps({"paths": paths, "sha256": sha256(projection.encode()).hexdigest()}))
    receipt.chmod(0o600)
    empty = _config(source_nat=False)

    assert not guard.policy_is_eligible(tmp_path, os.geteuid(), lambda: (empty, empty))


def test_revocation_during_router_read_prevents_promotion(guard, tmp_path):
    receipt = _receipt(guard, tmp_path)

    def observe():
        receipt.unlink()
        return _config(), _config()

    assert not guard.policy_is_eligible(tmp_path, os.geteuid(), observe)


@pytest.mark.parametrize("fault", ["missing", "symlink", "fifo", "public", "directory-public", "duplicate", "timeout"])
def test_untrusted_receipt_or_unavailable_observation_fails_closed(guard, tmp_path, fault):
    receipt = _receipt(guard, tmp_path)

    def observe():
        if fault == "timeout":
            raise TimeoutExpired("cli-shell-api", 1)
        pytest.fail("The router should not be queried for an untrusted receipt")

    if fault == "missing":
        receipt.unlink()
    elif fault == "symlink":
        receipt.rename(tmp_path / "other.json")
        receipt.symlink_to(tmp_path / "other.json")
    elif fault == "fifo":
        receipt.unlink()
        os.mkfifo(receipt, 0o600)
    elif fault == "public":
        receipt.chmod(0o644)
    elif fault == "directory-public":
        tmp_path.chmod(0o775)
    elif fault == "duplicate":
        digest = "a" * 64
        receipt.write_text(f'{{"paths": {json.dumps(POLICY_PATHS)}, "sha256": "{digest}", "sha256": "{digest}"}}')

    assert not guard.policy_is_eligible(tmp_path, os.geteuid(), observe)
@pytest.mark.parametrize(("version", "change"), [
    (2, None), (3, None), (2, "source"), (2, "ttl"), (2, "vrid"), (2, "priority"),
    (3, "vip"), (3, "checksum"), (3, "length"),
])
def test_standby_observer_accepts_only_the_expected_vrrp_advertisement(guard, version, change):
    from ipaddress import IPv4Address

    local, peer, vip = map(IPv4Address, ("192.0.2.3", "192.0.2.2", "192.0.2.1"))
    source = IPv4Address("192.0.2.5") if change == "source" else peer
    payload = struct.pack("!BBBBHH", version << 4 | 1, 43 if change == "vrid" else 42,
                          100 if change == "priority" else 120, 1, 1 if version == 2 else 100, 0)
    payload += (IPv4Address("192.0.2.9") if change == "vip" else vip).packed
    if version == 2:
        payload += bytes(8)
    pseudo = b"" if version == 2 else source.packed + local.packed + struct.pack("!BBH", 0, 112, len(payload))
    words = sum(struct.unpack(f"!{len(pseudo + payload) // 2}H", pseudo + payload))
    checksum = ~((words & 0xffff) + (words >> 16)) & 0xffff
    payload = payload[:6] + struct.pack("!H", checksum ^ (1 if change == "checksum" else 0)) + payload[8:]
    packet = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0,
                         254 if change == "ttl" else 255, 112, 0, source.packed, local.packed) + payload
    if change == "length":
        packet = packet[:-1]
    assert guard._matches_vrrp_advertisement(packet, local, peer, version, {vip.packed}) is (change is None)


@pytest.mark.parametrize("fault", [None, "generation", "boot-drift", "saved-scope", "no-advertisements"])
def test_receipt_manager_observes_only_the_saved_fenced_standby(guard, controller, monkeypatch, fault):
    execute, config = controller
    active = deepcopy(config)
    active["high-availability"]["vrrp"]["group"]["UXGSHADOW"].update(
        {"priority": "100", "advertise-interval": "1", "interface": "eth3",
         "hello-source-address": "192.0.2.3", "peer-address": "192.0.2.2",
         "address": {"192.0.2.1/24": {"interface": "eth3"}}}
    )
    saved = deepcopy(active)
    if fault == "saved-scope":
        saved["high-availability"]["vrrp"]["group"]["UXGSHADOW"]["interface"] = "eth5"
    sample = Mock(return_value=0 if fault == "no-advertisements" else 2)
    monkeypatch.setattr(guard, "_sample_standby_vrrp", sample)
    prove_saved = iter(((BOOT_ID, COMMIT), (BOOT_ID, ("e" * 64 if fault == "boot-drift" else COMMIT))))
    request = {"op": "observe-vrrp", "boot_id": BOOT_ID, "config_sha256": COMMIT,
               "generation": ("1" if fault == "generation" else "0") * 64}
    if fault in ("generation", "boot-drift", "saved-scope"):
        with pytest.raises(ValueError):
            execute(request, active=active, saved=saved, proof=lambda: next(prove_saved))
        assert sample.call_count == (1 if fault == "boot-drift" else 0)
    else:
        assert execute(request, active=active, saved=saved, proof=lambda: next(prove_saved)) == {
            "interface": "eth3", "local": "192.0.2.3", "peer": "192.0.2.2", "version": 2,
            "received": 0 if fault == "no-advertisements" else 2,
        }
    assert execute({"op": "status"}) == EMPTY


def test_vrrp_sample_uses_a_bounded_receive_only_socket(guard, monkeypatch):
    from ipaddress import IPv4Address

    local, peer = map(IPv4Address, ("192.0.2.3", "192.0.2.2"))
    receiver = Mock()
    receiver.recv.side_effect = [b"other", b"expected", TimeoutError]
    sock = Mock(return_value=Mock(__enter__=Mock(return_value=receiver), __exit__=Mock()))
    monkeypatch.setattr(guard.socket, "socket", sock)
    monkeypatch.setattr(guard.socket, "SO_BINDTODEVICE", 25, raising=False)
    monkeypatch.setattr(guard, "_matches_vrrp_advertisement", lambda packet, *_: packet == b"expected")

    assert guard._sample_standby_vrrp("eth3", local, peer, 2, {b"vip"}) == 1
    sock.assert_called_once_with(guard.socket.AF_INET, guard.socket.SOCK_RAW, 112)
    receiver.setsockopt.assert_called_once_with(guard.socket.SOL_SOCKET, 25, b"eth3\0")
    receiver.bind.assert_called_once_with(("192.0.2.3", 0))
    assert 0 < receiver.settimeout.call_args.args[0] <= 3.0
    receiver.send.assert_not_called()
